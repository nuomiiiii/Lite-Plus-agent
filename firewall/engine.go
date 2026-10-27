package firewall

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

var opMu sync.Mutex

const stateFileName = "firewall-state.json"

type backend interface {
	name() string
	snapshot() v2.FirewallResultParams
	apply(intent v2.FirewallIntent, holes []v2.FirewallHole) error
	adopt(keys []string) error
	dump() ([]byte, error)
	dumpHost() ([]byte, error)
	restore([]byte) error
	resetOwned() error
}

func Snapshot() v2.FirewallResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	return withStacks(currentBackend().snapshot())
}

func Apply(intent v2.FirewallIntent, holes []v2.FirewallHole) v2.FirewallResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	eng := currentBackend()
	result := withStacks(eng.snapshot())
	result.Kind = v2.FirewallKindApply
	result.Revision = intent.Revision
	if !result.Supported || !result.Privileged {
		result.Status = v2.FirewallStatusUnsupported
		if result.Error == "" {
			result.Error = "当前环境无法应用防火墙规则"
		}
		return result
	}
	if (intent.DefaultDeny4 || intent.DefaultDeny6) && defaultDenyConflict(result) {
		result.Status = v2.FirewallStatusError
		result.Error = "default deny conflicts with ufw or firewalld"
		result.DefaultDenyBlocked = true
		result.DefaultDenyBlockReason = result.Error
		return result
	}
	if len(holes) == 0 {
		holes = holesFromIntent(intent)
	}
	holes = liveHoles(intent, holes)
	prev, _ := eng.dump()
	ping4, ping6 := captureAux()
	needSSH := keepPort(intent.SshPort) != ""
	var sshSnap []sshFileSnap
	if needSSH {
		sshSnap = snapshotSSHConfigs()
	}
	if err := eng.apply(intent, holes); err != nil {
		rollbackApply(prev, ping4, ping6)
		result.Status = v2.FirewallStatusError
		result.Error = err.Error()
		return result
	}
	if needSSH {
		if err := syncSSHListenPort(intent.SshPort); err != nil {
			restoreSSHConfigs(sshSnap)
			rollbackApply(prev, ping4, ping6)
			result.Status = v2.FirewallStatusError
			result.Error = err.Error()
			return result
		}
	}
	if !watchdogOK() {
		if needSSH {
			restoreSSHConfigs(sshSnap)
		}
		rollbackApply(prev, ping4, ping6)
		result.Status = v2.FirewallStatusRolledBack
		result.Error = "agent lost the control plane after apply; previous rules restored"
		return result
	}
	if port := sshPortOf(intent); port != "" {
		intent.SshPort = port
	}
	if err := persistState(intent, holes); err != nil {
		if needSSH {
			restoreSSHConfigs(sshSnap)
		}
		rollbackApply(prev, ping4, ping6)
		result.Status = v2.FirewallStatusError
		result.Error = err.Error()
		return result
	}
	_ = persistBootLocked(eng, intent, holes)
	live := withStacks(eng.snapshot())
	live.Kind = v2.FirewallKindApply
	live.Status = v2.FirewallStatusOK
	live.Revision = intent.Revision
	live.AppliedRules = enabledRules(intent)
	live.BlockPing4 = intent.BlockPing4
	live.BlockPing6 = intent.BlockPing6
	live.DefaultDeny4 = intent.DefaultDeny4
	live.DefaultDeny6 = intent.DefaultDeny6
	live.SshPort = sshPortOf(intent)
	live.KeepRules = keepRules(intent)
	return live
}

func Adopt(keys []string) v2.FirewallResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	eng := currentBackend()
	result := withStacks(eng.snapshot())
	result.Kind = v2.FirewallKindAdopt
	if !result.Supported || !result.Privileged {
		result.Status = v2.FirewallStatusUnsupported
		return result
	}
	prev, _ := eng.dumpHost()
	if err := eng.adopt(keys); err != nil {
		rollbackAdopt(prev)
		result.Status = v2.FirewallStatusError
		result.Error = err.Error()
		return result
	}
	if !watchdogOK() {
		rollbackAdopt(prev)
		result.Status = v2.FirewallStatusRolledBack
		result.Error = "agent lost the control plane after adopt; previous rules restored"
		return result
	}
	live := withStacks(eng.snapshot())
	live.Kind = v2.FirewallKindAdopt
	live.Status = v2.FirewallStatusOK
	return live
}

func defaultDenyConflict(snapshot v2.FirewallResultParams) bool {
	if snapshot.Backend == v2.FirewallBackendUFW || snapshot.Backend == v2.FirewallBackendFirewalld {
		return false
	}
	for _, name := range snapshot.OuterManagers {
		if name == v2.FirewallBackendUFW || name == v2.FirewallBackendFirewalld {
			return true
		}
	}
	return false
}

func withStacks(result v2.FirewallResultParams) v2.FirewallResultParams {
	v4, v6 := stackPresent()
	result.HasStacks = true
	result.StackV4 = v4
	result.StackV6 = v6
	return result
}

func stackPresent() (v4, v6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true, true
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			v4 = true
			continue
		}
		if ipnet.IP.To16() != nil {
			v6 = true
		}
	}
	if !v4 && !v6 {
		return true, true
	}
	return v4, v6
}

func stackAllowed(stack string) bool {
	v4, v6 := stackPresent()
	if stack == v2.FirewallStackV6 {
		return v6
	}
	return v4
}

func enabledRules(intent v2.FirewallIntent) []v2.FirewallRule {
	rules := append([]v2.FirewallRule(nil), intent.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})
	out := make([]v2.FirewallRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled && ruleSafe(rule) {
			out = append(out, rule)
		}
	}
	return out
}

type persistedFirewall struct {
	Intent        v2.FirewallIntent `json:"intent"`
	ListenHoles   []v2.FirewallHole `json:"listen_holes,omitempty"`
	UfwIncoming   string            `json:"ufw_incoming,omitempty"`
	WindowsPolicy string            `json:"windows_policy,omitempty"`
}

var lastWindowsPolicy string

func rollbackApply(prev []byte, ping4, ping6 bool) {
	if len(prev) > 0 {
		_ = currentBackend().restore(prev)
	}
	restoreAux(ping4, ping6)
	if loadPersist() != nil {
		_ = restorePersistedLocked()
		return
	}
	_ = currentBackend().resetOwned()
	_ = persistBootLocked(currentBackend(), v2.FirewallIntent{}, nil)
}

func rollbackAdopt(prev []byte) {
	if len(prev) > 0 {
		_ = currentBackend().restore(prev)
	}
	_ = restorePersistedLocked()
}

func RestorePersisted() error {
	opMu.Lock()
	defer opMu.Unlock()
	return restorePersistedLocked()
}

func restorePersistedLocked() error {
	state := loadPersist()
	if state == nil {
		return nil
	}
	lastWindowsPolicy = state.WindowsPolicy
	eng := currentBackend()
	snap := eng.snapshot()
	if !snap.Supported || !snap.Privileged {
		return nil
	}
	if port := sshPortOf(state.Intent); port != "" {
		state.Intent.SshPort = port
	}
	holes := liveHoles(state.Intent, mergeHoles(state.ListenHoles, holesFromIntent(state.Intent)))
	if err := eng.apply(state.Intent, holes); err != nil {
		return err
	}
	_ = persistState(state.Intent, holes)
	return persistBootLocked(eng, state.Intent, holes)
}

func holesFromIntent(intent v2.FirewallIntent) []v2.FirewallHole {
	if !intent.DefaultDeny4 && !intent.DefaultDeny6 {
		return nil
	}
	// Inbound-linked allows are already in intent.Rules. Copying them into
	// listen holes made Plus write the same ACCEPT twice when 同时放行 is on.
	return nil
}

func allowCoversHole(intent v2.FirewallIntent, hole v2.FirewallHole) bool {
	for _, rule := range enabledRules(intent) {
		if strings.EqualFold(strings.TrimSpace(rule.Action), v2.FirewallActionDeny) {
			continue
		}
		if strings.TrimSpace(rule.Source) != "" {
			continue
		}
		if !strings.EqualFold(rule.Protocol, hole.Protocol) {
			continue
		}
		if !allPorts(rule.Port) && rule.Port != hole.Port {
			continue
		}
		return true
	}
	return false
}

func liveHoles(intent v2.FirewallIntent, holes []v2.FirewallHole) []v2.FirewallHole {
	if len(holes) == 0 {
		return nil
	}
	out := make([]v2.FirewallHole, 0, len(holes))
	for _, hole := range holes {
		if !holeSafe(hole) || allowCoversHole(intent, hole) {
			continue
		}
		out = append(out, hole)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeHoles(groups ...[]v2.FirewallHole) []v2.FirewallHole {
	seen := map[string]struct{}{}
	out := make([]v2.FirewallHole, 0)
	for _, group := range groups {
		for _, hole := range group {
			if !holeSafe(hole) {
				continue
			}
			key := hole.Stack + "|" + hole.Protocol + "|" + hole.Port
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, hole)
		}
	}
	return out
}

func intentIdle(intent v2.FirewallIntent) bool {
	if intent.BlockPing4 || intent.BlockPing6 || intent.DefaultDeny4 || intent.DefaultDeny6 {
		return false
	}
	for _, rule := range intent.Rules {
		if rule.Enabled {
			return false
		}
	}
	return true
}

func persistState(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	state := persistedFirewall{
		Intent:        intent,
		ListenHoles:   holes,
		WindowsPolicy: lastWindowsPolicy,
	}
	if prev := loadPersist(); prev != nil && state.WindowsPolicy == "" {
		state.WindowsPolicy = prev.WindowsPolicy
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := statePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func loadPersist() *persistedFirewall {
	raw, err := os.ReadFile(statePath())
	if err != nil {
		return nil
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return nil
	}
	if _, ok := probe["intent"]; ok {
		var state persistedFirewall
		if json.Unmarshal(raw, &state) != nil {
			return nil
		}
		return &state
	}
	var intent v2.FirewallIntent
	if json.Unmarshal(raw, &intent) != nil {
		return nil
	}
	return &persistedFirewall{Intent: intent}
}

func statePath() string {
	dir := strings.TrimSpace(os.Getenv("AGENT_DATA_DIR"))
	if dir == "" {
		if home, err := os.UserConfigDir(); err == nil && home != "" {
			dir = filepath.Join(home, "lite-plus-agent")
		} else {
			dir = os.TempDir()
		}
	}
	return filepath.Join(dir, stateFileName)
}

func matchPort(value string) (string, string) {
	from, to, ok := strings.Cut(value, "-")
	if !ok {
		return value, value
	}
	return from, to
}
