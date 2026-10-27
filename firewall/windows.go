//go:build windows

package firewall

import (
	"os"
	"path/filepath"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const windowsGroup = "Lite Plus"

type windowsBackend struct{}

func currentBackend() backend { return windowsBackend{} }

func (windowsBackend) name() string { return v2.FirewallBackendWindows }

func (windowsBackend) snapshot() v2.FirewallResultParams {
	out, _ := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	return v2.FirewallResultParams{
		Kind:       v2.FirewallKindSnapshot,
		Status:     v2.FirewallStatusOK,
		Backend:    v2.FirewallBackendWindows,
		Privileged: true,
		Supported:  true,
		KeepRules:  keepRules(v2.FirewallIntent{}),
		SshPort:    detectedSSHPort(),
		HostRules:  parseWindowsRules(out),
		BlockPing4: windowsPingBlocked(4),
		BlockPing6: windowsPingBlocked(6),
	}
}

func (windowsBackend) apply(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	savedPolicy := rememberWindowsPolicy()
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		current := strings.ReplaceAll(strings.ToLower(windowsFirewallPolicy()), " ", "")
		if strings.Contains(current, "blockinbound") {
			_, _ = runCmd(cmdTimeout, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,allowoutbound")
		}
	}
	_ = clearWindowsGroup()
	if err := applyWindowsPing(intent.BlockPing4, intent.BlockPing6); err != nil {
		return err
	}
	holes = liveHoles(intent, holes)
	if intentIdle(intent) {
		if savedPolicy != "" {
			_, err := runCmd(cmdTimeout, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", savedPolicy)
			return err
		}
		return nil
	}
	for _, rule := range enabledRules(intent) {
		if !stackAllowed(rule.Stack) {
			continue
		}
		if err := addWindowsRule(rule); err != nil {
			return err
		}
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		for _, hole := range holes {
			if !stackAllowed(hole.Stack) || !holeSafe(hole) {
				continue
			}
			if err := addWindowsRule(v2.FirewallRule{
				ID:       "hole-" + hole.Stack + "-" + hole.Port,
				Enabled:  true,
				Action:   v2.FirewallActionAllow,
				Protocol: hole.Protocol,
				Port:     hole.Port,
				Stack:    hole.Stack,
				Comment:  hole.Comment,
			}); err != nil {
				return err
			}
		}
		var keepErr error
		eachKeepRule(intent, func(rule v2.FirewallRule) {
			if keepErr != nil {
				return
			}
			keepErr = addWindowsRule(rule)
		})
		if keepErr != nil {
			return keepErr
		}
		if !intent.DefaultDeny4 && stackAllowed(v2.FirewallStackV4) {
			if err := addWindowsAllowAny(v2.FirewallStackV4); err != nil {
				return err
			}
		}
		if !intent.DefaultDeny6 && stackAllowed(v2.FirewallStackV6) {
			if err := addWindowsAllowAny(v2.FirewallStackV6); err != nil {
				return err
			}
		}
		lastWindowsPolicy = savedPolicy
		if _, err := runCmd(cmdTimeout, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"); err != nil {
			return err
		}
	} else if savedPolicy != "" {
		if _, err := runCmd(cmdTimeout, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", savedPolicy); err != nil {
			return err
		}
	}
	return nil
}

func (windowsBackend) adopt(keys []string) error {
	wanted := map[string]struct{}{}
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	out, _ := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in")
	for _, rule := range parseWindowsRules(out) {
		if _, ok := wanted[rule.Key]; !ok || !rule.Adoptable || rule.Comment == "" {
			continue
		}
		if _, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "delete", "rule", "name="+rule.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (windowsBackend) dump() ([]byte, error) {
	return windowsPolicyDump(), nil
}

func (windowsBackend) dumpHost() ([]byte, error) {
	dir, err := os.MkdirTemp("", "liteplus-wfw-*")
	if err != nil {
		return windowsPolicyDump(), nil
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "fw.wfw")
	if _, err := runCmd(dumpTimeout, "netsh", "advfirewall", "export", path); err != nil {
		return windowsPolicyDump(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return windowsPolicyDump(), nil
	}
	return raw, nil
}

func windowsPolicyDump() []byte {
	return []byte("POLICY " + windowsFirewallPolicy() + "\n")
}

func (windowsBackend) restore(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if strings.HasPrefix(string(raw), "POLICY ") {
		first, _, _ := strings.Cut(string(raw), "\n")
		policy := normalizeWindowsPolicy(strings.TrimSpace(strings.TrimPrefix(first, "POLICY ")))
		if policy == "" {
			return nil
		}
		_, err := runCmd(cmdTimeout, "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy)
		return err
	}
	dir, err := os.MkdirTemp("", "liteplus-wfw-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "fw.wfw")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return err
	}
	_, err = runCmd(dumpTimeout, "netsh", "advfirewall", "import", path)
	return err
}

func (windowsBackend) resetOwned() error {
	return clearWindowsGroup()
}

func rememberWindowsPolicy() string {
	if lastWindowsPolicy != "" {
		return lastWindowsPolicy
	}
	if prev := loadPersist(); prev != nil && prev.WindowsPolicy != "" {
		return prev.WindowsPolicy
	}
	return windowsFirewallPolicy()
}

func windowsFirewallPolicy() string {
	out, err := runCmd(cmdTimeout, "netsh", "advfirewall", "show", "allprofiles")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if policy := parseWindowsPolicyLine(line); policy != "" {
			return policy
		}
	}
	return ""
}

func parseWindowsPolicyLine(line string) string {
	trim := strings.TrimSpace(line)
	lower := strings.ToLower(trim)
	if strings.HasPrefix(lower, "firewall policy") || strings.Contains(trim, "防火墙策略") {
		return normalizeWindowsPolicy(trim)
	}
	return ""
}

func normalizeWindowsPolicy(raw string) string {
	compact := strings.ToLower(strings.ReplaceAll(raw, " ", ""))
	if strings.Contains(compact, "blockinboundalways") || strings.Contains(raw, "始终阻止") {
		return "blockinboundalways,allowoutbound"
	}
	if strings.Contains(compact, "blockinbound") || strings.Contains(raw, "阻止入站") {
		return "blockinbound,allowoutbound"
	}
	if strings.Contains(compact, "allowinbound") || strings.Contains(raw, "允许入站") {
		return "allowinbound,allowoutbound"
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	last := fields[len(fields)-1]
	if strings.Contains(last, ",") {
		return last
	}
	return ""
}

func addWindowsAllowAny(stack string) error {
	name := "Lite Plus allow unmatched IPv4"
	localip := "0.0.0.0/0"
	if stack == v2.FirewallStackV6 {
		name = "Lite Plus allow unmatched IPv6"
		localip = "::/0"
	}
	_, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "add", "rule",
		"name="+name,
		"group="+windowsGroup,
		"dir=in",
		"action=allow",
		"protocol=any",
		"localip="+localip,
		"profile=any",
		"enable=yes",
	)
	return err
}

func clearWindowsGroup() error {
	_, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "delete", "rule", "group="+windowsGroup)
	return err
}

func addWindowsRule(rule v2.FirewallRule) error {
	action := "allow"
	if rule.Action == v2.FirewallActionDeny {
		action = "block"
	}
	name := "Lite Plus " + rule.ID
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"group=" + windowsGroup,
		"dir=in",
		"action=" + action,
		"protocol=" + rule.Protocol,
		"profile=any",
		"enable=yes",
	}
	if allPorts(rule.Port) {
		args = append(args, "localport=any")
	} else {
		args = append(args, "localport="+strings.ReplaceAll(rule.Port, "-", "-"))
	}
	if rule.Source != "" {
		args = append(args, "remoteip="+rule.Source)
	}
	if rule.Stack == v2.FirewallStackV6 {
		args = append(args, "localip=::/0")
	}
	_, err := runCmd(cmdTimeout, "netsh", args...)
	return err
}

func applyWindowsPing(v4, v6 bool) error {
	_, _ = runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "delete", "rule", "name=Lite Plus Block ICMPv4 Echo")
	_, _ = runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "delete", "rule", "name=Lite Plus Block ICMPv6 Echo")
	if v4 && stackAllowed(v2.FirewallStackV4) {
		if _, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "add", "rule",
			"name=Lite Plus Block ICMPv4 Echo", "group="+windowsGroup, "dir=in", "action=block", "protocol=icmpv4:8,any"); err != nil {
			return err
		}
	}
	if v6 && stackAllowed(v2.FirewallStackV6) {
		if _, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "add", "rule",
			"name=Lite Plus Block ICMPv6 Echo", "group="+windowsGroup, "dir=in", "action=block", "protocol=icmpv6:128,any"); err != nil {
			return err
		}
	}
	return nil
}

func windowsPingBlocked(family int) bool {
	name := "Lite Plus Block ICMPv4 Echo"
	if family == 6 {
		name = "Lite Plus Block ICMPv6 Echo"
	}
	out, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "show", "rule", "name="+name)
	return err == nil && strings.Contains(strings.ToLower(out), "enabled") && strings.Contains(strings.ToLower(out), "yes")
}

