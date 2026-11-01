//go:build linux

package firewall

import (
	"encoding/json"
	"os"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func probeOwnedWatch() (stale, live bool) {
	prev := persistedBackend()
	kind := watchBackendKind()
	plusTable, plusErr := listPlusInetTable()
	leftover := plusErr == nil && nftTableLooksPresent(plusTable)
	hooks := liveForeignInetInputHooks()
	inetJumpLive := inetPlusJumpLive(hooks)
	iptablesLive := false
	if kind == v2.FirewallBackendIptables || kind == v2.FirewallBackendFirewalld {
		iptablesLive = iptablesPlusLive()
	}
	hostOwns := watchHostOwns(kind, leftover)
	if plusRulesStaleDecision(kind, leftover, hostOwns, iptablesLive, len(hooks) > 0, inetJumpLive) {
		return true, false
	}
	if prev != "" && prev != kind {
		return false, false
	}
	switch kind {
	case v2.FirewallBackendUFW:
		return false, ufwPlusLive()
	case v2.FirewallBackendFirewalld:
		if iptablesLive {
			return false, true
		}
		return false, firewalldDirectLive()
	case v2.FirewallBackendIptables:
		return false, iptablesLive
	case v2.FirewallBackendNFT:
		if len(hooks) == 0 {
			return false, plusErr == nil && nftTableLooksLive(plusTable, nftPersistWantsBaseAllows())
		}
		return false, inetJumpLive
	default:
		return false, true
	}
}

func watchBackendKind() string {
	persisted := persistedBackend()
	if persisted != v2.FirewallBackendUFW && ufwActive() {
		rememberAppliedBackend(v2.FirewallBackendUFW)
		return v2.FirewallBackendUFW
	}
	if persisted == v2.FirewallBackendUFW {
		if ufwInactiveByConf() {
			persisted = ""
		} else {
			return v2.FirewallBackendUFW
		}
	}
	if persisted != v2.FirewallBackendFirewalld && firewalldActive() {
		rememberAppliedBackend(v2.FirewallBackendFirewalld)
		return v2.FirewallBackendFirewalld
	}
	if persisted == v2.FirewallBackendFirewalld {
		if !firewalldRuntimePresent() {
			persisted = ""
		} else {
			return v2.FirewallBackendFirewalld
		}
	}
	if persisted != "" && persisted != v2.FirewallBackendNone {
		return persisted
	}
	kind := detectLinuxBackend()
	rememberAppliedBackend(kind)
	return kind
}

func persistedBackend() string {
	state := loadPersist()
	if state == nil {
		return ""
	}
	return state.AppliedBackend
}

func rememberAppliedBackend(kind string) {
	if kind == "" || kind == v2.FirewallBackendNone {
		return
	}
	state := loadPersist()
	if state == nil || state.AppliedBackend == kind {
		return
	}
	state.AppliedBackend = kind
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	_ = os.WriteFile(statePath(), raw, 0o600)
}

func watchHostOwns(kind string, leftover bool) bool {
	switch kind {
	case v2.FirewallBackendUFW:
		return false
	case v2.FirewallBackendIptables:
		return true
	case v2.FirewallBackendFirewalld:
		return leftover
	case v2.FirewallBackendNFT:
		return leftover && hostOwnsIptablesFilter()
	default:
		return false
	}
}

func ufwPlusLive() bool {
	for _, path := range []string{ufwUserRules, ufwUser6Rules} {
		raw, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(raw), plusCommentMark) {
			return true
		}
	}
	out, err := runCmd(cmdTimeout, "ufw", "status", "numbered")
	return err == nil && strings.Contains(out, plusCommentMark)
}
