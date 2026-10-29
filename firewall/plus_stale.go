package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func plusRulesStale() bool {
	return plusRulesStaleLinux()
}

// plusRulesStaleDecision reports that Plus is on the wrong hook and must be
// re-applied. ufw never uses the LITE_PLUS INPUT jump: its own chains always
// look like a foreign INPUT, so treating that as stale would delete and rewrite
// Plus rules every watch tick.
func plusRulesStaleDecision(kind string, leftoverPlus, hostOwns, iptablesLive, hasInetHooks, inetJumpLive bool) bool {
	if kind == v2.FirewallBackendUFW {
		if leftoverPlus {
			return true
		}
		if hasInetHooks && !inetJumpLive {
			return true
		}
		return false
	}
	if hasInetHooks {
		if leftoverPlus {
			return true
		}
		if !inetJumpLive {
			return true
		}
	}
	if leftoverPlus && hostOwns {
		return true
	}
	if hostOwns && !iptablesLive {
		return true
	}
	return false
}
