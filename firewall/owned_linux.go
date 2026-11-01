//go:build linux

package firewall

import (
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func firewalldDirectLive() bool {
	if stackAllowed(v2.FirewallStackV4) {
		out, err := runCmd(cmdTimeout, "firewall-cmd", "--direct", "--get-chains", "ipv4", "filter")
		if err != nil || !strings.Contains(out, iptablesChain) {
			return false
		}
		if nftPersistWantsBaseAllows() {
			marked, err := runCmd(cmdTimeout, "iptables", "-S", iptablesChain)
			if err == nil && !strings.Contains(marked, plusCommentMark) {
				return false
			}
		}
	}
	if stackAllowed(v2.FirewallStackV6) {
		out, err := runCmd(cmdTimeout, "firewall-cmd", "--direct", "--get-chains", "ipv6", "filter")
		if err != nil || !strings.Contains(out, iptablesChain) {
			return false
		}
		if nftPersistWantsBaseAllows() && lookPath("ip6tables") {
			marked, err := runCmd(cmdTimeout, "ip6tables", "-S", iptablesChain)
			if err == nil && !strings.Contains(marked, plusCommentMark) {
				return false
			}
		}
	}
	return true
}
