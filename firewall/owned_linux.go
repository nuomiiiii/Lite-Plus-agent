//go:build linux

package firewall

import (
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func engOwned(eng backend) bool {
	switch eng.name() {
	case v2.FirewallBackendNFT:
		return nftPlusLive()
	case v2.FirewallBackendIptables:
		return iptablesPlusLive()
	case v2.FirewallBackendUFW:
		out, err := runCmd(cmdTimeout, "ufw", "status", "numbered")
		return err == nil && strings.Contains(out, "lite-plus:")
	case v2.FirewallBackendFirewalld:
		if stackAllowed(v2.FirewallStackV4) {
			out, err := runCmd(cmdTimeout, "firewall-cmd", "--direct", "--get-chains", "ipv4", "filter")
			if err != nil || !strings.Contains(out, iptablesChain) {
				return false
			}
		}
		if stackAllowed(v2.FirewallStackV6) {
			out, err := runCmd(cmdTimeout, "firewall-cmd", "--direct", "--get-chains", "ipv6", "filter")
			if err != nil || !strings.Contains(out, iptablesChain) {
				return false
			}
		}
		return true
	default:
		return true
	}
}
