//go:build linux

package firewall

import (
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func engOwned(eng backend) bool {
	switch eng.name() {
	case v2.FirewallBackendNFT:
		out, err := runCmd(cmdTimeout, "nft", "list", "table", "inet", nftTable)
		return err == nil && strings.Contains(out, "chain")
	case v2.FirewallBackendIptables:
		_, err := runCmd(cmdTimeout, "iptables", "-n", "-L", iptablesChain)
		return err == nil
	case v2.FirewallBackendUFW:
		out, err := runCmd(cmdTimeout, "ufw", "status", "numbered")
		return err == nil && strings.Contains(out, "lite-plus:")
	case v2.FirewallBackendFirewalld:
		out, err := runCmd(cmdTimeout, "firewall-cmd", "--direct", "--get-chains", "ipv4", "filter")
		return err == nil && strings.Contains(out, iptablesChain)
	default:
		return true
	}
}
