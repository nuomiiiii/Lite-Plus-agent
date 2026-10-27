package firewall

import "path/filepath"

const (
	bootUnitName      = "lite-plus-firewall.service"
	bootAgentDropin   = "firewall.conf"
	bootNftFile       = "firewall-boot.nft"
	bootNftHooksFile  = "firewall-boot.hooks"
	bootIptablesFile  = "firewall-boot.v4"
	bootIP6tablesFile = "firewall-boot.v6"
	bootScriptFile    = "firewall-boot.sh"
	nftablesDropin    = "/etc/nftables.d/lite-plus-agent.nft"
	bootUnitPath      = "/etc/systemd/system/" + bootUnitName
	agentUnitDir      = "/etc/systemd/system/lite-plus-agent.service.d"
)

func bootPath(name string) string {
	return filepath.Join(filepath.Dir(statePath()), name)
}
