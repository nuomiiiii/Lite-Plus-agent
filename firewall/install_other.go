//go:build !linux

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func installNftables() v2.FirewallResultParams {
	result := currentBackend().snapshot()
	result.Kind = v2.FirewallKindInstall
	result.Status = v2.FirewallStatusUnsupported
	result.Error = "nftables 仅支持 Linux"
	result.CanInstallNftables = false
	return result
}

func canInstallNftables() bool { return false }
