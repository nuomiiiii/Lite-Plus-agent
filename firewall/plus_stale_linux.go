//go:build linux

package firewall

import "strings"

func leftoverInetPlusTable() bool {
	out, err := runCmd(cmdTimeout, "nft", "list", "table", "inet", nftTable)
	return err == nil && strings.Contains(out, "chain")
}

func plusRulesStaleLinux() bool {
	if leftoverInetPlusTable() && hostOwnsIptablesFilter() {
		return true
	}
	if !hostOwnsIptablesFilter() {
		return false
	}
	out, err := runCmd(cmdTimeout, "iptables", "-S", "INPUT")
	return err != nil || !iptablesInputJumpsToPlus(out)
}
