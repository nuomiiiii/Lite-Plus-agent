//go:build linux

package firewall

import "strings"

func leftoverInetPlusTable() bool {
	out, err := runCmd(cmdTimeout, "nft", "list", "table", "inet", nftTable)
	return err == nil && strings.Contains(out, "chain")
}

func plusRulesStaleLinux() bool {
	return hostOwnsIptablesFilter() && leftoverInetPlusTable()
}
