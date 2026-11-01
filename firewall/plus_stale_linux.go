//go:build linux

package firewall

func listPlusInetTable() (string, error) {
	return runCmd(cmdTimeout, "nft", "list", "table", "inet", nftTable)
}

func leftoverInetPlusTable() bool {
	out, err := listPlusInetTable()
	return err == nil && nftTableLooksPresent(out)
}
