//go:build linux

package firewall

func captureAux() (v4, v6 bool) {
	return pingBlocked(4), pingBlocked(6)
}

func restoreAux(v4, v6 bool) {
	_ = applyPing(v4, v6)
}
