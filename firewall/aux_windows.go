//go:build windows

package firewall

func captureAux() (v4, v6 bool) {
	return windowsPingBlocked(4), windowsPingBlocked(6)
}

func restoreAux(v4, v6 bool) {
	_ = applyWindowsPing(v4, v6)
}
