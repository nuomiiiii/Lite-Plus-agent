//go:build !linux && !windows

package firewall

func captureAux() (v4, v6 bool) { return false, false }

func restoreAux(bool, bool) {}
