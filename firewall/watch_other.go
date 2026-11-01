//go:build !linux

package firewall

func probeOwnedWatch() (stale, live bool) {
	return false, plusWatchLive()
}
