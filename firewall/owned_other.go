//go:build !linux && !windows

package firewall

func engOwned(_ backend) bool { return true }
