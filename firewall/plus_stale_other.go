//go:build !linux

package firewall

func plusRulesStaleLinux() bool { return false }
