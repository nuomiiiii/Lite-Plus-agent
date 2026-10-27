//go:build windows

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func keepRules(intent v2.FirewallIntent) []v2.FirewallRule {
	var out []v2.FirewallRule
	out = append(out, keepTCP("3389", "RDP")...)
	out = append(out, keepTCP("5985", "WinRM")...)
	out = append(out, keepTCP("5986", "WinRM HTTPS")...)
	out = append(out, keepTCP(sshPortOf(intent), "SSH")...)
	return filterOmittedKeep(intent, out)
}
