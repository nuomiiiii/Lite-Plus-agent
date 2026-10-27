//go:build linux

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func keepRules(intent v2.FirewallIntent) []v2.FirewallRule {
	return filterOmittedKeep(intent, keepTCP(sshPortOf(intent), "SSH"))
}
