//go:build !linux

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func persistBootLocked(_ backend, _ v2.FirewallIntent, _ []v2.FirewallHole) error {
	return nil
}
