//go:build !linux

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func liveForeignInetInputHooks() []nftInputHook { return nil }

func attachPlusToForeignInet(v2.FirewallIntent, []v2.FirewallHole) error { return nil }

func detachPlusFromForeignInet() {}

func nftPlusLive() bool { return true }
