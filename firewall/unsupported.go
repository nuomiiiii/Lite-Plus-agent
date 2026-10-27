//go:build !linux && !windows

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

type noneBackend struct{}

func currentBackend() backend { return noneBackend{} }

func (noneBackend) name() string { return v2.FirewallBackendNone }

func (noneBackend) snapshot() v2.FirewallResultParams {
	return v2.FirewallResultParams{
		Kind:      v2.FirewallKindSnapshot,
		Status:    v2.FirewallStatusUnsupported,
		Backend:   v2.FirewallBackendNone,
		Supported: false,
		Error:     "当前系统暂不支持主机防火墙",
	}
}

func (noneBackend) apply(v2.FirewallIntent, []v2.FirewallHole) error { return errUnsupported }
func (noneBackend) adopt([]string) error                             { return errUnsupported }
func (noneBackend) dump() ([]byte, error)                            { return nil, nil }
func (noneBackend) dumpHost() ([]byte, error)                        { return nil, nil }
func (noneBackend) restore([]byte) error                             { return nil }
func (noneBackend) resetOwned() error                                { return nil }
