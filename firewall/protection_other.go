//go:build !linux

package firewall

import (
	"runtime"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func probeProtectionCapabilityLocked() v2.ProtectionCapability {
	return v2.ProtectionCapability{
		Platform:    runtime.GOOS,
		Linux:       false,
		Privileged:  false,
		NftPresent:  false,
		ManualHints: []string{"此防护功能需要 Linux nftables"},
		ScopeNote:   "Windows 和其他非 Linux 节点不能加入可执行联动组。",
	}
}

func protectionPrecheckLocked() v2.ProtectionResultParams {
	cap := probeProtectionCapabilityLocked()
	return v2.ProtectionResultParams{
		Kind:       v2.ProtectionKindPrecheck,
		Status:     v2.ProtectionStatusUnsupported,
		Error:      "此防护功能需要 Linux nftables",
		Capability: &cap,
		Phase:      v2.ProtectionUpgradePhaseFailed,
	}
}

func protectionUpgradePrepareLocked(opID string) (v2.ProtectionResultParams, bool, bool, bool) {
	result := protectionPrecheckLocked()
	result.Kind = v2.ProtectionKindUpgrade
	result.OpID = opID
	return result, false, false, false
}

func protectionUpgradeEnableLocked(result v2.ProtectionResultParams) v2.ProtectionResultParams {
	return result
}

func installOrUpdateNftables(bool, bool) error { return nil }

func ptrCap(cap v2.ProtectionCapability) *v2.ProtectionCapability { return &cap }

func enableProtectionRuntimeLocked(*persistedProtection, bool) error {
	return nil
}

func syncProtectionBansLocked(*persistedProtection) error {
	noteProtectionEnableOK()
	return nil
}

func protectionPreviewLocked(p v2.ProtectionPreviewParams) v2.ProtectionResultParams {
	return v2.ProtectionResultParams{
		Kind:   v2.ProtectionKindPreview,
		Status: v2.ProtectionStatusUnsupported,
		Error:  "此防护功能需要 Linux nftables",
	}
}

func persistProtectionBootLocked() error { return nil }

func disableProtectionRuntimeLocked(*persistedProtection) error { return nil }

func protectionTableLive() bool { return false }

func skipProtectionInetTable(table string) bool {
	return strings.EqualFold(strings.TrimSpace(table), protectionNftTable)
}

func sampleProtectionCounters() []v2.ProtectionNflogSample {
	return nil
}
