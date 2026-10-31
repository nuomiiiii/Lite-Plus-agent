package firewall

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestStackPresent(t *testing.T) {
	v4, v6 := stackPresent()
	if !v4 && !v6 {
		t.Fatal("expected at least one IP stack")
	}
}

func TestStacksFromAddrsIgnoresLoopbackAndLinkLocal(t *testing.T) {
	v4, v6 := stacksFromAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("169.254.1.1"), Mask: net.CIDRMask(16, 32)},
	})
	if v4 || v6 {
		t.Fatal("loopback-only must not pretend the host has a public stack")
	}
	v4, v6 = stacksFromAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("203.0.113.8"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	})
	if !v4 || v6 {
		t.Fatalf("public v4 plus loopback v6 must be v4-only, got v4=%v v6=%v", v4, v6)
	}
	v4, v6 = stacksFromAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
	})
	if v4 || !v6 {
		t.Fatalf("public v6 plus loopback v4 must be v6-only, got v4=%v v6=%v", v4, v6)
	}
	v4, v6 = stacksFromAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
	})
	if !v4 || !v6 {
		t.Fatal("private v4 and ULA v6 must both count")
	}
	v4, v6 = stacksFromAddrs(nil)
	if v4 || v6 {
		t.Fatal("no usable address must not invent dual-stack")
	}
}

func TestPersistStateRoundTrip(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	origW := lastWindowsPolicy
	t.Cleanup(func() {
		lastWindowsPolicy = origW
	})
	lastWindowsPolicy = "blockinbound,allowoutbound"
	holes := []v2.FirewallHole{{Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4}}
	if err := persistState(v2.FirewallIntent{Revision: 3, BlockPing4: true, SshPort: "2222"}, holes); err != nil {
		t.Fatal(err)
	}
	lastWindowsPolicy = ""
	got := loadPersist()
	if got == nil || !got.Intent.BlockPing4 || !got.Intent.BlockPing6 || got.Intent.SshPort != "2222" || got.UfwIncoming != "" || got.WindowsPolicy != "blockinbound,allowoutbound" {
		t.Fatalf("%+v", got)
	}
	if len(got.ListenHoles) != 1 || got.ListenHoles[0].Port != "443" {
		t.Fatalf("holes %+v", got.ListenHoles)
	}
	v4, v6 := stackPresent()
	if !got.AppliedStacks || got.AppliedV4 != v4 || got.AppliedV6 != v6 {
		t.Fatalf("applied stacks %+v want v4=%v v6=%v", got, v4, v6)
	}
	known4, known6, ok := lastKnownStacks()
	if !ok || known4 != got.AppliedV4 || known6 != got.AppliedV6 {
		t.Fatalf("last known stacks %v %v %v", known4, known6, ok)
	}
}

func TestStacksChangedSincePersist(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	if stacksChangedSincePersist() {
		t.Fatal("no persist must not reapply")
	}
	if err := persistState(v2.FirewallIntent{Revision: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if stacksChangedSincePersist() {
		t.Fatal("fresh persist must match current stacks")
	}
	got := loadPersist()
	if got == nil {
		t.Fatal("missing persist")
	}
	got.AppliedV4 = !got.AppliedV4
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("AGENT_DATA_DIR"), stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if !stacksChangedSincePersist() {
		t.Fatal("nic change must reapply persisted rules onto the new stack")
	}
}

func TestOldPersistWithoutAppliedStacksMustReapply(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	raw, err := json.Marshal(persistedFirewall{Intent: v2.FirewallIntent{Revision: 1, DefaultDeny4: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if !stacksChangedSincePersist() {
		t.Fatal("old persist without applied_stacks must reapply once")
	}
}

func TestUnifyPairedPolicyCopiesOneSidedSwitch(t *testing.T) {
	intent := v2.FirewallIntent{DefaultDeny4: true, BlockPing6: true}
	unifyPairedPolicy(&intent)
	if !intent.DefaultDeny4 || !intent.DefaultDeny6 || !intent.BlockPing4 || !intent.BlockPing6 {
		t.Fatalf("one switch must persist both stacks: %+v", intent)
	}
}

func TestPersistStateDoesNotKeepUfwIncoming(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	raw, err := json.Marshal(persistedFirewall{
		Intent:      v2.FirewallIntent{Revision: 1},
		UfwIncoming: "deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistState(v2.FirewallIntent{Revision: 2}, nil); err != nil {
		t.Fatal(err)
	}
	got := loadPersist()
	if got == nil || got.Intent.Revision != 2 || got.UfwIncoming != "" {
		t.Fatalf("ufw incoming must not be copied forward: %+v", got)
	}
}

func TestRestorePersistedMissingState(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	if err := RestorePersisted(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistStateWritesResolvedSSHPort(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	if err := persistState(v2.FirewallIntent{Revision: 4, DefaultDeny4: true, SshPort: "2200"}, nil); err != nil {
		t.Fatal(err)
	}
	got := loadPersist()
	if got == nil || got.Intent.SshPort != "2200" {
		t.Fatalf("%+v", got)
	}
}

func TestHolesFromIntentAndIdle(t *testing.T) {
	if !intentIdle(v2.FirewallIntent{}) {
		t.Fatal("empty intent is idle")
	}
	if intentIdle(v2.FirewallIntent{BlockPing4: true}) {
		t.Fatal("ping is not idle")
	}
	intent := v2.FirewallIntent{
		DefaultDeny4: true,
		Rules: []v2.FirewallRule{
			{Origin: v2.FirewallOriginInbound, Enabled: true, Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4},
			{Origin: v2.FirewallOriginWeb, Enabled: true, Protocol: "tcp", Port: "22", Stack: v2.FirewallStackV4},
		},
	}
	if holes := holesFromIntent(intent); len(holes) != 0 {
		t.Fatalf("inbound allow must not also become a listen hole: %+v", holes)
	}
	merged := mergeHoles(nil, nil, []v2.FirewallHole{{Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4}, {Protocol: "tcp", Port: "80", Stack: v2.FirewallStackV4}})
	if len(merged) != 2 {
		t.Fatalf("merge holes: %+v", merged)
	}
}

func TestLiveHolesDropsCoveredInbound(t *testing.T) {
	intent := v2.FirewallIntent{
		DefaultDeny4: true,
		Rules: []v2.FirewallRule{
			{Enabled: true, Action: "allow", Protocol: "tcp", Port: "32688", Stack: v2.FirewallStackV4, Origin: v2.FirewallOriginInbound},
			{Enabled: true, Action: "allow", Protocol: "tcp", Port: "32800", Stack: v2.FirewallStackV4, Origin: v2.FirewallOriginWeb, Source: "10.0.0.1"},
		},
	}
	got := liveHoles(intent, []v2.FirewallHole{
		{Protocol: "tcp", Port: "32688", Stack: v2.FirewallStackV4},
		{Protocol: "tcp", Port: "8443", Stack: v2.FirewallStackV4},
		{Protocol: "tcp", Port: "32800", Stack: v2.FirewallStackV4},
	})
	if len(got) != 2 || got[0].Port != "8443" || got[1].Port != "32800" {
		t.Fatalf("covered inbound must drop, sourced allow must keep hole: %+v", got)
	}
}

func TestLiveHolesDoesNotCoverOtherStack(t *testing.T) {
	intent := v2.FirewallIntent{
		DefaultDeny4: true,
		Rules: []v2.FirewallRule{
			{Enabled: true, Action: "allow", Protocol: "tcp", Port: "2083", Stack: v2.FirewallStackV6},
		},
	}
	got := liveHoles(intent, []v2.FirewallHole{{Protocol: "tcp", Port: "2083", Stack: v2.FirewallStackV4}})
	if len(got) != 1 || got[0].Port != "2083" || got[0].Stack != v2.FirewallStackV4 {
		t.Fatalf("v6 unsourced allow must not cover a v4 hole: %+v", got)
	}
}

func TestLoadPersistLegacyIntent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	raw, err := json.Marshal(v2.FirewallIntent{Revision: 2, DefaultDeny4: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadPersist()
	if got == nil || !got.Intent.DefaultDeny4 || got.Intent.Revision != 2 {
		t.Fatalf("%+v", got)
	}
}
