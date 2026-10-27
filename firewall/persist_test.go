package firewall

import (
	"encoding/json"
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
	if got == nil || !got.Intent.BlockPing4 || got.Intent.SshPort != "2222" || got.UfwIncoming != "" || got.WindowsPolicy != "blockinbound,allowoutbound" {
		t.Fatalf("%+v", got)
	}
	if len(got.ListenHoles) != 1 || got.ListenHoles[0].Port != "443" {
		t.Fatalf("holes %+v", got.ListenHoles)
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
	holes := holesFromIntent(intent)
	if len(holes) != 1 || holes[0].Port != "443" {
		t.Fatalf("%+v", holes)
	}
	merged := mergeHoles(nil, holes, []v2.FirewallHole{{Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4}, {Protocol: "tcp", Port: "80", Stack: v2.FirewallStackV4}})
	if len(merged) != 2 {
		t.Fatalf("merge holes: %+v", merged)
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
