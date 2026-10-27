//go:build linux

package firewall

import (
	"strings"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestNftTableScriptKeepsAllAllowPorts(t *testing.T) {
	v4, _ := stackPresent()
	if !v4 {
		t.Skip("no IPv4")
	}
	script := nftTableScript(v2.FirewallIntent{
		DefaultDeny4: true,
		SshPort:      "22",
		Rules: []v2.FirewallRule{
			{ID: "web", Enabled: true, Action: "allow", Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4},
			{ID: "panel", Enabled: true, Action: "allow", Protocol: "tcp", Port: "29777", Stack: v2.FirewallStackV4, Source: "39.0.0.0/8"},
			{ID: "all", Enabled: true, Action: "allow", Protocol: "tcp", Port: "*", Stack: v2.FirewallStackV4, Source: "10.240.3.4"},
		},
	}, []v2.FirewallHole{{Protocol: "tcp", Port: "8443", Stack: v2.FirewallStackV4}})
	for _, want := range []string{"dport 443", "dport 29777", "dport 8443", "dport 22", "ip saddr 10.240.3.4 tcp accept"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in\n%s", want, script)
		}
	}
}

func TestOwnedIptablesRestoreOnlyPlusChain(t *testing.T) {
	raw := `*filter
:INPUT ACCEPT [0:0]
:LITE_PLUS - [0:0]
-A INPUT -j 1PANEL_BASIC
-A INPUT -j LITE_PLUS
-A LITE_PLUS -i lo -j ACCEPT
-A LITE_PLUS -p tcp -m tcp --dport 443 -j ACCEPT
-A LITE_PLUS -p tcp -m tcp --dport 22 -j ACCEPT
-A LITE_PLUS -j DROP
COMMIT
`
	got := ownedIptablesRestore(raw, iptablesChain)
	if strings.Contains(got, "1PANEL") || strings.Contains(got, "-j LITE_PLUS") {
		t.Fatalf("must not restore host INPUT jumps: %s", got)
	}
	if !strings.Contains(got, "--dport 443") || !strings.Contains(got, "--dport 22") || !strings.Contains(got, "-j DROP") {
		t.Fatalf("missing plus chain ports: %s", got)
	}
}

func TestFirewallBootUnitFollowsHostFirewall(t *testing.T) {
	unit := firewallBootUnit()
	for _, want := range []string{
		"After=",
		"nftables.service",
		"fail2ban.service",
		"bt.service",
		"1panel.service",
		"ExecStart=",
		bootScriptFile,
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("missing %q in %s", want, unit)
		}
	}
	if strings.Contains(unit, "Before=ssh") {
		t.Fatal("boot unit must not delay sshd; agent watch restores after a later host flush")
	}
}

func TestFirewallBootScriptLoadsNftAndIptables(t *testing.T) {
	script := firewallBootScript()
	for _, want := range []string{"nft -f", "iptables-restore --noflush", "-I INPUT 1 -j", iptablesChain, nftTable} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("boot must not flush the host ruleset")
	}
	if !strings.Contains(script, `if [ -f "$V4_FILE" ] || [ -f "$V6_FILE" ]; then`) {
		t.Fatal("boot must drop leftover inet liteplus when plus already lives in iptables INPUT")
	}
	if !strings.Contains(script, "HOOKS_FILE=") || !strings.Contains(script, `jump $CHAIN`) {
		t.Fatal("boot must insert plus into an existing inet input chain")
	}
}
