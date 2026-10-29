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

func TestNftTableScriptDropsHoleCoveredByAllow(t *testing.T) {
	v4, v6 := stackPresent()
	if !v4 && !v6 {
		t.Skip("no IP stack")
	}
	script := nftTableScript(v2.FirewallIntent{
		DefaultDeny4: true,
		DefaultDeny6: true,
		Rules: []v2.FirewallRule{
			{ID: "in", Enabled: true, Action: "allow", Protocol: "tcp", Port: "32688", Stack: v2.FirewallStackV4, Origin: v2.FirewallOriginInbound},
		},
	}, []v2.FirewallHole{
		{Protocol: "tcp", Port: "32688", Stack: v2.FirewallStackV4},
		{Protocol: "tcp", Port: "8443", Stack: v2.FirewallStackV4},
	})
	want32688 := 0
	want8443 := 0
	if v4 {
		want32688++
		want8443++
	}
	if v6 {
		want32688++
		want8443++
	}
	if got := strings.Count(script, "dport 32688"); got != want32688 {
		t.Fatalf("inbound allow + hole must write 32688 once per stack, got %d want %d in\n%s", got, want32688, script)
	}
	if got := strings.Count(script, "dport 8443"); got != want8443 {
		t.Fatalf("uncovered hole must remain, got %d want %d in\n%s", got, want8443, script)
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
	if !strings.Contains(script, "HOOKS_FILE=") || !strings.Contains(script, `jump "$CHAIN"`) {
		t.Fatal("boot must insert plus into an existing inet input chain")
	}
	jumpAt := strings.Index(script, `nft insert rule "$fam" "$tab" "$ch" jump "$CHAIN"`)
	loadAt := strings.Index(script, `[ -f "$NFT_FILE" ] && nft -f "$NFT_FILE"`)
	if jumpAt < 0 || loadAt < 0 || jumpAt > loadAt {
		t.Fatal("boot must insert the plus jump before loading marked allows so policy drop cannot sit in front")
	}
	if !strings.Contains(script, `nft flush chain "$fam" "$tab" "$CHAIN"`) {
		t.Fatal("boot must flush LITE_PLUS before reloading so old default-deny drops cannot shadow new allows")
	}
	if !strings.Contains(script, "lite-plus:") {
		t.Fatal("boot must remove previous plus accepts from inet input")
	}
}

func TestNftAttachScriptFlushesBeforeRules(t *testing.T) {
	script := nftAttachScript([]nftInputHook{{Family: "inet", Table: "filter", Chain: "input"}}, v2.FirewallIntent{
		DefaultDeny4: true,
		SshPort:      "22",
		Rules: []v2.FirewallRule{
			{ID: "web", Enabled: true, Action: "allow", Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4},
		},
	}, nil)
	flushAt := strings.Index(script, "flush chain inet filter "+plusIptablesChain)
	allowAt := strings.LastIndex(script, "dport 443")
	dropAt := strings.LastIndex(script, "meta nfproto ipv4 drop")
	if flushAt < 0 || allowAt < 0 || dropAt < 0 {
		t.Fatalf("missing flush/allow/drop in\n%s", script)
	}
	if flushAt > allowAt || flushAt > dropAt {
		t.Fatal("flush must come before plus rules so a second apply does not leave the old drop in front of new allows")
	}
	if !strings.Contains(script, "insert rule inet filter input") || !strings.Contains(script, `comment "lite-plus:web"`) {
		t.Fatal("attach script must insert plus allows into inet input so a later policy drop cannot ignore jumped accepts")
	}
}

func TestNftTableScriptFlushesBeforeRules(t *testing.T) {
	script := nftTableScript(v2.FirewallIntent{
		DefaultDeny4: true,
		SshPort:      "22",
		Rules: []v2.FirewallRule{
			{ID: "web", Enabled: true, Action: "allow", Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4},
		},
	}, nil)
	flushAt := strings.Index(script, "flush chain inet "+nftTable+" input")
	allowAt := strings.LastIndex(script, "dport 443")
	dropAt := strings.LastIndex(script, "meta nfproto ipv4 drop")
	if flushAt < 0 || allowAt < 0 || dropAt < 0 {
		t.Fatalf("missing flush/allow/drop in\n%s", script)
	}
	if flushAt > allowAt || flushAt > dropAt {
		t.Fatal("owned nft table must flush input before rewriting so nft -f cannot append an old drop in front of new allows")
	}
}
