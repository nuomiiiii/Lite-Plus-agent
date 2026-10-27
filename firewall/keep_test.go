package firewall

import (
	"strings"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestKeepRulesAreVisibleAllows(t *testing.T) {
	rules := keepRules(v2.FirewallIntent{})
	if len(rules) == 0 {
		t.Skip("no keep holes on this OS")
	}
	for _, rule := range rules {
		if rule.Origin != v2.FirewallOriginKeep || rule.Action != v2.FirewallActionAllow || rule.Protocol != v2.FirewallProtoTCP || rule.Port == "" || rule.Comment == "" {
			t.Fatalf("%+v", rule)
		}
	}
}

func TestEachKeepRuleFollowsDefaultDeny(t *testing.T) {
	var off int
	eachKeepRule(v2.FirewallIntent{}, func(v2.FirewallRule) { off++ })
	if off != 0 {
		t.Fatalf("deny off must not emit keep: %d", off)
	}
	if len(keepRules(v2.FirewallIntent{})) == 0 {
		return
	}
	var on int
	eachKeepRule(v2.FirewallIntent{DefaultDeny4: true, DefaultDeny6: true}, func(v2.FirewallRule) { on++ })
	if on == 0 {
		t.Fatal("deny on must emit keep holes")
	}
}

func TestKeepRulesUseIntentSSHPort(t *testing.T) {
	rules := keepRules(v2.FirewallIntent{SshPort: "2222"})
	var ssh int
	for _, rule := range rules {
		if rule.Comment != "SSH" {
			continue
		}
		ssh++
		if rule.Port != "2222" || rule.Origin != v2.FirewallOriginKeep || rule.Action != v2.FirewallActionAllow {
			t.Fatalf("%+v", rule)
		}
	}
	if ssh == 0 {
		t.Fatal("configured ssh port must emit a keep allow")
	}
	eachKeepRule(v2.FirewallIntent{DefaultDeny4: true, DefaultDeny6: true, SshPort: "2222"}, func(rule v2.FirewallRule) {
		if rule.Comment == "SSH" && rule.Port != "2222" {
			t.Fatalf("deny keep must follow ssh port: %+v", rule)
		}
	})
}

func TestKeepRulesOmitSSH(t *testing.T) {
	rules := keepRules(v2.FirewallIntent{OmitKeep: []string{"ssh"}, SshPort: "2222"})
	for _, rule := range rules {
		if strings.EqualFold(rule.Comment, "SSH") {
			t.Fatalf("omitted ssh keep still present: %+v", rule)
		}
	}
	eachKeepRule(v2.FirewallIntent{DefaultDeny4: true, DefaultDeny6: true, OmitKeep: []string{"ssh"}, SshPort: "2222"}, func(rule v2.FirewallRule) {
		if strings.EqualFold(rule.Comment, "SSH") {
			t.Fatalf("omitted ssh keep still applied: %+v", rule)
		}
	})
}

func TestRuleSafeRejectsInjection(t *testing.T) {
	ok := v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4"}
	if !ruleSafe(ok) {
		t.Fatal("plain ssh keep must be safe")
	}
	if ruleSafe(v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "22; drop", Stack: "v4"}) {
		t.Fatal("port injection")
	}
	if ruleSafe(v2.FirewallRule{Action: "allow", Protocol: "tcp; nft", Port: "22", Stack: "v4"}) {
		t.Fatal("protocol injection")
	}
	if ruleSafe(v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Source: "1.1.1.1; nft"}) {
		t.Fatal("source injection")
	}
	if ruleSafe(v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "22", Stack: "v4", Source: "fe80::1%eth0"}) {
		t.Fatal("source zone injection")
	}
	if !portSpecOK("1000-2000") || portSpecOK("2000-1000") || portSpecOK("22-22-22") {
		t.Fatal("port range")
	}
}

func TestSSHPortOfRejectsJunk(t *testing.T) {
	if keepPort("0") != "" || keepPort("65536") != "" || keepPort("22;drop") != "" || keepPort("22-22") != "" {
		t.Fatal("keepPort must only accept a single 1-65535 port")
	}
	if keepPort("2222") != "2222" {
		t.Fatal(keepPort("2222"))
	}
	got := sshPortOf(v2.FirewallIntent{SshPort: "nope"})
	want := keepPort(detectedSSHPort())
	if got != want {
		t.Fatalf("invalid ssh_port must fall back to detected: got %q want %q", got, want)
	}
}
