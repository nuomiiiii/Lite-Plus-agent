package firewall

import (
	"strings"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestParseIptablesSaveAdoptsSimpleINPUT(t *testing.T) {
	raw := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 1.2.3.0/24 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8000:8010 -j DROP
-A INPUT -i docker0 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
COMMIT
`
	rules := parseIptablesSave(raw, "v4", "INPUT")
	if len(rules) != 5 {
		t.Fatalf("rules = %d, want 5", len(rules))
	}
	if !rules[0].Adoptable || rules[0].Port != "22" || rules[0].Action != "allow" {
		t.Fatalf("ssh: %+v", rules[0])
	}
	if !rules[1].Adoptable || rules[1].Source != "1.2.3.0/24" || rules[1].Port != "443" {
		t.Fatalf("cidr: %+v", rules[1])
	}
	if !rules[2].Adoptable || rules[2].Port != "8000-8010" || rules[2].Action != "deny" {
		t.Fatalf("range: %+v", rules[2])
	}
	if rules[3].Adoptable {
		t.Fatalf("docker must not be adoptable: %+v", rules[3])
	}
	if rules[4].Adoptable {
		t.Fatalf("multiport must not be adoptable: %+v", rules[4])
	}
}

func TestParseIptablesRejectsFail2ban(t *testing.T) {
	raw := "-A INPUT -p tcp -m tcp --dport 22 -j FAIL2BAN"
	rules := parseIptablesSave(raw, "v4", "INPUT")
	if len(rules) != 1 || rules[0].Adoptable {
		t.Fatalf("fail2ban: %+v", rules)
	}
}

func TestParseIptablesFollows1PanelBasicAndAllPorts(t *testing.T) {
	raw := `*filter
:INPUT ACCEPT [0:0]
:1PANEL_BASIC_BEFORE - [0:0]
:1PANEL_BASIC - [0:0]
:1PANEL_BASIC_AFTER - [0:0]
-A INPUT -j 1PANEL_BASIC_BEFORE
-A INPUT -j 1PANEL_BASIC
-A INPUT -j 1PANEL_BASIC_AFTER
-A 1PANEL_BASIC -s 39.0.0.0/8 -p tcp -m tcp --dport 29777 -j ACCEPT
-A 1PANEL_BASIC -s 223.0.0.0/8 -p tcp -m tcp --dport 29777 -j ACCEPT
-A 1PANEL_BASIC -s 39.0.0.0/8 -p tcp -m tcp --dport 12969 -j ACCEPT
-A 1PANEL_BASIC -s 223.0.0.0/8 -p tcp -m tcp --dport 12969 -j ACCEPT
-A 1PANEL_BASIC -p tcp -m tcp --dport 30108 -j ACCEPT
-A 1PANEL_BASIC -s 10.240.3.4 -p tcp -j ACCEPT
COMMIT
`
	rules := parseIptablesSave(raw, "v4", "INPUT")
	if len(rules) != 9 {
		t.Fatalf("rules = %d, want 9: %+v", len(rules), rules)
	}
	var adoptable []v2.FirewallHostRule
	for _, rule := range rules {
		if strings.Contains(rule.Raw, "-j 1PANEL_") && rule.Adoptable {
			t.Fatalf("jump must stay view-only: %+v", rule)
		}
		if rule.Adoptable {
			adoptable = append(adoptable, rule)
		}
	}
	if len(adoptable) != 6 {
		t.Fatalf("adoptable = %d, want 6: %+v", len(adoptable), adoptable)
	}
	if adoptable[0].Port != "29777" || adoptable[0].Source != "39.0.0.0/8" {
		t.Fatalf("1panel-core: %+v", adoptable[0])
	}
	last := adoptable[len(adoptable)-1]
	if last.Port != "*" || last.Protocol != "tcp" || last.Source != "10.240.3.4" || last.Action != "allow" {
		t.Fatalf("all ports: %+v", last)
	}
}

func TestParseIptablesAdoptsMissingDportAsAllPorts(t *testing.T) {
	raw := `-A INPUT -s 10.240.3.4 -p tcp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
`
	rules := parseIptablesSave(raw, "v4", "INPUT")
	if len(rules) != 2 {
		t.Fatalf("%+v", rules)
	}
	if !rules[0].Adoptable || rules[0].Port != "*" || rules[0].Source != "10.240.3.4" {
		t.Fatalf("star: %+v", rules[0])
	}
	if !rules[1].Adoptable || rules[1].Port != "22" {
		t.Fatalf("ssh: %+v", rules[1])
	}
}

func TestParseIptablesSkipsPlusChainAndComments(t *testing.T) {
	raw := `*filter
-A INPUT -j LITE_PLUS
-A INPUT -p tcp -m tcp --dport 443 -m comment --comment "lite-plus:abc" -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
`
	rules := parseIptablesSave(raw, "v4", "INPUT")
	if len(rules) != 1 || !rules[0].Adoptable || rules[0].Port != "80" {
		t.Fatalf("%+v", rules)
	}
}

func TestParseUFWStatusNumbered(t *testing.T) {
	raw := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 22/tcp                     ALLOW IN    Anywhere
[ 3] 80/tcp                     ALLOW IN    10.0.0.0/8
[ 4] 8000:8010/tcp              DENY IN     Anywhere
[ 5] 443/tcp                    ALLOW OUT   Anywhere
[ 6] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 7] 53/udp                     ALLOW IN    Anywhere                   # dns
[ 8] 22/tcp                     ALLOW IN    Anywhere                   # lite-plus:abc
`
	v4 := parseUFWStatus(raw, "v4")
	if len(v4) != 6 {
		t.Fatalf("v4 rules = %d, want 6: %+v", len(v4), v4)
	}
	if v4[0].Adoptable {
		t.Fatalf("OpenSSH must be view-only: %+v", v4[0])
	}
	if !v4[1].Adoptable || v4[1].Protocol != "tcp" || v4[1].Port != "22" || v4[1].Source != "" {
		t.Fatalf("ssh: %+v", v4[1])
	}
	if !v4[2].Adoptable || v4[2].Source != "10.0.0.0/8" || v4[2].Port != "80" {
		t.Fatalf("cidr: %+v", v4[2])
	}
	if !v4[3].Adoptable || v4[3].Action != "deny" || v4[3].Port != "8000-8010" {
		t.Fatalf("range: %+v", v4[3])
	}
	if v4[4].Adoptable {
		t.Fatalf("outbound must not be adoptable: %+v", v4[4])
	}
	if !v4[5].Adoptable || v4[5].Protocol != "udp" || v4[5].Port != "53" {
		t.Fatalf("dns: %+v", v4[5])
	}
	v6 := parseUFWStatus(raw, "v6")
	if len(v6) != 1 || !v6[0].Adoptable || v6[0].Port != "22" {
		t.Fatalf("v6: %+v", v6)
	}
}

func TestParseUFWStatusAppProfiles(t *testing.T) {
	raw := `[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] WWW Full                   ALLOW IN    Anywhere
`
	apps := map[string]string{"OpenSSH": "22/tcp"}
	v4 := parseUFWStatusApps(raw, "v4", apps)
	if len(v4) != 2 {
		t.Fatalf("%+v", v4)
	}
	if !v4[0].Adoptable || v4[0].Port != "22" || v4[0].Protocol != "tcp" {
		t.Fatalf("OpenSSH: %+v", v4[0])
	}
	if v4[1].Adoptable {
		t.Fatalf("WWW Full stays view-only without a single port: %+v", v4[1])
	}
	if got := parseUfwAppInfo("Profile: OpenSSH\nPorts: 22/tcp\n"); got != "22/tcp" {
		t.Fatalf("app info = %q", got)
	}
}

func TestParseNftRulesetSkipsPlusTableAndNat(t *testing.T) {
	raw := `table inet liteplus {
  chain input {
    tcp dport 9443 accept
  }
}
table ip filter {
  chain INPUT {
    tcp dport 22 accept
    tcp dport 80 dnat to 10.0.0.2
  }
}
`
	rules := parseNftRuleset(raw)
	if len(rules) != 1 || !rules[0].Adoptable || rules[0].Port != "22" {
		t.Fatalf("%+v", rules)
	}
}

func TestParseNftRulesetUsesHandles(t *testing.T) {
	raw := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		tcp dport 22 ct state new,established counter packets 0 bytes 0 accept # handle 4
		tcp dport 80 accept # handle 5
		udp dport 53 drop # handle 6
	}
}
`
	rules := parseNftRuleset(raw)
	if len(rules) != 3 {
		t.Fatalf("%+v", rules)
	}
	if !rules[0].Adoptable || rules[0].Port != "22" || rules[0].Comment != "nft ip filter INPUT 4" {
		t.Fatalf("ssh: %+v", rules[0])
	}
	if !rules[1].Adoptable || rules[1].Port != "80" || rules[1].Comment != "nft ip filter INPUT 5" {
		t.Fatalf("http: %+v", rules[1])
	}
	if !rules[2].Adoptable || rules[2].Action != "deny" || rules[2].Comment != "nft ip filter INPUT 6" {
		t.Fatalf("dns: %+v", rules[2])
	}
}

func TestParseFirewalldPorts(t *testing.T) {
	rules := parseFirewalldPorts("22/tcp 80/tcp")
	if len(rules) != 4 {
		t.Fatalf("%+v", rules)
	}
	if !rules[0].Adoptable || rules[0].Port != "22" || rules[0].Protocol != "tcp" || rules[0].Stack != "v4" {
		t.Fatalf("%+v", rules[0])
	}
}

func TestParseFirewalldService(t *testing.T) {
	rules := parseFirewalldService("ssh", "ssh\n  ports: 22/tcp\n  protocols:\n")
	if len(rules) != 2 || !rules[0].Adoptable || rules[0].Port != "22" || rules[0].Comment != "firewalld-service ssh" {
		t.Fatalf("%+v", rules)
	}
}

func TestParseWindowsInboundPort(t *testing.T) {
	raw := `
Rule Name:                    Open SSH
----------------------------------------------------------------------
Enabled:                      Yes
Direction:                    In
Profiles:                     Domain,Private,Public
Grouping:
LocalIP:                      Any
RemoteIP:                     Any
Protocol:                     TCP
LocalPort:                    22
RemotePort:                   Any
Action:                       Allow

Rule Name:                    Web
Enabled:                      Yes
Direction:                    In
Protocol:                     TCP
LocalPort:                    80,443
Action:                       Allow
`
	rules := parseWindowsRules(raw)
	if len(rules) != 2 {
		t.Fatalf("%+v", rules)
	}
	if !rules[0].Adoptable || rules[0].Port != "22" || rules[0].Protocol != "tcp" {
		t.Fatalf("ssh: %+v", rules[0])
	}
	if rules[1].Adoptable {
		t.Fatalf("comma ports must stay view-only: %+v", rules[1])
	}
}

func TestParseWindowsAnyPortIsAllPorts(t *testing.T) {
	raw := `
Rule Name:                    Allow all TCP
Enabled:                      Yes
Direction:                    In
Protocol:                     TCP
LocalPort:                    Any
RemoteIP:                     10.240.3.4
Action:                       Allow
`
	rules := parseWindowsRules(raw)
	if len(rules) != 1 || !rules[0].Adoptable || rules[0].Port != "*" || rules[0].Source != "10.240.3.4" {
		t.Fatalf("%+v", rules)
	}
}

func TestParseNftSkipsPlusChainAndPriorityMeta(t *testing.T) {
	raw := `table inet filter {
	chain input {
		type filter hook input priority -1; policy accept;
		jump LITE_PLUS
		jump 1PANEL_BASIC
	}
	chain LITE_PLUS {
		iif lo accept
		meta nfproto ipv4 tcp dport 443 accept
		ip protocol icmp icmp type echo-request drop
	}
	chain 1PANEL_BASIC {
		tcp dport 22 accept
	}
}
`
	rules := parseNftRuleset(raw)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2: %+v", len(rules), rules)
	}
	if rules[0].Adoptable || !strings.Contains(rules[0].Raw, "1PANEL_BASIC") {
		t.Fatalf("1panel jump: %+v", rules[0])
	}
	if !rules[1].Adoptable || rules[1].Port != "22" {
		t.Fatalf("ssh: %+v", rules[1])
	}
	for _, rule := range rules {
		if strings.Contains(rule.Raw, "priority") || strings.Contains(rule.Raw, "LITE_PLUS") || strings.Contains(rule.Raw, "443") {
			t.Fatalf("plus/meta leaked: %+v", rule)
		}
	}
}

func TestParseNftAllPortsWithoutDport(t *testing.T) {
	raw := `table ip filter {
	chain INPUT {
		jump 1PANEL_BASIC
	}
	chain 1PANEL_BASIC {
		ip saddr 10.240.3.4 tcp accept
		tcp dport 22 accept
	}
}
`
	rules := parseNftRuleset(raw)
	if len(rules) != 3 {
		t.Fatalf("%+v", rules)
	}
	if rules[0].Adoptable {
		t.Fatalf("jump must stay view-only: %+v", rules[0])
	}
	if !rules[1].Adoptable || rules[1].Port != "*" || rules[1].Source != "10.240.3.4" || rules[1].Protocol != "tcp" {
		t.Fatalf("all ports: %+v", rules[1])
	}
	if !rules[2].Adoptable || rules[2].Port != "22" {
		t.Fatalf("ssh: %+v", rules[2])
	}
}

func TestParseUFWAnywhereTCPIsAllPorts(t *testing.T) {
	raw := `[ 1] Anywhere/tcp                ALLOW IN    10.240.3.4
`
	v4 := parseUFWStatus(raw, "v4")
	if len(v4) != 1 || !v4[0].Adoptable || v4[0].Port != "*" || v4[0].Protocol != "tcp" || v4[0].Source != "10.240.3.4" {
		t.Fatalf("%+v", v4)
	}
}
