package coreadapter

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGeoMatchSplitsGeoAndPlainTokens(t *testing.T) {
	m := parseGeoMatch(
		[]string{"geosite:cn", "geosite:geolocation-!cn", "example.com"},
		[]string{"geoip:private", "geoip:CN", "10.0.0.0/8"},
	)
	if strings.Join(m.Geosite, ",") != "cn,geolocation-!cn" {
		t.Fatalf("geosite = %#v", m.Geosite)
	}
	if strings.Join(m.Suffix, ",") != "example.com" {
		t.Fatalf("suffix = %#v", m.Suffix)
	}
	if !m.Private {
		t.Fatal("expected geoip:private")
	}
	if strings.Join(m.GeoIP, ",") != "cn" {
		t.Fatalf("geoip = %#v", m.GeoIP)
	}
	if strings.Join(m.CIDRs, ",") != "10.0.0.0/8" {
		t.Fatalf("cidrs = %#v", m.CIDRs)
	}
}

func TestSingBoxGeoRoutesUseRuleSets(t *testing.T) {
	SetGeoAssetDir(t.TempDir())
	t.Cleanup(func() { SetGeoAssetDir("") })
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{ID: "ob1", Name: "proxy", Protocol: "vless", Enabled: true}}
	c.routes = []RouteSpec{{
		ID: "r1", Name: "cn", Priority: 0, Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"geosite:cn, geosite:geolocation-!cn","ip":"geoip:private, geoip:cn"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"tag":"geosite-cn"`,
		`"tag":"geosite-geolocation-!cn"`,
		`"tag":"geoip-cn"`,
		`"type":"local"`,
		`"ip_is_private":true`,
		`"mode":"or"`,
		`"mode":"and"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"ip_cidr":["geoip:`) {
		t.Fatal("geoip tokens must not stay in ip_cidr")
	}
	if strings.Contains(text, `"domain":["geosite:`) {
		t.Fatal("geosite tokens must not stay in domain")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSingBoxPlainCIDRUnchanged(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{ID: "ob1", Name: "direct", Protocol: "direct", Enabled: true}}
	c.routes = []RouteSpec{{
		ID: "r1", Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"example.com","ip":"10.0.0.0/8"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"domain_suffix":["example.com"]`) {
		t.Fatalf("plain domain missing: %s", text)
	}
	if !strings.Contains(text, `"ip_cidr":["10.0.0.0/8"]`) {
		t.Fatalf("plain cidr missing: %s", text)
	}
	if strings.Contains(text, `"rule_set"`) {
		t.Fatal("plain routes should not add rule_set")
	}
}

func TestParseGeoMatchHonorsXrayDomainPrefixes(t *testing.T) {
	m := parseGeoMatch(
		[]string{"example.com", "domain:google.com", "full:api.google.com", "keyword:cdn", "regexp:.*\\.internal$"},
		nil,
	)
	if strings.Join(m.Suffix, ",") != "example.com,google.com" {
		t.Fatalf("suffix = %#v", m.Suffix)
	}
	if strings.Join(m.Exact, ",") != "api.google.com" {
		t.Fatalf("exact = %#v", m.Exact)
	}
	if strings.Join(m.Keyword, ",") != "cdn" {
		t.Fatalf("keyword = %#v", m.Keyword)
	}
	if strings.Join(m.Regex, ",") != `.*\.internal$` {
		t.Fatalf("regex = %#v", m.Regex)
	}
}

func TestSingBoxPlainDomainUsesSuffix(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{ID: "ob1", Name: "direct", Protocol: "direct", Enabled: true}}
	c.routes = []RouteSpec{{
		ID: "r1", Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"example.com, full:exact.example, keyword:cdn"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"domain_suffix":["example.com"]`, `"domain":["exact.example"]`, `"domain_keyword":["cdn"]`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestRuleHasDestFilterSeesGeoAndPortRange(t *testing.T) {
	if ruleHasDestFilter(map[string]any{"outbound": "direct"}) {
		t.Fatal("bare outbound is not a dest filter")
	}
	if !ruleHasDestFilter(map[string]any{"rule_set": []string{"geosite-cn"}, "outbound": "direct"}) {
		t.Fatal("geosite rule_set is a dest filter")
	}
	if !ruleHasDestFilter(map[string]any{"ip_is_private": true, "outbound": "direct"}) {
		t.Fatal("private IP is a dest filter")
	}
	if !ruleHasDestFilter(map[string]any{"port": []any{443}, "outbound": "direct"}) {
		t.Fatal("port list is a dest filter")
	}
	if !ruleHasDestFilter(map[string]any{
		"type": "logical", "mode": "or",
		"rules": []any{map[string]any{"domain_suffix": []string{"example.com"}}},
		"outbound": "direct",
	}) {
		t.Fatal("logical domain rule is a dest filter")
	}
}
