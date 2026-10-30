package coreadapter

import (
	"context"
	"net"
	"testing"
)

func TestIPAllowedByStack(t *testing.T) {
	v4 := net.ParseIP("1.1.1.1")
	v6 := net.ParseIP("2001:4860:4860::8888")
	if !ipAllowedByStack(v4, "ipv4") || ipAllowedByStack(v6, "ipv4") {
		t.Fatal("ipv4-only")
	}
	if ipAllowedByStack(v4, "ipv6") || !ipAllowedByStack(v6, "ipv6") {
		t.Fatal("ipv6-only")
	}
	for _, stack := range []string{"dual", "prefer_ipv4", "prefer_ipv6"} {
		if !ipAllowedByStack(v4, stack) || !ipAllowedByStack(v6, stack) {
			t.Fatalf("%s must allow both literals", stack)
		}
	}
}

func TestResolveUDPAddrWithStackLiteral(t *testing.T) {
	if _, err := resolveUDPAddrWithStack("[::1]:53", "ipv4"); err == nil {
		t.Fatal("ipv4-only must reject ipv6 dest")
	}
	if _, err := resolveUDPAddrWithStack("1.1.1.1:53", "ipv6"); err == nil {
		t.Fatal("ipv6-only must reject ipv4 dest")
	}
	got, err := resolveUDPAddrWithStack("1.1.1.1:53", "ipv4")
	if err != nil || !got.IP.Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("ipv4 dest %v %v", got, err)
	}
	got, err = resolveUDPAddrWithStack("[2001:4860:4860::8888]:53", "prefer_ipv4")
	if err != nil || got.IP.To4() != nil {
		t.Fatalf("prefer still allows ipv6 literal %v %v", got, err)
	}
}

func TestNormalizeDialStack(t *testing.T) {
	if got := NormalizeDialStack(""); got != dialStackDual {
		t.Fatalf("empty = %q", got)
	}
	if got := xrayDomainStrategy("prefer_ipv4"); got != "UseIPv4v6" {
		t.Fatalf("xray prefer v4 = %q", got)
	}
	if got := singBoxDomainStrategy("ipv6"); got != "ipv6_only" {
		t.Fatalf("sing-box v6 = %q", got)
	}
}

func TestApplyXrayDialStackFreedomAndProxy(t *testing.T) {
	obs := []map[string]any{
		{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"finalRules": []map[string]any{{"action": "allow"}}}},
		{"protocol": "blackhole", "tag": "block"},
		{"protocol": "vless", "tag": "up", "streamSettings": map[string]any{"network": "tcp"}},
	}
	applyXrayDialStack(obs, "prefer_ipv6")
	settings := obs[0]["settings"].(map[string]any)
	if settings["domainStrategy"] != "UseIPv6v4" {
		t.Fatalf("direct: %+v", settings)
	}
	if _, ok := obs[1]["settings"]; ok {
		t.Fatalf("block must stay untouched: %+v", obs[1])
	}
	stream := obs[2]["streamSettings"].(map[string]any)
	sockopt := stream["sockopt"].(map[string]any)
	if sockopt["domainStrategy"] != "UseIPv6v4" {
		t.Fatalf("proxy sockopt: %+v", sockopt)
	}
}

func TestApplyXrayDialStackSkipsPolicyLoopback(t *testing.T) {
	obs := []map[string]any{
		{
			"protocol": "socks",
			"tag":      "nodemgt-policy-u1-direct",
			"settings": map[string]any{"servers": []map[string]any{{"address": "127.0.0.1", "port": 1234}}},
		},
		{
			"protocol": "socks",
			"tag":      "exit",
			"settings": map[string]any{"servers": []map[string]any{{"address": "127.0.0.1", "port": 2345}}},
		},
		{"protocol": "freedom", "tag": "direct", "settings": map[string]any{}},
	}
	applyXrayDialStack(obs, "ipv6")
	if _, ok := obs[0]["streamSettings"]; ok {
		t.Fatalf("policy socks must stay untouched: %+v", obs[0])
	}
	if _, ok := obs[1]["streamSettings"]; ok {
		t.Fatalf("loopback socks must stay untouched: %+v", obs[1])
	}
	settings := obs[2]["settings"].(map[string]any)
	if settings["domainStrategy"] != "UseIPv6" {
		t.Fatalf("direct: %+v", settings)
	}
}

func TestApplySingBoxDialStackWritesResolver(t *testing.T) {
	cfg := map[string]any{}
	applySingBoxDialStack(cfg, nil, "ipv4")
	dns, _ := cfg["dns"].(map[string]any)
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("dns: %+v", dns)
	}
	route, _ := cfg["route"].(map[string]any)
	resolver, _ := route["default_domain_resolver"].(map[string]any)
	if resolver["server"] != "local" || resolver["strategy"] != "ipv4_only" {
		t.Fatalf("resolver: %+v", resolver)
	}
}

func TestApplySingBoxDialStackDualLeavesConfig(t *testing.T) {
	cfg := map[string]any{"log": map[string]any{"level": "error"}}
	applySingBoxDialStack(cfg, nil, "dual")
	if _, ok := cfg["dns"]; ok {
		t.Fatalf("dual must not inject dns: %+v", cfg)
	}
	if _, ok := cfg["route"]; ok {
		t.Fatalf("dual must not inject route: %+v", cfg)
	}
}

func TestRestoreLastGoodPinsDialStack(t *testing.T) {
	t.Run("xray", func(t *testing.T) {
		c := newXrayCore()
		startCoreForDialRestore(t, c, "xray")
		c.SetDialStack("ipv6")
		c.mu.Lock()
		c.restoreLastGood()
		got := c.dialStack
		c.mu.Unlock()
		if NormalizeDialStack(got) != dialStackDual {
			t.Fatalf("after restore dialStack=%q", got)
		}
	})
	t.Run("sing-box", func(t *testing.T) {
		c := newSingBoxCore()
		startCoreForDialRestore(t, c, "sing-box")
		c.SetDialStack("ipv4")
		c.mu.Lock()
		c.restoreLastGood()
		got := c.dialStack
		c.mu.Unlock()
		if NormalizeDialStack(got) != dialStackDual {
			t.Fatalf("after restore dialStack=%q", got)
		}
	})
}

func TestRestoreLastGoodKeepsAttemptedStackWhenEmpty(t *testing.T) {
	c := newXrayCore()
	c.lastUsers = []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
	c.lastDialStack = dialStackDual
	c.dialStack = dialStackIPv4
	c.restoreLastGood()
	if c.dialStack != dialStackIPv4 {
		t.Fatalf("empty restore must keep attempted stack, got %q", c.dialStack)
	}
}

type dialRestoreCore interface {
	ApplyUsers([]UserSpec) error
	SetDialStack(string)
	Start(context.Context, []InboundSpec) error
	Stop() error
}

func startCoreForDialRestore(t *testing.T, core dialRestoreCore, coreName string) {
	t.Helper()
	port, err := reserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	core.SetDialStack(dialStackDual)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "socks", Core: coreName, Listen: "127.0.0.1", Port: port, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Stop(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Stop() })
}
