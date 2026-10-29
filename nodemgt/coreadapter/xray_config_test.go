package coreadapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func TestXrayDialStackWritesFreedomStrategy(t *testing.T) {
	c := newXrayCore()
	c.SetDialStack("prefer_ipv4")
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"domainStrategy":"UseIPv4v6"`) {
		t.Fatalf("missing freedom strategy: %s", raw)
	}
}

func TestSingBoxDialStackWritesResolver(t *testing.T) {
	c := newSingBoxCore()
	c.SetDialStack("ipv4")
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"type":"local"`, `"ipv4_only"`, `"default_domain_resolver"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	ctx := include.Context(context.Background())
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw); err != nil {
		t.Fatalf("sing-box options: %v\n%s", err, text)
	}
}

func TestXrayConfigAppliesSniffingStreamAndRoutes(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID:           "in1",
		Listen:       "127.0.0.1",
		Port:         443,
		Protocol:     "vless",
		StreamJSON:   `{"network":"ws","security":"none","wsSettings":{"path":"/vless","host":"cdn.example.com"}}`,
		SettingsJSON: `{"sniffing":true,"dest_override":"http,tls","route_only":true}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "block", Protocol: "blackhole", Enabled: true,
	}}
	c.routes = []RouteSpec{{
		ID: "r1", Name: "ads", Priority: 0, Enabled: true,
		RuleJSON: `{"outbound_id":"ob1","domain":"geosite:category-ads-all","protocol":"http,tls"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"destOverride"`,
		`"routeOnly":true`,
		`"xtls-rprx-vision"`,
		`"geosite:category-ads-all"`,
		`"outboundTag":"block"`,
		`"protocol":"blackhole"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"path":"/vless"`) {
		t.Fatal("identity front should keep websocket off the core inbound")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
}

func TestXrayRealitySniffingForcesRouteOnly(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:           "reality",
		Listen:       "127.0.0.1",
		Port:         443,
		Protocol:     "vless",
		Flow:         "xtls-rprx-vision",
		StreamJSON:   `{"network":"tcp","security":"reality"}`,
		SettingsJSON: `{"sniffing":true,"security":"reality","flow":"xtls-rprx-vision","dest_override":"http,tls,quic"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"routeOnly":true`) {
		t.Fatalf("reality sniffing must be route-only: %s", text)
	}
}

func TestSingBoxRealityUsesStringServerName(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "audit-pass"}}
	c.inbounds = []InboundSpec{{
		ID:         "schema",
		Listen:     "127.0.0.1",
		Port:       8443,
		Protocol:   "vless",
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := cfg["inbounds"].([]any)
	if len(inbounds) == 0 {
		t.Fatalf("no inbounds: %s", raw)
	}
	in, _ := inbounds[0].(map[string]any)
	tls, _ := in["tls"].(map[string]any)
	name, ok := tls["server_name"].(string)
	if !ok || name != "audit.test" {
		t.Fatalf("server_name=%v %s", tls["server_name"], raw)
	}
	reality, _ := tls["reality"].(map[string]any)
	hs, _ := reality["handshake"].(map[string]any)
	if hs["server"] != "127.0.0.1" {
		t.Fatalf("handshake server=%v", hs["server"])
	}
	port, _ := hs["server_port"].(float64)
	if int(port) != 9 {
		t.Fatalf("handshake port=%v", hs["server_port"])
	}
}

func TestXrayUserFlowVisionKeepsCoreTLS(t *testing.T) {
	c := newXrayCore()
	cert, key := testPEMs(t)
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID: "tls", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		CertPEM: cert, KeyPEM: key,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"security":"tls"`, `"xtls-rprx-vision"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"nodemgt-policy-u1"`) {
		t.Fatal("vision must not detour through policy SOCKS")
	}
}

func TestXrayRealityVisionSkipsPolicySocks(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Protocol:   "vless",
		Listen:     "127.0.0.1",
		Port:       443,
		Flow:       "xtls-rprx-vision",
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("reality+vision must go to freedom, got policy SOCKS: %s", text)
	}
	if !strings.Contains(text, `"tag":"direct"`) {
		t.Fatalf("missing direct outbound: %s", text)
	}
}

func TestXrayRealityWithoutVisionSkipsPolicySocks(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Protocol:   "vless",
		Listen:     "127.0.0.1",
		Port:       443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must go to freedom without vision: %s", text)
	}
}

func TestSingBoxRealityVisionKeepsPolicySocks(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Protocol:   "vless",
		Listen:     "127.0.0.1",
		Port:       443,
		Flow:       "xtls-rprx-vision",
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"nodemgt-policy-u1"`) {
		t.Fatalf("sing-box reality has no vision splice, keep policy SOCKS: %s", text)
	}
	if !strings.Contains(text, `"network":"tcp"`) {
		t.Fatalf("sing-box policy SOCKS must be tcp-only: %s", text)
	}
	if !strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("sing-box reality inbound must copy vision onto users: %s", text)
	}
}

func TestSingBoxUserFlowVisionWritesInboundUser(t *testing.T) {
	c := newSingBoxCore()
	cert, key := testPEMs(t)
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID: "tls", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		CertPEM: cert, KeyPEM: key,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("sing-box user flow must land on vless users: %s", text)
	}
}

func TestSingBoxUserFlowIgnoredOnWebSocket(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"}}
	c.inbounds = []InboundSpec{{
		ID: "ws", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		StreamJSON: `{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"xtls-rprx-vision"`) {
		t.Fatalf("sing-box websocket inbound must not stamp vision: %s", raw)
	}
}

func TestSingBoxUdp443FlowNormalizedToVision(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision-udp443"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Protocol:   "vless",
		Listen:     "127.0.0.1",
		Port:       443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("sing-box must map udp443 onto vision: %s", text)
	}
	if strings.Contains(text, "udp443") {
		t.Fatalf("sing-box must not keep udp443 flow: %s", text)
	}
}

func TestSingBoxSniffingIsRouteOnly(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:           "reality",
		Protocol:     "vless",
		Listen:       "127.0.0.1",
		Port:         443,
		StreamJSON:   `{"network":"tcp","security":"reality"}`,
		SettingsJSON: `{"sniffing":true,"security":"reality","dest_override":"http,tls,quic"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"action":"sniff"`) {
		t.Fatalf("sniffing inbound needs sniff action: %s", text)
	}
	if strings.Contains(text, "sniff_override_destination") {
		t.Fatalf("reality sniff must not override dest: %s", text)
	}
}

func TestXrayBusinessRouteSkipsPolicyDialer(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{ID: "audit-direct", Name: "audit-direct", Protocol: "freedom", Enabled: true}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-direct"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must not detour policy SOCKS: %s", text)
	}
	if !strings.Contains(text, `"outboundTag":"audit-direct"`) {
		t.Fatalf("missing business route: %s", text)
	}
}

func TestXraySocksViaKeepsOriginalChain(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080,"via_outbound":"audit-B"}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("policy cloned socks outbound and overwrote via: %s", text)
	}
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must not detour policy SOCKS: %s", text)
	}
	for _, part := range []string{`"dialerProxy":"audit-B"`, `"outboundTag":"audit-A"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxSocksViaKeepsPolicyExit(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-exit", Name: "audit-exit", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"detour"`) {
		t.Fatalf("policy set detour on socks outbound: %s", text)
	}
	if !strings.Contains(text, `"nodemgt-policy-u1-audit-exit"`) {
		t.Fatalf("missing policy socks exit in %s", text)
	}
}

func TestXrayVLESSViaKeepsPolicyExit(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "vless", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","via_outbound":"audit-B"}`},
	}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-A"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("policy cloned vless outbound and skipped hop A: %s", text)
	}
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must not detour policy SOCKS: %s", text)
	}
	if !strings.Contains(text, `"outboundTag":"audit-A"`) {
		t.Fatalf("missing vless route in %s", text)
	}
}

func TestXrayVLESSTLSKeepsPolicyExit(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","security":"tls","transport":"tcp","sni":"audit.test"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("tls vless fell back to cloned outbound: %s", text)
	}
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must not detour policy SOCKS: %s", text)
	}
	if !strings.Contains(text, `"outboundTag":"audit-exit"`) {
		t.Fatalf("missing tls vless route in %s", text)
	}
}

func TestXrayGRPCUsesCoreDetour(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"none","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("grpc fell back to metered dialerProxy: %s", text)
	}
	if strings.Contains(text, `"nodemgt-policy-`) {
		t.Fatalf("xray reality must not detour policy SOCKS: %s", text)
	}
	for _, part := range []string{`"outboundTag":"audit-exit"`, `"network":"grpc"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxGRPCMapsOutboundTransport(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"none","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("grpc fell back to cloned outbound: %s", text)
	}
	for _, part := range []string{`"nodemgt-policy-u1-audit-exit"`, `"nodemgt-core-audit-exit"`, `"type":"grpc"`, `"service_name":"audit"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	for _, ob := range singBoxTypedOutbounds(t, raw, "vless") {
		if tls, _ := ob["tls"].(map[string]any); tls != nil {
			if enabled, _ := tls["enabled"].(bool); enabled {
				t.Fatalf("security=none still enabled tls on %v", ob["tag"])
			}
		}
	}
}

func TestSingBoxGRPCMapsOutboundTLS(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "reality", Protocol: "vless", Listen: "127.0.0.1", Port: 443,
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	c.outbounds = []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","security":"tls","sni":"audit.test","grpc_service":"audit"}`,
	}}
	c.routes = []RouteSpec{{ID: "business-route", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"nodemgt-via-`) {
		t.Fatalf("tls grpc fell back to cloned outbound: %s", text)
	}
	found := 0
	for _, ob := range singBoxTypedOutbounds(t, raw, "vless") {
		tag, _ := ob["tag"].(string)
		if !strings.Contains(tag, "audit-exit") {
			continue
		}
		found++
		tls, _ := ob["tls"].(map[string]any)
		if tls == nil {
			t.Fatalf("missing tls on %s: %v", tag, ob)
		}
		if enabled, _ := tls["enabled"].(bool); !enabled {
			t.Fatalf("tls.enabled=%v on %s", tls["enabled"], tag)
		}
		if tls["server_name"] != "audit.test" {
			t.Fatalf("tls.server_name=%v on %s", tls["server_name"], tag)
		}
		if insecure, ok := tls["insecure"]; ok && insecure == true {
			t.Fatalf("tls verification disabled on %s", tag)
		}
		transport, _ := ob["transport"].(map[string]any)
		if transport["type"] != "grpc" || transport["service_name"] != "audit" {
			t.Fatalf("transport=%v on %s", transport, tag)
		}
	}
	if found == 0 {
		t.Fatalf("missing grpc vless outbound in %s", text)
	}
}

func TestSingBoxSOCKSMapsUsername(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{
		{
			ID: "audit-socks", Name: "audit-socks", Protocol: "socks", Enabled: true,
			SettingsJSON: `{"address":"127.0.0.1","port":1080,"username":"audit-user","password":"audit-password"}`,
		},
		{
			ID: "audit-open", Name: "audit-open", Protocol: "socks", Enabled: true,
			SettingsJSON: `{"address":"127.0.0.1","port":1081,"password":"ignored-without-user"}`,
		},
	}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	foundAuth, foundOpen := false, false
	for _, ob := range singBoxTypedOutbounds(t, raw, "socks") {
		switch ob["tag"] {
		case "audit-socks":
			foundAuth = true
			if ob["username"] != "audit-user" || ob["password"] != "audit-password" {
				t.Fatalf("auth socks %v", ob)
			}
		case "audit-open":
			foundOpen = true
			if _, ok := ob["username"]; ok {
				t.Fatalf("empty username still mapped on %v", ob)
			}
		}
	}
	if !foundAuth || !foundOpen {
		t.Fatalf("missing socks outbounds in %s", raw)
	}
}

func TestSingBoxOutboundMapsShadowsocksMethod(t *testing.T) {
	outbounds := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true, SettingsJSON: `{"ss_method":"aes-128-gcm"}`,
	}})
	if method := outbounds[len(outbounds)-1]["method"]; method != "aes-128-gcm" {
		t.Fatalf("method=%v", method)
	}
}

func TestSingBoxSSOutboundHonorsNetwork(t *testing.T) {
	udp := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true,
		SettingsJSON: `{"address":"ss.example.com","port":8388,"password":"x","ss_method":"aes-128-gcm","ss_network":"udp"}`,
	}})
	if network := udp[len(udp)-1]["network"]; network != "udp" {
		t.Fatalf("udp network=%v", network)
	}
	tcp := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true,
		SettingsJSON: `{"address":"ss.example.com","port":8388,"password":"x","ss_method":"aes-128-gcm","ss_network":"tcp"}`,
	}})
	if network := tcp[len(tcp)-1]["network"]; network != "tcp" {
		t.Fatalf("tcp network=%v", network)
	}
	both := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true,
		SettingsJSON: `{"address":"ss.example.com","port":8388,"password":"x","ss_method":"aes-128-gcm","ss_network":"tcp,udp","transport":"tcp"}`,
	}})
	if _, ok := both[len(both)-1]["network"]; ok {
		t.Fatalf("tcp,udp must omit network, got %v", both[len(both)-1])
	}
	legacy := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true,
		SettingsJSON: `{"address":"ss.example.com","port":8388,"password":"x","ss_method":"aes-128-gcm","transport":"tcp"}`,
	}})
	if _, ok := legacy[len(legacy)-1]["network"]; ok {
		t.Fatalf("legacy tcp dummy must stay both, got %v", legacy[len(legacy)-1])
	}
}

func TestXraySSOutboundDoesNotCopyListenNetworkIntoStream(t *testing.T) {
	item := xrayOutboundItem(OutboundSpec{
		Protocol:     "shadowsocks",
		SettingsJSON: `{"address":"ss.example.com","port":8388,"password":"x","ss_method":"aes-128-gcm","transport":"tcp,udp"}`,
	}, "ss")
	if item == nil {
		t.Fatal("missing ss outbound")
	}
	stream, _ := item["streamSettings"].(map[string]any)
	if netw, _ := stream["network"].(string); netw == "tcp,udp" || netw == "udp" {
		t.Fatalf("ss listen network leaked into stream: %v", stream)
	}
}

func TestSingBoxOutboundDefaultsShadowsocksMethod(t *testing.T) {
	outbounds := singBoxOutbounds([]OutboundSpec{{
		Protocol: "shadowsocks", Enabled: true, SettingsJSON: `{"password":"x"}`,
	}})
	if method := outbounds[len(outbounds)-1]["method"]; method != "2022-blake3-aes-128-gcm" {
		t.Fatalf("method=%v", method)
	}
}

func TestSingBoxOutboundIgnoresLeftoverSSMethod(t *testing.T) {
	leftover := `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","username":"","password":"","ss_method":"2022-blake3-aes-128-gcm","via_outbound":"exit"}`
	outbounds := singBoxOutbounds([]OutboundSpec{
		{ID: "exit", Name: "exit", Protocol: "socks", Enabled: true, SettingsJSON: `{"address":"127.0.0.1","port":1080,"ss_method":"2022-blake3-aes-128-gcm"}`},
		{ID: "relay", Name: "relay", Protocol: "vless", Enabled: true, SettingsJSON: leftover},
	})
	for _, ob := range outbounds {
		switch ob["tag"] {
		case "relay", "exit":
			if _, ok := ob["method"]; ok {
				t.Fatalf("%s outbound must not copy leftover ss_method: %v", ob["tag"], ob)
			}
		}
	}
	relay := outboundByTag(outbounds, "relay")
	if relay == nil || relay["detour"] != "exit" {
		t.Fatalf("via_outbound detour=%v", relay)
	}
	if _, ok := relay["username"]; ok {
		t.Fatalf("vless outbound must not copy empty socks fields: %v", relay)
	}
}

func TestSingBoxAnyTLSPolicyConfigParses(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 1 << 20}}
	c.inbounds = []InboundSpec{{
		ID: "anytls", Listen: "127.0.0.1", Port: 443, Protocol: "anytls",
		CertPEM: "cert", KeyPEM: "key",
		StreamJSON: `{"network":"tcp","security":"tls"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"auth_user"`) {
		t.Fatalf("expected auth_user policy rule: %s", raw)
	}
	ctx := include.Context(context.Background())
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw); err != nil {
		t.Fatalf("sing-box rejected anytls policy: %v\n%s", err, raw)
	}
}

func TestSingBoxConfigParsesLeftoverOutboundSSMethod(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "relay", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","ss_method":"2022-blake3-aes-128-gcm"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw); err != nil {
		t.Fatalf("sing-box rejected leftover ss_method: %v\n%s", err, raw)
	}
}

func TestSingBoxRouteMapsDestAndViaSelectors(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{
		{ID: "ob1", Name: "proxy", Protocol: "direct", Enabled: true},
	}
	c.routes = []RouteSpec{
		{ID: "late", Enabled: true, Priority: 10, RuleJSON: `{"outbound_id":"direct"}`},
		{ID: "first", Enabled: true, Priority: 0, RuleJSON: `{"outbound_id":"ob1","ip":"10.0.0.0/8","network":"tcp","port":"443,1000-2000","source":"192.168.1.0/24"}`},
	}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Route.Rules) < 2 {
		t.Fatalf("rules=%v", cfg.Route.Rules)
	}
	first, late := cfg.Route.Rules[0], cfg.Route.Rules[1]
	if first["outbound"] != "proxy" {
		t.Fatalf("priority 0 should lead: %v", cfg.Route.Rules)
	}
	if late["outbound"] != "direct" {
		t.Fatalf("catch-all direct missing: %v", late)
	}
	if cidrs, _ := first["ip_cidr"].([]any); len(cidrs) != 1 || cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("dest ip=%v", first["ip_cidr"])
	}
	if nets, _ := first["network"].([]any); len(nets) != 1 || nets[0] != "tcp" {
		t.Fatalf("network=%v", first["network"])
	}
	if ports, _ := first["port"].([]any); len(ports) != 1 || int(ports[0].(float64)) != 443 {
		t.Fatalf("port=%v", first["port"])
	}
	if ranges, _ := first["port_range"].([]any); len(ranges) != 1 || ranges[0] != "1000:2000" {
		t.Fatalf("port_range=%v", first["port_range"])
	}
	if src, _ := first["source_ip_cidr"].([]any); len(src) != 1 || src[0] != "192.168.1.0/24" {
		t.Fatalf("source=%v", first["source_ip_cidr"])
	}
}

func singBoxTypedOutbounds(t *testing.T, raw []byte, typ string) []map[string]any {
	t.Helper()
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, ob := range cfg.Outbounds {
		if ob["type"] == typ {
			out = append(out, ob)
		}
	}
	return out
}

func TestXrayVisionKeepsCoreTLSWithoutPolicyExit(t *testing.T) {
	c := newXrayCore()
	cert, key := testPEMs(t)
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID: "tls", Protocol: "vless", Listen: "127.0.0.1", Port: 8443,
		CertPEM: cert, KeyPEM: key, Flow: "xtls-rprx-vision",
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"security":"tls"`, `"xtls-rprx-vision"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, `"nodemgt-policy-u1"`) {
		t.Fatal("vision must not detour through policy SOCKS")
	}
}

func TestXrayOutboundAppliesRealityPublicKey(t *testing.T) {
	c := newXrayCore()
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "relay", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","transport":"tcp","security":"reality","sni":"www.microsoft.com","fingerprint":"chrome","reality_public_key":"pubkey","reality_short_id":"abcd","spider_x":"/"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"security":"reality"`,
		`"publicKey":"pubkey"`,
		`"shortId":"abcd"`,
		`"spiderX":"/"`,
		`"serverName":"www.microsoft.com"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxOutboundAppliesRealityPublicKey(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "relay", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision","transport":"tcp","security":"reality","sni":"www.microsoft.com","fingerprint":"chrome","reality_public_key":"pubkey","reality_short_id":"abcd"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"public_key":"pubkey"`,
		`"short_id":"abcd"`,
		`"server_name":"www.microsoft.com"`,
		`"fingerprint":"chrome"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if !strings.Contains(text, `"reality"`) {
		t.Fatalf("missing reality block: %s", text)
	}
}

func TestSingBoxOutboundUdp443NormalizedToVision(t *testing.T) {
	c := newSingBoxCore()
	c.outbounds = []OutboundSpec{{
		ID: "ob1", Name: "relay", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision-udp443","transport":"tcp","security":"reality"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"flow":"xtls-rprx-vision"`) {
		t.Fatalf("sing-box outbound must map udp443 onto vision: %s", text)
	}
	if strings.Contains(text, "udp443") {
		t.Fatalf("sing-box outbound must not keep udp443 flow: %s", text)
	}
}

func TestXraySSConfigUsesPasswordAndMethod(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{
		ID: "u1", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Username: "免流", Password: "secret",
	}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","transport":"tcp","security":"none"}`,
		StreamJSON:   `{"network":"tcp","security":"none"}`,
	}}
	raw, _, fronts, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fronts) != 0 {
		t.Fatalf("ss must listen on the core, fronts=%+v", fronts)
	}
	text := string(raw)
	for _, part := range []string{
		`"protocol":"shadowsocks"`,
		`"password":"secret"`,
		`"method":"aes-128-gcm"`,
		`"network":"tcp,udp"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, "acceptProxyProtocol") || strings.Contains(text, "proxy_protocol") {
		t.Fatalf("ss must not use proxy protocol: %s", text)
	}
	if strings.Contains(text, `"streamSettings"`) {
		t.Fatalf("ss must not wrap stream settings: %s", text)
	}
}

func TestXraySSNetworkHonorsSetting(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", Password: "secret"}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","ss_network":"tcp","transport":"tcp","security":"none"}`,
	}}
	raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"network":"tcp"`) {
		t.Fatalf("tcp-only ss: %s", text)
	}
	if strings.Contains(text, `"network":"tcp,udp"`) {
		t.Fatalf("tcp-only ss still has both: %s", text)
	}
	c.inbounds[0].SettingsJSON = `{"ss_method":"aes-128-gcm","ss_network":"udp"}`
	raw, _, _, err = c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"network":"udp"`) {
		t.Fatalf("udp-only ss: %s", raw)
	}
}

func TestSingBoxSSConfigNoProxyProtocol(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{
		ID: "u1", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Password: "secret",
	}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm"}`,
	}}
	raw, _, fronts, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fronts) != 0 {
		t.Fatalf("ss must listen on the core, fronts=%+v", fronts)
	}
	text := string(raw)
	for _, part := range []string{
		`"type":"shadowsocks"`,
		`"method":"aes-128-gcm"`,
		`"password":"secret"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
	if strings.Contains(text, "proxy_protocol") {
		t.Fatalf("ss must not use proxy protocol: %s", text)
	}
	if strings.Contains(text, "udp_fragment") {
		t.Fatalf("ss udp inbound must omit udp_fragment by default: %s", text)
	}
}

func TestSingBoxSSNetworkHonorsSetting(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", Password: "secret"}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","ss_network":"tcp"}`,
	}}
	raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"network": "tcp"`) && !strings.Contains(text, `"network":"tcp"`) {
		t.Fatalf("tcp-only ss: %s", text)
	}
	if strings.Contains(text, "udp_fragment") {
		t.Fatalf("tcp-only ss must not set udp_fragment: %s", text)
	}
	c.inbounds[0].SettingsJSON = `{"ss_method":"aes-128-gcm"}`
	raw, _, _, err = c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"network": "tcp"`) || strings.Contains(string(raw), `"network":"tcp"`) {
		t.Fatalf("default ss must listen both, got %s", raw)
	}
	if strings.Contains(string(raw), "udp_fragment") {
		t.Fatalf("default ss must omit udp_fragment: %s", raw)
	}
}

func TestSingBoxSSUDPFragmentCanTurnOff(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", Password: "secret"}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","udp_fragment":false}`,
	}}
	raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"udp_fragment":false`) && !strings.Contains(text, `"udp_fragment": false`) {
		t.Fatalf("explicit off: %s", text)
	}
}

func TestSingBoxSSUDPFragmentCanTurnOn(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", Password: "secret"}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","udp_fragment":true}`,
	}}
	raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"udp_fragment":true`) && !strings.Contains(text, `"udp_fragment": true`) {
		t.Fatalf("explicit on: %s", text)
	}
}

func TestXrayHTTPInboundSettingsAccounts(t *testing.T) {
	c := newXrayCore()
	c.inbounds = []InboundSpec{{
		ID: "http1", Listen: "127.0.0.1", Port: 8080, Protocol: "http",
		SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"protocol":"http"`, `"user":"sms"`, `"pass":"secret1"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestXraySOCKSInboundSettingsAccounts(t *testing.T) {
	c := newXrayCore()
	c.inbounds = []InboundSpec{{
		ID: "socks1", Listen: "127.0.0.1", Port: 1080, Protocol: "socks",
		SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"protocol":"socks"`, `"user":"sms"`, `"pass":"secret1"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestSingBoxSOCKSInboundSettingsAccounts(t *testing.T) {
	c := newSingBoxCore()
	c.inbounds = []InboundSpec{{
		ID: "socks1", Listen: "127.0.0.1", Port: 1080, Protocol: "socks",
		SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{`"type":"socks"`, `"username":"sms"`, `"password":"secret1"`} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}

func TestXrayHTTPInboundAccountSurvivesOtherInboundUsername(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{
		ID: "u1", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Username: "sms", Password: "node",
		InboundIDs: []string{"vless1"},
	}}
	c.inbounds = []InboundSpec{
		{ID: "vless1", Listen: "127.0.0.1", Port: 443, Protocol: "vless"},
		{ID: "http1", Listen: "127.0.0.1", Port: 8080, Protocol: "http",
			SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`},
	}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"protocol":"http"`) || !strings.Contains(text, `"user":"sms"`) || !strings.Contains(text, `"pass":"secret1"`) {
		t.Fatalf("http inbound account dropped: %s", text)
	}
}

func TestXrayHTTPConfigUsesUsernameAndUUID(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{
		ID: "u1", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Username: "免流", Password: "secret",
	}}
	c.inbounds = []InboundSpec{{
		ID: "http1", Listen: "127.0.0.1", Port: 8080, Protocol: "http",
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, part := range []string{
		`"protocol":"http"`,
		`"user":"免流"`,
		`"user":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
		`"pass":"secret"`,
	} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %s in %s", part, text)
		}
	}
}
