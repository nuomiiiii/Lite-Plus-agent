//go:build with_quic

package coreadapter

import (
	"net"
	"strconv"
	"testing"

	_ "github.com/sagernet/sing-box/protocol/hysteria2"
	_ "github.com/sagernet/sing-box/protocol/tuic"
)

func TestQUICLibrariesLinked(t *testing.T) {
	if !NewSingBox().Linked() {
		t.Fatal("sing-box not linked")
	}
}

func TestSingBoxUDPDualWildcardStarts(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			testSingBoxDualWildcardStart(t, protocol, "tls")
		})
	}
}

func TestSingBoxHysteria2ToHysteria2RelayForwardsLiveTraffic(t *testing.T) {
	// 1. Verify QUIC outbounds (hysteria2, tuic) strip uTLS even when fingerprint is present in SettingsJSON.
	for _, proto := range []string{"hysteria2", "tuic"} {
		ob := singBoxProxyOutbound(OutboundSpec{
			ID:       "q-" + proto,
			Name:     "q-" + proto,
			Protocol: proto,
			Enabled:  true,
			SettingsJSON: `{
				"address":"203.0.113.10","port":443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
				"password":"secret","security":"tls","sni":"hk.example.com",
				"fingerprint":"edge","alpn":"h3, h2"
			}`,
		}, "q-"+proto, map[string]string{})
		tlsMap, ok := ob["tls"].(map[string]any)
		if !ok {
			t.Fatalf("%s outbound missing tls block: %#v", proto, ob)
		}
		if _, hasUTLS := tlsMap["utls"]; hasUTLS {
			t.Fatalf("%s outbound must NOT emit tls.utls (causes 'unsupported usage for uTLS'): %#v", proto, tlsMap)
		}
		if tlsMap["server_name"] != "hk.example.com" {
			t.Fatalf("%s server_name = %v, want hk.example.com", proto, tlsMap["server_name"])
		}
		alpn, _ := tlsMap["alpn"].([]string)
		if len(alpn) != 2 || alpn[0] != "h3" || alpn[1] != "h2" {
			t.Fatalf("%s alpn = %#v, want [h3 h2]", proto, tlsMap["alpn"])
		}
	}

	// 2. End-to-end live 3-hop test:
	// Client (sing-box hy2 outbound) -> Source Node (hy2 inbound -> hy2 outbound WITH fingerprint="edge") -> Landing Node (hy2 inbound) -> TCP echo server.
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := testPEMs(t)

	// Start Landing sing-box node with Hysteria2 inbound.
	landingPort := freeUDPPort(t)
	landing := newSingBoxCore()
	defer landing.Stop()
	if err := landing.ApplyUsers([]UserSpec{{
		ID: "relay-user", Username: "__relay__", UUID: vlessAlice, Password: "relay-hy2-password",
		InboundIDs: []string{"landing-hy2"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := landing.Start(t.Context(), []InboundSpec{{
		ID: "landing-hy2", Core: "sing-box", Listen: "127.0.0.1", Port: landingPort, Protocol: "hysteria2",
		CertPEM: certPEM, KeyPEM: keyPEM,
		StreamJSON: `{"network":"quic","security":"tls","tlsSettings":{"serverName":"localhost"}}`,
	}}); err != nil {
		t.Fatalf("start landing hy2: %v", err)
	}

	// Start Source (line) sing-box node: Hysteria2 inbound -> Hysteria2 outbound (including leftover fingerprint="edge").
	sourcePort := freeUDPPort(t)
	source := newSingBoxCore()
	defer source.Stop()
	hopSettings := `{
		"address":"127.0.0.1","port":` + strconv.Itoa(landingPort) + `,
		"password":"relay-hy2-password","transport":"quic","security":"tls",
		"sni":"localhost","fingerprint":"edge","insecure":true
	}`
	source.SetForwarding(
		[]OutboundSpec{{
			ID: "hop-hy2", Name: "relay-landing-hy2", Protocol: "hysteria2",
			Enabled: true, SettingsJSON: hopSettings,
		}},
		[]RouteSpec{{
			ID: "chain-route", Name: "chain-src", Priority: 0, Enabled: true,
			RuleJSON: `{"inbound_id":"src-hy2","outbound_id":"hop-hy2"}`,
		}},
	)
	if err := source.ApplyUsers([]UserSpec{{
		ID: "end-user", Username: "alice", UUID: vlessBob, Password: "alice-hy2-password",
		QuotaBytes: 1 << 20, InboundIDs: []string{"src-hy2"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := source.Start(t.Context(), []InboundSpec{{
		ID: "src-hy2", Core: "sing-box", Listen: "127.0.0.1", Port: sourcePort, Protocol: "hysteria2",
		CertPEM: certPEM, KeyPEM: keyPEM,
		StreamJSON: `{"network":"quic","security":"tls","tlsSettings":{"serverName":"localhost"}}`,
	}}); err != nil {
		t.Fatalf("start source hy2: %v", err)
	}

	// Start Client sing-box (SOCKS5 -> Hysteria2 outbound to Source Node).
	clientSocksPort := freePort(t)
	clientBox := newSingBoxCore()
	defer clientBox.Stop()
	cliSettings := `{
		"address":"127.0.0.1","port":` + strconv.Itoa(sourcePort) + `,
		"password":"alice-hy2-password","transport":"quic","security":"tls",
		"sni":"localhost","fingerprint":"chrome","insecure":true
	}`
	clientBox.SetForwarding(
		[]OutboundSpec{{ID: "to-src", Name: "to-src", Protocol: "hysteria2", Enabled: true, SettingsJSON: cliSettings}},
		[]RouteSpec{{ID: "r-cli", Priority: 1, Enabled: true, RuleJSON: `{"inbound_id":"cli-socks","outbound_id":"to-src"}`}},
	)
	if err := clientBox.ApplyUsers([]UserSpec{{ID: "local", UUID: "local", Password: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := clientBox.Start(t.Context(), []InboundSpec{{
		ID: "cli-socks", Core: "sing-box", Listen: "127.0.0.1", Port: clientSocksPort, Protocol: "socks",
	}}); err != nil {
		t.Fatalf("start client socks->hy2: %v", err)
	}
	cliAddr := "127.0.0.1:" + strconv.Itoa(clientSocksPort)
	waitProxy(t, cliAddr)

	conn, err := socksTry(cliAddr, "local", "local", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through hy2->hy2 chain failed: %v", err)
	}
	defer conn.Close()
	if !echoConn(conn, []byte("hy2-to-hy2-end-to-end-ok")) {
		t.Fatal("payload echo through hy2->hy2 chain failed")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
