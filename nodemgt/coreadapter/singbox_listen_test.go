package coreadapter

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSingBoxTCPDualWildcardStarts(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		security string
	}{
		{"anytls", "tls"},
		{"anytls", "reality"},
		{"vless", "reality"},
	} {
		t.Run(tc.protocol+"/"+tc.security, func(t *testing.T) {
			testSingBoxDualWildcardStart(t, tc.protocol, tc.security)
		})
	}
}

func TestXrayTCPDualWildcardStarts(t *testing.T) {
	testXrayDualWildcardStart(t)
}

func testSingBoxDualWildcardStart(t *testing.T, protocol, security string) {
	t.Helper()
	in := dualWildcardInbound(t, "sing-box", protocol, security)
	core := NewSingBox()
	t.Cleanup(func() { _ = core.Stop() })
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "test-password"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{in}); err != nil {
		t.Fatalf("dual-stack %s/%s failed to start: %v", protocol, security, err)
	}
	hosts := publicCoreListenHosts(FrontListenHosts("dual", in.Listen), "tcp4")
	if udpInbound(protocol) {
		assertWildcardUDPHeld(t, in.Port, hosts)
		return
	}
	assertWildcardTCPDial(t, in.Port, hosts)
}

func testXrayDualWildcardStart(t *testing.T) {
	t.Helper()
	in := dualWildcardInbound(t, "xray", "vless", "reality")
	core := NewXray()
	t.Cleanup(func() { _ = core.Stop() })
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "test-password"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{in}); err != nil {
		t.Fatalf("dual-stack xray/vless/reality failed to start: %v", err)
	}
	hosts := publicCoreListenHosts(FrontListenHosts("dual", in.Listen), "tcp")
	assertWildcardTCPDial(t, in.Port, hosts)
}

func dualWildcardInbound(t *testing.T, coreName, protocol, security string) InboundSpec {
	t.Helper()
	in := InboundSpec{
		ID:           "dual",
		Core:         coreName,
		Protocol:     protocol,
		Listen:       "0.0.0.0,::",
		Port:         freePort(t),
		SettingsJSON: `{"stack":"dual"}`,
	}
	stream := map[string]any{
		"network":  "tcp",
		"security": security,
	}
	if security == "reality" {
		priv, _ := realityKeys(t)
		stream["realitySettings"] = map[string]any{
			"dest":        "127.0.0.1:9",
			"serverNames": []string{"audit.test"},
			"privateKey":  priv,
			"shortIds":    []string{"abcd"},
		}
	} else {
		in.CertPEM, in.KeyPEM = testPEMs(t)
	}
	raw, err := json.Marshal(stream)
	if err != nil {
		t.Fatal(err)
	}
	in.StreamJSON = string(raw)
	return in
}

func dualWildcardFamilies(hosts []string) (v4, v6 bool) {
	for _, host := range hosts {
		switch host {
		case "0.0.0.0":
			v4 = true
		case "::":
			v6 = true
		}
	}
	if v6 && !v4 {
		return true, true
	}
	return v4, v6
}

func assertWildcardTCPDial(t *testing.T, port int, hosts []string) {
	t.Helper()
	v4, v6 := dualWildcardFamilies(hosts)
	if v4 {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 400*time.Millisecond)
		if err != nil {
			t.Fatalf("ipv4 dial %v on %v: %v", port, hosts, err)
		}
		_ = conn.Close()
	}
	if v6 {
		conn, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)), 400*time.Millisecond)
		if err != nil {
			t.Fatalf("ipv6 dial %v on %v: %v", port, hosts, err)
		}
		_ = conn.Close()
	}
}

func assertWildcardUDPHeld(t *testing.T, port int, hosts []string) {
	t.Helper()
	v4, v6 := dualWildcardFamilies(hosts)
	if v4 {
		conn, err := net.ListenPacket("udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			t.Fatalf("udp4 %d still free after start (%v)", port, hosts)
		}
	}
	if v6 {
		conn, err := net.ListenPacket("udp", net.JoinHostPort("::", strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			t.Fatalf("udp %d still free after start (%v)", port, hosts)
		}
	}
}

func TestSingBoxPublicUDPListenUsesPacketProbe(t *testing.T) {
	raw, err := os.ReadFile("singbox_linked.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "publicListenHostsForProtocol(hosts, inboundListensTCP(in), inboundListensUDP(in))") {
		t.Fatal("public sing-box UDP inbounds must probe UDP overlap, not tcp4")
	}
	if strings.Contains(text, `publicCoreListenHosts(hosts, "tcp4")`) {
		t.Fatal("sing-box public listen hosts still hardcode tcp4")
	}
}
