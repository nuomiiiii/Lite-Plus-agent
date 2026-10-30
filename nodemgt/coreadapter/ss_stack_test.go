package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestListenWANUDPIsNotLoopbackOnly(t *testing.T) {
	wan, err := listenWANUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer wan.Close()
	if wan.v4 == nil {
		t.Fatal("wan udp must keep an IPv4 wildcard; 127.0.0.1 bind is the reported global DNS failure")
	}
	for _, pc := range wan.conns() {
		host, _, err := net.SplitHostPort(pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			t.Fatalf("wan udp must not bind loopback, got %s", host)
		}
	}
}

func TestWANUDPEchoIPv4AndIPv6(t *testing.T) {
	wan, err := listenWANUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer wan.Close()

	v4 := startUDPEchoOn(t, "udp4", "127.0.0.1:0")
	defer v4.Close()
	if wan.v4 == nil {
		t.Fatal("missing ipv4 wan")
	}
	_ = wan.v4.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := wan.WriteTo([]byte("v4"), v4.LocalAddr()); err != nil {
		t.Fatalf("wan write v4: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := wan.v4.ReadFrom(buf)
	if err != nil {
		t.Fatalf("wan read v4: %v", err)
	}
	if string(buf[:n]) != "v4" {
		t.Fatalf("wan v4 echo %q", buf[:n])
	}

	v6 := startUDPEchoOn(t, "udp6", "[::1]:0")
	if v6 == nil {
		return
	}
	defer v6.Close()
	if wan.v6 == nil {
		t.Fatal("ipv6 loopback exists but wan has no ipv6 socket")
	}
	_ = wan.v6.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := wan.WriteTo([]byte("v6"), v6.LocalAddr()); err != nil {
		t.Fatalf("wan write v6: %v", err)
	}
	n, _, err = wan.v6.ReadFrom(buf)
	if err != nil {
		t.Fatalf("wan read v6: %v", err)
	}
	if string(buf[:n]) != "v6" {
		t.Fatalf("wan v6 echo %q", buf[:n])
	}
}

func TestWANUDPPicksSocketByDestinationFamily(t *testing.T) {
	wan, err := listenWANUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer wan.Close()
	if wan.connFor(&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}) != wan.v4 {
		t.Fatal("ipv4 dest must use ipv4 wan")
	}
	if wan.v6 != nil && wan.connFor(&net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}) != wan.v6 {
		t.Fatal("ipv6 dest must use ipv6 wan")
	}
	if wan.connFor(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}) != wan.v4 {
		t.Fatal("loopback hop must stay on ipv4 wan, not the client 127.0.0.1 socket")
	}
	missing := &wanUDP{v4: wan.v4}
	if missing.connFor(&net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}) != nil {
		t.Fatal("ipv6 dest must not fall back onto the ipv4 socket")
	}
}

func TestWANUDPWriteToPublicIPv4DoesNotFailImmediately(t *testing.T) {
	wan, err := listenWANUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer wan.Close()
	if wan.v4 == nil {
		t.Fatal("missing ipv4 wan")
	}
	dest := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
	if _, err := wan.WriteTo([]byte{0}, dest); err != nil {
		t.Fatalf("wildcard wan must send ipv4, got %v", err)
	}
	loop, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if _, err := loop.WriteTo([]byte{0}, dest); err == nil {
		t.Log("this OS allows loopback-bound udp to reach 1.1.1.1; the reported global failure still requires the wildcard wan")
	}
}

func TestRewriteUDPBindUnspecified(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	got := rewriteUDPBind(&net.UDPAddr{IP: net.IPv4zero, Port: 9}, client)
	ua, ok := got.(*net.UDPAddr)
	if !ok || ua.Port != 9 || !ua.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("unspecified bind %v", got)
	}
}

func TestPolicyExitUDPAssociateEchoIPv6(t *testing.T) {
	echo := startUDPEchoOn(t, "udp6", "[::1]:0")
	if echo == nil {
		t.Skip("no ipv6 loopback")
	}
	defer echo.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-udp-v6", UUID: "alice-udp-v6", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()
	tcp, bind := policySOCKSUDPAssociate(t, ln.Addr().String(), "alice-udp-v6", "pw")
	defer tcp.Close()
	assertUDPEcho(t, bind, echo.LocalAddr().String(), []byte("ping-v6"))
}

func TestSingBoxSSInboundStackListen(t *testing.T) {
	for _, tc := range []struct {
		stack string
		want  string
	}{
		{stack: "ipv4", want: "0.0.0.0"},
		{stack: "ipv6", want: "::"},
	} {
		t.Run(tc.stack, func(t *testing.T) {
			c := newSingBoxCore()
			c.users = []UserSpec{{ID: "u1", Password: "secret"}}
			c.inbounds = []InboundSpec{{
				ID: "ss1", Listen: "::", Port: 8388, Protocol: "shadowsocks",
				SettingsJSON: fmt.Sprintf(`{"ss_method":"aes-128-gcm","stack":%q}`, tc.stack),
			}}
			raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := ssInboundListen(raw, "ss1"); got != tc.want {
				t.Fatalf("ss inbound listen=%q want %q in %s", got, tc.want, raw)
			}
		})
	}
}

func TestXraySSInboundStackListen(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "secret"}}
	c.inbounds = []InboundSpec{{
		ID: "ss1", Listen: "::", Port: 8388, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","stack":"ipv6"}`,
	}}
	raw, _, _, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := xrayInboundListen(raw, "ss1"); got != "::" {
		t.Fatalf("xray ss ipv6 listen=%q in %s", got, raw)
	}
}

func TestSingBoxSSInboundIPv6ThenOutbound(t *testing.T) {
	if !ipv6LoopbackOK() {
		t.Skip("no ipv6 loopback")
	}
	tcp4 := startEcho(t)
	defer tcp4.Close()
	tcp6 := startEchoOn(t, "tcp6", "[::1]:0")
	if tcp6 == nil {
		t.Skip("no ipv6 tcp echo")
	}
	defer tcp6.Close()
	udp4 := startUDPEchoOn(t, "udp4", "127.0.0.1:0")
	defer udp4.Close()
	udp6 := startUDPEchoOn(t, "udp6", "[::1]:0")
	if udp6 == nil {
		t.Skip("no ipv6 udp echo")
	}
	defer udp6.Close()

	core := NewSingBox()
	defer core.Stop()
	port := freePort(t)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw1"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "ss1", Core: "sing-box", Listen: "::", Port: port, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","stack":"ipv6"}`,
	}}); err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("::1", strconv.Itoa(port))
	waitProxy(t, addr)
	payload := []byte("ss-v6-in")
	if got := ssEcho(t, addr, "aes-128-gcm", "pw1", tcp4.Addr().String(), payload); string(got) != string(payload) {
		t.Fatalf("tcp v4 dest via v6 ss inbound %q", got)
	}
	if got := ssEcho(t, addr, "aes-128-gcm", "pw1", tcp6.Addr().String(), payload); string(got) != string(payload) {
		t.Fatalf("tcp v6 dest via v6 ss inbound %q", got)
	}
	got, err := ssUDPRoundTrip(addr, "aes-128-gcm", "pw1", udp4.LocalAddr().String(), payload)
	if err != nil {
		t.Fatalf("udp v4 dest via v6 ss inbound: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("udp v4 dest %q", got)
	}
	got, err = ssUDPRoundTrip(addr, "aes-128-gcm", "pw1", udp6.LocalAddr().String(), payload)
	if err != nil {
		t.Fatalf("udp v6 dest via v6 ss inbound: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("udp v6 dest %q", got)
	}
}

func TestSingBoxSSOutboundIPv6ThroughPolicy(t *testing.T) {
	if !ipv6LoopbackOK() {
		t.Skip("no ipv6 loopback")
	}
	tcp4 := startEcho(t)
	defer tcp4.Close()
	udp4 := startUDPEchoOn(t, "udp4", "127.0.0.1:0")
	defer udp4.Close()
	udp6 := startUDPEchoOn(t, "udp6", "[::1]:0")
	if udp6 == nil {
		t.Skip("no ipv6 udp echo")
	}
	defer udp6.Close()

	ssPort := freePort(t)
	ss := NewSingBox()
	defer ss.Stop()
	if err := ss.ApplyUsers([]UserSpec{{ID: "peer", UUID: vlessAlice, Password: "ss-secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := ss.Start(context.Background(), []InboundSpec{{
		ID: "ss-in", Core: "sing-box", Listen: "::", Port: ssPort, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm","stack":"ipv6"}`,
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, net.JoinHostPort("::1", strconv.Itoa(ssPort)))

	certPEM, keyPEM, _ := auditCerts(t)
	decoy := startTLS13Decoy(t, certPEM, keyPEM)
	defer decoy.Close()
	priv, _ := realityKeys(t)
	stream, err := json.Marshal(map[string]any{
		"network": "tcp", "security": "reality",
		"realitySettings": map[string]any{
			"dest": decoy.Addr().String(), "target": decoy.Addr().String(),
			"serverNames": []string{"audit.test"}, "privateKey": priv, "shortIds": []string{"abcd"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	core := NewSingBox()
	defer core.Stop()
	settings, err := json.Marshal(map[string]any{
		"address": "::1", "port": ssPort, "password": "ss-secret",
		"ss_method": "aes-128-gcm", "ss_network": "tcp,udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	setForwarding(t, core, []OutboundSpec{{
		ID: "audit-exit", Name: "audit-exit", Protocol: "shadowsocks", Enabled: true,
		SettingsJSON: string(settings),
	}}, []RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"audit-exit"}`}})
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: "sing-box", Listen: "127.0.0.1", Port: port, Protocol: "vless",
		StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	policyAddr := policyFrontAddr(t, core)
	if !policyTCPEchoOK(policyAddr, vlessAlice, "pw", tcp4.Addr().String(), []byte("ss6-tcp")) {
		t.Fatal("tcp through ipv6 ss outbound")
	}
	if !policyUDPEchoOK(policyAddr, vlessAlice, "pw", udp4.LocalAddr().String(), []byte("ss6-udp4")) {
		t.Fatal("udp v4 dest through ipv6 ss outbound")
	}
	if !policyUDPEchoOK(policyAddr, vlessAlice, "pw", udp6.LocalAddr().String(), []byte("ss6-udp6")) {
		t.Fatal("udp v6 dest through ipv6 ss outbound")
	}
}

func ssInboundListen(raw []byte, tag string) string {
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	for _, in := range cfg.Inbounds {
		if in["tag"] != tag {
			continue
		}
		s, _ := in["listen"].(string)
		return s
	}
	return ""
}

func xrayInboundListen(raw []byte, tag string) string {
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	for _, in := range cfg.Inbounds {
		if in["tag"] != tag {
			continue
		}
		s, _ := in["listen"].(string)
		return s
	}
	return ""
}

func ipv6LoopbackOK() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func startEchoOn(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln
}

func startUDPEchoOn(t *testing.T, network, addr string) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return pc
}
