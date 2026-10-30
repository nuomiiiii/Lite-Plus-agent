package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func policySocksNetwork(raw []byte, tag string) string {
	return taggedJSONNetwork(raw, "outbounds", tag)
}

func singBoxInboundNetwork(raw []byte, tag string) string {
	return taggedJSONNetwork(raw, "inbounds", tag)
}

func taggedJSONNetwork(raw []byte, field, tag string) string {
	var cfg map[string]json.RawMessage
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	var items []map[string]any
	if json.Unmarshal(cfg[field], &items) != nil {
		return ""
	}
	for _, item := range items {
		if item["tag"] != tag {
			continue
		}
		n, _ := item["network"].(string)
		return n
	}
	return ""
}

func TestUDPHopsOK(t *testing.T) {
	if !udpHopsOK(nil) {
		t.Fatal("direct")
	}
	if !udpHopsOK([]egressHop{{Protocol: "socks", Addr: "127.0.0.1:1080"}}) {
		t.Fatal("single socks")
	}
	if udpHopsOK([]egressHop{{Protocol: "http", Addr: "127.0.0.1:8080"}}) {
		t.Fatal("http hop")
	}
	if udpHopsOK([]egressHop{{Protocol: "vless", Addr: "127.0.0.1:443"}}) {
		t.Fatal("vless hop")
	}
	if udpHopsOK([]egressHop{
		{Protocol: "socks", Addr: "127.0.0.1:1080"},
		{Protocol: "socks", Addr: "10.0.0.1:1080"},
	}) {
		t.Fatal("two hops")
	}
}

func TestSocksUDPHeaderRoundTrip(t *testing.T) {
	pkt, err := encodeSocksUDP("127.0.0.1:9", []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	dest, payload, err := parseSocksUDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if dest != "127.0.0.1:9" || string(payload) != "ping" {
		t.Fatalf("dest=%q payload=%q", dest, payload)
	}
	if _, _, err := parseSocksUDP([]byte{0, 0, 1, 1, 0, 0, 0, 0, 0, 9}); err == nil {
		t.Fatal("frag must fail")
	}
}

func TestPolicyExitTCPConnectEchoIPv6(t *testing.T) {
	echo := startEchoOn(t, "tcp6", "[::1]:0")
	if echo == nil {
		t.Skip("no ipv6 loopback")
	}
	defer echo.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-tcp-v6", UUID: "alice-tcp-v6", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()
	conn := policySOCKSConnect(t, ln.Addr().String(), "alice-tcp-v6", "pw", echo.Addr().String())
	defer conn.Close()
	assertTCPEcho(t, conn, []byte("ping-tcp-v6"))
}

func TestPolicyExitDirectHonorsDialStack(t *testing.T) {
	v4 := startEcho(t)
	defer v4.Close()
	v6 := startEchoOn(t, "tcp6", "[::1]:0")
	if v6 == nil {
		t.Skip("no ipv6 loopback")
	}
	defer v6.Close()
	udp4 := startUDPEcho(t)
	defer udp4.Close()
	udp6 := startUDPEchoOn(t, "udp6", "[::1]:0")
	if udp6 == nil {
		t.Skip("no ipv6 udp")
	}
	defer udp6.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-stack", UUID: "alice-stack", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()
	addr := ln.Addr().String()
	user, pass := "alice-stack", "pw"

	p.setDialStack("ipv4")
	if !policyTCPEchoOK(addr, user, pass, v4.Addr().String(), []byte("v4-tcp")) {
		t.Fatal("ipv4-only must reach ipv4 dest")
	}
	if policyTCPEchoOK(addr, user, pass, v6.Addr().String(), []byte("v6-tcp")) {
		t.Fatal("ipv4-only must not reach ipv6 dest")
	}
	if !policyUDPEchoOK(addr, user, pass, udp4.LocalAddr().String(), []byte("v4-udp")) {
		t.Fatal("ipv4-only must reach ipv4 udp")
	}
	if policyUDPEchoOK(addr, user, pass, udp6.LocalAddr().String(), []byte("v6-udp")) {
		t.Fatal("ipv4-only must drop ipv6 udp")
	}

	p.setDialStack("ipv6")
	if policyTCPEchoOK(addr, user, pass, v4.Addr().String(), []byte("v4-tcp6")) {
		t.Fatal("ipv6-only must not reach ipv4 dest")
	}
	if !policyTCPEchoOK(addr, user, pass, v6.Addr().String(), []byte("v6-tcp6")) {
		t.Fatal("ipv6-only must reach ipv6 dest")
	}
	if policyUDPEchoOK(addr, user, pass, udp4.LocalAddr().String(), []byte("v4-udp6")) {
		t.Fatal("ipv6-only must drop ipv4 udp")
	}
	if !policyUDPEchoOK(addr, user, pass, udp6.LocalAddr().String(), []byte("v6-udp6")) {
		t.Fatal("ipv6-only must reach ipv6 udp")
	}

	for _, stack := range []string{"dual", "prefer_ipv4", "prefer_ipv6"} {
		p.setDialStack(stack)
		if !policyTCPEchoOK(addr, user, pass, v4.Addr().String(), []byte("ok4-"+stack)) {
			t.Fatalf("%s must reach ipv4 dest", stack)
		}
		if !policyTCPEchoOK(addr, user, pass, v6.Addr().String(), []byte("ok6-"+stack)) {
			t.Fatalf("%s must reach ipv6 dest", stack)
		}
	}
}

func TestPolicyExitHopIgnoresStackForLoopback(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	hopLn, hopClose := startMiniSOCKSUDP(t)
	defer hopClose()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.setDialStack("ipv6")
	p.sync([]UserSpec{{ID: "policy-hop-stack", UUID: "alice-hop-stack", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{Egress: []egressHop{{Protocol: "socks", Addr: hopLn.Addr().String()}}}, p)
	defer front.close()
	conn := policySOCKSConnect(t, ln.Addr().String(), "alice-hop-stack", "pw", echo.Addr().String())
	defer conn.Close()
	assertTCPEcho(t, conn, []byte("hop-v6-stack"))
}

func TestPolicyExitTCPConnectEcho(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-tcp-direct", UUID: "alice-tcp", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()
	conn := policySOCKSConnect(t, ln.Addr().String(), "alice-tcp", "pw", echo.Addr().String())
	defer conn.Close()
	assertTCPEcho(t, conn, []byte("ping-tcp"))
}

func TestPolicyExitTCPAndUDPSameFront(t *testing.T) {
	tcpEcho := startEcho(t)
	defer tcpEcho.Close()
	udpEcho := startUDPEcho(t)
	defer udpEcho.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-both", UUID: "alice-both", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()

	conn := policySOCKSConnect(t, ln.Addr().String(), "alice-both", "pw", tcpEcho.Addr().String())
	defer conn.Close()
	assertTCPEcho(t, conn, []byte("both-tcp"))

	udpTCP, bind := policySOCKSUDPAssociate(t, ln.Addr().String(), "alice-both", "pw")
	defer udpTCP.Close()
	assertUDPEcho(t, bind, udpEcho.LocalAddr().String(), []byte("both-udp"))
}

func TestPolicyExitTCPConnectViaSOCKSHop(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	hopLn, hopClose := startMiniSOCKSUDP(t)
	defer hopClose()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-tcp-hop", UUID: "alice-tcp-hop", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{Egress: []egressHop{{Protocol: "socks", Addr: hopLn.Addr().String()}}}, p)
	defer front.close()
	conn := policySOCKSConnect(t, ln.Addr().String(), "alice-tcp-hop", "pw", echo.Addr().String())
	defer conn.Close()
	assertTCPEcho(t, conn, []byte("ping-tcp-hop"))
}

func TestPolicyExitUDPAssociateEcho(t *testing.T) {
	echo := startUDPEcho(t)
	defer echo.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-udp-direct", UUID: "alice-udp", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{}, p)
	defer front.close()

	tcp, bind := policySOCKSUDPAssociate(t, ln.Addr().String(), "alice-udp", "pw")
	defer tcp.Close()
	assertUDPEcho(t, bind, echo.LocalAddr().String(), []byte("ping-direct"))
}

func TestPolicyExitUDPAssociateViaSOCKSHop(t *testing.T) {
	echo := startUDPEcho(t)
	defer echo.Close()
	hopLn, hopClose := startMiniSOCKSUDP(t)
	defer hopClose()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-udp-hop", UUID: "alice-udp-hop", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{Egress: []egressHop{{Protocol: "socks", Addr: hopLn.Addr().String()}}}, p)
	defer front.close()

	tcp, bind := policySOCKSUDPAssociate(t, ln.Addr().String(), "alice-udp-hop", "pw")
	defer tcp.Close()
	assertUDPEcho(t, bind, echo.LocalAddr().String(), []byte("ping-hop"))
}

func TestPolicyExitUDPRejectsHTTPHop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "policy-udp-http", UUID: "alice-udp-http", Password: "pw"}}, nil)
	front := &spliceFront{ln: ln}
	go servePolicyExit(front, frontSpec{Egress: []egressHop{{Protocol: "http", Addr: "127.0.0.1:9"}}}, p)
	defer front.close()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	policySOCKSAuth(t, conn, "alice-udp-http", "pw")
	req, err := socks5CommandRequest(0x03, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[0] != 0x05 || head[1] != 0x07 {
		t.Fatalf("want command-not-supported, got %v", head)
	}
}

func TestSingBoxSSOutboundPolicyLiveTCPAndUDP(t *testing.T) {
	tcpEcho := startEcho(t)
	defer tcpEcho.Close()
	udpEcho := startUDPEcho(t)
	defer udpEcho.Close()

	ssPort := freePort(t)
	ss := NewSingBox()
	defer ss.Stop()
	if err := ss.ApplyUsers([]UserSpec{{ID: "peer", UUID: vlessAlice, Password: "ss-secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := ss.Start(context.Background(), []InboundSpec{{
		ID: "ss-in", Core: "sing-box", Listen: "127.0.0.1", Port: ssPort, Protocol: "shadowsocks",
		SettingsJSON: `{"ss_method":"aes-128-gcm"}`,
	}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", ssPort))

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

	for _, tc := range []struct {
		name, network  string
		wantTCP, wantUDP bool
	}{
		{name: "tcp", network: "tcp", wantTCP: true, wantUDP: false},
		{name: "udp", network: "udp", wantTCP: false, wantUDP: true},
		{name: "tcp-udp", network: "tcp,udp", wantTCP: true, wantUDP: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core := NewSingBox()
			defer core.Stop()
			settings, err := json.Marshal(map[string]any{
				"address": "127.0.0.1", "port": ssPort, "password": "ss-secret",
				"ss_method": "aes-128-gcm", "ss_network": tc.network,
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
			tcpOK := policyTCPEchoOK(policyAddr, vlessAlice, "pw", tcpEcho.Addr().String(), []byte("ss-tcp-"+tc.name))
			udpOK := policyUDPEchoOK(policyAddr, vlessAlice, "pw", udpEcho.LocalAddr().String(), []byte("ss-udp-"+tc.name))
			if tcpOK != tc.wantTCP {
				t.Fatalf("tcp through ss_network=%s got %v want %v", tc.network, tcpOK, tc.wantTCP)
			}
			if udpOK != tc.wantUDP {
				t.Fatalf("udp through ss_network=%s got %v want %v", tc.network, udpOK, tc.wantUDP)
			}
		})
	}
}

func policyFrontAddr(t *testing.T, core Core) string {
	t.Helper()
	c, ok := core.(*singBoxCore)
	if !ok {
		t.Fatalf("core %T", core)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.fronts {
		if f != nil && f.ln != nil {
			return f.ln.Addr().String()
		}
	}
	t.Fatal("no policy front")
	return ""
}

func policySOCKSConnect(t *testing.T, socksAddr, user, pass, dest string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	setTCPNoDelay(conn)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	policySOCKSAuth(t, conn, user, pass)
	req, err := socks5CommandRequest(0x01, dest)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := socks5SkipReply(conn); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

func assertTCPEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo %q want %q", got, payload)
	}
}

func policyTCPEchoOK(socksAddr, user, pass, dest string, payload []byte) bool {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	setTCPNoDelay(conn)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := policySOCKSAuthQuiet(conn, user, pass); err != nil {
		return false
	}
	req, err := socks5CommandRequest(0x01, dest)
	if err != nil {
		return false
	}
	if _, err := conn.Write(req); err != nil {
		return false
	}
	if err := socks5SkipReply(conn); err != nil {
		return false
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return false
	}
	return string(got) == string(payload)
}

func policyUDPEchoOK(socksAddr, user, pass, dest string, payload []byte) bool {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	setTCPNoDelay(conn)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := policySOCKSAuthQuiet(conn, user, pass); err != nil {
		return false
	}
	req, err := socks5CommandRequest(0x03, "0.0.0.0:0")
	if err != nil {
		return false
	}
	if _, err := conn.Write(req); err != nil {
		return false
	}
	bind, err := socks5ReadBindAddr(conn)
	if err != nil {
		return false
	}
	_ = conn.SetDeadline(time.Time{})
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(2 * time.Second))
	pkt, err := encodeSocksUDP(dest, payload)
	if err != nil {
		return false
	}
	if _, err := uc.WriteTo(pkt, bind); err != nil {
		return false
	}
	buf := make([]byte, 2048)
	n, _, err := uc.ReadFrom(buf)
	if err != nil {
		return false
	}
	_, got, err := parseSocksUDP(buf[:n])
	return err == nil && string(got) == string(payload)
}

func policySOCKSAuthQuiet(conn net.Conn, user, pass string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return err
	}
	if method[0] != 0x05 || method[1] != 0x02 {
		return fmt.Errorf("method %v", method)
	}
	if _, err := conn.Write(socks5UserPassBytes(user, pass)); err != nil {
		return err
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		return err
	}
	if auth[0] != 0x01 || auth[1] != 0 {
		return fmt.Errorf("auth %v", auth)
	}
	return nil
}

func policySOCKSUDPAssociate(t *testing.T, socksAddr, user, pass string) (net.Conn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	policySOCKSAuth(t, conn, user, pass)
	req, err := socks5CommandRequest(0x03, "0.0.0.0:0")
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	bind, err := socks5ReadBindAddr(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	udpAddr, ok := bind.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port == 0 {
		conn.Close()
		t.Fatalf("bind %v", bind)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, udpAddr
}

func policySOCKSAuth(t *testing.T, conn net.Conn, user, pass string) {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	if method[0] != 0x05 || method[1] != 0x02 {
		t.Fatalf("method %v", method)
	}
	if _, err := conn.Write(socks5UserPassBytes(user, pass)); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil {
		t.Fatal(err)
	}
	if auth[0] != 0x01 || auth[1] != 0 {
		t.Fatalf("auth %v", auth)
	}
}

func assertUDPEcho(t *testing.T, bind *net.UDPAddr, dest string, payload []byte) {
	t.Helper()
	uc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
	pkt, err := encodeSocksUDP(dest, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uc.WriteTo(pkt, bind); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := uc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotDest, got, err := parseSocksUDP(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload %q want %q dest=%s", got, payload, gotDest)
	}
}

func startUDPEcho(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc
}

func startMiniSOCKSUDP(t *testing.T) (net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMiniSOCKSUDP(conn)
		}
	}()
	return ln, func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func handleMiniSOCKSUDP(conn net.Conn) {
	defer conn.Close()
	setTCPNoDelay(conn)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req, err := readSOCKS5AddrHead(conn)
	if err != nil {
		return
	}
	if socks5Cmd(req) != 0x03 {
		dest, err := socks5Dest(req)
		if err != nil {
			return
		}
		backend, err := net.DialTimeout("tcp", dest, 2*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer backend.Close()
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		go func() { _, _ = io.Copy(backend, conn) }()
		_, _ = io.Copy(conn, backend)
		return
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer pc.Close()
	reply, err := socks5UDPBindReply(pc.LocalAddr())
	if err != nil {
		return
	}
	if _, err := conn.Write(reply); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		_, _ = io.Copy(io.Discard, conn)
	}()
	buf := make([]byte, 64*1024)
	var clientAddr net.Addr
	for {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		select {
		case <-stop:
			return
		default:
		}
		pkt := append([]byte(nil), buf[:n]...)
		if dest, payload, err := parseSocksUDP(pkt); err == nil {
			clientAddr = from
			raddr, err := net.ResolveUDPAddr("udp", dest)
			if err != nil {
				continue
			}
			if _, err := pc.WriteTo(payload, raddr); err != nil {
				return
			}
			continue
		}
		if clientAddr == nil {
			continue
		}
		wrapped, err := encodeSocksUDP(from.String(), pkt)
		if err != nil {
			continue
		}
		if _, err := pc.WriteTo(wrapped, clientAddr); err != nil {
			return
		}
	}
}
