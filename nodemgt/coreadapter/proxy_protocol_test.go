package coreadapter

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPublicPresenceIPSkipsLoopback(t *testing.T) {
	for _, raw := range []string{"", "127.0.0.1", "::1", "0.0.0.0", "[::1]:443", "127.0.0.1:1234", "not-an-ip"} {
		if got := publicPresenceIP(raw); got != "" {
			t.Fatalf("%q -> %q", raw, got)
		}
	}
	if got := publicPresenceIP("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("v4 %q", got)
	}
	if got := publicPresenceIP("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("v6 %q", got)
	}
}

func TestWriteProxyProtocolV1TCP4(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			got <- err.Error()
			return
		}
		got <- line
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := writeProxyProtocolV1(client, fakeAddrConn{addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321}}, client); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "PROXY TCP4 203.0.113.9 127.0.0.1 4321 ") || !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("header %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestServeSpliceWritesProxyProtocol(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			got <- err.Error()
			return
		}
		got <- line
	}()
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	front := &spliceFront{ln: frontLn}
	go serveSplice(front, frontSpec{Dest: backend.Addr().String(), ProxyProtocol: true})
	defer func() {
		_ = frontLn.Close()
		front.mu.Lock()
		for _, c := range front.conns {
			_ = c.Close()
		}
		front.mu.Unlock()
	}()
	client, err := net.DialTimeout("tcp", frontLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "PROXY TCP4 127.0.0.1 127.0.0.1 ") || !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("header %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

type fakeAddrConn struct {
	net.Conn
	addr net.Addr
}

func (c fakeAddrConn) RemoteAddr() net.Addr { return c.addr }

func TestXrayRealityBindsPublicWithoutProxyProtocol(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Listen:     "127.0.0.1",
		Port:       443,
		Protocol:   "vless",
		Flow:       "xtls-rprx-vision",
		StreamJSON: `{"network":"tcp","security":"reality"}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "acceptProxyProtocol") {
		t.Fatalf("public reality must not use PROXY: %s", text)
	}
	if !strings.Contains(text, `"statsUserOnline":true`) {
		t.Fatalf("missing online stats: %s", text)
	}
	if !strings.Contains(text, `"listen":"127.0.0.1"`) || !strings.Contains(text, `"port":443`) {
		t.Fatalf("reality must bind public listen: %s", text)
	}
}

func TestXrayIdentityFrontOmitsProxyProtocol(t *testing.T) {
	c := newXrayCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice}}
	c.inbounds = []InboundSpec{{
		ID:         "in1",
		Listen:     "127.0.0.1",
		Port:       443,
		Protocol:   "vless",
		StreamJSON: `{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "acceptProxyProtocol") {
		t.Fatalf("identity front must not ask core for PROXY: %s", raw)
	}
}

func TestSingBoxRealityBindsPublicWithoutProxyProtocol(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{
		ID:         "reality",
		Listen:     "127.0.0.1",
		Port:       443,
		Protocol:   "vless",
		StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
	}}
	raw, err := c.configJSON()
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `"proxy_protocol":true`) {
		t.Fatalf("public reality must not use PROXY: %s", text)
	}
	if !strings.Contains(text, `"listen":"127.0.0.1"`) || !strings.Contains(text, `"listen_port":443`) {
		t.Fatalf("reality must bind public listen: %s", text)
	}
}

func TestEnableXrayProxyProtocolXHTTPUsesSockopt(t *testing.T) {
	got := enableXrayProxyProtocol(map[string]any{"network": "xhttp"})
	sock, _ := got["sockopt"].(map[string]any)
	if sock == nil || sock["acceptProxyProtocol"] != true {
		t.Fatalf("xhttp sockopt: %+v", got)
	}
	if _, ok := got["tcpSettings"]; ok {
		t.Fatalf("xhttp must not use tcpSettings: %+v", got)
	}
	split := enableXrayProxyProtocol(map[string]any{"network": "splithttp"})
	sock, _ = split["sockopt"].(map[string]any)
	if sock == nil || sock["acceptProxyProtocol"] != true {
		t.Fatalf("splithttp sockopt: %+v", split)
	}
}

func TestSingBoxSOCKSStillUsesIdentityFront(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	c.inbounds = []InboundSpec{{ID: "socks", Listen: "127.0.0.1", Port: 1080, Protocol: "socks"}}
	raw, _, fronts, err := c.buildConfig(c.users, c.inbounds, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fronts) == 0 || !fronts[0].Identity || fronts[0].Addr != "127.0.0.1:1080" {
		t.Fatalf("socks must keep the identity front: %+v", fronts)
	}
	if strings.Contains(string(raw), `"listen_port":1080`) {
		t.Fatalf("socks core must not bind the public port: %s", raw)
	}
}

func TestSingBoxTrojanAndVMessBindPublicWithoutProxyProtocol(t *testing.T) {
	c := newSingBoxCore()
	c.users = []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	for _, proto := range []string{"trojan", "vmess"} {
		c.inbounds = []InboundSpec{{
			ID: proto, Listen: "127.0.0.1", Port: 443, Protocol: proto,
			StreamJSON: `{"network":"tcp","security":"tls"}`,
			CertPEM:    "cert", KeyPEM: "key",
		}}
		raw, _, fronts, err := c.buildConfig(c.users, c.inbounds, nil, nil)
		if err != nil {
			t.Fatal(proto, err)
		}
		if strings.Contains(string(raw), `"proxy_protocol":true`) {
			t.Fatalf("%s still sets removed proxy_protocol: %s", proto, raw)
		}
		if len(fronts) != 0 {
			t.Fatalf("%s must bind the core publicly so device limits see the client IP, fronts=%+v", proto, fronts)
		}
		text := string(raw)
		if !strings.Contains(text, `"listen":"127.0.0.1"`) || !strings.Contains(text, `"listen_port":443`) {
			t.Fatalf("%s must listen on the public port: %s", proto, raw)
		}
	}
}

func TestWriteProxyProtocolV1Unknown(t *testing.T) {
	var b strings.Builder
	if err := writeProxyProtocolV1(&b, fakeAddrConn{}, nil); err != nil {
		t.Fatal(err)
	}
	if b.String() != "PROXY UNKNOWN\r\n" {
		t.Fatalf("got %q", b.String())
	}
}

func TestMergePresenceIPPrefersNewer(t *testing.T) {
	older := PresenceIP{IP: "203.0.113.10", SeenAt: time.Unix(1, 0)}
	newer := PresenceIP{IP: "203.0.113.10", SeenAt: time.Unix(2, 0)}
	out := mergePresenceIP([]PresenceIP{older}, newer)
	if len(out) != 1 || !out[0].SeenAt.Equal(newer.SeenAt) {
		t.Fatalf("%+v", out)
	}
}
