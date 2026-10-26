package coreadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	vlessAlice = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	vlessBob   = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func TestDualCoreVLESSPersonalControl(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)

	xrayPort := freePort(t)
	sbPort := freePort(t)
	xray := NewXray()
	sb := NewSingBox()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer xray.Stop()
	defer sb.Stop()

	users := []UserSpec{
		{ID: "u1", UUID: vlessAlice, Password: "pw1", QuotaBytes: 1 << 20},
		{ID: "u2", UUID: vlessBob, Password: "pw2", QuotaBytes: 1 << 20},
	}
	if err := xray.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := sb.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := xray.Start(ctx, []InboundSpec{{
		ID: "xray-vless", Core: "xray", Listen: "127.0.0.1", Port: xrayPort, Protocol: "vless",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(ctx, []InboundSpec{{
		ID: "sb-vless", Core: "sing-box", Listen: "127.0.0.1", Port: sbPort, Protocol: "vless",
	}}); err != nil {
		t.Fatal(err)
	}

	payload := []byte("lite-nodemgt-vless")
	for _, tc := range []struct{ name, addr, uuid string }{
		{"xray-alice", fmt.Sprintf("127.0.0.1:%d", xrayPort), vlessAlice},
		{"xray-bob", fmt.Sprintf("127.0.0.1:%d", xrayPort), vlessBob},
		{"singbox-alice", fmt.Sprintf("127.0.0.1:%d", sbPort), vlessAlice},
		{"singbox-bob", fmt.Sprintf("127.0.0.1:%d", sbPort), vlessBob},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waitProxy(t, tc.addr)
			got := vlessEcho(t, tc.addr, tc.uuid, host, destPort, payload, false)
			if string(got) != string(payload) {
				t.Fatalf("echo %q", got)
			}
		})
	}

	if _, err := vlessRoundTrip(fmt.Sprintf("127.0.0.1:%d", xrayPort), "ffffffff-ffff-ffff-ffff-ffffffffffff", host, destPort, payload, false); err == nil {
		t.Fatal("xray accepted unknown uuid")
	}

	if err := xray.CloseUserSessions("u1"); err != nil {
		t.Fatal(err)
	}
	if err := sb.CloseUserSessions("u1"); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", xrayPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", sbPort))

	if got := vlessEcho(t, fmt.Sprintf("127.0.0.1:%d", xrayPort), vlessBob, host, destPort, payload, false); string(got) != string(payload) {
		t.Fatalf("xray bob after alice disable: %q", got)
	}
	if got := vlessEcho(t, fmt.Sprintf("127.0.0.1:%d", sbPort), vlessBob, host, destPort, payload, false); string(got) != string(payload) {
		t.Fatalf("sing-box bob after alice disable: %q", got)
	}
	if _, err := vlessRoundTrip(fmt.Sprintf("127.0.0.1:%d", xrayPort), vlessAlice, host, destPort, payload, false); err == nil {
		t.Fatal("xray still allowed disabled vless user")
	}
}

func TestXrayVLESSTLS(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	certPEM, keyPEM := testPEMs(t)
	port := freePort(t)
	xray := NewXray()
	defer xray.Stop()
	users := []UserSpec{{ID: "u1", UUID: vlessAlice, QuotaBytes: 1 << 20}}
	if err := xray.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := xray.Start(context.Background(), []InboundSpec{{
		ID: "xray-vless-tls", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "vless",
		CertPEM: certPEM, KeyPEM: keyPEM,
	}}); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitProxy(t, addr)
	payload := []byte("vless-tls")
	got := vlessEcho(t, addr, vlessAlice, host, destPort, payload, true)
	if string(got) != string(payload) {
		t.Fatalf("echo %q", got)
	}
}

func TestTLSVLESSQuotaDeviceAndPeerSession(t *testing.T) {
	requireAltLoopback(t)
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	certPEM, keyPEM := testPEMs(t)
	for _, core := range []Core{NewXray(), NewSingBox()} {
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			port := freePort(t)
			if err := core.ApplyUsers([]UserSpec{
				{ID: "u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 32, DeviceLimit: 1},
				{ID: "u2", UUID: vlessBob, Password: "pw", QuotaBytes: 1 << 20},
			}); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "tls", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				CertPEM: certPEM, KeyPEM: keyPEM,
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			alice, err := vlessOpenTLS(addr, vlessAlice, host, destPort)
			if err != nil {
				t.Fatal(err)
			}
			defer alice.Close()
			same, err := vlessOpenTLS(addr, vlessAlice, host, destPort)
			if err != nil {
				t.Fatal("same ip extra conn")
			}
			same.Close()
			if _, err := vlessOpenTLSFrom(addr, vlessAlice, host, destPort, "127.0.0.2"); err == nil {
				t.Fatal("second tls ip allowed")
			}
			bob, err := vlessOpenTLS(addr, vlessBob, host, destPort)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Close()
			if echoConn(alice, make([]byte, 65536)) {
				t.Fatal("tls vless quota allowed 64KiB")
			}
			if err := core.CloseUserSessions("u1"); err != nil {
				t.Fatal(err)
			}
			if !echoConn(bob, []byte("stay")) {
				t.Fatal("healthy tls session dropped")
			}
			if echoConn(alice, []byte("dead")) {
				t.Fatal("revoked tls session still alive")
			}
		})
	}
}

func presenceHasIP(rows []Presence, userID, ip string) bool {
	for _, row := range rows {
		if row.UserID != userID || !row.Online {
			continue
		}
		for _, item := range row.IPs {
			if item.IP == ip {
				return true
			}
		}
	}
	return false
}

func TestVLESSPresenceIncludesClientIP(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	payload := []byte("vless-ip")
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			port := freePort(t)
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "vless", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)
			conn, err := vlessRoundTripConn(addr, vlessAlice, host, destPort, payload, false)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if !presenceHasIP(core.Presence(), "u1", "127.0.0.1") {
				t.Fatalf("vless identity presence %+v", core.Presence())
			}
			conn.Close()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if !presenceHasIP(core.Presence(), "u1", "127.0.0.1") {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatalf("offline still has ip %+v", core.Presence())
		})
	}
}

func TestVLESSRealityPresenceIncludesClientIP(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, _ := auditCerts(t)
	decoy := startTLS13Decoy(t, certPEM, keyPEM)
	defer decoy.Close()
	priv, pub := realityKeys(t)
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
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		core := maker()
		t.Run(core.Name(), func(t *testing.T) {
			defer core.Stop()
			if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			if err := core.Start(context.Background(), []InboundSpec{{
				ID: "reality", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
				StreamJSON: string(stream),
			}}); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
			cli, conn, err := xrayDialRetry(port, vlessAlice, "", "reality", pub, "", echo.Addr().String())
			if err != nil {
				t.Fatalf("reality connect: %v", err)
			}
			defer cli.Close()
			defer conn.Close()
			if core.Name() == "xray" && !echoConn(conn, []byte("ip")) {
				t.Fatal("xray reality echo")
			}
			found := false
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if presenceHasIP(core.Presence(), "u1", "127.0.0.1") {
					found = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !found {
				t.Fatalf("vless reality presence %+v", core.Presence())
			}
		})
	}
}

func TestVLESSWebSocketHandshake(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	certPEM, keyPEM := testPEMs(t)
	header, err := encodeVLESSHeader(vlessAlice, host, destPort)
	if err != nil {
		t.Fatal(err)
	}
	for _, maker := range []func() Core{NewXray, NewSingBox} {
		for _, secure := range []bool{false, true} {
			core := maker()
			name := core.Name() + "/ws"
			if secure {
				name = core.Name() + "/wss"
			}
			t.Run(name, func(t *testing.T) {
				defer core.Stop()
				port := freePort(t)
				if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
					t.Fatal(err)
				}
				in := InboundSpec{
					ID: "ws", Core: core.Name(), Listen: "127.0.0.1", Port: port, Protocol: "vless",
					StreamJSON: `{"network":"ws","wsSettings":{"path":"/audit"}}`,
				}
				scheme := "ws"
				if secure {
					in.CertPEM, in.KeyPEM = certPEM, keyPEM
					scheme = "wss"
				}
				if err := core.Start(context.Background(), []InboundSpec{in}); err != nil {
					t.Fatal(err)
				}
				waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))
				d := websocket.Dialer{HandshakeTimeout: 2 * time.Second, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				wc, _, err := d.Dial(fmt.Sprintf("%s://127.0.0.1:%d/audit", scheme, port), nil)
				if err != nil {
					t.Fatalf("handshake: %v", err)
				}
				defer wc.Close()
				_ = wc.SetReadDeadline(time.Now().Add(3 * time.Second))
				if err := wc.WriteMessage(websocket.BinaryMessage, append(header, []byte("echo")...)); err != nil {
					t.Fatal(err)
				}
				var response []byte
				for len(response) < 6 {
					_, payload, err := wc.ReadMessage()
					if err != nil {
						t.Fatalf("read: %v", err)
					}
					response = append(response, payload...)
				}
				if string(response[len(response)-4:]) != "echo" {
					t.Fatalf("echo %q", response)
				}
			})
		}
	}
}

func TestXrayMixedSOCKSAndTLSMeter(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	var destPort int
	fmt.Sscanf(portStr, "%d", &destPort)
	certPEM, keyPEM := testPEMs(t)
	core := NewXray()
	defer core.Stop()
	tlsPort, socksPort := freePort(t), freePort(t)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{
		{ID: "tls", Core: "xray", Listen: "127.0.0.1", Port: tlsPort, Protocol: "vless", CertPEM: certPEM, KeyPEM: keyPEM},
		{ID: "socks", Core: "xray", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks"},
	}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", tlsPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", socksPort))
	tlsConn, err := vlessOpenTLS(fmt.Sprintf("127.0.0.1:%d", tlsPort), vlessAlice, host, destPort)
	if err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()
	if !echoConn(tlsConn, make([]byte, 20)) {
		t.Fatal("tls echo")
	}
	socksConn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", socksPort), vlessAlice, "pw", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer socksConn.Close()
	if !echoConn(socksConn, make([]byte, 10)) {
		t.Fatal("socks echo")
	}
	first := core.TakeSnapshots()
	if total := totalUser(first, "u1"); total != 62 {
		t.Fatalf("mixed snapshot %d %+v", total, first)
	}
	core.AcknowledgeUsage()
	if idle := core.TakeSnapshots(); totalUser(idle, "u1") != 0 {
		t.Fatalf("idle %+v", idle)
	}
}

func vlessOpenTLS(addr, id, destHost string, destPort int) (net.Conn, error) {
	return vlessOpenTLSFrom(addr, id, destHost, destPort, "")
}

func vlessOpenTLSFrom(addr, id, destHost string, destPort int, localIP string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	if localIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	header, err := encodeVLESSHeader(id, destHost, destPort)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(append(header, 0x42)); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] > 0 {
		if _, err := io.ReadFull(conn, make([]byte, int(resp[1]))); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func vlessEcho(t *testing.T, addr, id, destHost string, destPort int, payload []byte, useTLS bool) []byte {
	t.Helper()
	got, err := vlessRoundTrip(addr, id, destHost, destPort, payload, useTLS)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func vlessRoundTripConn(addr, id, destHost string, destPort int, payload []byte, useTLS bool) (net.Conn, error) {
	var conn net.Conn
	var err error
	if useTLS {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	header, err := encodeVLESSHeader(id, destHost, destPort)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(append(header, payload...)); err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] > 0 {
		if _, err := io.ReadFull(conn, make([]byte, int(resp[1]))); err != nil {
			conn.Close()
			return nil, err
		}
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func vlessRoundTrip(addr, id, destHost string, destPort int, payload []byte, useTLS bool) ([]byte, error) {
	var conn net.Conn
	var err error
	if useTLS {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 3*time.Second)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	header, err := encodeVLESSHeader(id, destHost, destPort)
	if err != nil {
		return nil, err
	}
	// Xray buffers the VLESS response until the first downlink write. Send
	// payload with the request so the echo dest can reply and flush it.
	frame := append(header, payload...)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[1] > 0 {
		if _, err := io.ReadFull(conn, make([]byte, int(resp[1]))); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func encodeVLESSHeader(id, destHost string, destPort int) ([]byte, error) {
	parsed, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 64)
	buf = append(buf, 0)
	buf = append(buf, parsed[:]...)
	buf = append(buf, 0)
	buf = append(buf, 1)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(destPort))
	buf = append(buf, portBytes...)
	if ip := net.ParseIP(destHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 1)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 3)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, 2, byte(len(destHost)))
		buf = append(buf, destHost...)
	}
	return buf, nil
}

func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	var a, b, c, d, e uint64
	n, err := fmt.Sscanf(s, "%08x-%04x-%04x-%04x-%012x", &a, &b, &c, &d, &e)
	if err != nil || n != 5 {
		return out, fmt.Errorf("uuid %q", s)
	}
	binary.BigEndian.PutUint32(out[0:4], uint32(a))
	binary.BigEndian.PutUint16(out[4:6], uint16(b))
	binary.BigEndian.PutUint16(out[6:8], uint16(c))
	binary.BigEndian.PutUint16(out[8:10], uint16(d))
	for i := 5; i >= 0; i-- {
		out[10+i] = byte(e)
		e >>= 8
	}
	return out, nil
}

func testPEMs(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "nodemgt-vless"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}
