package coreadapter

import (
	"net"
	"testing"
	"time"
)

func requireAltLoopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := &net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("need 127.0.0.2 as a second source IP: %v", err)
	}
	c.Close()
}

func TestIPGuardCountsUniqueIPsNotSessions(t *testing.T) {
	g := newIPGuard()
	if !g.hold("u1", "203.0.113.10:443", 1) {
		t.Fatal("first ip")
	}
	if !g.hold("u1", "203.0.113.10", 1) {
		t.Fatal("same ip second conn")
	}
	if g.hold("u1", "203.0.113.11", 1) {
		t.Fatal("second ip must be rejected")
	}
	g.release("u1", "203.0.113.10")
	if g.hold("u1", "198.51.100.9", 1) {
		t.Fatal("first ip still held")
	}
	g.release("u1", "203.0.113.10")
	if !g.hold("u1", "198.51.100.9", 1) {
		t.Fatal("slot after last conn of first ip")
	}
	if g.hold("u1", "", 1) {
		t.Fatal("empty ip")
	}
	if !g.hold("u1", "203.0.113.10", 0) {
		t.Fatal("limit 0 is unlimited")
	}
	live := g.liveIPs()["u1"]
	found := false
	for _, ip := range live {
		if ip == "203.0.113.10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unlimited still tracks live ip: %v", live)
	}
}
