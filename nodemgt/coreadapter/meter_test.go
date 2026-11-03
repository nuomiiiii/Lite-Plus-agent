package coreadapter

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestTrackerMetersCoreOwnedConn(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newIPLimitTracker(p)
	inner, peer := net.Pipe()
	defer peer.Close()
	md := adapter.InboundContext{Inbound: "hy2", User: "u1"}
	conn := tr.RoutedConnection(context.Background(), inner, md, nil, nil)
	go func() {
		buf := make([]byte, 4)
		for i := 0; i < 4; i++ {
			if _, err := peer.Read(buf); err != nil {
				return
			}
			if _, err := peer.Write(buf); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 4; i++ {
		if _, err := conn.Write([]byte("abcd")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := make([]byte, 4); true {
			if _, err := conn.Read(got); err != nil {
				t.Fatalf("read: %v", err)
			}
		}
	}
	if got := totalUser(p.snapshots(), "u1"); got != 32 {
		t.Fatalf("metered bytes = %d, want 32", got)
	}
	conn.Close()
}

func TestTrackerSkipsFrontInbound(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newIPLimitTracker(p)
	inner, peer := net.Pipe()
	defer peer.Close()
	md := adapter.InboundContext{Inbound: "front", User: "u1"}
	conn := tr.RoutedConnection(context.Background(), inner, md, nil, nil)
	go func() { _, _ = peer.Write([]byte("ok")) }()
	b := make([]byte, 2)
	if _, err := conn.Read(b); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := totalUser(p.snapshots(), "u1"); got != 0 {
		t.Fatalf("front inbound metered %d bytes, want 0", got)
	}
	conn.Close()
}
