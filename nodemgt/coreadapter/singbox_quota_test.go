package coreadapter

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func TestSingBoxBuildConfigMetersCoreOwnedNotFrontOrExit(t *testing.T) {
	c := newSingBoxCore()
	users := []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	_, _, _, err := c.buildConfig(users, []InboundSpec{
		{ID: "hy2", Port: 38403, Protocol: "hysteria2", SettingsJSON: `{"stack":"v4"}`},
		{ID: "tuic", Port: 38405, Protocol: "tuic", SettingsJSON: `{"stack":"v4"}`},
		{ID: "ss", Listen: "127.0.0.1", Port: 18388, Protocol: "shadowsocks", SettingsJSON: `{"ss_method":"aes-128-gcm"}`},
		{ID: "http", Listen: "127.0.0.1", Port: 18080, Protocol: "http"},
		{ID: "vless-ws", Listen: "127.0.0.1", Port: 18440, Protocol: "vless", StreamJSON: `{"network":"ws"}`},
		{
			ID:         "anytls",
			Listen:     "127.0.0.1",
			Port:       38404,
			Protocol:   "anytls",
			StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
		},
		{ID: "trojan", Listen: "127.0.0.1", Port: 18443, Protocol: "trojan", StreamJSON: `{"security":"tls"}`},
		{ID: "vmess", Listen: "127.0.0.1", Port: 18444, Protocol: "vmess", StreamJSON: `{"security":"tls"}`},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"hy2", "tuic", "ss", "trojan", "vmess"} {
		if !c.policy.meterCoreTag(tag) {
			t.Fatalf("%s has no front or policy exit and must be metered in-core", tag)
		}
	}
	if c.policy.meterCoreTag("http") {
		t.Fatal("http front must not also be core-metered")
	}
	if c.policy.meterCoreTag("vless-ws") {
		t.Fatal("vless ws authenticates on the policy front and must not also be core-metered")
	}
	if c.policy.meterCoreTag("anytls") {
		t.Fatal("anytls reality uses the policy SOCKS exit and must not double-count")
	}
}

func TestQuotaTrackerMetersCoreOwnedConn(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newQuotaTracker(p)
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
		got := make([]byte, 4)
		if _, err := conn.Read(got); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if got := totalUser(p.snapshots(), "u1"); got != 32 {
		t.Fatalf("metered bytes = %d, want 32", got)
	}
	_ = conn.Close()
}

func TestQuotaTrackerSkipsFrontInbound(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newQuotaTracker(p)
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
	_ = conn.Close()
}

func TestQuotaTrackerUnknownUserNotMetered(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newQuotaTracker(p)
	inner, peer := net.Pipe()
	defer peer.Close()
	md := adapter.InboundContext{Inbound: "hy2", User: "ghost"}
	conn := tr.RoutedConnection(context.Background(), inner, md, nil, nil)
	go func() { _, _ = peer.Write([]byte("ok")) }()
	b := make([]byte, 2)
	if _, err := conn.Read(b); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := totalUser(p.snapshots(), "ghost"); got != 0 {
		t.Fatalf("unknown user created quota entry: %d", got)
	}
	if got := totalUser(p.snapshots(), "u1"); got != 0 {
		t.Fatalf("unknown user charged u1: %d", got)
	}
	_ = conn.Close()
}

func TestQuotaCounterSurvivesUnwrap(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newQuotaTracker(p)
	inner, peer := net.Pipe()
	defer peer.Close()
	defer inner.Close()
	conn := tr.RoutedConnection(context.Background(), inner, adapter.InboundContext{Inbound: "hy2", User: "u1"}, nil, nil)
	_, fns := N.UnwrapCountReader(conn, nil)
	if len(fns) == 0 {
		t.Fatal("copy/splice must keep the quota CountFunc after unwrap")
	}
	_ = conn.Close()
}

func TestQuotaTrackerClosesOnExceed(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1", QuotaBytes: 4}}, nil)
	p.setMeterCore([]string{"hy2"})
	tr := newQuotaTracker(p)
	inner, peer := net.Pipe()
	defer peer.Close()
	md := adapter.InboundContext{Inbound: "hy2", User: "u1"}
	conn := tr.RoutedConnection(context.Background(), inner, md, nil, nil)
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	if _, err := conn.Write([]byte("abcd")); err != nil {
		t.Fatalf("fill write: %v", err)
	}
	if !p.userBlocked("u1") {
		t.Fatal("exhausted quota must deny the user")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("write after quota deny must fail")
	}
	if got := totalUser(p.snapshots(), "u1"); got != 4 {
		t.Fatalf("metered bytes = %d, want 4", got)
	}
	_ = conn.Close()
}

func TestQuotaPacketConnReservesSSHeaderRoom(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1"}}, nil)
	p.setMeterCore([]string{"ss"})
	tr := newQuotaTracker(p)
	ss := headroomPacketConn{}
	nat := natHop{PacketConn: ss}
	wrapped := tr.RoutedPacketConnection(context.Background(), nat, adapter.InboundContext{Inbound: "ss", User: "u1"}, nil, nil)
	outer := timeoutHop{PacketConn: wrapped}
	if got := N.CalculateFrontHeadroom(outer); got != 23 {
		t.Fatalf("front headroom=%d, want 23 after quota wrap", got)
	}
	if got := N.CalculateRearHeadroom(outer); got != 16 {
		t.Fatalf("rear headroom=%d, want 16 after quota wrap", got)
	}
	_, fns := N.UnwrapCountPacketReader(wrapped, nil)
	if len(fns) == 0 {
		t.Fatal("packet copy must keep the quota CountFunc after unwrap")
	}
	_ = wrapped.Close()
}
