package coreadapter

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSnapshotAckKeepsBytesAfterCapture(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}, nil)
	if _, ok := p.takeBytes("u1", 10, nil); !ok {
		t.Fatal("first 10")
	}
	first := p.snapshots()
	if totalSnap(first) != 10 {
		t.Fatalf("first %d", totalSnap(first))
	}
	if _, ok := p.takeBytes("u1", 20, nil); !ok {
		t.Fatal("between")
	}
	p.ack()
	if _, ok := p.takeBytes("u1", 30, nil); !ok {
		t.Fatal("after ack")
	}
	next := p.snapshots()
	if totalSnap(next) != 50 {
		t.Fatalf("next %d want 50", totalSnap(next))
	}
}

func TestSnapshotRetryBeforeAck(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}, nil)
	if _, ok := p.takeBytes("u1", 20, nil); !ok {
		t.Fatal("seed")
	}
	first := p.snapshots()
	retry := p.snapshots()
	if totalSnap(first) != 20 || totalSnap(retry) != 20 {
		t.Fatalf("first %d retry %d", totalSnap(first), totalSnap(retry))
	}
	if _, ok := p.takeBytes("u1", 20, nil); !ok {
		t.Fatal("gap")
	}
	if totalSnap(p.snapshots()) != 20 {
		t.Fatal("retry should keep captured watermark")
	}
	p.ack()
	if totalSnap(p.snapshots()) != 20 {
		t.Fatal("bytes after failed persist should remain")
	}
}

func TestIdleSnapshotEmptyAfterAck(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}, nil)
	if _, ok := p.takeBytes("u1", 20, nil); !ok {
		t.Fatal("seed")
	}
	if totalSnap(p.snapshots()) != 20 {
		t.Fatal("first")
	}
	p.ack()
	if snaps := p.snapshots(); len(snaps) != 0 {
		t.Fatalf("idle %+v", snaps)
	}
}

func TestSharedQuotaAcrossEngines(t *testing.T) {
	a := newPolicyEngine()
	b := newPolicyEngine()
	users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 100}}
	a.sync(users, nil)
	b.sync(users, nil)
	if _, ok := a.takeBytes("u1", 80, nil); !ok {
		t.Fatal("first engine")
	}
	_, _ = b.takeBytes("u1", 80, nil)
	if _, ok := b.takeBytes("u1", 1, nil); ok {
		t.Fatal("second engine should share quota")
	}
}

func TestEgressChainKeepsViaOrder(t *testing.T) {
	specs := []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "socks", SettingsJSON: `{"address":"10.0.0.1","port":1080,"via_outbound":"audit-B"}`},
	}
	hops, ok := egressChain("audit-A", specs, map[string]bool{})
	if !ok || len(hops) != 2 {
		t.Fatalf("hops %d ok %t %+v", len(hops), ok, hops)
	}
	if hops[0].Addr != "127.0.0.1:1081" || hops[1].Addr != "10.0.0.1:1080" {
		t.Fatalf("order %+v", hops)
	}
	if hops, ok := egressChain("audit-direct", []OutboundSpec{{ID: "audit-direct", Name: "audit-direct", Protocol: "freedom"}}, map[string]bool{}); !ok || len(hops) != 0 {
		t.Fatalf("direct hops %+v ok %t", hops, ok)
	}
}

func TestEgressChainVLESSViaSOCKSIsComplete(t *testing.T) {
	specs := []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "vless", SettingsJSON: `{"address":"10.0.0.1","port":443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","via_outbound":"audit-B"}`},
	}
	hops, ok := egressChain("audit-A", specs, map[string]bool{})
	if !ok || len(hops) != 2 {
		t.Fatalf("hops %d ok %t %+v", len(hops), ok, hops)
	}
	if hops[0].Protocol != "socks" || hops[1].Protocol != "vless" || hops[1].UUID == "" {
		t.Fatalf("vless chain %+v", hops)
	}
	partial := []OutboundSpec{
		{ID: "audit-B", Name: "audit-B", Protocol: "socks", SettingsJSON: `{"address":"127.0.0.1","port":1081}`},
		{ID: "audit-A", Name: "audit-A", Protocol: "trojan", SettingsJSON: `{"address":"10.0.0.1","port":443,"password":"x","via_outbound":"audit-B"}`},
	}
	if hops, ok := egressChain("audit-A", partial, map[string]bool{}); ok {
		t.Fatalf("partial chain treated complete %+v", hops)
	}
}

func TestHopFromOutboundKeepsTLSAndRejectsReality(t *testing.T) {
	tlsHop, ok := hopFromOutbound(OutboundSpec{
		Protocol:     "vless",
		SettingsJSON: `{"address":"127.0.0.1","port":443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","security":"tls","transport":"tcp","sni":"audit.test"}`,
	})
	if !ok || tlsHop.Security != "tls" || tlsHop.SNI != "audit.test" {
		t.Fatalf("tls hop %+v ok %t", tlsHop, ok)
	}
	if _, ok := hopFromOutbound(OutboundSpec{
		Protocol:     "vless",
		SettingsJSON: `{"address":"127.0.0.1","port":443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","security":"reality"}`,
	}); ok {
		t.Fatal("reality vless should not be a native hop")
	}
	wsHop, ok := hopFromOutbound(OutboundSpec{
		Protocol:     "vless",
		SettingsJSON: `{"address":"127.0.0.1","port":80,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"ws","security":"none","ws_path":"/audit"}`,
	})
	if !ok || wsHop.Transport != "ws" || wsHop.WSPath != "/audit" {
		t.Fatalf("ws hop %+v ok %t", wsHop, ok)
	}
	if _, ok := hopFromOutbound(OutboundSpec{
		Protocol:     "vless",
		SettingsJSON: `{"address":"127.0.0.1","port":443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc","grpc_service":"audit"}`,
	}); ok {
		t.Fatal("grpc vless should stay on the core")
	}
}

func TestWSRequestURLKeepsQuery(t *testing.T) {
	u := wsRequestURL("127.0.0.1:80", "/audit?token=audit")
	if u.Path != "/audit" || u.RawQuery != "token=audit" {
		t.Fatalf("url path=%q query=%q", u.Path, u.RawQuery)
	}
	if got := u.String(); strings.Contains(got, "%3F") || !strings.Contains(got, "/audit?token=audit") {
		t.Fatalf("encoded %s", got)
	}
	if u := wsRequestURL("127.0.0.1:80", "/audit"); u.RawQuery != "" || u.Path != "/audit" {
		t.Fatalf("plain path %+v", u)
	}
}

func TestWSRequestURLKeepsEscapedPath(t *testing.T) {
	u := wsRequestURL("127.0.0.1:80", "/%61udit?token=audit")
	got := u.String()
	if strings.Contains(got, "%2561") || !strings.Contains(got, "/%61udit?token=audit") {
		t.Fatalf("double-encoded %s path=%q raw=%q", got, u.Path, u.RawPath)
	}
}

func TestHTTPIdentityFrontAndUsernameLogin(t *testing.T) {
	if !identityFront(InboundSpec{Protocol: "http"}, nil) {
		t.Fatal("http inbound should use identity front")
	}
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "u1", UUID: "alice-id", Username: "免流", Password: "pw"}}, nil)
	if _, ok := p.lookup("免流", "pw"); !ok {
		t.Fatal("username login")
	}
	if _, ok := p.lookup("alice-id", "pw"); !ok {
		t.Fatal("uuid login")
	}
	if _, ok := p.lookup("免流", "wrong"); ok {
		t.Fatal("wrong password")
	}
}

func TestHopTLSServerNameDefaultsToHost(t *testing.T) {
	if hopTLSServerName(egressHop{SNI: "audit.test", Addr: "localhost:443"}) != "audit.test" {
		t.Fatal("explicit sni")
	}
	if hopTLSServerName(egressHop{Addr: "localhost:8443"}) != "localhost" {
		t.Fatal("default host")
	}
}

func TestSpliceFrontDropRemovesConn(t *testing.T) {
	front := &spliceFront{}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	front.track(a)
	front.track(b)
	if n := front.tracked(); n != 2 {
		t.Fatalf("tracked %d", n)
	}
	front.drop(a)
	if n := front.tracked(); n != 1 {
		t.Fatalf("after drop a %d", n)
	}
	front.drop(a)
	if n := front.tracked(); n != 1 {
		t.Fatalf("double drop %d", n)
	}
	front.drop(b)
	if n := front.tracked(); n != 0 {
		t.Fatalf("empty %d", n)
	}
}

func TestSpliceFrontSpawnTrackedDropsOnExit(t *testing.T) {
	front := &spliceFront{}
	a, b := net.Pipe()
	defer b.Close()
	started := make(chan struct{})
	done := make(chan struct{})
	front.spawnTracked(a, func() {
		close(started)
		defer close(done)
		defer a.Close()
		buf := make([]byte, 1)
		_, _ = a.Read(buf)
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	if n := front.tracked(); n != 1 {
		t.Fatalf("during session %d", n)
	}
	_ = b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler stuck")
	}
	deadline := time.Now().Add(time.Second)
	for front.tracked() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := front.tracked(); n != 0 {
		t.Fatalf("after session %d", n)
	}
}

func totalSnap(snaps []Snapshot) int64 {
	var n int64
	for _, s := range snaps {
		if s.UserID == "u1" {
			n += s.Bytes
		}
	}
	return n
}
