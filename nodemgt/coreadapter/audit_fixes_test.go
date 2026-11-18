package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/features/stats"
)

func TestAccountLinkBytesRateLimitChargesAllBytesAndStopsMidStream(t *testing.T) {
	p := newPolicyEngine()
	// 80000 bps = 10000 bytes/sec (10000B burst); 16000 bytes must wait ~600ms for the 6000B beyond burst and charge all 16000B.
	p.sync([]UserSpec{{
		ID:           "rl-user",
		UUID:         vlessAlice,
		Password:     "pw",
		QuotaBytes:   50000,
		RateLimitBps: 80000,
	}}, nil)

	stop := make(chan struct{})
	start := time.Now()
	if !p.accountLinkBytesContext("rl-user", 16000, stop) {
		t.Fatal("expected 16000 bytes within 50000 quota to succeed")
	}
	elapsed := time.Since(start)
	if elapsed < 400*time.Millisecond {
		t.Fatalf("rate limit did not throttle: 16000B at 10000B/s took %v", elapsed)
	}
	if used := p.quota.Used("rl-user"); used != 16000 {
		t.Fatalf("quota used = %d, want 16000", used)
	}
	if snapped := totalUser(p.snapshots(), "rl-user"); snapped != 16000 {
		t.Fatalf("snapshot bytes = %d, want 16000", snapped)
	}
	p.ack()

	// Disconnect (closing stop) while throttled on a transfer that would otherwise take ~3s must abort promptly without denying user.
	connStop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		close(started)
		done <- p.accountLinkBytesContext("rl-user", 30000, connStop)
	}()
	<-started
	time.Sleep(50 * time.Millisecond)
	close(connStop)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("closed stop channel must abort throttled transfer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing stop channel did not unblock rate-limited transfer promptly")
	}
	if p.userBlocked("rl-user") {
		t.Fatal("normal client disconnect with remaining quota must not deny user")
	}

	// Quota exhaustion mid-chunk must stop and deny user.
	p.sync([]UserSpec{{
		ID:           "quota-mid",
		UUID:         vlessBob,
		Password:     "pw",
		QuotaBytes:   1500,
		RateLimitBps: 80000, // 10 KB/s
	}}, nil)
	if p.accountLinkBytesContext("quota-mid", 3000, nil) {
		t.Fatal("chunk exceeding remaining quota must fail")
	}
	if !p.userBlocked("quota-mid") {
		t.Fatal("exhausted user must be denied")
	}
	if got := p.quota.Used("quota-mid"); got != 1500 {
		t.Fatalf("exhausted quota used = %d, want 1500", got)
	}
}

func TestPolicySyncPreservesUnackedInFlightBytesAndHandlesReset(t *testing.T) {
	p := newPolicyEngine()
	u := UserSpec{ID: "inflight-u", UUID: vlessAlice, Password: "pw", QuotaBytes: 1000, UsedBytes: 200}
	p.sync([]UserSpec{u}, nil)
	if got, ok := p.takeBytes("inflight-u", 350, nil); !ok || got != 350 {
		t.Fatalf("takeBytes = %d, %v", got, ok)
	}
	// Periodic snapshot arrives before FlushUsage acked the 350 bytes (Master still says UsedBytes=200).
	p.sync([]UserSpec{u}, nil)
	if got := p.quota.Used("inflight-u"); got != 550 {
		t.Fatalf("unacked bytes lost on sync: quota.Used = %d, want 550", got)
	}
	if room := p.quota.Room("inflight-u"); room != 450 {
		t.Fatalf("room = %d, want 450", room)
	}

	// Flush + Ack sends 350 to Master (Master now has 550).
	snaps := p.snapshots()
	if got := totalUser(snaps, "inflight-u"); got != 350 {
		t.Fatalf("snapshot = %d, want 350", got)
	}
	p.ack()
	u.UsedBytes = 550
	p.sync([]UserSpec{u}, nil)
	if got := p.quota.Used("inflight-u"); got != 550 {
		t.Fatalf("after ack + master sync: quota.Used = %d, want 550", got)
	}

	// Monthly traffic reset on Master sets UsedBytes = 0 while 45 unsent bytes are in-flight -> Used = 45!
	if got, ok := p.takeBytes("inflight-u", 45, nil); !ok || got != 45 {
		t.Fatalf("takeBytes 45 = %d, %v", got, ok)
	}
	u.UsedBytes = 0
	p.sync([]UserSpec{u}, nil)
	if got := p.quota.Used("inflight-u"); got != 45 {
		t.Fatalf("after monthly reset with 45B unacked: quota.Used = %d, want 45", got)
	}
	if room := p.quota.Room("inflight-u"); room != 955 {
		t.Fatalf("after monthly reset with 45B unacked: room = %d, want 955", room)
	}
	_ = p.snapshots()
	p.ackUser("inflight-u", 45)

	// Cycle reset + Master received batch B=600 when prev UsedBytes was 950 (600 >= 950/2!):
	u.UsedBytes = 950
	p.sync([]UserSpec{u}, nil)
	if got, ok := p.takeBytes("inflight-u", 50, nil); !ok || got != 50 {
		t.Fatalf("takeBytes 50 = %d, %v", got, ok)
	}
	_ = p.snapshots()
	p.ackUser("inflight-u", 50)
	// Master reset to 0 then added another 600 -> UsedBytes = 600; with local unacked = 0, Used must be 600!
	u.UsedBytes = 600
	p.sync([]UserSpec{u}, nil)
	if got := p.quota.Used("inflight-u"); got != 600 {
		t.Fatalf("after reset+batch sync (UsedBytes=600): quota.Used = %d, want 600", got)
	}
}

func TestEvictAndDynamicUpdateZeroDropTrojanAndIdentity(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := testPEMs(t)

	for _, tc := range []struct {
		name string
		core Core
	}{
		{"xray", NewXray()},
		{"sing-box", NewSingBox()},
	} {
		t.Run(tc.name+"-trojan-evict-and-dynamic", func(t *testing.T) {
			srv := tc.core
			defer srv.Stop()
			port := freePort(t)
			u1 := UserSpec{ID: "t-u1", UUID: vlessAlice, Password: "pw1", QuotaBytes: 1 << 20}
			u2 := UserSpec{ID: "t-u2", UUID: vlessBob, Password: "pw2", QuotaBytes: 1 << 20}
			u3 := UserSpec{ID: "t-u3", UUID: "cccccccc-cccc-cccc-cccc-cccccccccccc", Password: "pw3", QuotaBytes: 1 << 20}
			in := []InboundSpec{{
				ID: "trojan-in", Core: tc.name, Listen: "127.0.0.1", Port: port, Protocol: "trojan",
				CertPEM: certPEM, KeyPEM: keyPEM, StreamJSON: `{"network":"tcp","security":"tls"}`,
			}}
			if err := srv.ApplyUsers([]UserSpec{u1, u2}); err != nil {
				t.Fatal(err)
			}
			if err := srv.Start(context.Background(), in); err != nil {
				t.Fatal(err)
			}
			waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))

			cli1, stop1 := startTrojanClientSOCKS(t, port, "pw1")
			defer stop1()
			cli2, stop2 := startTrojanClientSOCKS(t, port, "pw2")
			defer stop2()

			conn1, err := socksTry(cli1, "c", "c", echo.Addr().String())
			if err != nil {
				t.Fatalf("u1 dial: %v", err)
			}
			defer conn1.Close()
			conn2, err := socksTry(cli2, "c", "c", echo.Addr().String())
			if err != nil {
				t.Fatalf("u2 dial: %v", err)
			}
			defer conn2.Close()

			if !echoConn(conn1, []byte("u1-before")) {
				t.Fatal("u1 initial echo failed")
			}
			if !echoConn(conn2, []byte("u2-before")) {
				t.Fatal("u2 initial echo failed")
			}

			// Evict u1: u1's active stream must die and reconnect must fail, while u2's open stream stays alive!
			if err := srv.CloseUserSessions("t-u1"); err != nil {
				t.Fatal(err)
			}
			if echoConn(conn1, []byte("u1-after")) {
				t.Fatal("evicted u1 stream stayed alive")
			}
			if !echoConn(conn2, []byte("u2-stays-alive-1")) {
				t.Fatal("u2 active connection dropped when u1 was evicted")
			}
			if c, err := socksTry(cli1, "c", "c", echo.Addr().String()); err == nil {
				if echoConn(c, []byte("probe")) {
					c.Close()
					t.Fatal("evicted u1 was able to open a new working stream")
				}
				c.Close()
			}

			// Re-enable u1 via ApplyUsers (simulating syncQuota after reset/topup): u2 STILL stays alive!
			if err := srv.ApplyUsers([]UserSpec{u1, u2}); err != nil {
				t.Fatal(err)
			}
			if !echoConn(conn2, []byte("u2-stays-alive-2")) {
				t.Fatal("u2 active connection dropped when u1 was re-enabled")
			}
			conn1Re, err := socksTry(cli1, "c", "c", echo.Addr().String())
			if err != nil || !echoConn(conn1Re, []byte("u1-restored")) {
				if conn1Re != nil {
					conn1Re.Close()
				}
				t.Fatalf("re-enabled u1 failed to reconnect: %v", err)
			}
			conn1Re.Close()

			// On Xray, adding brand-new u3 on Trojan uses UserManager dynamically without dropping u2!
			if tc.name == "xray" {
				if err := srv.ApplyUsers([]UserSpec{u1, u2, u3}); err != nil {
					t.Fatal(err)
				}
				if !echoConn(conn2, []byte("u2-stays-alive-3")) {
					t.Fatal("u2 active connection dropped when u3 was added dynamically on Xray")
				}
				cli3, stop3 := startTrojanClientSOCKS(t, port, "pw3")
				defer stop3()
				conn3, err := socksTry(cli3, "c", "c", echo.Addr().String())
				if err != nil || !echoConn(conn3, []byte("u3-live")) {
					if conn3 != nil {
						conn3.Close()
					}
					t.Fatalf("dynamically added u3 failed on Xray Trojan: %v", err)
				}
				conn3.Close()
			}
		})

		t.Run(tc.name+"-identity-dynamic-add-user", func(t *testing.T) {
			srv := tc.core
			defer srv.Stop()
			port := freePort(t)
			u1 := UserSpec{ID: "s-u1", UUID: "alice", Password: "pw1", QuotaBytes: 1 << 20}
			u2 := UserSpec{ID: "s-u2", UUID: "bob", Password: "pw2", QuotaBytes: 1 << 20}
			if err := srv.ApplyUsers([]UserSpec{u1}); err != nil {
				t.Fatal(err)
			}
			if err := srv.Start(context.Background(), []InboundSpec{{
				ID: "socks-in", Core: tc.name, Listen: "127.0.0.1", Port: port, Protocol: "socks",
			}}); err != nil {
				t.Fatal(err)
			}
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			waitProxy(t, addr)

			conn1, err := socksTry(addr, "alice", "pw1", echo.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn1.Close()
			if !echoConn(conn1, []byte("alice-1")) {
				t.Fatal("alice initial echo")
			}

			// Add u2 dynamically on identityFront -> conn1 stays open and bob works immediately!
			if err := srv.ApplyUsers([]UserSpec{u1, u2}); err != nil {
				t.Fatal(err)
			}
			if !echoConn(conn1, []byte("alice-2")) {
				t.Fatal("alice active SOCKS connection dropped when bob was added")
			}
			conn2, err := socksTry(addr, "bob", "pw2", echo.Addr().String())
			if err != nil || !echoConn(conn2, []byte("bob-1")) {
				if conn2 != nil {
					conn2.Close()
				}
				t.Fatalf("dynamically added bob failed: %v", err)
			}
			conn2.Close()
		})
	}
}

func startTrojanClientSOCKS(t *testing.T, serverPort int, password string) (string, func()) {
	t.Helper()
	socksPort := freePort(t)
	cli := newSingBoxCore()
	settings, err := json.Marshal(map[string]any{
		"address": "127.0.0.1", "port": serverPort, "password": password,
		"security": "tls", "sni": "localhost", "insecure": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli.SetForwarding(
		[]OutboundSpec{{ID: "out", Name: "out", Protocol: "trojan", Enabled: true, SettingsJSON: string(settings)}},
		[]RouteSpec{{ID: "r", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"in","outbound_id":"out"}`}},
	)
	if err := cli.ApplyUsers([]UserSpec{{ID: "c", UUID: "c", Password: "c"}}); err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(context.Background(), []InboundSpec{{
		ID: "in", Core: "sing-box", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks",
	}}); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	waitProxy(t, addr)
	return addr, func() { _ = cli.Stop() }
}

func TestEnsureFallbackLoopbackSocksRequiresRandomAuth(t *testing.T) {
	users := []UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}
	specs := []OutboundSpec{{
		ID: "grpc-exit", Name: "grpc-exit", Protocol: "vless", Enabled: true,
		SettingsJSON: `{"address":"127.0.0.1","port":8443,"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","transport":"grpc"}`,
	}}

	for _, xray := range []bool{true, false} {
		var obs, rules []map[string]any
		if xray {
			obs = []map[string]any{
				{"protocol": "freedom", "tag": "direct"},
				{"protocol": "vless", "tag": "grpc-exit"},
			}
			rules = []map[string]any{
				{"type": "field", "inboundTag": []string{"reality"}, "outboundTag": "grpc-exit"},
			}
		} else {
			obs = []map[string]any{
				{"type": "direct", "tag": "direct"},
				{"type": "vless", "tag": "grpc-exit"},
			}
			rules = []map[string]any{
				{"inbound": []string{"reality"}, "outbound": "grpc-exit"},
			}
		}
		_, _, extra, coreIn, err := attachPolicyExit(obs, rules, users, []string{"reality"}, xray, specs)
		if err != nil {
			t.Fatalf("xray=%v: %v", xray, err)
		}
		if len(coreIn) != 1 || len(extra) == 0 || len(extra[0].Egress) != 1 {
			t.Fatalf("xray=%v unexpected fallback layout coreIn=%+v extra=%+v", xray, coreIn, extra)
		}
		hop := extra[0].Egress[0]
		if len(hop.User) != 32 || len(hop.Pass) != 32 || hop.User == hop.Pass {
			t.Fatalf("xray=%v expected 16-byte random hex user/pass, got user=%q pass=%q", xray, hop.User, hop.Pass)
		}
		if xray {
			settings, _ := coreIn[0]["settings"].(map[string]any)
			if settings["auth"] != "password" {
				t.Fatalf("xray fallback auth = %v, want password", settings["auth"])
			}
			accounts, _ := settings["accounts"].([]map[string]string)
			if len(accounts) != 1 || accounts[0]["user"] != hop.User || accounts[0]["pass"] != hop.Pass {
				t.Fatalf("xray fallback accounts = %+v", accounts)
			}
		} else {
			sbUsers, _ := coreIn[0]["users"].([]map[string]string)
			if len(sbUsers) != 1 || sbUsers[0]["username"] != hop.User || sbUsers[0]["password"] != hop.Pass {
				t.Fatalf("sing-box fallback users = %+v", sbUsers)
			}
		}
	}

	// Verify live sing-box fallback rejects unauthenticated local SOCKS5 probe!
	echo := startEcho(t)
	defer echo.Close()
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
	stream, _ := json.Marshal(map[string]any{
		"network": "tcp", "security": "reality",
		"realitySettings": map[string]any{
			"dest": decoy.Addr().String(), "target": decoy.Addr().String(),
			"serverNames": []string{"audit.test"}, "privateKey": priv, "shortIds": []string{"abcd"},
		},
	})
	core := NewSingBox()
	defer core.Stop()
	outSettings, _ := json.Marshal(map[string]any{
		"address": "127.0.0.1", "port": ssPort, "password": "ss-secret", "ss_method": "aes-128-gcm",
	})
	core.(*singBoxCore).SetForwarding(
		[]OutboundSpec{{ID: "ss-out", Name: "ss-out", Protocol: "shadowsocks", Enabled: true, SettingsJSON: string(outSettings)}},
		[]RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"reality","outbound_id":"ss-out"}`}},
	)
	if err := core.ApplyUsers([]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	if err := core.Start(context.Background(), []InboundSpec{{
		ID: "reality", Core: "sing-box", Listen: "127.0.0.1", Port: freePort(t), Protocol: "vless", StreamJSON: string(stream),
	}}); err != nil {
		t.Fatal(err)
	}
	// Authenticated policy exit hop succeeds:
	pAddr := policyFrontAddr(t, core)
	if !policyTCPEchoOK(pAddr, vlessAlice, "pw", echo.Addr().String(), []byte("ok")) {
		t.Fatal("authenticated policy exit through loopback core SOCKS failed")
	}
}

func TestClearUserIPsRemovesGuardAndSeen(t *testing.T) {
	p := newPolicyEngine()
	rel1, ok := p.acquireIP("clear-u1", "203.0.113.1", 1)
	if !ok {
		t.Fatal("acquire u1")
	}
	rel2, ok := p.acquireIP("clear-u2", "203.0.113.2", 1)
	if !ok {
		t.Fatal("acquire u2")
	}
	defer rel2()
	p.noteIP("clear-u1", "203.0.113.1")
	p.noteIP("clear-u2", "203.0.113.2")
	if _, ok := p.acquireIP("clear-u1", "203.0.113.9", 1); ok {
		t.Fatal("device limit=1 should reject second IP before clear")
	}
	p.clearUserIPs("clear-u1")
	relAfterClear, ok := p.acquireIP("clear-u1", "203.0.113.9", 1)
	if !ok {
		t.Fatal("after clearUserIPs, new IP should be accepted immediately")
	}
	defer relAfterClear()
	// Releasing the pre-clear handle must not underflow the newly acquired slot!
	rel1()
	if _, ok := p.acquireIP("clear-u1", "203.0.113.88", 1); ok {
		t.Fatal("stale pre-clear release underflowed active IP slot")
	}
	if _, ok := p.acquireIP("clear-u2", "203.0.113.9", 1); ok {
		t.Fatal("clearing u1 must not clear u2's held IP")
	}
	p.clearUserIPs("clear-u1")
	p.clearUserIPs("clear-u2")
	_ = io.EOF
}

func TestXrayMixedSocksTrojanMeteringAndRestartPreservesUnacked(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM, pin := auditCerts(t)
	socksPort := freePort(t)
	trojanPort := freePort(t)

	xr := NewXray()
	defer xr.Stop()
	if err := xr.ApplyUsers([]UserSpec{{ID: "mix-u1", UUID: vlessAlice, Password: "trojan-mix-secret", QuotaBytes: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	// Note: plain Trojan (no CertPEM -> !public && !identityFront) tests Item #1 (meterTags on !identityFront)!
	// Let's also test TLS Trojan + built SOCKS in the same window and across a core restart!
	if err := xr.Start(context.Background(), []InboundSpec{
		{ID: "socks-in", Core: "xray", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks"},
		{ID: "trojan-plain", Core: "xray", Listen: "127.0.0.1", Port: trojanPort, Protocol: "trojan"},
	}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", socksPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", trojanPort))

	// Dial plain Trojan through sing-box trojan outbound (no TLS) to verify Item #1 (!public trojan metered!):
	sbCli := NewSingBox()
	defer sbCli.Stop()
	cliPort := freePort(t)
	setForwarding(t, sbCli,
		[]OutboundSpec{{
			ID: "tr-out", Name: "tr-out", Protocol: "trojan", Enabled: true,
			SettingsJSON: fmt.Sprintf(`{"address":"127.0.0.1","port":%d,"password":"trojan-mix-secret"}`, trojanPort),
		}},
		[]RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"in","outbound_id":"tr-out"}`}},
	)
	if err := sbCli.ApplyUsers([]UserSpec{{ID: "c", UUID: "cli", Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	if err := sbCli.Start(context.Background(), []InboundSpec{{ID: "in", Core: "sing-box", Listen: "127.0.0.1", Port: cliPort, Protocol: "socks"}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", cliPort))

	trConn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", cliPort), "cli", "pw", echo.Addr().String())
	if err != nil {
		t.Fatalf("plain trojan dial: %v", err)
	}
	if !echoConn(trConn, make([]byte, 25)) { // 50 bytes on plain trojan
		trConn.Close()
		t.Fatal("plain trojan echo")
	}
	trConn.Close()

	socksConn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", socksPort), vlessAlice, "trojan-mix-secret", echo.Addr().String())
	if err != nil {
		t.Fatalf("built socks dial: %v", err)
	}
	if !echoConn(socksConn, make([]byte, 15)) { // 30 bytes on built socks
		socksConn.Close()
		t.Fatal("built socks echo")
	}
	socksConn.Close()

	// Before calling TakeSnapshots/AcknowledgeUsage, force a real core restart (change trojan to TLS on a new port)!
	newTrojanPort := freePort(t)
	if err := xr.Start(context.Background(), []InboundSpec{
		{ID: "socks-in", Core: "xray", Listen: "127.0.0.1", Port: socksPort, Protocol: "socks"},
		{ID: "trojan-tls", Core: "xray", Listen: "127.0.0.1", Port: newTrojanPort, Protocol: "trojan", CertPEM: certPEM, KeyPEM: keyPEM},
	}); err != nil {
		t.Fatal(err)
	}
	_ = pin
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", socksPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", newTrojanPort))

	// Send another 20 bytes (10 up + 10 down) on built SOCKS after restart:
	socksConn2, err := socksTry(fmt.Sprintf("127.0.0.1:%d", socksPort), vlessAlice, "trojan-mix-secret", echo.Addr().String())
	if err != nil {
		t.Fatalf("post-restart socks dial: %v", err)
	}
	if !echoConn(socksConn2, make([]byte, 10)) {
		socksConn2.Close()
		t.Fatal("post-restart socks echo")
	}
	socksConn2.Close()

	got := totalUser(xr.TakeSnapshots(), "mix-u1")
	// 50 (plain trojan) + 30 (pre-restart built socks) + 20 (post-restart built socks) = 100 bytes!
	if got < 100 {
		t.Fatalf("mixed + pre-restart unacked bytes dropped: got %d, want >= 100", got)
	}
	xr.AcknowledgeUsage()
	if idle := totalUser(xr.TakeSnapshots(), "mix-u1"); idle != 0 {
		t.Fatalf("idle after ack = %d, want 0", idle)
	}
}

func TestDualCoreSharedQuotaPreservesPeerUnackedBytes(t *testing.T) {
	xr := NewXray()
	defer xr.Stop()
	sb := NewSingBox()
	defer sb.Stop()

	users := []UserSpec{{ID: "shared-q-u1", UUID: vlessAlice, Password: "pw", QuotaBytes: 1000, UsedBytes: 100}}
	if err := xr.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if err := sb.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	// Simulate 400 unacked bytes recorded on Xray's policyEngine:
	xrRaw := xr.(*xrayCore)
	if got, ok := xrRaw.policy.takeBytes("shared-q-u1", 400, nil); !ok || got != 400 {
		t.Fatalf("xray takeBytes = %d, %v", got, ok)
	}
	// Now sing-box runs ApplyUsers with Master's UsedBytes still 100 -> must NOT wipe Xray's 400 unacked bytes!
	if err := sb.ApplyUsers(users); err != nil {
		t.Fatal(err)
	}
	if used := nodeExec.quota.Used("shared-q-u1"); used != 500 {
		t.Fatalf("singBoxCore.ApplyUsers wiped xrayCore unacked bytes: quota.Used = %d, want 500", used)
	}
}

func TestCloseUserSessionsPreservesBuiltTopologyAndVisionUserWorksOnWS(t *testing.T) {
	certPEM, keyPEM, pin := auditCerts(t)
	tlsEcho := startTLSEcho(t, certPEM, keyPEM)
	defer tlsEcho.Close()
	echo := startEcho(t)
	defer echo.Close()

	xr := NewXray()
	defer xr.Stop()
	visionPort := freePort(t)
	wsPort := freePort(t)

	// Start with u1 having Flow: xtls-rprx-vision on BOTH a TLS VLESS inbound (coreOwnedTLS=true) AND a VLESS+WS inbound (Item #5!).
	if err := xr.ApplyUsers([]UserSpec{
		{ID: "vis-u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := xr.Start(context.Background(), []InboundSpec{
		{ID: "tls-in", Core: "xray", Listen: "127.0.0.1", Port: visionPort, Protocol: "vless", CertPEM: certPEM, KeyPEM: keyPEM},
		{ID: "ws-in", Core: "xray", Listen: "127.0.0.1", Port: wsPort, Protocol: "vless", StreamJSON: `{"network":"ws","wsSettings":{"path":"/ws"}}`},
	}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", visionPort))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", wsPort))

	// Verify Item #5: vis-u1 (with Flow: xtls-rprx-vision) can connect over non-Vision VLESS+WS!
	wsCli := NewSingBox()
	defer wsCli.Stop()
	wsSocksPort := freePort(t)
	setForwarding(t, wsCli,
		[]OutboundSpec{{
			ID: "ws-out", Name: "ws-out", Protocol: "vless", Enabled: true,
			SettingsJSON: fmt.Sprintf(`{"address":"127.0.0.1","port":%d,"uuid":%q,"transport":"ws","ws_path":"/ws"}`, wsPort, vlessAlice),
		}},
		[]RouteSpec{{ID: "r1", Enabled: true, Priority: 1, RuleJSON: `{"inbound_id":"in","outbound_id":"ws-out"}`}},
	)
	if err := wsCli.ApplyUsers([]UserSpec{{ID: "c", UUID: "cli", Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	if err := wsCli.Start(context.Background(), []InboundSpec{{ID: "in", Core: "sing-box", Listen: "127.0.0.1", Port: wsSocksPort, Protocol: "socks"}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", wsSocksPort))
	wsConn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", wsSocksPort), "cli", "pw", echo.Addr().String())
	if err != nil {
		t.Fatalf("vision user rejected on VLESS+WS: %v", err)
	}
	if !echoConn(wsConn, []byte("ws-vision-user-ok")) {
		wsConn.Close()
		t.Fatal("VLESS+WS echo failed for vision user")
	}
	wsConn.Close()

	// Verify Item #4: CloseUserSessions("vis-u1") must NOT corrupt builtUsers topology so dynamically adding vis-u2 works!
	if err := xr.CloseUserSessions("vis-u1"); err != nil {
		t.Fatal(err)
	}
	if err := xr.ApplyUsers([]UserSpec{
		{ID: "vis-u1", UUID: vlessAlice, Password: "pw", Flow: "xtls-rprx-vision", Disabled: true},
		{ID: "vis-u2", UUID: vlessBob, Password: "pw", Flow: "xtls-rprx-vision"},
	}); err != nil {
		t.Fatal(err)
	}
	cli2, conn2, err := xrayDial(visionPort, vlessBob, "xtls-rprx-vision", "tls", "", pin, tlsEcho.Addr().String())
	if err != nil {
		t.Fatalf("vis-u2 failed to connect after CloseUserSessions(vis-u1) + ApplyUsers: %v", err)
	}
	defer cli2.Close()
	defer conn2.Close()
	if !echoConn(conn2, []byte("vis-u2-alive")) {
		t.Fatal("vis-u2 vision echo failed")
	}
}

func TestCloseUserSessionsAbortsThrottledPolicyCopyAndClearIPRefcount(t *testing.T) {
	// Part A (Item #10): ClearUserIPs while C1 is open must NOT let C1's deferred release underflow post-clear C2!
	g := newIPGuard()
	relC1, ok := g.acquire("ip-u1", "203.0.113.50", 1)
	if !ok {
		t.Fatal("C1 acquire failed")
	}
	g.clear("ip-u1")
	relC2, ok := g.acquire("ip-u1", "203.0.113.50", 1)
	if !ok {
		t.Fatal("C2 acquire after clear failed")
	}
	// Now old C1 closes -> must NOT decrement C2's bucket!
	relC1()
	if _, allowed := g.acquire("ip-u1", "203.0.113.99", 1); allowed {
		t.Fatal("C1's post-clear release underflowed C2's active IP slot, allowing a second distinct IP!")
	}
	relC2()
	if _, allowed := g.acquire("ip-u1", "203.0.113.99", 1); !allowed {
		t.Fatal("after C2 released, new IP should be allowed")
	}

	// Also verify Xray OnlineMap clearedAt suppresses stale OnlineMap entries:
	xr := NewXray()
	defer xr.Stop()
	if err := xr.ApplyUsers([]UserSpec{{ID: "om-u1", UUID: vlessAlice, Password: "pw"}}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	if err := xr.Start(context.Background(), []InboundSpec{{ID: "tr", Core: "xray", Listen: "127.0.0.1", Port: port, Protocol: "trojan"}}); err != nil {
		t.Fatal(err)
	}
	xrRaw := xr.(*xrayCore)
	if feat := xrRaw.inst.GetFeature(stats.ManagerType()); feat != nil {
		if mgr, ok := feat.(stats.Manager); ok {
			om, _ := stats.GetOrRegisterOnlineMap(mgr, "user>>>om-u1>>>online")
			if om != nil {
				om.AddIP("8.8.8.8")
			}
		}
	}
	xr.ClearUserIPs("om-u1")
	for _, row := range xr.Presence() {
		if row.UserID == "om-u1" {
			for _, ip := range row.IPs {
				if ip.IP == "8.8.8.8" {
					t.Fatalf("stale Xray OnlineMap IP 8.8.8.8 re-reported after ClearUserIPs: %+v", row)
				}
			}
		}
	}

	// Part B (Item #9): Throttled 32KB policyCopy aborts in <500ms on CloseUserSessions!
	echo := startEcho(t)
	defer echo.Close()
	sPort := freePort(t)
	sb := NewSingBox()
	defer sb.Stop()
	// 8000 bps = 1000 bytes/s -> 32KB would take ~31 seconds without immediate stop!
	if err := sb.ApplyUsers([]UserSpec{{ID: "slow-u1", UUID: vlessAlice, Password: "pw", RateLimitBps: 8000, DeviceLimit: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(context.Background(), []InboundSpec{{ID: "s", Core: "sing-box", Listen: "127.0.0.1", Port: sPort, Protocol: "socks"}}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", sPort))
	slowConn, err := socksTry(fmt.Sprintf("127.0.0.1:%d", sPort), vlessAlice, "pw", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slowConn.Close()
	// Start 32KB write in background so policyCopy blocks inside limiter.Wait:
	_, _ = slowConn.Write(make([]byte, 32*1024))
	time.Sleep(80 * time.Millisecond)

	startAbort := time.Now()
	if err := sb.CloseUserSessions("slow-u1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = slowConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, rerr := slowConn.Read(buf); rerr != nil {
			break
		}
	}
	if elapsed := time.Since(startAbort); elapsed > 3*time.Second {
		t.Fatalf("CloseUserSessions took %v to abort throttled policyCopy (would take ~31s uncancelled)", elapsed)
	}
}

func TestXrayDynamicUserSyncHandlesReorderedInboundsWithoutWrongTagOrRestart(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := testPEMs(t)

	srv := newXrayCore()
	defer srv.Stop()

	portA := freePort(t)
	portB := freePort(t)
	trojanA := InboundSpec{
		ID: "trojan-a", Core: "xray", Listen: "127.0.0.1", Port: portA, Protocol: "trojan",
		CertPEM: certPEM, KeyPEM: keyPEM, StreamJSON: `{"network":"tcp","security":"tls"}`,
	}
	trojanB := InboundSpec{
		ID: "trojan-b", Core: "xray", Listen: "127.0.0.1", Port: portB, Protocol: "trojan",
		CertPEM: certPEM, KeyPEM: keyPEM, StreamJSON: `{"network":"tcp","security":"tls"}`,
	}
	u1 := UserSpec{ID: "ro-u1", UUID: vlessAlice, Password: "pw1", InboundIDs: []string{"trojan-a"}, QuotaBytes: 1 << 20}
	u2 := UserSpec{ID: "ro-u2", UUID: vlessBob, Password: "pw2", InboundIDs: []string{"trojan-b"}, QuotaBytes: 1 << 20}
	u3 := UserSpec{ID: "ro-u3", UUID: "cccccccc-cccc-cccc-cccc-cccccccccccc", Password: "pw3", InboundIDs: []string{"trojan-a"}, QuotaBytes: 1 << 20}

	srv.StageUsers([]UserSpec{u1, u2})
	if err := srv.Start(context.Background(), []InboundSpec{trojanA, trojanB}); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", portA))
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", portB))

	cli1, stop1 := startTrojanClientSOCKS(t, portA, "pw1")
	defer stop1()
	cli2, stop2 := startTrojanClientSOCKS(t, portB, "pw2")
	defer stop2()

	conn1, err := socksTry(cli1, "c", "c", echo.Addr().String())
	if err != nil {
		t.Fatalf("u1 initial dial on trojan-a: %v", err)
	}
	defer conn1.Close()
	conn2, err := socksTry(cli2, "c", "c", echo.Addr().String())
	if err != nil {
		t.Fatalf("u2 initial dial on trojan-b: %v", err)
	}
	defer conn2.Close()
	if !echoConn(conn1, []byte("a-before")) || !echoConn(conn2, []byte("b-before")) {
		t.Fatal("initial echo on trojan-a or trojan-b failed")
	}

	// Reorder inbound slice [trojanB, trojanA] AND add u3 (granted ONLY on trojan-a):
	// Xray must sync u3 onto trojan-a's UserManager (not trojan-b at index 0!) without restarting!
	srv.StageUsers([]UserSpec{u1, u2, u3})
	if err := srv.Start(context.Background(), []InboundSpec{trojanB, trojanA}); err != nil {
		t.Fatal(err)
	}

	if !echoConn(conn1, []byte("a-still-live")) || !echoConn(conn2, []byte("b-still-live")) {
		t.Fatal("active Trojan connections dropped when inbounds were reordered during user sync")
	}

	cli3A, stop3A := startTrojanClientSOCKS(t, portA, "pw3")
	defer stop3A()
	conn3A, err := socksTry(cli3A, "c", "c", echo.Addr().String())
	if err != nil || !echoConn(conn3A, []byte("u3-on-a")) {
		if conn3A != nil {
			conn3A.Close()
		}
		t.Fatalf("u3 failed on trojan-a after reordered dynamic sync: %v", err)
	}
	conn3A.Close()

	cli3B, stop3B := startTrojanClientSOCKS(t, portB, "pw3")
	defer stop3B()
	if conn3B, err := socksTry(cli3B, "c", "c", echo.Addr().String()); err == nil {
		ok := echoConn(conn3B, []byte("u3-wrong-inbound"))
		conn3B.Close()
		if ok {
			t.Fatal("u3 was synced into trojan-b's UserManager due to slice index misalignment!")
		}
	}
}

func TestSingBoxCoreOwnedInboundRemovesDeletedAndDisabledUsersAndBlocksUnknownID(t *testing.T) {
	// 1. Verify policyEngine.userBlocked is fail-closed for unknown IDs (not in p.users or p.denied).
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "known-live", UUID: vlessAlice, Password: "pw1"}}, nil)
	if p.userBlocked("known-live") {
		t.Fatal("known live user should not be blocked")
	}
	if !p.userBlocked("deleted-ghost") {
		t.Fatal("unknown/deleted user ID must be treated as blocked (fail-closed)")
	}

	// 2. End-to-end live sing-box core-owned Trojan TLS inbound:
	// deleting or disabling a user via ApplyUsers (applyConfig path, WITHOUT CloseUserSessions)
	// must genuinely remove the user from sing-box so new connections cannot authenticate or bypass quota!
	echo := startEcho(t)
	defer echo.Close()
	certPEM, keyPEM := testPEMs(t)

	srv := NewSingBox()
	defer srv.Stop()

	port := freePort(t)
	in := []InboundSpec{{
		ID: "sb-trojan-del", Core: "sing-box", Listen: "127.0.0.1", Port: port, Protocol: "trojan",
		CertPEM: certPEM, KeyPEM: keyPEM, StreamJSON: `{"network":"tcp","security":"tls"}`,
	}}
	u1 := UserSpec{ID: "sb-u1", UUID: vlessAlice, Password: "pw1", QuotaBytes: 1 << 20}
	u2 := UserSpec{ID: "sb-u2", UUID: vlessBob, Password: "pw2", QuotaBytes: 1 << 20}

	if err := srv.ApplyUsers([]UserSpec{u1, u2}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	waitProxy(t, fmt.Sprintf("127.0.0.1:%d", port))

	cli1, stop1 := startTrojanClientSOCKS(t, port, "pw1")
	defer stop1()
	cli2, stop2 := startTrojanClientSOCKS(t, port, "pw2")
	defer stop2()

	tryEcho := func(cliAddr string, payload string) bool {
		c, err := socksTry(cliAddr, "c", "c", echo.Addr().String())
		if err != nil {
			return false
		}
		defer c.Close()
		return echoConn(c, []byte(payload))
	}

	if !tryEcho(cli1, "u1-init") || !tryEcho(cli2, "u2-init") {
		t.Fatal("both u1 and u2 must connect initially on sing-box Trojan")
	}

	// Delete u1 via ApplyUsers([u2]) (normal applyConfig delete path, no CloseUserSessions!):
	if err := srv.ApplyUsers([]UserSpec{u2}); err != nil {
		t.Fatal(err)
	}
	if tryEcho(cli1, "u1-after-delete") {
		t.Fatal("deleted u1 could still open a new connection on sing-box core-owned Trojan inbound!")
	}
	if !tryEcho(cli2, "u2-after-u1-delete") {
		t.Fatal("remaining active user u2 failed to connect after u1 was deleted")
	}

	// Re-add u1, verify it works, then disable u1 via ApplyUsers([u1{Disabled:true}, u2]):
	if err := srv.ApplyUsers([]UserSpec{u1, u2}); err != nil {
		t.Fatal(err)
	}
	if !tryEcho(cli1, "u1-readded") {
		t.Fatal("re-added u1 failed to connect")
	}
	u1Disabled := u1
	u1Disabled.Disabled = true
	if err := srv.ApplyUsers([]UserSpec{u1Disabled, u2}); err != nil {
		t.Fatal(err)
	}
	if tryEcho(cli1, "u1-after-disable") {
		t.Fatal("disabled u1 could still open a new connection on sing-box core-owned Trojan inbound!")
	}
	if !tryEcho(cli2, "u2-after-u1-disable") {
		t.Fatal("active user u2 failed to connect after u1 was disabled")
	}
}
