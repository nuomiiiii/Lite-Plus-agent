package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/certstore"
	"github.com/nuomiiiii/lite-agent/nodemgt/coreadapter"
	"github.com/nuomiiiii/lite-agent/nodemgt/quota"
	"golang.org/x/net/proxy"
)

func TestHandleControlIgnoresDuplicateAndStaleQuotaAfterRevoke(t *testing.T) {
	dir := t.TempDir()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	target := echo.Addr().String()
	apply := func(op, kind, user string) {
		rt.HandleControl(map[string]any{
			"operation_id": op,
			"kind":         kind,
			"payload": map[string]any{
				"inbounds": []any{map[string]any{"id": "audit", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true}},
				"users": []any{map[string]any{
					"id": "u1", "status": "active", "inbound_ids": []string{"audit"},
					"credentials": []any{map[string]any{"uuid": user, "secret": "pw", "enabled": true}},
				}},
			},
		}, "")
	}
	can := func(user string) bool {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: user, Password: "pw"}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			return false
		}
		c, err := d.Dial("tcp", target)
		if err != nil {
			return false
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("ok")); err != nil {
			return false
		}
		buf := make([]byte, 2)
		_, err = io.ReadFull(c, buf)
		return err == nil
	}
	apply("apply-a", "applyConfig", "alice")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !can("alice") {
		time.Sleep(50 * time.Millisecond)
	}
	if !can("alice") {
		t.Fatal("initial apply failed")
	}
	rt.HandleControl(map[string]any{"operation_id": "revoke", "kind": "revokeUser", "payload": map[string]any{"user_ids": []string{"u1"}}}, "")
	if can("alice") {
		t.Fatal("revoke did not take effect")
	}
	apply("apply-a", "applyConfig", "alice")
	if can("alice") {
		t.Fatal("duplicate apply restored revoked user")
	}
	apply("apply-new", "applyConfig", "bob")
	if can("alice") {
		t.Fatal("alice connected after new credential")
	}
	apply("old-quota", "syncQuota", "alice")
	if can("alice") {
		t.Fatal("old syncQuota restored revoked user")
	}
}

func TestNotifyLiveInboundsHook(t *testing.T) {
	var got []bool
	SetLiveInboundsHook(func(live bool) { got = append(got, live) })
	t.Cleanup(func() { SetLiveInboundsHook(nil) })
	notifyLiveInbounds(true)
	notifyLiveInbounds(false)
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("hook calls = %v", got)
	}
}

func TestApplySnapshotNotifiesLiveInboundsBeforeStartError(t *testing.T) {
	raw, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "notifyLiveInbounds(coresHaveLiveInbounds(r.cores))") {
		t.Fatal("applySnapshot must follow restored core instances, not the Start return value")
	}
	notifyAt := strings.Index(text, "notifyLiveInbounds(coresHaveLiveInbounds(r.cores))")
	errAt := strings.Index(text[notifyAt+1:], "if firstErr != nil")
	if notifyAt < 0 || errAt < 0 {
		t.Fatal("live inbound memory must be updated before returning a partial Start error")
	}
}

type restoreLiveCore struct {
	geoLoopCore
	startErr error
	live     bool
}

func (c *restoreLiveCore) Start(context.Context, []coreadapter.InboundSpec) error {
	return c.startErr
}

func (c *restoreLiveCore) LiveInbounds() bool { return c.live }

func TestApplySnapshotKeepsMemoryWhenStartFailsButCoreRestored(t *testing.T) {
	rt := newApplyRuntime(t, &restoreLiveCore{startErr: fmt.Errorf("bad inbound"), live: true})
	got := captureLiveInbounds(t)
	err := rt.applySnapshot([]byte(`{"inbounds":[{"id":"a","core":"xray","listen":"127.0.0.1","port":1080,"protocol":"socks","enabled":true}],"users":[{"id":"u1","status":"active","inbound_ids":["a"],"credentials":[{"uuid":"alice","secret":"pw","enabled":true}]}]}`), false)
	if err == nil {
		t.Fatal("want start error")
	}
	if len(*got) != 1 || !(*got)[0] {
		t.Fatalf("memory hook = %v, want live after last-good restore", *got)
	}
}

func TestApplySnapshotDropsMemoryWhenStartFailsAndNothingRunning(t *testing.T) {
	rt := newApplyRuntime(t, &restoreLiveCore{startErr: fmt.Errorf("bad inbound"), live: false})
	got := captureLiveInbounds(t)
	err := rt.applySnapshot([]byte(`{"inbounds":[{"id":"a","core":"xray","listen":"127.0.0.1","port":1080,"protocol":"socks","enabled":true}],"users":[{"id":"u1","status":"active","inbound_ids":["a"],"credentials":[{"uuid":"alice","secret":"pw","enabled":true}]}]}`), false)
	if err == nil {
		t.Fatal("want start error")
	}
	if len(*got) != 1 || (*got)[0] {
		t.Fatalf("memory hook = %v, want monitor cap when nothing is running", *got)
	}
}

func captureLiveInbounds(t *testing.T) *[]bool {
	t.Helper()
	got := []bool{}
	SetLiveInboundsHook(func(live bool) { got = append(got, live) })
	t.Cleanup(func() { SetLiveInboundsHook(nil) })
	return &got
}

func newApplyRuntime(t *testing.T, cores ...coreadapter.Core) *Runtime {
	t.Helper()
	dir := t.TempDir()
	certs, err := certstore.Open(filepath.Join(dir, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	return &Runtime{
		dir:         dir,
		certs:       certs,
		cores:       cores,
		denied:      map[string]struct{}{},
		quotaDenied: map[string]struct{}{},
		quota:       quota.New(),
	}
}

func TestSyncQuotaUnblocksExhaustedUserWhileKeepingAdminRevoked(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt)

	sendSnap := func(op, kind string, u1Used, u1Quota int64) {
		rt.HandleControl(map[string]any{
			"operation_id": op,
			"kind":         kind,
			"payload": map[string]any{
				"inbounds": []any{map[string]any{
					"id": "socks", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true,
				}},
				"users": []any{
					map[string]any{
						"id": "u-quota", "status": "active", "quota_bytes": u1Quota, "used_bytes": u1Used,
						"inbound_ids": []string{"socks"},
						"credentials": []any{map[string]any{"uuid": "quota-alice", "secret": "pw", "enabled": true}},
					},
					map[string]any{
						"id": "u-revoked", "status": "active", "quota_bytes": 10000, "used_bytes": 0,
						"inbound_ids": []string{"socks"},
						"credentials": []any{map[string]any{"uuid": "revoked-bob", "secret": "pw", "enabled": true}},
					},
				},
			},
		}, "")
	}
	canDial := func(user string) bool {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: user, Password: "pw"}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			return false
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			return false
		}
		defer c.Close()
		return echoN(c, 4) == nil
	}

	sendSnap("cfg-1", "applyConfig", 0, 20)
	waitPort(t, port)
	if !canDial("quota-alice") || !canDial("revoked-bob") {
		t.Fatal("initial users should connect")
	}

	// Admin revokes u-revoked.
	rt.HandleControl(map[string]any{
		"operation_id": "rev-bob",
		"kind":         "revokeUser",
		"payload":      map[string]any{"user_ids": []string{"u-revoked"}},
	}, "")
	if canDial("revoked-bob") {
		t.Fatal("admin revoked user still connected")
	}

	// Exhaust u-quota locally and run FlushUsage.
	d, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "quota-alice", Password: "pw"}, &net.Dialer{Timeout: 2 * time.Second})
	if c, err := d.Dial("tcp", echo.Addr().String()); err == nil {
		_ = echoN(c, 10) // 20 bytes total -> hits 20B quota!
		_ = c.Close()
	}
	rt.FlushUsage()
	if canDial("quota-alice") {
		t.Fatal("quota-exhausted user still connected")
	}
	if rawDenied, err := os.ReadFile(filepath.Join(dir, "nodemgt", "denied.json")); err == nil {
		if strings.Contains(string(rawDenied), "u-quota") {
			t.Fatalf("quota exhaustion must not write into admin denied.json: %s", rawDenied)
		}
	}

	// A stale pre-flush syncQuota (still carrying UsedBytes=0 from before FlushUsage)
	// MUST NOT wipe out the 20 flushed bytes or falsely unblock u-quota!
	sendSnap("stale-pre-flush-sync", "syncQuota", 0, 20)
	if canDial("quota-alice") {
		t.Fatal("stale pre-flush syncQuota wiped flushed bytes and falsely unblocked u-quota")
	}

	// Genuine monthly traffic reset arrives via syncQuota (traffic-reset:<user>:<cycle>, UsedBytes=0 < QuotaBytes=20):
	// u-quota MUST immediately unblock, while admin-revoked u-revoked MUST stay blocked!
	sendSnap("traffic-reset:u-quota:2026-11", "syncQuota", 0, 20)
	if !canDial("quota-alice") {
		t.Fatal("syncQuota after monthly reset failed to unblock u-quota")
	}
	if canDial("revoked-bob") {
		t.Fatal("syncQuota must not unblock admin-revoked u-revoked")
	}
}

func TestExpiredUserStaysBlockedAcrossRestartUntilRenewed(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	cfgPath := filepath.Join(dir, "agent.json")

	rt, err := Start(cfgPath, func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}

	canDialUser := func(username, password string) bool {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: username, Password: password}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			return false
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			return false
		}
		defer c.Close()
		return echoN(c, 4) == nil
	}

	soon := time.Now().UTC().Add(180 * time.Millisecond).Format(time.RFC3339Nano)
	rt.HandleControl(map[string]any{
		"operation_id": "exp-init",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{
				"id": "socks", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true,
			}},
			"users": []any{
				map[string]any{
					"id": "u-exp", "status": "active", "expires_at": soon, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "exp-alice", "secret": "pw", "enabled": true}},
				},
				map[string]any{
					"id": "u-keep", "status": "active", "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "keep-bob", "secret": "pw2", "enabled": true}},
				},
			},
		},
	}, "")
	waitPort(t, port)
	if !canDialUser("exp-alice", "pw") || !canDialUser("keep-bob", "pw2") {
		stopGeoRuntime(rt)
		t.Fatal("both users should connect before expiration")
	}

	time.Sleep(250 * time.Millisecond)
	rt.expireUsers()
	if canDialUser("exp-alice", "pw") {
		stopGeoRuntime(rt)
		t.Fatal("expired user still connected after expireUsers")
	}
	if !canDialUser("keep-bob", "pw2") {
		stopGeoRuntime(rt)
		t.Fatal("active user lost access when sibling user expired")
	}
	stopGeoRuntime(rt)

	// Simulate Agent process restart: last-snapshot.json still has status="active",
	// and Start() restores before Master sends any new snapshot!
	rt2, err := Start(cfgPath, func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt2)
	waitPort(t, port)

	if !canDialUser("keep-bob", "pw2") {
		t.Fatal("active user failed to connect after Agent restart")
	}
	if canDialUser("exp-alice", "pw") {
		t.Fatal("expired user connected after Agent restart before Master snapshot")
	}

	// Admin renews the user into the future -> user immediately reconnects!
	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	rt2.HandleControl(map[string]any{
		"operation_id": "exp-renew",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{
				"id": "socks", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true,
			}},
			"users": []any{
				map[string]any{
					"id": "u-exp", "status": "active", "expires_at": future, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "exp-alice", "secret": "pw", "enabled": true}},
				},
				map[string]any{
					"id": "u-keep", "status": "active", "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "keep-bob", "secret": "pw2", "enabled": true}},
				},
			},
		},
	}, "")
	if !canDialUser("exp-alice", "pw") {
		t.Fatal("renewed user failed to reconnect after applyConfig")
	}
}

func TestQuotaExhaustedUserStaysBlockedAcrossRestartUntilToppedUp(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	cfgPath := filepath.Join(dir, "agent.json")

	rt, err := Start(cfgPath, func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}

	canDialUser := func(username, password string, n int) bool {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: username, Password: password}, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			return false
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			return false
		}
		defer c.Close()
		return echoN(c, n) == nil
	}

	rt.HandleControl(map[string]any{
		"operation_id": "qd-init",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{
				"id": "socks", "core": "sing-box", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true,
			}},
			"users": []any{
				map[string]any{
					"id": "u-qexhaust", "status": "active", "quota_bytes": 40, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "q-alice", "secret": "pw1", "enabled": true}},
				},
				map[string]any{
					"id": "u-qkeep", "status": "active", "quota_bytes": 10000, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "q-bob", "secret": "pw2", "enabled": true}},
				},
			},
		},
	}, "")
	waitPort(t, port)

	// Consume all 40 bytes (20 up + 20 down) for u-qexhaust, then FlushUsage succeeds
	// (removing pending-usage.json while last-snapshot.json still has used_bytes=0!).
	if !canDialUser("q-alice", "pw1", 20) {
		stopGeoRuntime(rt)
		t.Fatal("u-qexhaust initial 40B transfer should succeed")
	}
	rt.SetSender(func(string, any) error { return nil })
	rt.FlushUsage()
	if canDialUser("q-alice", "pw1", 4) {
		stopGeoRuntime(rt)
		t.Fatal("exhausted user still connected after FlushUsage")
	}
	stopGeoRuntime(rt)

	// Simulate Agent self-upgrade / restart: last-snapshot.json still says used_bytes=0,
	// pending-usage.json is gone, so quota-denied.json MUST keep u-qexhaust blocked!
	rt2, err := Start(cfgPath, func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt2)
	waitPort(t, port)

	if !canDialUser("q-bob", "pw2", 4) {
		t.Fatal("healthy user failed to connect after Agent restart")
	}
	if canDialUser("q-alice", "pw1", 4) {
		t.Fatal("quota-exhausted user reconnected after Agent restart before Master syncQuota!")
	}

	// Master pushes monthly reset / top-up via syncQuota -> u-qexhaust immediately unblocks!
	rt2.HandleControl(map[string]any{
		"operation_id": "traffic-reset:u-qexhaust:2026-12",
		"kind":         "syncQuota",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{
				"id": "socks", "core": "sing-box", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true,
			}},
			"users": []any{
				map[string]any{
					"id": "u-qexhaust", "status": "active", "quota_bytes": 200, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "q-alice", "secret": "pw1", "enabled": true}},
				},
				map[string]any{
					"id": "u-qkeep", "status": "active", "quota_bytes": 10000, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "q-bob", "secret": "pw2", "enabled": true}},
				},
			},
		},
	}, "")
	if !canDialUser("q-alice", "pw1", 4) {
		t.Fatal("topped-up/reset user failed to reconnect after syncQuota")
	}
}

func TestHandleControlClearUserIPs(t *testing.T) {
	core := &geoLoopCore{}
	var got map[string]any
	rt := newApplyRuntime(t, core)
	rt.result = func(_ string, params any) {
		got, _ = params.(map[string]any)
	}
	if !rt.HandleControl(map[string]any{
		"operation_id": "clear-ip-op",
		"kind":         "clearUserIPs",
		"payload":      map[string]any{"user_ids": []string{"u1", "u2"}},
	}, "ev-1") {
		t.Fatal("HandleControl returned false")
	}
	if strings.Join(core.clearedIPs, ",") != "u1,u2" {
		t.Fatalf("clearedIPs = %v, want [u1 u2]", core.clearedIPs)
	}
	if got["status"] != "applied" || got["operation_id"] != "clear-ip-op" {
		t.Fatalf("controlResult = %#v", got)
	}
}
