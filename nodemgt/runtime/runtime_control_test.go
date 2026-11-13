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
		dir:    dir,
		certs:  certs,
		cores:  cores,
		denied: map[string]struct{}{},
		quota:  quota.New(),
	}
}
