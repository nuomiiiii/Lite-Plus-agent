package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/coreadapter"
	"golang.org/x/net/proxy"
)

func TestFlushUsageRecoversAfterPendingWriteFailure(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	rt.HandleControl(map[string]any{
		"operation_id": "start",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{map[string]any{
				"id": "persist-user", "status": "active", "inbound_ids": []string{"socks"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	waitPort(t, port)
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var sent []int64
	rt.SetSender(func(method string, params any) error {
		if method == "nodemgt.usage" {
			sent = append(sent, params.(map[string]any)["bytes"].(int64))
		}
		return nil
	})
	pending := filepath.Join(dir, "nodemgt", "pending-usage.json")
	if err := os.Mkdir(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := echoN(c, 10); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if err := echoN(c, 10); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	var total int64
	for _, n := range sent {
		total += n
	}
	if total != 40 {
		t.Fatalf("sent %+v total %d want 40", sent, total)
	}
}

func TestMergeUsageItemsSumsSameUser(t *testing.T) {
	got := mergeUsageItems([]coreadapter.Snapshot{
		{UserID: "u1", Bytes: 20},
		{UserID: "u2", Bytes: 5},
		{UserID: "u1", Bytes: 40},
	})
	if len(got) != 2 || got[0].UserID != "u1" || got[0].Bytes != 60 || got[1].Bytes != 5 {
		t.Fatalf("%+v", got)
	}
}

func TestFlushUsageMergesDualCoreAndKeepsGap(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	ports := make([]int, 2)
	var inbounds []any
	for i, name := range []string{"xray", "sing-box"} {
		ports[i] = freePort(t)
		inbounds = append(inbounds, map[string]any{
			"id": name, "core": name, "protocol": "socks", "listen": "127.0.0.1", "port": ports[i], "enabled": true,
		})
	}
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	rt.HandleControl(map[string]any{
		"operation_id": "dual-start",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": inbounds,
			"users": []any{map[string]any{
				"id": "u1", "status": "active", "inbound_ids": []string{"xray", "sing-box"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	conns := make([]net.Conn, 2)
	for i, port := range ports {
		waitPort(t, port)
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
		defer c.Close()
		if err := echoN(c, 10*(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	var batches []int64
	inject := true
	rt.SetSender(func(method string, params any) error {
		if method != "nodemgt.usage" {
			return nil
		}
		v := params.(map[string]any)
		batches = append(batches, v["bytes"].(int64))
		if inject {
			inject = false
			_ = echoN(conns[0], 20)
		}
		return nil
	})
	rt.FlushUsage()
	if len(batches) != 1 || batches[0] != 60 {
		t.Fatalf("merged batch %+v want [60]", batches)
	}
	if err := echoN(conns[0], 30); err != nil {
		t.Fatal(err)
	}
	rt.FlushUsage()
	if len(batches) != 2 || batches[1] != 100 {
		t.Fatalf("gap batch %+v want [60 100]", batches)
	}
	rt.FlushUsage()
	if len(batches) != 2 {
		t.Fatalf("idle extra %+v", batches)
	}
}

func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proxy %s not listening", addr)
}

func echoN(c net.Conn, n int) error {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(make([]byte, n)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, n))
	return err
}

func TestFlushUsagePartialSendPersistsRemainingItems(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt)

	rt.HandleControl(map[string]any{
		"operation_id": "partial-init",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{
				map[string]any{
					"id": "p-u1", "status": "active", "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "p-alice", "secret": "pw", "enabled": true}},
				},
				map[string]any{
					"id": "p-u2", "status": "active", "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "p-bob", "secret": "pw", "enabled": true}},
				},
			},
		},
	}, "")
	waitPort(t, port)

	for _, cred := range []string{"p-alice", "p-bob"} {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: cred, Password: "pw"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := echoN(c, 10); err != nil {
			c.Close()
			t.Fatal(err)
		}
		c.Close()
	}

	sentByUser := map[string]int{}
	failSecond := true
	callNum := 0
	rt.SetSender(func(method string, params any) error {
		if method != "nodemgt.usage" {
			return nil
		}
		callNum++
		if failSecond && callNum == 2 {
			return fmt.Errorf("transient network failure")
		}
		uid := params.(map[string]any)["user_id"].(string)
		sentByUser[uid]++
		return nil
	})

	rt.FlushUsage()
	pending, err := rt.loadPendingUsage()
	if err != nil || pending == nil || len(pending.Items) != 1 {
		t.Fatalf("after partial send, pending = %+v err=%v, want 1 remaining item", pending, err)
	}

	failSecond = false
	rt.FlushUsage()
	if sentByUser["p-u1"] != 1 || sentByUser["p-u2"] != 1 {
		t.Fatalf("expected each user sent once across retry, got %+v", sentByUser)
	}
	if _, err := os.Stat(rt.pendingUsagePath()); !os.IsNotExist(err) {
		t.Fatalf("pending-usage.json should be removed after retry succeeds: %v", err)
	}
}

type countRestartCore struct {
	coreadapter.Core
	applyUsersCalls int
	stageUsersCalls int
	startCalls      int
}

func (c *countRestartCore) ApplyUsers(users []coreadapter.UserSpec) error {
	c.applyUsersCalls++
	return c.Core.ApplyUsers(users)
}

func (c *countRestartCore) StageUsers(users []coreadapter.UserSpec) {
	c.stageUsersCalls++
	if stager, ok := c.Core.(interface{ StageUsers([]coreadapter.UserSpec) }); ok {
		stager.StageUsers(users)
	}
}

func (c *countRestartCore) Start(ctx context.Context, inbounds []coreadapter.InboundSpec) error {
	c.startCalls++
	return c.Core.Start(ctx, inbounds)
}

func (c *countRestartCore) AcknowledgeUsageItem(userID string, maxBytes int64) int64 {
	if acker, ok := c.Core.(interface{ AcknowledgeUsageItem(string, int64) int64 }); ok {
		return acker.AcknowledgeUsageItem(userID, maxBytes)
	}
	return 0
}

func TestApplySnapshotStagesUsersOnceAndPerItemAckPreventsDoubleCount(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt)

	wrapped := &countRestartCore{Core: rt.cores[0]}
	rt.cores[0] = wrapped

	rt.HandleControl(map[string]any{
		"operation_id": "stage-once-1",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{"id": "socks", "core": "xray", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{
				map[string]any{
					"id": "ack-u1", "status": "active", "quota_bytes": 100, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "ack-alice", "secret": "pw", "enabled": true}},
				},
				map[string]any{
					"id": "ack-u2", "status": "active", "quota_bytes": 100, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "ack-bob", "secret": "pw", "enabled": true}},
				},
			},
		},
	}, "")
	waitPort(t, port)

	if wrapped.applyUsersCalls != 0 || wrapped.stageUsersCalls != 1 || wrapped.startCalls != 1 {
		t.Fatalf("expected StageUsers(1) + Start(1) with 0 redundant ApplyUsers, got apply=%d stage=%d start=%d",
			wrapped.applyUsersCalls, wrapped.stageUsersCalls, wrapped.startCalls)
	}

	// Send 30 bytes (60 echo total) for ack-u1 and 10 bytes (20 echo total) for ack-u2.
	for _, tc := range []struct {
		user string
		n    int
	}{
		{"ack-alice", 30},
		{"ack-bob", 10},
	} {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: tc.user, Password: "pw"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := echoN(c, tc.n); err != nil {
			c.Close()
			t.Fatal(err)
		}
		c.Close()
	}

	// First item (ack-u1) succeeds, second item (ack-u2) fails!
	var sentOrder []string
	rt.SetSender(func(method string, params any) error {
		if method != "nodemgt.usage" {
			return nil
		}
		m, _ := params.(map[string]any)
		uid, _ := m["user_id"].(string)
		sentOrder = append(sentOrder, uid)
		if uid == "ack-u1" {
			return nil
		}
		return fmt.Errorf("second item send error")
	})
	rt.FlushUsage()
	if len(sentOrder) != 2 || sentOrder[0] != "ack-u1" || sentOrder[1] != "ack-u2" {
		t.Fatalf("expected deterministic flush order [ack-u1 ack-u2], got %v", sentOrder)
	}

	// Now Master sends syncQuota where ack-u1's UsedBytes is 60 (Master received ack-u1's 60 bytes!).
	// Because ack-u1 was already acked per-item despite ack-u2 failing, ack-u1 MUST still have 40 bytes of quota room (NOT 60+60=120 >= 100 blocked!).
	rt.HandleControl(map[string]any{
		"operation_id": "sync-after-partial",
		"kind":         "syncQuota",
		"payload": map[string]any{
			"inbounds": []any{map[string]any{"id": "socks", "core": "xray", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{
				map[string]any{
					"id": "ack-u1", "status": "active", "quota_bytes": 100, "used_bytes": 60, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "ack-alice", "secret": "pw", "enabled": true}},
				},
				map[string]any{
					"id": "ack-u2", "status": "active", "quota_bytes": 100, "used_bytes": 0, "inbound_ids": []string{"socks"},
					"credentials": []any{map[string]any{"uuid": "ack-bob", "secret": "pw", "enabled": true}},
				},
			},
		},
	}, "")

	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "ack-alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("ack-u1 falsely quota-blocked by double-counting after partial FlushUsage + syncQuota: %v", err)
	}
	defer c.Close()
	if err := echoN(c, 10); err != nil {
		t.Fatalf("ack-u1 should still have 40B room, echo 20B failed: %v", err)
	}
}

func TestStaleMasterSnapshotAfterFlushAckPreservesReportedQuota(t *testing.T) {
	dir := t.TempDir()
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	rt, err := Start(filepath.Join(dir, "agent.json"), func(string, any) {})
	if err != nil {
		t.Fatal(err)
	}
	defer stopGeoRuntime(rt)

	const nodeUUID = "node-quota-race"
	rt.HandleControl(map[string]any{
		"operation_id": "init-race",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"node_uuid":       nodeUUID,
			"acked_usage_ops": []string{},
			"inbounds":        []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{map[string]any{
				"id": "race-u1", "status": "active", "quota_bytes": 100, "used_bytes": 20, "inbound_ids": []string{"socks"},
				"credentials": []any{map[string]any{"uuid": "race-alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	waitPort(t, port)

	dialAndEcho := func(n int) error {
		d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), &proxy.Auth{User: "race-alice", Password: "pw"}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			return err
		}
		c, err := d.Dial("tcp", echo.Addr().String())
		if err != nil {
			return err
		}
		defer c.Close()
		return echoN(c, n)
	}

	// Consume 60 bytes (30 up + 30 down) -> total effective used = 20 + 60 = 80 (20B remaining out of 100B).
	if err := dialAndEcho(30); err != nil {
		t.Fatalf("initial 60B echo: %v", err)
	}

	var flushedBatchID string
	rt.SetSender(func(method string, params any) error {
		if method == "nodemgt.usage" {
			flushedBatchID = params.(map[string]any)["batch_id"].(string)
		}
		return nil
	})
	rt.FlushUsage()
	if flushedBatchID == "" {
		t.Fatal("expected FlushUsage to send batch")
	}

	// Now an in-flight stale Master snapshot arrives (generated BEFORE Master processed flushedBatchID:
	// used_bytes is still 20 and acked_usage_ops is empty!).
	// Agent MUST preserve the 60 flushed bytes -> effective used remains 80 (only 20B room left, so 40B echo must fail!).
	rt.HandleControl(map[string]any{
		"operation_id": "stale-master-snap",
		"kind":         "syncQuota",
		"payload": map[string]any{
			"node_uuid":       nodeUUID,
			"acked_usage_ops": []string{},
			"inbounds":        []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{map[string]any{
				"id": "race-u1", "status": "active", "quota_bytes": 100, "used_bytes": 20, "inbound_ids": []string{"socks"},
				"credentials": []any{map[string]any{"uuid": "race-alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")

	// Trying to use 40 bytes (20 up + 20 down) exceeds the 20B remaining quota and MUST be blocked!
	if err := dialAndEcho(20); err == nil {
		t.Fatal("stale snapshot wiped out just-acked 60B usage, allowing user to exceed 100B quota!")
	}

	// Once Master sends a caught-up snapshot (acked_usage_ops includes the batch AND admin topped up quota to 200),
	// effective used is accurately 100 (not double-counted as 160), leaving 100B room!
	rt.HandleControl(map[string]any{
		"operation_id": "caught-up-topup",
		"kind":         "syncQuota",
		"payload": map[string]any{
			"node_uuid":       nodeUUID,
			"acked_usage_ops": []string{usageDedupOpID(nodeUUID, flushedBatchID, "race-u1")},
			"inbounds":        []any{map[string]any{"id": "socks", "core": "sing-box", "protocol": "socks", "listen": "127.0.0.1", "port": port, "enabled": true}},
			"users": []any{map[string]any{
				"id": "race-u1", "status": "active", "quota_bytes": 200, "used_bytes": 100, "inbound_ids": []string{"socks"},
				"credentials": []any{map[string]any{"uuid": "race-alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	if err := dialAndEcho(30); err != nil {
		t.Fatalf("after caught-up topup (100/200 used), 60B echo failed (double-counted?): %v", err)
	}
}
