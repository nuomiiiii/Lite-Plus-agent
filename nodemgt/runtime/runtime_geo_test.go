package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/certstore"
	"github.com/nuomiiiii/lite-agent/nodemgt/coreadapter"
	"github.com/nuomiiiii/lite-agent/nodemgt/geostore"
	"github.com/nuomiiiii/lite-agent/nodemgt/quota"
	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

type geoTestRoundTrip func(*http.Request) (*http.Response, error)

func (f geoTestRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type geoLoopCore struct {
	closed        []string
	presenceCalls int
}

func (*geoLoopCore) Name() string                                          { return "audit" }
func (*geoLoopCore) Version() string                                       { return "audit" }
func (*geoLoopCore) Linked() bool                                          { return true }
func (*geoLoopCore) Start(context.Context, []coreadapter.InboundSpec) error { return nil }
func (*geoLoopCore) Stop() error                                           { return nil }
func (*geoLoopCore) LiveInbounds() bool                                    { return false }
func (*geoLoopCore) ApplyUsers([]coreadapter.UserSpec) error               { return nil }
func (c *geoLoopCore) CloseUserSessions(id string) error {
	c.closed = append(c.closed, id)
	return nil
}
func (*geoLoopCore) TakeSnapshots() []coreadapter.Snapshot { return nil }
func (*geoLoopCore) AcknowledgeUsage()                     {}
func (c *geoLoopCore) Presence() []coreadapter.Presence {
	c.presenceCalls++
	return []coreadapter.Presence{{UserID: "expiry-user", Online: true}}
}

func TestUsedCoreNamesFollowsEnabledInbounds(t *testing.T) {
	got := usedCoreNames([]coreadapter.InboundSpec{
		{ID: "a", Core: "xray"},
		{ID: "b", Core: "sing-box"},
	})
	if strings.Join(got, ",") != "xray,sing-box" {
		t.Fatalf("both = %v", got)
	}
	got = usedCoreNames([]coreadapter.InboundSpec{{ID: "a", Core: "xray"}})
	if strings.Join(got, ",") != "xray" {
		t.Fatalf("xray = %v", got)
	}
	got = usedCoreNames([]coreadapter.InboundSpec{{ID: "b", Core: "sing-box"}})
	if strings.Join(got, ",") != "sing-box" {
		t.Fatalf("sing-box = %v", got)
	}
	got = usedCoreNames([]coreadapter.InboundSpec{{ID: "empty", Core: ""}})
	if strings.Join(got, ",") != "xray,sing-box" {
		t.Fatalf("empty core = %v", got)
	}
	if len(usedCoreNames(nil)) != 0 {
		t.Fatal("no inbounds should skip geo")
	}
}

func TestGeoRefreshDoesNotBlockExpireAndPresence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		geo, err := geostore.Open(filepath.Join(dir, "geo"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(geo.Dir, "geoip.dat")
		if err := os.WriteFile(path, []byte(strings.Repeat("G", 120000)), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-8 * 24 * time.Hour)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		geo.Client = &http.Client{Timeout: 60 * time.Second, Transport: geoTestRoundTrip(func(r *http.Request) (*http.Response, error) {
			select {
			case <-entered:
			default:
				close(entered)
			}
			select {
			case <-release:
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("G", 120000))),
					Request:    r,
				}, nil
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		})}
		certs, err := certstore.Open(filepath.Join(dir, "certs"))
		if err != nil {
			t.Fatal(err)
		}
		core := &geoLoopCore{}
		due := time.Now().Add(12*time.Hour + time.Second)
		rt := &Runtime{
			dir:    dir,
			certs:  certs,
			geo:    geo,
			cores:  []coreadapter.Core{core},
			users:  []coreadapter.UserSpec{{ID: "expiry-user", ExpiresAt: &due}},
			denied: map[string]struct{}{},
			quota:  quota.New(),
			result: func(string, any) {},
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go rt.loop(ctx)
		time.Sleep(12 * time.Hour)
		<-entered
		synctest.Wait()
		beforePresence := core.presenceCalls
		time.Sleep(16 * time.Second)
		synctest.Wait()
		if len(core.closed) != 1 || core.closed[0] != "expiry-user" {
			t.Fatalf("expire should run during geo refresh, closed=%v", core.closed)
		}
		if core.presenceCalls <= beforePresence {
			t.Fatalf("presence should continue during geo refresh, before=%d after=%d", beforePresence, core.presenceCalls)
		}
		close(release)
		synctest.Wait()
		cancel()
		synctest.Wait()
	})
}

func TestApplyConfigXrayOnlyIgnoresUnusedRuleSetFailure(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nodemgt", "geo")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), validGeositeDat(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests []string
	rt, ack := startGeoRuntime(t, base, &requests)
	defer stopGeoRuntime(rt)
	port := freePort(t)
	rt.HandleControl(map[string]any{
		"operation_id": "xray-only",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds":  []any{map[string]any{"id": "xray", "core": "xray", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true}},
			"outbounds": []any{map[string]any{"id": "direct-out", "name": "audit-direct", "protocol": "direct", "enabled": true}},
			"routes":    []any{map[string]any{"id": "cn", "enabled": true, "rule_json": `{"outbound_id":"direct-out","domain":"geosite:cn"}`}},
			"users": []any{map[string]any{
				"id": "xray-user", "status": "active", "inbound_ids": []string{"xray"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	if ack["status"] != "applied" {
		t.Fatalf("xray-only apply = %#v requests=%v", ack, requests)
	}
	for _, raw := range requests {
		if strings.Contains(raw, ".srs") {
			t.Fatalf("xray-only fetched rule-set: %v", requests)
		}
	}
}

func TestApplyConfigSingBoxPrivateIgnoresUnusedDatFailure(t *testing.T) {
	base := t.TempDir()
	var requests []string
	rt, ack := startGeoRuntime(t, base, &requests)
	defer stopGeoRuntime(rt)
	port := freePort(t)
	rt.HandleControl(map[string]any{
		"operation_id": "private",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds":  []any{map[string]any{"id": "private", "core": "sing-box", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true}},
			"outbounds": []any{map[string]any{"id": "direct-out", "name": "audit-direct", "protocol": "direct", "enabled": true}},
			"routes":    []any{map[string]any{"id": "private", "enabled": true, "rule_json": `{"outbound_id":"direct-out","ip":"geoip:private"}`}},
			"users": []any{map[string]any{
				"id": "private-user", "status": "active", "inbound_ids": []string{"private"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	if ack["status"] != "applied" {
		t.Fatalf("private apply = %#v requests=%v", ack, requests)
	}
	if len(requests) != 0 {
		t.Fatalf("private sing-box fetched geo files: %v", requests)
	}
}

func TestApplyConfigStillFailsWhenRequiredRuleSetMissing(t *testing.T) {
	base := t.TempDir()
	var requests []string
	rt, ack := startGeoRuntime(t, base, &requests)
	defer stopGeoRuntime(rt)
	port := freePort(t)
	rt.HandleControl(map[string]any{
		"operation_id": "need-srs",
		"kind":         "applyConfig",
		"payload": map[string]any{
			"inbounds":  []any{map[string]any{"id": "sb", "core": "sing-box", "listen": "127.0.0.1", "port": port, "protocol": "socks", "enabled": true}},
			"outbounds": []any{map[string]any{"id": "direct-out", "name": "audit-direct", "protocol": "direct", "enabled": true}},
			"routes":    []any{map[string]any{"id": "cn", "enabled": true, "rule_json": `{"outbound_id":"direct-out","domain":"geosite:cn"}`}},
			"users": []any{map[string]any{
				"id": "sb-user", "status": "active", "inbound_ids": []string{"sb"},
				"credentials": []any{map[string]any{"uuid": "alice", "secret": "pw", "enabled": true}},
			}},
		},
	}, "")
	if ack["status"] != "failed" {
		t.Fatalf("missing required rule-set must fail, ack=%#v", ack)
	}
	if len(requests) == 0 {
		t.Fatal("expected rule-set download attempts")
	}
}

func startGeoRuntime(t *testing.T, base string, requests *[]string) (*Runtime, map[string]any) {
	t.Helper()
	ack := map[string]any{}
	rt, err := Start(filepath.Join(base, "agent.json"), func(_ string, v any) {
		if m, ok := v.(map[string]any); ok {
			if _, ok := m["operation_id"]; ok {
				for k, val := range m {
					ack[k] = val
				}
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.geo.Client = &http.Client{Timeout: 2 * time.Second, Transport: geoTestRoundTrip(func(r *http.Request) (*http.Response, error) {
		*requests = append(*requests, r.URL.String())
		return &http.Response{
			StatusCode: 503,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("offline")),
			Request:    r,
		}, nil
	})}
	return rt, ack
}

func stopGeoRuntime(rt *Runtime) {
	if rt == nil {
		return
	}
	for _, core := range rt.cores {
		_ = core.Stop()
	}
	if rt.cancel != nil {
		rt.cancel()
	}
}

func validGeositeDat(t *testing.T) []byte {
	t.Helper()
	var domains []*geodata.Domain
	for i := 0; i < 7000; i++ {
		domains = append(domains, &geodata.Domain{Type: geodata.Domain_Full, Value: fmt.Sprintf("audit-%d.example", i)})
	}
	raw, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{Code: "CN", Domain: domains}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 100*1024 {
		t.Fatal("fixture smaller than production minimum")
	}
	return raw
}
