package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/ws"
)

func TestClearLiveWebSocketKeepsNewerPeer(t *testing.T) {
	t.Cleanup(func() { setLiveWebSocket(nil) })
	first := &ws.SafeConn{}
	second := &ws.SafeConn{}
	setLiveWebSocket(first)
	clearLiveWebSocket(second)
	if liveWS != first {
		t.Fatal("clearing a different socket must not drop the live peer")
	}
	setLiveWebSocket(second)
	clearLiveWebSocket(first)
	if liveWS != second {
		t.Fatal("clearing an old socket must not drop the current peer")
	}
	clearLiveWebSocket(second)
	if liveWS != nil {
		t.Fatal("clearing the current socket must drop the peer")
	}
}

func TestRestorePersistedFirewallRegistersControlPlanePeer(t *testing.T) {
	raw, err := os.ReadFile("firewall.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "firewall.SetControlPlanePeer(liveControlPlanePeer)") {
		t.Fatal("startup restore must register the live websocket peer for firewall watchdog")
	}
	if !strings.Contains(text, "func liveControlPlanePeer()") {
		t.Fatal("liveControlPlanePeer must read the attached websocket remote address")
	}
	if !strings.Contains(text, "func clearLiveWebSocket(") {
		t.Fatal("drop must only clear the websocket that is still the live peer")
	}
}

func TestLiveControlPlanePeerTracksAttachedSocket(t *testing.T) {
	t.Cleanup(func() { setLiveWebSocket(nil) })
	setLiveWebSocket(nil)
	if got := liveControlPlanePeer(); got != "" {
		t.Fatalf("empty socket: %q", got)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	raw, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := ws.NewSafeConn(raw)
	t.Cleanup(func() { _ = conn.Close() })

	setLiveWebSocket(conn)
	got := liveControlPlanePeer()
	if got == "" {
		t.Fatal("attached websocket must expose a control-plane peer")
	}
	if !strings.Contains(got, "127.0.0.1") && !strings.Contains(got, "[::1]") {
		t.Fatalf("peer %q is not the local test server", got)
	}
}

func TestFirewallAndProtectionRejectWhenRemoteControlDisabled(t *testing.T) {
	prev := pkg_flags.GlobalConfig.RemoteControlEnabled
	pkg_flags.GlobalConfig.RemoteControlEnabled = false
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.RemoteControlEnabled = prev
	})

	received := make(chan v2.Request, 4)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			var req v2.Request
			if json.Unmarshal(raw, &req) == nil {
				received <- req
			}
		}
	}))
	t.Cleanup(srv.Close)

	raw, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := ws.NewSafeConn(raw)
	t.Cleanup(func() { _ = conn.Close() })

	if !processFirewallEvent(conn, v2.MethodAgentFirewallApply, map[string]interface{}{"request_id": "fw-req-1"}) {
		t.Fatal("processFirewallEvent returned false for firewall apply")
	}
	select {
	case msg := <-received:
		if msg.Method != v2.MethodAgentFirewallResult {
			t.Fatalf("unexpected method %q", msg.Method)
		}
		var res v2.FirewallResultParams
		if err := v2.BindParams(msg.Params, &res); err != nil {
			t.Fatal(err)
		}
		if res.RequestID != "fw-req-1" || res.Kind != v2.FirewallKindApply || res.Status != v2.FirewallStatusError || !strings.Contains(res.Error, "remote control is disabled") {
			t.Fatalf("unexpected firewall rejection: %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for firewall rejection")
	}

	if !processProtectionEvent(conn, v2.MethodAgentProtectionBan, map[string]interface{}{"request_id": "prot-req-1"}) {
		t.Fatal("processProtectionEvent returned false for protection ban")
	}
	select {
	case msg := <-received:
		if msg.Method != v2.MethodAgentProtectionResult {
			t.Fatalf("unexpected method %q", msg.Method)
		}
		var res v2.ProtectionResultParams
		if err := v2.BindParams(msg.Params, &res); err != nil {
			t.Fatal(err)
		}
		if res.RequestID != "prot-req-1" || res.Kind != v2.ProtectionKindBan || res.Status != v2.ProtectionStatusError || !strings.Contains(res.Error, "remote control is disabled") {
			t.Fatalf("unexpected protection rejection: %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for protection rejection")
	}
}

func TestFlushProtectionReportsGuardedByMutex(t *testing.T) {
	raw, err := os.ReadFile("protection.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "flushReportMu.Lock()") || !strings.Contains(text, "defer flushReportMu.Unlock()") {
		t.Fatal("FlushProtectionReports must hold flushReportMu")
	}
}
