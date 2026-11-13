package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
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
