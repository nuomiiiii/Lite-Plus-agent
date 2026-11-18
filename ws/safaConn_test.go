package ws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRemoteAddrUsesUnderlyingNetConn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(time.Second)
	}))
	t.Cleanup(server.Close)

	raw, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := NewSafeConn(raw)
	defer conn.Close()

	addr := conn.RemoteAddr()
	if addr == nil || addr.String() == "" {
		t.Fatal("SafeConn must expose the websocket remote address")
	}
}

func TestWriteMessageTimesOutWhenPeerStopsReading(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(WriteTimeout + 2*time.Second)
	}))
	t.Cleanup(server.Close)

	raw, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := NewSafeConn(raw)
	defer conn.Close()

	payload := make([]byte, 64*1024)
	deadline := time.Now().Add(WriteTimeout + 2*time.Second)
	var writeErr error
	for time.Now().Before(deadline) {
		writeErr = conn.WriteMessage(websocket.BinaryMessage, payload)
		if writeErr != nil {
			break
		}
	}
	if writeErr == nil {
		t.Fatal("write continued without a deadline after the peer stopped reading")
	}
}

func TestCloseUnblocksInFlightWrite(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-started
		time.Sleep(WriteTimeout + time.Second)
		_, _ = io.Copy(io.Discard, request.Body)
	}))
	t.Cleanup(server.Close)

	raw, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn := NewSafeConn(raw)

	done := make(chan error, 1)
	go func() {
		close(started)
		payload := make([]byte, 1024*1024)
		for {
			if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				done <- err
				return
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	if err := conn.Close(); err != nil && !strings.Contains(err.Error(), "use of closed") {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(WriteTimeout + time.Second):
		t.Fatal("Close did not unblock the in-flight write")
	}
}
