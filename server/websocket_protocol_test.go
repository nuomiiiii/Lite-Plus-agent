package server

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
)

func TestV2PullCapabilitiesIncludeRemoteNotTerminal(t *testing.T) {
	hasRemote, hasTerminal := false, false
	for _, capability := range v2BasePullCapabilities {
		if capability == "remote" {
			hasRemote = true
		}
		if capability == "terminal" {
			hasTerminal = true
		}
	}
	if !hasRemote {
		t.Fatal("pull capabilities must include remote")
	}
	if hasTerminal {
		t.Fatal("pull capabilities must not include terminal")
	}
	for _, required := range []string{"files", "exec", "ping", "route", "message", "event", "config"} {
		found := false
		for _, capability := range v2BasePullCapabilities {
			if capability == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("pull capabilities missing %q: %v", required, v2BasePullCapabilities)
		}
	}
	for _, capability := range v2BasePullCapabilities {
		if capability == "mcp_full" {
			t.Fatal("base pull capabilities must not include mcp_full; advertise it only when remote control is enabled")
		}
	}
}

func TestV2PullPayloadAdvertisesMCPFullWhenRemoteControlEnabled(t *testing.T) {
	original := pkg_flags.GlobalConfig.RemoteControlEnabled
	t.Cleanup(func() { pkg_flags.GlobalConfig.RemoteControlEnabled = original })
	pkg_flags.GlobalConfig.RemoteControlEnabled = true
	payload := v2PullPayload(nil)
	if !bytes.Contains(payload, []byte(`"method":"agent.pull"`)) {
		t.Fatalf("pull payload missing agent.pull: %s", payload)
	}
	if !bytes.Contains(payload, []byte(`"mcp_full"`)) {
		t.Fatalf("pull payload missing mcp_full: %s", payload)
	}
}

func TestHandleWebSocketAdvertisesPullAfterConnect(t *testing.T) {
	source, err := os.ReadFile("websocket.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("advertiseV2PullCapabilities(conn)")) {
		t.Fatal("websocket connect must advertise pull capabilities so Lite can record mcp_full")
	}
	if !bytes.Contains(source, []byte("if message.Method == \"\"")) {
		t.Fatal("websocket read loop must ignore pull RPC responses without a method")
	}
}

func TestV2PullAdvertisesMCPFullOnlyWhenRemoteControlEnabled(t *testing.T) {
	original := pkg_flags.GlobalConfig.RemoteControlEnabled
	t.Cleanup(func() { pkg_flags.GlobalConfig.RemoteControlEnabled = original })

	pkg_flags.GlobalConfig.RemoteControlEnabled = false
	caps, versions := currentV2PullCapabilities()
	for _, capability := range caps {
		if capability == "mcp_full" || capability == "firewall" {
			t.Fatal("disabled remote control must not advertise " + capability)
		}
	}
	if _, ok := versions["mcp_full"]; ok {
		t.Fatal("disabled remote control must not advertise mcp_full version")
	}

	pkg_flags.GlobalConfig.RemoteControlEnabled = true
	caps, versions = currentV2PullCapabilities()
	found := false
	for _, capability := range caps {
		if capability == "mcp_full" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("enabled remote control must advertise mcp_full: %v", caps)
	}
	if versions["mcp_full"] != 1 {
		t.Fatalf("mcp_full version = %d, want 1", versions["mcp_full"])
	}
	foundFirewall := false
	for _, capability := range caps {
		if capability == "firewall" {
			foundFirewall = true
			break
		}
	}
	if !foundFirewall {
		t.Fatalf("enabled remote control must advertise firewall: %v", caps)
	}
	if versions["firewall"] != 1 {
		t.Fatalf("firewall version = %d, want 1", versions["firewall"])
	}
}

func TestRunV2PullLoopHasNoErrCh(t *testing.T) {
	fn := reflect.TypeOf(runV2PullLoop)
	if fn.NumIn() != 1 {
		t.Fatalf("runV2PullLoop should only take context, got %d params", fn.NumIn())
	}
	if fn.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("runV2PullLoop argument = %s, want context.Context", fn)
	}
}

func TestRemoteWebSocketReadLimitIs2MiB(t *testing.T) {
	if remoteWebSocketReadLimit != 2<<20 {
		t.Fatalf("remote WebSocket read limit = %d, want 2MiB", remoteWebSocketReadLimit)
	}
}
