package server

import (
	"os"
	"strings"
	"testing"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
)

func TestAddressesChangedDetectsFamilyAppearingOrLeaving(t *testing.T) {
	if addressesChanged("203.0.113.9", "", "203.0.113.9", "") {
		t.Fatal("unchanged addresses must not retrigger upload")
	}
	if !addressesChanged("203.0.113.9", "", "203.0.113.9", "2001:db8::9") {
		t.Fatal("a newly reported v6 must retrigger upload")
	}
	if !addressesChanged("203.0.113.9", "2001:db8::9", "203.0.113.9", "") {
		t.Fatal("a lost v6 must retrigger upload")
	}
	if !addressesChanged("203.0.113.9", "", "198.51.100.9", "") {
		t.Fatal("a changed v4 must retrigger upload")
	}
}

func TestDoUploadBasicInfoWorksWatchesAddressChanges(t *testing.T) {
	src, err := os.ReadFile("basicInfo.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "go watchHostAddresses()") {
		t.Fatal("periodic basic info must also watch for address changes")
	}
	if !strings.Contains(text, "addressWatchEvery") || !strings.Contains(text, "30 * time.Second") {
		t.Fatal("address changes must not wait for the minute-scale info-report interval")
	}
	if !strings.Contains(text, "Error uploading address change:") {
		t.Fatal("a failed address upload must retry instead of remembering the new pair")
	}
	if strings.Contains(text, "last4, last6, _ := monitoring.GetIPAddress()") {
		t.Fatal("watch must not remember an address it has not uploaded")
	}
}

func TestBasicInfoIncludesRemoteProtocol(t *testing.T) {
	original := flags.RemoteControlEnabled
	flags.RemoteControlEnabled = true
	t.Cleanup(func() { flags.RemoteControlEnabled = original })

	data := buildBasicInfoMap()
	if data["remote_protocol"] != 2 {
		t.Fatalf("remote_protocol = %#v, want 2", data["remote_protocol"])
	}
	enabled, ok := data["remote_control_enabled"].(bool)
	if !ok {
		t.Fatalf("remote_control_enabled missing: %#v", data["remote_control_enabled"])
	}
	if !enabled {
		t.Fatal("remote_control_enabled should follow the positive flag")
	}
	if _, ok := data["mcp_full"]; ok {
		t.Fatal("basic info must not include mcp_full; 2.3.2 Lite would reject the whole update")
	}
	if _, ok := data["mcp_full_version"]; ok {
		t.Fatal("basic info must not include mcp_full_version; 2.3.2 Lite would reject the whole update")
	}
	if _, ok := data["mcp_enabled"]; ok {
		t.Fatal("basic info must not include mcp_enabled; 2.3.2 Lite would reject the whole update")
	}
	if _, ok := data["remote_control_protected"]; ok {
		t.Fatal("basic info must not report remote_control_protected")
	}
}

func TestBasicInfoRemoteControlEnabledFollowsFlag(t *testing.T) {
	original := flags.RemoteControlEnabled
	t.Cleanup(func() { flags.RemoteControlEnabled = original })

	flags.RemoteControlEnabled = false
	if pkg_flags.RemoteControlEnabled() {
		t.Fatal("RemoteControlEnabled() should be false")
	}
	data := buildBasicInfoMap()
	if data["remote_control_enabled"] != false {
		t.Fatalf("remote_control_enabled = %#v, want false", data["remote_control_enabled"])
	}

	flags.RemoteControlEnabled = true
	data = buildBasicInfoMap()
	if data["remote_control_enabled"] != true {
		t.Fatalf("remote_control_enabled = %#v, want true", data["remote_control_enabled"])
	}
}
