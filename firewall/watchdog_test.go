package firewall

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
)

func TestEndpointHostPort(t *testing.T) {
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() { pkg_flags.GlobalConfig.Endpoint = orig })

	pkg_flags.GlobalConfig.Endpoint = ""
	if got := endpointHostPort(); got != "" {
		t.Fatalf("empty endpoint: %q", got)
	}
	pkg_flags.GlobalConfig.Endpoint = "https://panel.example.com:28777"
	if got := endpointHostPort(); got != "panel.example.com:28777" {
		t.Fatalf("explicit port: %q", got)
	}
	pkg_flags.GlobalConfig.Endpoint = "http://panel.example.com"
	if got := endpointHostPort(); got != "panel.example.com:80" {
		t.Fatalf("http default: %q", got)
	}
	pkg_flags.GlobalConfig.Endpoint = "panel.example.com"
	if got := endpointHostPort(); got != "panel.example.com:443" {
		t.Fatalf("bare host: %q", got)
	}
	pkg_flags.GlobalConfig.Endpoint = "https://[2001:db8::1]"
	if got := endpointHostPort(); got != "[2001:db8::1]:443" {
		t.Fatalf("ipv6 host: %q", got)
	}
	pkg_flags.GlobalConfig.Endpoint = "https://[2001:db8::1]:28777"
	if got := endpointHostPort(); got != "[2001:db8::1]:28777" {
		t.Fatalf("ipv6 port: %q", got)
	}
}

func TestWatchdogUsesLivePeerBeforeEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.Endpoint = orig
		SetControlPlanePeer(nil)
	})
	pkg_flags.GlobalConfig.Endpoint = "http://127.0.0.1:1"
	SetControlPlanePeer(func() string { return ln.Addr().String() })
	if !watchdogOK() {
		t.Fatal("live control-plane peer must keep the new rules")
	}
}

func TestWatchdogDialsPreferredEndpointWhenPeerMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.Endpoint = orig
		SetControlPlanePeer(nil)
	})
	SetControlPlanePeer(nil)
	pkg_flags.GlobalConfig.Endpoint = "http://" + ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if watchdogOK() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("endpoint dial must succeed when the live peer is missing")
}

func TestWatchdogRejectsUnreachableEndpoint(t *testing.T) {
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.Endpoint = orig
		SetControlPlanePeer(nil)
	})
	SetControlPlanePeer(nil)
	pkg_flags.GlobalConfig.Endpoint = "http://127.0.0.1:1"
	if watchdogOK() {
		t.Fatal("unreachable endpoint must fail the control-plane probe")
	}
}

func TestWatchdogOKWhenEndpointEmpty(t *testing.T) {
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.Endpoint = orig
		SetControlPlanePeer(nil)
	})
	SetControlPlanePeer(nil)
	pkg_flags.GlobalConfig.Endpoint = ""
	if !watchdogOK() {
		t.Fatal("empty endpoint must not roll back applied rules")
	}
}

func TestWatchdogEmptyEndpointDoesNotRollbackWhenPeerFails(t *testing.T) {
	orig := pkg_flags.GlobalConfig.Endpoint
	t.Cleanup(func() {
		pkg_flags.GlobalConfig.Endpoint = orig
		SetControlPlanePeer(nil)
	})
	SetControlPlanePeer(func() string { return "127.0.0.1:1" })
	pkg_flags.GlobalConfig.Endpoint = ""
	if !watchdogOK() {
		t.Fatal("debug agents without Endpoint must not roll back applied rules")
	}
}

func TestIPLiteral(t *testing.T) {
	if !ipLiteral("127.0.0.1") || !ipLiteral("::1") || !ipLiteral("2001:db8::1") {
		t.Fatal("plain IP literals must skip DNS")
	}
	if !ipLiteral("::ffff:127.0.0.1") || !ipLiteral("fe80::1%eth0") {
		t.Fatal("mapped and zoned IPs must skip DNS")
	}
	if ipLiteral("panel.example.com") || ipLiteral("") {
		t.Fatal("hostnames must keep the resolver path")
	}
}

func TestWatchdogProbeUsesResolverPreference(t *testing.T) {
	raw, err := os.ReadFile("watchdog.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, `net.DialTimeout("tcp"`) {
		t.Fatal("watchdog must not DualStack-dial the panel hostname")
	}
	if !strings.Contains(text, "GetDialContextWithPreference") || !strings.Contains(text, "PreferIPVersion") {
		t.Fatal("watchdog must dial the panel the same way the websocket does")
	}
	if !strings.Contains(text, "liveControlPeer()") {
		t.Fatal("watchdog must try the live websocket peer before a new hostname lookup")
	}
	if !strings.Contains(text, "ipLiteral(host)") {
		t.Fatal("live peer IPs must be dialed directly without a hostname lookup")
	}
	if !strings.Contains(text, "if host == \"\"") || !strings.Contains(text, "return true") {
		t.Fatal("empty Endpoint must not roll back applied rules")
	}
}
