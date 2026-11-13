package coreadapter

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFrontListenHosts(t *testing.T) {
	dual := FrontListenHosts("dual", "")
	if len(dual) != 2 || dual[0] != "0.0.0.0" || dual[1] != "::" {
		t.Fatalf("dual hosts %v", dual)
	}
	legacy := FrontListenHosts("dual", "::")
	if len(legacy) != 2 || legacy[0] != "0.0.0.0" || legacy[1] != "::" {
		t.Fatalf("legacy dual listen=:: %v", legacy)
	}
	ipv4 := FrontListenHosts("ipv4", "")
	if len(ipv4) != 1 || ipv4[0] != "0.0.0.0" {
		t.Fatalf("ipv4 hosts %v", ipv4)
	}
	for _, host := range ipv4 {
		if host == "::" {
			t.Fatalf("ipv4 hosts must not include ::: %v", ipv4)
		}
	}
	fromV6Wildcard := FrontListenHosts("ipv4", "[::]")
	if len(fromV6Wildcard) != 1 || fromV6Wildcard[0] != "0.0.0.0" {
		t.Fatalf("ipv4 from [::] %v", fromV6Wildcard)
	}
	if got := FrontListenHosts("dual", "192.0.2.8"); len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("explicit IP %v", got)
	}
}

func TestIsDualWildcardHosts(t *testing.T) {
	if !isDualWildcardHosts([]string{"0.0.0.0", "::"}) {
		t.Fatal("0.0.0.0 + ::")
	}
	if !isDualWildcardHosts([]string{"::", "0.0.0.0"}) {
		t.Fatal(":: + 0.0.0.0")
	}
	if isDualWildcardHosts([]string{"0.0.0.0"}) {
		t.Fatal("single host")
	}
	if isDualWildcardHosts([]string{"192.0.2.8", "::"}) {
		t.Fatal("explicit v4 + ::")
	}
}

func TestPublicCoreListenHosts(t *testing.T) {
	orig := detectOverlappingWildcard
	t.Cleanup(func() { detectOverlappingWildcard = orig })

	got := publicCoreListenHosts([]string{"192.0.2.8"}, "tcp4")
	if len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("explicit IP %v", got)
	}

	detectOverlappingWildcard = func(string) []string { return []string{"::"} }
	got = publicCoreListenHosts([]string{"::", "0.0.0.0"}, "tcp4")
	if len(got) != 1 || got[0] != "::" {
		t.Fatalf("dual-stack collapse %v", got)
	}

	detectOverlappingWildcard = func(string) []string { return []string{"0.0.0.0"} }
	got = publicCoreListenHosts([]string{"0.0.0.0", "::"}, "tcp4")
	if len(got) != 1 || got[0] != "0.0.0.0" {
		t.Fatalf("no-ipv6 fallback %v", got)
	}

	detectOverlappingWildcard = func(string) []string { return []string{"0.0.0.0", "::"} }
	got = publicCoreListenHosts([]string{"::", "0.0.0.0"}, "tcp")
	if len(got) != 2 || got[0] != "::" || got[1] != "0.0.0.0" {
		t.Fatalf("v6only keeps input order %v", got)
	}
}

func TestInboundPublicFrontsProbesOverlap(t *testing.T) {
	orig := detectOverlappingWildcard
	t.Cleanup(func() { detectOverlappingWildcard = orig })
	detectOverlappingWildcard = func(network string) []string {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(network)), "udp") {
			return []string{"::"}
		}
		return []string{"::"}
	}
	fronts := inboundPublicFronts(InboundSpec{Port: 443, SettingsJSON: `{"stack":"dual"}`}, "127.0.0.1:9", "shadowsocks", nil, true)
	if len(fronts) != 1 || !strings.Contains(fronts[0].Addr, "::") {
		t.Fatalf("overlap probe fronts %+v", fronts)
	}
}

func TestPublicListenHostsForProtocol(t *testing.T) {
	orig := detectOverlappingWildcard
	t.Cleanup(func() { detectOverlappingWildcard = orig })
	detectOverlappingWildcard = func(network string) []string {
		switch strings.ToLower(strings.TrimSpace(network)) {
		case "udp", "udp4", "udp6":
			return []string{"::"}
		default:
			return []string{"0.0.0.0", "::"}
		}
	}
	hosts := []string{"0.0.0.0", "::"}
	got := publicListenHostsForProtocol(hosts, true, false)
	if !sameStrings(got, hosts) {
		t.Fatalf("tcp-only %v", got)
	}
	got = publicListenHostsForProtocol(hosts, false, true)
	if len(got) != 1 || got[0] != "::" {
		t.Fatalf("udp-only %v", got)
	}
	got = publicListenHostsForProtocol(hosts, true, true)
	if len(got) != 1 || got[0] != "::" {
		t.Fatalf("tcp+udp intersection %v", got)
	}
	got = publicListenHostsForProtocol([]string{"192.0.2.8"}, false, true)
	if len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("explicit udp %v", got)
	}
}

func TestProbeOverlappingWildcard(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp", "udp", "udp4"} {
		got := probeOverlappingWildcard(network)
		switch {
		case len(got) == 1 && (got[0] == "::" || got[0] == "0.0.0.0"):
		case len(got) == 2 && got[0] == "0.0.0.0" && got[1] == "::":
		default:
			t.Fatalf("%s probe %v", network, got)
		}
	}
}

func TestInboundStackPrefersSettings(t *testing.T) {
	in := InboundSpec{
		SettingsJSON: `{"stack":"ipv4"}`,
		StreamJSON:   `{"stack":"dual"}`,
		Listen:       "::",
	}
	if got := inboundStack(in); got != "ipv4" {
		t.Fatalf("stack %q", got)
	}
	hosts := FrontListenHosts(inboundStack(in), in.Listen)
	if len(hosts) != 1 || hosts[0] != "0.0.0.0" {
		t.Fatalf("ipv4 from settings with listen=:: %v", hosts)
	}
}

func TestStartPolicyFrontsIPv4(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	specs := []frontSpec{{
		Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Dest: echo.Addr().String(),
	}}
	started, err := startPolicyFronts(nil, specs)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFronts(started)
	if err := pingTCP(t, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatalf("ipv4 dial: %v", err)
	}
	if err := pingTCP(t, "tcp6", net.JoinHostPort("::1", strconv.Itoa(port))); err == nil {
		t.Fatal("ipv4 front accepted IPv6 loopback")
	}
}

func TestStartPolicyFrontsIPv6(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	specs := []frontSpec{{
		Addr: net.JoinHostPort("::1", strconv.Itoa(port)),
		Dest: echo.Addr().String(),
	}}
	started, err := startPolicyFronts(nil, specs)
	if err != nil {
		t.Skipf("IPv6 listen unavailable: %v", err)
	}
	defer closeFronts(started)
	if err := pingTCP(t, "tcp6", net.JoinHostPort("::1", strconv.Itoa(port))); err != nil {
		t.Fatalf("ipv6 dial: %v", err)
	}
	if err := pingTCP(t, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		t.Fatal("ipv6 front accepted IPv4 loopback")
	}
}

func TestStartPolicyFrontsDual(t *testing.T) {
	echo := startEcho(t)
	defer echo.Close()
	port := freePort(t)
	echoAddr := echo.Addr().String()
	v4 := frontSpec{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Dest: echoAddr}
	v6 := frontSpec{Addr: net.JoinHostPort("::1", strconv.Itoa(port)), Dest: echoAddr}
	started, err := startPolicyFronts(nil, []frontSpec{v4, v6})
	if err != nil {
		t.Skipf("dual listen unavailable: %v", err)
	}
	defer closeFronts(started)
	if len(started) != 2 {
		t.Fatalf("started %d fronts, want 2", len(started))
	}
	if err := pingTCP(t, "tcp4", v4.Addr); err != nil {
		t.Fatalf("dual ipv4: %v", err)
	}
	if err := pingTCP(t, "tcp6", v6.Addr); err != nil {
		t.Fatalf("dual ipv6: %v", err)
	}
}

func TestXrayWSIdentityStillCreatesFronts(t *testing.T) {
	c := newXrayCore()
	_, _, fronts, err := c.buildConfig(
		[]UserSpec{{ID: "u1", UUID: vlessAlice}},
		[]InboundSpec{{
			ID:         "ws",
			Listen:     "127.0.0.1",
			Port:       38400,
			Protocol:   "vless",
			StreamJSON: `{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}`,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var public []frontSpec
	for _, front := range fronts {
		if !front.Exit {
			public = append(public, front)
		}
	}
	if len(public) != 1 || public[0].Addr != "127.0.0.1:38400" || !public[0].Identity {
		t.Fatalf("ws identity front %+v", public)
	}
}

func TestXrayRealityDualWildcardBindsCore(t *testing.T) {
	c := newXrayCore()
	raw, _, fronts, err := c.buildConfig(
		[]UserSpec{{ID: "u1", UUID: vlessAlice}},
		[]InboundSpec{{
			ID:           "in1",
			Listen:       "::",
			Port:         38401,
			Protocol:     "vless",
			SettingsJSON: `{"stack":"dual"}`,
			StreamJSON:   `{"network":"tcp","security":"reality","stack":"dual"}`,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, front := range fronts {
		if !front.Exit {
			t.Fatalf("reality must bind the core, got public front %+v", front)
		}
	}
	var cfg struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
			Tag    string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var listens []string
	for _, in := range cfg.Inbounds {
		if in.Port == 38401 {
			listens = append(listens, in.Listen)
		}
	}
	if !sameStrings(listens, publicCoreListenHosts([]string{"0.0.0.0", "::"}, "tcp")) {
		t.Fatalf("reality dual listens %v", listens)
	}
}

func TestSingBoxRealityDualWildcardBindsCore(t *testing.T) {
	c := newSingBoxCore()
	raw, _, fronts, err := c.buildConfig(
		[]UserSpec{{ID: "u1", UUID: vlessAlice}},
		[]InboundSpec{{
			ID:           "in1",
			Listen:       "::",
			Port:         38402,
			Protocol:     "vless",
			SettingsJSON: `{"stack":"dual"}`,
			StreamJSON:   `{"network":"tcp","security":"reality"}`,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, front := range fronts {
		if !front.Exit {
			t.Fatalf("reality must bind the core, got public front %+v", front)
		}
	}
	var cfg struct {
		Inbounds []struct {
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
			Type       string `json:"type"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var listens []string
	for _, in := range cfg.Inbounds {
		if in.Type == "vless" && in.ListenPort == 38402 {
			listens = append(listens, in.Listen)
		}
	}
	if !sameStrings(listens, publicCoreListenHosts([]string{"0.0.0.0", "::"}, "tcp4")) {
		t.Fatalf("reality dual listens %v", listens)
	}
}

func TestSingBoxAnyTLSRealityBindsPublic(t *testing.T) {
	c := newSingBoxCore()
	raw, _, fronts, err := c.buildConfig(
		[]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}},
		[]InboundSpec{{
			ID:         "anytls",
			Listen:     "127.0.0.1",
			Port:       38404,
			Protocol:   "anytls",
			StreamJSON: `{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:9","serverNames":["audit.test"],"privateKey":"dGVzdA","shortIds":["abcd"]}}`,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, front := range fronts {
		if !front.Exit {
			t.Fatalf("anytls reality must bind the core, got public front %+v", front)
		}
	}
	var cfg struct {
		Inbounds []struct {
			Listen     string         `json:"listen"`
			ListenPort int            `json:"listen_port"`
			Type       string         `json:"type"`
			TLS        map[string]any `json:"tls"`
			Users      []struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, in := range cfg.Inbounds {
		if in.Type != "anytls" || in.ListenPort != 38404 {
			continue
		}
		found = true
		if in.Listen != "127.0.0.1" {
			t.Fatalf("anytls listen %s", in.Listen)
		}
		if in.TLS == nil {
			t.Fatal("anytls reality missing tls")
		}
		reality, _ := in.TLS["reality"].(map[string]any)
		if reality == nil {
			t.Fatalf("anytls missing reality: %+v", in.TLS)
		}
		if len(in.Users) != 1 || in.Users[0].Password != "pw" {
			t.Fatalf("anytls users %+v", in.Users)
		}
	}
	if !found {
		t.Fatalf("anytls inbound missing: %s", raw)
	}
}

func TestSingBoxUDPDualCreatesOneListen(t *testing.T) {
	c := newSingBoxCore()
	raw, _, fronts, err := c.buildConfig(
		[]UserSpec{{ID: "u1", UUID: vlessAlice, Password: "pw"}},
		[]InboundSpec{{
			ID:           "hy2",
			Listen:       "",
			Port:         38403,
			Protocol:     "hysteria2",
			SettingsJSON: `{"stack":"dual"}`,
		}},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(fronts) != 0 {
		t.Fatalf("udp must not use tcp fronts: %+v", fronts)
	}
	var cfg struct {
		Inbounds []struct {
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
			Type       string `json:"type"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var listens []string
	for _, in := range cfg.Inbounds {
		if in.Type == "hysteria2" && in.ListenPort == 38403 {
			listens = append(listens, in.Listen)
		}
	}
	if !sameStrings(listens, publicCoreListenHosts([]string{"0.0.0.0", "::"}, "tcp4")) {
		t.Fatalf("udp dual listens %v", listens)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestListenNetwork(t *testing.T) {
	if got := listenNetwork("0.0.0.0:443"); got != "tcp4" {
		t.Fatalf("v4 network %s", got)
	}
	if got := listenNetwork("[::]:443"); got != "tcp6" {
		t.Fatalf("v6 network %s", got)
	}
}

func closeFronts(fronts []*spliceFront) {
	for _, f := range fronts {
		f.close()
	}
}

func pingTCP(t *testing.T, network, addr string) error {
	t.Helper()
	conn, err := net.DialTimeout(network, addr, 400*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != "ping" {
		return fmt.Errorf("echo %q", buf[:n])
	}
	return nil
}
