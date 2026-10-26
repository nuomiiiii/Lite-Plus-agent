package coreadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

func inboundStack(in InboundSpec) string {
	if stack := strings.TrimSpace(settingString(in.SettingsJSON, "stack")); stack != "" {
		return stack
	}
	if strings.TrimSpace(in.StreamJSON) == "" {
		return ""
	}
	var stream map[string]any
	if err := json.Unmarshal([]byte(in.StreamJSON), &stream); err != nil {
		return ""
	}
	got, _ := stream["stack"].(string)
	return strings.TrimSpace(got)
}

func isWildcardListen(listen string) bool {
	switch strings.ToLower(strings.TrimSpace(listen)) {
	case "", "*", "0.0.0.0", "::", "[::]", "0.0.0.0,::", "::,0.0.0.0":
		return true
	default:
		return false
	}
}

func unwrapListenHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) > 2 {
		return host[1 : len(host)-1]
	}
	return host
}

func FrontListenHosts(stack, listen string) []string {
	listen = strings.TrimSpace(listen)
	if listen != "" && !isWildcardListen(listen) {
		return []string{unwrapListenHost(listen)}
	}
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv4":
		return []string{"0.0.0.0"}
	case "ipv6":
		return []string{"::"}
	default:
		return []string{"0.0.0.0", "::"}
	}
}

func isDualWildcardHosts(hosts []string) bool {
	if len(hosts) != 2 {
		return false
	}
	a, b := hosts[0], hosts[1]
	return (a == "0.0.0.0" && b == "::") || (a == "::" && b == "0.0.0.0")
}

// publicCoreListenHosts folds a dual wildcard pair to match a core's
// listen networks. v4network is "tcp4" (sing-box) or "tcp" (Xray).
// Bind order matches the cores: 0.0.0.0 first, then ::. If the IPv6
// socket overlaps IPv4, keep only "::". If IPv6 is missing, keep
// "0.0.0.0". If they coexist, keep both.
func publicCoreListenHosts(hosts []string, v4network string) []string {
	if !isDualWildcardHosts(hosts) {
		return hosts
	}
	if strings.TrimSpace(v4network) == "" {
		v4network = "tcp4"
	}
	probed := detectOverlappingWildcard(v4network)
	if len(probed) == 1 {
		return probed
	}
	return hosts
}

var detectOverlappingWildcard = probeOverlappingWildcard

func probeOverlappingWildcard(v4network string) []string {
	v4, err := net.Listen(v4network, "0.0.0.0:0")
	if err != nil {
		v6, v6err := net.Listen("tcp", "[::]:0")
		if v6err == nil {
			_ = v6.Close()
			return []string{"::"}
		}
		return []string{"0.0.0.0"}
	}
	defer v4.Close()
	port := v4.Addr().(*net.TCPAddr).Port
	v6, err := net.Listen("tcp", net.JoinHostPort("::", strconv.Itoa(port)))
	if err == nil {
		_ = v6.Close()
		return []string{"0.0.0.0", "::"}
	}
	if isAddrInUse(err) {
		return []string{"::"}
	}
	return []string{"0.0.0.0"}
}

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "Only one usage of each socket address")
}

func inboundPublicFronts(in InboundSpec, dest, proto string, users []UserSpec, sendProxy bool) []frontSpec {
	port := fmt.Sprintf("%d", in.Port)
	hosts := FrontListenHosts(inboundStack(in), in.Listen)
	out := make([]frontSpec, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, newFrontSpec(
			net.JoinHostPort(unwrapListenHost(host), port),
			dest,
			proto,
			in,
			users,
			sendProxy,
		))
	}
	return out
}
