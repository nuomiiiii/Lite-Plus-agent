package coreadapter

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	dialStackDual       = "dual"
	dialStackIPv4       = "ipv4"
	dialStackIPv6       = "ipv6"
	dialStackPreferIPv4 = "prefer_ipv4"
	dialStackPreferIPv6 = "prefer_ipv6"
)

func NormalizeDialStack(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case dialStackIPv4, "ipv4_only", "useipv4":
		return dialStackIPv4
	case dialStackIPv6, "ipv6_only", "useipv6":
		return dialStackIPv6
	case dialStackPreferIPv4, "useipv4v6":
		return dialStackPreferIPv4
	case dialStackPreferIPv6, "useipv6v4":
		return dialStackPreferIPv6
	default:
		return dialStackDual
	}
}

func xrayDomainStrategy(stack string) string {
	switch NormalizeDialStack(stack) {
	case dialStackIPv4:
		return "UseIPv4"
	case dialStackIPv6:
		return "UseIPv6"
	case dialStackPreferIPv4:
		return "UseIPv4v6"
	case dialStackPreferIPv6:
		return "UseIPv6v4"
	default:
		return ""
	}
}

func singBoxDomainStrategy(stack string) string {
	switch NormalizeDialStack(stack) {
	case dialStackIPv4:
		return "ipv4_only"
	case dialStackIPv6:
		return "ipv6_only"
	case dialStackPreferIPv4:
		return "prefer_ipv4"
	case dialStackPreferIPv6:
		return "prefer_ipv6"
	default:
		return ""
	}
}

func skipXrayDialStackOutbound(ob map[string]any) bool {
	kind := outboundKind(ob)
	if kind == "blackhole" || kind == "block" {
		return true
	}
	tag, _ := ob["tag"].(string)
	if strings.HasPrefix(tag, "nodemgt-") {
		return true
	}
	return outboundDialsLoopback(ob)
}

func outboundDialsLoopback(ob map[string]any) bool {
	if hostIsLoopback(stringFromAny(ob["server"])) {
		return true
	}
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return false
	}
	for _, key := range []string{"servers", "vnext"} {
		for _, row := range anyMaps(settings[key]) {
			if hostIsLoopback(stringFromAny(row["address"])) {
				return true
			}
		}
	}
	return false
}

func hostIsLoopback(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	return s
}

func ipAllowedByStack(ip net.IP, stack string) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4() != nil
	switch NormalizeDialStack(stack) {
	case dialStackIPv4:
		return v4
	case dialStackIPv6:
		return !v4
	default:
		return true
	}
}

func dialTCPWithStack(dest, stack string, timeout time.Duration) (net.Conn, error) {
	stack = NormalizeDialStack(stack)
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ipAllowedByStack(ip, stack) {
			return nil, fmt.Errorf("dial stack %s", stack)
		}
		network := "tcp6"
		if ip.To4() != nil {
			network = "tcp4"
		}
		return net.DialTimeout(network, dest, timeout)
	}
	switch stack {
	case dialStackIPv4:
		return net.DialTimeout("tcp4", dest, timeout)
	case dialStackIPv6:
		return net.DialTimeout("tcp6", dest, timeout)
	case dialStackPreferIPv4:
		return dialTCPPrefer(dest, timeout, true)
	case dialStackPreferIPv6:
		return dialTCPPrefer(dest, timeout, false)
	default:
		return net.DialTimeout("tcp", dest, timeout)
	}
}

func dialTCPPrefer(dest string, timeout time.Duration, v4First bool) (net.Conn, error) {
	first, second := "tcp4", "tcp6"
	if !v4First {
		first, second = "tcp6", "tcp4"
	}
	conn, err := net.DialTimeout(first, dest, timeout)
	if err == nil {
		return conn, nil
	}
	return net.DialTimeout(second, dest, timeout)
}

func resolveUDPAddrWithStack(dest, stack string) (*net.UDPAddr, error) {
	stack = NormalizeDialStack(stack)
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("udp port")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ipAllowedByStack(ip, stack) {
			return nil, fmt.Errorf("udp stack %s", stack)
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	switch stack {
	case dialStackIPv4:
		return net.ResolveUDPAddr("udp4", dest)
	case dialStackIPv6:
		return net.ResolveUDPAddr("udp6", dest)
	case dialStackPreferIPv4:
		if addr, err := net.ResolveUDPAddr("udp4", dest); err == nil {
			return addr, nil
		}
		return net.ResolveUDPAddr("udp6", dest)
	case dialStackPreferIPv6:
		if addr, err := net.ResolveUDPAddr("udp6", dest); err == nil {
			return addr, nil
		}
		return net.ResolveUDPAddr("udp4", dest)
	default:
		return net.ResolveUDPAddr("udp", dest)
	}
}

func applyXrayDialStack(obs []map[string]any, stack string) {
	ds := xrayDomainStrategy(stack)
	if ds == "" {
		return
	}
	for _, ob := range obs {
		if skipXrayDialStackOutbound(ob) {
			continue
		}
		kind := outboundKind(ob)
		if kind == "freedom" || kind == "direct" || kind == "" {
			settings, _ := ob["settings"].(map[string]any)
			if settings == nil {
				settings = map[string]any{}
				ob["settings"] = settings
			}
			settings["domainStrategy"] = ds
			continue
		}
		stream, _ := ob["streamSettings"].(map[string]any)
		if stream == nil {
			stream = map[string]any{}
			ob["streamSettings"] = stream
		}
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt == nil {
			sockopt = map[string]any{}
			stream["sockopt"] = sockopt
		}
		sockopt["domainStrategy"] = ds
	}
}

func singBoxDNS(stack string) map[string]any {
	strategy := singBoxDomainStrategy(stack)
	if strategy == "" {
		return nil
	}
	return map[string]any{
		"servers":  []map[string]any{{"type": "local", "tag": "local"}},
		"final":    "local",
		"strategy": strategy,
	}
}

func applySingBoxDialStack(cfg, route map[string]any, stack string) {
	strategy := singBoxDomainStrategy(stack)
	if strategy == "" {
		return
	}
	if dns := singBoxDNS(stack); dns != nil {
		cfg["dns"] = dns
	}
	if route == nil {
		route = map[string]any{"final": "direct"}
		cfg["route"] = route
	}
	route["default_domain_resolver"] = map[string]any{
		"server":   "local",
		"strategy": strategy,
	}
}
