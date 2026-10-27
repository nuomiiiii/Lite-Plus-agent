package coreadapter

import (
	"net"
	"strings"
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
