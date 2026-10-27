package firewall

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const (
	plusNftTable      = "liteplus"
	plusIptablesChain = "LITE_PLUS"
	plusCommentMark   = "lite-plus:"
)

var (
	iptablesRuleRe = regexp.MustCompile(`^-A\s+(\S+)\s+(.*)$`)
	dportRe        = regexp.MustCompile(`--dport(?:s)?\s+(\d+)(?::(\d+))?`)
	protoRe        = regexp.MustCompile(`(?:^|\s)-p\s+(tcp|udp)\b`)
	sourceRe       = regexp.MustCompile(`(?:^|\s)-s\s+(\S+)`)
	jumpRe         = regexp.MustCompile(`(?:^|\s)-j\s+(ACCEPT|DROP|REJECT)\b`)
	ifaceRe        = regexp.MustCompile(`(?:^|\s)-i\s+(\S+)`)
	complexRe      = regexp.MustCompile(`(?i)\b(DOCKER|FAIL2BAN|BR-|docker0|multiport|connlimit|limit|set\s+--match-set|owner|physdev|policy|helper|recent)\b`)
	ufwLineRe      = regexp.MustCompile(`(?i)^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(\S.*)$`)
	nftHandleRe    = regexp.MustCompile(`(?i)#\s*handle\s+(\d+)\s*$`)
)

func hostKey(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:12])
}

func parseIptablesSave(raw, stack, chain string) []v2.FirewallHostRule {
	var out []v2.FirewallHostRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") || strings.HasPrefix(line, ":") || line == "COMMIT" {
			continue
		}
		if strings.Contains(line, plusCommentMark) || strings.Contains(line, "-j "+plusIptablesChain) {
			continue
		}
		match := iptablesRuleRe.FindStringSubmatch(line)
		if match == nil || !strings.EqualFold(match[1], chain) {
			continue
		}
		out = append(out, classifyIptablesBody(line, match[2], stack))
	}
	return out
}

func classifyIptablesBody(raw, body, stack string) v2.FirewallHostRule {
	rule := v2.FirewallHostRule{Key: hostKey("iptables", stack, raw), Raw: raw, Stack: stack}
	if ifaceRe.MatchString(body) || complexRe.MatchString(body) || strings.Contains(body, "!") {
		rule.Reason = "complex"
		return rule
	}
	jump := jumpRe.FindStringSubmatch(body)
	proto := protoRe.FindStringSubmatch(body)
	dport := dportRe.FindStringSubmatch(body)
	if jump == nil || proto == nil || dport == nil {
		rule.Reason = "unsupported match"
		return rule
	}
	action := v2.FirewallActionAllow
	if jump[1] != "ACCEPT" {
		action = v2.FirewallActionDeny
	}
	port := dport[1]
	if dport[2] != "" && dport[2] != dport[1] {
		port = dport[1] + "-" + dport[2]
	}
	source := ""
	if src := sourceRe.FindStringSubmatch(body); len(src) > 1 {
		source = src[1]
	}
	rule.Adoptable = true
	rule.Action = action
	rule.Protocol = strings.ToLower(proto[1])
	rule.Port = port
	rule.Source = source
	return rule
}

func parseUFWStatus(raw, stack string) []v2.FirewallHostRule {
	return parseUFWStatusApps(raw, stack, nil)
}

func parseUFWStatusApps(raw, stack string, appPorts map[string]string) []v2.FirewallHostRule {
	var out []v2.FirewallHostRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, plusCommentMark) {
			continue
		}
		v6 := strings.Contains(line, "(v6)")
		if stack == v2.FirewallStackV4 && v6 {
			continue
		}
		if stack == v2.FirewallStackV6 && !v6 {
			continue
		}
		match := ufwLineRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		num, to, action, dir := match[1], match[2], strings.ToUpper(match[3]), strings.ToUpper(match[4])
		from := ufwFromField(match[5])
		rule := v2.FirewallHostRule{Key: hostKey("ufw", stack, num, line), Raw: line, Stack: stack, Comment: "ufw #" + num}
		if dir != "IN" {
			rule.Reason = "not inbound"
			out = append(out, rule)
			continue
		}
		mapped := v2.FirewallActionAllow
		if action == "DENY" || action == "REJECT" {
			mapped = v2.FirewallActionDeny
		} else if action != "ALLOW" {
			rule.Reason = "complex"
			out = append(out, rule)
			continue
		}
		rule.Action = mapped
		rule.Source = from
		proto, port := splitPortProto(to)
		if proto == "" || port == "" {
			if spec := appPorts[ufwAppName(to)]; spec != "" {
				proto, port = splitPortProto(spec)
			}
		}
		if proto == "" || port == "" {
			rule.Reason = "unsupported match"
			out = append(out, rule)
			continue
		}
		rule.Adoptable = true
		rule.Protocol = proto
		rule.Port = port
		out = append(out, rule)
	}
	return out
}

func ufwAppName(to string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(to), "(v6)"))
}

func parseUfwAppInfo(info string) string {
	for _, line := range strings.Split(info, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(trim), "ports:") {
			continue
		}
		rest := strings.TrimSpace(trim[len("ports:"):])
		if rest == "" || strings.ContainsAny(rest, ",|") {
			return ""
		}
		proto, port := splitPortProto(rest)
		if proto == "" || port == "" {
			return ""
		}
		return port + "/" + proto
	}
	return ""
}

func ufwFromField(raw string) string {
	from := strings.TrimSpace(strings.Split(raw, "#")[0])
	from = strings.TrimSpace(strings.TrimSuffix(from, "(v6)"))
	from = strings.TrimSpace(strings.TrimSuffix(from, "(log)"))
	if strings.EqualFold(from, "anywhere") || from == "" {
		return ""
	}
	return from
}

func splitPortProto(to string) (string, string) {
	to = strings.TrimSpace(to)
	to = strings.TrimSpace(strings.TrimSuffix(to, "(v6)"))
	if to == "" || strings.EqualFold(to, "Anywhere") {
		return "", ""
	}
	port, proto, ok := strings.Cut(to, "/")
	if ok {
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto != "tcp" && proto != "udp" {
			return "", ""
		}
		port = strings.ReplaceAll(strings.TrimSpace(port), ":", "-")
		if !validHostPort(port) {
			return "", ""
		}
		return proto, port
	}
	if _, err := strconv.Atoi(to); err == nil {
		return "tcp", to
	}
	return "", ""
}

func validHostPort(port string) bool {
	from, to, ok := strings.Cut(port, "-")
	if !ok {
		_, err := strconv.Atoi(port)
		return err == nil
	}
	start, err1 := strconv.Atoi(from)
	end, err2 := strconv.Atoi(to)
	return err1 == nil && err2 == nil && start >= 1 && end >= start && end <= 65535
}

func parseNftRuleset(raw string) []v2.FirewallHostRule {
	var out []v2.FirewallHostRule
	family, table, chain := "", "", ""
	skipTable := false
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "table ") {
			family, table, skipTable = nftTableHeader(trim)
			chain = ""
			continue
		}
		if skipTable {
			continue
		}
		if strings.HasPrefix(trim, "chain ") {
			fields := strings.Fields(trim)
			if len(fields) >= 2 {
				chain = fields[1]
			}
			continue
		}
		if !strings.Contains(trim, "dport") || strings.Contains(trim, plusCommentMark) {
			continue
		}
		if strings.Contains(trim, "dnat") || strings.Contains(trim, "snat") || strings.Contains(trim, "masquerade") || strings.Contains(trim, "redirect") {
			continue
		}
		out = append(out, nftSimpleLine(trim, family, table, chain))
	}
	return out
}

func nftTableHeader(trim string) (family, table string, skip bool) {
	fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(trim), "{"))
	if len(fields) < 3 {
		return "", "", true
	}
	family, table = fields[1], fields[2]
	switch {
	case table == plusNftTable, table == "nat", table == "mangle", table == "raw":
		return family, table, true
	case family == "arp", family == "bridge", family == "netdev":
		return family, table, true
	default:
		return family, table, false
	}
}

func parseFirewalldPorts(raw string) []v2.FirewallHostRule {
	return firewalldPortRules("", raw, "firewalld-port")
}

func parseFirewalldService(name, info string) []v2.FirewallHostRule {
	var ports []string
	for _, line := range strings.Split(info, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(trim), "ports:") {
			continue
		}
		ports = append(ports, strings.Fields(strings.TrimSpace(trim[len("ports:"):]))...)
	}
	return firewalldPortRules(name, strings.Join(ports, " "), "firewalld-service")
}

func firewalldPortRules(name, raw, kind string) []v2.FirewallHostRule {
	var out []v2.FirewallHostRule
	for _, field := range strings.Fields(raw) {
		proto, port := splitPortProto(field)
		if proto == "" || port == "" {
			continue
		}
		comment := kind + " " + port + "/" + proto
		if kind == "firewalld-service" {
			comment = kind + " " + name
		}
		for _, stack := range []string{v2.FirewallStackV4, v2.FirewallStackV6} {
			out = append(out, v2.FirewallHostRule{
				Key:       hostKey(kind, name, stack, proto, port),
				Adoptable: true,
				Action:    v2.FirewallActionAllow,
				Protocol:  proto,
				Port:      port,
				Stack:     stack,
				Comment:   comment,
				Raw:       strings.TrimSpace(name + " " + field),
			})
		}
	}
	return out
}

func nftSimpleLine(line, family, table, chain string) v2.FirewallHostRule {
	raw := strings.TrimSpace(line)
	handle := ""
	if match := nftHandleRe.FindStringSubmatch(raw); len(match) > 1 {
		handle = match[1]
		raw = strings.TrimSpace(nftHandleRe.ReplaceAllString(raw, ""))
	}
	stack := v2.FirewallStackV4
	if family == "ip6" || strings.Contains(strings.ToLower(raw), "ip6") {
		stack = v2.FirewallStackV6
	}
	rule := v2.FirewallHostRule{Key: hostKey("nft", family, table, chain, handle, raw), Raw: strings.TrimSpace(line), Stack: stack}
	if handle != "" && family != "" && table != "" && chain != "" {
		rule.Comment = "nft " + family + " " + table + " " + chain + " " + handle
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "iif") || strings.Contains(lower, "oif") || strings.Contains(lower, "goto") || strings.Contains(lower, "jump") || strings.Contains(lower, "limit") || strings.Contains(lower, "set") {
		rule.Reason = "complex"
		return rule
	}
	action := nftAction(lower)
	if action == "" {
		rule.Reason = "unsupported match"
		return rule
	}
	proto := ""
	if strings.Contains(lower, "tcp") {
		proto = v2.FirewallProtoTCP
	} else if strings.Contains(lower, "udp") {
		proto = v2.FirewallProtoUDP
	} else {
		rule.Reason = "unsupported match"
		return rule
	}
	port := ""
	if parts := strings.Fields(lower); len(parts) > 0 {
		for i, part := range parts {
			if part == "dport" && i+1 < len(parts) {
				port = strings.ReplaceAll(parts[i+1], ":", "-")
				port = strings.TrimSpace(strings.Trim(port, "{}"))
				break
			}
		}
	}
	port = strings.ReplaceAll(port, ":", "-")
	if port == "" || strings.Contains(port, ",") || !validHostPort(port) {
		rule.Reason = "unsupported match"
		return rule
	}
	source := ""
	for _, key := range []string{"ip saddr", "ip6 saddr"} {
		if idx := strings.Index(lower, key); idx >= 0 {
			rest := strings.TrimSpace(lower[idx+len(key):])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				source = fields[0]
			}
		}
	}
	rule.Adoptable = true
	rule.Action = action
	rule.Protocol = proto
	rule.Port = port
	rule.Source = source
	return rule
}

func nftAction(lower string) string {
	fields := strings.Fields(lower)
	for i := len(fields) - 1; i >= 0; i-- {
		switch strings.Trim(fields[i], `"'`) {
		case "accept":
			return v2.FirewallActionAllow
		case "drop", "reject":
			return v2.FirewallActionDeny
		}
	}
	return ""
}

func parseWindowsRules(raw string) []v2.FirewallHostRule {
	blocks := strings.Split(raw, "Rule Name:")
	var out []v2.FirewallHostRule
	for _, block := range blocks[1:] {
		fields := map[string]string{}
		name := strings.TrimSpace(strings.Split(block, "\n")[0])
		fields["name"] = name
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
		if !strings.EqualFold(fields["direction"], "in") && fields["direction"] != "" {
			continue
		}
		proto := strings.ToLower(fields["protocol"])
		port := fields["localport"]
		rule := v2.FirewallHostRule{
			Key:     hostKey("windows", name, proto, port),
			Raw:     strings.TrimSpace(block),
			Comment: name,
			Stack:   v2.FirewallStackV4,
		}
		if strings.Contains(fields["localip"], ":") || strings.Contains(strings.ToLower(name), "ipv6") {
			rule.Stack = v2.FirewallStackV6
		}
		if (proto != "tcp" && proto != "udp") || port == "" || strings.EqualFold(port, "any") || strings.Contains(port, ",") {
			rule.Reason = "unsupported match"
			out = append(out, rule)
			continue
		}
		action := v2.FirewallActionAllow
		if strings.EqualFold(fields["action"], "block") {
			action = v2.FirewallActionDeny
		}
		rule.Adoptable = true
		rule.Action = action
		rule.Protocol = proto
		rule.Port = strings.ReplaceAll(port, ":", "-")
		if remote := fields["remoteip"]; remote != "" && !strings.EqualFold(remote, "any") {
			rule.Source = remote
		}
		out = append(out, rule)
	}
	return out
}

func plusComment(id string) string {
	return fmt.Sprintf("lite-plus:%s", id)
}
