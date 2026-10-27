package firewall

import (
	"strconv"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func sshPortOf(intent v2.FirewallIntent) string {
	if port := keepPort(intent.SshPort); port != "" {
		return port
	}
	return keepPort(detectedSSHPort())
}

func portSpecOK(raw string) bool {
	raw = strings.TrimSpace(raw)
	from, to, cut := strings.Cut(raw, "-")
	if !cut {
		return keepPort(raw) != ""
	}
	a := keepPort(from)
	b := keepPort(to)
	if a == "" || b == "" {
		return false
	}
	ai, _ := strconv.Atoi(a)
	bi, _ := strconv.Atoi(b)
	return ai <= bi
}

func sourceOK(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	return !strings.ContainsAny(raw, " \t\n\r;\"'`$|&{}()\\%")
}

func ruleSafe(rule v2.FirewallRule) bool {
	switch rule.Protocol {
	case v2.FirewallProtoTCP, v2.FirewallProtoUDP:
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(rule.Action)) {
	case v2.FirewallActionAllow, v2.FirewallActionDeny, "":
	default:
		return false
	}
	switch rule.Stack {
	case v2.FirewallStackV4, v2.FirewallStackV6:
	default:
		return false
	}
	return portSpecOK(rule.Port) && sourceOK(rule.Source)
}

func holeSafe(hole v2.FirewallHole) bool {
	return ruleSafe(v2.FirewallRule{
		Action:   v2.FirewallActionAllow,
		Protocol: hole.Protocol,
		Port:     hole.Port,
		Stack:    hole.Stack,
	})
}

func keepPort(raw string) string {
	raw = strings.TrimSpace(raw)
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	return strconv.Itoa(port)
}

func keepTCP(port, comment string) []v2.FirewallRule {
	port = keepPort(port)
	if port == "" {
		return nil
	}
	out := make([]v2.FirewallRule, 0, 2)
	for _, stack := range []string{v2.FirewallStackV4, v2.FirewallStackV6} {
		if !stackAllowed(stack) {
			continue
		}
		out = append(out, v2.FirewallRule{
			ID:       "keep-" + stack + "-" + port,
			Enabled:  true,
			Action:   v2.FirewallActionAllow,
			Protocol: v2.FirewallProtoTCP,
			Port:     port,
			Stack:    stack,
			Comment:  comment,
			Origin:   v2.FirewallOriginKeep,
			Priority: 1,
		})
	}
	return out
}

func eachKeepRule(intent v2.FirewallIntent, fn func(v2.FirewallRule)) {
	if !intent.DefaultDeny4 && !intent.DefaultDeny6 {
		return
	}
	for _, rule := range keepRules(intent) {
		if rule.Stack == v2.FirewallStackV4 && !intent.DefaultDeny4 {
			continue
		}
		if rule.Stack == v2.FirewallStackV6 && !intent.DefaultDeny6 {
			continue
		}
		if !stackAllowed(rule.Stack) || !ruleSafe(rule) {
			continue
		}
		fn(rule)
	}
}
