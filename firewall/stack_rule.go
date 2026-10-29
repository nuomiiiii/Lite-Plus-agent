package firewall

import (
	"net"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func sourceFitsStack(source, stack string) bool {
	source = strings.TrimSpace(source)
	if source == "" {
		return true
	}
	host := source
	if i := strings.Index(source, "/"); i >= 0 {
		host = source[:i]
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	is4 := ip.To4() != nil
	if stack == v2.FirewallStackV6 {
		return !is4
	}
	return is4
}

func ruleAppliesToStack(rule v2.FirewallRule, stack string) bool {
	if stack != v2.FirewallStackV4 && stack != v2.FirewallStackV6 {
		return false
	}
	if !sourceFitsStack(rule.Source, stack) {
		return false
	}
	declared := strings.TrimSpace(rule.Stack)
	if declared == "" {
		return true
	}
	return declared == stack
}

func holeAppliesToStack(hole v2.FirewallHole, stack string) bool {
	return ruleAppliesToStack(v2.FirewallRule{
		Action:   v2.FirewallActionAllow,
		Protocol: hole.Protocol,
		Port:     hole.Port,
		Stack:    hole.Stack,
	}, stack)
}

func eachStackedRule(rule v2.FirewallRule, fn func(v2.FirewallRule)) {
	for _, stack := range []string{v2.FirewallStackV4, v2.FirewallStackV6} {
		if !stackAllowed(stack) || !ruleAppliesToStack(rule, stack) {
			continue
		}
		next := rule
		next.Stack = stack
		fn(next)
	}
}
