package firewall

import (
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestRuleAppliesToStackDualStack(t *testing.T) {
	allow := v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "443", Stack: v2.FirewallStackV4}
	if !ruleAppliesToStack(allow, v2.FirewallStackV4) || ruleAppliesToStack(allow, v2.FirewallStackV6) {
		t.Fatal("unsourced v4 allow must stay on v4")
	}
	v6 := allow
	v6.Stack = v2.FirewallStackV6
	if ruleAppliesToStack(v6, v2.FirewallStackV4) || !ruleAppliesToStack(v6, v2.FirewallStackV6) {
		t.Fatal("unsourced v6 allow must stay on v6")
	}
	legacy := v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "443"}
	if !ruleAppliesToStack(legacy, v2.FirewallStackV4) || !ruleAppliesToStack(legacy, v2.FirewallStackV6) {
		t.Fatal("legacy unsourced allow with no stack must land on both families")
	}
	v4src := allow
	v4src.Source = "203.0.113.8"
	if !ruleAppliesToStack(v4src, v2.FirewallStackV4) || ruleAppliesToStack(v4src, v2.FirewallStackV6) {
		t.Fatal("ipv4 source must stay on v4")
	}
	v6src := allow
	v6src.Stack = v2.FirewallStackV6
	v6src.Source = "2001:db8::1"
	if ruleAppliesToStack(v6src, v2.FirewallStackV4) || !ruleAppliesToStack(v6src, v2.FirewallStackV6) {
		t.Fatal("ipv6 source must stay on v6")
	}
	if holeAppliesToStack(v2.FirewallHole{Protocol: "tcp", Port: "80", Stack: v2.FirewallStackV4}, v2.FirewallStackV6) {
		t.Fatal("v4 hole must not apply to v6")
	}
	if !holeAppliesToStack(v2.FirewallHole{Protocol: "tcp", Port: "80"}, v2.FirewallStackV6) {
		t.Fatal("legacy unsourced hole with no stack must apply to both families")
	}
}

func TestEachStackedRuleKeepsDeclaredStack(t *testing.T) {
	var stacks []string
	eachStackedRule(v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "2083", Stack: v2.FirewallStackV6}, func(next v2.FirewallRule) {
		stacks = append(stacks, next.Stack)
	})
	for _, stack := range stacks {
		if stack == v2.FirewallStackV4 {
			t.Fatal("v6 unsourced must not be copied onto v4")
		}
	}
	stacks = nil
	eachStackedRule(v2.FirewallRule{Action: "allow", Protocol: "tcp", Port: "2083", Stack: v2.FirewallStackV4}, func(next v2.FirewallRule) {
		stacks = append(stacks, next.Stack)
	})
	for _, stack := range stacks {
		if stack == v2.FirewallStackV6 {
			t.Fatal("v4 unsourced must not be copied onto v6")
		}
	}
}
