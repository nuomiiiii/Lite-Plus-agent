//go:build linux

package firewall

import (
	"os"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func liveForeignInetInputHooks() []nftInputHook {
	out, err := runCmd(dumpTimeout, "nft", "list", "ruleset")
	if err != nil {
		return nil
	}
	return attachableInetHooks(foreignInetInputHooks(out))
}

func detachPlusFromForeignInet() {
	for _, hook := range liveForeignInetInputHooks() {
		listed, _ := runCmd(cmdTimeout, "nft", "-a", "list", "chain", hook.Family, hook.Table, hook.Chain)
		for _, handle := range nftJumpHandles(listed) {
			_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
		}
		for _, handle := range nftPlusCommentHandles(listed) {
			_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
		}
	}
}

func attachPlusToForeignInet(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	hooks := liveForeignInetInputHooks()
	if len(hooks) == 0 {
		return nil
	}
	deleteInetPlusTable()
	if intentIdle(intent) {
		detachPlusFromForeignInet()
		return nil
	}
	tmp, err := os.CreateTemp("", "liteplus-nft-attach-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(nftAttachScript(hooks, intent, holes)); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if _, err := runCmd(cmdTimeout, "nft", "-f", tmp.Name()); err != nil {
		return err
	}
	for _, hook := range hooks {
		if err := ensureNftPlusHead(hook, intent, holes); err != nil {
			return err
		}
	}
	return nil
}

func ensureNftPlusHead(hook nftInputHook, intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	listed, _ := runCmd(cmdTimeout, "nft", "-a", "list", "chain", hook.Family, hook.Table, hook.Chain)
	for _, handle := range nftJumpHandles(listed) {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
	}
	for _, handle := range nftPlusCommentHandles(listed) {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
	}
	if _, err := runCmd(cmdTimeout, "nft", "insert", "rule", hook.Family, hook.Table, hook.Chain, "jump", plusIptablesChain); err != nil {
		return err
	}
	allows := nftBaseAllowTokens(intent, holes)
	for i := len(allows) - 1; i >= 0; i-- {
		args := append([]string{"insert", "rule", hook.Family, hook.Table, hook.Chain}, allows[i]...)
		if _, err := runCmd(cmdTimeout, "nft", args...); err != nil {
			return err
		}
	}
	return nil
}

func nftBaseAllowTokens(intent v2.FirewallIntent, holes []v2.FirewallHole) [][]string {
	var out [][]string
	add := func(rule v2.FirewallRule) {
		if rule.Action != v2.FirewallActionAllow {
			return
		}
		eachStackedRule(rule, func(next v2.FirewallRule) {
			out = append(out, nftRuleTokens(next))
		})
	}
	for _, rule := range enabledRules(intent) {
		add(rule)
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		for _, hole := range liveHoles(intent, holes) {
			add(v2.FirewallRule{
				Action:   v2.FirewallActionAllow,
				Protocol: hole.Protocol,
				Port:     hole.Port,
				Stack:    hole.Stack,
				Comment:  hole.Comment,
			})
		}
		eachKeepRule(intent, add)
	}
	return out
}

func nftPlusLive() bool {
	hooks := liveForeignInetInputHooks()
	if len(hooks) == 0 {
		return leftoverInetPlusTable()
	}
	if leftoverInetPlusTable() {
		return false
	}
	wantAllows := nftPersistWantsBaseAllows()
	for _, hook := range hooks {
		listed, err := runCmd(cmdTimeout, "nft", "list", "chain", hook.Family, hook.Table, hook.Chain)
		if err != nil || !nftInetHeadLive(listed, wantAllows) {
			return false
		}
	}
	return true
}

func nftPersistWantsBaseAllows() bool {
	state := loadPersist()
	if state == nil {
		return false
	}
	return len(nftBaseAllowTokens(state.Intent, state.ListenHoles)) > 0
}

func plusRulesStaleLinux() bool {
	kind := detectLinuxBackend()
	leftover := leftoverInetPlusTable()
	hooks := liveForeignInetInputHooks()
	inetJumpLive := true
	wantAllows := nftPersistWantsBaseAllows()
	if len(hooks) > 0 {
		for _, hook := range hooks {
			listed, err := runCmd(cmdTimeout, "nft", "list", "chain", hook.Family, hook.Table, hook.Chain)
			if err != nil || !nftInetHeadLive(listed, wantAllows) {
				inetJumpLive = false
				break
			}
		}
	}
	if kind == v2.FirewallBackendUFW {
		return plusRulesStaleDecision(kind, leftover, false, false, len(hooks) > 0, inetJumpLive)
	}
	return plusRulesStaleDecision(kind, leftover, hostOwnsIptablesFilter(), iptablesPlusLive(), len(hooks) > 0, inetJumpLive)
}
