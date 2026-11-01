//go:build linux

package firewall

import (
	"os"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func liveForeignInetInputHooks() []nftInputHook {
	listed, err := runCmd(cmdTimeout, "nft", "list", "tables")
	if err != nil {
		return nil
	}
	var hooks []nftInputHook
	for _, table := range inetTablesForWatch(parseNftListedTables(listed)) {
		out, err := runCmd(cmdTimeout, "nft", "list", "table", table.Family, table.Table)
		if err != nil {
			continue
		}
		hooks = append(hooks, attachableInetHooks(foreignInetInputHooks(out))...)
	}
	return hooks
}

func nftListChain(hook nftInputHook) (string, error) {
	return runCmd(cmdTimeout, "nft", "-a", "list", "chain", hook.Family, hook.Table, hook.Chain)
}

func nftListPlusChain(hook nftInputHook) (string, error) {
	return runCmd(cmdTimeout, "nft", "-a", "list", "chain", hook.Family, hook.Table, plusIptablesChain)
}

func detachPlusFromForeignInet() {
	for _, hook := range liveForeignInetInputHooks() {
		listed, _ := nftListChain(hook)
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
		if err := ensureNftPlusHead(hook); err != nil {
			return err
		}
	}
	return nil
}

func ensureNftPlusHead(hook nftInputHook) error {
	listed, _ := nftListChain(hook)
	for _, handle := range nftJumpHandles(listed) {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
	}
	for _, handle := range nftPlusCommentHandles(listed) {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
	}
	_, err := runCmd(cmdTimeout, "nft", "insert", "rule", hook.Family, hook.Table, hook.Chain, "jump", plusIptablesChain)
	return err
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

func nftPersistWantsBaseAllows() bool {
	return persistWantsMarkedAllows(v2.FirewallStackV4) || persistWantsMarkedAllows(v2.FirewallStackV6)
}

func inetPlusJumpLive(hooks []nftInputHook) bool {
	if len(hooks) == 0 {
		return true
	}
	wantAllows := nftPersistWantsBaseAllows()
	for _, hook := range hooks {
		hostListed, err := nftListChain(hook)
		if err != nil {
			return false
		}
		plusListed, err := nftListPlusChain(hook)
		if err != nil || !nftAttachLive(hostListed, plusListed, wantAllows) {
			return false
		}
	}
	return true
}
