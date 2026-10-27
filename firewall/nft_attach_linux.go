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
	return foreignInetInputHooks(out)
}

func attachPlusToForeignInet(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	hooks := liveForeignInetInputHooks()
	if len(hooks) == 0 {
		return nil
	}
	deleteInetPlusTable()
	if intentIdle(intent) {
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
		if err := ensureNftJumpHead(hook); err != nil {
			return err
		}
	}
	return nil
}

func ensureNftJumpHead(hook nftInputHook) error {
	listed, _ := runCmd(cmdTimeout, "nft", "-a", "list", "chain", hook.Family, hook.Table, hook.Chain)
	for _, handle := range nftJumpHandles(listed) {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "rule", hook.Family, hook.Table, hook.Chain, "handle", handle)
	}
	_, err := runCmd(cmdTimeout, "nft", "insert", "rule", hook.Family, hook.Table, hook.Chain, "jump", plusIptablesChain)
	return err
}

func nftPlusLive() bool {
	hooks := liveForeignInetInputHooks()
	if len(hooks) == 0 {
		return leftoverInetPlusTable()
	}
	if leftoverInetPlusTable() {
		return false
	}
	for _, hook := range hooks {
		listed, err := runCmd(cmdTimeout, "nft", "list", "chain", hook.Family, hook.Table, hook.Chain)
		if err != nil || !nftChainJumpsToPlus(listed) {
			return false
		}
	}
	return true
}

func plusRulesStaleLinux() bool {
	kind := detectLinuxBackend()
	leftover := leftoverInetPlusTable()
	if kind == v2.FirewallBackendUFW {
		return plusRulesStaleDecision(kind, leftover, false, false, false, true)
	}
	hooks := liveForeignInetInputHooks()
	inetJumpLive := true
	if len(hooks) > 0 {
		for _, hook := range hooks {
			listed, err := runCmd(cmdTimeout, "nft", "list", "chain", hook.Family, hook.Table, hook.Chain)
			if err != nil || !nftChainJumpsToPlus(listed) {
				inetJumpLive = false
				break
			}
		}
	}
	return plusRulesStaleDecision(kind, leftover, hostOwnsIptablesFilter(), iptablesPlusLive(), len(hooks) > 0, inetJumpLive)
}
