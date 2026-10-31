package firewall

import (
	"os"
	"strings"
	"testing"
)

func TestRollbackClearsOwnedRules(t *testing.T) {
	engine, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(engine)
	rollback := text[strings.Index(text, "func rollbackApply("):]
	if end := strings.Index(rollback, "\nfunc "); end > 0 {
		rollback = rollback[:end]
	}
	if !strings.Contains(rollback, "resetOwned()") || !strings.Contains(rollback, "loadPersist()") {
		t.Fatal("first failed apply must clear owned rules when nothing is persisted yet")
	}
	snapFn := text[strings.Index(text, "func Snapshot("):]
	if end := strings.Index(snapFn, "\nfunc "); end > 0 {
		snapFn = snapFn[:end]
	}
	if !strings.Contains(snapFn, "stacksChangedSincePersist()") || !strings.Contains(snapFn, "restorePersistedLocked()") {
		t.Fatal("snapshot must reapply persisted rules when host stacks change")
	}
	applyFn := text[strings.Index(text, "func Apply("):]
	if end := strings.Index(applyFn, "\nfunc "); end > 0 {
		applyFn = applyFn[:end]
	}
	if !strings.Contains(applyFn, "unifyPairedPolicy(&intent)") {
		t.Fatal("apply must persist the ping/deny switch onto both stacks")
	}
	adopt := text[strings.Index(text, "func Adopt("):]
	if end := strings.Index(adopt, "\nfunc "); end > 0 {
		adopt = adopt[:end]
	}
	if !strings.Contains(adopt, "rollbackAdopt(") {
		t.Fatal("failed adopt must restore the pre-adopt dump and Plus persist")
	}
	adoptRollback := text[strings.Index(text, "func rollbackAdopt("):]
	if end := strings.Index(adoptRollback, "\nfunc "); end > 0 {
		adoptRollback = adoptRollback[:end]
	}
	if !strings.Contains(adoptRollback, "restore(prev)") || !strings.Contains(adoptRollback, "restorePersistedLocked()") {
		t.Fatal("adopt rollback must restore host rules then re-apply Plus persist")
	}

	stackRule, err := os.ReadFile("stack_rule.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stackRule), `return strings.TrimSpace(rule.Source) == ""`) {
		t.Fatal("unsourced rules must not be copied onto the other address family")
	}

	windows, err := os.ReadFile("windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(windows), "func (windowsBackend) resetOwned") || !strings.Contains(string(windows), "clearWindowsGroup()") {
		t.Fatal("windows resetOwned must delete the Lite Plus rule group")
	}

	linux, err := os.ReadFile("linux.go")
	if err != nil {
		t.Fatal(err)
	}
	textLinux := string(linux)
	if strings.Contains(textLinux, "func sshPort(") || strings.Contains(textLinux, `strings.Contains(out, "sshd")`) {
		t.Fatal("linux ssh port must not hardcode 22 when ss only sees sshd")
	}
	if !strings.Contains(text, "syncSSHListenPort(") || !strings.Contains(text, "restoreSSHConfigs(") {
		t.Fatal("apply must sync sshd listen port and restore it on failure")
	}
	if !strings.Contains(textLinux, "func (b linuxBackend) resetOwned") || !strings.Contains(textLinux, "clearUfwPlusRules()") {
		t.Fatal("linux resetOwned must drop nft/ufw plus rules")
	}
	if !strings.Contains(textLinux, "capEffectiveHasNetAdmin(") || !strings.Contains(textLinux, `/proc/self/status`) {
		t.Fatal("linux privileged check must accept CAP_NET_ADMIN without root")
	}
	if !strings.Contains(textLinux, `nft", "list", "table"`) {
		t.Fatal("nft apply dump must capture only the plus table")
	}
	detect := textLinux[strings.Index(textLinux, "func detectLinuxBackend("):]
	if end := strings.Index(detect, "\nfunc "); end > 0 {
		detect = detect[:end]
	}
	if strings.Index(detect, "hostOwnsIptablesFilter()") < 0 || strings.Index(detect, "hostOwnsIptablesFilter()") > strings.Index(detect, `lookPath("nft")`) {
		t.Fatal("hosts with an existing iptables-nft INPUT must not use a separate inet liteplus table")
	}
	if !strings.Contains(textLinux, "clearOtherBackend(") || !strings.Contains(textLinux, "deleteInetPlusTable(") {
		t.Fatal("switching to iptables must drop leftover inet liteplus so a later host filter cannot drop plus accepts")
	}
	owner, err := os.ReadFile("iptables_owner.go")
	if err != nil {
		t.Fatal(err)
	}
	ownerText := string(owner)
	if strings.Contains(ownerText, `strings.Contains(blob, "1PANEL")`) || strings.Contains(ownerText, `strings.Contains(blob, "1panel")`) {
		t.Fatal("host INPUT detect must not special-case one panel by name")
	}
	if !strings.Contains(ownerText, "iptablesInputHasForeignRules(") || !strings.Contains(ownerText, "nftInputHasForeignRules(") {
		t.Fatal("host INPUT detect must look at any foreign INPUT rule")
	}
	if !strings.Contains(text, "persistBootLocked(") {
		t.Fatal("apply and restore must persist the owned table for reboot")
	}
	restoreFn := text[strings.Index(text, "func restorePersistedLocked("):]
	if end := strings.Index(restoreFn, "\nfunc "); end > 0 {
		restoreFn = restoreFn[:end]
	}
	if !strings.Contains(restoreFn, "mergeHoles(") || !strings.Contains(restoreFn, "eng.apply(") || !strings.Contains(restoreFn, "state.Intent") {
		t.Fatal("restore on upgrade must re-apply persisted plus rules through the current backend")
	}
	keepLinux, err := os.ReadFile("keep_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(keepLinux), "detectedPanelListenPorts") || strings.Contains(string(keepLinux), "parsePanelListenPorts") {
		t.Fatal("upgrade migrate must use persisted plus rules, not guessed panel listen ports")
	}
	watch, err := os.ReadFile("watch.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(watch), "engOwned(") || !strings.Contains(string(watch), "restorePersistedLocked()") || !strings.Contains(string(watch), "plusRulesStale(") || !strings.Contains(string(watch), "stacksChangedSincePersist(") || !strings.Contains(string(watch), "stackWatchEvery") || !strings.Contains(string(watch), "ensureStacks(") {
		t.Fatal("watch must restore after a host flush, stack change, and leftover inet table")
	}
	stale, err := os.ReadFile("plus_stale.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stale), "plusRulesStaleDecision(") || !strings.Contains(string(stale), "FirewallBackendUFW") {
		t.Fatal("ufw hosts must not treat the native INPUT chain as a missing plus jump")
	}
	ownedLinux, err := os.ReadFile("owned_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ownedLinux), "iptablesPlusLive(") {
		t.Fatal("iptables owned check must require the INPUT jump, not only a leftover chain")
	}
	if !strings.Contains(string(ownedLinux), `"--get-chains", "ipv6", "filter"`) {
		t.Fatal("firewalld owned check must cover the ipv6 plus chain, not only ipv4")
	}
	if !strings.Contains(textLinux, "iptablesPlusLive(") || !strings.Contains(textLinux, `iptablesPlusInputLive("ip6tables")`) {
		t.Fatal("iptables live check must cover ipv6 INPUT jump as well as ipv4")
	}
	if !strings.Contains(textLinux, "ruleAppliesToStack(") {
		t.Fatal("plus allow rules must stay on the stack declared on the rule")
	}
	if !strings.Contains(textLinux, "eachStackedRule(") {
		t.Fatal("nft, ufw, and firewalld must apply through eachStackedRule so a v6 unsourced allow cannot land on v4")
	}
	ufwArgsFn := textLinux[strings.Index(textLinux, "func ufwArgs("):]
	if end := strings.Index(ufwArgsFn, "\nfunc "); end > 0 {
		ufwArgsFn = ufwArgsFn[:end]
	}
	if !strings.Contains(ufwArgsFn, `"0.0.0.0/0"`) || !strings.Contains(ufwArgsFn, `"::/0"`) {
		t.Fatal("ufw unsourced allows must pin 0.0.0.0/0 or ::/0 to the declared stack")
	}
	nftTok := textLinux[strings.Index(textLinux, "func nftRuleTokens("):]
	if end := strings.Index(nftTok, "\nfunc "); end > 0 {
		nftTok = nftTok[:end]
	}
	if !strings.Contains(nftTok, `"nfproto", "ipv4"`) || !strings.Contains(nftTok, `"nfproto", "ipv6"`) {
		t.Fatal("nft inet rules must pin meta nfproto to the declared stack")
	}
	if !strings.Contains(textLinux, "attachPlusToForeignInet(") || !strings.Contains(textLinux, "liveForeignInetInputHooks()") {
		t.Fatal("nft inet filter hosts must join the existing input chain instead of a parallel liteplus table")
	}
	if !strings.Contains(textLinux, "detachPlusFromForeignInet(") {
		t.Fatal("idle nft apply must drop plus accepts from a leftover inet filter")
	}
	attachFn := textLinux[strings.Index(textLinux, "func nftAttachScript("):]
	if end := strings.Index(attachFn, "\nfunc "); end > 0 {
		attachFn = attachFn[:end]
	}
	if !strings.Contains(attachFn, "flush chain ") {
		t.Fatal("nft attach must flush LITE_PLUS before rewriting; nft -f appends and an old default-deny drop would shadow new allows")
	}
	tableFn := textLinux[strings.Index(textLinux, "func nftTableScript("):]
	if end := strings.Index(tableFn, "\nfunc "); end > 0 {
		tableFn = tableFn[:end]
	}
	flushOwn := strings.Index(tableFn, `flush chain inet " + nftTable + " input`)
	if flushOwn < 0 {
		flushOwn = strings.Index(tableFn, "flush chain inet")
	}
	bodyOwn := strings.Index(tableFn, "nftPlusChainBody(")
	if flushOwn < 0 || bodyOwn < 0 || flushOwn > bodyOwn {
		t.Fatal("owned nft table must flush input before rewriting; nft -f appends")
	}
	iptablesFn := textLinux[strings.Index(textLinux, "func applyIptablesFamily("):]
	if end := strings.Index(iptablesFn, "\nfunc "); end > 0 {
		iptablesFn = iptablesFn[:end]
	}
	flushIP := strings.Index(iptablesFn, `"-F", chain`)
	addIP := strings.Index(iptablesFn, `"-A", chain`)
	if flushIP < 0 || addIP < 0 || flushIP > addIP {
		t.Fatal("iptables apply must flush LITE_PLUS before adding rules")
	}
	argsFn := textLinux[strings.Index(textLinux, "func iptablesArgs("):]
	if end := strings.Index(argsFn, "\nfunc "); end > 0 {
		argsFn = argsFn[:end]
	}
	if !strings.Contains(argsFn, `"--comment"`) || !strings.Contains(argsFn, "plusRuleMark(") {
		t.Fatal("iptables apply must mark plus rules with lite-plus comments")
	}
	attachLinux, err := os.ReadFile("nft_attach_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(attachLinux), "ensureNftPlusHead(") || !strings.Contains(string(attachLinux), "nftBaseAllowTokens(") {
		t.Fatal("inet attach must insert plus accepts into the foreign input chain")
	}
	if !strings.Contains(string(attachLinux), "nftQuotedTokens(") {
		t.Fatal("inet argv insert must quote lite-plus comments so nft does not treat the colon as syntax")
	}
	if strings.Contains(string(attachLinux), `"nft", "list", "chain"`) {
		t.Fatal("listing inet input must use nft -a; nftables 1.1.3 omits handles without -a so allow rules look missing")
	}
	if !strings.Contains(string(attachLinux), `nft", "-a", "list", "chain"`) {
		t.Fatal("live and stale checks must list inet input with handles")
	}
	if !strings.Contains(textLinux, `"insert rule "`) {
		t.Fatal("attach script must insert plus allows into the host input chain so policy drop cannot ignore jumped accepts")
	}
	ufwFn := textLinux[strings.Index(textLinux, "func applyUFW("):]
	if end := strings.Index(ufwFn, "\nfunc "); end > 0 {
		ufwFn = ufwFn[:end]
	}
	clearUfw := strings.Index(ufwFn, "clearUfwPlusRules()")
	addUfw := strings.Index(ufwFn, `runCmd(cmdTimeout, "ufw"`)
	if clearUfw < 0 || addUfw < 0 || clearUfw > addUfw {
		t.Fatal("ufw apply must delete plus-owned rules before adding replacements")
	}
	applyFn = textLinux[strings.Index(textLinux, "func (b linuxBackend) apply("):]
	if end := strings.Index(applyFn, "\nfunc "); end > 0 {
		applyFn = applyFn[:end]
	}
	if !strings.Contains(applyFn, "applyUFW(") || strings.Index(applyFn, "applyUFW(") > strings.LastIndex(applyFn, "attachPlusToForeignInet(") {
		t.Fatal("ufw apply must also attach plus allows into a leftover inet filter")
	}
	if !strings.Contains(applyFn, "applyFirewalld(") || strings.Index(applyFn, "applyFirewalld(") > strings.LastIndex(applyFn, "attachPlusToForeignInet(") {
		t.Fatal("firewalld apply must also attach plus allows into a leftover inet filter")
	}
	fwFn := textLinux[strings.Index(textLinux, "func applyFirewalld("):]
	if end := strings.Index(fwFn, "\nfunc "); end > 0 {
		fwFn = fwFn[:end]
	}
	removeFD := strings.Index(fwFn, `removeFirewalldChain("ipv4")`)
	addFD := strings.Index(fwFn, `"--add-chain"`)
	if removeFD < 0 || addFD < 0 || removeFD > addFD {
		t.Fatal("firewalld apply must remove the plus chain before adding rules")
	}
	bootLinux, err := os.ReadFile("boot_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	bootText := string(bootLinux)
	bootShared, err := os.ReadFile("boot.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bootShared), "lite-plus-firewall.service") || !strings.Contains(bootText, "fail2ban.service") || !strings.Contains(bootText, "bt.service") {
		t.Fatal("boot unit must load plus ports after common host firewalls, not only one panel")
	}
	if !strings.Contains(bootText, "ownedIptablesRestore(") || !strings.Contains(bootText, "nftTableScript(") || !strings.Contains(bootText, "applyBootScriptLocked(") {
		t.Fatal("boot persist must apply the same live rules as reboot, not wait for a machine restart")
	}
	installFn := bootText[strings.Index(bootText, "func installBootUnit("):]
	if end := strings.Index(installFn, "\nfunc "); end > 0 {
		installFn = installFn[:end]
	}
	if !strings.Contains(installFn, "writeFileIfChanged(") {
		t.Fatal("boot unit install must skip daemon-reload when the unit file is unchanged")
	}
	reloadAt := strings.Index(installFn, `"systemctl", "daemon-reload"`)
	changedAt := strings.Index(installFn, "unitChanged || dropinChanged")
	if reloadAt < 0 || changedAt < 0 || changedAt > reloadAt {
		t.Fatal("boot unit install must daemon-reload only after a unit or drop-in change")
	}
	if !strings.Contains(bootText, "lite-plus:") || !strings.Contains(bootText, `nft delete rule "$fam" "$tab" "$ch" handle`) {
		t.Fatal("boot must drop previous plus accepts from inet input before reloading")
	}
	jumpAt := strings.Index(bootText, `nft insert rule "$fam" "$tab" "$ch" jump "$CHAIN"`)
	loadAt := strings.Index(bootText, `[ -f "$NFT_FILE" ] && nft -f "$NFT_FILE"`)
	if jumpAt < 0 || loadAt < 0 || jumpAt > loadAt {
		t.Fatal("boot must insert the plus jump before loading marked allows")
	}
	if !strings.Contains(textLinux, "NFT_HOST_V1") || !strings.Contains(textLinux, `nft", "list", "ruleset"`) {
		t.Fatal("nft adopt dump must capture the full host ruleset")
	}
	dumpFn := textLinux[strings.Index(textLinux, "func (b linuxBackend) dump()"):]
	if end := strings.Index(dumpFn, "\nfunc "); end > 0 {
		dumpFn = dumpFn[:end]
	}
	if strings.Contains(dumpFn, "flush ruleset") || strings.Contains(dumpFn, "list\", \"ruleset\"") {
		t.Fatal("nft apply rollback must not dump or flush the whole ruleset")
	}
	if !strings.Contains(textLinux, "UFW_FILES_V1") || !strings.Contains(textLinux, "ufwUserRules") {
		t.Fatal("ufw dump must snapshot user.rules so adopt can restore host rules")
	}
	if strings.Contains(textLinux, `"ufw", "default", "deny", "incoming"`) {
		t.Fatal("ufw default deny must not change the global incoming policy")
	}
	if !strings.Contains(textLinux, "func ufwDropAll") || !strings.Contains(textLinux, `"deny", "in", "from"`) {
		t.Fatal("ufw default deny must use a plus-owned inbound catch-all")
	}
	if !strings.Contains(textLinux, "deleteFirewalldPermanent") || !strings.Contains(textLinux, "addFirewalldPermanent") {
		t.Fatal("firewalld adopt must undo permanent deletes if they fail")
	}
	if !strings.Contains(textLinux, "func firewalldDirect(") || !strings.Contains(textLinux, "firewalldDirect(true,") {
		t.Fatal("firewalld apply must also write permanent direct rules so reboot keeps all plus ports")
	}
	if !strings.Contains(textLinux, "firewalldDump()") || !strings.Contains(textLinux, `--permanent", "--list-services"`) {
		t.Fatal("firewalld adopt dump must snapshot permanent services and ports")
	}
	if !strings.Contains(textLinux, "firewalldRestore(") || !strings.Contains(textLinux, "--add-service=") {
		t.Fatal("firewalld adopt restore must put permanent host rules back after reload")
	}
	hostDump, err := os.ReadFile("firewalld_dump.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hostDump), "FIREWALLD_HOST_V1") {
		t.Fatal("firewalld adopt dump must be marked so apply rollback does not rewrite host rules")
	}

	winText := string(windows)
	if !strings.Contains(winText, `"export"`) || !strings.Contains(winText, `"import"`) {
		t.Fatal("windows dump/restore must use netsh export/import so adopt can restore host rules")
	}
	winDump := winText[strings.Index(winText, "func (windowsBackend) dump()"):]
	if end := strings.Index(winDump, "\nfunc "); end > 0 {
		winDump = winDump[:end]
	}
	if strings.Contains(winDump, `"export"`) {
		t.Fatal("windows apply dump must not export the whole firewall on every apply")
	}
	winApply := winText[strings.Index(winText, "func (windowsBackend) apply("):]
	if end := strings.Index(winApply, "\nfunc "); end > 0 {
		winApply = winApply[:end]
	}
	clearWin := strings.Index(winApply, "clearWindowsGroup()")
	addWin := strings.Index(winApply, "addWindowsRule(")
	if clearWin < 0 || addWin < 0 || clearWin > addWin {
		t.Fatal("windows apply must clear the Lite Plus group before adding replacements")
	}
	addFn := winText[strings.Index(winText, "func addWindowsRule("):]
	if end := strings.Index(addFn, "\nfunc "); end > 0 {
		addFn = addFn[:end]
	}
	if !strings.Contains(addFn, `"localip=::/0"`) || !strings.Contains(addFn, `"localip=0.0.0.0/0"`) {
		t.Fatal("windows unsourced allows must pin localip so a v4 rule cannot match ipv6")
	}
}
