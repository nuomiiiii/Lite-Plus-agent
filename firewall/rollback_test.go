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
	if !strings.Contains(textLinux, "clearOtherBackend(") {
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
	if !strings.Contains(restoreFn, "mergeHoles(") || !strings.Contains(restoreFn, "eng.apply(") {
		t.Fatal("restore on upgrade must re-apply persisted allow ports through the current backend")
	}
	watch, err := os.ReadFile("watch.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(watch), "engOwned(") || !strings.Contains(string(watch), "restorePersistedLocked()") || !strings.Contains(string(watch), "plusRulesStale(") {
		t.Fatal("watch must restore after a host flush and when plus still sits on a leftover inet table")
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
	if !strings.Contains(bootText, "ownedIptablesRestore(") || !strings.Contains(bootText, "nftTableScript(") {
		t.Fatal("boot persist must keep every plus allow port, not only ssh")
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
}
