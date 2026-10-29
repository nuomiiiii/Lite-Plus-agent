//go:build linux

package firewall

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func persistBootLocked(eng backend, intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	if intentIdle(intent) {
		return clearBootPersist()
	}
	if err := os.MkdirAll(filepath.Dir(statePath()), 0o755); err != nil {
		return err
	}
	hooks := liveForeignInetInputHooks()
	wroteIpt := false
	switch eng.name() {
	case v2.FirewallBackendIptables:
		if err := writeOwnedIptablesBoot(); err != nil {
			return err
		}
		wroteIpt = true
	case v2.FirewallBackendNFT:
	default:
		return clearBootPersist()
	}
	if len(hooks) > 0 {
		body := strings.TrimSpace(nftAttachScript(hooks, intent, holes))
		if err := os.WriteFile(bootPath(bootNftFile), []byte(body+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(bootPath(bootNftHooksFile), []byte(encodeNftHooks(hooks)), 0o600); err != nil {
			return err
		}
		if st, err := os.Stat("/etc/nftables.d"); err == nil && st.IsDir() {
			_ = os.WriteFile(nftablesDropin, []byte(body+"\n"), 0o644)
		}
	} else if eng.name() == v2.FirewallBackendNFT {
		raw, err := eng.dump()
		body := strings.TrimSpace(string(raw))
		if err != nil || body == "" {
			body = strings.TrimSpace(nftTableScript(intent, holes))
		}
		if body == "" {
			return clearBootPersist()
		}
		if err := os.WriteFile(bootPath(bootNftFile), []byte(body+"\n"), 0o600); err != nil {
			return err
		}
		_ = os.Remove(bootPath(bootNftHooksFile))
		if st, err := os.Stat("/etc/nftables.d"); err == nil && st.IsDir() {
			_ = os.WriteFile(nftablesDropin, []byte(body+"\n"), 0o644)
		}
	} else {
		_ = os.Remove(bootPath(bootNftFile))
		_ = os.Remove(bootPath(bootNftHooksFile))
		_ = os.Remove(nftablesDropin)
	}
	if !wroteIpt {
		_ = os.Remove(bootPath(bootIptablesFile))
		_ = os.Remove(bootPath(bootIP6tablesFile))
	}
	script := firewallBootScript()
	if err := os.WriteFile(bootPath(bootScriptFile), []byte(script), 0o700); err != nil {
		return err
	}
	if err := installBootUnit(); err != nil {
		return err
	}
	return applyBootScriptLocked()
}

func applyBootScriptLocked() error {
	path := bootPath(bootScriptFile)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	_, err := runCmd(dumpTimeout, path)
	return err
}

func writeOwnedIptablesBoot() error {
	v4, _ := runCmd(cmdTimeout, "iptables-save", "-t", "filter")
	if err := os.WriteFile(bootPath(bootIptablesFile), []byte(ownedIptablesRestore(v4, iptablesChain)), 0o600); err != nil {
		return err
	}
	if lookPath("ip6tables-save") {
		v6, _ := runCmd(cmdTimeout, "ip6tables-save", "-t", "filter")
		if err := os.WriteFile(bootPath(bootIP6tablesFile), []byte(ownedIptablesRestore(v6, iptablesChain)), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func ownedIptablesRestore(raw, chain string) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + chain + " - [0:0]\n")
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "-A "+chain+" ") && trim != "-A "+chain {
			continue
		}
		b.WriteString(trim + "\n")
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func firewallBootScript() string {
	nft := bootPath(bootNftFile)
	v4 := bootPath(bootIptablesFile)
	v6 := bootPath(bootIP6tablesFile)
	hooks := bootPath(bootNftHooksFile)
	return `#!/bin/sh
NFT_FILE="` + nft + `"
HOOKS_FILE="` + hooks + `"
V4_FILE="` + v4 + `"
V6_FILE="` + v6 + `"
CHAIN="` + iptablesChain + `"
TABLE="` + nftTable + `"
load_nft() {
	nft delete table inet "$TABLE" >/dev/null 2>&1 || true
	if [ -f "$HOOKS_FILE" ]; then
		while read -r fam tab ch; do
			[ -z "$fam" ] && continue
			nft add chain "$fam" "$tab" "$CHAIN" >/dev/null 2>&1 || true
			nft flush chain "$fam" "$tab" "$CHAIN" >/dev/null 2>&1 || true
		done < "$HOOKS_FILE"
		while read -r fam tab ch; do
			[ -z "$fam" ] && continue
			nft -a list chain "$fam" "$tab" "$ch" 2>/dev/null | awk -v chain="$CHAIN" '
				/lite-plus:/ || $0 ~ "jump "chain { if (match($0, /# handle [0-9]+/)) print substr($0, RSTART+9) }
			' | sort -nr | while read -r handle; do
				[ -z "$handle" ] && continue
				nft delete rule "$fam" "$tab" "$ch" handle "$handle" >/dev/null 2>&1 || true
			done
			nft insert rule "$fam" "$tab" "$ch" jump "$CHAIN" >/dev/null 2>&1 || true
		done < "$HOOKS_FILE"
		[ -f "$NFT_FILE" ] && nft -f "$NFT_FILE"
		return 0
	fi
	if [ -f "$V4_FILE" ] || [ -f "$V6_FILE" ]; then
		return 0
	fi
	[ -f "$NFT_FILE" ] || return 0
	nft -f "$NFT_FILE"
}
load_ipt() {
	bin="$1"
	file="$2"
	restore="$3"
	[ -f "$file" ] || return 0
	"$bin" -D INPUT -j "$CHAIN" >/dev/null 2>&1 || true
	"$bin" -F "$CHAIN" >/dev/null 2>&1 || true
	"$bin" -X "$CHAIN" >/dev/null 2>&1 || true
	"$restore" --noflush < "$file" || return 1
	"$bin" -D INPUT -j "$CHAIN" >/dev/null 2>&1 || true
	"$bin" -I INPUT 1 -j "$CHAIN"
}
load_nft || exit 1
load_ipt iptables "$V4_FILE" iptables-restore || exit 1
load_ipt ip6tables "$V6_FILE" ip6tables-restore || exit 1
exit 0
`
}

func firewallBootUnit() string {
	return `[Unit]
Description=Lite Plus host firewall
After=nftables.service iptables.service ip6tables.service netfilter-persistent.service iptables-persistent.service ufw.service firewalld.service fail2ban.service csf.service bt.service btpanel.service 1panel.service 1Panel.service network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=` + bootPath(bootScriptFile) + `

[Install]
WantedBy=multi-user.target
`
}

func agentFirewallDropin() string {
	return "[Unit]\nAfter=" + bootUnitName + "\n"
}

func installBootUnit() error {
	if skipBootUnit() {
		return nil
	}
	if err := os.WriteFile(bootUnitPath, []byte(firewallBootUnit()), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(agentUnitDir, 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(agentUnitDir, bootAgentDropin), []byte(agentFirewallDropin()), 0o644)
	}
	_, _ = runCmd(cmdTimeout, "systemctl", "daemon-reload")
	if _, err := runCmd(cmdTimeout, "systemctl", "enable", bootUnitName); err != nil {
		log.Printf("firewall boot unit enable: %v", err)
		return err
	}
	return nil
}

func clearBootPersist() error {
	_ = os.Remove(bootPath(bootNftFile))
	_ = os.Remove(bootPath(bootNftHooksFile))
	_ = os.Remove(bootPath(bootIptablesFile))
	_ = os.Remove(bootPath(bootIP6tablesFile))
	_ = os.Remove(bootPath(bootScriptFile))
	_ = os.Remove(nftablesDropin)
	if skipBootUnit() {
		return nil
	}
	_, _ = runCmd(cmdTimeout, "systemctl", "disable", bootUnitName)
	_ = os.Remove(bootUnitPath)
	_ = os.Remove(filepath.Join(agentUnitDir, bootAgentDropin))
	_, _ = runCmd(cmdTimeout, "systemctl", "daemon-reload")
	return nil
}

func skipBootUnit() bool {
	if _, err := os.Stat("/.lite-plus-agent-container"); err == nil {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return true
	}
	return !lookPath("systemctl")
}
