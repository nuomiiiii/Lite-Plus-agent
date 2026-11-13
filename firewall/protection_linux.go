//go:build linux

package firewall

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nuomiiiii/lite-agent/protection"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func probeProtectionCapabilityLocked() v2.ProtectionCapability {
	state := loadProtection()
	cap := v2.ProtectionCapability{
		Platform:       runtime.GOOS,
		Linux:          true,
		Privileged:     privileged(),
		StaticBackend:  currentBackend().name(),
		NftPresent:     lookPath("nft"),
		RuntimeEnabled: state.RuntimeEnabled,
		ScopeNote:      "首版覆盖主机 INPUT。Docker / 桥接 DNAT 经 FORWARD 的流量不在范围内。封禁精确源 IP，切断该源全部入站（含已建立连接）；本机主动连出去的回包不封。",
	}
	if cap.NftPresent {
		if out, err := runCmd(cmdTimeout, "nft", "--version"); err == nil {
			cap.NftVersion = strings.TrimSpace(out)
		}
		warmNft()
	}
	v4, v6 := stackPresent()
	cap.Features.IPv4 = v4
	cap.Features.IPv6 = v6
	if !cap.Privileged {
		cap.Missing = append(cap.Missing, "需要 root 或 CAP_NET_ADMIN")
		cap.ManualHints = append(cap.ManualHints, "请用 root 运行 Agent，或授予 CAP_NET_ADMIN。")
	}
	var setsErr error
	if !cap.NftPresent {
		cap.Missing = append(cap.Missing, "缺少 nft 命令")
		if mgr := firstPackageManager(); mgr != "" {
			cap.PackageManager = mgr
			cap.CanInstall = cap.Privileged
			cap.PlannedSteps = append(cap.PlannedSteps, "使用发行版仓库安装 nftables")
		} else {
			cap.ManualHints = append(cap.ManualHints, "未识别包管理器，请手动安装 nftables 后再检查。")
		}
	} else {
		setsErr = nftSyntaxErr(protectionBaseScript(false, false, false, nil))
		cap.Features.SetsTimeout = setsErr == nil
		cap.Features.Meter = nftFeatureSupported(protectionProbeScript("meter"))
		cap.Features.ConnLimit = nftFeatureSupported(protectionProbeScript("connlimit"))
		cap.Features.Nflog = nftSyntaxOK(protectionProbeScript("nflog"))
		if !cap.Features.SetsTimeout && !nftCommandTimedOut(setsErr) {
			cap.Missing = append(cap.Missing, "内核或 nft 不支持带 timeout 的集合")
			if mgr := firstPackageManager(); mgr != "" && cap.Privileged {
				cap.PackageManager = mgr
				cap.CanUpdate = true
				cap.PlannedSteps = append(cap.PlannedSteps, "尝试更新发行版 nftables 软件包后复检")
				cap.ManualHints = append(cap.ManualHints, "若更新后仍缺 timeout 集合，属于内核能力不足，不能把包装成功当成防护成功。")
			}
		}
	}
	tableLive := cap.NftPresent && protectionTableLive()
	if cap.NftPresent && cap.Privileged && (cap.Features.SetsTimeout || tableLive || nftCommandTimedOut(setsErr)) {
		cap.CanEnableRuntime = true
		if !protectionReloadSafe() {
			cap.Conflicts = append(cap.Conflicts, "检测到 nftables 规则可能在 reload 时 flush ruleset，将依赖 Agent 监视恢复自有表")
			cap.ManualHints = append(cap.ManualHints, "请确认 /etc/nftables.conf 在 flush 后仍 include /etc/nftables.d，或不要停用 Agent 监视。")
		}
	}
	cap.RuntimeReady = cap.CanEnableRuntime && (state.RuntimeEnabled || tableLive)
	if cap.CanEnableRuntime && !state.RuntimeEnabled {
		cap.PlannedSteps = append(cap.PlannedSteps, "提交独立表 inet "+protectionNftTable+"（不 flush 全机规则）")
	}
	if cap.StaticBackend != "" && cap.StaticBackend != v2.FirewallBackendNFT && cap.StaticBackend != v2.FirewallBackendNone {
		cap.ManualHints = append(cap.ManualHints, "静态后端仍是 "+cap.StaticBackend+"。启用防护不会改全局静态后端，也不会卸载原管理器。")
	}
	cap.SshdLogPath = protection.DetectSSHDLogPath()
	return cap
}

func protectionPrecheckLocked() v2.ProtectionResultParams {
	cap := probeProtectionCapabilityLocked()
	result := v2.ProtectionResultParams{
		Kind:       v2.ProtectionKindPrecheck,
		Capability: &cap,
		Phase:      v2.ProtectionUpgradePhasePrecheck,
	}
	if !cap.Linux {
		result.Status = v2.ProtectionStatusUnsupported
		result.Error = "此防护功能需要 Linux nftables"
		return result
	}
	if !cap.Privileged {
		result.Status = v2.ProtectionStatusUnsupported
		result.Error = strings.Join(cap.Missing, "；")
		return result
	}
	if cap.RuntimeReady && cap.RuntimeEnabled {
		result.Status = v2.ProtectionStatusOK
		result.RuntimeEnabled = true
		result.Phase = v2.ProtectionUpgradePhaseReady
		return result
	}
	if cap.CanEnableRuntime || cap.CanInstall || cap.CanUpdate {
		result.Status = v2.ProtectionStatusOK
		return result
	}
	result.Status = v2.ProtectionStatusUnsupported
	if result.Error == "" && len(cap.Missing) > 0 {
		result.Error = strings.Join(cap.Missing, "；")
	}
	return result
}

func protectionUpgradePrepareLocked(opID string) (v2.ProtectionResultParams, bool, bool, bool) {
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindUpgrade, OpID: opID, Phase: v2.ProtectionUpgradePhasePrecheck}
	pre := protectionPrecheckLocked()
	cap := probeProtectionCapabilityLocked()
	result.Capability = &cap
	if pre.Status == v2.ProtectionStatusUnsupported && !cap.CanInstall && !cap.CanUpdate && !cap.CanEnableRuntime {
		result.Status = pre.Status
		result.Error = pre.Error
		result.Phase = v2.ProtectionUpgradePhaseFailed
		return result, false, false, false
	}
	wasActive, wasEnabled := nftablesServiceState()
	needPkg := !lookPath("nft") || (cap.CanUpdate && !cap.Features.SetsTimeout)
	return result, needPkg, wasActive, wasEnabled
}

func protectionUpgradeEnableLocked(result v2.ProtectionResultParams) v2.ProtectionResultParams {
	cap := probeProtectionCapabilityLocked()
	result.Capability = &cap
	if !cap.CanEnableRuntime {
		result.Status = v2.ProtectionStatusError
		result.Error = "nftables 已处理，但所需能力仍不满足，未启用防护运行时"
		if len(cap.Missing) > 0 {
			result.Error += "：" + strings.Join(cap.Missing, "；")
		}
		result.Phase = v2.ProtectionUpgradePhaseFailed
		return result
	}
	result.Phase = v2.ProtectionUpgradePhaseEnable
	state := loadProtection()
	state.RuntimeEnabled = true
	state.Config.RuntimeEnabled = true
	if err := saveProtection(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		result.Phase = v2.ProtectionUpgradePhaseFailed
		return result
	}
	if err := enableProtectionRuntimeLocked(state, false); err != nil {
		state.RuntimeEnabled = false
		_ = saveProtection(state)
		_ = removeProtectionTable()
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		result.Phase = v2.ProtectionUpgradePhaseFailed
		result.Restored = !protectionTableLive()
		return result
	}
	result.Phase = v2.ProtectionUpgradePhaseVerify
	if !protectionTableLive() {
		result.Status = v2.ProtectionStatusError
		result.Error = "防护表提交后未出现，未标记就绪"
		result.Phase = v2.ProtectionUpgradePhaseFailed
		return result
	}
	cap = probeProtectionCapabilityLocked()
	result.Capability = &cap
	result.Status = v2.ProtectionStatusOK
	result.Phase = v2.ProtectionUpgradePhaseReady
	result.RuntimeEnabled = true
	result.RuntimeApplied = true
	return result
}

func installOrUpdateNftables(wasActive, wasEnabled bool) error {
	if !privileged() {
		return fmt.Errorf("Agent 需要 root 或 CAP_NET_ADMIN")
	}
	hadNft := lookPath("nft")
	steps := nftablesInstallPlan(lookPath)
	if len(steps) == 0 {
		return fmt.Errorf("未找到 apt / dnf / yum / zypper / apk / opkg / pacman，请先手动安装 nftables")
	}
	if steps[0].Name == "apt-get" {
		restore := suppressServiceStart()
		defer restore()
	}
	for _, step := range steps {
		if _, err := runCmdEnv(nftInstallTimeout, step.Env, step.Name, step.Args...); err != nil {
			return fmt.Errorf("安装或更新 nftables 失败: %v", err)
		}
	}
	if !hadNft && !wasActive && !wasEnabled {
		disableNftablesService()
	}
	if !lookPath("nft") {
		return fmt.Errorf("已尝试安装 nftables，但仍找不到 nft 命令")
	}
	return nil
}

func nftablesServiceState() (active, enabled bool) {
	if lookPath("systemctl") {
		out, err := runCmd(cmdTimeout, "systemctl", "is-active", "nftables")
		active = err == nil && strings.TrimSpace(out) == "active"
		out, err = runCmd(cmdTimeout, "systemctl", "is-enabled", "nftables")
		enabled = err == nil && strings.Contains(strings.TrimSpace(out), "enabled")
		return active, enabled
	}
	if lookPath("rc-service") {
		out, err := runCmd(cmdTimeout, "rc-service", "nftables", "status")
		text := strings.ToLower(out)
		if err != nil {
			text += " " + strings.ToLower(err.Error())
		}
		active = strings.Contains(text, "started") || strings.Contains(text, "running")
		if lookPath("rc-update") {
			shown, _ := runCmd(cmdTimeout, "rc-update", "show")
			enabled = strings.Contains(shown, "nftables")
		}
		return active, enabled
	}
	return true, true
}

func firstPackageManager() string {
	for _, name := range []string{"apt-get", "dnf", "yum", "zypper", "apk", "opkg", "pacman"} {
		if lookPath(name) {
			return name
		}
	}
	return ""
}

func enableProtectionRuntimeLocked(state *persistedProtection, restore bool) error {
	if !lookPath("nft") || !privileged() {
		return fmt.Errorf("nft 运行时不可用")
	}
	script := protectionApplyScript(state)
	if err := nftSyntaxErr(script); err != nil {
		return fmt.Errorf("nft -c 检查失败: %v", err)
	}
	if _, err := runCmdStdin(cmdTimeout, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("提交防护表失败: %v", err)
	}
	_ = persistProtectionBootLocked()
	_ = restore
	return nil
}

func protectionApplyScript(state *persistedProtection) string {
	var b strings.Builder
	// Ensure the table exists so delete cannot fail the whole nft -f when
	// list table timed out. Delete+add stay in one script so a failed add
	// does not leave a gap. Boot files use this same script; do not delete
	// the table in the shell first.
	b.WriteString(protectionEnsureInputChain())
	b.WriteString("delete table inet " + protectionNftTable + "\n")
	b.WriteString(protectionTableScript(state))
	return b.String()
}

func protectionEnsureInputChain() string {
	return "table inet " + protectionNftTable + " {\n" +
		"  chain input {\n" +
		fmt.Sprintf("    type filter hook input priority %d; policy accept;\n", protectionHookPrio) +
		"  }\n}\n"
}

func warmNft() {
	_, err := runCmd(3*time.Second, "nft", "list", "tables")
	if err != nil {
		time.Sleep(400 * time.Millisecond)
		_, _ = runCmd(3*time.Second, "nft", "list", "tables")
	}
}

func nftSyntaxOK(script string) bool {
	return nftSyntaxErr(script) == nil
}

func nftFeatureSupported(script string) bool {
	err := nftSyntaxErr(script)
	return err == nil || nftCommandTimedOut(err)
}

func nftSyntaxErr(script string) error {
	_, err := runCmdStdin(cmdTimeout, script, "nft", "-c", "-f", "-")
	if err == nil || !nftCommandTimedOut(err) {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	_, err = runCmdStdin(cmdTimeout, script, "nft", "-c", "-f", "-")
	return err
}

func nftCommandTimedOut(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timed out")
}

func protectionTableLive() bool {
	if !lookPath("nft") {
		return false
	}
	out, err := runCmd(cmdTimeout, "nft", "list", "table", "inet", protectionNftTable)
	return err == nil && strings.Contains(out, "table inet "+protectionNftTable)
}

func removeProtectionTable() error {
	_, err := runCmd(cmdTimeout, "nft", "delete", "table", "inet", protectionNftTable)
	return err
}

func syncProtectionBansLocked(state *persistedProtection) error {
	if !state.RuntimeEnabled {
		return nil
	}
	if !lookPath("nft") {
		noteProtectionEnableOK()
		return nil
	}
	now := time.Now().UTC()
	before := len(state.Reasons)
	pruneReasons(state, now)
	if len(state.Reasons) != before {
		_ = saveProtection(state)
	}
	if !protectionTableLive() {
		if err := enableProtectionRuntimeLocked(state, true); err != nil {
			return err
		}
	}
	desired := activeIPs(state, now)
	live, listed := liveProtectionSetTimeouts()
	if !listed && protectionTableLive() {
		return nil
	}
	var b strings.Builder
	for ip := range live {
		if _, ok := desired[ip]; ok {
			continue
		}
		set := protectionSetV4
		if v2.ProtectionIPFamily(ip) == "v6" {
			set = protectionSetV6
		}
		b.WriteString("delete element inet " + protectionNftTable + " " + set + " { " + ip + " }\n")
	}
	for _, ip := range sortedIPs(desired) {
		sec := protectionNftTimeoutSec(desired[ip])
		if sec == 0 {
			continue
		}
		liveSec, exists := live[ip]
		if exists && !timeoutNeedsUpdate(liveSec, sec) {
			continue
		}
		set := protectionSetV4
		if v2.ProtectionIPFamily(ip) == "v6" {
			set = protectionSetV6
		}
		if exists {
			b.WriteString("delete element inet " + protectionNftTable + " " + set + " { " + ip + " }\n")
		}
		if sec < 0 {
			b.WriteString(fmt.Sprintf("add element inet %s %s { %s }\n", protectionNftTable, set, ip))
			continue
		}
		b.WriteString(fmt.Sprintf("add element inet %s %s { %s timeout %ds }\n", protectionNftTable, set, ip, sec))
	}
	if b.Len() > 0 {
		if _, err := runCmdStdin(cmdTimeout, b.String(), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("同步防护集合失败: %v", err)
		}
	}
	fp := protectionBanFingerprint(desired, now)
	if fp != lastProtectionBootFP {
		if err := persistProtectionBootLocked(); err != nil {
			logProtection("boot persist: %v", err)
		} else {
			lastProtectionBootFP = fp
		}
	}
	noteProtectionEnableOK()
	return nil
}

func liveProtectionSetTimeouts() (map[string]int, bool) {
	out := map[string]int{}
	listed := false
	for _, set := range []string{protectionSetV4, protectionSetV6} {
		raw, err := runCmd(cmdTimeout, "nft", "list", "set", "inet", protectionNftTable, set)
		if err != nil {
			continue
		}
		listed = true
		for ip, sec := range parseNftSetTimeouts(raw) {
			out[ip] = sec
		}
	}
	return out, listed
}

func addProtectionElement(ip string, timeout time.Duration) error {
	sec := protectionNftTimeoutSec(timeout)
	if sec == 0 {
		return nil
	}
	set := protectionSetV4
	if v2.ProtectionIPFamily(ip) == "v6" {
		set = protectionSetV6
	}
	elem := fmt.Sprintf("{ %s }", ip)
	if sec > 0 {
		elem = fmt.Sprintf("{ %s timeout %ds }", ip, sec)
	}
	_, _ = runCmd(cmdTimeout, "nft", "delete", "element", "inet", protectionNftTable, set, "{ "+ip+" }")
	_, err := runCmd(cmdTimeout, "nft", "add", "element", "inet", protectionNftTable, set, elem)
	return err
}

func deleteProtectionElement(ip string) error {
	set := protectionSetV4
	if v2.ProtectionIPFamily(ip) == "v6" {
		set = protectionSetV6
	}
	_, err := runCmd(cmdTimeout, "nft", "delete", "element", "inet", protectionNftTable, set, "{ "+ip+" }")
	return err
}

func protectionTableScript(state *persistedProtection) string {
	cap := probeProtectionCapabilityLocked()
	return protectionBaseScript(cap.Features.Meter, cap.Features.ConnLimit, false, state)
}

func protectionBaseScript(meter, connlimit, nflog bool, state *persistedProtection) string {
	var policies []v2.ProtectionPolicy
	enabled := false
	if state != nil {
		policies = state.Config.Policies
		enabled = state.Config.Enabled
	}
	var b strings.Builder
	b.WriteString("table inet " + protectionNftTable + " {\n")
	b.WriteString(protectionSetBlock(protectionSetV4, "ipv4_addr", protectionSetElements(state, "v4")))
	b.WriteString(protectionSetBlock(protectionSetV6, "ipv6_addr", protectionSetElements(state, "v6")))
	b.WriteString(protectionWhitelistBlock("wl4", "ipv4_addr", protectionWhitelistIPs(state, "v4")))
	b.WriteString(protectionWhitelistBlock("wl6", "ipv6_addr", protectionWhitelistIPs(state, "v6")))
	b.WriteString("  chain input {\n")
	b.WriteString(fmt.Sprintf("    type filter hook input priority %d; policy accept;\n", protectionHookPrio))
	b.WriteString("    iif lo return\n")
	b.WriteString("    ct state established,related ct direction reply return\n")
	b.WriteString("    ip saddr @wl4 return\n")
	b.WriteString("    ip6 saddr @wl6 return\n")
	_ = nflog
	if enabled {
		b.WriteString("    ip saddr @" + protectionSetV4 + " drop\n")
		b.WriteString("    ip6 saddr @" + protectionSetV6 + " drop\n")
		for _, policy := range policies {
			if !policy.Enabled || strings.ToLower(policy.Protocol) != "tcp" {
				continue
			}
			port, ok := nftTCPPort(policy.Port)
			if !ok {
				continue
			}
			enforce := policy.Mode == v2.ProtectionModeEnforce
			v4Match, v6Match := protectionDestMatch(policy.BindAddr)
			if meter && policy.SynRate > 0 {
				burst := policy.SynBurst
				if burst <= 0 {
					burst = policy.SynRate
				}
				name := sanitizeNftName(policy.ID)
				if v4Match != "skip" {
					b.WriteString(protectionMeterLine(port, "syn4_"+name, "ip saddr", policy.SynRate, burst, false, enforce, v4Match))
				}
				if v6Match != "skip" {
					b.WriteString(protectionMeterLine(port, "syn6_"+name, "ip6 saddr", policy.SynRate, burst, false, enforce, v6Match))
				}
			}
			if connlimit && policy.ConnLimit > 0 {
				name := sanitizeNftName(policy.ID)
				if v4Match != "skip" {
					b.WriteString(protectionConnlimitLine(port, "cl4_"+name, "ip saddr", policy.ConnLimit, enforce, v4Match))
				}
				if v6Match != "skip" {
					b.WriteString(protectionConnlimitLine(port, "cl6_"+name, "ip6 saddr", policy.ConnLimit, enforce, v6Match))
				}
			}
		}
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func protectionProbeScript(kind string) string {
	switch kind {
	case "meter":
		return "table inet liteplus_protection_probe {\n  chain input {\n    type filter hook input priority -201; policy accept;\n    tcp dport 9 ct state new meter p { ip saddr timeout 60s limit rate over 8/second burst 8 packets }\n  }\n}\n"
	case "connlimit":
		return "table inet liteplus_protection_probe {\n  chain input {\n    type filter hook input priority -201; policy accept;\n    tcp dport 9 meter p { ip saddr ct count over 8 }\n  }\n}\n"
	case "nflog":
		return "table inet liteplus_protection_probe {\n  chain input {\n    type filter hook input priority -201; policy accept;\n    tcp dport 9 limit rate 1/second nflog group 4242 nflog-snaplen 64\n  }\n}\n"
	default:
		return protectionBaseScript(false, false, false, nil)
	}
}

func protectionSetBlock(name, typ string, elems []string) string {
	var b strings.Builder
	b.WriteString("  set " + name + " {\n    type " + typ + "\n    flags timeout\n")
	if len(elems) > 0 {
		b.WriteString("    elements = { " + strings.Join(elems, ", ") + " }\n")
	}
	b.WriteString("  }\n")
	return b.String()
}

func protectionSetElements(state *persistedProtection, family string) []string {
	if state == nil {
		return nil
	}
	desired := activeIPs(state, time.Now().UTC())
	var out []string
	for _, ip := range sortedIPs(desired) {
		if v2.ProtectionIPFamily(ip) != family {
			continue
		}
		sec := protectionNftTimeoutSec(desired[ip])
		if sec == 0 {
			continue
		}
		if sec < 0 {
			out = append(out, ip)
			continue
		}
		out = append(out, fmt.Sprintf("%s timeout %ds", ip, sec))
	}
	return out
}

func protectionMeterLine(port, name, key string, rate, burst int, nflog, enforce bool, dest string) string {
	line := "    "
	if dest != "" {
		line += dest + " "
	}
	line += fmt.Sprintf("tcp dport %s ct state new meter %s { %s timeout 60s limit rate over %d/second burst %d packets } counter", port, name, key, rate, burst)
	if nflog {
		line += fmt.Sprintf(" limit rate 2/second burst 4 packets nflog group %d nflog-prefix \"lp-prot\" nflog-snaplen 64", protectionNflogGroup)
	}
	if enforce {
		line += " drop"
	}
	return line + "\n"
}

func protectionConnlimitLine(port, name, key string, limit int, enforce bool, dest string) string {
	line := "    "
	if dest != "" {
		line += dest + " "
	}
	line += fmt.Sprintf("tcp dport %s meter %s { %s ct count over %d } counter", port, name, key, limit)
	if enforce {
		line += " drop"
	}
	return line + "\n"
}

func protectionWhitelistBlock(name, typ string, elems []string) string {
	var b strings.Builder
	b.WriteString("  set " + name + " {\n    type " + typ + "\n")
	if len(elems) > 0 {
		b.WriteString("    elements = { " + strings.Join(elems, ", ") + " }\n")
	}
	b.WriteString("  }\n")
	return b.String()
}

func protectionWhitelistIPs(state *persistedProtection, family string) []string {
	if state == nil {
		return nil
	}
	var out []string
	for _, item := range state.Config.Whitelist {
		ip, ok := v2.NormalizeProtectionIP(item)
		if !ok || v2.ProtectionIPFamily(ip) != family {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func protectionDestMatch(bind string) (v4, v6 string) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return "", ""
	}
	ip, ok := v2.NormalizeProtectionIP(bind)
	if !ok {
		return "skip", "skip"
	}
	if v2.ProtectionIPFamily(ip) == "v6" {
		return "skip", "ip6 daddr " + ip
	}
	return "ip daddr " + ip, "skip"
}

func sanitizeNftName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "p"
	}
	return b.String()
}

func protectionReloadSafe() bool {
	raw, err := os.ReadFile("/etc/nftables.conf")
	if err != nil {
		return true
	}
	text := string(raw)
	if !strings.Contains(text, "flush ruleset") {
		return true
	}
	return strings.Contains(text, "nftables.d")
}

func disableProtectionRuntimeLocked(_ *persistedProtection) error {
	if lookPath("nft") && protectionTableLive() {
		_ = removeProtectionTable()
	}
	lastProtectionBootFP = ""
	return persistProtectionBootLocked()
}

func nftTCPPort(port string) (string, bool) {
	port = strings.TrimSpace(port)
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

func persistProtectionBootLocked() error {
	state := loadProtection()
	if !state.RuntimeEnabled {
		_ = os.Remove(bootPath(protectionBootFile))
		_ = os.Remove(protectionDropin)
		return nil
	}
	body := protectionApplyScript(state)
	if err := os.MkdirAll(filepath.Dir(statePath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(bootPath(protectionBootFile), []byte(body), 0o600); err != nil {
		return err
	}
	if st, err := os.Stat("/etc/nftables.d"); err == nil && st.IsDir() {
		_ = os.WriteFile(protectionDropin, []byte(body), 0o644)
	}
	return nil
}

func protectionPreviewLocked(p v2.ProtectionPreviewParams) v2.ProtectionResultParams {
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindPreview}
	state := loadProtection()
	path := strings.TrimSpace(p.Path)
	format := strings.TrimSpace(p.Format)
	if p.SourceID != "" {
		for _, src := range state.Config.Sources {
			if src.ID == p.SourceID {
				path = src.Path
				format = src.Format
				break
			}
		}
	}
	if path == "" || format == "" {
		result.Status = v2.ProtectionStatusError
		result.Error = "缺少日志路径或格式"
		return result
	}
	if !v2.ValidProtectionLogFormat(format) {
		result.Status = v2.ProtectionStatusError
		result.Error = "不支持的日志格式"
		return result
	}
	if !protectionPreviewPathAllowed(state, p.SourceID, path) {
		result.Status = v2.ProtectionStatusError
		result.Error = "只能预览已配置的日志源，或 /var/log 下的访问日志"
		return result
	}
	limit := p.Limit
	if limit <= 0 || limit > 20 {
		limit = 8
	}
	var lines []string
	if v2.IsProtectionJournalPath(path) {
		if format != v2.ProtectionLogSSHD {
			result.Status = v2.ProtectionStatusError
			result.Error = "journal:sshd 只能用于 SSH 日志"
			return result
		}
		tail, err := protection.ReadJournalTail(200)
		if err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = "无法读取 SSH 日志"
			return result
		}
		lines = tail
	} else {
		raw, err := readFileTail(path, 256*1024)
		if err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = "无法读取日志文件"
			return result
		}
		lines = strings.Split(string(raw), "\n")
	}
	var preview []v2.ProtectionPreviewRecord
	for i := len(lines) - 1; i >= 0 && len(preview) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		rec, err := protection.ParseLine(format, line)
		if protection.IsSkip(err) {
			continue
		}
		item := v2.ProtectionPreviewRecord{}
		if err != nil {
			if format == v2.ProtectionLogSSHD {
				continue
			}
			item.Error = "parse"
			preview = append(preview, item)
			continue
		}
		item.TS = rec.Time.UTC().Format(time.RFC3339)
		item.IP = rec.IP
		item.Method = rec.Method
		item.Path = rec.Path
		item.Host = rec.Host
		item.Status = rec.Status
		item.Transport = rec.Transport
		item.Port = rec.ServerPort
		preview = append(preview, item)
	}
	for i, j := 0, len(preview)-1; i < j; i, j = i+1, j-1 {
		preview[i], preview[j] = preview[j], preview[i]
	}
	result.Status = v2.ProtectionStatusOK
	result.Preview = preview
	return result
}

func readFileTail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	start := int64(0)
	if size > max {
		start = size - max
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, size-start)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

func skipProtectionInetTable(table string) bool {
	return strings.EqualFold(strings.TrimSpace(table), protectionNftTable)
}

func sampleProtectionCounters() []v2.ProtectionNflogSample {
	if !lookPath("nft") || !protectionTableLive() {
		return nil
	}
	raw, err := runCmd(cmdTimeout, "nft", "list", "chain", "inet", protectionNftTable, "input")
	if err != nil {
		return nil
	}
	return parseProtectionCounters(raw)
}

func ptrCap(cap v2.ProtectionCapability) *v2.ProtectionCapability {
	return &cap
}

func nftDuration(d time.Duration) string {
	return strconv.Itoa(int(d.Seconds())) + "s"
}
