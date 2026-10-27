//go:build linux

package firewall

import (
	"os"
	"strconv"
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const (
	nftTable      = "liteplus"
	iptablesChain = "LITE_PLUS"
)

type linuxBackend struct {
	kind string
}

func currentBackend() backend {
	return linuxBackend{kind: detectLinuxBackend()}
}

func detectLinuxBackend() string {
	if ufwActive() {
		return v2.FirewallBackendUFW
	}
	if firewalldActive() {
		return v2.FirewallBackendFirewalld
	}
	if lookPath("nft") {
		return v2.FirewallBackendNFT
	}
	if lookPath("iptables") {
		return v2.FirewallBackendIptables
	}
	return v2.FirewallBackendNone
}

func ufwActive() bool {
	if !lookPath("ufw") {
		return false
	}
	out, err := runCmd(cmdTimeout, "ufw", "status")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), "status: active")
}

func firewalldActive() bool {
	if !lookPath("firewall-cmd") {
		return false
	}
	out, err := runCmd(cmdTimeout, "firewall-cmd", "--state")
	return err == nil && strings.Contains(strings.ToLower(out), "running")
}

func privileged() bool {
	if os.Geteuid() == 0 {
		return true
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return capEffectiveHasNetAdmin(string(raw))
}

func (b linuxBackend) name() string { return b.kind }

func (b linuxBackend) snapshot() v2.FirewallResultParams {
	outer := outerManagers(b.kind)
	result := v2.FirewallResultParams{
		Kind:               v2.FirewallKindSnapshot,
		Status:             v2.FirewallStatusOK,
		Backend:            b.kind,
		Privileged:         privileged(),
		Supported:          b.kind != v2.FirewallBackendNone && privileged(),
		OuterManagers:      outer,
		OuterFilter:        len(outer) > 0,
		BlockPing4:         pingBlocked(4),
		BlockPing6:         pingBlocked(6),
		DefaultDenyBlocked: defaultDenyBlocked(b.kind, outer),
		KeepRules:          keepRules(v2.FirewallIntent{}),
		SshPort:            detectedSSHPort(),
	}
	if result.DefaultDenyBlocked {
		result.DefaultDenyBlockReason = "default deny conflicts with ufw or firewalld"
	}
	if b.kind == v2.FirewallBackendNone {
		result.Status = v2.FirewallStatusUnsupported
		result.Error = "未找到 nft / iptables / ufw / firewalld"
		return result
	}
	if !result.Privileged {
		result.Status = v2.FirewallStatusUnsupported
		result.Error = "Agent 需要 root 或 CAP_NET_ADMIN 才能改防火墙"
	}
	if len(outer) > 0 {
		result.OuterHint = "本机还有另一层过滤：" + strings.Join(outer, ", ")
	}
	result.HostRules = append(result.HostRules, scanLinux(b.kind)...)
	return result
}

func defaultDenyBlocked(backend string, outer []string) bool {
	if backend == v2.FirewallBackendUFW || backend == v2.FirewallBackendFirewalld {
		return false
	}
	for _, name := range outer {
		if name == v2.FirewallBackendUFW || name == v2.FirewallBackendFirewalld {
			return true
		}
	}
	return false
}

func outerManagers(backend string) []string {
	var out []string
	if backend != v2.FirewallBackendUFW && ufwActive() {
		out = append(out, v2.FirewallBackendUFW)
	}
	if backend != v2.FirewallBackendFirewalld && firewalldActive() {
		out = append(out, v2.FirewallBackendFirewalld)
	}
	if dockerPresent() {
		out = append(out, "docker")
	}
	return out
}

func dockerPresent() bool {
	out, err := runCmd(cmdTimeout, "iptables", "-S")
	if err != nil {
		return lookPath("docker")
	}
	upper := strings.ToUpper(out)
	return strings.Contains(upper, "DOCKER") || strings.Contains(upper, "BR-")
}

func (b linuxBackend) apply(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	if !privileged() {
		return errUnsupported
	}
	if err := applyPing(intent.BlockPing4, intent.BlockPing6); err != nil {
		return err
	}
	switch b.kind {
	case v2.FirewallBackendUFW:
		return applyUFW(intent, holes)
	case v2.FirewallBackendFirewalld:
		return applyFirewalld(intent, holes)
	case v2.FirewallBackendNFT:
		return applyNFT(intent, holes)
	case v2.FirewallBackendIptables:
		return applyIptables(intent, holes)
	default:
		return errUnsupported
	}
}

func (b linuxBackend) adopt(keys []string) error {
	wanted := map[string]struct{}{}
	for _, key := range keys {
		wanted[key] = struct{}{}
	}
	var removed []v2.FirewallHostRule
	for _, rule := range scanLinux(b.kind) {
		if _, ok := wanted[rule.Key]; !ok || !rule.Adoptable {
			continue
		}
		if err := deleteHostRule(b.kind, rule); err != nil {
			return err
		}
		removed = append(removed, rule)
	}
	if b.kind != v2.FirewallBackendFirewalld {
		return nil
	}
	var permDone []v2.FirewallHostRule
	for _, rule := range removed {
		if err := deleteFirewalldPermanent(rule); err != nil {
			for i := len(permDone) - 1; i >= 0; i-- {
				_ = addFirewalldPermanent(permDone[i])
			}
			return err
		}
		permDone = append(permDone, rule)
	}
	return nil
}

const iptDumpSep = "#####LITEPLUS_IP6#####"

func (b linuxBackend) dump() ([]byte, error) {
	switch b.kind {
	case v2.FirewallBackendNFT:
		out, err := runCmd(dumpTimeout, "nft", "list", "table", "inet", nftTable)
		if err != nil {
			return nil, nil
		}
		return []byte(out), nil
	case v2.FirewallBackendFirewalld:
		return []byte("firewalld-runtime"), nil
	default:
		return b.dumpHost()
	}
}

func (b linuxBackend) dumpHost() ([]byte, error) {
	switch b.kind {
	case v2.FirewallBackendNFT:
		out, err := runCmd(dumpTimeout, "nft", "list", "ruleset")
		if err != nil {
			return nil, nil
		}
		return append([]byte(nftHostMark), out...), nil
	case v2.FirewallBackendIptables:
		return iptablesDump()
	case v2.FirewallBackendFirewalld:
		return firewalldDump()
	case v2.FirewallBackendUFW:
		return ufwDump()
	default:
		return nil, nil
	}
}

func (b linuxBackend) resetOwned() error {
	switch b.kind {
	case v2.FirewallBackendNFT:
		_, _ = runCmd(cmdTimeout, "nft", "delete", "table", "inet", nftTable)
	case v2.FirewallBackendUFW:
		clearUfwPlusRules()
	case v2.FirewallBackendFirewalld:
		_, _ = runCmd(cmdTimeout, "firewall-cmd", "--reload")
	}
	return nil
}

func (b linuxBackend) restore(raw []byte) error {
	if b.kind == v2.FirewallBackendNFT && len(strings.TrimSpace(string(raw))) == 0 {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "table", "inet", nftTable)
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	switch b.kind {
	case v2.FirewallBackendNFT:
		tmp, err := os.CreateTemp("", "liteplus-nft-*.nft")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		body := raw
		if rest, ok := strings.CutPrefix(string(raw), nftHostMark); ok {
			body = []byte(rest)
			if !strings.Contains(rest, "flush ruleset") {
				body = append([]byte("flush ruleset\n"), body...)
			}
		} else {
			_, _ = runCmd(cmdTimeout, "nft", "delete", "table", "inet", nftTable)
		}
		if _, err := tmp.Write(body); err != nil {
			tmp.Close()
			return err
		}
		tmp.Close()
		_, err = runCmd(dumpTimeout, "nft", "-f", tmp.Name())
		return err
	case v2.FirewallBackendIptables:
		return iptablesRestore(raw)
	case v2.FirewallBackendFirewalld:
		return firewalldRestore(raw)
	case v2.FirewallBackendUFW:
		return ufwRestore(raw)
	default:
		return nil
	}
}

func iptablesDump() ([]byte, error) {
	v4, _ := runCmd(cmdTimeout, "iptables-save")
	v6 := ""
	if lookPath("ip6tables-save") {
		v6, _ = runCmd(cmdTimeout, "ip6tables-save")
	}
	return []byte(v4 + "\n" + iptDumpSep + "\n" + v6), nil
}

func iptablesRestore(raw []byte) error {
	parts := strings.SplitN(string(raw), iptDumpSep, 2)
	restore := func(bin, table string) error {
		if strings.TrimSpace(table) == "" || !lookPath(bin) {
			return nil
		}
		_, err := runCmdStdin(cmdTimeout, strings.TrimSpace(table)+"\n", bin)
		return err
	}
	if err := restore("iptables-restore", parts[0]); err != nil {
		return err
	}
	if len(parts) > 1 {
		return restore("ip6tables-restore", parts[1])
	}
	return nil
}

const (
	nftHostMark   = "NFT_HOST_V1\n"
	ufwDumpMark   = "UFW_FILES_V1\n"
	ufwUserRules  = "/etc/ufw/user.rules"
	ufwUser6Rules = "/etc/ufw/user6.rules"
)

func ufwDump() ([]byte, error) {
	var b strings.Builder
	b.WriteString(ufwDumpMark)
	b.WriteString("INCOMING " + ufwIncomingPolicy() + "\n")
	b.WriteString("----- user.rules -----\n")
	if raw, err := os.ReadFile(ufwUserRules); err == nil {
		b.Write(raw)
		if !strings.HasSuffix(string(raw), "\n") {
			b.WriteByte('\n')
		}
	}
	b.WriteString("----- user6.rules -----\n")
	if raw, err := os.ReadFile(ufwUser6Rules); err == nil {
		b.Write(raw)
	}
	return []byte(b.String()), nil
}

func ufwRestore(raw []byte) error {
	text := string(raw)
	if strings.HasPrefix(text, ufwDumpMark) {
		rest := strings.TrimPrefix(text, ufwDumpMark)
		first, rest, _ := strings.Cut(rest, "\n")
		userPart, user6, has6 := strings.Cut(rest, "\n----- user6.rules -----\n")
		userPart = strings.TrimPrefix(userPart, "----- user.rules -----\n")
		if has6 {
			_ = os.WriteFile(ufwUserRules, []byte(userPart), 0o644)
			_ = os.WriteFile(ufwUser6Rules, []byte(user6), 0o644)
			_, _ = runCmd(dumpTimeout, "ufw", "reload")
		}
		return restoreUfwIncomingPolicy(strings.TrimSpace(strings.TrimPrefix(first, "INCOMING ")))
	}
	first, _, _ := strings.Cut(text, "\n")
	return restoreUfwIncomingPolicy(strings.TrimSpace(strings.TrimPrefix(first, "INCOMING ")))
}

func restoreUfwIncomingPolicy(policy string) error {
	if policy == "" {
		return nil
	}
	_, err := runCmd(cmdTimeout, "ufw", "default", policy, "incoming")
	return err
}

func ufwIncomingPolicy() string {
	out, _ := runCmd(cmdTimeout, "ufw", "status", "verbose")
	lower := strings.ToLower(out)
	idx := strings.Index(lower, "(incoming)")
	if idx < 0 {
		return "allow"
	}
	head := strings.TrimSpace(lower[:idx])
	fields := strings.Fields(head)
	if len(fields) == 0 {
		return "allow"
	}
	switch fields[len(fields)-1] {
	case "deny", "reject", "allow":
		return fields[len(fields)-1]
	default:
		return "allow"
	}
}

func scanLinux(kind string) []v2.FirewallHostRule {
	var rules []v2.FirewallHostRule
	switch kind {
	case v2.FirewallBackendUFW:
		out, _ := runCmd(cmdTimeout, "ufw", "status", "numbered")
		apps := ufwAppPorts(out)
		rules = append(rules, parseUFWStatusApps(out, v2.FirewallStackV4, apps)...)
		rules = append(rules, parseUFWStatusApps(out, v2.FirewallStackV6, apps)...)
	case v2.FirewallBackendNFT:
		out, _ := runCmd(cmdTimeout, "nft", "-a", "list", "ruleset")
		rules = append(rules, parseNftRuleset(out)...)
	case v2.FirewallBackendFirewalld:
		v4, _ := runCmd(cmdTimeout, "iptables-save", "-t", "filter")
		v6, _ := runCmd(cmdTimeout, "ip6tables-save", "-t", "filter")
		rules = append(rules, parseIptablesSave(v4, v2.FirewallStackV4, "INPUT")...)
		rules = append(rules, parseIptablesSave(v6, v2.FirewallStackV6, "INPUT")...)
		rules = append(rules, scanFirewalldZone()...)
	default:
		v4, _ := runCmd(cmdTimeout, "iptables-save", "-t", "filter")
		v6, _ := runCmd(cmdTimeout, "ip6tables-save", "-t", "filter")
		rules = append(rules, parseIptablesSave(v4, v2.FirewallStackV4, "INPUT")...)
		rules = append(rules, parseIptablesSave(v6, v2.FirewallStackV6, "INPUT")...)
	}
	return rules
}

func ufwAppPorts(numbered string) map[string]string {
	apps := map[string]string{}
	for _, line := range strings.Split(numbered, "\n") {
		match := ufwLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		name := ufwAppName(match[2])
		if name == "" || apps[name] != "" {
			continue
		}
		if proto, _ := splitPortProto(name); proto != "" {
			continue
		}
		info, err := runCmd(cmdTimeout, "ufw", "app", "info", name)
		if err != nil {
			continue
		}
		if spec := parseUfwAppInfo(info); spec != "" {
			apps[name] = spec
		}
	}
	return apps
}

func scanFirewalldZone() []v2.FirewallHostRule {
	var rules []v2.FirewallHostRule
	seen := map[string]struct{}{}
	add := func(list []v2.FirewallHostRule) {
		for _, rule := range list {
			if rule.Adoptable {
				key := rule.Stack + "|" + rule.Protocol + "|" + rule.Port
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			rules = append(rules, rule)
		}
	}
	services, _ := runCmd(cmdTimeout, "firewall-cmd", "--list-services")
	for _, name := range strings.Fields(services) {
		info, err := runCmd(cmdTimeout, "firewall-cmd", "--info-service="+name)
		if err != nil {
			continue
		}
		add(parseFirewalldService(name, info))
	}
	ports, _ := runCmd(cmdTimeout, "firewall-cmd", "--list-ports")
	add(parseFirewalldPorts(ports))
	return rules
}

func deleteHostRule(kind string, rule v2.FirewallHostRule) error {
	switch kind {
	case v2.FirewallBackendUFW:
		if idx := strings.TrimPrefix(rule.Comment, "ufw #"); idx != rule.Comment {
			_, err := runCmd(cmdTimeout, "ufw", "--force", "delete", idx)
			return err
		}
	case v2.FirewallBackendNFT:
		fields := strings.Fields(rule.Comment)
		if len(fields) == 5 && fields[0] == "nft" {
			_, err := runCmd(cmdTimeout, "nft", "delete", "rule", fields[1], fields[2], fields[3], "handle", fields[4])
			return err
		}
	case v2.FirewallBackendIptables, v2.FirewallBackendFirewalld:
		if name := strings.TrimPrefix(rule.Comment, "firewalld-service "); name != rule.Comment && name != "" {
			_, err := runCmd(cmdTimeout, "firewall-cmd", "--remove-service="+name)
			return err
		}
		if strings.HasPrefix(rule.Comment, "firewalld-port ") {
			spec := rule.Port + "/" + rule.Protocol
			_, err := runCmd(cmdTimeout, "firewall-cmd", "--remove-port="+spec)
			return err
		}
		args := strings.Fields(strings.TrimPrefix(rule.Raw, "-A "))
		if len(args) == 0 {
			return nil
		}
		bin := "iptables"
		if rule.Stack == v2.FirewallStackV6 {
			bin = "ip6tables"
		}
		del := append([]string{"-D"}, args...)
		_, err := runCmd(cmdTimeout, bin, del...)
		return err
	}
	return nil
}

func firewalldPortSpec(rule v2.FirewallHostRule) string {
	return rule.Port + "/" + rule.Protocol
}

func deleteFirewalldPermanent(rule v2.FirewallHostRule) error {
	if name := strings.TrimPrefix(rule.Comment, "firewalld-service "); name != rule.Comment && name != "" {
		_, err := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--remove-service="+name)
		return err
	}
	if strings.HasPrefix(rule.Comment, "firewalld-port ") {
		_, err := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--remove-port="+firewalldPortSpec(rule))
		return err
	}
	return nil
}

func firewalldDump() ([]byte, error) {
	services, _ := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--list-services")
	ports, _ := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--list-ports")
	return []byte(firewalldHostMark + "SERVICES " + strings.TrimSpace(services) + "\nPORTS " + strings.TrimSpace(ports) + "\n"), nil
}

func firewalldRestore(raw []byte) error {
	_, reloadErr := runCmd(cmdTimeout, "firewall-cmd", "--reload")
	services, ports := parseFirewalldHostDump(string(raw))
	var first error
	first = reloadErr
	for _, name := range services {
		if err := firewalldAdd("service", name, true); err != nil && first == nil {
			first = err
		}
		_ = firewalldAdd("service", name, false)
	}
	for _, spec := range ports {
		if err := firewalldAdd("port", spec, true); err != nil && first == nil {
			first = err
		}
		_ = firewalldAdd("port", spec, false)
	}
	return first
}

func firewalldAdd(kind, value string, permanent bool) error {
	if value == "" {
		return nil
	}
	args := []string{}
	if permanent {
		args = append(args, "--permanent")
	}
	switch kind {
	case "service":
		args = append(args, "--add-service="+value)
	default:
		args = append(args, "--add-port="+value)
	}
	_, err := runCmd(cmdTimeout, "firewall-cmd", args...)
	return err
}

func addFirewalldPermanent(rule v2.FirewallHostRule) error {
	if name := strings.TrimPrefix(rule.Comment, "firewalld-service "); name != rule.Comment && name != "" {
		_, err := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--add-service="+name)
		return err
	}
	if strings.HasPrefix(rule.Comment, "firewalld-port ") {
		_, err := runCmd(cmdTimeout, "firewall-cmd", "--permanent", "--add-port="+firewalldPortSpec(rule))
		return err
	}
	return nil
}

func applyPing(v4, v6 bool) error {
	if stackAllowed(v2.FirewallStackV4) {
		if err := writeSysctl("/proc/sys/net/ipv4/icmp_echo_ignore_all", bool01(v4)); err != nil {
			return err
		}
	}
	if stackAllowed(v2.FirewallStackV6) {
		if err := writeSysctl("/proc/sys/net/ipv6/icmp/echo_ignore_all", bool01(v6)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func pingBlocked(family int) bool {
	path := "/proc/sys/net/ipv4/icmp_echo_ignore_all"
	if family == 6 {
		path = "/proc/sys/net/ipv6/icmp/echo_ignore_all"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "1"
}

func bool01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func writeSysctl(path, value string) error {
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}

func applyNFT(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	_, _ = runCmd(cmdTimeout, "nft", "delete", "table", "inet", nftTable)
	if intentIdle(intent) {
		return nil
	}
	var b strings.Builder
	b.WriteString("table inet " + nftTable + " {\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority -150; policy accept;\n")
	b.WriteString("    iif lo accept\n")
	b.WriteString("    ct state established,related accept\n")
	if stackAllowed(v2.FirewallStackV4) {
		b.WriteString("    ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n")
	}
	if stackAllowed(v2.FirewallStackV6) {
		b.WriteString("    ip6 nexthdr ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	}
	if intent.BlockPing4 && stackAllowed(v2.FirewallStackV4) {
		b.WriteString("    ip protocol icmp icmp type echo-request drop\n")
	}
	if intent.BlockPing6 && stackAllowed(v2.FirewallStackV6) {
		b.WriteString("    ip6 nexthdr ipv6-icmp icmpv6 type echo-request drop\n")
	}
	for _, rule := range enabledRules(intent) {
		if !stackAllowed(rule.Stack) {
			continue
		}
		b.WriteString("    " + nftRule(rule) + "\n")
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		for _, hole := range holes {
			if !stackAllowed(hole.Stack) || !holeSafe(hole) {
				continue
			}
			b.WriteString("    " + nftHole(hole) + "\n")
		}
		eachKeepRule(intent, func(rule v2.FirewallRule) {
			b.WriteString("    " + nftRule(rule) + "\n")
		})
		if intent.DefaultDeny4 && stackAllowed(v2.FirewallStackV4) {
			b.WriteString("    meta nfproto ipv4 drop\n")
		}
		if intent.DefaultDeny6 && stackAllowed(v2.FirewallStackV6) {
			b.WriteString("    meta nfproto ipv6 drop\n")
		}
	}
	b.WriteString("  }\n}\n")
	tmp, err := os.CreateTemp("", "liteplus-nft-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	_, err = runCmd(cmdTimeout, "nft", "-f", tmp.Name())
	return err
}

func nftRule(rule v2.FirewallRule) string {
	family := "meta nfproto ipv4"
	saddr := ""
	if rule.Stack == v2.FirewallStackV6 {
		family = "meta nfproto ipv6"
		if rule.Source != "" {
			saddr = " ip6 saddr " + rule.Source
		}
	} else if rule.Source != "" {
		saddr = " ip saddr " + rule.Source
	}
	spec := rule.Protocol
	if !allPorts(rule.Port) {
		port := rule.Port
		if strings.Contains(port, "-") {
			from, to := matchPort(port)
			port = from + "-" + to
		}
		spec += " dport " + port
	}
	action := "accept"
	if rule.Action == v2.FirewallActionDeny {
		action = "drop"
	}
	return strings.TrimSpace(family + saddr + " " + spec + " " + action)
}

func nftHole(hole v2.FirewallHole) string {
	return nftRule(v2.FirewallRule{Action: v2.FirewallActionAllow, Protocol: hole.Protocol, Port: hole.Port, Stack: hole.Stack})
}

func applyIptables(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	if stackAllowed(v2.FirewallStackV4) {
		if err := applyIptablesFamily("iptables", v2.FirewallStackV4, intent, holes); err != nil {
			return err
		}
	}
	if stackAllowed(v2.FirewallStackV6) && lookPath("ip6tables") {
		return applyIptablesFamily("ip6tables", v2.FirewallStackV6, intent, holes)
	}
	return nil
}

func applyIptablesFamily(bin, stack string, intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	chain := iptablesChain
	_, _ = runCmd(cmdTimeout, bin, "-D", "INPUT", "-j", chain)
	_, _ = runCmd(cmdTimeout, bin, "-F", chain)
	_, _ = runCmd(cmdTimeout, bin, "-X", chain)
	if intentIdle(intent) {
		return nil
	}
	if _, err := runCmd(cmdTimeout, bin, "-N", chain); err != nil {
		if _, flushErr := runCmd(cmdTimeout, bin, "-F", chain); flushErr != nil {
			return err
		}
	}
	if _, err := runCmd(cmdTimeout, bin, "-I", "INPUT", "1", "-j", chain); err != nil {
		return err
	}
	add := func(args ...string) error {
		_, err := runCmd(cmdTimeout, bin, append([]string{"-A", chain}, args...)...)
		return err
	}
	if err := add("-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := add("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		if err := add("-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if stack == v2.FirewallStackV4 {
		_ = add("-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "ACCEPT")
		_ = add("-p", "icmp", "--icmp-type", "time-exceeded", "-j", "ACCEPT")
		if intent.BlockPing4 {
			_ = add("-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP")
		}
	} else {
		_ = add("-p", "ipv6-icmp", "--icmpv6-type", "neighbour-solicitation", "-j", "ACCEPT")
		_ = add("-p", "ipv6-icmp", "--icmpv6-type", "neighbour-advertisement", "-j", "ACCEPT")
		_ = add("-p", "ipv6-icmp", "--icmpv6-type", "router-solicitation", "-j", "ACCEPT")
		_ = add("-p", "ipv6-icmp", "--icmpv6-type", "router-advertisement", "-j", "ACCEPT")
		_ = add("-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT")
		if intent.BlockPing6 {
			_ = add("-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j", "DROP")
		}
	}
	for _, rule := range enabledRules(intent) {
		if rule.Stack != stack {
			continue
		}
		args := iptablesArgs(rule)
		if err := add(args...); err != nil {
			return err
		}
	}
	deny := (stack == v2.FirewallStackV4 && intent.DefaultDeny4) || (stack == v2.FirewallStackV6 && intent.DefaultDeny6)
	if deny {
		for _, hole := range holes {
			if hole.Stack != stack || !holeSafe(hole) {
				continue
			}
			if err := add(iptablesArgs(v2.FirewallRule{Action: v2.FirewallActionAllow, Protocol: hole.Protocol, Port: hole.Port, Stack: stack})...); err != nil {
				return err
			}
		}
		var keepErr error
		eachKeepRule(intent, func(rule v2.FirewallRule) {
			if keepErr != nil || rule.Stack != stack {
				return
			}
			keepErr = add(iptablesArgs(rule)...)
		})
		if keepErr != nil {
			return keepErr
		}
		if err := add("-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}

func iptablesArgs(rule v2.FirewallRule) []string {
	args := []string{}
	if rule.Source != "" {
		args = append(args, "-s", rule.Source)
	}
	args = append(args, "-p", rule.Protocol)
	if !allPorts(rule.Port) {
		from, to := matchPort(rule.Port)
		if from == to {
			args = append(args, "--dport", from)
		} else {
			args = append(args, "-m", "multiport", "--dports", from+":"+to)
		}
	}
	if rule.Action == v2.FirewallActionDeny {
		args = append(args, "-j", "DROP")
	} else {
		args = append(args, "-j", "ACCEPT")
	}
	return args
}

func clearUfwPlusRules() {
	out, _ := runCmd(cmdTimeout, "ufw", "status", "numbered")
	var indexes []int
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "lite-plus:") {
			continue
		}
		if match := ufwLineRe.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			if n, err := strconv.Atoi(match[1]); err == nil {
				indexes = append(indexes, n)
			}
		}
	}
	for i := len(indexes) - 1; i >= 0; i-- {
		_, _ = runCmd(cmdTimeout, "ufw", "--force", "delete", strconv.Itoa(indexes[i]))
	}
}

func applyUFW(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	clearUfwPlusRules()
	if intentIdle(intent) {
		return nil
	}
	for _, rule := range enabledRules(intent) {
		if !stackAllowed(rule.Stack) {
			continue
		}
		args := ufwArgs(rule)
		if _, err := runCmd(cmdTimeout, "ufw", args...); err != nil {
			return err
		}
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		for _, hole := range holes {
			if !stackAllowed(hole.Stack) || !holeSafe(hole) {
				continue
			}
			if _, err := runCmd(cmdTimeout, "ufw", ufwArgs(v2.FirewallRule{
				Action:   v2.FirewallActionAllow,
				Protocol: hole.Protocol,
				Port:     hole.Port,
				Stack:    hole.Stack,
				Comment:  hole.Comment,
				ID:       "hole",
			})...); err != nil {
				return err
			}
		}
		var keepErr error
		eachKeepRule(intent, func(rule v2.FirewallRule) {
			if keepErr != nil {
				return
			}
			_, keepErr = runCmd(cmdTimeout, "ufw", ufwArgs(rule)...)
		})
		if keepErr != nil {
			return keepErr
		}
		if intent.DefaultDeny4 && stackAllowed(v2.FirewallStackV4) {
			if _, err := runCmd(cmdTimeout, "ufw", ufwDropAll(v2.FirewallStackV4)...); err != nil {
				return err
			}
		}
		if intent.DefaultDeny6 && stackAllowed(v2.FirewallStackV6) {
			if _, err := runCmd(cmdTimeout, "ufw", ufwDropAll(v2.FirewallStackV6)...); err != nil {
				return err
			}
		}
	}
	return nil
}

func ufwDropAll(stack string) []string {
	from := "0.0.0.0/0"
	id := "drop-v4"
	if stack == v2.FirewallStackV6 {
		from = "::/0"
		id = "drop-v6"
	}
	return []string{"deny", "in", "from", from, "to", "any", "comment", plusComment(id)}
}

func ufwArgs(rule v2.FirewallRule) []string {
	action := "allow"
	if rule.Action == v2.FirewallActionDeny {
		action = "deny"
	}
	args := []string{action, "proto", rule.Protocol}
	if rule.Source != "" {
		args = append(args, "from", rule.Source)
	} else if rule.Stack == v2.FirewallStackV4 {
		args = append(args, "from", "0.0.0.0/0")
	} else {
		args = append(args, "from", "::/0")
	}
	args = append(args, "to", "any")
	if !allPorts(rule.Port) {
		args = append(args, "port", strings.ReplaceAll(rule.Port, "-", ":"))
	}
	args = append(args, "comment", plusComment(rule.ID))
	return args
}

func applyFirewalld(intent v2.FirewallIntent, holes []v2.FirewallHole) error {
	removeFirewalldChain("ipv4")
	removeFirewalldChain("ipv6")
	if intentIdle(intent) {
		return nil
	}
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--add-chain", "ipv4", "filter", iptablesChain)
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--add-chain", "ipv6", "filter", iptablesChain)
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--add-rule", "ipv4", "filter", "INPUT", "0", "-j", iptablesChain)
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--add-rule", "ipv6", "filter", "INPUT", "0", "-j", iptablesChain)
	prio := 1
	add := func(family string, args []string) error {
		cmd := append([]string{"--direct", "--add-rule", family, "filter", iptablesChain, strconv.Itoa(prio)}, args...)
		prio++
		_, err := runCmd(cmdTimeout, "firewall-cmd", cmd...)
		return err
	}
	if stackAllowed(v2.FirewallStackV4) {
		_ = add("ipv4", []string{"-i", "lo", "-j", "ACCEPT"})
		if err := add("ipv4", []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}); err != nil {
			_ = add("ipv4", []string{"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
		}
		_ = add("ipv4", []string{"-p", "icmp", "--icmp-type", "destination-unreachable", "-j", "ACCEPT"})
		_ = add("ipv4", []string{"-p", "icmp", "--icmp-type", "time-exceeded", "-j", "ACCEPT"})
		if intent.BlockPing4 {
			_ = add("ipv4", []string{"-p", "icmp", "--icmp-type", "echo-request", "-j", "DROP"})
		}
	}
	if stackAllowed(v2.FirewallStackV6) {
		_ = add("ipv6", []string{"-i", "lo", "-j", "ACCEPT"})
		if err := add("ipv6", []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}); err != nil {
			_ = add("ipv6", []string{"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
		}
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "neighbour-solicitation", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "neighbour-advertisement", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "router-solicitation", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "router-advertisement", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "destination-unreachable", "-j", "ACCEPT"})
		_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "time-exceeded", "-j", "ACCEPT"})
		if intent.BlockPing6 {
			_ = add("ipv6", []string{"-p", "ipv6-icmp", "--icmpv6-type", "echo-request", "-j", "DROP"})
		}
	}
	for _, rule := range enabledRules(intent) {
		if !stackAllowed(rule.Stack) {
			continue
		}
		family := "ipv4"
		if rule.Stack == v2.FirewallStackV6 {
			family = "ipv6"
		}
		if err := add(family, iptablesArgs(rule)); err != nil {
			return err
		}
	}
	if intent.DefaultDeny4 || intent.DefaultDeny6 {
		for _, hole := range holes {
			if !stackAllowed(hole.Stack) || !holeSafe(hole) {
				continue
			}
			family := "ipv4"
			if hole.Stack == v2.FirewallStackV6 {
				family = "ipv6"
			}
			if err := add(family, iptablesArgs(v2.FirewallRule{Action: v2.FirewallActionAllow, Protocol: hole.Protocol, Port: hole.Port, Stack: hole.Stack})); err != nil {
				return err
			}
		}
		var keepErr error
		eachKeepRule(intent, func(rule v2.FirewallRule) {
			if keepErr != nil {
				return
			}
			family := "ipv4"
			if rule.Stack == v2.FirewallStackV6 {
				family = "ipv6"
			}
			keepErr = add(family, iptablesArgs(rule))
		})
		if keepErr != nil {
			return keepErr
		}
		if intent.DefaultDeny4 && stackAllowed(v2.FirewallStackV4) {
			if err := add("ipv4", []string{"-j", "DROP"}); err != nil {
				return err
			}
		}
		if intent.DefaultDeny6 && stackAllowed(v2.FirewallStackV6) {
			if err := add("ipv6", []string{"-j", "DROP"}); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeFirewalldChain(family string) {
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--remove-rule", family, "filter", "INPUT", "0", "-j", iptablesChain)
	_, _ = runCmd(cmdTimeout, "firewall-cmd", "--direct", "--remove-chain", family, "filter", iptablesChain)
}

