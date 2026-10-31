package firewall

import "strings"

type nftInputHook struct {
	Family string
	Table  string
	Chain  string
}

func parseNftInputHooks(raw string) []nftInputHook {
	raw = strings.ReplaceAll(strings.ReplaceAll(raw, "{", "{\n"), "}", "\n}")
	var hooks []nftInputHook
	seen := map[string]struct{}{}
	fam, table, chain := "", "", ""
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(trim, "table ") {
			fam, table = parseNftTableHeader(trim)
			chain = ""
			continue
		}
		if strings.HasPrefix(trim, "chain ") {
			chain = nftChainName(trim)
			continue
		}
		if !strings.Contains(trim, "hook input") {
			continue
		}
		if fam == "" || table == "" || chain == "" {
			continue
		}
		if table == plusNftTable {
			continue
		}
		key := fam + "|" + table + "|" + chain
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		hooks = append(hooks, nftInputHook{Family: fam, Table: table, Chain: chain})
	}
	return hooks
}

func parseNftTableHeader(line string) (family, name string) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", ""
	}
	return fields[1], strings.TrimSuffix(fields[2], "{")
}

func foreignInetInputHooks(raw string) []nftInputHook {
	var out []nftInputHook
	for _, hook := range parseNftInputHooks(raw) {
		if hook.Family == "inet" {
			out = append(out, hook)
		}
	}
	return out
}

func skipManagedInetTable(table string) bool {
	name := strings.ToLower(strings.TrimSpace(table))
	return strings.Contains(name, "ufw") || strings.Contains(name, "firewalld")
}

func attachableInetHooks(hooks []nftInputHook) []nftInputHook {
	out := make([]nftInputHook, 0, len(hooks))
	for _, hook := range hooks {
		if skipManagedInetTable(hook.Table) {
			continue
		}
		out = append(out, hook)
	}
	return out
}

func nftChainJumpsToPlus(listed string) bool {
	for _, line := range strings.Split(listed, "\n") {
		if strings.Contains(line, "jump "+plusIptablesChain) {
			return true
		}
	}
	return false
}

// nftAttachLive reports that Plus is on the host inet input without copying
// allows onto that chain. A jump into LITE_PLUS that accepts is already final
// for this base chain; extra host-input allows were only feeding the live
// check. Leftover lite-plus comments on the host chain are the previous
// dual-write and must be migrated once.
func nftAttachLive(hostListed, plusListed string, wantAllows bool) bool {
	if !nftChainJumpsToPlus(hostListed) {
		return false
	}
	if nftPlusCommentsLive(hostListed) {
		return false
	}
	if wantAllows && !nftPlusCommentsLive(plusListed) {
		return false
	}
	return true
}

func nftPlusCommentsLive(listed string) bool {
	for _, line := range strings.Split(listed, "\n") {
		if strings.Contains(line, plusCommentMark) {
			return true
		}
	}
	return false
}

func nftJumpHandles(listed string) []string {
	return nftLineHandles(listed, func(line string) bool {
		return strings.Contains(line, "jump "+plusIptablesChain)
	})
}

func nftPlusCommentHandles(listed string) []string {
	return nftLineHandles(listed, func(line string) bool {
		return strings.Contains(line, plusCommentMark)
	})
}

func nftLineHandles(listed string, keep func(string) bool) []string {
	var handles []string
	for _, line := range strings.Split(listed, "\n") {
		if !keep(line) {
			continue
		}
		const mark = "# handle "
		i := strings.LastIndex(line, mark)
		if i < 0 {
			continue
		}
		handle := strings.TrimSpace(line[i+len(mark):])
		if handle != "" {
			handles = append(handles, handle)
		}
	}
	return handles
}

func encodeNftHooks(hooks []nftInputHook) string {
	var b strings.Builder
	for _, hook := range hooks {
		b.WriteString(hook.Family + " " + hook.Table + " " + hook.Chain + "\n")
	}
	return b.String()
}
