package firewall

import "strings"

// iptablesFilterOwnedByHost reports that some other manager already owns
// iptables-nft `ip filter` INPUT. Plus must apply in that same table: an accept
// in a separate inet table does not stop a later INPUT drop, whether the later
// drop comes from 1Panel, 宝塔, fail2ban, CSF, or a hand-written chain.
func iptablesFilterOwnedByHost(nftFilter, iptablesSave string) bool {
	return iptablesInputHasForeignRules(iptablesSave) || nftInputHasForeignRules(nftFilter)
}

func iptablesInputHasForeignRules(save string) bool {
	for _, line := range strings.Split(save, "\n") {
		trim := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if inputPolicyDrop(trim) {
			return true
		}
		if !strings.HasPrefix(trim, "-A INPUT") {
			continue
		}
		if iptablesInputJumpIsPlus(trim) {
			continue
		}
		return true
	}
	return false
}

func inputPolicyDrop(line string) bool {
	if !strings.HasPrefix(line, ":INPUT ") {
		return false
	}
	fields := strings.Fields(line)
	return len(fields) >= 2 && strings.EqualFold(fields[1], "DROP")
}

func iptablesInputJumpIsPlus(line string) bool {
	return strings.HasPrefix(line, "-A INPUT") && (strings.Contains(line, " -j "+plusIptablesChain) || strings.HasSuffix(line, " -j "+plusIptablesChain))
}

func iptablesInputJumpsToPlus(save string) bool {
	for _, line := range strings.Split(save, "\n") {
		trim := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if iptablesInputJumpIsPlus(trim) {
			return true
		}
	}
	return false
}

func nftInputHasForeignRules(raw string) bool {
	raw = strings.ReplaceAll(strings.ReplaceAll(raw, "{", "{\n"), "}", "\n}")
	inFilter := false
	inInput := false
	depth := 0
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(trim, "table ") {
			inFilter = nftIsIPFilterTable(trim)
			inInput = false
			depth = 0
			continue
		}
		if !inFilter {
			continue
		}
		if strings.HasPrefix(trim, "chain ") {
			inInput = nftChainName(trim) == "INPUT"
			depth = strings.Count(trim, "{") - strings.Count(trim, "}")
			if !inInput {
				continue
			}
			if nftInputLineIsForeign(trim) {
				return true
			}
			if depth <= 0 {
				inInput = false
			}
			continue
		}
		if !inInput {
			continue
		}
		depth += strings.Count(trim, "{") - strings.Count(trim, "}")
		if nftInputLineIsForeign(trim) {
			return true
		}
		if depth <= 0 {
			inInput = false
		}
	}
	return false
}

func nftIsIPFilterTable(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return false
	}
	name := strings.TrimSuffix(fields[2], "{")
	return (fields[1] == "ip" || fields[1] == "ip6") && name == "filter"
}

func nftChainName(line string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "chain "))
	if i := strings.IndexAny(rest, " \t{"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

func nftInputLineIsForeign(trim string) bool {
	lower := strings.ToLower(trim)
	if strings.Contains(lower, "policy drop") {
		return true
	}
	if strings.HasPrefix(trim, "chain ") || strings.HasPrefix(trim, "type ") || strings.HasPrefix(trim, "policy ") || strings.HasPrefix(trim, "comment ") {
		return false
	}
	if nftCounterOnly(trim) || trim == "" || trim == "{" || trim == "}" {
		return false
	}
	if strings.Contains(trim, "jump "+plusIptablesChain) {
		return false
	}
	return true
}

func nftCounterOnly(trim string) bool {
	fields := strings.Fields(trim)
	if len(fields) == 0 || fields[0] != "counter" {
		return false
	}
	if len(fields) == 1 {
		return true
	}
	return len(fields) >= 5 && fields[1] == "packets" && fields[3] == "bytes"
}
