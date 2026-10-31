package firewall

import "strings"

func nftQuotedTokens(tokens []string) []string {
	out := append([]string(nil), tokens...)
	n := len(out)
	if n < 2 || out[n-2] != "comment" {
		return out
	}
	mark := strings.ReplaceAll(out[n-1], `"`, "")
	out[n-1] = `"` + mark + `"`
	return out
}

// nftArgvJoin matches nft src/main.c: remaining argv is strcat'd with spaces
// then parsed as nft syntax (nft_run_cmd_from_buffer).
func nftArgvJoin(args []string) string {
	return strings.Join(args, " ")
}
