package firewall

import (
	"strings"
	"testing"
)

func TestNftQuotedTokensSurviveNftArgvJoin(t *testing.T) {
	tokens := []string{
		"meta", "nfproto", "ipv4", "tcp", "dport", "42223", "accept",
		"comment", "lite-plus:KbAJgCJ5u1E19ehO",
	}
	unquoted := nftArgvJoin(append([]string{"insert", "rule", "inet", "filter", "input"}, tokens...))
	quoted := nftArgvJoin(append([]string{"insert", "rule", "inet", "filter", "input"}, nftQuotedTokens(tokens)...))
	if strings.Contains(unquoted, `comment "lite-plus:`) {
		t.Fatalf("unquoted argv would not hit the colon syntax error: %s", unquoted)
	}
	if !strings.Contains(unquoted, "comment lite-plus:KbAJgCJ5u1E19ehO") {
		t.Fatalf("unquoted argv must be the command that nft rejects: %s", unquoted)
	}
	if !nftJoinedCommentQuoted(quoted) {
		t.Fatalf("quoted argv must survive nft joining as a quoted comment: %s", quoted)
	}
	keep := nftQuotedTokens([]string{
		"meta", "nfproto", "ipv6", "tcp", "dport", "15321", "accept",
		"comment", "lite-plus:keep-v6-15321",
	})
	keepJoined := nftArgvJoin(keep)
	if !strings.Contains(keepJoined, `comment "lite-plus:keep-v6-15321"`) || strings.Contains(keepJoined, "comment lite-plus:keep-v6-15321") {
		t.Fatalf("keep v6 comment must be quoted after argv join: %s", keepJoined)
	}
}

func nftJoinedCommentQuoted(joined string) bool {
	i := strings.LastIndex(joined, " comment ")
	if i < 0 {
		return false
	}
	rest := strings.TrimSpace(joined[i+len(" comment "):])
	return strings.HasPrefix(rest, `"`) && strings.Contains(rest, "lite-plus:")
}
