package firewall

import "testing"

func TestParseNftInputHooksSkipsLiteplusAndFindsInetFilter(t *testing.T) {
	raw := `table inet liteplus {
	chain input {
		type filter hook input priority -150; policy accept;
		tcp dport 443 accept
	}
}
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		jump 1PANEL_BASIC
	}
}
`
	hooks := parseNftInputHooks(raw)
	if len(hooks) != 2 {
		t.Fatalf("hooks: %+v", hooks)
	}
	inet := foreignInetInputHooks(raw)
	if len(inet) != 1 || inet[0].Family != "inet" || inet[0].Table != "filter" || inet[0].Chain != "input" {
		t.Fatalf("inet: %+v", inet)
	}
}

func TestNftChainJumpsToPlus(t *testing.T) {
	listed := `chain input {
	jump LITE_PLUS # handle 7
	tcp dport 22 accept # handle 8
}
`
	if !nftChainJumpsToPlus(listed) {
		t.Fatal("jump must count")
	}
	got := nftJumpHandles(listed)
	if len(got) != 1 || got[0] != "7" {
		t.Fatalf("handles %v", got)
	}
	if nftChainJumpsToPlus("tcp dport 22 accept") {
		t.Fatal("plain accept is not a plus jump")
	}
}
