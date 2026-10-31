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

func TestAttachableInetHooksSkipsUfwAndFirewalld(t *testing.T) {
	hooks := attachableInetHooks([]nftInputHook{
		{Family: "inet", Table: "filter", Chain: "input"},
		{Family: "inet", Table: "ufw-user-input", Chain: "input"},
		{Family: "inet", Table: "firewalld", Chain: "filter_INPUT"},
	})
	if len(hooks) != 1 || hooks[0].Table != "filter" {
		t.Fatalf("only distro inet filter should be attached: %+v", hooks)
	}
}

func TestNftInetHeadLiveRequiresBaseAllows(t *testing.T) {
	jumpOnly := `chain input {
	jump LITE_PLUS # handle 7
	tcp dport 22 accept # handle 8
}
`
	if nftInetHeadLive(jumpOnly, false) != true {
		t.Fatal("jump is enough when plus has no base allows")
	}
	if nftInetHeadLive(jumpOnly, true) {
		t.Fatal("jumped accept is not enough when plus allows must sit in the host input chain")
	}
	withAllow := `chain input {
	meta nfproto ipv4 tcp dport 45633 accept comment "lite-plus:abc" # handle 9
	jump LITE_PLUS # handle 7
}
`
	if !nftInetHeadLive(withAllow, true) {
		t.Fatal("jump plus marked allows must count as live")
	}
	withoutHandles := `chain input {
	meta nfproto ipv4 tcp dport 45633 accept comment "lite-plus:abc"
	jump LITE_PLUS
}
`
	if !nftInetHeadLive(withoutHandles, true) {
		t.Fatal("nftables 1.1.3 omits # handle without -a; marked allows must still count as live")
	}
}

func TestNftPlusCommentHandles(t *testing.T) {
	listed := `chain input {
	jump LITE_PLUS # handle 7
	meta nfproto ipv4 tcp dport 45633 accept comment "lite-plus:abc" # handle 9
	tcp dport 22 accept # handle 8
}
`
	got := nftPlusCommentHandles(listed)
	if len(got) != 1 || got[0] != "9" {
		t.Fatalf("handles %v", got)
	}
}
