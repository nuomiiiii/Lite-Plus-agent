package firewall

import "testing"

func TestIptablesFilterOwnedByHostDetectsAnyHostInput(t *testing.T) {
	panel := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		jump 1PANEL_BASIC_AFTER
	}
	chain 1PANEL_BASIC_AFTER {
		ip protocol tcp drop
	}
}
`
	if !iptablesFilterOwnedByHost(panel, "") {
		t.Fatal("1Panel nft INPUT jumps must share the iptables table")
	}
	if !iptablesFilterOwnedByHost("", "*filter\n-A INPUT -j 1PANEL_BASIC\n-A 1PANEL_BASIC_AFTER -p tcp -j DROP\n") {
		t.Fatal("1Panel iptables-save INPUT jumps must share the iptables table")
	}

	baota := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		jump IN_BT
	}
	chain IN_BT {
		tcp dport 8888 accept
		drop
	}
}
`
	if !iptablesFilterOwnedByHost(baota, "") {
		t.Fatal("宝塔-style nft INPUT jumps must share the iptables table")
	}
	if !iptablesFilterOwnedByHost("", "*filter\n-A INPUT -j IN_BT\n-A IN_BT -j DROP\n") {
		t.Fatal("宝塔-style iptables INPUT jumps must share the iptables table")
	}

	if !iptablesFilterOwnedByHost("", "*filter\n-A INPUT -p tcp --dport 22 -j f2b-sshd\n") {
		t.Fatal("fail2ban INPUT jumps must share the iptables table")
	}
	if !iptablesFilterOwnedByHost("", "*filter\n-A INPUT -j LOCALINPUT\n-A LOCALINPUT -j DROP\n") {
		t.Fatal("CSF-style INPUT jumps must share the iptables table")
	}
	if !iptablesFilterOwnedByHost("", "*filter\n:INPUT DROP [0:0]\nCOMMIT\n") {
		t.Fatal("INPUT policy DROP is a host filter even with no extra rules")
	}
	if !iptablesFilterOwnedByHost("table ip filter { chain INPUT { type filter hook input priority filter; policy drop; } }", "") {
		t.Fatal("nft INPUT policy drop is a host filter")
	}

	if iptablesFilterOwnedByHost("table inet liteplus { chain input { tcp dport 22 accept } }", "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n") {
		t.Fatal("plain nft plus table must not force iptables backend")
	}
	if iptablesFilterOwnedByHost("", "*filter\n:INPUT ACCEPT [0:0]\n:LITE_PLUS - [0:0]\n-A INPUT -j LITE_PLUS\n-A LITE_PLUS -j DROP\nCOMMIT\n") {
		t.Fatal("Plus's own INPUT jump must not look like another host firewall")
	}
	if iptablesFilterOwnedByHost(`table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		counter packets 0 bytes 0
		jump LITE_PLUS
	}
	chain LITE_PLUS {
		drop
	}
}
`, "") {
		t.Fatal("nft Plus INPUT jump must not look like another host firewall")
	}
}
