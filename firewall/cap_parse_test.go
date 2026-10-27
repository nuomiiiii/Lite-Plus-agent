package firewall

import "testing"

func TestCapEffectiveHasNetAdmin(t *testing.T) {
	if capEffectiveHasNetAdmin("") || capEffectiveHasNetAdmin("Name:\tagent\n") {
		t.Fatal("missing CapEff must not look privileged")
	}
	if capEffectiveHasNetAdmin("CapEff:\t0000000000000000\n") {
		t.Fatal("empty capability set must not look privileged")
	}
	if !capEffectiveHasNetAdmin("CapEff:\t0000000000001000\n") {
		t.Fatal("CAP_NET_ADMIN without root must look privileged")
	}
	if !capEffectiveHasNetAdmin("CapEff:\t000001ffffffffff\n") {
		t.Fatal("full root capability set must include CAP_NET_ADMIN")
	}
}
