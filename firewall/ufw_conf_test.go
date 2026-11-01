package firewall

import "testing"

func TestUfwConfEnabled(t *testing.T) {
	if ufwConfEnabled("ENABLED=no\n") {
		t.Fatal("disabled ufw must not look active")
	}
	if ufwConfEnabled("# ENABLED=yes\nENABLED=no\n") {
		t.Fatal("commented yes must not override ENABLED=no")
	}
	if !ufwConfEnabled("ENABLED=yes\n") {
		t.Fatal("enabled ufw must look active")
	}
	if !ufwConfEnabled("ENABLED = YES\n") {
		t.Fatal("ufw conf keys are case-insensitive")
	}
	if ufwConfEnabled("") {
		t.Fatal("missing ENABLED must not look active")
	}
}
