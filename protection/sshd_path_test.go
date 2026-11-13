package protection

import "testing"

func TestDetectSSHDLogPathPrefersAuthLog(t *testing.T) {
	got := detectSSHDLogPath(func(path string) bool {
		return path == "/var/log/auth.log" || path == "/var/log/secure"
	}, true)
	if got != "/var/log/auth.log" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectSSHDLogPathUsesSecureThenJournal(t *testing.T) {
	got := detectSSHDLogPath(func(path string) bool { return path == "/var/log/secure" }, false)
	if got != "/var/log/secure" {
		t.Fatalf("got %q", got)
	}
	got = detectSSHDLogPath(func(string) bool { return false }, true)
	if got != "journal:sshd" {
		t.Fatalf("got %q", got)
	}
	got = detectSSHDLogPath(func(string) bool { return false }, false)
	if got != "" {
		t.Fatalf("got %q", got)
	}
}
