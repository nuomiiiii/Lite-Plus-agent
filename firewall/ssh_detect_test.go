package firewall

import (
	"strings"
	"testing"
)

func TestParseSSHConfigPortsReadsDropinsAndSkipsComments(t *testing.T) {
	main := parseSSHConfigPorts(`#Port 22
Port 2222
Include /etc/ssh/sshd_config.d/*.conf
Match User joe
Port 9
`)
	if preferSSHPort(main) != "2222" {
		t.Fatalf("main: %v", main)
	}
	drop := parseSSHConfigPorts("Port 2200 # custom\n")
	if preferSSHPort(drop) != "2200" {
		t.Fatalf("drop: %v", drop)
	}
	if !sshConfigIncludesDropins("Include /etc/ssh/sshd_config.d/*.conf\n") {
		t.Fatal("include dropins")
	}
	if sshConfigIncludesDropins("# Include /etc/ssh/sshd_config.d/*.conf\nPort 2222\n") {
		t.Fatal("commented include must not count as drop-in")
	}
	includes := parseSSHConfigIncludes("Include /etc/ssh/sshd_config.d/*.conf\n", "/etc/ssh")
	if len(includes) != 1 || includes[0] != "/etc/ssh/sshd_config.d/*.conf" {
		t.Fatalf("includes: %v", includes)
	}
}

func TestParseSSHListenPortsUsesSshdSocketNotHardcoded22(t *testing.T) {
	ss := `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))
LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=12,fd=4))
LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("ssh-agent",pid=9,fd=3))
`
	got := parseSSHListenPorts(ss)
	if preferSSHPort(got) != "2222" {
		t.Fatalf("ss: %v", got)
	}
	netstat := `tcp 0 0 0.0.0.0:2201 0.0.0.0:* LISTEN 88/sshd
tcp 0 0 :::2201 :::* LISTEN 88/sshd
`
	got = parseSSHListenPorts(netstat)
	if preferSSHPort(got) != "2201" {
		t.Fatalf("netstat: %v", got)
	}
}

func TestPickDetectedSSHPortPrefersListenThenConfig(t *testing.T) {
	if got := pickDetectedSSHPort([]string{"2222"}, []string{"22"}, true); got != "2222" {
		t.Fatalf("listen wins: %q", got)
	}
	if got := pickDetectedSSHPort(nil, []string{"2200"}, true); got != "2200" {
		t.Fatalf("config: %q", got)
	}
	if got := pickDetectedSSHPort(nil, nil, true); got != "22" {
		t.Fatalf("sshd default: %q", got)
	}
	if got := pickDetectedSSHPort(nil, nil, false); got != "" {
		t.Fatalf("no sshd: %q", got)
	}
}

func TestRewriteSSHConfigPortCommentsOldListen(t *testing.T) {
	got := rewriteSSHConfigPort("Port 22\nPermitRootLogin no\n", "2222")
	if !containsLine(got, "# Port 22") || !containsLine(got, "Port 2222") {
		t.Fatalf("%q", got)
	}
	body := plusSSHDropinBody("2200")
	if body != "# Managed by Lite Plus.\nPort 2200\n" {
		t.Fatalf("%q", body)
	}
}

func TestParsePanelListenPortsSkipsAgent(t *testing.T) {
	ss := `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 4096 0.0.0.0:28777 0.0.0.0:* users:(("Lite-Plus",pid=8,fd=6))
LISTEN 0 4096 *:37888 *:* users:(("Lite-Plus",pid=8,fd=7))
LISTEN 0 128 0.0.0.0:18293 0.0.0.0:* users:(("Lite-Plus-agent",pid=9,fd=3))
`
	got := parsePanelListenPorts(ss)
	if preferSSHPort(got) != "28777" && preferSSHPort(got) != "37888" {
		t.Fatalf("panel ports: %v", got)
	}
	for _, port := range got {
		if port == "18293" {
			t.Fatalf("agent listen must not become a panel keep: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want two panel ports, got %v", got)
	}
}

func containsLine(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if line == want {
			return true
		}
	}
	return false
}
