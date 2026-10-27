package firewall

import (
	"strings"
	"testing"
)

func TestParseFirewalldHostDump(t *testing.T) {
	services, ports := parseFirewalldHostDump("firewalld-runtime")
	if len(services) != 0 || len(ports) != 0 {
		t.Fatalf("runtime token must not look like a host dump: %v %v", services, ports)
	}
	services, ports = parseFirewalldHostDump(firewalldHostMark + "SERVICES ssh dhcpv6-client\nPORTS 443/tcp 53/udp\n")
	if strings.Join(services, " ") != "ssh dhcpv6-client" || strings.Join(ports, " ") != "443/tcp 53/udp" {
		t.Fatalf("got services=%v ports=%v", services, ports)
	}
}
