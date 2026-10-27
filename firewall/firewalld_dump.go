package firewall

import "strings"

const firewalldHostMark = "FIREWALLD_HOST_V1\n"

func parseFirewalldHostDump(text string) (services, ports []string) {
	rest, ok := strings.CutPrefix(text, firewalldHostMark)
	if !ok {
		return nil, nil
	}
	for _, line := range strings.Split(rest, "\n") {
		if value, found := strings.CutPrefix(line, "SERVICES "); found {
			services = strings.Fields(value)
			continue
		}
		if value, found := strings.CutPrefix(line, "PORTS "); found {
			ports = strings.Fields(value)
		}
	}
	return services, ports
}
