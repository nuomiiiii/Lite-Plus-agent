//go:build linux

package firewall

import v2 "github.com/nuomiiiii/lite-agent/protocol/v2"

func keepRules(intent v2.FirewallIntent) []v2.FirewallRule {
	rules := keepTCP(sshPortOf(intent), "SSH")
	for _, port := range detectedPanelListenPorts() {
		rules = append(rules, keepTCP(port, "panel")...)
	}
	return filterOmittedKeep(intent, rules)
}

func detectedPanelListenPorts() []string {
	if lookPath("ss") {
		if out, err := runCmd(cmdTimeout, "ss", "-lntp"); err == nil {
			if ports := parsePanelListenPorts(out); len(ports) > 0 {
				return ports
			}
		}
	}
	if lookPath("netstat") {
		if out, err := runCmd(cmdTimeout, "netstat", "-ltnp"); err == nil {
			return parsePanelListenPorts(out)
		}
	}
	return nil
}
