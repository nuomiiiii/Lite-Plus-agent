//go:build windows

package firewall

import "strings"

func engOwned(_ backend) bool {
	out, err := runCmd(cmdTimeout, "netsh", "advfirewall", "firewall", "show", "rule", "group="+windowsGroup)
	if err != nil {
		return false
	}
	return strings.Contains(out, windowsGroup)
}
