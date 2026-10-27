package firewall

import (
	"strconv"
	"strings"
)

const capNetAdmin = 12

func capEffectiveHasNetAdmin(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "CapEff:")
		if !ok {
			continue
		}
		hex := strings.TrimSpace(rest)
		if hex == "" {
			return false
		}
		if len(hex) > 16 {
			hex = hex[len(hex)-16:]
		}
		value, err := strconv.ParseUint(hex, 16, 64)
		return err == nil && value&(1<<capNetAdmin) != 0
	}
	return false
}
