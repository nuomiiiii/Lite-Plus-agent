package firewall

import "strings"

func ufwConfEnabled(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		key, val, ok := strings.Cut(trim, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "ENABLED") {
			return strings.EqualFold(strings.TrimSpace(val), "yes")
		}
	}
	return false
}
