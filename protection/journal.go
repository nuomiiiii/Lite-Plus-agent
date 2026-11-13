package protection

import (
	"strings"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func IsJournalPath(path string) bool {
	return v2.IsProtectionJournalPath(path)
}

func journalIdentArgs() []string {
	return []string{"-t", "sshd", "-t", "sshd-session", "-t", "ssh"}
}

func trimJournalLines(raw string, limit int) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
