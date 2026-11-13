package protection

import (
	"os"
	"os/exec"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

var sshdLogCandidates = []string{"/var/log/auth.log", "/var/log/secure"}

func DetectSSHDLogPath() string {
	return detectSSHDLogPath(func(path string) bool {
		info, err := os.Stat(path)
		return err == nil && info != nil && !info.IsDir()
	}, journalctlAvailable())
}

func journalctlAvailable() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

func detectSSHDLogPath(exists func(string) bool, journal bool) string {
	for _, path := range sshdLogCandidates {
		if exists(path) {
			return path
		}
	}
	if journal {
		return v2.ProtectionJournalSSHD
	}
	return ""
}
