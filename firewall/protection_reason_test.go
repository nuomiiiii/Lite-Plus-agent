package firewall

import (
	"os"
	"strings"
	"testing"
)

func TestSkipProtectionInetTable(t *testing.T) {
	if !skipProtectionInetTable(protectionNftTable) {
		t.Fatal("must skip owned protection table")
	}
	if skipProtectionInetTable("filter") {
		t.Fatal("must not skip host filter")
	}
}

func TestProtectionBanDoesNotCallApply(t *testing.T) {
	src, err := os.ReadFile("protection.go")
	if err != nil {
		t.Fatal(err)
	}
	ban := extractProtectionFunc(string(src), "func ProtectionBan")
	if strings.Contains(ban, "firewall.Apply") || strings.Contains(ban, "Apply(cfg") || strings.Contains(ban, "Apply(state") {
		t.Fatal("incremental protection bans must not call firewall.Apply")
	}
}

func TestProtectionLogQueuesSummariesNotRawLines(t *testing.T) {
	src, err := os.ReadFile("protection_log.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if !strings.Contains(text, "enqueueProtectionReport") {
		t.Fatal("missing report queue")
	}
	if strings.Contains(text, "Hits: []v2.ProtectionBanReason{reason}") && strings.Contains(text, "URI:") {
		t.Fatal("must not queue raw URI")
	}
}
