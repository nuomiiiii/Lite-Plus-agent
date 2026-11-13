//go:build linux

package firewall

import (
	"strings"
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const protectionAuditTable = "liteplus_protection_audit"

func TestProtectionApplyScriptNftCheckAndReplace(t *testing.T) {
	t.Setenv("AGENT_DATA_DIR", t.TempDir())
	if !lookPath("nft") {
		t.Skip("nft not present")
	}
	state := &persistedProtection{
		RuntimeEnabled: true,
		Config: v2.ProtectionConfig{
			Enabled: true,
			Policies: []v2.ProtectionPolicy{{
				ID:        "auditp1",
				Enabled:   true,
				Protocol:  "tcp",
				Port:      "22",
				Mode:      v2.ProtectionModeEnforce,
				SynRate:   8,
				SynBurst:  8,
				ConnLimit: 8,
			}},
		},
	}
	name := sanitizeNftName("auditp1")
	orig := protectionApplyScript(state)
	if strings.Count(orig, "ip saddr @"+protectionSetV4+" drop") != 1 {
		t.Fatalf("apply script must emit one ban4 drop\n%s", orig)
	}
	if del := strings.Index(orig, "delete table inet "+protectionNftTable); del < 0 || del > strings.Index(orig, "ip saddr @"+protectionSetV4+" drop") {
		t.Fatal("delete must stay in the same nft -f script and run before ban drops")
	}
	if strings.Contains(orig, "flush chain inet "+protectionNftTable) {
		t.Fatal("apply script must replace by delete+add, not flush then append")
	}

	script := protectionAuditApplyScript(true, true, state)
	if !strings.Contains(script, "meter syn4_"+name) || !strings.Contains(script, "meter cl4_"+name) {
		t.Fatalf("audit script must include syn meter and connlimit so replace can count them\n%s", script)
	}
	if strings.Count(script, "ct state new meter syn4_"+name) != 1 || strings.Count(script, "tcp dport 22 meter cl4_"+name) != 1 {
		t.Fatalf("audit script must emit one v4 meter and one v4 connlimit\n%s", script)
	}
	if err := nftSyntaxErr(script); err != nil {
		t.Fatalf("nft -c: %v\n%s", err, script)
	}
	if !privileged() {
		t.Skip("nft -f replace requires CAP_NET_ADMIN")
	}
	t.Cleanup(func() {
		_, _ = runCmd(cmdTimeout, "nft", "delete", "table", "inet", protectionAuditTable)
	})
	if _, err := runCmdStdin(cmdTimeout, script, "nft", "-f", "-"); err != nil {
		t.Fatalf("first nft -f: %v", err)
	}
	if _, err := runCmdStdin(cmdTimeout, script, "nft", "-f", "-"); err != nil {
		t.Fatalf("second nft -f: %v", err)
	}
	out, err := runCmd(cmdTimeout, "nft", "list", "table", "inet", protectionAuditTable)
	if err != nil {
		t.Fatal(err)
	}
	mustOccur(t, out, "saddr @"+protectionSetV4+" drop", 1)
	mustOccur(t, out, "update @syn4_"+name, 1)
	mustOccur(t, out, "update @syn6_"+name, 1)
	mustOccur(t, out, "add @cl4_"+name, 1)
	mustOccur(t, out, "add @cl6_"+name, 1)
}

func protectionAuditApplyScript(meter, connlimit bool, state *persistedProtection) string {
	body := strings.ReplaceAll(protectionBaseScript(meter, connlimit, false, state), protectionNftTable, protectionAuditTable)
	ensure := strings.ReplaceAll(protectionEnsureInputChain(), protectionNftTable, protectionAuditTable)
	return ensure + "delete table inet " + protectionAuditTable + "\n" + body
}

func mustOccur(t *testing.T, haystack, needle string, want int) {
	t.Helper()
	if got := strings.Count(haystack, needle); got != want {
		t.Fatalf("%q count=%d want=%d\n%s", needle, got, want, haystack)
	}
}
