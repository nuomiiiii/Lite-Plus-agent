package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestProtectionReasonsKeepLatestExpiryAndSameEvent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	first := v2.ProtectionBanReason{
		BanID: "b1", EventID: "e1", IP: "203.0.113.10", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		Status: v2.ProtectionBanActive,
	}
	state := loadProtection()
	if _, err := upsertBanLocked(state, first); err != nil {
		t.Fatal(err)
	}
	retry := first
	retry.ExpiresAt = now.Add(30 * time.Minute).Format(time.RFC3339Nano)
	if _, err := upsertBanLocked(loadProtection(), retry); err != nil {
		t.Fatal(err)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].ExpiresAt != first.ExpiresAt {
		t.Fatalf("retry must not extend expiry: %+v", got.Reasons)
	}
	second := v2.ProtectionBanReason{
		BanID: "b2", EventID: "e2", IP: "203.0.113.10", ReasonType: v2.ProtectionReasonPathScan,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339Nano),
		Status: v2.ProtectionBanActive,
	}
	if _, err := upsertBanLocked(loadProtection(), second); err != nil {
		t.Fatal(err)
	}
	got = loadProtection()
	if len(got.Reasons) != 2 {
		t.Fatalf("two reasons: %+v", got.Reasons)
	}
	unban := ProtectionUnban(v2.ProtectionUnbanParams{IP: "203.0.113.10", Local: true})
	if unban.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", unban)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("local auto reasons remain %d", n)
	}
	_ = filepath.Join(dir, "x")
}

func TestProtectionIgnoresExpiredAndRevoked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	expired := v2.ProtectionBanReason{
		BanID: "b", EventID: "old", IP: "198.51.100.9", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Add(-20 * time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		GroupID:   "g1",
	}
	res := ProtectionBan(expired, 1)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatal(res.Error)
	}
	if len(loadProtection().Reasons) != 0 {
		t.Fatal("expired ban stored")
	}
	_ = os.WriteFile(filepath.Join(dir, "keep"), []byte("1"), 0o600)
}

func TestProtectionEventIDStaysInWindow(t *testing.T) {
	base := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
	first := protectionEventID(v2.ProtectionReasonRequestRate, "p1", "203.0.113.1", base, time.Time{}, 60)
	same := protectionEventID(v2.ProtectionReasonRequestRate, "p1", "203.0.113.1", base.Add(59*time.Second), time.Time{}, 60)
	next := protectionEventID(v2.ProtectionReasonRequestRate, "p1", "203.0.113.1", base.Add(60*time.Second), time.Time{}, 60)
	if first != same {
		t.Fatalf("same window %s vs %s", first, same)
	}
	if first == next {
		t.Fatal("next window must mint a new event")
	}
	reset := protectionEventID(v2.ProtectionReasonRequestRate, "p1", "203.0.113.1", base.Add(30*time.Second), base.Add(20*time.Second), 60)
	if reset == first {
		t.Fatal("unban reset must mint a new generation")
	}
}

func TestProtectionWhitelistDropsBan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	state := loadProtection()
	state.Config.Whitelist = []string{"203.0.113.8"}
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "w1", EventID: "w1", IP: "203.0.113.8", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		Status: v2.ProtectionBanActive,
	}, 0)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatal(res.Error)
	}
	if len(loadProtection().Reasons) != 0 {
		t.Fatal("whitelist must skip storing the ban")
	}
}

func TestProtectionGroupLeaveClearsGroupReasons(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	state := loadProtection()
	state.Reasons = []v2.ProtectionBanReason{{
		BanID: "g1", EventID: "g1", IP: "198.51.100.4", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp", Status: v2.ProtectionBanActive,
	}, {
		BanID: "l1", EventID: "l1", IP: "203.0.113.4", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		Status: v2.ProtectionBanActive,
	}}
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	res := ProtectionUnban(v2.ProtectionUnbanParams{GroupID: "grp", Revision: 3})
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].BanID != "l1" {
		t.Fatalf("leave must keep unrelated local reasons: %+v", got.Reasons)
	}
	if got.GroupApplied["grp"] != 3 {
		t.Fatalf("applied revision %v", got.GroupApplied)
	}
}

func TestProtectionBanResultCarriesGroup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "gban", EventID: "gban", IP: "203.0.113.20", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-a", Status: v2.ProtectionBanActive,
	}, 4)
	if res.Status != v2.ProtectionStatusOK || res.GroupID != "grp-a" || res.GroupRevision != 4 {
		t.Fatalf("%+v", res)
	}
	got := loadProtection()
	if got.GroupApplied["grp-a"] != 0 {
		t.Fatalf("incremental ban must not raise snapshot revision: %v", got.GroupApplied)
	}
	if got.GroupSeen["grp-a"] != 4 {
		t.Fatalf("incremental ban must record seen revision: %v", got.GroupSeen)
	}
}

func TestProtectionUnbanOneGroupKeepsAnother(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	state := loadProtection()
	state.Reasons = []v2.ProtectionBanReason{{
		BanID: "g1", EventID: "g1", IP: "198.51.100.8", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "g1", Status: v2.ProtectionBanActive,
	}, {
		BanID: "g2", EventID: "g2", IP: "198.51.100.8", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "g2", Status: v2.ProtectionBanActive,
	}}
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	res := ProtectionUnban(v2.ProtectionUnbanParams{IP: "198.51.100.8", GroupID: "g1", Revision: 2, Local: true, ResetAt: now.Format(time.RFC3339Nano)})
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].GroupID != "g2" {
		t.Fatalf("other group reason dropped: %+v", got.Reasons)
	}
}

func TestStaleGroupSnapshotDoesNotWipeNewerBan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "x1", EventID: "x1", IP: "203.0.113.40", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-x", Status: v2.ProtectionBanActive,
	}, 3)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	snap := ApplyProtectionGroupSnapshot(v2.ProtectionGroupSnapshot{Group: "grp-x", Revision: 2})
	if snap.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", snap)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].IP != "203.0.113.40" {
		t.Fatalf("stale snapshot wiped the newer ban: %+v", got.Reasons)
	}
}

func TestOldSharedBanWithNewerRevisionStaysRevoked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	resetAt := now.Add(-time.Minute)
	unban := ProtectionUnban(v2.ProtectionUnbanParams{
		IP: "203.0.113.70", GroupID: "grp-u", Revision: 12, ResetAt: resetAt.Format(time.RFC3339Nano),
	})
	if unban.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", unban)
	}
	old := ProtectionBan(v2.ProtectionBanReason{
		BanID: "old-e", EventID: "old-e", IP: "203.0.113.70", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: resetAt.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID:   "grp-u", Status: v2.ProtectionBanActive,
	}, 13)
	if old.Status != v2.ProtectionStatusOK || old.Error == "" {
		t.Fatalf("old hit with a newer revision must stay revoked: %+v", old)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("old hit was applied: %+v", loadProtection().Reasons)
	}
	fresh := ProtectionBan(v2.ProtectionBanReason{
		BanID: "new-e", EventID: "new-e", IP: "203.0.113.70", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID:   "grp-u", Status: v2.ProtectionBanActive,
	}, 13)
	if fresh.Status != v2.ProtectionStatusOK || fresh.Error != "" {
		t.Fatalf("new attack after reset must apply: %+v", fresh)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].EventID != "new-e" {
		t.Fatalf("new attack missing: %+v", got.Reasons)
	}
}

func TestOutOfOrderIncrementalBansKeepBothIPs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	later := ProtectionBan(v2.ProtectionBanReason{
		BanID: "y12", EventID: "y12", IP: "198.51.100.12", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-c", Status: v2.ProtectionBanActive,
	}, 12)
	if later.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", later)
	}
	earlier := ProtectionBan(v2.ProtectionBanReason{
		BanID: "x11", EventID: "x11", IP: "203.0.113.11", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-c", Status: v2.ProtectionBanActive,
	}, 11)
	if earlier.Status != v2.ProtectionStatusOK || earlier.Error != "" {
		t.Fatalf("earlier IP dropped: %+v", earlier)
	}
	got := loadProtection()
	if len(got.Reasons) != 2 {
		t.Fatalf("both incrementals must apply: %+v", got.Reasons)
	}
	unban := ProtectionUnban(v2.ProtectionUnbanParams{IP: "203.0.113.11", GroupID: "grp-c", Revision: 11, ResetAt: now.Format(time.RFC3339Nano)})
	if unban.Status != v2.ProtectionStatusOK || unban.Error != "" {
		t.Fatalf("earlier unban dropped: %+v", unban)
	}
	got = loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].IP != "198.51.100.12" {
		t.Fatalf("unban of X must keep Y: %+v", got.Reasons)
	}
}

func TestProtectionLogWorkerStartsWithoutSources(t *testing.T) {
	raw, err := os.ReadFile("protection_log.go")
	if err != nil {
		t.Fatal(err)
	}
	start := extractProtectionFunc(string(raw), "func startProtectionLogLocked")
	if !strings.Contains(start, "protectionHasNetworkPolicies") {
		t.Fatal("TCP observe must run even when no Caddy/Nginx source exists")
	}
	if !strings.Contains(start, "prevDone") || !strings.Contains(start, "<-prevDone") {
		t.Fatal("log worker restart must wait for the previous reader to exit")
	}
}

func TestApplyProtectionConfigKeepsOneSSHD(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	got := ApplyProtectionConfig(v2.ProtectionConfig{
		Revision: 1,
		Whitelist: []string{"192.0.2.8"},
		Sources: []v2.ProtectionLogSource{
			{ID: "s2", Format: v2.ProtectionLogSSHD, Path: "/var/log/auth.log", BindPort: "12560"},
			{ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "12560"},
		},
	})
	if got.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", got)
	}
	state := loadProtection()
	if len(state.Config.Sources) != 1 || state.Config.Sources[0].ID != "s1" {
		t.Fatalf("persist journal sshd: %+v", state.Config.Sources)
	}
	if len(state.Config.Whitelist) != 1 || state.Config.Whitelist[0] != "192.0.2.8" {
		t.Fatalf("whitelist dropped: %+v", state.Config.Whitelist)
	}
}

func TestApplyProtectionConfigAppliesWhitelistDespiteSSHDMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	got := ApplyProtectionConfig(v2.ProtectionConfig{
		Revision:  1,
		Enabled:   true,
		Whitelist: []string{"192.0.2.8"},
		Sources: []v2.ProtectionLogSource{{
			ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD, BindPort: "12560",
		}},
		Policies: []v2.ProtectionPolicy{{
			ID: "p1", Enabled: true, Protocol: "tcp", Port: "22", SourceID: "s1",
			RequestWindowSec: 60, RequestThreshold: 3,
		}},
	})
	if got.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", got)
	}
	state := loadProtection()
	if len(state.Config.Whitelist) != 1 || state.Config.Whitelist[0] != "192.0.2.8" {
		t.Fatalf("whitelist dropped: %+v", state.Config.Whitelist)
	}
}

func TestApplyProtectionConfigDisablesRuntimeWhenMasterOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	on := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 1, Enabled: true, RuntimeEnabled: true})
	if on.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", on)
	}
	off := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 2, Enabled: false, RuntimeEnabled: true})
	if off.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", off)
	}
	state := loadProtection()
	if state.RuntimeEnabled || state.Config.RuntimeEnabled {
		t.Fatalf("master off must drop runtime: %+v", state)
	}
}

func TestApplyProtectionConfigRejectsStaleRevision(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	newer := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 3, Enabled: true})
	if newer.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", newer)
	}
	stale := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 1, Enabled: false})
	if stale.Revision != 3 {
		t.Fatalf("stale overwrite: %+v", stale)
	}
	if !loadProtection().Config.Enabled {
		t.Fatal("stale config replaced current")
	}
}

func TestProtectionLinuxAppliesTableInOneTransaction(t *testing.T) {
	raw, err := os.ReadFile("protection_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	enable := extractProtectionFunc(text, "func enableProtectionRuntimeLocked")
	if strings.Contains(enable, `"nft", "delete", "table"`) {
		t.Fatal("delete table must stay inside the nft -f script so a failed add does not leave a gap")
	}
	apply := extractProtectionFunc(text, "func protectionApplyScript")
	if !strings.Contains(apply, "delete table inet") {
		t.Fatal("apply script must batch delete+add")
	}
	if strings.Contains(apply, "protectionTableLive()") {
		t.Fatal("apply must not skip delete when list table times out; nft -f would append")
	}
	if !strings.Contains(apply, "protectionEnsureInputChain()") {
		t.Fatal("apply must create the table before delete so a missing table cannot fail the whole nft -f")
	}
	table := extractProtectionFunc(text, "func protectionTableScript")
	if !strings.Contains(table, "false, state") {
		t.Fatal("live table must not attach NFLOG until a reader exists")
	}
	if strings.Contains(table, "flush chain") || strings.Contains(table, "protectionEnsureInputChain") {
		t.Fatal("table script must be the replacement body; delete+ensure belong in apply")
	}
	meter := extractProtectionFunc(text, "func protectionMeterLine")
	if !strings.Contains(meter, "counter") {
		t.Fatal("observe and enforce over-limit rules must expose nft counters")
	}
	base := extractProtectionFunc(text, "func protectionBaseScript")
	if !strings.Contains(base, "enabled = state.Config.Enabled") || !strings.Contains(base, "if enabled") {
		t.Fatal("master switch must control meter and connlimit rules")
	}
	if !strings.Contains(base, "protectionWhitelistBlock") || !strings.Contains(base, "protectionDestMatch") {
		t.Fatal("tcp limits must honor whitelist sets and bind_addr")
	}
	if !strings.Contains(base, "ct state established,related ct direction reply return") {
		t.Fatal("bans must drop established inbound and still allow replies to host-originated connections")
	}
	enabledAt := strings.Index(base, "if enabled {")
	dropAt := strings.Index(base, `ip saddr @" + protectionSetV4 + " drop`)
	wlAt := strings.Index(base, `ip saddr @wl4 return`)
	if enabledAt < 0 || dropAt < enabledAt {
		t.Fatal("master switch must also stop ban drops")
	}
	if wlAt < 0 || dropAt < wlAt {
		t.Fatal("whitelist must return before ban drops")
	}
	if !strings.Contains(text, "func readFileTail") {
		t.Fatal("log preview must seek a bounded tail")
	}
	if !strings.Contains(text, "func nftTCPPort") {
		t.Fatal("nft scripts must reject non-numeric ports")
	}
	probe := extractProtectionFunc(text, "func probeProtectionCapabilityLocked")
	if !strings.Contains(probe, "warmNft()") {
		t.Fatal("fresh nft must warm the kernel before syntax probes")
	}
	if !strings.Contains(probe, "nftCommandTimedOut") {
		t.Fatal("nft -c timeout must not be recorded as missing timeout sets")
	}
	if !strings.Contains(probe, "nftFeatureSupported(protectionProbeScript(\"meter\"))") ||
		!strings.Contains(probe, "nftFeatureSupported(protectionProbeScript(\"connlimit\"))") {
		t.Fatal("meter and connlimit probes must retry nft -c timeout and keep the rules after a warm-up timeout")
	}
	feature := extractProtectionFunc(text, "func nftFeatureSupported")
	if !strings.Contains(feature, "nftCommandTimedOut") {
		t.Fatal("meter and connlimit must treat a probe timeout as supported so the first table still has those rules")
	}
	if !strings.Contains(enable, "nftSyntaxErr(script)") {
		t.Fatal("enable nft -c must retry timeout like the feature probes")
	}
	boot := extractProtectionFunc(text, "func persistProtectionBootLocked")
	if strings.Contains(boot, "protectionBootState") {
		t.Fatal("boot files must persist remaining timeouts, not strip live IPs")
	}
	if !strings.Contains(boot, "protectionApplyScript(state)") {
		t.Fatal("boot nft must use the same delete+add script as live apply")
	}
	bootLinux, err := os.ReadFile("boot_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	bootText := string(bootLinux)
	loadStart := strings.Index(bootText, "load_prot() {")
	loadFile := strings.Index(bootText, `nft -f "$PROT_FILE"`)
	if loadStart < 0 || loadFile < 0 || loadStart > loadFile {
		t.Fatal("boot must load the protection table with nft -f")
	}
	loadProt := bootText[loadStart:loadFile]
	if strings.Contains(loadProt, "nft delete table") {
		t.Fatal("boot must not delete liteplus_protection outside nft -f; a failed add would leave a gap")
	}
}

func TestApplyProtectionConfigSkipsUnchangedRevision(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	cfg := v2.ProtectionConfig{Revision: 2, Enabled: true, Whitelist: []string{}, Sources: []v2.ProtectionLogSource{}, Policies: []v2.ProtectionPolicy{}}
	first := ApplyProtectionConfig(cfg)
	if first.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", first)
	}
	if loadProtection().ConfigAppliedRevision != 2 {
		t.Fatal("successful apply must record the applied revision")
	}
	second := ApplyProtectionConfig(cfg)
	if second.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", second)
	}
	raw, err := os.ReadFile("protection.go")
	if err != nil {
		t.Fatal(err)
	}
	apply := extractProtectionFunc(string(raw), "func ApplyProtectionConfig")
	if !strings.Contains(apply, "shouldSkipProtectionApply") || !strings.Contains(apply, "ConfigAppliedRevision") {
		t.Fatal("equal revision may skip only after a successful apply")
	}
	if strings.Contains(apply, "|| state.RuntimeEnabled") {
		t.Fatal("config must be able to turn runtime off")
	}
	if !strings.Contains(apply, "disableProtectionRuntimeLocked") {
		t.Fatal("runtime off must tear down the protection table")
	}
}

func TestFailedApplyDoesNotSkipRetry(t *testing.T) {
	cfg := v2.ProtectionConfig{Revision: 4, Enabled: true}
	state := &persistedProtection{Config: cfg, ConfigAppliedRevision: 0}
	if shouldSkipProtectionApply(state, cfg) {
		t.Fatal("a failed apply must run again")
	}
	state.ConfigAppliedRevision = cfg.Revision
	if !shouldSkipProtectionApply(state, cfg) {
		t.Fatal("a successful apply with the same content may skip")
	}
}

func TestOldUnbanDoesNotDeleteNewerSameIP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	t1 := now.Add(-time.Minute)
	t2 := now
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "x11", EventID: "x11", IP: "203.0.113.50", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: t2.Format(time.RFC3339Nano), ExpiresAt: t2.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-s", Status: v2.ProtectionBanActive,
	}, 11)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	unban := ProtectionUnban(v2.ProtectionUnbanParams{
		IP: "203.0.113.50", GroupID: "grp-s", Revision: 10, ResetAt: t1.Format(time.RFC3339Nano),
	})
	if unban.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", unban)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].EventID != "x11" {
		t.Fatalf("old unban deleted the newer ban: %+v", got.Reasons)
	}
}

func TestNewerUnbanStillDeletesSameIP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	t1 := now.Add(-time.Minute)
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "x11", EventID: "x11", IP: "203.0.113.51", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: t1.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-s", Status: v2.ProtectionBanActive,
	}, 11)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	unban := ProtectionUnban(v2.ProtectionUnbanParams{
		IP: "203.0.113.51", GroupID: "grp-s", Revision: 12, ResetAt: t1.Add(time.Second).Format(time.RFC3339Nano),
	})
	if unban.Status != v2.ProtectionStatusOK || unban.Error != "" {
		t.Fatalf("%+v", unban)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("newer unban must delete the older ban: %d", n)
	}
}

func TestFailedBanRetryMustSyncAndKeepExpiry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	first := v2.ProtectionBanReason{
		BanID: "e-fail", EventID: "e-fail", IP: "203.0.113.60", ReasonType: v2.ProtectionReasonRequestRate,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		Status: v2.ProtectionBanActive,
	}
	protectionBanSyncTest = func(*persistedProtection) error {
		return errors.New("nft failed")
	}
	t.Cleanup(func() { protectionBanSyncTest = nil })
	if _, err := upsertBanLocked(loadProtection(), first); err == nil {
		t.Fatal("first nft failure must surface")
	}
	if n := len(loadProtection().Reasons); n != 1 {
		t.Fatalf("failed sync must keep the reason for retry: %d", n)
	}
	retry := first
	retry.ExpiresAt = now.Add(30 * time.Minute).Format(time.RFC3339Nano)
	if _, err := upsertBanLocked(loadProtection(), retry); err == nil {
		t.Fatal("repeat must keep trying while nft fails")
	}
	protectionBanSyncTest = nil
	applied, err := upsertBanLocked(loadProtection(), retry)
	if err != nil || len(applied) != 1 {
		t.Fatalf("recovery must report the original ban: %+v %v", applied, err)
	}
	if applied[0].ExpiresAt != first.ExpiresAt {
		t.Fatalf("retry must not renew expiry: %s", applied[0].ExpiresAt)
	}
}

func TestEqualRevisionSnapshotDoesNotRestoreRevokedIP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	res := ProtectionBan(v2.ProtectionBanReason{
		BanID: "x12", EventID: "x12", IP: "203.0.113.61", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-t", Status: v2.ProtectionBanActive,
	}, 11)
	if res.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", res)
	}
	unban := ProtectionUnban(v2.ProtectionUnbanParams{
		IP: "203.0.113.61", GroupID: "grp-t", Revision: 12, ResetAt: now.Format(time.RFC3339Nano),
	})
	if unban.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", unban)
	}
	stale := ApplyProtectionGroupSnapshot(v2.ProtectionGroupSnapshot{
		Group:    "grp-t",
		Revision: 12,
		Bans: []v2.ProtectionBanReason{{
			BanID: "x12", EventID: "x12", IP: "203.0.113.61", ReasonType: v2.ProtectionReasonShared,
			CreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			GroupID: "grp-t", Status: v2.ProtectionBanActive,
		}},
	})
	if stale.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", stale)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("same-revision snapshot restored the revoked IP: %+v", loadProtection().Reasons)
	}
}

func TestFirstSyncSnapshotHonorsRevokeResetAt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	resetAt := now.Add(-time.Minute)
	old := ApplyProtectionGroupSnapshot(v2.ProtectionGroupSnapshot{
		Group:    "grp-v",
		Revision: 13,
		Bans: []v2.ProtectionBanReason{{
			BanID: "old-e", EventID: "old-e", IP: "203.0.113.80", ReasonType: v2.ProtectionReasonShared,
			CreatedAt: resetAt.Add(-time.Minute).Format(time.RFC3339Nano),
			ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			GroupID:   "grp-v", Status: v2.ProtectionBanActive,
		}},
		Revoked: map[string]v2.ProtectionRevoke{
			"203.0.113.80": {Revision: 12, ResetAt: resetAt.Format(time.RFC3339Nano)},
		},
	})
	if old.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", old)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("first sync restored a pre-unban hit: %+v", loadProtection().Reasons)
	}
	fresh := ApplyProtectionGroupSnapshot(v2.ProtectionGroupSnapshot{
		Group:    "grp-v",
		Revision: 14,
		Bans: []v2.ProtectionBanReason{{
			BanID: "new-e", EventID: "new-e", IP: "203.0.113.80", ReasonType: v2.ProtectionReasonShared,
			CreatedAt: now.Format(time.RFC3339Nano),
			ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			GroupID:   "grp-v", Status: v2.ProtectionBanActive,
		}},
		Revoked: map[string]v2.ProtectionRevoke{
			"203.0.113.80": {Revision: 12, ResetAt: resetAt.Format(time.RFC3339Nano)},
		},
	})
	if fresh.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", fresh)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].EventID != "new-e" {
		t.Fatalf("new attack after reset must apply: %+v", got.Reasons)
	}
}

func TestNewerSnapshotAfterUnbanAppliesNewAttack(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	resetAt := now.Add(-time.Minute)
	_ = ProtectionBan(v2.ProtectionBanReason{
		BanID: "old", EventID: "old", IP: "203.0.113.62", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: resetAt.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-n", Status: v2.ProtectionBanActive,
	}, 11)
	_ = ProtectionUnban(v2.ProtectionUnbanParams{
		IP: "203.0.113.62", GroupID: "grp-n", Revision: 12, ResetAt: resetAt.Format(time.RFC3339Nano),
	})
	fresh := ApplyProtectionGroupSnapshot(v2.ProtectionGroupSnapshot{
		Group:    "grp-n",
		Revision: 13,
		Bans: []v2.ProtectionBanReason{{
			BanID: "new", EventID: "new", IP: "203.0.113.62", ReasonType: v2.ProtectionReasonShared,
			CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
			GroupID: "grp-n", Status: v2.ProtectionBanActive, ObservedRevision: 13,
		}},
	})
	if fresh.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", fresh)
	}
	got := loadProtection()
	if len(got.Reasons) != 1 || got.Reasons[0].EventID != "new" {
		t.Fatalf("new attack after unban must apply: %+v", got.Reasons)
	}
}

func TestLocalUnbanRejectsGroupedReason(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	now := time.Now().UTC()
	_ = ProtectionBan(v2.ProtectionBanReason{
		BanID: "g1", EventID: "g1", IP: "203.0.113.63", ReasonType: v2.ProtectionReasonShared,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		GroupID: "grp-l", Status: v2.ProtectionBanActive,
	}, 4)
	res := ProtectionUnban(v2.ProtectionUnbanParams{IP: "203.0.113.63", Local: true})
	if res.Status == v2.ProtectionStatusOK {
		t.Fatalf("grouped reason must not accept local unban: %+v", res)
	}
	if n := len(loadProtection().Reasons); n != 1 {
		t.Fatalf("grouped reason dropped: %d", n)
	}
}

func TestProtectionBootKeepsUnexpiredIPs(t *testing.T) {
	now := time.Now().UTC()
	state := &persistedProtection{
		RuntimeEnabled: true,
		Reasons: []v2.ProtectionBanReason{{
			IP: "203.0.113.9", EventID: "e", BanID: "e",
			ExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		}, {
			IP: "203.0.113.10", EventID: "old", BanID: "old",
			ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		}},
	}
	got := activeIPs(state, now)
	if _, ok := got["203.0.113.9"]; !ok {
		t.Fatal("unexpired IP missing from boot/live set")
	}
	if _, ok := got["203.0.113.10"]; ok {
		t.Fatal("expired IP must not be written into nft timeout")
	}
}

func TestAckProtectionReportsKeepsLaterItems(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	logMu.Lock()
	reportQueue = []v2.ProtectionReportParams{{Kind: "a"}, {Kind: "b"}, {Kind: "c"}}
	logMu.Unlock()
	AckProtectionReports(2)
	got := PeekProtectionReports()
	if len(got) != 1 || got[0].Kind != "c" {
		t.Fatalf("later reports dropped: %+v", got)
	}
}

func TestProtectionPermanentBanStaysActive(t *testing.T) {
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	reason := v2.ProtectionBanReason{
		IP: "203.0.113.40", ExpiresAt: v2.FormatProtectionBanExpiry(now, v2.ProtectionBanPermanentSec),
	}
	if expiredReason(reason, now) || expiredReason(reason, now.Add(365*24*time.Hour)) {
		t.Fatal("permanent ban must not expire")
	}
	if remainingTimeout(reason, now) != protectionForeverTimeout {
		t.Fatal("remaining timeout")
	}
	if protectionNftTimeoutSec(remainingTimeout(reason, now)) != -1 {
		t.Fatal("nft timeout")
	}
	timed := map[string]time.Duration{"203.0.113.40": time.Minute}
	forever := map[string]time.Duration{"203.0.113.40": protectionForeverTimeout}
	if protectionBanFingerprint(timed, now) == protectionBanFingerprint(forever, now) {
		t.Fatal("fingerprint must distinguish permanent bans")
	}
	if timeoutNeedsUpdate(-1, -1) {
		t.Fatal("live permanent element must stay")
	}
	if !timeoutNeedsUpdate(60, -1) || !timeoutNeedsUpdate(-1, 60) {
		t.Fatal("timed and permanent must rewrite")
	}
	state := &persistedProtection{Reasons: []v2.ProtectionBanReason{reason}}
	got := activeIPs(state, now)
	if !foreverTimeout(got["203.0.113.40"]) {
		t.Fatalf("%v", got)
	}
}

func TestProtectionBanFingerprintIncludesExpiry(t *testing.T) {
	now := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	short := map[string]time.Duration{"203.0.113.9": time.Minute}
	long := map[string]time.Duration{"203.0.113.9": 3 * time.Minute}
	if protectionBanFingerprint(short, now) == protectionBanFingerprint(long, now) {
		t.Fatal("fingerprint must change when the same IP gets a later expiry")
	}
	if !timeoutNeedsUpdate(60, 150) {
		t.Fatal("live timeout must be rewritten when remaining time jumps")
	}
	if timeoutNeedsUpdate(58, 60) {
		t.Fatal("one-second drift must not rewrite the set")
	}
	got := parseNftSetTimeouts("elements = { 203.0.113.1 timeout 59s, 203.0.113.2 timeout 1m30s }")
	if got["203.0.113.1"] != 59 || got["203.0.113.2"] != 90 {
		t.Fatalf("%v", got)
	}
	remain := parseNftSetTimeouts("elements = {\n  203.0.113.1 timeout 10s expires 8s,\n  203.0.113.2 timeout 30s expires 29s }")
	if remain["203.0.113.1"] != 8 || remain["203.0.113.2"] != 29 {
		t.Fatalf("expires remaining time ignored: %v", remain)
	}
}

func TestApplyProtectionConfigHonorsRuntimeOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	on := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 1, RuntimeEnabled: true, Enabled: true})
	if on.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", on)
	}
	if !loadProtection().RuntimeEnabled {
		t.Fatal("runtime should enable when config asks")
	}
	off := ApplyProtectionConfig(v2.ProtectionConfig{Revision: 2, RuntimeEnabled: false, Enabled: true})
	if off.Status != v2.ProtectionStatusOK {
		t.Fatalf("%+v", off)
	}
	got := loadProtection()
	if got.RuntimeEnabled {
		t.Fatal("runtime stayed on after config turned it off")
	}
	if got.Config.Revision != 2 {
		t.Fatalf("revision %d", got.Config.Revision)
	}
}

func TestProtectionPreviewPathIsRestricted(t *testing.T) {
	state := &persistedProtection{Config: v2.ProtectionConfig{Sources: []v2.ProtectionLogSource{{
		ID: "s1", Path: "/opt/app/access.json", Format: v2.ProtectionLogCaddyJSON,
	}}}}
	if protectionPreviewPathAllowed(state, "", "/etc/shadow") {
		t.Fatal("must not preview arbitrary files")
	}
	if protectionPreviewPathAllowed(state, "s1", "/etc/shadow") {
		t.Fatal("source id must not unlock a different path")
	}
	if !protectionPreviewPathAllowed(state, "s1", "/opt/app/access.json") {
		t.Fatal("configured source path must preview")
	}
	if !protectionPreviewPathAllowed(state, "", "/var/log/nginx/access.log") {
		t.Fatal("unsaved drafts under /var/log must preview")
	}
	if protectionPreviewPathAllowed(state, "", "/var/log/../etc/shadow") {
		t.Fatal("path escape must be rejected")
	}
	if !protectionPreviewPathAllowed(state, "", v2.ProtectionJournalSSHD) {
		t.Fatal("unsaved journal:sshd drafts must preview")
	}
	if protectionPreviewPathAllowed(state, "s1", v2.ProtectionJournalSSHD) {
		t.Fatal("caddy source id must not unlock journal preview")
	}
}

func TestWatchDoesNotForceProtectionEveryTick(t *testing.T) {
	raw, err := os.ReadFile("watch.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	ensureStacks := extractProtectionFunc(text, "func ensureStacks")
	if !strings.Contains(ensureStacks, "restoreProtectionIfNeeded()") {
		t.Fatal("unchanged stacks must not rebuild protection every second")
	}
	if strings.Count(ensureStacks, "RestoreProtectionLocked()") != 1 {
		t.Fatal("only a host stack change should force protection restore")
	}
	ensureOwned := extractProtectionFunc(text, "func ensureOwned")
	if !strings.Contains(ensureOwned, "restoreProtectionIfNeeded()") {
		t.Fatal("owned watch must skip healthy protection restores")
	}
}

func TestFailedApplyDoesNotLatchRuntime(t *testing.T) {
	raw, err := os.ReadFile("protection.go")
	if err != nil {
		t.Fatal(err)
	}
	apply := extractProtectionFunc(string(raw), "func ApplyProtectionConfig")
	if !strings.Contains(apply, "state.RuntimeEnabled = false") || !strings.Contains(apply, "disableProtectionRuntimeLocked") {
		t.Fatal("failed enable must roll runtime back")
	}
	restore := extractProtectionFunc(string(raw), "func restoreProtectionLocked")
	if !strings.Contains(restore, "protectionEnableBackoff") {
		t.Fatal("missing table must back off instead of retrying nft every second")
	}
}

func TestParseProtectionCounters(t *testing.T) {
	raw := "tcp dport 443 ct state new meter syn4_p { ip saddr timeout 60s limit rate over 8/second burst 8 packets } counter packets 12 bytes 800"
	got := parseProtectionCounters(raw)
	if len(got) != 1 || got[0].Dport != 443 || !strings.Contains(got[0].Prefix, "12") {
		t.Fatalf("%+v", got)
	}
}

func extractProtectionFunc(src, signature string) string {
	start := strings.Index(src, signature)
	if start < 0 {
		return ""
	}
	rest := src[start:]
	depth := 0
	for i, r := range rest {
		if r == '{' {
			depth++
		}
		if r == '}' {
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
