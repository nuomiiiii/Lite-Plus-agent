package firewall

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/protection"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func resetProtectionLogTestState() {
	logMu.Lock()
	reportQueue = nil
	reportedEvents = map[string]struct{}{}
	logStats = map[string]v2.ProtectionSourceStats{}
	liveResets = map[string]time.Time{}
	lastStatsAt = time.Time{}
	lastNflogAt = time.Time{}
	logMu.Unlock()
	rateCounter = protection.NewCounter(50000)
	pathCounter = protection.NewCounter(50000)
}

func TestApplyLogPolicyHonorsOwnWindow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	short := v2.ProtectionPolicy{
		ID: "a", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1,
	}
	long := v2.ProtectionPolicy{
		ID: "b", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 3600, RequestThreshold: 1,
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Policies: []v2.ProtectionPolicy{short, long}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	src := v2.ProtectionLogSource{ID: "s1"}
	old := protection.Record{Time: now.Add(-10 * time.Minute), IP: "203.0.113.80"}
	applyLogPolicy(cfg, short, src, old, "203.0.113.80", now)
	if n := len(PeekProtectionReports()); n != 0 {
		t.Fatalf("stale short-window log banned: %d", n)
	}
	applyLogPolicy(cfg, long, src, old, "203.0.113.80", now)
	if n := len(PeekProtectionReports()); n != 1 {
		t.Fatalf("long-window log should still hit: %d", n)
	}
	resetProtectionLogTestState()
	fresh := protection.Record{Time: now, IP: "203.0.113.81"}
	applyLogPolicy(cfg, short, src, fresh, "203.0.113.81", now)
	if n := len(PeekProtectionReports()); n != 1 {
		t.Fatalf("fresh short-window log must still hit: %d", n)
	}
}

func TestSamePolicyUsesSeparateDetectionWindows(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1,
		PathWindowSec: 3600, PathThreshold: 1, Paths: []string{"/admin"},
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	old := protection.Record{Time: now.Add(-10 * time.Minute), IP: "203.0.113.82", Path: "/admin"}
	applyLogPolicy(cfg, policy, v2.ProtectionLogSource{ID: "s1"}, old, "203.0.113.82", now)
	got := PeekProtectionReports()
	if len(got) != 1 || len(got[0].Hits) != 1 || got[0].Hits[0].ReasonType != v2.ProtectionReasonPathScan {
		t.Fatalf("10-minute-old log must hit the hour path window only: %+v", got)
	}
}

func TestSourceBindsHonorsLocalAddr(t *testing.T) {
	policy := v2.ProtectionPolicy{Protocol: "tcp", Port: "443", BindAddr: "192.0.2.10"}
	src := v2.ProtectionLogSource{BindProtocol: "tcp", BindPort: "443", BindAddr: "192.0.2.10"}
	rec := protection.Record{Transport: "tcp", ServerPort: 443}
	if !sourceBinds(src, policy, rec) {
		t.Fatal("matching source bind must count")
	}
	other := src
	other.BindAddr = "192.0.2.11"
	if sourceBinds(other, policy, rec) {
		t.Fatal("other local address must not count")
	}
	unbound := v2.ProtectionLogSource{BindProtocol: "tcp", BindPort: "443"}
	if sourceBinds(unbound, policy, rec) {
		t.Fatal("logs without a destination must not join a bind_addr policy")
	}
	rec.DestAddr = "192.0.2.10"
	if !sourceBinds(unbound, policy, rec) {
		t.Fatal("log dest addr must prove ownership")
	}
	open := v2.ProtectionPolicy{Protocol: "tcp", Port: "443"}
	if !sourceBinds(unbound, open, protection.Record{Transport: "tcp", ServerPort: 443}) {
		t.Fatal("unscoped policies must keep current matching")
	}
}

func TestFailedLocalBanRemembersEvent(t *testing.T) {
	raw, err := os.ReadFile("protection_log.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := extractProtectionFunc(string(raw), "func maybeBanFromLog")
	fail := fn
	if i := strings.Index(fn, "if err != nil"); i >= 0 {
		fail = fn[i:]
	}
	if !strings.Contains(fail, "rememberProtectionEvent(eventID)") {
		t.Fatal("nft failure must not retry the same log event every line")
	}
}

func TestFailedBanDoesNotReportExecution(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeEnforce, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1,
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, RuntimeEnabled: true, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	state.RuntimeEnabled = true
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	protectionBanSyncTest = func(*persistedProtection) error {
		return errInvalidProtectionIP
	}
	t.Cleanup(func() { protectionBanSyncTest = nil })
	src := v2.ProtectionLogSource{ID: "s1"}
	rec := protection.Record{Time: now, IP: "203.0.113.91"}
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.91", now)
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.91", now)
	for _, report := range PeekProtectionReports() {
		if len(report.Executions) != 0 {
			t.Fatalf("nft failure reported executions: %+v", report)
		}
		if report.Error == "" {
			t.Fatalf("nft failure must stay an error: %+v", report)
		}
	}
	protectionBanSyncTest = nil
	resetProtectionLogTestState()
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.91", now)
	got := PeekProtectionReports()
	if len(got) != 1 || len(got[0].Executions) != 1 || got[0].Error != "" {
		t.Fatalf("recovery must report one execution: %+v", got)
	}
}

func TestSameEventIDDoesNotRepeatReports(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1,
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	src := v2.ProtectionLogSource{ID: "s1"}
	rec := protection.Record{Time: now, IP: "203.0.113.90"}
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.90", now)
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.90", now)
	applyLogPolicy(cfg, policy, src, rec, "203.0.113.90", now)
	if n := len(PeekProtectionReports()); n != 1 {
		t.Fatalf("duplicate event reports: %d", n)
	}
}

func TestProxyObserveUsesClientIP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1, SourceID: "s1",
	}
	src := v2.ProtectionLogSource{
		ID: "s1", Format: v2.ProtectionLogNginxJSON, DeployMode: v2.ProtectionDeployProxy,
		BindProtocol: "tcp", BindPort: "443",
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Sources: []v2.ProtectionLogSource{src}, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	line := `{"ts":"` + now.Format(time.RFC3339Nano) + `","remote_addr":"192.0.2.8","server_port":"443","host":"web.test","method":"GET","uri":"/","protocol":"HTTP/1.1","status":"200","peer_addr":"198.51.100.1"}`
	handleLogLine(cfg, src, line, now, map[string]struct{}{})
	got := PeekProtectionReports()
	if len(got) != 1 || len(got[0].Hits) != 1 || got[0].Hits[0].IP != "192.0.2.8" {
		t.Fatalf("proxy observe must use client IP: %+v", got)
	}
	if got[0].Hits[0].IP == "198.51.100.1" {
		t.Fatal("proxy peer was counted")
	}
}

func TestProxyObserveSkipsMissingPeer(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1, SourceID: "s1",
	}
	src := v2.ProtectionLogSource{
		ID: "s1", Format: v2.ProtectionLogNginxJSON, DeployMode: v2.ProtectionDeployProxy,
		BindProtocol: "tcp", BindPort: "443",
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Sources: []v2.ProtectionLogSource{src}, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	line := `{"ts":"` + now.Format(time.RFC3339Nano) + `","remote_addr":"192.0.2.8","server_port":"443","host":"web.test","method":"GET","uri":"/","protocol":"HTTP/1.1","status":"200"}`
	handleLogLine(cfg, src, line, now, map[string]struct{}{})
	if n := len(PeekProtectionReports()); n != 0 {
		t.Fatalf("proxy without peer_addr must skip: %d", n)
	}
}

func TestSSHDAuthFailuresBanAfterThreshold(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeObserve, Protocol: "tcp", Port: "12560",
		RequestWindowSec: 60, RequestThreshold: 3, SourceID: "s1",
	}
	src := v2.ProtectionLogSource{
		ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD,
		BindProtocol: "tcp", BindPort: "12560",
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, Sources: []v2.ProtectionLogSource{src}, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	line := func(ip string) string {
		return now.Format(time.RFC3339) + ` vps sshd[12]: Failed password for root from ` + ip + ` port 9 ssh2`
	}
	applied := map[string]struct{}{}
	handleLogLine(cfg, src, now.Format(time.RFC3339)+` vps sshd[12]: Accepted password for root from 203.0.113.20 port 9 ssh2`, now, applied)
	handleLogLine(cfg, src, line("203.0.113.20"), now, map[string]struct{}{})
	handleLogLine(cfg, src, line("203.0.113.20"), now, map[string]struct{}{})
	if n := len(PeekProtectionReports()); n != 0 {
		t.Fatalf("two failures must not ban: %d", n)
	}
	handleLogLine(cfg, src, line("203.0.113.20"), now, map[string]struct{}{})
	got := PeekProtectionReports()
	if len(got) != 1 || len(got[0].Hits) != 1 || got[0].Hits[0].ReasonType != v2.ProtectionReasonSSHAuth || got[0].Hits[0].IP != "203.0.113.20" {
		t.Fatalf("third failure must ban: %+v", got)
	}
}

func TestSourceBindsSSHDUsesSourcePort(t *testing.T) {
	policy := v2.ProtectionPolicy{Protocol: "tcp", Port: "12560"}
	src := v2.ProtectionLogSource{Format: v2.ProtectionLogSSHD, BindProtocol: "tcp", BindPort: "12560"}
	rec := protection.Record{Transport: "tcp"}
	if !sourceBinds(src, policy, rec) {
		t.Fatal("sshd logs without server port must match the bound SSH port")
	}
	other := src
	other.BindPort = "22"
	if sourceBinds(other, policy, rec) {
		t.Fatal("other ssh port must not match")
	}
}

func TestProxyEnforceStillSkipped(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENT_DATA_DIR", dir)
	resetProtectionLogTestState()
	now := time.Now().UTC()
	policy := v2.ProtectionPolicy{
		ID: "p1", Enabled: true, Mode: v2.ProtectionModeEnforce, Protocol: "tcp", Port: "443",
		RequestWindowSec: 60, RequestThreshold: 1, SourceID: "s1",
	}
	src := v2.ProtectionLogSource{
		ID: "s1", Format: v2.ProtectionLogNginxJSON, DeployMode: v2.ProtectionDeployProxy,
		BindProtocol: "tcp", BindPort: "443",
	}
	cfg := v2.ProtectionConfig{Revision: 1, Enabled: true, RuntimeEnabled: true, Sources: []v2.ProtectionLogSource{src}, Policies: []v2.ProtectionPolicy{policy}}
	state := loadProtection()
	state.Config = cfg
	state.RuntimeEnabled = true
	if err := saveProtection(state); err != nil {
		t.Fatal(err)
	}
	line := `{"ts":"` + now.Format(time.RFC3339Nano) + `","remote_addr":"192.0.2.8","server_port":"443","host":"web.test","method":"GET","uri":"/","protocol":"HTTP/1.1","status":"200","peer_addr":"198.51.100.1"}`
	handleLogLine(cfg, src, line, now, map[string]struct{}{})
	if n := len(PeekProtectionReports()); n != 0 {
		t.Fatalf("proxy must not auto-ban: %d", n)
	}
	if n := len(loadProtection().Reasons); n != 0 {
		t.Fatalf("proxy enforce stored a ban: %d", n)
	}
}

func TestLiveProtectionSourcesKeepsOneSSHD(t *testing.T) {
	auth := v2.ProtectionLogSource{ID: "s2", Format: v2.ProtectionLogSSHD, Path: "/var/log/auth.log"}
	journal := v2.ProtectionLogSource{ID: "s1", Format: v2.ProtectionLogSSHD, Path: v2.ProtectionJournalSSHD}
	nginx := v2.ProtectionLogSource{ID: "n1", Format: v2.ProtectionLogNginxCombined, Path: "/var/log/nginx/access.log"}
	got := liveProtectionSources([]v2.ProtectionLogSource{auth, nginx, journal})
	if len(got) != 2 || got[0].ID != "n1" || got[1].ID != "s1" {
		t.Fatalf("prefer journal: %+v", got)
	}
	got = liveProtectionSources([]v2.ProtectionLogSource{auth, nginx})
	if len(got) != 2 || got[0].ID != "s2" || got[1].ID != "n1" {
		t.Fatalf("first sshd: %+v", got)
	}
	got = liveProtectionSources([]v2.ProtectionLogSource{nginx})
	if len(got) != 1 || got[0].ID != "n1" {
		t.Fatalf("no sshd: %+v", got)
	}
}
