package firewall

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nuomiiiii/lite-agent/protection"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const (
	protectionStateFile        = "protection-state.json"
	protectionNftTable         = "liteplus_protection"
	protectionSetV4            = "ban4"
	protectionSetV6            = "ban6"
	protectionBootFile         = "protection-boot.nft"
	protectionDropin           = "/etc/nftables.d/lite-plus-protection.nft"
	protectionNflogGroup       = 4242
	protectionHookPrio         = -200
	protectionQueueLimit       = 4096
	protectionEnableBackoffMax = time.Minute
	protectionForeverTimeout   = time.Duration(-1)
)

var (
	protectionDirty        bool
	protectionRuntimeOK    bool
	protectionEnableFailAt time.Time
	protectionEnableDelay  time.Duration
	lastProtectionBootFP   string
)

type persistedProtection struct {
	RuntimeEnabled        bool                           `json:"runtime_enabled"`
	Config                v2.ProtectionConfig            `json:"config"`
	ConfigAppliedRevision uint64                         `json:"config_applied_revision,omitempty"`
	Reasons               []v2.ProtectionBanReason       `json:"reasons,omitempty"`
	GroupApplied          map[string]uint64              `json:"group_applied,omitempty"`
	GroupSeen             map[string]uint64              `json:"group_seen,omitempty"`
	Revokes               map[string]v2.ProtectionRevoke `json:"revokes,omitempty"`
	Cursors               map[string]protection.Cursor   `json:"cursors,omitempty"`
	PendingReports        []v2.ProtectionReportParams    `json:"pending_reports,omitempty"`
}

func protectionStatePath() string {
	return filepath.Join(filepath.Dir(statePath()), protectionStateFile)
}

func loadProtection() *persistedProtection {
	raw, err := os.ReadFile(protectionStatePath())
	if err != nil || len(raw) == 0 {
		return &persistedProtection{
			GroupApplied: map[string]uint64{},
			GroupSeen:    map[string]uint64{},
			Revokes:      map[string]v2.ProtectionRevoke{},
			Cursors:      map[string]protection.Cursor{},
		}
	}
	var state persistedProtection
	if json.Unmarshal(raw, &state) != nil {
		return &persistedProtection{
			GroupApplied: map[string]uint64{},
			GroupSeen:    map[string]uint64{},
			Revokes:      map[string]v2.ProtectionRevoke{},
			Cursors:      map[string]protection.Cursor{},
		}
	}
	if state.GroupApplied == nil {
		state.GroupApplied = map[string]uint64{}
	}
	if state.GroupSeen == nil {
		state.GroupSeen = map[string]uint64{}
	}
	if state.Revokes == nil {
		state.Revokes = map[string]v2.ProtectionRevoke{}
	}
	if state.Cursors == nil {
		state.Cursors = map[string]protection.Cursor{}
	}
	return &state
}

func saveProtection(state *persistedProtection) error {
	if state != nil {
		logMu.Lock()
		state.PendingReports = append([]v2.ProtectionReportParams(nil), reportQueue...)
		logMu.Unlock()
	}
	if err := os.MkdirAll(filepath.Dir(protectionStatePath()), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := protectionStatePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, protectionStatePath())
}

func ProtectionPrecheck() v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	return protectionPrecheckLocked()
}

func ProtectionUpgrade(opID string) v2.ProtectionResultParams {
	opMu.Lock()
	result, needPkg, wasActive, wasEnabled := protectionUpgradePrepareLocked(opID)
	opMu.Unlock()
	if result.Status != "" && result.Status != v2.ProtectionStatusOK {
		return result
	}
	if result.Phase == v2.ProtectionUpgradePhaseFailed {
		return result
	}
	if needPkg {
		result.Phase = v2.ProtectionUpgradePhaseInstall
		if err := installOrUpdateNftables(wasActive, wasEnabled); err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = err.Error()
			result.Phase = v2.ProtectionUpgradePhaseFailed
			opMu.Lock()
			result.Capability = ptrCap(probeProtectionCapabilityLocked())
			opMu.Unlock()
			return result
		}
		result.PackageInstalled = true
	}
	opMu.Lock()
	defer opMu.Unlock()
	return protectionUpgradeEnableLocked(result)
}

func ApplyProtectionConfig(cfg v2.ProtectionConfig) v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindApplyConfig, Revision: cfg.Revision}
	state := loadProtection()
	if state.Config.Revision > 0 && cfg.Revision < state.Config.Revision {
		result.Status = v2.ProtectionStatusOK
		result.Error = "stale config ignored"
		result.Revision = state.Config.Revision
		return result
	}
	if err := v2.CheckProtectionSSHSources(cfg); err != nil {
		log.Printf("protection ssh sources: %v", err)
	}
	cfg.Sources = liveProtectionSources(cfg.Sources)
	if !cfg.Enabled {
		cfg.RuntimeEnabled = false
	}
	alreadyApplied := shouldSkipProtectionApply(state, cfg)
	resets := state.Config.CounterResetAt
	state.Config = cfg
	state.Config.CounterResetAt = mergeCounterResets(resets, cfg.CounterResetAt)
	state.RuntimeEnabled = cfg.RuntimeEnabled
	pruneWhitelistLocked(state)
	rememberResets(state.Config.CounterResetAt)
	if err := saveProtection(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	if !alreadyApplied {
		if cfg.RuntimeEnabled {
			if err := enableProtectionRuntimeLocked(state, false); err != nil {
				state.RuntimeEnabled = false
				_ = saveProtection(state)
				_ = disableProtectionRuntimeLocked(state)
				result.Status = v2.ProtectionStatusError
				result.Error = err.Error()
				result.RuntimeEnabled = false
				result.Capability = ptrCap(probeProtectionCapabilityLocked())
				return result
			}
			state.RuntimeEnabled = true
			noteProtectionEnableOK()
		} else if err := disableProtectionRuntimeLocked(state); err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = err.Error()
			return result
		}
		state.ConfigAppliedRevision = cfg.Revision
		if err := saveProtection(state); err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = err.Error()
			return result
		}
		markProtectionDirty()
		if state.RuntimeEnabled {
			if err := syncProtectionBansLocked(state); err != nil {
				result.Status = v2.ProtectionStatusError
				result.Error = err.Error()
				return result
			}
		}
		startProtectionLogLocked(state, true)
	} else {
		startProtectionLogLocked(state, false)
	}
	cap := probeProtectionCapabilityLocked()
	result.Status = v2.ProtectionStatusOK
	result.RuntimeEnabled = state.RuntimeEnabled
	result.Capability = &cap
	result.SourceStats = ProtectionSourceStats()
	return result
}

func ProtectionBan(reason v2.ProtectionBanReason, observed uint64) v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindBan, GroupID: reason.GroupID, GroupRevision: observed}
	state := loadProtection()
	if observed > 0 {
		reason.ObservedRevision = observed
	}
	if reason.GroupID != "" {
		if snapshotCoversGroupEvent(state, reason.GroupID, observed) {
			result.Status = v2.ProtectionStatusOK
			result.Error = "stale group event ignored"
			return result
		}
		key := revokeKey(reason.GroupID, reason.IP)
		if rev, ok := state.Revokes[key]; ok && (observed <= rev.Revision || !banFormedAfterRevoke(reason, rev)) {
			result.Status = v2.ProtectionStatusOK
			result.Error = "revoked event ignored"
			return result
		}
	}
	applied, err := upsertBanLocked(state, reason)
	if err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	if groupEventStored(state, reason) {
		noteGroupSeen(state, reason.GroupID, observed)
		_ = saveProtection(state)
	}
	markProtectionDirty()
	result.Status = v2.ProtectionStatusOK
	result.AppliedBans = applied
	result.RuntimeEnabled = state.RuntimeEnabled
	return result
}

func ProtectionUnban(p v2.ProtectionUnbanParams) v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindUnban, GroupID: p.GroupID, GroupRevision: p.Revision}
	state := loadProtection()
	if p.GroupID != "" && snapshotCoversGroupEvent(state, p.GroupID, p.Revision) {
		result.Status = v2.ProtectionStatusOK
		result.Error = "stale unban ignored"
		return result
	}
	if strings.TrimSpace(p.IP) == "" {
		if p.GroupID == "" {
			result.Status = v2.ProtectionStatusError
			result.Error = "invalid ip"
			return result
		}
		if p.Revision > state.GroupApplied[p.GroupID] {
			state.GroupApplied[p.GroupID] = p.Revision
		}
		kept := state.Reasons[:0]
		for _, reason := range state.Reasons {
			if reason.GroupID == p.GroupID {
				continue
			}
			kept = append(kept, reason)
		}
		state.Reasons = kept
		if err := saveProtection(state); err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = err.Error()
			return result
		}
		markProtectionDirty()
		if err := syncProtectionBansLocked(state); err != nil {
			result.Status = v2.ProtectionStatusError
			result.Error = err.Error()
			return result
		}
		result.Status = v2.ProtectionStatusOK
		return result
	}
	ip, ok := v2.NormalizeProtectionIP(p.IP)
	if !ok {
		result.Status = v2.ProtectionStatusError
		result.Error = "invalid ip"
		return result
	}
	if p.Local && p.GroupID == "" {
		local := 0
		grouped := 0
		for _, reason := range state.Reasons {
			if reason.IP != ip {
				continue
			}
			if isLocalAutoReason(reason.ReasonType) && reason.GroupID == "" {
				local++
			} else if reason.GroupID != "" {
				grouped++
			}
		}
		if local == 0 && grouped > 0 {
			result.Status = v2.ProtectionStatusError
			result.Error = "grouped reason requires group unban"
			return result
		}
	}
	if p.GroupID != "" {
		key := revokeKey(p.GroupID, ip)
		if existing, ok := state.Revokes[key]; ok && existing.Revision > p.Revision {
			result.Status = v2.ProtectionStatusOK
			result.Error = "stale unban ignored"
			return result
		}
		state.Revokes[key] = v2.ProtectionRevoke{Revision: p.Revision, ResetAt: p.ResetAt}
	}
	kept := state.Reasons[:0]
	for _, reason := range state.Reasons {
		if reason.IP != ip {
			kept = append(kept, reason)
			continue
		}
		if p.GroupID != "" && reason.GroupID == p.GroupID {
			if reasonNewerThanUnban(reason, p.Revision, p.ResetAt) {
				kept = append(kept, reason)
			}
			continue
		}
		if p.Local && isLocalAutoReason(reason.ReasonType) && (reason.GroupID == "" || reason.GroupID == p.GroupID) {
			if p.GroupID != "" && reasonNewerThanUnban(reason, p.Revision, p.ResetAt) {
				kept = append(kept, reason)
			}
			continue
		}
		kept = append(kept, reason)
	}
	state.Reasons = kept
	if p.ResetAt != "" {
		if state.Config.CounterResetAt == nil {
			state.Config.CounterResetAt = map[string]string{}
		}
		state.Config.CounterResetAt[ip] = p.ResetAt
		rememberResets(map[string]string{ip: p.ResetAt})
	}
	resetProtectionCounters(ip)
	noteGroupSeen(state, p.GroupID, p.Revision)
	if err := saveProtection(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	markProtectionDirty()
	if err := syncProtectionBansLocked(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	result.Status = v2.ProtectionStatusOK
	result.AppliedBans = activeReasonsForIP(state, ip)
	return result
}

func ApplyProtectionGroupSnapshot(snap v2.ProtectionGroupSnapshot) v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	result := v2.ProtectionResultParams{Kind: v2.ProtectionKindGroupSnapshot, GroupID: snap.Group, GroupRevision: snap.Revision}
	state := loadProtection()
	if snapshotStale(state, snap.Group, snap.Revision) {
		result.Status = v2.ProtectionStatusOK
		return result
	}
	kept := state.Reasons[:0]
	for _, reason := range state.Reasons {
		if reason.GroupID == snap.Group {
			continue
		}
		kept = append(kept, reason)
	}
	state.Reasons = kept
	now := time.Now().UTC()
	for _, reason := range snap.Bans {
		if expiredReason(reason, now) {
			continue
		}
		if snapshotReasonBlocked(state, snap, reason) {
			continue
		}
		state.Reasons = append(state.Reasons, reason)
	}
	for ip, rev := range snap.Revoked {
		key := revokeKey(snap.Group, ip)
		if existing, ok := state.Revokes[key]; ok && existing.Revision > rev.Revision {
			continue
		}
		state.Revokes[key] = rev
	}
	applyRevokeResets(state, snap.Revoked)
	state.GroupApplied[snap.Group] = snap.Revision
	if err := saveProtection(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	markProtectionDirty()
	if err := syncProtectionBansLocked(state); err != nil {
		result.Status = v2.ProtectionStatusError
		result.Error = err.Error()
		return result
	}
	result.Status = v2.ProtectionStatusOK
	result.AppliedBans = copyReasons(state.Reasons)
	return result
}

func ProtectionPreview(p v2.ProtectionPreviewParams) v2.ProtectionResultParams {
	opMu.Lock()
	defer opMu.Unlock()
	return protectionPreviewLocked(p)
}

func RestoreProtectionLocked() error {
	return restoreProtectionLocked(true)
}

func restoreProtectionIfNeeded() error {
	return restoreProtectionLocked(false)
}

func restoreProtectionLocked(force bool) error {
	state := loadProtection()
	restorePendingReports(state)
	if stripped := liveProtectionSources(state.Config.Sources); len(stripped) != len(state.Config.Sources) {
		state.Config.Sources = stripped
		_ = saveProtection(state)
	}
	if !state.Config.Enabled && (state.RuntimeEnabled || state.Config.RuntimeEnabled) {
		state.RuntimeEnabled = false
		state.Config.RuntimeEnabled = false
		_ = saveProtection(state)
	}
	if !state.RuntimeEnabled {
		if lookPath("nft") && protectionTableLive() {
			if err := disableProtectionRuntimeLocked(state); err != nil {
				return err
			}
		}
		protectionRuntimeOK = true
		protectionDirty = false
		startProtectionLogLocked(state, false)
		return nil
	}
	if !force && protectionEnableBackoff() {
		return nil
	}
	if !force && !protectionDirty && protectionRuntimePresent() {
		startProtectionLogLocked(state, false)
		return nil
	}
	if !protectionTableLive() {
		if err := enableProtectionRuntimeLocked(state, true); err != nil {
			noteProtectionEnableFail()
			return err
		}
	}
	if err := syncProtectionBansLocked(state); err != nil {
		noteProtectionEnableFail()
		return err
	}
	noteProtectionEnableOK()
	startProtectionLogLocked(state, false)
	return nil
}

func protectionWantedLocked() bool {
	return loadProtection().RuntimeEnabled
}

func protectionRuntimePresent() bool {
	if !lookPath("nft") {
		return true
	}
	return protectionTableLive()
}

func markProtectionDirty() {
	protectionDirty = true
	protectionRuntimeOK = false
}

func noteProtectionEnableFail() {
	if protectionEnableDelay == 0 {
		protectionEnableDelay = time.Second
	} else {
		protectionEnableDelay *= 2
		if protectionEnableDelay > protectionEnableBackoffMax {
			protectionEnableDelay = protectionEnableBackoffMax
		}
	}
	protectionEnableFailAt = time.Now()
}

func noteProtectionEnableOK() {
	protectionEnableFailAt = time.Time{}
	protectionEnableDelay = 0
	protectionDirty = false
	protectionRuntimeOK = true
}

func protectionEnableBackoff() bool {
	if protectionEnableFailAt.IsZero() {
		return false
	}
	return time.Since(protectionEnableFailAt) < protectionEnableDelay
}

func upsertBanLocked(state *persistedProtection, reason v2.ProtectionBanReason) ([]v2.ProtectionBanReason, error) {
	ip, ok := v2.NormalizeProtectionIP(reason.IP)
	if !ok {
		return nil, errInvalidProtectionIP
	}
	reason.IP = ip
	if reason.Status == "" {
		reason.Status = v2.ProtectionBanActive
	}
	if isWhitelisted(state, ip) {
		return activeReasonsForIP(state, ip), nil
	}
	now := time.Now().UTC()
	if expiredReason(reason, now) {
		return activeReasonsForIP(state, ip), nil
	}
	stored := reason
	found := false
	for i, existing := range state.Reasons {
		if existing.EventID == "" || existing.EventID != reason.EventID {
			continue
		}
		stored = existing
		stored.IP = ip
		if stored.BanID == "" {
			stored.BanID = stored.EventID
		}
		if reason.ObservedRevision > stored.ObservedRevision {
			stored.ObservedRevision = reason.ObservedRevision
		}
		if reason.Status != "" {
			stored.Status = reason.Status
		}
		state.Reasons[i] = stored
		found = true
		break
	}
	if !found {
		if stored.BanID == "" {
			stored.BanID = stored.EventID
		}
		state.Reasons = append(state.Reasons, stored)
	}
	if err := saveProtection(state); err != nil {
		return nil, err
	}
	markProtectionDirty()
	if expiredReason(stored, now) {
		return activeReasonsForIP(state, ip), nil
	}
	if err := applyProtectionBans(state); err != nil {
		return nil, err
	}
	return []v2.ProtectionBanReason{stored}, nil
}

var protectionBanSyncTest func(*persistedProtection) error

func applyProtectionBans(state *persistedProtection) error {
	if protectionBanSyncTest != nil {
		return protectionBanSyncTest(state)
	}
	return syncProtectionBansLocked(state)
}

func snapshotReasonBlocked(state *persistedProtection, snap v2.ProtectionGroupSnapshot, reason v2.ProtectionBanReason) bool {
	if rev, ok := snap.Revoked[reason.IP]; ok {
		if snap.Revision <= rev.Revision || !banFormedAfterRevoke(reason, rev) {
			return true
		}
	}
	if state == nil || snap.Group == "" {
		return false
	}
	local, ok := state.Revokes[revokeKey(snap.Group, reason.IP)]
	if !ok {
		return false
	}
	if snap.Revision <= local.Revision {
		return true
	}
	return !banFormedAfterRevoke(reason, local)
}

func pruneReasons(state *persistedProtection, now time.Time) {
	kept := state.Reasons[:0]
	for _, reason := range state.Reasons {
		if expiredReason(reason, now) || reason.Status == v2.ProtectionBanRevoked {
			continue
		}
		kept = append(kept, reason)
	}
	state.Reasons = kept
}

func expiredReason(reason v2.ProtectionBanReason, now time.Time) bool {
	if strings.TrimSpace(reason.ExpiresAt) == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339Nano, reason.ExpiresAt)
	if err != nil {
		exp, err = time.Parse(time.RFC3339, reason.ExpiresAt)
	}
	if err != nil {
		return true
	}
	if v2.ProtectionBanNever(exp) {
		return false
	}
	return !exp.After(now)
}

func remainingTimeout(reason v2.ProtectionBanReason, now time.Time) time.Duration {
	exp, err := time.Parse(time.RFC3339Nano, reason.ExpiresAt)
	if err != nil {
		exp, err = time.Parse(time.RFC3339, reason.ExpiresAt)
	}
	if err != nil {
		return 0
	}
	if v2.ProtectionBanNever(exp) {
		return protectionForeverTimeout
	}
	d := exp.Sub(now)
	if d < time.Second {
		return 0
	}
	return d
}

func foreverTimeout(d time.Duration) bool {
	return d < 0
}

func laterTimeout(cur, next time.Duration) time.Duration {
	if foreverTimeout(next) {
		return protectionForeverTimeout
	}
	if foreverTimeout(cur) {
		return cur
	}
	if next > cur {
		return next
	}
	return cur
}

func protectionNftTimeoutSec(d time.Duration) int {
	if foreverTimeout(d) {
		return -1
	}
	sec := int(d.Round(time.Second) / time.Second)
	if sec < 1 {
		return 0
	}
	return sec
}

func latestExpiry(reasons []v2.ProtectionBanReason, ip string, now time.Time) time.Duration {
	var latest time.Duration
	for _, reason := range reasons {
		if reason.IP != ip {
			continue
		}
		latest = laterTimeout(latest, remainingTimeout(reason, now))
	}
	return latest
}

func activeIPs(state *persistedProtection, now time.Time) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, reason := range state.Reasons {
		if expiredReason(reason, now) || isWhitelisted(state, reason.IP) {
			continue
		}
		out[reason.IP] = laterTimeout(out[reason.IP], remainingTimeout(reason, now))
	}
	return out
}

func pruneWhitelistLocked(state *persistedProtection) {
	kept := state.Reasons[:0]
	for _, reason := range state.Reasons {
		if isWhitelisted(state, reason.IP) {
			continue
		}
		kept = append(kept, reason)
	}
	state.Reasons = kept
}

func mergeCounterResets(prev, next map[string]string) map[string]string {
	if len(prev) == 0 && len(next) == 0 {
		return nil
	}
	out := map[string]string{}
	for ip, raw := range prev {
		out[ip] = raw
	}
	for ip, raw := range next {
		out[ip] = raw
	}
	return out
}

func activeReasonsForIP(state *persistedProtection, ip string) []v2.ProtectionBanReason {
	var out []v2.ProtectionBanReason
	now := time.Now().UTC()
	for _, reason := range state.Reasons {
		if reason.IP == ip && !expiredReason(reason, now) {
			out = append(out, reason)
		}
	}
	return out
}

func copyReasons(in []v2.ProtectionBanReason) []v2.ProtectionBanReason {
	out := make([]v2.ProtectionBanReason, len(in))
	copy(out, in)
	return out
}

func isLocalAutoReason(kind string) bool {
	for _, item := range v2.ProtectionAutoBanReasons() {
		if kind == item {
			return true
		}
	}
	return false
}

func isWhitelisted(state *persistedProtection, ip string) bool {
	for _, item := range state.Config.Whitelist {
		got, ok := v2.NormalizeProtectionIP(item)
		if ok && got == ip {
			return true
		}
	}
	return false
}

func revokeKey(group, ip string) string {
	return group + "|" + ip
}

func snapshotCoversGroupEvent(state *persistedProtection, group string, rev uint64) bool {
	if group == "" || rev == 0 {
		return false
	}
	return state.GroupApplied[group] > rev
}

func snapshotStale(state *persistedProtection, group string, rev uint64) bool {
	if group == "" {
		return false
	}
	return state.GroupApplied[group] > rev || state.GroupSeen[group] > rev
}

func noteGroupSeen(state *persistedProtection, group string, rev uint64) {
	if state == nil || group == "" || rev == 0 {
		return
	}
	if state.GroupSeen == nil {
		state.GroupSeen = map[string]uint64{}
	}
	if rev > state.GroupSeen[group] {
		state.GroupSeen[group] = rev
	}
}

func groupEventStored(state *persistedProtection, reason v2.ProtectionBanReason) bool {
	if state == nil || reason.EventID == "" {
		return false
	}
	for _, existing := range state.Reasons {
		if existing.EventID == reason.EventID {
			return true
		}
	}
	return false
}

func applyRevokeResets(state *persistedProtection, revoked map[string]v2.ProtectionRevoke) {
	if len(revoked) == 0 {
		return
	}
	if state.Config.CounterResetAt == nil {
		state.Config.CounterResetAt = map[string]string{}
	}
	for ip, rev := range revoked {
		if strings.TrimSpace(rev.ResetAt) == "" {
			continue
		}
		prev := parseProtectionTime(state.Config.CounterResetAt[ip])
		next := parseProtectionTime(rev.ResetAt)
		if prev.IsZero() || next.After(prev) {
			state.Config.CounterResetAt[ip] = rev.ResetAt
			resetProtectionCounters(ip)
		}
	}
	rememberResets(state.Config.CounterResetAt)
}

func parseProtectionTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return time.Time{}
	}
	return ts.UTC()
}

func sortedIPs(set map[string]time.Duration) []string {
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

const banTimeoutSlackSec = 3

func protectionBanFingerprint(desired map[string]time.Duration, now time.Time) string {
	ips := sortedIPs(desired)
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if foreverTimeout(desired[ip]) {
			parts = append(parts, ip+"=forever")
			continue
		}
		exp := now.Add(desired[ip]).Unix()
		parts = append(parts, ip+"="+strconv.FormatInt(exp, 10))
	}
	return strings.Join(parts, ",")
}

func timeoutNeedsUpdate(liveSec, desiredSec int) bool {
	if desiredSec < 0 {
		return liveSec >= 0
	}
	if liveSec < 0 {
		return true
	}
	diff := liveSec - desiredSec
	if diff < 0 {
		diff = -diff
	}
	return diff > banTimeoutSlackSec
}

func parseNftSetTimeouts(raw string) map[string]int {
	out := map[string]int{}
	text := raw
	if i := strings.Index(text, "elements"); i >= 0 {
		text = text[i:]
	}
	text = strings.ReplaceAll(text, "\n", " ")
	if i := strings.Index(text, "{"); i >= 0 {
		text = text[i+1:]
	}
	if j := strings.LastIndex(text, "}"); j >= 0 {
		text = text[:j]
	}
	for _, part := range strings.Split(text, ",") {
		if ip, sec, ok := nftElementTimeout(part); ok {
			out[ip] = sec
		}
	}
	return out
}

func nftElementTimeout(part string) (string, int, bool) {
	part = strings.TrimSpace(part)
	part = strings.TrimSuffix(part, "}")
	part = strings.TrimSpace(strings.Trim(part, ","))
	if part == "" {
		return "", -1, false
	}
	sec := -1
	if i := strings.Index(part, " expires "); i >= 0 {
		sec = parseNftDuration(part[i+len(" expires "):])
		part = strings.TrimSpace(part[:i])
	}
	if i := strings.Index(part, " timeout "); i >= 0 {
		if sec < 0 {
			sec = parseNftDuration(part[i+len(" timeout "):])
		}
		part = strings.TrimSpace(part[:i])
	}
	ip, ok := v2.NormalizeProtectionIP(part)
	if !ok {
		return "", -1, false
	}
	return ip, sec, true
}

func parseNftDuration(raw string) int {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexAny(raw, " \t"); i >= 0 {
		raw = raw[:i]
	}
	total := 0
	num := 0
	hasNum := false
	runes := []rune(raw)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r >= '0' && r <= '9' {
			num = num*10 + int(r-'0')
			hasNum = true
			continue
		}
		if !hasNum {
			continue
		}
		switch r {
		case 'd':
			total += num * 86400
		case 'h':
			total += num * 3600
		case 'm':
			if i+1 < len(runes) && runes[i+1] == 's' {
				i++
			} else {
				total += num * 60
			}
		case 's':
			total += num
		}
		num = 0
		hasNum = false
	}
	return total
}

func parseProtectionCounters(raw string) []v2.ProtectionNflogSample {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var out []v2.ProtectionNflogSample
	for _, line := range strings.Split(raw, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.Contains(trim, "counter packets") {
			continue
		}
		port := 0
		if i := strings.Index(trim, "tcp dport "); i >= 0 {
			rest := strings.TrimSpace(trim[i+len("tcp dport "):])
			field := rest
			if j := strings.IndexAny(rest, " \t"); j >= 0 {
				field = rest[:j]
			}
			port, _ = strconv.Atoi(field)
		}
		packets := 0
		if i := strings.Index(trim, "counter packets "); i >= 0 {
			rest := strings.TrimSpace(trim[i+len("counter packets "):])
			field := rest
			if j := strings.IndexAny(rest, " \t"); j >= 0 {
				field = rest[:j]
			}
			packets, _ = strconv.Atoi(field)
		}
		if packets <= 0 {
			continue
		}
		out = append(out, v2.ProtectionNflogSample{
			At:     now,
			Dport:  port,
			Proto:  "tcp",
			Prefix: "lp-prot counter " + strconv.Itoa(packets),
		})
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func findProtectionPolicy(cfg v2.ProtectionConfig, id string) *v2.ProtectionPolicy {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range cfg.Policies {
		if cfg.Policies[i].ID == id {
			return &cfg.Policies[i]
		}
	}
	return nil
}

func protectionUnsupported(message string) v2.ProtectionResultParams {
	cap := probeProtectionCapabilityLocked()
	return v2.ProtectionResultParams{
		Status:     v2.ProtectionStatusUnsupported,
		Error:      message,
		Capability: &cap,
	}
}

func logProtection(format string, args ...any) {
	log.Printf("protection: "+format, args...)
}

func PeekProtectionReports() []v2.ProtectionReportParams {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]v2.ProtectionReportParams, len(reportQueue))
	copy(out, reportQueue)
	return out
}

func AckProtectionReports(n int) {
	if n <= 0 {
		return
	}
	opMu.Lock()
	defer opMu.Unlock()
	logMu.Lock()
	if n > len(reportQueue) {
		n = len(reportQueue)
	}
	reportQueue = append([]v2.ProtectionReportParams(nil), reportQueue[n:]...)
	logMu.Unlock()
	_ = saveProtection(loadProtection())
}

func shouldSkipProtectionApply(state *persistedProtection, cfg v2.ProtectionConfig) bool {
	if state == nil || cfg.Revision == 0 {
		return false
	}
	return state.ConfigAppliedRevision == cfg.Revision && protectionConfigUnchanged(state.Config, cfg)
}

func banFormedAfterRevoke(reason v2.ProtectionBanReason, rev v2.ProtectionRevoke) bool {
	created := parseProtectionTime(reason.CreatedAt)
	reset := parseProtectionTime(rev.ResetAt)
	if reset.IsZero() || created.IsZero() {
		return false
	}
	return created.After(reset)
}

func reasonNewerThanUnban(reason v2.ProtectionBanReason, rev uint64, resetAt string) bool {
	if reason.ObservedRevision > rev {
		return true
	}
	created := parseProtectionTime(reason.CreatedAt)
	reset := parseProtectionTime(resetAt)
	if !created.IsZero() && !reset.IsZero() && created.After(reset) {
		return true
	}
	return false
}

func protectionConfigUnchanged(prev, next v2.ProtectionConfig) bool {
	a := prev
	b := next
	a.CounterResetAt = nil
	b.CounterResetAt = nil
	if a.Whitelist == nil {
		a.Whitelist = []string{}
	}
	if b.Whitelist == nil {
		b.Whitelist = []string{}
	}
	if a.Sources == nil {
		a.Sources = []v2.ProtectionLogSource{}
	}
	if b.Sources == nil {
		b.Sources = []v2.ProtectionLogSource{}
	}
	if a.Policies == nil {
		a.Policies = []v2.ProtectionPolicy{}
	}
	if b.Policies == nil {
		b.Policies = []v2.ProtectionPolicy{}
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}

func restorePendingReports(state *persistedProtection) {
	if state == nil || len(state.PendingReports) == 0 {
		return
	}
	logMu.Lock()
	if len(reportQueue) == 0 {
		reportQueue = append([]v2.ProtectionReportParams(nil), state.PendingReports...)
	}
	logMu.Unlock()
}

func cleanLinuxPath(path string) string {
	path = strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	if path == "" || strings.Contains(path, "://") {
		return ""
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if strings.Contains(path, "/../") || strings.HasPrefix(path, "../") || strings.HasSuffix(path, "/..") {
		return ""
	}
	return path
}

func protectionPreviewPathAllowed(state *persistedProtection, sourceID, path string) bool {
	path = strings.TrimSpace(path)
	sourceID = strings.TrimSpace(sourceID)
	if v2.IsProtectionJournalPath(path) {
		if state != nil {
			for _, src := range state.Config.Sources {
				if sourceID != "" && src.ID == sourceID {
					return v2.IsProtectionJournalPath(src.Path)
				}
				if sourceID == "" && v2.IsProtectionJournalPath(src.Path) {
					return true
				}
			}
		}
		return sourceID == ""
	}
	path = cleanLinuxPath(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	if state != nil {
		for _, src := range state.Config.Sources {
			srcPath := cleanLinuxPath(src.Path)
			if sourceID != "" && src.ID == sourceID {
				return srcPath == path
			}
			if sourceID == "" && srcPath == path {
				return true
			}
		}
	}
	if sourceID != "" {
		return false
	}
	return strings.HasPrefix(path, "/var/log/")
}
