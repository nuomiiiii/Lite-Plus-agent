package firewall

import (
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite-agent/protection"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

type protectionHit struct {
	reason v2.ProtectionBanReason
}

var (
	logMu          sync.Mutex
	logStop        chan struct{}
	logDone        chan struct{}
	logRunning     bool
	rateCounter    = protection.NewCounter(50000)
	pathCounter    = protection.NewCounter(50000)
	reportQueue    []v2.ProtectionReportParams
	logStats       = map[string]v2.ProtectionSourceStats{}
	liveResets     = map[string]time.Time{}
	lastStatsAt    time.Time
	lastNflogAt    time.Time
	reportedEvents = map[string]struct{}{}
)

func startProtectionLogLocked(state *persistedProtection, restart bool) {
	logMu.Lock()
	if logRunning && !restart {
		logMu.Unlock()
		return
	}
	prevDone := logDone
	if logRunning {
		if logStop != nil {
			close(logStop)
		}
		logRunning = false
	}
	if !state.Config.Enabled || (len(state.Config.Sources) == 0 && !protectionHasNetworkPolicies(state.Config)) {
		logDone = prevDone
		logMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	logStop = stop
	logDone = done
	logRunning = true
	cfg := state.Config
	cursors := map[string]protection.Cursor{}
	for id, cur := range state.Cursors {
		cursors[id] = cur
	}
	rememberResetsLocked(cfg.CounterResetAt)
	logMu.Unlock()
	go func() {
		if prevDone != nil {
			<-prevDone
		}
		defer close(done)
		runProtectionLog(cfg, cursors, stop)
	}()
}

func rememberResets(raw map[string]string) {
	logMu.Lock()
	defer logMu.Unlock()
	rememberResetsLocked(raw)
}

func rememberResetsLocked(raw map[string]string) {
	for ip, value := range raw {
		if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
			liveResets[ip] = ts
		} else if ts, err := time.Parse(time.RFC3339, value); err == nil {
			liveResets[ip] = ts
		}
	}
}

func resetTimeFor(ip string) time.Time {
	logMu.Lock()
	defer logMu.Unlock()
	return liveResets[ip]
}

func resetProtectionCounters(ip string) {
	rateCounter.ResetPrefix(ip + "|")
	pathCounter.ResetPrefix(ip + "|")
}

type protectionLogReader interface {
	Read(now time.Time) ([]string, protection.Cursor, protection.ReadStats, error)
	Close()
}

func liveProtectionSources(sources []v2.ProtectionLogSource) []v2.ProtectionLogSource {
	keep := -1
	for i, src := range sources {
		if strings.TrimSpace(src.Format) != v2.ProtectionLogSSHD {
			continue
		}
		if v2.IsProtectionJournalPath(src.Path) {
			keep = i
			break
		}
		if keep < 0 {
			keep = i
		}
	}
	if keep < 0 {
		return append([]v2.ProtectionLogSource(nil), sources...)
	}
	out := make([]v2.ProtectionLogSource, 0, len(sources))
	skipped := 0
	for i, src := range sources {
		if strings.TrimSpace(src.Format) == v2.ProtectionLogSSHD && i != keep {
			skipped++
			continue
		}
		out = append(out, src)
	}
	if skipped > 0 {
		log.Printf("protection: ignoring %d extra sshd log source(s); only one SSH log is used", skipped)
	}
	return out
}

func runProtectionLog(cfg v2.ProtectionConfig, cursors map[string]protection.Cursor, stop <-chan struct{}) {
	cfg.Sources = liveProtectionSources(cfg.Sources)
	byPath := map[string][]v2.ProtectionLogSource{}
	for _, src := range cfg.Sources {
		if protection.IsJournalPath(src.Path) {
			byPath[src.Path] = append(byPath[src.Path], src)
			continue
		}
		if !filepath.IsAbs(src.Path) {
			continue
		}
		byPath[src.Path] = append(byPath[src.Path], src)
	}
	for path, sources := range byPath {
		if protection.IsJournalPath(path) {
			continue
		}
		if _, ok := cursors[path]; !ok {
			if cur, err := protection.OpenAtEnd(path); err == nil {
				cursors[path] = cur
			}
		}
		_ = sources
	}
	sessions := map[string]protectionLogReader{}
	for path := range byPath {
		sessions[path] = newProtectionLogReader(path, cursors[path])
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			for path, sources := range byPath {
				session := sessions[path]
				if session == nil {
					session = newProtectionLogReader(path, cursors[path])
					sessions[path] = session
				}
				lines, next, stats, err := session.Read(now)
				if err != nil {
					for _, src := range sources {
						bumpLogStats(src, now, 0, 0, 1, 0)
					}
					maybeReportSourceStats(cfg.Revision, now)
					continue
				}
				for _, src := range sources {
					bumpLogStats(src, now, 0, uint64(stats.Skipped), uint64(stats.Errors), 0)
				}
				maybeReportSourceStats(cfg.Revision, now)
				if !protection.IsJournalPath(path) {
					cursors[path] = next
					persistLogCursor(path, next)
				}
				for _, line := range lines {
					applied := map[string]struct{}{}
					for _, src := range sources {
						handleLogLine(cfg, src, line, now, applied)
					}
				}
			}
			maybeReportNetworkObserve(cfg.Revision, now)
		}
	}
}

func newProtectionLogReader(path string, cur protection.Cursor) protectionLogReader {
	if protection.IsJournalPath(path) {
		return protection.NewJournalSession()
	}
	return protection.NewSession(path, cur)
}

func protectionHasNetworkPolicies(cfg v2.ProtectionConfig) bool {
	for _, policy := range cfg.Policies {
		if !policy.Enabled {
			continue
		}
		if strings.ToLower(strings.TrimSpace(policy.Protocol)) != "tcp" {
			continue
		}
		port := strings.TrimSpace(policy.Port)
		if port == "" || port == "*" {
			continue
		}
		if policy.SynRate > 0 || policy.ConnLimit > 0 {
			return true
		}
	}
	return false
}

func persistLogCursor(path string, cur protection.Cursor) {
	opMu.Lock()
	defer opMu.Unlock()
	state := loadProtection()
	if prev, ok := state.Cursors[path]; ok && prev == cur {
		return
	}
	state.Cursors[path] = cur
	_ = saveProtection(state)
}

func handleLogLine(cfg v2.ProtectionConfig, src v2.ProtectionLogSource, line string, now time.Time, applied map[string]struct{}) {
	rec, err := protection.ParseLine(src.Format, line)
	if err != nil {
		if protection.IsSkip(err) {
			bumpLogStats(src, now, 0, 1, 0, 0)
			return
		}
		bumpLogStats(src, now, 0, 0, 1, 0)
		return
	}
	if rec.Time.IsZero() {
		rec.Time = now
	}
	if rec.Time.After(now.Add(5 * time.Minute)) {
		bumpLogStats(src, now, 0, 1, 0, 0)
		return
	}
	window := maxPolicyWindow(cfg.Policies)
	if window > 0 && now.Sub(rec.Time) > window {
		bumpLogStats(src, now, 0, 1, 0, 0)
		return
	}
	ip := rec.IP
	if src.DeployMode == v2.ProtectionDeployProxy {
		if rec.PeerAddr == "" {
			bumpLogStats(src, now, 0, 1, 0, 0)
			return
		}
	}
	if src.HostFilter != "" && !hostAllowed(rec.Host, src.HostFilter) {
		bumpLogStats(src, now, 0, 1, 0, 0)
		return
	}
	lag := int64(0)
	if rec.Time.Before(now) {
		lag = now.Sub(rec.Time).Milliseconds()
	}
	bumpLogStats(src, now, 1, 0, 0, lag)
	if resetAt := resetTimeFor(ip); !resetAt.IsZero() && !rec.Time.After(resetAt) {
		return
	}
	for _, policy := range cfg.Policies {
		if !policy.Enabled {
			continue
		}
		if _, ok := applied[policy.ID]; ok {
			continue
		}
		if policy.SourceID != "" && policy.SourceID != src.ID {
			continue
		}
		if !sourceBinds(src, policy, rec) {
			continue
		}
		applied[policy.ID] = struct{}{}
		applyLogPolicy(cfg, policy, src, rec, ip, now)
	}
}

func bumpLogStats(src v2.ProtectionLogSource, now time.Time, parsed, dropped, errors uint64, lagMS int64) {
	logMu.Lock()
	defer logMu.Unlock()
	st := logStats[src.ID]
	st.ID = src.ID
	st.Path = src.Path
	st.LastReadAt = now.UTC().Format(time.RFC3339Nano)
	st.Parsed += parsed
	st.Dropped += dropped
	st.Errors += errors
	st.LagMS = lagMS
	logStats[src.ID] = st
}

func sourceBinds(src v2.ProtectionLogSource, policy v2.ProtectionPolicy, rec protection.Record) bool {
	proto := strings.ToLower(strings.TrimSpace(policy.Protocol))
	if proto == "" {
		proto = v2.FirewallProtoTCP
	}
	bindProto := strings.ToLower(strings.TrimSpace(src.BindProtocol))
	if rec.Transport == "" && bindProto == "" {
		return false
	}
	transport := rec.Transport
	if transport == "" {
		transport = bindProto
	}
	if transport != "" && transport != proto {
		return false
	}
	if bindProto != "" && transport != "" && bindProto != transport {
		return false
	}
	port := strings.TrimSpace(policy.Port)
	bindPort := strings.TrimSpace(src.BindPort)
	if rec.ServerPort == 0 && bindPort == "" {
		return false
	}
	if port != "" && port != "*" {
		if rec.ServerPort > 0 && strconv.Itoa(rec.ServerPort) != port {
			return false
		}
		if rec.ServerPort == 0 && bindPort != "" && bindPort != port {
			return false
		}
	}
	if src.Format == v2.ProtectionLogNginxCombined && strings.Count(src.BindPort, ",") > 0 {
		return false
	}
	bind := strings.TrimSpace(policy.BindAddr)
	if bind != "" {
		dest := rec.DestAddr
		if dest == "" {
			dest = src.BindAddr
		}
		destIP, ok := v2.NormalizeProtectionIP(dest)
		bindIP, bindOK := v2.NormalizeProtectionIP(bind)
		if !ok || !bindOK || destIP != bindIP {
			return false
		}
	}
	return true
}

func hostAllowed(host, filter string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, item := range strings.Split(filter, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" && item == host {
			return true
		}
	}
	return false
}

func maxPolicyWindow(policies []v2.ProtectionPolicy) time.Duration {
	var max int
	for _, p := range policies {
		if p.RequestWindowSec > max {
			max = p.RequestWindowSec
		}
		if p.PathWindowSec > max {
			max = p.PathWindowSec
		}
	}
	if max <= 0 {
		return 2 * time.Minute
	}
	return time.Duration(max) * time.Second
}

func applyLogPolicy(cfg v2.ProtectionConfig, policy v2.ProtectionPolicy, src v2.ProtectionLogSource, rec protection.Record, ip string, now time.Time) {
	if isWhitelisted(&persistedProtection{Config: cfg}, ip) {
		return
	}
	if src.DeployMode == v2.ProtectionDeployProxy && policy.Mode == v2.ProtectionModeEnforce {
		return
	}
	if policy.RequestThreshold > 0 && policy.RequestWindowSec > 0 {
		window := time.Duration(policy.RequestWindowSec) * time.Second
		if window > 0 && now.Sub(rec.Time) <= window {
			key := ip + "|" + policy.ID + "|rate"
			n := rateCounter.Add(key, rec.Time, window)
			if n >= policy.RequestThreshold {
				reason := v2.ProtectionReasonRequestRate
				if src.Format == v2.ProtectionLogSSHD {
					reason = v2.ProtectionReasonSSHAuth
				}
				maybeBanFromLog(cfg, policy, ip, reason, rec.Time, now)
			}
		}
	}
	if src.Format == v2.ProtectionLogSSHD {
		return
	}
	if len(policy.Paths) > 0 && policy.PathThreshold > 0 && policy.PathWindowSec > 0 {
		if len(policy.PathStatus) > 0 && !statusListed(rec.Status, policy.PathStatus) {
			return
		}
		if !protection.PathMatches(rec.Path, policy.Paths) {
			return
		}
		window := time.Duration(policy.PathWindowSec) * time.Second
		if window > 0 && now.Sub(rec.Time) <= window {
			key := ip + "|" + policy.ID + "|path"
			n := pathCounter.Add(key, rec.Time, window)
			if n >= policy.PathThreshold {
				maybeBanFromLog(cfg, policy, ip, v2.ProtectionReasonPathScan, rec.Time, now)
			}
		}
	}
}

func statusListed(status int, list []int) bool {
	for _, item := range list {
		if item == status {
			return true
		}
	}
	return false
}

func protectionEventID(reasonType, policyID, ip string, logTime, resetAt time.Time, windowSec int) string {
	if windowSec <= 0 {
		windowSec = 60
	}
	unix := logTime.UTC().Unix()
	bucket := unix / int64(windowSec) * int64(windowSec)
	gen := int64(0)
	if !resetAt.IsZero() {
		gen = resetAt.UTC().Unix()
	}
	return reasonType + "|" + policyID + "|" + ip + "|" + strconv.FormatInt(bucket, 10) + "|" + strconv.FormatInt(gen, 10)
}

func maybeBanFromLog(cfg v2.ProtectionConfig, policy v2.ProtectionPolicy, ip, reasonType string, logTime, now time.Time) {
	window := policy.RequestWindowSec
	if reasonType == v2.ProtectionReasonPathScan {
		window = policy.PathWindowSec
	}
	if reasonType == v2.ProtectionReasonSSHAuth && window <= 0 {
		window = policy.RequestWindowSec
	}
	opMu.Lock()
	state := loadProtection()
	eventID := protectionEventID(reasonType, policy.ID, ip, logTime, resetTimeFor(ip), window)
	if protectionEventReported(eventID) {
		opMu.Unlock()
		return
	}
	reason := v2.ProtectionBanReason{
		BanID:      eventID,
		EventID:    eventID,
		IP:         ip,
		PolicyID:   policy.ID,
		ReasonType: reasonType,
		CreatedAt:  logTime.UTC().Format(time.RFC3339Nano),
		ExpiresAt:  v2.FormatProtectionBanExpiry(now, protectionBanSeconds(policy)),
		GroupID:    policy.GroupID,
		Status:     v2.ProtectionBanActive,
	}
	if cfg.Revision > 0 && state.Config.Revision != cfg.Revision {
		opMu.Unlock()
		return
	}
	if !state.Config.Enabled {
		opMu.Unlock()
		return
	}
	current := findProtectionPolicy(state.Config, policy.ID)
	if current == nil || !current.Enabled {
		opMu.Unlock()
		return
	}
	reason.GroupID = current.GroupID
	reason.ExpiresAt = v2.FormatProtectionBanExpiry(now, protectionBanSeconds(*current))
	if current.Mode != v2.ProtectionModeEnforce {
		rev := state.Config.Revision
		opMu.Unlock()
		if enqueueProtectionReport(v2.ProtectionReportParams{
			Kind:        v2.ProtectionKindReport,
			Hits:        []v2.ProtectionBanReason{reason},
			SourceStats: ProtectionSourceStats(),
			ConfigRev:   rev,
		}) {
			rememberProtectionEvent(eventID)
		}
		return
	}
	if !state.RuntimeEnabled {
		opMu.Unlock()
		return
	}
	applied, err := upsertBanLocked(state, reason)
	if err != nil {
		rememberProtectionEvent(eventID)
		opMu.Unlock()
		log.Printf("protection local ban: %v", err)
		enqueueProtectionReport(v2.ProtectionReportParams{
			Kind:      v2.ProtectionKindBan,
			Error:     err.Error(),
			Hits:      []v2.ProtectionBanReason{reason},
			ConfigRev: state.Config.Revision,
		})
		return
	}
	if isWhitelisted(state, ip) {
		opMu.Unlock()
		return
	}
	if len(applied) == 0 {
		opMu.Unlock()
		return
	}
	queued := enqueueProtectionReport(v2.ProtectionReportParams{
		Kind:         v2.ProtectionKindReport,
		Hits:         []v2.ProtectionBanReason{reason},
		Executions:   applied,
		SourceStats:  ProtectionSourceStats(),
		ConfigRev:    state.Config.Revision,
		GroupApplied: copyUint64Map(state.GroupApplied),
	})
	if queued {
		rememberProtectionEvent(eventID)
	}
	_ = saveProtection(state)
	opMu.Unlock()
}

func protectionEventReported(eventID string) bool {
	logMu.Lock()
	defer logMu.Unlock()
	_, ok := reportedEvents[eventID]
	return ok
}

func rememberProtectionEvent(eventID string) {
	if eventID == "" {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(reportedEvents) >= 8192 {
		reportedEvents = map[string]struct{}{}
	}
	reportedEvents[eventID] = struct{}{}
}

func protectionBanSeconds(policy v2.ProtectionPolicy) int {
	return v2.NormalizeProtectionBanSec(policy.BanDurationSec)
}

func enqueueProtectionReport(report v2.ProtectionReportParams) bool {
	logMu.Lock()
	defer logMu.Unlock()
	if len(reportQueue) >= protectionQueueLimit {
		st := logStats[""]
		st.QueueDropped++
		logStats[""] = st
		return false
	}
	reportQueue = append(reportQueue, report)
	return true
}

func maybeReportSourceStats(rev uint64, now time.Time) {
	logMu.Lock()
	if !lastStatsAt.IsZero() && now.Sub(lastStatsAt) < 15*time.Second {
		logMu.Unlock()
		return
	}
	lastStatsAt = now
	logMu.Unlock()
	enqueueProtectionReport(v2.ProtectionReportParams{
		Kind:        v2.ProtectionKindReport,
		SourceStats: ProtectionSourceStats(),
		ConfigRev:   rev,
	})
}

func maybeReportNetworkObserve(rev uint64, now time.Time) {
	logMu.Lock()
	if !lastNflogAt.IsZero() && now.Sub(lastNflogAt) < 15*time.Second {
		logMu.Unlock()
		return
	}
	logMu.Unlock()
	samples := sampleProtectionCounters()
	if len(samples) == 0 {
		return
	}
	logMu.Lock()
	lastNflogAt = now
	logMu.Unlock()
	enqueueProtectionReport(v2.ProtectionReportParams{
		Kind:      v2.ProtectionKindReport,
		Nflog:     samples,
		ConfigRev: rev,
	})
}

func ProtectionSourceStats() []v2.ProtectionSourceStats {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]v2.ProtectionSourceStats, 0, len(logStats))
	for _, st := range logStats {
		out = append(out, st)
	}
	return out
}

func copyUint64Map(in map[string]uint64) map[string]uint64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
