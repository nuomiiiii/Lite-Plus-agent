package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/certstore"
	"github.com/nuomiiiii/lite-agent/nodemgt/coreadapter"
	"github.com/nuomiiiii/lite-agent/nodemgt/geostore"
	"github.com/nuomiiiii/lite-agent/nodemgt/quota"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

type Runtime struct {
	opMu          sync.Mutex
	mu            sync.Mutex
	dir           string
	certs         *certstore.Store
	geo           *geostore.Store
	cores         []coreadapter.Core
	users         []coreadapter.UserSpec
	denied        map[string]struct{}
	expiredDenied map[string]struct{}
	quotaDenied   map[string]struct{}
	usageSync     map[string]*userUsageSync
	lastSnap      json.RawMessage
	ops           opLog
	quota         *quota.Ledger
	cancel        context.CancelFunc
	result        func(method string, params any)
	sender        func(method string, params any) error
	geoBusy       atomic.Bool
}

type sentUsageBatch struct {
	BatchID string    `json:"batch_id"`
	Bytes   int64     `json:"bytes"`
	SentAt  time.Time `json:"sent_at"`
}

type userUsageSync struct {
	BaseUsed   int64            `json:"base_used"`
	ResetCycle string           `json:"reset_cycle"`
	InFlight   []sentUsageBatch `json:"in_flight"`
}

const maxSentUsageRetention = 30 * time.Minute

func usageDedupOpID(nodeUUID, batchID, userID string) string {
	sum := sha256.Sum256([]byte("usage:" + strings.TrimSpace(nodeUUID) + ":" + strings.TrimSpace(batchID) + ":" + strings.TrimSpace(userID)))
	return hex.EncodeToString(sum[:])
}

type snapshotMode int

const (
	snapApplyConfig snapshotMode = iota
	snapSyncQuota
	snapInternalReload
)

type opLog struct {
	LatestSeq    int            `json:"latest_seq"`
	LatestID     string         `json:"latest_apply_id"`
	LatestTarget string         `json:"latest_target"`
	Applied      map[string]int `json:"applied"`
}

type pendingUsage struct {
	BatchID string `json:"batch_id"`
	Items   []struct {
		UserID string `json:"user_id"`
		Bytes  int64  `json:"bytes"`
	} `json:"items"`
}

func mergeUsageItems(snaps []coreadapter.Snapshot) []struct {
	UserID string `json:"user_id"`
	Bytes  int64  `json:"bytes"`
} {
	byUser := map[string]int64{}
	order := make([]string, 0, len(snaps))
	for _, snap := range snaps {
		if snap.UserID == "" || snap.Bytes <= 0 {
			continue
		}
		if _, ok := byUser[snap.UserID]; !ok {
			order = append(order, snap.UserID)
		}
		byUser[snap.UserID] += snap.Bytes
	}
	sort.Strings(order)
	items := make([]struct {
		UserID string `json:"user_id"`
		Bytes  int64  `json:"bytes"`
	}, 0, len(order))
	for _, id := range order {
		items = append(items, struct {
			UserID string `json:"user_id"`
			Bytes  int64  `json:"bytes"`
		}{UserID: id, Bytes: byUser[id]})
	}
	return items
}

var global *Runtime

func Start(configFile string, result func(method string, params any)) (*Runtime, error) {
	dir := filepath.Join(filepath.Dir(configFile), "nodemgt")
	certs, err := certstore.Open(filepath.Join(dir, "certs"))
	if err != nil {
		return nil, err
	}
	geo, err := geostore.Open(filepath.Join(dir, "geo"))
	if err != nil {
		return nil, err
	}
	geostore.BindXray(geo.Dir)
	coreadapter.SetGeoAssetDir(geo.Dir)
	_ = os.MkdirAll(dir, 0o700)
	ctx, cancel := context.WithCancel(context.Background())
	rt := &Runtime{
		dir:           dir,
		certs:         certs,
		geo:           geo,
		cores:         coreadapter.All(),
		denied:        map[string]struct{}{},
		expiredDenied: map[string]struct{}{},
		quotaDenied:   map[string]struct{}{},
		usageSync:     map[string]*userUsageSync{},
		quota:         quota.New(),
		ops:           opLog{Applied: map[string]int{}},
		cancel:        cancel,
		result:        result,
	}
	global = rt
	log.Printf("Lite-Plus Agent cores: xray %s linked=%v; sing-box %s linked=%v",
		coreadapter.XrayVersion, rt.cores[0].Linked(),
		coreadapter.SingBoxVersion, rt.cores[1].Linked())
	rt.loadDenied()
	rt.loadExpired()
	rt.loadQuotaDenied()
	rt.loadOps()
	if err := rt.restore(); err != nil && !os.IsNotExist(err) {
		log.Printf("nodemgt restore: %v", err)
	}
	go rt.loop(ctx)
	return rt, nil
}

var liveInboundsHook atomic.Value

func SetLiveInboundsHook(fn func(bool)) {
	liveInboundsHook.Store(fn)
}

func notifyLiveInbounds(live bool) {
	v := liveInboundsHook.Load()
	if fn, ok := v.(func(bool)); ok && fn != nil {
		fn(live)
	}
}

func coresHaveLiveInbounds(cores []coreadapter.Core) bool {
	for _, core := range cores {
		if core != nil && core.LiveInbounds() {
			return true
		}
	}
	return false
}

func Current() *Runtime { return global }

func (r *Runtime) SetSender(fn func(method string, params any) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sender = fn
}

func (r *Runtime) loop(ctx context.Context) {
	expireTick := time.NewTicker(time.Second)
	usageTick := time.NewTicker(15 * time.Second)
	certTick := time.NewTicker(time.Minute)
	geoTick := time.NewTicker(12 * time.Hour)
	defer expireTick.Stop()
	defer usageTick.Stop()
	defer certTick.Stop()
	defer geoTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expireTick.C:
			r.expireUsers()
		case <-usageTick.C:
			r.FlushUsage()
		case <-certTick.C:
			r.reloadRenewedFileCerts()
		case <-geoTick.C:
			r.refreshGeo(ctx)
		}
	}
}

func (r *Runtime) refreshGeo(ctx context.Context) {
	if r == nil || r.geo == nil {
		return
	}
	if !r.geoBusy.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.geoBusy.Store(false)
		r.geo.RefreshStale(ctx)
	}()
}

func (r *Runtime) HandleControl(params any, eventID string) bool {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	raw, _ := json.Marshal(params)
	var cmd struct {
		OperationID string          `json:"operation_id"`
		Kind        string          `json:"kind"`
		Payload     json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return false
	}
	status, lastErr, fp := "applied", "", ""
	switch cmd.Kind {
	case "needCSR":
		var p struct {
			Domain   string   `json:"domain"`
			CertID   string   `json:"cert_id"`
			DNSNames []string `json:"dns_names"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		_, csr, err := r.certs.GenerateCSR(p.Domain, p.DNSNames...)
		if err != nil {
			status, lastErr = "failed", err.Error()
		} else if r.result != nil {
			r.result(v2.MethodNodemgtControlResult, map[string]any{
				"operation_id": cmd.OperationID,
				"status":       "applied",
				"csr_pem":      csr,
				"domain":       p.Domain,
				"cert_id":      p.CertID,
			})
			return true
		}
	case "applyCert":
		var p struct {
			Domain   string `json:"domain"`
			ChainPEM string `json:"chain_pem"`
			KeyPEM   string `json:"key_pem"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		var err error
		if strings.TrimSpace(p.KeyPEM) != "" {
			err = r.certs.SaveChainKey(p.Domain, p.ChainPEM, p.KeyPEM)
		} else {
			err = r.certs.SaveChain(p.Domain, p.ChainPEM)
		}
		if err != nil {
			status, lastErr = "failed", err.Error()
		} else if _, got, err := r.certs.TLSConfig(p.Domain); err == nil {
			fp = got
			if snap := r.currentSnapshot(); len(snap) > 0 {
				if err := r.applySnapshotModeLocked(snap, snapInternalReload); err != nil {
					status, lastErr = "failed", err.Error()
				}
			}
		} else {
			status, lastErr = "failed", err.Error()
		}
	case "revokeUser":
		var p struct {
			UserIDs []string `json:"user_ids"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		if err := r.persistDeny(p.UserIDs); err != nil {
			status, lastErr = "failed", err.Error()
			break
		}
		var firstErr error
		for _, core := range r.cores {
			for _, id := range p.UserIDs {
				if err := core.CloseUserSessions(id); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		if firstErr != nil {
			status, lastErr = "failed", firstErr.Error()
		}
	case "clearUserIPs":
		var p struct {
			UserIDs []string `json:"user_ids"`
		}
		_ = json.Unmarshal(cmd.Payload, &p)
		for _, id := range p.UserIDs {
			coreadapter.ClearUserIPs(id)
			for _, core := range r.cores {
				core.ClearUserIPs(id)
			}
		}
	default:
		if r.alreadyApplied(cmd.OperationID) {
			break
		}
		mode := snapApplyConfig
		if cmd.Kind == "syncQuota" {
			mode = snapSyncQuota
			if r.staleTarget(cmd.Payload) {
				break
			}
		}
		if err := r.applySnapshotModeWithOpLocked(cmd.Payload, mode, cmd.OperationID); err != nil {
			status, lastErr = "failed", err.Error()
		} else {
			r.noteApplied(cmd.OperationID)
			if mode == snapApplyConfig {
				r.noteTarget(cmd.Payload)
			}
		}
	}
	if r.result != nil {
		r.result(v2.MethodNodemgtControlResult, map[string]any{
			"operation_id": cmd.OperationID,
			"status":       status,
			"error":        lastErr,
			"fingerprint":  fp,
			"event_id":     eventID,
		})
	}
	if cmd.Kind == "applyConfig" || cmd.Kind == "applyCert" {
		r.reportFileCerts(true)
	}
	return true
}

func (r *Runtime) applySnapshot(payload json.RawMessage, keepDeny bool) error {
	if keepDeny {
		return r.applySnapshotMode(payload, snapSyncQuota)
	}
	return r.applySnapshotMode(payload, snapApplyConfig)
}

func (r *Runtime) applySnapshotMode(payload json.RawMessage, mode snapshotMode) error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	return r.applySnapshotModeLocked(payload, mode)
}

func (r *Runtime) applySnapshotModeLocked(payload json.RawMessage, mode snapshotMode) error {
	return r.applySnapshotModeWithOpLocked(payload, mode, "")
}

func (r *Runtime) reconcileMasterUsedLocked(nodeUUID string, ackedOps map[string]struct{}, opID string, mode snapshotMode, userID string, masterUsed int64, resetCycle string, now time.Time) int64 {
	if r.usageSync == nil {
		r.usageSync = map[string]*userUsageSync{}
	}
	st := r.usageSync[userID]
	if st == nil {
		r.usageSync[userID] = &userUsageSync{
			BaseUsed:   masterUsed,
			ResetCycle: resetCycle,
		}
		return masterUsed
	}
	cutoff := now.Add(-maxSentUsageRetention)
	pruned := st.InFlight[:0]
	for _, b := range st.InFlight {
		if b.Bytes > 0 && (b.SentAt.IsZero() || b.SentAt.After(cutoff)) {
			pruned = append(pruned, b)
		}
	}
	st.InFlight = pruned

	if strings.TrimSpace(nodeUUID) != "" {
		kept := st.InFlight[:0]
		var unconfirmed int64
		for _, b := range st.InFlight {
			if _, ok := ackedOps[usageDedupOpID(nodeUUID, b.BatchID, userID)]; ok {
				continue
			}
			kept = append(kept, b)
			unconfirmed += b.Bytes
		}
		st.InFlight = kept
		st.BaseUsed = masterUsed
		st.ResetCycle = resetCycle
		return masterUsed + unconfirmed
	}

	if mode == snapInternalReload {
		var unconfirmed int64
		for _, b := range st.InFlight {
			unconfirmed += b.Bytes
		}
		return masterUsed + unconfirmed
	}

	cycleChanged := resetCycle != "" && resetCycle != st.ResetCycle
	resetOp := strings.HasPrefix(strings.TrimSpace(opID), "traffic-reset:")
	rolledBack := masterUsed < st.BaseUsed
	if cycleChanged || resetOp || rolledBack {
		st.InFlight = nil
		st.BaseUsed = masterUsed
		st.ResetCycle = resetCycle
		return masterUsed
	}

	delta := masterUsed - st.BaseUsed
	rem := delta
	kept := st.InFlight[:0]
	var unconfirmed int64
	for _, b := range st.InFlight {
		if rem >= b.Bytes {
			rem -= b.Bytes
			continue
		}
		if rem > 0 {
			b.Bytes -= rem
			rem = 0
		}
		kept = append(kept, b)
		unconfirmed += b.Bytes
	}
	st.InFlight = kept
	st.BaseUsed = masterUsed
	st.ResetCycle = resetCycle
	return masterUsed + unconfirmed
}

func (r *Runtime) applySnapshotModeWithOpLocked(payload json.RawMessage, mode snapshotMode, opID string) error {
	var snap struct {
		NodeUUID      string   `json:"node_uuid"`
		AckedUsageOps []string `json:"acked_usage_ops"`
		Inbounds      []struct {
			ID           string `json:"id"`
			Core         string `json:"core"`
			Listen       string `json:"listen"`
			Port         int    `json:"port"`
			Protocol     string `json:"protocol"`
			Enabled      bool   `json:"enabled"`
			StreamJSON   string `json:"stream_json"`
			SettingsJSON string `json:"settings_json"`
		} `json:"inbounds"`
		Outbounds []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Protocol     string `json:"protocol"`
			SettingsJSON string `json:"settings_json"`
			Enabled      bool   `json:"enabled"`
		} `json:"outbounds"`
		Routes []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Priority int    `json:"priority"`
			RuleJSON string `json:"rule_json"`
			Enabled  bool   `json:"enabled"`
		} `json:"routes"`
		Users []struct {
			ID                string     `json:"id"`
			Username          string     `json:"username"`
			Status            string     `json:"status"`
			QuotaBytes        int64      `json:"quota_bytes"`
			UsedBytes         int64      `json:"used_bytes"`
			TrafficResetCycle string     `json:"traffic_reset_cycle"`
			RateLimitBps      int64      `json:"rate_limit_bps"`
			DeviceLimit       int        `json:"device_limit"`
			Flow              string     `json:"flow"`
			ExpiresAt         *time.Time `json:"expires_at"`
			InboundIDs        []string   `json:"inbound_ids"`
			Credentials       []struct {
				UUID      string     `json:"uuid"`
				Secret    string     `json:"secret"`
				Enabled   bool       `json:"enabled"`
				ExpiresAt *time.Time `json:"expires_at"`
			} `json:"credentials"`
		} `json:"users"`
		Certs []struct {
			ID       string `json:"id"`
			Domain   string `json:"domain"`
			Status   string `json:"status"`
			Source   string `json:"source"`
			CertPath string `json:"cert_path"`
			KeyPath  string `json:"key_path"`
		} `json:"certs"`
		DialStack string `json:"dial_stack"`
	}
	if err := json.Unmarshal(payload, &snap); err != nil {
		return err
	}
	ackedOps := make(map[string]struct{}, len(snap.AckedUsageOps))
	for _, op := range snap.AckedUsageOps {
		if op != "" {
			ackedOps[op] = struct{}{}
		}
	}
	now := time.Now().UTC()
	var users []coreadapter.UserSpec
	r.mu.Lock()
	if r.denied == nil {
		r.denied = map[string]struct{}{}
	}
	if r.expiredDenied == nil {
		r.expiredDenied = map[string]struct{}{}
	}
	if r.quotaDenied == nil {
		r.quotaDenied = map[string]struct{}{}
	}
	for _, u := range snap.Users {
		effectiveMasterUsed := r.reconcileMasterUsedLocked(snap.NodeUUID, ackedOps, opID, mode, u.ID, u.UsedBytes, u.TrafficResetCycle, now)
		expiredNow := u.Status == "expired" || (u.ExpiresAt != nil && !u.ExpiresAt.After(now))
		spec := coreadapter.UserSpec{
			ID:           u.ID,
			Username:     strings.TrimSpace(u.Username),
			QuotaBytes:   u.QuotaBytes,
			UsedBytes:    effectiveMasterUsed,
			RateLimitBps: u.RateLimitBps,
			DeviceLimit:  u.DeviceLimit,
			Disabled:     u.Status == "disabled" || expiredNow,
			Expired:      expiredNow,
			Flow:         u.Flow,
			ExpiresAt:    u.ExpiresAt,
			InboundIDs:   append([]string(nil), u.InboundIDs...),
		}
		if spec.InboundIDs == nil {
			spec.InboundIDs = []string{}
		}
		for _, c := range u.Credentials {
			if !c.Enabled {
				continue
			}
			if c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
				continue
			}
			spec.UUID = c.UUID
			spec.Password = c.Secret
			spec.CredExpiresAt = c.ExpiresAt
			if spec.Password == "" {
				spec.Password = c.UUID
			}
			break
		}
		if spec.UUID == "" && spec.Password == "" {
			continue
		}
		if _, ok := r.expiredDenied[spec.ID]; ok {
			if mode == snapInternalReload || spec.Disabled || spec.Expired {
				spec.Expired = true
				spec.Disabled = true
			} else {
				delete(r.expiredDenied, spec.ID)
			}
		} else if spec.Expired {
			r.expiredDenied[spec.ID] = struct{}{}
		}
		if _, ok := r.denied[spec.ID]; ok {
			if mode != snapApplyConfig || spec.Disabled || spec.Expired {
				spec.Disabled = true
			} else {
				delete(r.denied, spec.ID)
			}
		}
		hasQuotaRoom := spec.QuotaBytes <= 0 || spec.UsedBytes < spec.QuotaBytes
		if _, ok := r.quotaDenied[spec.ID]; ok {
			if mode == snapInternalReload {
				spec.Disabled = true
			} else if !spec.Disabled && !spec.Expired && hasQuotaRoom {
				delete(r.quotaDenied, spec.ID)
			} else {
				spec.Disabled = true
			}
		} else if !hasQuotaRoom {
			r.quotaDenied[spec.ID] = struct{}{}
			spec.Disabled = true
		}
		users = append(users, spec)
		r.quota.Configure(spec.ID, spec.QuotaBytes, spec.UsedBytes)
	}
	r.users = users
	r.mu.Unlock()
	certsByID := map[string]string{}
	keepFiles := map[string]struct{}{}
	for _, cert := range snap.Certs {
		if cert.ID != "" {
			certsByID[cert.ID] = cert.Domain
		}
		if strings.TrimSpace(cert.CertPath) != "" && strings.TrimSpace(cert.KeyPath) != "" && strings.TrimSpace(cert.Domain) != "" {
			r.certs.BindFile(cert.ID, cert.Domain, cert.CertPath, cert.KeyPath)
			keepFiles[cert.Domain] = struct{}{}
		}
	}
	r.certs.UnbindMissing(keepFiles)
	var inbounds []coreadapter.InboundSpec
	for _, in := range snap.Inbounds {
		if !in.Enabled {
			continue
		}
		spec := coreadapter.InboundSpec{
			ID: in.ID, Core: in.Core, Listen: in.Listen, Port: in.Port, Protocol: in.Protocol,
			StreamJSON: in.StreamJSON, SettingsJSON: in.SettingsJSON,
		}
		var settings struct {
			CertID string `json:"cert_id"`
		}
		_ = json.Unmarshal([]byte(in.SettingsJSON), &settings)
		domain := certsByID[settings.CertID]
		if domain != "" {
			if tlsCfg, _, err := r.certs.TLSConfig(domain); err == nil && tlsCfg != nil && len(tlsCfg.Certificates) > 0 {
				spec.TLS = tlsCfg
				if pem, key, err := r.certs.PEM(domain); err == nil {
					spec.CertPEM = string(pem)
					spec.KeyPEM = string(key)
				}
			}
		}
		inbounds = append(inbounds, spec)
	}
	var outs []coreadapter.OutboundSpec
	for _, row := range snap.Outbounds {
		outs = append(outs, coreadapter.OutboundSpec{
			ID: row.ID, Name: row.Name, Protocol: row.Protocol, SettingsJSON: row.SettingsJSON, Enabled: row.Enabled,
		})
	}
	var rts []coreadapter.RouteSpec
	for _, row := range snap.Routes {
		rts = append(rts, coreadapter.RouteSpec{
			ID: row.ID, Name: row.Name, Priority: row.Priority, RuleJSON: row.RuleJSON, Enabled: row.Enabled,
		})
	}
	ctx := context.Background()
	if cores := usedCoreNames(inbounds); len(cores) > 0 {
		if geosite, geoip := coreadapter.CollectGeo(rts); len(geosite) > 0 || len(geoip) > 0 {
			if err := r.geo.Ensure(ctx, geosite, geoip, cores...); err != nil {
				return fmt.Errorf("geo files: %w", err)
			}
		}
	}
	var firstErr error
	for _, core := range r.cores {
		if setter, ok := core.(interface {
			SetForwarding([]coreadapter.OutboundSpec, []coreadapter.RouteSpec)
		}); ok {
			setter.SetForwarding(outs, rts)
		}
		if setter, ok := core.(interface {
			SetDialStack(string)
		}); ok {
			setter.SetDialStack(snap.DialStack)
		}
		if stager, ok := core.(interface {
			StageUsers([]coreadapter.UserSpec)
		}); ok {
			stager.StageUsers(users)
		} else if err := core.ApplyUsers(users); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := core.Start(ctx, inbounds); err != nil {
			log.Printf("nodemgt core %s start: %v", core.Name(), err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	notifyLiveInbounds(coresHaveLiveInbounds(r.cores))
	if firstErr != nil {
		return firstErr
	}
	if err := atomicWrite(r.snapshotPath(), payload); err != nil {
		return err
	}
	if err := r.writeDenied(); err != nil {
		return err
	}
	if err := r.writeExpired(); err != nil {
		return err
	}
	if err := r.writeQuotaDenied(); err != nil {
		return err
	}
	r.mu.Lock()
	r.lastSnap = append(json.RawMessage(nil), payload...)
	r.mu.Unlock()
	return nil
}

func usedCoreNames(inbounds []coreadapter.InboundSpec) []string {
	xray, singbox := false, false
	for _, in := range inbounds {
		switch in.Core {
		case "", "xray":
			xray = true
		}
		switch in.Core {
		case "", "sing-box":
			singbox = true
		}
	}
	out := make([]string, 0, 2)
	if xray {
		out = append(out, "xray")
	}
	if singbox {
		out = append(out, "sing-box")
	}
	return out
}

func (r *Runtime) snapshotPath() string {
	return filepath.Join(r.dir, "last-snapshot.json")
}

func (r *Runtime) currentSnapshot() json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lastSnap) > 0 {
		return append(json.RawMessage(nil), r.lastSnap...)
	}
	return nil
}

func (r *Runtime) reloadRenewedFileCerts() {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	infos := r.certs.InspectFiles()
	needReload := false
	for _, info := range infos {
		if info.Changed && info.Err == nil {
			needReload = true
			break
		}
	}
	if needReload {
		if snap := r.currentSnapshot(); len(snap) > 0 {
			if err := r.applySnapshotModeLocked(snap, snapInternalReload); err != nil {
				log.Printf("nodemgt file cert reload: %v", err)
			}
		}
	}
	r.reportFileCertInfos(infos, false)
}

func (r *Runtime) reportFileCerts(all bool) {
	r.reportFileCertInfos(r.certs.InspectFiles(), all)
}

func (r *Runtime) reportFileCertInfos(infos []certstore.FileInfo, all bool) {
	if r.result == nil {
		return
	}
	for _, info := range infos {
		if !all && !info.Changed {
			continue
		}
		status, lastErr := "applied", ""
		if info.Err != nil {
			status, lastErr = "failed", info.Err.Error()
		}
		params := map[string]any{
			"status":      status,
			"error":       lastErr,
			"cert_id":     info.ID,
			"domain":      info.Domain,
			"fingerprint": info.Fingerprint,
		}
		if !info.NotAfter.IsZero() {
			params["not_after"] = info.NotAfter.UTC().Format(time.RFC3339)
		}
		if info.Issuer != "" {
			params["issuer"] = info.Issuer
		}
		r.result(v2.MethodNodemgtControlResult, params)
		if info.Err != nil {
			r.certs.RememberError(info.Domain, info.Err.Error())
		} else if info.Fingerprint != "" {
			r.certs.RememberFingerprint(info.Domain, info.Fingerprint)
		}
	}
}

func (r *Runtime) restore() error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	raw, err := os.ReadFile(r.snapshotPath())
	if err != nil {
		return err
	}
	if err := r.applySnapshotModeLocked(raw, snapInternalReload); err != nil {
		return err
	}
	for _, info := range r.certs.InspectFiles() {
		if info.Err == nil && info.Fingerprint != "" {
			r.certs.RememberFingerprint(info.Domain, info.Fingerprint)
		}
	}
	return nil
}

func (r *Runtime) expireUsers() {
	now := time.Now().UTC()
	var ids []string
	r.mu.Lock()
	if r.expiredDenied == nil {
		r.expiredDenied = map[string]struct{}{}
	}
	for i, u := range r.users {
		due := false
		if u.ExpiresAt != nil && !u.ExpiresAt.After(now) {
			due = true
		}
		if u.CredExpiresAt != nil && !u.CredExpiresAt.After(now) {
			due = true
		}
		if !due || u.Disabled || u.Expired {
			continue
		}
		r.users[i].Disabled = true
		r.users[i].Expired = true
		r.expiredDenied[u.ID] = struct{}{}
		ids = append(ids, u.ID)
	}
	r.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	_ = r.writeExpired()
	for _, core := range r.cores {
		for _, id := range ids {
			_ = core.CloseUserSessions(id)
		}
	}
}

func (r *Runtime) commitSentUsageItem(batchID string, item struct {
	UserID string `json:"user_id"`
	Bytes  int64  `json:"bytes"`
}) {
	r.opMu.Lock()
	defer r.opMu.Unlock()

	r.mu.Lock()
	if r.usageSync == nil {
		r.usageSync = map[string]*userUsageSync{}
	}
	st := r.usageSync[item.UserID]
	if st == nil {
		var base int64
		for i := range r.users {
			if r.users[i].ID == item.UserID {
				base = r.users[i].UsedBytes
				break
			}
		}
		st = &userUsageSync{BaseUsed: base}
		r.usageSync[item.UserID] = st
	}
	st.InFlight = append(st.InFlight, sentUsageBatch{
		BatchID: batchID,
		Bytes:   item.Bytes,
		SentAt:  time.Now().UTC(),
	})
	r.mu.Unlock()

	r.ackUsageItem(item.UserID, item.Bytes)
	r.applyFlushedUsageItem(item)
}

func (r *Runtime) ackUsageItem(userID string, bytes int64) {
	rem := bytes
	for _, core := range r.cores {
		if rem <= 0 {
			break
		}
		if acker, ok := core.(interface {
			AcknowledgeUsageItem(string, int64) int64
		}); ok {
			rem -= acker.AcknowledgeUsageItem(userID, rem)
		}
	}
}

func (r *Runtime) applyFlushedUsageItem(item struct {
	UserID string `json:"user_id"`
	Bytes  int64  `json:"bytes"`
}) {
	var exhausted bool
	r.mu.Lock()
	if r.quotaDenied == nil {
		r.quotaDenied = map[string]struct{}{}
	}
	found := false
	for i := range r.users {
		if r.users[i].ID == item.UserID {
			found = true
			r.users[i].UsedBytes += item.Bytes
			limit := r.users[i].QuotaBytes
			r.quota.Configure(item.UserID, limit, r.users[i].UsedBytes)
			if limit > 0 && r.users[i].UsedBytes >= limit {
				r.users[i].Disabled = true
				r.quotaDenied[item.UserID] = struct{}{}
				exhausted = true
			}
		}
	}
	if !found {
		used, limit, ok := r.quota.Add(item.UserID, item.Bytes)
		if !ok || (limit > 0 && used >= limit) {
			r.quotaDenied[item.UserID] = struct{}{}
			exhausted = true
		}
	}
	r.mu.Unlock()
	if exhausted {
		_ = r.writeQuotaDenied()
		for _, core := range r.cores {
			_ = core.CloseUserSessions(item.UserID)
		}
	}
}

func (r *Runtime) enforcePendingQuota(items []struct {
	UserID string `json:"user_id"`
	Bytes  int64  `json:"bytes"`
}) {
	if len(items) == 0 {
		return
	}
	var exhaustedIDs []string
	r.mu.Lock()
	if r.quotaDenied == nil {
		r.quotaDenied = map[string]struct{}{}
	}
	for _, item := range items {
		if item.UserID == "" || item.Bytes <= 0 {
			continue
		}
		for i := range r.users {
			if r.users[i].ID == item.UserID {
				limit := r.users[i].QuotaBytes
				if limit > 0 && r.users[i].UsedBytes+item.Bytes >= limit {
					r.users[i].Disabled = true
					if _, already := r.quotaDenied[item.UserID]; !already {
						r.quotaDenied[item.UserID] = struct{}{}
						exhaustedIDs = append(exhaustedIDs, item.UserID)
					}
				}
			}
		}
	}
	r.mu.Unlock()
	if len(exhaustedIDs) > 0 {
		_ = r.writeQuotaDenied()
		for _, id := range exhaustedIDs {
			for _, core := range r.cores {
				_ = core.CloseUserSessions(id)
			}
		}
	}
}

func (r *Runtime) FlushUsage() {
	pending, _ := r.loadPendingUsage()
	if pending == nil || len(pending.Items) == 0 {
		var items []struct {
			UserID string `json:"user_id"`
			Bytes  int64  `json:"bytes"`
		}
		var snaps []coreadapter.Snapshot
		for _, core := range r.cores {
			snaps = append(snaps, core.TakeSnapshots()...)
		}
		items = mergeUsageItems(snaps)
		if len(items) == 0 {
			r.flushPresence()
			for _, core := range r.cores {
				core.AcknowledgeUsage()
			}
			return
		}
		pending = &pendingUsage{BatchID: fmt.Sprintf("%d", time.Now().UnixNano()), Items: items}
		raw, _ := json.Marshal(pending)
		if err := atomicWrite(r.pendingUsagePath(), raw); err != nil {
			log.Printf("nodemgt usage persist: %v", err)
			return
		}
	}
	r.enforcePendingQuota(pending.Items)
	r.mu.Lock()
	send := r.sender
	result := r.result
	if send == nil && result != nil {
		send = func(method string, params any) error {
			result(method, params)
			return nil
		}
	}
	r.mu.Unlock()
	sentCount := 0
	var sendErr error
	for _, item := range pending.Items {
		if send != nil {
			if err := send(v2.MethodNodemgtUsage, map[string]any{
				"user_id":  item.UserID,
				"bytes":    item.Bytes,
				"batch_id": pending.BatchID,
			}); err != nil {
				sendErr = err
				break
			}
		}
		r.commitSentUsageItem(pending.BatchID, item)
		sentCount++
	}
	if sendErr != nil {
		log.Printf("nodemgt usage send: %v", sendErr)
		if sentCount > 0 {
			pending.Items = append([]struct {
				UserID string `json:"user_id"`
				Bytes  int64  `json:"bytes"`
			}(nil), pending.Items[sentCount:]...)
			if raw, err := json.Marshal(pending); err == nil {
				_ = atomicWrite(r.pendingUsagePath(), raw)
			}
		}
		return
	}
	r.flushPresence()
	for _, core := range r.cores {
		if _, ok := core.(interface {
			AcknowledgeUsageItem(string, int64) int64
		}); !ok {
			core.AcknowledgeUsage()
		}
	}
	_ = os.Remove(r.pendingUsagePath())
}

func (r *Runtime) flushPresence() {
	r.mu.Lock()
	send := r.sender
	result := r.result
	if send == nil && result != nil {
		send = func(method string, params any) error {
			result(method, params)
			return nil
		}
	}
	r.mu.Unlock()
	if send == nil {
		return
	}
	byUser := map[string]coreadapter.Presence{}
	for _, core := range r.cores {
		for _, row := range core.Presence() {
			if row.UserID == "" {
				continue
			}
			prev := byUser[row.UserID]
			prev.UserID = row.UserID
			prev.Online = prev.Online || row.Online
			prev.IPs = mergePresenceIPs(prev.IPs, row.IPs)
			byUser[row.UserID] = prev
		}
	}
	if len(byUser) == 0 {
		return
	}
	users := make([]map[string]any, 0, len(byUser))
	for _, row := range byUser {
		ips := make([]map[string]any, 0, len(row.IPs))
		for _, ip := range row.IPs {
			ips = append(ips, map[string]any{"ip": ip.IP, "seen_at": ip.SeenAt.UTC().Format(time.RFC3339)})
		}
		users = append(users, map[string]any{
			"user_id": row.UserID,
			"online":  row.Online,
			"ips":     ips,
		})
	}
	if err := send(v2.MethodNodemgtPresence, map[string]any{"users": users}); err != nil {
		log.Printf("nodemgt presence send: %v", err)
	}
}

func mergePresenceIPs(a, b []coreadapter.PresenceIP) []coreadapter.PresenceIP {
	seen := map[string]coreadapter.PresenceIP{}
	for _, ip := range append(append([]coreadapter.PresenceIP(nil), a...), b...) {
		if ip.IP == "" {
			continue
		}
		prev, ok := seen[ip.IP]
		if !ok || ip.SeenAt.After(prev.SeenAt) {
			seen[ip.IP] = ip
		}
	}
	out := make([]coreadapter.PresenceIP, 0, len(seen))
	for _, ip := range seen {
		out = append(out, ip)
	}
	return out
}

func (r *Runtime) pendingUsagePath() string {
	return filepath.Join(r.dir, "pending-usage.json")
}

func (r *Runtime) loadPendingUsage() (*pendingUsage, error) {
	raw, err := os.ReadFile(r.pendingUsagePath())
	if err != nil {
		return nil, err
	}
	var pending pendingUsage
	if err := json.Unmarshal(raw, &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

func (r *Runtime) alreadyApplied(opID string) bool {
	if opID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ops.Applied[opID]
	return ok
}

func (r *Runtime) staleTarget(payload json.RawMessage) bool {
	fp := targetFingerprint(payload)
	if fp == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ops.LatestTarget != "" && r.ops.LatestTarget != fp
}

func (r *Runtime) noteTarget(payload json.RawMessage) {
	fp := targetFingerprint(payload)
	if fp == "" {
		return
	}
	r.mu.Lock()
	r.ops.LatestTarget = fp
	st := r.ops
	r.mu.Unlock()
	raw, _ := json.Marshal(st)
	_ = atomicWrite(filepath.Join(r.dir, "op-log.json"), raw)
}

func targetFingerprint(payload json.RawMessage) string {
	var snap struct {
		Inbounds json.RawMessage `json:"inbounds"`
		Users    []struct {
			ID          string `json:"id"`
			Status      string `json:"status"`
			Credentials []struct {
				UUID    string `json:"uuid"`
				Secret  string `json:"secret"`
				Enabled bool   `json:"enabled"`
			} `json:"credentials"`
		} `json:"users"`
	}
	if json.Unmarshal(payload, &snap) != nil {
		return ""
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r *Runtime) noteApplied(opID string) {
	if opID == "" {
		return
	}
	r.mu.Lock()
	if r.ops.Applied == nil {
		r.ops.Applied = map[string]int{}
	}
	r.ops.LatestSeq++
	r.ops.Applied[opID] = r.ops.LatestSeq
	r.ops.LatestID = opID
	st := r.ops
	r.mu.Unlock()
	raw, _ := json.Marshal(st)
	_ = atomicWrite(filepath.Join(r.dir, "op-log.json"), raw)
}

func (r *Runtime) loadOps() {
	raw, err := os.ReadFile(filepath.Join(r.dir, "op-log.json"))
	if err != nil {
		return
	}
	var st opLog
	if json.Unmarshal(raw, &st) == nil {
		if st.Applied == nil {
			st.Applied = map[string]int{}
		}
		r.ops = st
	}
}

func (r *Runtime) persistDeny(ids []string) error {
	r.mu.Lock()
	if r.denied == nil {
		r.denied = map[string]struct{}{}
	}
	for _, id := range ids {
		if id != "" {
			r.denied[id] = struct{}{}
		}
		for i := range r.users {
			if r.users[i].ID == id {
				r.users[i].Disabled = true
			}
		}
	}
	r.mu.Unlock()
	return r.writeDenied()
}

func (r *Runtime) writeDenied() error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.denied))
	for id := range r.denied {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	raw, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.dir, "denied.json"), raw)
}

func (r *Runtime) loadDenied() {
	raw, err := os.ReadFile(filepath.Join(r.dir, "denied.json"))
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return
	}
	r.denied = map[string]struct{}{}
	for _, id := range ids {
		r.denied[id] = struct{}{}
	}
}

func (r *Runtime) writeExpired() error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.expiredDenied))
	for id := range r.expiredDenied {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	raw, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.dir, "expired.json"), raw)
}

func (r *Runtime) loadExpired() {
	raw, err := os.ReadFile(filepath.Join(r.dir, "expired.json"))
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return
	}
	r.expiredDenied = map[string]struct{}{}
	for _, id := range ids {
		if id != "" {
			r.expiredDenied[id] = struct{}{}
		}
	}
}

func (r *Runtime) writeQuotaDenied() error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.quotaDenied))
	for id := range r.quotaDenied {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	raw, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(r.dir, "quota-denied.json"), raw)
}

func (r *Runtime) loadQuotaDenied() {
	raw, err := os.ReadFile(filepath.Join(r.dir, "quota-denied.json"))
	if err != nil {
		return
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return
	}
	r.quotaDenied = map[string]struct{}{}
	for _, id := range ids {
		if id != "" {
			r.quotaDenied[id] = struct{}{}
		}
	}
}

func atomicWrite(path string, data []byte) error {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return fmt.Errorf("cannot write snapshot: %s is a directory", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
