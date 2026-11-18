package server

import (
	"log"
	"sync"
	"time"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/firewall"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/ws"
)

var (
	liveWSMu sync.Mutex
	liveWS   *ws.SafeConn
)

func setLiveWebSocket(conn *ws.SafeConn) {
	liveWSMu.Lock()
	liveWS = conn
	liveWSMu.Unlock()
}

func clearLiveWebSocket(conn *ws.SafeConn) {
	liveWSMu.Lock()
	if liveWS == conn {
		liveWS = nil
	}
	liveWSMu.Unlock()
}

func liveControlPlanePeer() string {
	liveWSMu.Lock()
	conn := liveWS
	liveWSMu.Unlock()
	if conn == nil {
		return ""
	}
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

func RestorePersistedFirewall() {
	firewall.SetControlPlanePeer(liveControlPlanePeer)
	if err := firewall.RestorePersisted(); err != nil {
		log.Printf("firewall restore: %v", err)
	}
}

func WatchPersistedFirewall() {
	firewall.SetControlPlanePeer(liveControlPlanePeer)
	go flushProtectionReportsLoop()
	firewall.WatchOwned()
}

func flushProtectionReportsLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		FlushProtectionReports(nil)
	}
}

func firewallMethodKind(method string) (string, bool) {
	switch method {
	case v2.MethodAgentFirewallSnapshot:
		return v2.FirewallKindSnapshot, true
	case v2.MethodAgentFirewallApply:
		return v2.FirewallKindApply, true
	case v2.MethodAgentFirewallAdopt:
		return v2.FirewallKindAdopt, true
	case v2.MethodAgentFirewallInstall:
		return v2.FirewallKindInstall, true
	default:
		return "", false
	}
}

func processFirewallEvent(conn *ws.SafeConn, method string, params interface{}) bool {
	kind, ok := firewallMethodKind(method)
	if !ok {
		return false
	}
	if !pkg_flags.RemoteControlEnabled() {
		var req struct {
			RequestID string `json:"request_id"`
		}
		_ = v2.BindParams(params, &req)
		go reportFirewallResult(conn, v2.FirewallResultParams{
			RequestID: req.RequestID,
			Kind:      kind,
			Status:    v2.FirewallStatusError,
			Error:     "remote control is disabled.",
		})
		return true
	}
	switch method {
	case v2.MethodAgentFirewallSnapshot:
		var p v2.FirewallSnapshotParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall snapshot params: %v", err)
			return true
		}
		go reportFirewallResult(conn, withRequest(firewall.Snapshot(), p.RequestID, v2.FirewallKindSnapshot))
		return true
	case v2.MethodAgentFirewallApply:
		var p v2.FirewallApplyParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall apply params: %v", err)
			return true
		}
		go reportFirewallResult(conn, withRequest(firewall.Apply(p.Intent, p.ListenHoles), p.RequestID, v2.FirewallKindApply))
		return true
	case v2.MethodAgentFirewallAdopt:
		var p v2.FirewallAdoptParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall adopt params: %v", err)
			return true
		}
		go reportFirewallResult(conn, withRequest(firewall.Adopt(p.Keys), p.RequestID, v2.FirewallKindAdopt))
		return true
	case v2.MethodAgentFirewallInstall:
		var p v2.FirewallInstallParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall install params: %v", err)
			return true
		}
		go reportFirewallResult(conn, withRequest(firewall.InstallNftables(), p.RequestID, v2.FirewallKindInstall))
		return true
	default:
		return false
	}
}

func withRequest(result v2.FirewallResultParams, requestID, kind string) v2.FirewallResultParams {
	result.RequestID = requestID
	if result.Kind == "" {
		result.Kind = kind
	}
	return result
}

func reportFirewallResult(conn *ws.SafeConn, result v2.FirewallResultParams) {
	payload := v2.Request{JSONRPC: v2.Version, Method: v2.MethodAgentFirewallResult, Params: result}
	reportV2Result(conn, payload, "failed to upload firewall result")
}
