package server

import (
	"log"
	"sync"
	"time"

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

func processFirewallEvent(conn *ws.SafeConn, method string, params interface{}) bool {
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
