package server

import (
	"log"

	"github.com/nuomiiiii/lite-agent/firewall"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/ws"
)

func RestorePersistedFirewall() {
	firewall.RestorePersisted()
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
	if conn != nil && conn.WriteJSON(payload) == nil {
		return
	}
	if err := postV2RPC(payload); err != nil {
		log.Printf("failed to upload firewall result: %v", err)
	}
}
