package server

import (
	"log"
	"sync"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/firewall"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/ws"
)

var (
	protectionCmdCh = make(chan func(), 32)
	flushReportMu   sync.Mutex
)

func init() {
	go runProtectionCommands()
}

func runProtectionCommands() {
	for fn := range protectionCmdCh {
		fn()
	}
}

func enqueueProtectionCommand(fn func()) bool {
	select {
	case protectionCmdCh <- fn:
		return true
	default:
		return false
	}
}

func protectionMethodKind(method string) (string, bool) {
	switch method {
	case v2.MethodAgentProtectionPrecheck:
		return v2.ProtectionKindPrecheck, true
	case v2.MethodAgentProtectionUpgrade:
		return v2.ProtectionKindUpgrade, true
	case v2.MethodAgentProtectionApplyConfig:
		return v2.ProtectionKindApplyConfig, true
	case v2.MethodAgentProtectionBan:
		return v2.ProtectionKindBan, true
	case v2.MethodAgentProtectionUnban:
		return v2.ProtectionKindUnban, true
	case v2.MethodAgentProtectionGroupSnapshot:
		return v2.ProtectionKindGroupSnapshot, true
	case v2.MethodAgentProtectionPreview:
		return v2.ProtectionKindPreview, true
	default:
		return "", false
	}
}

func processProtectionEvent(conn *ws.SafeConn, method string, params interface{}) bool {
	kind, ok := protectionMethodKind(method)
	if !ok {
		return false
	}
	if !pkg_flags.RemoteControlEnabled() {
		reportProtectionResult(conn, v2.ProtectionResultParams{
			RequestID: protectionParamsRequestID(params),
			Kind:      kind,
			Status:    v2.ProtectionStatusError,
			Error:     "remote control is disabled.",
		})
		return true
	}
	switch method {
	case v2.MethodAgentProtectionPrecheck:
		return runProtectionRPC(conn, params, v2.ProtectionKindPrecheck, func(p v2.ProtectionRequest) v2.ProtectionResultParams {
			return withProtectionRequest(firewall.ProtectionPrecheck(), p.RequestID, v2.ProtectionKindPrecheck)
		})
	case v2.MethodAgentProtectionUpgrade:
		var p v2.ProtectionUpgradeParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindUpgrade, err)
			return true
		}
		go func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ProtectionUpgrade(p.OpID), p.RequestID, v2.ProtectionKindUpgrade))
		}()
		return true
	case v2.MethodAgentProtectionApplyConfig:
		var p v2.ProtectionApplyConfigParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindApplyConfig, err)
			return true
		}
		return enqueueOrReject(conn, p.RequestID, v2.ProtectionKindApplyConfig, func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ApplyProtectionConfig(p.Config), p.RequestID, v2.ProtectionKindApplyConfig))
		})
	case v2.MethodAgentProtectionBan:
		var p v2.ProtectionBanParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindBan, err)
			return true
		}
		return enqueueOrReject(conn, p.RequestID, v2.ProtectionKindBan, func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ProtectionBan(p.Reason, p.ObservedRevision), p.RequestID, v2.ProtectionKindBan))
		})
	case v2.MethodAgentProtectionUnban:
		var p v2.ProtectionUnbanParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindUnban, err)
			return true
		}
		return enqueueOrReject(conn, p.RequestID, v2.ProtectionKindUnban, func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ProtectionUnban(p), p.RequestID, v2.ProtectionKindUnban))
		})
	case v2.MethodAgentProtectionGroupSnapshot:
		var p v2.ProtectionGroupSnapshotParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindGroupSnapshot, err)
			return true
		}
		return enqueueOrReject(conn, p.RequestID, v2.ProtectionKindGroupSnapshot, func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ApplyProtectionGroupSnapshot(p.Snapshot), p.RequestID, v2.ProtectionKindGroupSnapshot))
		})
	case v2.MethodAgentProtectionPreview:
		var p v2.ProtectionPreviewParams
		if err := v2.BindParams(params, &p); err != nil {
			reportProtectionParamError(conn, params, v2.ProtectionKindPreview, err)
			return true
		}
		return enqueueOrReject(conn, p.RequestID, v2.ProtectionKindPreview, func() {
			reportProtectionResult(conn, withProtectionRequest(firewall.ProtectionPreview(p), p.RequestID, v2.ProtectionKindPreview))
		})
	default:
		return false
	}
}

func runProtectionRPC(conn *ws.SafeConn, params interface{}, kind string, fn func(v2.ProtectionRequest) v2.ProtectionResultParams) bool {
	var p v2.ProtectionRequest
	if err := v2.BindParams(params, &p); err != nil {
		reportProtectionParamError(conn, params, kind, err)
		return true
	}
	return enqueueOrReject(conn, p.RequestID, kind, func() {
		reportProtectionResult(conn, fn(p))
	})
}

func enqueueOrReject(conn *ws.SafeConn, requestID, kind string, fn func()) bool {
	if enqueueProtectionCommand(fn) {
		return true
	}
	reportProtectionResult(conn, v2.ProtectionResultParams{
		RequestID: requestID,
		Kind:      kind,
		Status:    v2.ProtectionStatusError,
		Error:     "protection command queue full",
	})
	return true
}

func protectionParamsRequestID(params interface{}) string {
	var p v2.ProtectionRequest
	if v2.BindParams(params, &p) == nil {
		return p.RequestID
	}
	if raw, ok := params.(map[string]interface{}); ok {
		if id, ok := raw["request_id"].(string); ok {
			return id
		}
	}
	return ""
}

func reportProtectionParamError(conn *ws.SafeConn, params interface{}, kind string, err error) {
	log.Printf("bad protection %s params: %v", kind, err)
	reportProtectionResult(conn, v2.ProtectionResultParams{
		RequestID: protectionParamsRequestID(params),
		Kind:      kind,
		Status:    v2.ProtectionStatusError,
		Error:     "invalid params",
	})
}

func withProtectionRequest(result v2.ProtectionResultParams, requestID, kind string) v2.ProtectionResultParams {
	result.RequestID = requestID
	if result.Kind == "" {
		result.Kind = kind
	}
	return result
}

func reportProtectionResult(conn *ws.SafeConn, result v2.ProtectionResultParams) {
	payload := v2.Request{JSONRPC: v2.Version, Method: v2.MethodAgentProtectionResult, Params: result}
	reportV2Result(conn, payload, "failed to upload protection result")
}

func FlushProtectionReports(conn *ws.SafeConn) {
	flushReportMu.Lock()
	defer flushReportMu.Unlock()
	reports := firewall.PeekProtectionReports()
	sent := 0
	for _, report := range reports {
		payload := v2.Request{JSONRPC: v2.Version, Method: v2.MethodAgentProtectionReport, Params: report}
		if err := sendProtectionReport(conn, payload); err != nil {
			log.Printf("failed to upload protection report: %v", err)
			firewall.AckProtectionReports(sent)
			return
		}
		sent++
	}
	firewall.AckProtectionReports(sent)
}

func sendProtectionReport(conn *ws.SafeConn, payload v2.Request) error {
	if conn != nil && conn.WriteJSON(payload) == nil {
		return nil
	}
	return postV2RPC(payload)
}
