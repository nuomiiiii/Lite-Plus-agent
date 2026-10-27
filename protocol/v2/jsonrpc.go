package v2

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

const (
	Version                    = "2.0"
	MethodAgentReport          = "agent.report"
	MethodAgentBasicInfo       = "agent.basicInfo"
	MethodAgentPingResult      = "agent.pingResult"
	MethodAgentRouteResult     = "agent.routeResult"
	MethodAgentTaskResult      = "agent.taskResult"
	MethodAgentExec            = "agent.exec"
	MethodAgentMCPExec         = "agent.mcp.exec"
	MethodAgentMCPCancel       = "agent.mcp.cancel"
	MethodAgentMCPRenew        = "agent.mcp.renew"
	MethodAgentMCPRevoke       = "agent.mcp.revoke"
	MethodAgentMCPFile         = "agent.mcp.file"
	MethodAgentPing            = "agent.ping"
	MethodAgentRoute           = "agent.route"
	MethodAgentMessage         = "agent.message"
	MethodAgentEvent           = "agent.event"
	MethodAgentRemote          = "agent.remote.request"
	MethodAgentConfig          = "agent.config"
	MethodAgentConfigResult    = "agent.configResult"
	MethodAgentPull            = "agent.pull"
	MethodNodemgtControl       = "nodemgt.control"
	MethodNodemgtControlResult = "nodemgt.controlResult"
	MethodNodemgtUsage          = "nodemgt.usage"
	MethodNodemgtPresence       = "nodemgt.presence"
	MethodAgentFirewallSnapshot = "agent.firewall.snapshot"
	MethodAgentFirewallApply    = "agent.firewall.apply"
	MethodAgentFirewallAdopt    = "agent.firewall.adopt"
	MethodAgentFirewallResult   = "agent.firewall.result"

	CapabilityMCPFull  = "mcp_full"
	MCPFullVersion     = 1
	CapabilityFirewall = "firewall"
	FirewallVersion    = 1

	TaskResultStatusFinished    = "finished"
	TaskResultStatusInterrupted = "interrupted"
)

type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Event struct {
	ID        string      `json:"id"`
	Method    string      `json:"method"`
	Params    interface{} `json:"params,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
	ExpiresAt string      `json:"expires_at,omitempty"`
}

type EventResult struct {
	Status string  `json:"status,omitempty"`
	Events []Event `json:"events,omitempty"`
}

type ConfigParams struct {
	Revision            uint64   `json:"revision,omitempty"`
	MonthRotate         *int     `json:"month_rotate,omitempty"`
	MonthRotateTime     *string  `json:"month_rotate_time,omitempty"`
	MonthRotateTimezone *string  `json:"month_rotate_timezone,omitempty"`
	Interval            *float64 `json:"interval,omitempty"`
	IncludeNics         *string  `json:"include_nics,omitempty"`
	ExcludeNics         *string  `json:"exclude_nics,omitempty"`
	IncludeMountpoints  *string  `json:"include_mountpoints,omitempty"`
	MemoryIncludeCache  *bool    `json:"memory_include_cache,omitempty"`
	EnableGPU           *bool    `json:"enable_gpu,omitempty"`
}

type ConfigResultParams struct {
	Revision uint64 `json:"revision"`
	EventID  string `json:"event_id,omitempty"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type BasicInfoParams struct {
	Info         map[string]interface{} `json:"info"`
	ConfigState  *ConfigParams          `json:"config_state,omitempty"`
	ConfigResult *ConfigResultParams    `json:"config_result,omitempty"`
	Platform     string                 `json:"platform,omitempty"`
}

type RouteHop struct {
	TTL       int     `json:"ttl"`
	IP        string  `json:"ip,omitempty"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Timeout   bool    `json:"timeout,omitempty"`
}

type RouteParams struct {
	TaskID    uint   `json:"task_id"`
	Protocol  string `json:"protocol"`
	Target    string `json:"target"`
	IPVersion int    `json:"ip_version"`
	MaxHops   int    `json:"max_hops"`
}

type RemoteRequestParams struct {
	RequestID string `json:"request_id"`
	Ticket    string `json:"ticket"`
}

type MCPExecParams struct {
	TaskID                 string `json:"task_id"`
	LeaseID                string `json:"lease_id"`
	OperationID            string `json:"operation_id"`
	AgentUUID              string `json:"agent_uuid"`
	Mode                   string `json:"mode,omitempty"`
	Command                string `json:"command"`
	Cwd                    string `json:"cwd,omitempty"`
	ExpiresAt              string `json:"expires_at,omitempty"`
	OperationDeadline      string `json:"operation_deadline,omitempty"`
	ExecutionLeaseDeadline string `json:"execution_lease_deadline,omitempty"`
	RequestDigest          string `json:"request_digest,omitempty"`
}

type MCPCancelParams struct {
	OperationID string `json:"operation_id"`
	LeaseID     string `json:"lease_id"`
}

type MCPRenewParams struct {
	LeaseID                string `json:"lease_id"`
	ExecutionLeaseDeadline string `json:"execution_lease_deadline,omitempty"`
}

type MCPRevokeParams struct {
	LeaseID string `json:"lease_id"`
}

type MCPFileParams struct {
	TaskID                 string          `json:"task_id"`
	LeaseID                string          `json:"lease_id"`
	OperationID            string          `json:"operation_id"`
	Request                json.RawMessage `json:"request"`
	ExpiresAt              string          `json:"expires_at,omitempty"`
	OperationDeadline      string          `json:"operation_deadline,omitempty"`
	ExecutionLeaseDeadline string          `json:"execution_lease_deadline,omitempty"`
}

func NewNotification(method string, params interface{}) []byte {
	payload, _ := json.Marshal(Request{JSONRPC: Version, Method: method, Params: params})
	return payload
}

func NewRequest(id interface{}, method string, params interface{}) []byte {
	payload, _ := json.Marshal(Request{JSONRPC: Version, Method: method, Params: params, ID: id})
	return payload
}

func BuildReportPayload(report []byte) []byte {
	return NewNotification(MethodAgentReport, reportParams{Report: json.RawMessage(report)})
}

func BuildReportRequest(id interface{}, report []byte, ackEventIDs []string) []byte {
	return NewRequest(id, MethodAgentReport, reportParams{Report: json.RawMessage(report), AckEventIDs: ackEventIDs})
}

func BuildBasicInfoPayload(info map[string]interface{}, configState ConfigParams, configResult *ConfigResultParams, platform string) []byte {
	return NewNotification(MethodAgentBasicInfo, BasicInfoParams{
		Info:         info,
		ConfigState:  &configState,
		ConfigResult: configResult,
		Platform:     platform,
	})
}

type reportParams struct {
	Report      json.RawMessage `json:"report"`
	AckEventIDs []string        `json:"ack_event_ids,omitempty"`
}

// pingResultWireValues 把探测值拆成旧版能写入的整数毫秒，以及新版使用的小数毫秒。
// 失败、NaN、Inf 两边都记为 -1。
func pingResultWireValues(value float64) (int64, float64) {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return -1, -1
	}
	return int64(math.Round(value)), value
}

func BuildPingResultPayload(taskID uint, pingType string, value float64, finishedAt time.Time) interface{} {
	whole, precise := pingResultWireValues(value)
	return Request{
		JSONRPC: Version,
		Method:  MethodAgentPingResult,
		Params: map[string]interface{}{
			"task_id":     taskID,
			"ping_type":   pingType,
			"value":       whole,
			"value_ms":    precise,
			"finished_at": finishedAt.Format(time.RFC3339Nano),
		},
	}
}

func BuildTaskResultPayload(taskID, result string, exitCode int, finishedAt time.Time, status string) interface{} {
	params := map[string]interface{}{
		"task_id":     taskID,
		"result":      result,
		"exit_code":   exitCode,
		"finished_at": finishedAt.UTC().Format(time.RFC3339Nano),
	}
	if status != "" {
		params["status"] = status
	}
	return Request{
		JSONRPC: Version,
		Method:  MethodAgentTaskResult,
		Params:  params,
	}
}

func BuildRouteResultPayload(task RouteParams, hops []RouteHop, probeError string, finishedAt time.Time, resolvedTarget string, targetReached bool) interface{} {
	params := map[string]interface{}{
		"task_id": task.TaskID, "protocol": task.Protocol, "target": task.Target,
		"ip_version": task.IPVersion, "hops": hops, "error": probeError,
		"finished_at": finishedAt.Format(time.RFC3339Nano),
	}
	if strings.TrimSpace(resolvedTarget) != "" {
		params["resolved_target_ip"] = resolvedTarget
	}
	if targetReached {
		params["target_reached"] = true
	}
	return Request{
		JSONRPC: Version,
		Method:  MethodAgentRouteResult,
		Params:  params,
	}
}

func BindParams(raw interface{}, target interface{}) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

func BindResult(raw interface{}, target interface{}) error {
	return BindParams(raw, target)
}
