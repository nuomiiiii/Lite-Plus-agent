package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/dnsresolver"
	"github.com/nuomiiiii/lite-agent/monitoring"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/runtimeconfig"
	"github.com/nuomiiiii/lite-agent/terminal"
	"github.com/nuomiiiii/lite-agent/utils"
	"github.com/nuomiiiii/lite-agent/ws"
)

var (
	v2AckMu        sync.Mutex
	v2AckEventIDs  []string
	v2SeenEvents   = make(map[string]struct{})
	v2SeenEventIDs []string
)

const v2SeenEventLimit = 512

const (
	websocketHeartbeatInterval  = 30 * time.Second
	websocketPongWait           = 60 * time.Second
	websocketHandshakeAliveWait = 10 * time.Second
	websocketReconnectDelay     = 1500 * time.Millisecond
	remoteWebSocketReadLimit    = 2 << 20
)

var v2BasePullCapabilities = []string{"exec", "ping", "route", "message", "event", "remote", "files", "config"}

func currentV2PullCapabilities() ([]string, map[string]int) {
	caps := append([]string(nil), v2BasePullCapabilities...)
	versions := map[string]int{}
	if pkg_flags.RemoteControlEnabled() {
		caps = append(caps, v2.CapabilityMCPFull)
		versions[v2.CapabilityMCPFull] = v2.MCPFullVersion
		caps = append(caps, v2.CapabilityFirewall)
		versions[v2.CapabilityFirewall] = v2.FirewallVersion
	}
	return caps, versions
}

func v2PullPayload(ackIDs []string) []byte {
	caps, versions := currentV2PullCapabilities()
	return v2.NewRequest(fmt.Sprintf("pull-%d", time.Now().UnixNano()), v2.MethodAgentPull, map[string]interface{}{
		"capabilities":        caps,
		"capability_versions": versions,
		"ack_event_ids":       ackIDs,
	})
}

func advertiseV2PullCapabilities(conn *ws.SafeConn) error {
	if conn == nil {
		return nil
	}
	return conn.WriteMessage(websocket.TextMessage, v2PullPayload(snapshotV2AckEventIDs()))
}

type agentWebSocketSession struct {
	conn     *ws.SafeConn
	readDone <-chan struct{}
}

func (s *agentWebSocketSession) drop(reason string) {
	if reason != "" {
		log.Println(reason)
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.readDone = nil
}

func (s *agentWebSocketSession) attach(conn *ws.SafeConn) {
	s.conn = conn
	done := make(chan struct{})
	s.readDone = done
	go handleWebSocketMessages(conn, done)
}

func (s *agentWebSocketSession) dial() (shouldExit bool) {
	if s.conn != nil {
		return false
	}
	log.Println("Attempting to connect to WebSocket...")
	retry := 0
	for retry <= flags.MaxRetries {
		if retry > 0 {
			log.Println("Retrying websocket connection, attempt:", retry)
		}
		conn, err := connectWebSocket(buildWebSocketEndpoint())
		if err == nil {
			s.attach(conn)
			return false
		}
		log.Println("Failed to connect to WebSocket:", err)
		retry++
		time.Sleep(time.Duration(flags.ReconnectInterval) * time.Second)
	}

	log.Println("Max retries reached.")
	conn, err := runPostFallback(buildWebSocketEndpoint())
	if err != nil {
		log.Println("POST fallback stopped:", err)
		return true
	}
	log.Println("WebSocket recovered from POST fallback")
	s.attach(conn)
	return false
}

func EstablishWebSocketConnection() {
	session := &agentWebSocketSession{}
	defer session.drop("")

	dataTicker := time.NewTicker(reportIntervalDuration())
	defer dataTicker.Stop()

	heartbeatTicker := time.NewTicker(websocketHeartbeatInterval)
	defer heartbeatTicker.Stop()

	if session.dial() {
		return
	}

	for {
		select {
		case <-dataTicker.C:
			if session.dial() {
				return
			}
			if session.conn == nil {
				continue
			}
			data := v2.BuildReportPayload(monitoring.GenerateReport())
			if err := session.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println("Failed to send WebSocket message:", err)
				session.drop("WebSocket write failed, reconnecting")
				time.Sleep(websocketReconnectDelay)
				if session.dial() {
					return
				}
			}
		case <-heartbeatTicker.C:
			if session.conn == nil {
				continue
			}
			if err := session.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Println("Failed to send heartbeat:", err)
				session.drop("WebSocket heartbeat failed, reconnecting")
				time.Sleep(websocketReconnectDelay)
				if session.dial() {
					return
				}
			}
		case <-runtimeconfig.Changes():
			dataTicker.Reset(reportIntervalDuration())
		case <-session.readDone:
			log.Println("WebSocket disconnected, reconnecting")
			session.drop("")
			time.Sleep(websocketReconnectDelay)
			if session.dial() {
				return
			}
		}
	}
}

func buildWebSocketEndpoint() string {
	websocketEndpoint := strings.TrimSuffix(flags.Endpoint, "/") + "/api/clients/v2/rpc"
	websocketEndpoint = "ws" + strings.TrimPrefix(websocketEndpoint, "http")
	if convertedEndpoint, err := utils.ConvertIDNToASCII(websocketEndpoint); err == nil {
		return convertedEndpoint
	} else {
		log.Printf("Warning: Failed to convert WebSocket IDN to ASCII: %v", err)
	}
	return websocketEndpoint
}

func runPostFallback(websocketEndpoint string) (*ws.SafeConn, error) {
	log.Println("Entering v2 POST fallback mode")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runV2PullLoop(ctx)

	reportTicker := time.NewTicker(reportIntervalDuration())
	defer reportTicker.Stop()
	reconnectTicker := time.NewTicker(time.Duration(flags.ReconnectInterval) * time.Second)
	defer reconnectTicker.Stop()

	for {
		select {
		case <-reportTicker.C:
			reportID := fmt.Sprintf("report-%d", time.Now().UnixNano())
			ackIDs := snapshotV2AckEventIDs()
			resp, err := postV2Request(v2.BuildReportRequest(reportID, monitoring.GenerateReport(), ackIDs))
			if err != nil {
				log.Println("Failed to POST v2 report:", err)
				continue
			}
			clearV2AckEventIDs(ackIDs)
			processV2ResponseEvents(resp)
		case <-reconnectTicker.C:
			conn, err := connectWebSocket(websocketEndpoint)
			if err == nil {
				return conn, nil
			}
			log.Println("POST fallback WebSocket recovery failed:", err)
		case <-runtimeconfig.Changes():
			reportTicker.Reset(reportIntervalDuration())
		}
	}
}

func reportIntervalDuration() time.Duration {
	return time.Duration(runtimeconfig.ReportInterval() * float64(time.Second))
}

func runV2PullLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		ackIDs := snapshotV2AckEventIDs()
		resp, err := postV2RequestContext(ctx, v2PullPayload(ackIDs))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to POST v2 pull:", err)
			time.Sleep(time.Duration(flags.ReconnectInterval) * time.Second)
			continue
		}
		clearV2AckEventIDs(ackIDs)
		processV2ResponseEvents(resp)
	}
}

func postV2Request(payload []byte) (*v2.Response, error) {
	return postV2RequestContext(context.Background(), payload)
}

func postV2RequestContext(ctx context.Context, payload []byte) (*v2.Response, error) {
	status, bytesBody, err := postV2JSONRPC(ctx, payload, 35*time.Second)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &httpStatusError{StatusCode: status, Status: http.StatusText(status), Body: string(bytesBody)}
	}
	rpcResp, err := parseV2Response(bytesBody)
	if err != nil {
		return nil, err
	}
	return rpcResp, nil
}

func processV2ResponseEvents(resp *v2.Response) {
	if resp == nil || resp.Result == nil {
		return
	}
	var result v2.EventResult
	if err := v2.BindResult(resp.Result, &result); err != nil {
		log.Println("Failed to bind v2 event result:", err)
		return
	}
	for _, event := range result.Events {
		if processV2Event(nil, event.Method, event.Params, event.ID) {
			addV2AckEventID(event.ID)
		}
	}
}

func snapshotV2AckEventIDs() []string {
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	return append([]string{}, v2AckEventIDs...)
}

func clearV2AckEventIDs(sent []string) {
	if len(sent) == 0 {
		return
	}
	sentSet := make(map[string]struct{}, len(sent))
	for _, id := range sent {
		sentSet[id] = struct{}{}
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	remaining := v2AckEventIDs[:0]
	for _, id := range v2AckEventIDs {
		if _, ok := sentSet[id]; !ok {
			remaining = append(remaining, id)
		}
	}
	v2AckEventIDs = remaining
}

func addV2AckEventID(id string) {
	if id == "" {
		return
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	v2AckEventIDs = append(v2AckEventIDs, id)
}

func markV2EventSeen(id string) bool {
	if id == "" {
		return true
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	if _, ok := v2SeenEvents[id]; ok {
		return false
	}
	v2SeenEvents[id] = struct{}{}
	v2SeenEventIDs = append(v2SeenEventIDs, id)
	if len(v2SeenEventIDs) > v2SeenEventLimit {
		oldest := v2SeenEventIDs[0]
		v2SeenEventIDs = v2SeenEventIDs[1:]
		delete(v2SeenEvents, oldest)
	}
	return true
}

func forgetV2Event(id string) {
	if id == "" {
		return
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	delete(v2SeenEvents, id)
	for i, seenID := range v2SeenEventIDs {
		if seenID == id {
			v2SeenEventIDs = append(v2SeenEventIDs[:i], v2SeenEventIDs[i+1:]...)
			break
		}
	}
}

func connectWebSocket(websocketEndpoint string) (*ws.SafeConn, error) {
	dialer := newWSDialer()

	conn, resp, err := dialer.Dial(websocketEndpoint, agentAuthorizationHeader(flags.Token))
	if err != nil {
		if resp != nil && resp.StatusCode != 101 {
			return nil, &httpStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
		}
		return nil, err
	}

	return ws.NewSafeConn(conn), nil
}

func handleWebSocketMessages(conn *ws.SafeConn, done chan<- struct{}) {
	defer close(done)
	var alive atomic.Bool
	markAlive := func() {
		if alive.CompareAndSwap(false, true) {
			log.Printf("WebSocket connected using v2 protocol")
		}
		_ = conn.SetReadDeadline(time.Now().Add(websocketPongWait))
	}
	_ = conn.SetReadDeadline(time.Now().Add(websocketHandshakeAliveWait))
	conn.SetPongHandler(func(string) error {
		markAlive()
		return nil
	})
	if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		log.Println("Failed to send heartbeat:", err)
		return
	}
	if err := advertiseV2PullCapabilities(conn); err != nil {
		log.Println("Failed to advertise v2 pull capabilities:", err)
		return
	}
	for {
		_, message_raw, err := conn.ReadMessage()
		if err != nil {
			log.Println("WebSocket read error:", err)
			return
		}
		markAlive()
		var message struct {
			JSONRPC string      `json:"jsonrpc,omitempty"`
			Method  string      `json:"method,omitempty"`
			Params  interface{} `json:"params,omitempty"`
			ID      interface{} `json:"id,omitempty"`
		}
		err = json.Unmarshal(message_raw, &message)
		if err != nil {
			log.Println("Bad ws message:", err)
			continue
		}
		if message.JSONRPC != v2.Version {
			log.Printf("ignored non-v2 websocket message method=%q", message.Method)
			continue
		}
		if message.Method == "" {
			continue
		}
		eventID, _ := message.ID.(string)
		if processV2Event(conn, message.Method, message.Params, eventID) {
			addV2AckEventID(eventID)
		}
	}
}

func processV2Event(conn *ws.SafeConn, method string, params interface{}, eventID string) bool {
	if !markV2EventSeen(eventID) {
		return true
	}
	switch method {
	case v2.MethodAgentExec:
		var p struct {
			TaskID  string `json:"task_id"`
			Command string `json:"command"`
		}
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 exec params: %v", err)
			return false
		}
		run, ack := acceptTask(p.TaskID)
		if run {
			go executeAcceptedTask(p.TaskID, p.Command)
		}
		if !ack {
			forgetV2Event(eventID)
			return false
		}
		return true
	case v2.MethodAgentMCPExec:
		var p v2.MCPExecParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 mcp exec params: %v", err)
			return false
		}
		run, ack := acceptMCPExec(p)
		if run {
			go executeMCPExec(p)
		}
		if !ack {
			forgetV2Event(eventID)
			return false
		}
		return true
	case v2.MethodAgentMCPCancel:
		var p v2.MCPCancelParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 mcp cancel params: %v", err)
			return false
		}
		_ = cancelMCPOperation(p.OperationID)
		return true
	case v2.MethodAgentMCPRenew:
		var p v2.MCPRenewParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 mcp renew params: %v", err)
			return false
		}
		renewMCPLease(p.LeaseID, parseMCPDeadline(p.ExecutionLeaseDeadline))
		return true
	case v2.MethodAgentMCPRevoke:
		var p v2.MCPRevokeParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 mcp revoke params: %v", err)
			return false
		}
		revokeMCPLease(p.LeaseID)
		return true
	case v2.MethodAgentMCPFile:
		var p v2.MCPFileParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 mcp file params: %v", err)
			return false
		}
		run, ack := acceptMCPFile(p)
		if run {
			go executeMCPFile(p)
		}
		if !ack {
			forgetV2Event(eventID)
			return false
		}
		return true
	case v2.MethodAgentPing:
		var p struct {
			TaskID uint   `json:"ping_task_id"`
			Type   string `json:"ping_type"`
			Target string `json:"ping_target"`
		}
		if err := v2.BindParams(params, &p); err == nil {
			go NewPingTask(conn, p.TaskID, p.Type, p.Target)
			return true
		} else {
			log.Printf("bad v2 ping params: %v", err)
		}
	case v2.MethodAgentRoute:
		var p v2.RouteParams
		if err := v2.BindParams(params, &p); err == nil {
			go NewRouteTask(conn, p)
			return true
		} else {
			log.Printf("bad v2 route params: %v", err)
		}
	case v2.MethodAgentRemote:
		var p v2.RemoteRequestParams
		if err := v2.BindParams(params, &p); err == nil && p.RequestID != "" && p.Ticket != "" {
			go establishRemoteConnection(flags.Token, p.RequestID, p.Ticket, flags.Endpoint)
			return true
		} else {
			log.Printf("bad v2 remote params: %v", err)
		}
	case v2.MethodAgentConfig:
		var p v2.ConfigParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 config params: %v", err)
			return false
		}
		return processRuntimeConfig(p, eventID)
	case v2.MethodNodemgtControl:
		if nodemgtrt := nodemgtRuntimeHandle(); nodemgtrt != nil {
			return nodemgtrt(params, eventID)
		}
		log.Printf("nodemgt.control received before runtime start")
		return true
	case v2.MethodAgentFirewallSnapshot, v2.MethodAgentFirewallApply, v2.MethodAgentFirewallAdopt:
		return processFirewallEvent(conn, method, params)
	case v2.MethodAgentMessage, v2.MethodAgentEvent:
		log.Printf("received v2 %s: %+v", method, params)
		return true
	default:
		log.Printf("unknown v2 event method %s", method)
	}
	return false
}

func establishRemoteConnection(token, id, ticket, endpoint string) {
	endpoint = strings.TrimSuffix(endpoint, "/") + "/api/clients/remote"
	endpoint = "ws" + strings.TrimPrefix(endpoint, "http")
	if convertedEndpoint, err := utils.ConvertIDNToASCII(endpoint); err == nil {
		endpoint = convertedEndpoint
	} else {
		log.Printf("Warning: Failed to convert remote WebSocket IDN to ASCII: %v", err)
	}
	headers := remoteAuthorizationHeader(token, id, ticket)
	conn, _, err := newWSDialer().Dial(endpoint, headers)
	if err != nil {
		log.Println("Failed to establish remote connection:", err)
		return
	}
	conn.SetReadLimit(remoteWebSocketReadLimit)
	terminal.StartRemoteSession(conn)
	_ = conn.Close()
}

// newWSDialer 构造统一的 WebSocket 拨号器（自定义解析、IPv4/IPv6 动态排序、可选 TLS 忽略）
func newWSDialer() *websocket.Dialer {
	d := &websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		NetDialContext:    dnsresolver.GetDialContextWithPreference(15*time.Second, flags.PreferIPVersion),
		Proxy:             http.ProxyFromEnvironment,
		EnableCompression: !flags.DisableCompression,
	}
	if flags.IgnoreUnsafeCert {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return d
}
