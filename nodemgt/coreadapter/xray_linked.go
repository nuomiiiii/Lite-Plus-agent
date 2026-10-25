package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func init() {
	linkedXray = func() Core { return newXrayCore() }
}

type xrayCore struct {
	mu          sync.Mutex
	inst        *xraycore.Instance
	users       []UserSpec
	inbounds    []InboundSpec
	outbounds   []OutboundSpec
	routes      []RouteSpec
	denied      map[string]struct{}
	lastUsers   []UserSpec
	lastIn      []InboundSpec
	lastOut     []OutboundSpec
	lastRoutes  []RouteSpec
	lastTraffic map[string]int64
	lastSeen    map[string]int64
	fronts      []*spliceFront
	policy      *policyEngine
}

func (c *xrayCore) SetForwarding(outbounds []OutboundSpec, routes []RouteSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbounds = append([]OutboundSpec(nil), outbounds...)
	c.routes = append([]RouteSpec(nil), routes...)
}

func newXrayCore() *xrayCore {
	return &xrayCore{denied: map[string]struct{}{}, policy: newPolicyEngine()}
}

func (c *xrayCore) Name() string    { return "xray" }
func (c *xrayCore) Version() string { return XrayVersion }
func (c *xrayCore) Linked() bool    { return true }

func (c *xrayCore) Start(_ context.Context, inbounds []InboundSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.inbounds
	c.inbounds = coreInbounds("xray", inbounds)
	if err := c.applyIfChangedLocked(); err != nil {
		c.inbounds = prev
		return err
	}
	return nil
}

func (c *xrayCore) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopLocked()
}

func (c *xrayCore) ApplyUsers(users []UserSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users = append([]UserSpec(nil), users...)
	if c.denied == nil {
		c.denied = map[string]struct{}{}
	}
	for _, u := range users {
		if userLive(u) {
			delete(c.denied, u.ID)
		}
	}
	c.policy.sync(c.users, c.denied)
	return c.applyIfChangedLocked()
}

func (c *xrayCore) CloseUserSessions(userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.denied == nil {
		c.denied = map[string]struct{}{}
	}
	c.denied[userID] = struct{}{}
	c.users = markDenied(c.users, userID)
	c.policy.sync(c.users, c.denied)
	c.policy.deny(userID)
	if c.inst == nil && len(c.inbounds) == 0 && len(c.lastIn) == 0 {
		c.lastUsers = markDenied(c.lastUsers, userID)
		return nil
	}
	check := c.inbounds
	if len(check) == 0 {
		check = c.lastIn
	}
	if !inboundsNeedCoreRestart(check, c.users) {
		removeXrayUser(c.inst, userID)
		c.lastUsers = markDenied(c.lastUsers, userID)
		return nil
	}
	if len(c.inbounds) == 0 && len(c.lastIn) > 0 {
		c.inbounds = append([]InboundSpec(nil), c.lastIn...)
	}
	return c.restartLocked()
}

func (c *xrayCore) TakeSnapshots() []Snapshot {
	out := c.policy.snapshots()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inst == nil {
		return out
	}
	feat := c.inst.GetFeature(stats.ManagerType())
	mgr, ok := feat.(stats.Manager)
	if !ok || mgr == nil {
		return out
	}
	byUser := map[string]int64{}
	mgr.VisitCounters(func(name string, counter stats.Counter) bool {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			return true
		}
		byUser[c.policy.mapStatName(parts[1])] += counter.Value()
		return true
	})
	if c.lastTraffic == nil {
		c.lastTraffic = map[string]int64{}
	}
	c.lastSeen = byUser
	coreIDs := map[string]struct{}{}
	var coreOut []Snapshot
	for id, n := range byUser {
		prev := c.lastTraffic[id]
		delta := n - prev
		if delta < 0 {
			delta = n
		}
		if delta > 0 {
			coreOut = append(coreOut, Snapshot{UserID: id, Bytes: delta})
			coreIDs[id] = struct{}{}
		}
	}
	if len(coreOut) == 0 {
		return out
	}
	filtered := out[:0]
	for _, snap := range out {
		if _, ok := coreIDs[snap.UserID]; ok {
			continue
		}
		filtered = append(filtered, snap)
	}
	return append(filtered, coreOut...)
}

func (c *xrayCore) AcknowledgeUsage() {
	c.policy.ack()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastTraffic == nil {
		c.lastTraffic = map[string]int64{}
	}
	for id, n := range c.lastSeen {
		c.lastTraffic[id] = n
	}
}

func (c *xrayCore) Presence() []Presence {
	out := c.policy.presence()
	c.mu.Lock()
	defer c.mu.Unlock()
	byID := map[string]Presence{}
	for _, row := range out {
		byID[row.UserID] = row
	}
	now := time.Now().UTC()
	if c.inst != nil {
		if feat := c.inst.GetFeature(stats.ManagerType()); feat != nil {
			if mgr, ok := feat.(stats.Manager); ok && mgr != nil {
				mgr.VisitOnlineMaps(func(name string, om stats.OnlineMap) bool {
					parts := strings.Split(name, ">>>")
					if len(parts) != 3 || parts[0] != "user" || parts[2] != "online" {
						return true
					}
					id := c.policy.mapStatName(parts[1])
					row := byID[id]
					row.UserID = id
					om.ForEach(func(ip string, unix int64) bool {
						ip = publicPresenceIP(ip)
						if ip == "" {
							return true
						}
						seen := presenceIPAt(ip, unix, now)
						if now.Sub(seen.SeenAt) > presenceFresh {
							return true
						}
						row.Online = true
						row.IPs = mergePresenceIP(row.IPs, seen)
						return true
					})
					byID[id] = row
					return true
				})
			}
		}
	}
	for id, n := range c.lastSeen {
		prev := c.lastTraffic[id]
		if n <= prev {
			continue
		}
		row := byID[id]
		row.UserID = id
		row.Online = true
		byID[id] = row
	}
	rows := make([]Presence, 0, len(byID))
	for _, row := range byID {
		rows = append(rows, row)
	}
	return rows
}

func (c *xrayCore) applyIfChangedLocked() error {
	nextUsers := applyDenied(c.users, c.denied)
	if !coreShouldRestart(c.inst != nil, c.inbounds, c.lastIn, nextUsers, c.lastUsers, c.outbounds, c.lastOut, c.routes, c.lastRoutes) {
		if c.inst == nil && len(c.inbounds) == 0 {
			c.rememberGood()
		}
		return nil
	}
	return c.restartLocked()
}

func (c *xrayCore) stopLocked() error {
	for _, front := range c.fronts {
		front.close()
	}
	c.fronts = nil
	if c.inst == nil {
		return nil
	}
	err := c.inst.Close()
	c.inst = nil
	return err
}

func (c *xrayCore) restartLocked() error {
	raw, n, fronts, err := c.buildConfig(applyDenied(c.users, c.denied), c.inbounds, c.outbounds, c.routes)
	if err != nil {
		return err
	}
	_ = c.stopLocked()
	if n == 0 {
		c.rememberGood()
		return nil
	}
	inst, err := startXrayInstance(raw, c.policy)
	if err != nil {
		c.restoreLastGood()
		return err
	}
	c.inst = inst
	c.policy.sync(c.users, c.denied)
	started, err := startPolicyFronts(c.policy, fronts)
	if err != nil {
		_ = c.stopLocked()
		c.restoreLastGood()
		return err
	}
	c.fronts = started
	c.rememberGood()
	return nil
}

func (c *xrayCore) rememberGood() {
	c.lastUsers = applyDenied(c.users, c.denied)
	c.lastIn = append([]InboundSpec(nil), c.inbounds...)
	c.lastOut = append([]OutboundSpec(nil), c.outbounds...)
	c.lastRoutes = append([]RouteSpec(nil), c.routes...)
}

func (c *xrayCore) restoreLastGood() {
	if len(c.lastIn) == 0 && len(c.lastUsers) == 0 {
		return
	}
	raw, n, fronts, err := c.buildConfig(applyDenied(c.lastUsers, c.denied), c.lastIn, c.lastOut, c.lastRoutes)
	if err != nil || n == 0 {
		return
	}
	inst, err := startXrayInstance(raw, c.policy)
	if err != nil {
		return
	}
	c.inst = inst
	c.policy.sync(c.lastUsers, c.denied)
	started, err := startPolicyFronts(c.policy, fronts)
	if err == nil {
		c.fronts = started
	}
	c.inbounds = append([]InboundSpec(nil), c.lastIn...)
}

func (c *xrayCore) configJSON() ([]byte, error) {
	raw, _, _, err := c.buildConfig(applyDenied(c.users, c.denied), c.inbounds, c.outbounds, c.routes)
	return raw, err
}

func reserveLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}

func (c *xrayCore) buildConfig(users []UserSpec, inbounds []InboundSpec, outbounds []OutboundSpec, routes []RouteSpec) ([]byte, int, []frontSpec, error) {
	var items []map[string]any
	var fronts []frontSpec
	var policyTags []string
	var skipIP []string
	var meterTags []string
	for i, in := range inbounds {
		tag := in.ID
		if tag == "" {
			tag = fmt.Sprintf("nodemgt-xray-%d", i)
		}
		proto := strings.ToLower(in.Protocol)
		if proto == "" {
			proto = "socks"
		}
		granted := usersForInbound(users, in.ID)
		accounts := make([]map[string]string, 0, len(granted))
		clients := make([]map[string]string, 0, len(granted))
		for _, u := range granted {
			if user, pass, ok := socksIdentity(u); ok {
				accounts = append(accounts, map[string]string{"user": user, "pass": pass})
			}
			if id := vlessUUID(u); id != "" {
				client := map[string]string{"id": id, "email": u.ID}
				if u.Flow != "" {
					client["flow"] = u.Flow
				}
				clients = append(clients, client)
			}
		}
		flow := inboundFlow(in)
		liveClients := clients
		if flow != "" {
			liveClients = applyClientFlow(clients, flow)
		}
		public := coreOwnedTLS(in, users) || udpInbound(proto)
		var listenHosts []string
		var listenPort int
		if public {
			listenHosts = publicCoreListenHosts(FrontListenHosts(inboundStack(in), in.Listen), "tcp")
			if len(listenHosts) == 0 {
				continue
			}
			listenPort = in.Port
		} else {
			internalPort, err := reserveLoopbackPort()
			if err != nil {
				return nil, 0, nil, err
			}
			listenHosts = []string{"127.0.0.1"}
			listenPort = internalPort
		}
		item := map[string]any{}
		if sniff := xraySniffing(in); sniff != nil {
			item["sniffing"] = sniff
		}
		switch proto {
		case "vless":
			if len(liveClients) == 0 {
				continue
			}
			item["protocol"] = "vless"
			item["settings"] = map[string]any{"clients": liveClients, "decryption": "none"}
		case "vmess":
			if len(liveClients) == 0 {
				continue
			}
			item["protocol"] = "vmess"
			item["settings"] = map[string]any{"clients": liveClients}
		case "trojan":
			trojanUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				if _, pass, ok := socksIdentity(u); ok {
					trojanUsers = append(trojanUsers, map[string]string{"password": pass, "email": u.ID})
				}
			}
			if len(trojanUsers) == 0 {
				continue
			}
			item["protocol"] = "trojan"
			item["settings"] = map[string]any{"clients": trojanUsers}
		case "shadowsocks":
			_, ssSettings, ok := ssXrayClients(in, granted)
			if !ok {
				continue
			}
			item["protocol"] = "shadowsocks"
			item["settings"] = ssSettings
		case "http":
			httpAccounts := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				httpAccounts = append(httpAccounts, proxyAccounts(u)...)
			}
			if len(httpAccounts) == 0 {
				continue
			}
			item["protocol"] = "http"
			item["settings"] = map[string]any{"accounts": httpAccounts}
		case "socks":
			if len(accounts) == 0 {
				continue
			}
			item["protocol"] = "socks"
			item["settings"] = map[string]any{"auth": "password", "accounts": accounts, "udp": false}
		default:
			continue
		}
		for hi, host := range listenHosts {
			cloned := cloneAnyMap(item)
			useTag := tag
			if hi > 0 {
				useTag = fmt.Sprintf("%s-%d", tag, hi)
			}
			cloned["tag"] = useTag
			cloned["listen"] = host
			cloned["port"] = listenPort
			if proto != "shadowsocks" && !identityFront(in, users) {
				stream := xrayStreamSettings(in)
				if !public {
					stream = enableXrayProxyProtocol(stream)
				}
				if stream != nil {
					cloned["streamSettings"] = stream
				}
			}
			items = append(items, cloned)
			if identityFront(in, users) {
				skipIP = append(skipIP, useTag)
			}
			if public {
				meterTags = append(meterTags, useTag)
			}
			if policyExitNeeded(in, users, true) {
				policyTags = append(policyTags, useTag)
			}
		}
		if !public {
			fronts = append(fronts, inboundPublicFronts(
				in,
				net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", listenPort)),
				proto,
				users,
			)...)
		}
	}
	obs := xrayOutbounds(outbounds)
	rules := xrayRouteRules(routes, outbounds)
	if len(policyTags) > 0 {
		var extra []frontSpec
		var coreIn []map[string]any
		var err error
		obs, rules, extra, coreIn, err = attachPolicyExit(obs, rules, users, policyTags, true, outbounds)
		if err != nil {
			return nil, 0, nil, err
		}
		items = append(items, coreIn...)
		fronts = append(fronts, extra...)
	}
	c.policy.setSkipCoreIP(skipIP)
	c.policy.setMeterCore(meterTags)
	cfg := map[string]any{
		"log":   map[string]any{"loglevel": "error"},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true},
			},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"inbounds":  items,
		"outbounds": obs,
	}
	if len(rules) > 0 {
		cfg["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	}
	raw, err := json.Marshal(cfg)
	return raw, len(items), fronts, err
}

func xrayStreamSettings(in InboundSpec) map[string]any {
	var stream map[string]any
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	if stream == nil {
		if in.CertPEM == "" || in.KeyPEM == "" {
			return nil
		}
		stream = map[string]any{"network": "tcp", "security": "tls"}
	}
	delete(stream, "stack")
	if sockopt, ok := stream["sockopt"].(map[string]any); ok {
		delete(sockopt, "v6only")
		if len(sockopt) == 0 {
			delete(stream, "sockopt")
		} else {
			stream["sockopt"] = sockopt
		}
	}
	if in.CertPEM != "" && in.KeyPEM != "" {
		tls, _ := stream["tlsSettings"].(map[string]any)
		if tls == nil {
			tls = map[string]any{}
		}
		tls["certificates"] = []map[string]any{{
			"certificate": splitPEM(in.CertPEM),
			"key":         splitPEM(in.KeyPEM),
		}}
		stream["tlsSettings"] = tls
		if _, ok := stream["security"]; !ok || stream["security"] == "" || stream["security"] == "none" {
			stream["security"] = "tls"
		}
	}
	if len(stream) == 0 {
		return nil
	}
	return stream
}

func enableXrayProxyProtocol(stream map[string]any) map[string]any {
	if stream == nil {
		stream = map[string]any{}
	}
	network := strings.ToLower(strings.TrimSpace(fmt.Sprint(stream["network"])))
	if network == "<nil>" {
		network = ""
	}
	switch network {
	case "ws", "websocket":
		ws, _ := stream["wsSettings"].(map[string]any)
		if ws == nil {
			ws = map[string]any{}
		}
		ws["acceptProxyProtocol"] = true
		stream["wsSettings"] = ws
	case "httpupgrade":
		hu, _ := stream["httpupgradeSettings"].(map[string]any)
		if hu == nil {
			hu = map[string]any{}
		}
		hu["acceptProxyProtocol"] = true
		stream["httpupgradeSettings"] = hu
	case "grpc", "gun":
		sock, _ := stream["sockopt"].(map[string]any)
		if sock == nil {
			sock = map[string]any{}
		}
		sock["acceptProxyProtocol"] = true
		stream["sockopt"] = sock
	default:
		if network == "" {
			stream["network"] = "tcp"
		}
		tcp, _ := stream["tcpSettings"].(map[string]any)
		if tcp == nil {
			tcp = map[string]any{}
		}
		tcp["acceptProxyProtocol"] = true
		stream["tcpSettings"] = tcp
	}
	return stream
}

func xraySniffing(in InboundSpec) map[string]any {
	var s struct {
		Sniffing     bool   `json:"sniffing"`
		DestOverride string `json:"dest_override"`
		RouteOnly    bool   `json:"route_only"`
		Security     string `json:"security"`
		Flow         string `json:"flow"`
	}
	if strings.TrimSpace(in.SettingsJSON) == "" {
		return nil
	}
	_ = json.Unmarshal([]byte(in.SettingsJSON), &s)
	if !s.Sniffing {
		return nil
	}
	dest := splitCSV(s.DestOverride)
	if len(dest) == 0 {
		dest = []string{"http", "tls", "quic"}
	}
	routeOnly := s.RouteOnly
	flow := inboundFlow(in)
	if flow == "" {
		flow = s.Flow
	}
	if strings.EqualFold(strings.TrimSpace(s.Security), "reality") || strings.Contains(strings.ToLower(flow), "vision") {
		routeOnly = true
	}
	return map[string]any{"enabled": true, "destOverride": dest, "routeOnly": routeOnly}
}

func inboundFlow(in InboundSpec) string {
	if in.Flow != "" {
		return in.Flow
	}
	return settingString(in.SettingsJSON, "flow")
}

func applyClientFlow(clients []map[string]string, flow string) []map[string]string {
	out := make([]map[string]string, 0, len(clients))
	for _, client := range clients {
		next := map[string]string{}
		for k, v := range client {
			next[k] = v
		}
		if next["flow"] == "" {
			next["flow"] = flow
		}
		out = append(out, next)
	}
	return out
}

func settingString(raw, key string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return ""
	}
	got, _ := obj[key].(string)
	return got
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func xrayOutbounds(rows []OutboundSpec) []map[string]any {
	direct := map[string]any{
		"protocol": "freedom",
		"tag":      "direct",
		"settings": map[string]any{"finalRules": []map[string]any{{"action": "allow"}}},
	}
	block := map[string]any{
		"protocol": "blackhole",
		"tag":      "block",
		"settings": map[string]any{"response": map[string]any{"type": "http"}},
	}
	out := []map[string]any{direct, block}
	seen := map[string]bool{"direct": true, "block": true}
	for _, row := range rows {
		if !row.Enabled && row.ID != "" {
			continue
		}
		tag := row.Name
		if tag == "" {
			tag = row.ID
		}
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		item := xrayOutboundItem(row, tag)
		if item != nil {
			out = append(out, item)
		}
	}
	return out
}

func xrayOutboundItem(row OutboundSpec, tag string) map[string]any {
	var s struct {
		Address          string `json:"address"`
		Port             int    `json:"port"`
		Username         string `json:"username"`
		Password         string `json:"password"`
		UUID             string `json:"uuid"`
		Flow             string `json:"flow"`
		DomainStrategy   string `json:"domain_strategy"`
		Transport        string `json:"transport"`
		Security         string `json:"security"`
		SNI              string `json:"sni"`
		Fingerprint      string `json:"fingerprint"`
		WSPath           string `json:"ws_path"`
		WSHost           string `json:"ws_host"`
		GRPCService      string `json:"grpc_service"`
		SSMethod         string `json:"ss_method"`
		ViaOutbound      string `json:"via_outbound"`
		RealityPublicKey string `json:"reality_public_key"`
		RealityShortID   string `json:"reality_short_id"`
		SpiderX          string `json:"spider_x"`
		PinnedCertSHA256 string `json:"pinned_peer_cert_sha256"`
	}
	_ = json.Unmarshal([]byte(row.SettingsJSON), &s)
	proto := strings.ToLower(row.Protocol)
	if proto == "" {
		proto = "freedom"
	}
	item := map[string]any{"protocol": proto, "tag": tag}
	switch proto {
	case "freedom":
		settings := map[string]any{"finalRules": []map[string]any{{"action": "allow"}}}
		if s.DomainStrategy != "" {
			settings["domainStrategy"] = s.DomainStrategy
		}
		item["settings"] = settings
	case "blackhole":
		item["settings"] = map[string]any{"response": map[string]any{"type": "http"}}
	case "vless", "vmess":
		user := map[string]any{"id": s.UUID, "encryption": "none"}
		if proto == "vmess" {
			user = map[string]any{"id": s.UUID, "security": "auto"}
		}
		if s.Flow != "" {
			user["flow"] = s.Flow
		}
		item["settings"] = map[string]any{"vnext": []map[string]any{{
			"address": s.Address, "port": s.Port, "users": []map[string]any{user},
		}}}
	case "trojan":
		item["settings"] = map[string]any{"servers": []map[string]any{{
			"address": s.Address, "port": s.Port, "password": s.Password,
		}}}
	case "shadowsocks":
		method := s.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		item["settings"] = map[string]any{"servers": []map[string]any{{
			"address": s.Address, "port": s.Port, "password": s.Password, "method": method,
		}}}
	case "socks", "http":
		server := map[string]any{"address": s.Address, "port": s.Port}
		if s.Username != "" {
			server["users"] = []map[string]any{{"user": s.Username, "pass": s.Password}}
		}
		item["settings"] = map[string]any{"servers": []map[string]any{server}}
	default:
		return nil
	}
	if stream := outboundStream(s.Transport, s.Security, s.SNI, s.Fingerprint, s.WSPath, s.WSHost, s.GRPCService, s.ViaOutbound, s.RealityPublicKey, s.RealityShortID, s.SpiderX, s.PinnedCertSHA256); stream != nil {
		item["streamSettings"] = stream
	} else if s.ViaOutbound != "" {
		item["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": s.ViaOutbound}}
	}
	return item
}

func outboundStream(transport, security, sni, fingerprint, wsPath, wsHost, grpcService, via, realityPublicKey, realityShortID, spiderX, pinnedCertSHA256 string) map[string]any {
	if transport == "" && security == "" && via == "" {
		return nil
	}
	if (transport == "" || transport == "tcp") && (security == "" || security == "none") && via == "" {
		return nil
	}
	stream := map[string]any{}
	if transport != "" {
		stream["network"] = transport
	}
	if security != "" && security != "none" {
		stream["security"] = security
	}
	if security == "tls" || security == "reality" {
		tls := map[string]any{}
		if sni != "" {
			tls["serverName"] = sni
		}
		if fingerprint != "" {
			tls["fingerprint"] = fingerprint
		}
		if security == "tls" {
			if pinnedCertSHA256 != "" {
				tls["pinnedPeerCertSha256"] = pinnedCertSHA256
			}
			stream["tlsSettings"] = tls
		} else {
			if realityPublicKey != "" {
				tls["publicKey"] = realityPublicKey
			}
			if realityShortID != "" {
				tls["shortId"] = realityShortID
			}
			if spiderX != "" {
				tls["spiderX"] = spiderX
			}
			stream["realitySettings"] = tls
		}
	}
	if transport == "ws" {
		path := wsPath
		if path == "" {
			path = "/"
		}
		ws := map[string]any{"path": path}
		if wsHost != "" {
			ws["host"] = wsHost
		}
		stream["wsSettings"] = ws
	}
	if transport == "grpc" {
		svc := grpcService
		if svc == "" {
			svc = "gun"
		}
		stream["grpcSettings"] = map[string]any{"serviceName": svc}
	}
	if via != "" {
		stream["sockopt"] = map[string]any{"dialerProxy": via}
	}
	if len(stream) == 0 {
		return nil
	}
	return stream
}

func xrayRouteRules(routes []RouteSpec, outbounds []OutboundSpec) []map[string]any {
	byID := map[string]string{}
	for _, row := range outbounds {
		if row.ID != "" && row.Name != "" {
			byID[row.ID] = row.Name
		}
	}
	sorted := append([]RouteSpec(nil), routes...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Priority < sorted[i].Priority {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	var rules []map[string]any
	for _, row := range sorted {
		if !row.Enabled && row.ID != "" {
			continue
		}
		var s struct {
			InboundID  string `json:"inbound_id"`
			OutboundID string `json:"outbound_id"`
			Domain     string `json:"domain"`
			IP         string `json:"ip"`
			Network    string `json:"network"`
			Protocol   string `json:"protocol"`
			Port       string `json:"port"`
			Source     string `json:"source"`
		}
		_ = json.Unmarshal([]byte(row.RuleJSON), &s)
		tag := byID[s.OutboundID]
		if tag == "" {
			tag = s.OutboundID
		}
		if tag == "" {
			continue
		}
		rule := map[string]any{"type": "field", "outboundTag": tag}
		if s.InboundID != "" {
			rule["inboundTag"] = []string{s.InboundID}
		}
		if domains := splitCSV(s.Domain); len(domains) > 0 {
			rule["domain"] = domains
		}
		if ips := splitCSV(s.IP); len(ips) > 0 {
			rule["ip"] = ips
		}
		if s.Network != "" {
			rule["network"] = s.Network
		}
		if protocols := splitCSV(s.Protocol); len(protocols) > 0 {
			rule["protocol"] = protocols
		}
		if s.Port != "" {
			rule["port"] = s.Port
		}
		if sources := splitCSV(s.Source); len(sources) > 0 {
			rule["source"] = sources
		}
		rules = append(rules, rule)
	}
	return rules
}
