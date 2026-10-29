package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func init() {
	linkedSingBox = func() Core { return newSingBoxCore() }
}

type singBoxCore struct {
	mu         sync.Mutex
	inst       *box.Box
	cancel     context.CancelFunc
	users      []UserSpec
	inbounds   []InboundSpec
	outbounds  []OutboundSpec
	routes     []RouteSpec
	denied     map[string]struct{}
	lastUsers     []UserSpec
	lastIn        []InboundSpec
	lastOut       []OutboundSpec
	lastRoutes    []RouteSpec
	dialStack     string
	lastDialStack string
	fronts        []*spliceFront
	policy     *policyEngine
}

func (c *singBoxCore) SetForwarding(outbounds []OutboundSpec, routes []RouteSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbounds = append([]OutboundSpec(nil), outbounds...)
	c.routes = append([]RouteSpec(nil), routes...)
}

func (c *singBoxCore) SetDialStack(stack string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialStack = NormalizeDialStack(stack)
}

func newSingBoxCore() *singBoxCore {
	return &singBoxCore{denied: map[string]struct{}{}, policy: newPolicyEngine()}
}

func (c *singBoxCore) Name() string    { return "sing-box" }
func (c *singBoxCore) Version() string { return SingBoxVersion }
func (c *singBoxCore) Linked() bool    { return true }

func (c *singBoxCore) Start(_ context.Context, inbounds []InboundSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.inbounds
	c.inbounds = coreInbounds("sing-box", inbounds)
	if err := c.applyIfChangedLocked(); err != nil {
		c.inbounds = prev
		return err
	}
	return nil
}

func (c *singBoxCore) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopLocked()
}

func (c *singBoxCore) ApplyUsers(users []UserSpec) error {
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

func (c *singBoxCore) CloseUserSessions(userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.denied == nil {
		c.denied = map[string]struct{}{}
	}
	c.denied[userID] = struct{}{}
	c.users = markDenied(c.users, userID)
	c.lastUsers = markDenied(c.lastUsers, userID)
	c.policy.sync(c.users, c.denied)
	c.policy.deny(userID)
	if c.inst == nil && len(c.inbounds) == 0 && len(c.lastIn) == 0 {
		return nil
	}
	check := c.inbounds
	if len(check) == 0 {
		check = c.lastIn
	}
	if !inboundsNeedCoreRestart(check, c.users) {
		return nil
	}
	if len(c.inbounds) == 0 && len(c.lastIn) > 0 {
		c.inbounds = append([]InboundSpec(nil), c.lastIn...)
	}
	return c.restartLocked()
}

func (c *singBoxCore) TakeSnapshots() []Snapshot {
	return c.policy.snapshots()
}

func (c *singBoxCore) AcknowledgeUsage() {
	c.policy.ack()
}

func (c *singBoxCore) Presence() []Presence {
	return c.policy.presence()
}

func (c *singBoxCore) applyIfChangedLocked() error {
	nextUsers := applyDenied(c.users, c.denied)
	if !coreShouldRestart(c.inst != nil, c.inbounds, c.lastIn, nextUsers, c.lastUsers, c.outbounds, c.lastOut, c.routes, c.lastRoutes) && c.dialStack == c.lastDialStack {
		if c.inst == nil && len(c.inbounds) == 0 {
			c.rememberGood()
		}
		return nil
	}
	return c.restartLocked()
}

func (c *singBoxCore) stopLocked() error {
	for _, front := range c.fronts {
		front.close()
	}
	c.fronts = nil
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.inst == nil {
		return nil
	}
	err := c.inst.Close()
	c.inst = nil
	return err
}

func (c *singBoxCore) restartLocked() error {
	live := liveUsers(c.users, c.denied, c.inbounds)
	raw, n, fronts, err := c.buildConfig(live, c.inbounds, c.outbounds, c.routes)
	if err != nil {
		c.dialStack = c.lastDialStack
		return err
	}
	_ = c.stopLocked()
	if n == 0 {
		c.rememberGood()
		return nil
	}
	inst, cancel, err := startSingBox(raw)
	if err != nil {
		c.restoreLastGood()
		return err
	}
	c.inst = inst
	c.cancel = cancel
	c.policy.sync(live, c.denied)
	c.inst.Router().AppendTracker(newIPLimitTracker(c.policy))
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

func (c *singBoxCore) rememberGood() {
	c.lastUsers = applyDenied(c.users, c.denied)
	c.lastIn = append([]InboundSpec(nil), c.inbounds...)
	c.lastOut = append([]OutboundSpec(nil), c.outbounds...)
	c.lastRoutes = append([]RouteSpec(nil), c.routes...)
	c.lastDialStack = c.dialStack
}

func (c *singBoxCore) restoreLastGood() {
	if len(c.lastIn) == 0 && len(c.lastUsers) == 0 {
		return
	}
	live := liveUsers(c.lastUsers, c.denied, c.lastIn)
	attempted := c.dialStack
	c.dialStack = c.lastDialStack
	raw, n, fronts, err := c.buildConfig(live, c.lastIn, c.lastOut, c.lastRoutes)
	if err != nil || n == 0 {
		c.dialStack = attempted
		return
	}
	inst, cancel, err := startSingBox(raw)
	if err != nil {
		c.dialStack = attempted
		return
	}
	c.inst = inst
	c.cancel = cancel
	c.policy.sync(live, c.denied)
	c.inst.Router().AppendTracker(newIPLimitTracker(c.policy))
	started, ferr := startPolicyFronts(c.policy, fronts)
	if ferr == nil {
		c.fronts = started
	}
	c.inbounds = append([]InboundSpec(nil), c.lastIn...)
}

func startSingBox(raw []byte) (*box.Box, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		cancel()
		return nil, nil, err
	}
	return inst, cancel, nil
}

func (c *singBoxCore) configJSON() ([]byte, error) {
	raw, _, _, err := c.buildConfig(liveUsers(c.users, c.denied, c.inbounds), c.inbounds, c.outbounds, c.routes)
	return raw, err
}

func (c *singBoxCore) buildConfig(users []UserSpec, inbounds []InboundSpec, outbounds []OutboundSpec, routes []RouteSpec) ([]byte, int, []frontSpec, error) {
	var items []map[string]any
	var fronts []frontSpec
	var policyTags []string
	var skipIP []string
	listenTags := map[string][]string{}
	for i, in := range inbounds {
		tag := in.ID
		if tag == "" {
			tag = fmt.Sprintf("nodemgt-singbox-%d", i)
		}
		proto := strings.ToLower(in.Protocol)
		if proto == "" {
			proto = "socks"
		}
		switch proto {
		case "socks", "mixed", "http", "vless", "vmess", "trojan", "hysteria2", "tuic", "shadowsocks", "anytls":
		default:
			continue
		}
		granted := usersForInbound(users, in.ID)
		hosts := FrontListenHosts(inboundStack(in), in.Listen)
		if len(hosts) == 0 {
			continue
		}
		listenAddr := hosts[0]
		listenPort := in.Port
		var pendingFronts []frontSpec
		udp := udpInbound(proto)
		// SOCKS/HTTP/VLESS TCP+WS authenticate on the policy front and hold
		// IP from conn.RemoteAddr. Everything else authenticates inside
		// sing-box. Inbound PROXY protocol was removed in 1.6.0, so those
		// protocols must bind the public address or device limits see 127.0.0.1.
		public := udp || coreOwnedTLS(in, users) || !identityFront(in, users)
		if !public {
			internalPort, err := reserveLoopbackPort()
			if err != nil {
				return nil, 0, nil, err
			}
			listenAddr = "127.0.0.1"
			listenPort = internalPort
			pendingFronts = inboundPublicFronts(
				in,
				net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", internalPort)),
				proto,
				users,
				false,
			)
		}
		item := map[string]any{
			"type":        proto,
			"tag":         tag,
			"listen":      listenAddr,
			"listen_port": listenPort,
		}
		if proto != "shadowsocks" && !identityFront(in, users) {
			if tls := singBoxTLS(in); tls != nil {
				item["tls"] = tls
			}
			if transport := singBoxTransport(in); transport != nil {
				item["transport"] = transport
			}
		}
		switch proto {
		case "socks", "mixed":
			authUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				authUsers = append(authUsers, proxyAuthUsers(u)...)
			}
			if len(authUsers) == 0 {
				continue
			}
			item["users"] = authUsers
		case "http":
			authUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				authUsers = append(authUsers, proxyAuthUsers(u)...)
			}
			if len(authUsers) == 0 && !inboundAllowTransparent(in) {
				continue
			}
			if len(authUsers) > 0 {
				item["users"] = authUsers
			}
		case "vless", "vmess":
			clients := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				id := vlessUUID(u)
				if id == "" {
					continue
				}
				client := map[string]string{"uuid": id, "name": u.ID}
				if proto == "vless" {
					if flow := singBoxNormalizeFlow(u.Flow); flow != "" && inboundAllowsVLESSFlow(in) {
						client["flow"] = flow
					}
				}
				clients = append(clients, client)
			}
			if len(clients) == 0 {
				continue
			}
			if proto == "vless" && inboundAllowsVLESSFlow(in) {
				if flow := singBoxNormalizeFlow(inboundFlow(in)); flow != "" {
					clients = applyClientFlow(clients, flow)
				}
			}
			item["users"] = clients
		case "trojan", "hysteria2", "anytls":
			pwds := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				if _, pass, ok := socksIdentity(u); ok {
					pwds = append(pwds, map[string]string{"name": u.ID, "password": pass})
				}
			}
			if len(pwds) == 0 {
				continue
			}
			item["users"] = pwds
			if proto == "anytls" {
				if scheme := settingString(in.SettingsJSON, "padding_scheme"); scheme != "" {
					item["padding_scheme"] = splitPaddingScheme(scheme)
				}
			}
		case "tuic":
			tuicUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				id := vlessUUID(u)
				if id == "" {
					id = strings.TrimSpace(u.UUID)
				}
				if id == "" {
					continue
				}
				entry := map[string]string{"name": u.ID, "uuid": id}
				if _, pass, ok := socksIdentity(u); ok {
					entry["password"] = pass
				}
				tuicUsers = append(tuicUsers, entry)
			}
			if len(tuicUsers) == 0 {
				continue
			}
			item["users"] = tuicUsers
		case "shadowsocks":
			ssItem, ok := ssSingBoxInbound(in, granted)
			if !ok {
				continue
			}
			for key, value := range ssItem {
				item[key] = value
			}
		}
		applySingBoxUDPFragment(item, in)
		listenHosts := []string{listenAddr}
		if public {
			listenHosts = publicCoreListenHosts(hosts, "tcp4")
		}
		for hi, host := range listenHosts {
			cloned := cloneAnyMap(item)
			cloned["listen"] = host
			useTag := tag
			if hi > 0 {
				useTag = fmt.Sprintf("%s-%d", tag, hi)
				cloned["tag"] = useTag
			}
			items = append(items, cloned)
			if in.ID != "" {
				listenTags[in.ID] = append(listenTags[in.ID], useTag)
			}
			if identityFront(in, users) {
				skipIP = append(skipIP, useTag)
			}
		}
		if policyExitNeeded(in, users, false) {
			if extra := listenTags[in.ID]; len(extra) > 0 {
				policyTags = append(policyTags, extra...)
			} else {
				policyTags = append(policyTags, tag)
			}
		}
		if len(pendingFronts) > 0 {
			fronts = append(fronts, pendingFronts...)
		}
	}
	obs := singBoxOutbounds(outbounds)
	rules := append(singBoxSniffRules(inbounds, listenTags), singBoxRouteRules(routes, outbounds, listenTags)...)
	if len(policyTags) > 0 {
		var extra []frontSpec
		var coreIn []map[string]any
		var err error
		obs, rules, extra, coreIn, err = attachPolicyExit(obs, rules, users, policyTags, false, outbounds)
		if err != nil {
			return nil, 0, nil, err
		}
		items = append(items, coreIn...)
		fronts = append(fronts, extra...)
	}
	c.policy.setSkipCoreIP(skipIP)
	cfg := map[string]any{
		"log":       map[string]any{"level": "error", "timestamp": false},
		"inbounds":  items,
		"outbounds": obs,
	}
	var route map[string]any
	if len(rules) > 0 {
		route = map[string]any{"rules": rules, "final": "direct"}
		if sets := singBoxRuleSets(routes); len(sets) > 0 {
			route["rule_set"] = sets
		}
		cfg["route"] = route
	}
	applySingBoxDialStack(cfg, route, c.dialStack)
	raw, err := json.Marshal(cfg)
	return raw, len(items), fronts, err
}

func singBoxTransport(in InboundSpec) map[string]any {
	var stream map[string]any
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	if stream == nil {
		return nil
	}
	network, _ := stream["network"].(string)
	switch strings.ToLower(network) {
	case "ws", "websocket":
		ws, _ := stream["wsSettings"].(map[string]any)
		item := map[string]any{"type": "ws"}
		if ws != nil {
			if path, _ := ws["path"].(string); path != "" {
				item["path"] = path
			}
			if host, _ := ws["host"].(string); host != "" {
				item["headers"] = map[string]any{"Host": host}
			}
			if headers, ok := ws["headers"].(map[string]any); ok {
				item["headers"] = headers
			}
		}
		return item
	case "grpc":
		grpc, _ := stream["grpcSettings"].(map[string]any)
		item := map[string]any{"type": "grpc"}
		if grpc != nil {
			if name, _ := grpc["serviceName"].(string); name != "" {
				item["service_name"] = name
			}
		}
		return item
	case "httpupgrade":
		httpUp, _ := stream["httpupgradeSettings"].(map[string]any)
		item := map[string]any{"type": "httpupgrade"}
		if httpUp != nil {
			if path, _ := httpUp["path"].(string); path != "" {
				item["path"] = path
			}
			if host, _ := httpUp["host"].(string); host != "" {
				item["host"] = host
			}
		}
		return item
	default:
		return nil
	}
}

func singBoxTLS(in InboundSpec) map[string]any {
	var stream map[string]any
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	security, _ := stream["security"].(string)
	tls := map[string]any{}
	if in.CertPEM != "" && in.KeyPEM != "" {
		tls["enabled"] = true
		tls["certificate"] = []string{in.CertPEM}
		tls["key"] = []string{in.KeyPEM}
	}
	if tlsSettings, ok := stream["tlsSettings"].(map[string]any); ok {
		if name, _ := tlsSettings["serverName"].(string); name != "" {
			tls["server_name"] = name
		}
		if alpn, ok := tlsSettings["alpn"].([]any); ok {
			tls["alpn"] = alpn
		}
		tls["enabled"] = true
	}
	if strings.EqualFold(security, "reality") {
		tls["enabled"] = true
		reality, _ := stream["realitySettings"].(map[string]any)
		item := map[string]any{"enabled": true}
		if reality != nil {
			if dest, _ := reality["dest"].(string); dest != "" {
				item["handshake"] = singBoxHandshake(dest)
			}
			if key, _ := reality["privateKey"].(string); key != "" {
				item["private_key"] = key
			}
			if ids, ok := reality["shortIds"].([]any); ok {
				var shorts []string
				for _, id := range ids {
					if s, ok := id.(string); ok && s != "" {
						shorts = append(shorts, s)
					}
				}
				item["short_id"] = shorts
			}
			if name := firstString(reality["serverNames"]); name != "" {
				tls["server_name"] = name
			}
		}
		tls["reality"] = item
	}
	if len(tls) == 0 {
		return nil
	}
	if _, ok := tls["enabled"]; !ok {
		return nil
	}
	return tls
}

func singBoxOutbounds(rows []OutboundSpec) []map[string]any {
	out := []map[string]any{{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}}
	tags := outboundTagIndex(rows)
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		tag := outboundTag(row)
		switch strings.ToLower(row.Protocol) {
		case "freedom", "direct":
			out = append(out, map[string]any{"type": "direct", "tag": tag})
		case "blackhole", "block":
			out = append(out, map[string]any{"type": "block", "tag": tag})
		default:
			out = append(out, singBoxProxyOutbound(row, tag, tags))
		}
	}
	return out
}

func outboundTag(row OutboundSpec) string {
	if row.Name != "" {
		return row.Name
	}
	return row.ID
}

func outboundTagIndex(rows []OutboundSpec) map[string]string {
	idx := map[string]string{}
	for _, row := range rows {
		tag := outboundTag(row)
		if row.ID != "" {
			idx[row.ID] = tag
		}
		if row.Name != "" {
			idx[row.Name] = tag
		}
	}
	return idx
}

func singBoxProxyOutbound(row OutboundSpec, tag string, tags map[string]string) map[string]any {
	var settings map[string]any
	_ = json.Unmarshal([]byte(row.SettingsJSON), &settings)
	if settings == nil {
		settings = map[string]any{}
	}
	proto := strings.ToLower(row.Protocol)
	item := map[string]any{"type": proto, "tag": tag}
	if addr, _ := settings["address"].(string); addr != "" {
		item["server"] = addr
	}
	if port := jsonPort(settings["port"]); port > 0 {
		item["server_port"] = port
	}
	switch proto {
	case "shadowsocks":
		method, _ := settings["ss_method"].(string)
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		item["method"] = method
		if pass, _ := settings["password"].(string); pass != "" {
			item["password"] = pass
		}
		if network := ssOutboundNetwork(settings); network == "tcp" || network == "udp" {
			item["network"] = network
		}
	case "vless", "vmess":
		if uuid, _ := settings["uuid"].(string); uuid != "" {
			item["uuid"] = uuid
		}
		if proto == "vless" {
			if flow, _ := settings["flow"].(string); flow != "" {
				if flow = singBoxNormalizeFlow(flow); flow != "" {
					item["flow"] = flow
				}
			}
		}
	case "trojan", "anytls":
		if pass, _ := settings["password"].(string); pass != "" {
			item["password"] = pass
		}
	case "socks", "http":
		if user, _ := settings["username"].(string); user != "" {
			item["username"] = user
		}
		if pass, _ := settings["password"].(string); pass != "" {
			item["password"] = pass
		}
	}
	if via, _ := settings["via_outbound"].(string); via != "" {
		if detour := tags[via]; detour != "" {
			item["detour"] = detour
		} else {
			item["detour"] = via
		}
	}
	if transport := singBoxOutboundTransport(settings); transport != nil {
		item["transport"] = transport
	}
	if tls := singBoxOutboundTLS(settings); tls != nil {
		item["tls"] = tls
	}
	return item
}

func singBoxRouteRules(routes []RouteSpec, outbounds []OutboundSpec, inboundTags map[string][]string) []map[string]any {
	tags := outboundTagIndex(outbounds)
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
		if !row.Enabled {
			continue
		}
		var rule struct {
			OutboundID string `json:"outbound_id"`
			Domain     string `json:"domain"`
			IP         string `json:"ip"`
			Network    string `json:"network"`
			Protocol   string `json:"protocol"`
			Port       string `json:"port"`
			Source     string `json:"source"`
			InboundID  string `json:"inbound_id"`
		}
		_ = json.Unmarshal([]byte(row.RuleJSON), &rule)
		item := map[string]any{}
		tag := tags[rule.OutboundID]
		if tag == "" {
			tag = strings.TrimSpace(rule.OutboundID)
		}
		if tag == "" {
			continue
		}
		item["outbound"] = tag
		if nets := splitCSV(rule.Network); len(nets) > 0 {
			item["network"] = nets
		}
		if rule.Protocol != "" {
			item["protocol"] = splitCSV(rule.Protocol)
		}
		ports, ranges := singBoxRulePorts(rule.Port)
		if len(ports) > 0 {
			item["port"] = ports
		}
		if len(ranges) > 0 {
			item["port_range"] = ranges
		}
		if sources := splitCSV(rule.Source); len(sources) > 0 {
			item["source_ip_cidr"] = sources
		}
		if tags := inboundAliasTags(rule.InboundID, inboundTags); len(tags) > 0 {
			item["inbound"] = tags
		}
		rules = append(rules, mergeSingBoxGeo(item, parseGeoMatch(splitCSV(rule.Domain), splitCSV(rule.IP))))
	}
	return rules
}

func singBoxRulePorts(raw string) (ports []int, ranges []string) {
	for _, part := range splitCSV(raw) {
		if strings.ContainsAny(part, "-:") {
			ranges = append(ranges, strings.ReplaceAll(part, "-", ":"))
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n <= 0 || n > 65535 {
			continue
		}
		ports = append(ports, n)
	}
	return
}

func singBoxOutboundTLS(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	security := strings.ToLower(strings.TrimSpace(firstString(settings["security"])))
	if security != "tls" && security != "reality" {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if sni := strings.TrimSpace(firstString(settings["sni"])); sni != "" {
		tls["server_name"] = sni
	}
	fp := strings.TrimSpace(firstString(settings["fingerprint"]))
	if fp == "" && security == "reality" {
		fp = "chrome"
	}
	if fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if insecure, ok := settings["insecure"].(bool); ok && insecure {
		tls["insecure"] = true
	}
	if alpn := strings.TrimSpace(firstString(settings["alpn"])); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if security == "reality" {
		reality := map[string]any{"enabled": true}
		if pk := strings.TrimSpace(firstString(settings["reality_public_key"])); pk != "" {
			reality["public_key"] = pk
		}
		if sid := strings.TrimSpace(firstString(settings["reality_short_id"])); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	return tls
}

func splitPaddingScheme(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func singBoxOutboundTransport(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	transport, _ := settings["transport"].(string)
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "ws", "websocket":
		item := map[string]any{"type": "ws"}
		if path, _ := settings["ws_path"].(string); path != "" {
			item["path"] = path
		}
		if host, _ := settings["ws_host"].(string); host != "" {
			item["headers"] = map[string]any{"Host": host}
		}
		return item
	case "grpc":
		item := map[string]any{"type": "grpc"}
		name, _ := settings["grpc_service"].(string)
		if name == "" {
			name = "gun"
		}
		item["service_name"] = name
		return item
	case "httpupgrade":
		item := map[string]any{"type": "httpupgrade"}
		path := firstString(settings["http_path"])
		if path == "" {
			path = firstString(settings["ws_path"])
		}
		if path != "" {
			item["path"] = path
		}
		host := firstString(settings["http_host"])
		if host == "" {
			host = firstString(settings["ws_host"])
		}
		if host != "" {
			item["host"] = host
		}
		return item
	default:
		return nil
	}
}

func singBoxHandshake(dest string) map[string]any {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return map[string]any{"server": dest, "server_port": 443}
	}
	item := map[string]any{"server": host}
	if n, convErr := strconv.Atoi(port); convErr == nil && n > 0 {
		item["server_port"] = n
	} else {
		item["server_port"] = 443
	}
	return item
}

func singBoxSniffRules(inbounds []InboundSpec, inboundTags map[string][]string) []map[string]any {
	var out []map[string]any
	for _, in := range inbounds {
		var s struct {
			Sniffing bool `json:"sniffing"`
		}
		if strings.TrimSpace(in.SettingsJSON) == "" {
			continue
		}
		_ = json.Unmarshal([]byte(in.SettingsJSON), &s)
		if !s.Sniffing || strings.TrimSpace(in.ID) == "" {
			continue
		}
		tags := inboundAliasTags(in.ID, inboundTags)
		if len(tags) == 0 {
			continue
		}
		out = append(out, map[string]any{
			"inbound": tags,
			"action":  "sniff",
		})
	}
	return out
}

func firstString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func applySingBoxUDPFragment(item map[string]any, in InboundSpec) {
	if !inboundListensUDP(in) {
		return
	}
	v := settingBool(in.SettingsJSON, "udp_fragment")
	if v == nil {
		return
	}
	item["udp_fragment"] = *v
}

func inboundListensUDP(in InboundSpec) bool {
	switch strings.ToLower(strings.TrimSpace(in.Protocol)) {
	case "hysteria2", "tuic":
		return true
	case "shadowsocks":
		return ssListenNetwork(in) != "tcp"
	default:
		return false
	}
}

func udpInbound(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "hysteria2", "tuic", "shadowsocks":
		return true
	default:
		return false
	}
}
