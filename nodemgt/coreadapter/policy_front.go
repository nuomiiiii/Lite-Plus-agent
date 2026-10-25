package coreadapter

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nuomiiiii/lite-agent/nodemgt/limiter"
	"github.com/nuomiiiii/lite-agent/nodemgt/quota"
	"github.com/nuomiiiii/lite-agent/nodemgt/sessions"
)

type spliceFront struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

func (s *spliceFront) close() {
	if s == nil {
		return
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *spliceFront) track(c net.Conn) {
	if s == nil || c == nil {
		return
	}
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

func (s *spliceFront) drop(c net.Conn) {
	if s == nil || c == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.conns {
		if x != c {
			continue
		}
		last := len(s.conns) - 1
		s.conns[i] = s.conns[last]
		s.conns[last] = nil
		s.conns = s.conns[:last]
		return
	}
}

func (s *spliceFront) tracked() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *spliceFront) spawn(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
}

func (s *spliceFront) spawnTracked(c net.Conn, fn func()) {
	s.track(c)
	s.spawn(func() {
		defer s.drop(c)
		fn()
	})
}

type egressHop struct {
	Protocol  string
	Addr      string
	User      string
	Pass      string
	UUID      string
	Transport string
	Security  string
	SNI       string
	WSPath    string
	WSHost    string
}

var (
	hopTLSMu      sync.Mutex
	hopTLSRootCAs *x509.CertPool
)

type frontSpec struct {
	Addr          string
	Dest          string
	Protocol      string
	Identity      bool
	Exit          bool
	ProxyProtocol bool
	Egress        []egressHop
	TLS           *tls.Config
	Network       string
	WSPath        string
}

type policyEngine struct {
	mu         sync.Mutex
	users      []UserSpec
	denied     map[string]struct{}
	byLogin    map[string]UserSpec
	byUUID     map[string]UserSpec
	quota      *quota.Ledger
	limit      *limiter.Set
	sess       *sessions.Set
	used       map[string]int64
	acked      map[string]int64
	captured   map[string]int64
	ips        *ipGuard
	seen       map[string]map[string]time.Time
	skipCoreIP map[string]struct{}
	meterCore  map[string]struct{}
	coreConns  map[string]map[net.Conn]struct{}
}

type sharedExec struct {
	quota *quota.Ledger
	limit *limiter.Set
	sess  *sessions.Set
	ips   *ipGuard
}

var nodeExec = &sharedExec{
	quota: quota.New(),
	limit: limiter.New(),
	sess:  sessions.New(),
	ips:   newIPGuard(),
}

func newPolicyEngine() *policyEngine {
	return &policyEngine{
		denied:     map[string]struct{}{},
		byLogin:    map[string]UserSpec{},
		byUUID:     map[string]UserSpec{},
		quota:      nodeExec.quota,
		limit:      nodeExec.limit,
		sess:       nodeExec.sess,
		used:       map[string]int64{},
		acked:      map[string]int64{},
		ips:        nodeExec.ips,
		seen:       map[string]map[string]time.Time{},
		skipCoreIP: map[string]struct{}{},
		meterCore:  map[string]struct{}{},
	}
}

func (p *policyEngine) sync(users []UserSpec, denied map[string]struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = append([]UserSpec(nil), users...)
	p.denied = map[string]struct{}{}
	for id := range denied {
		p.denied[id] = struct{}{}
	}
	p.byLogin = map[string]UserSpec{}
	p.byUUID = map[string]UserSpec{}
	for _, u := range users {
		indexLoginNames(u, p.byLogin)
		if id := vlessUUID(u); id != "" {
			p.byUUID[strings.ToLower(id)] = u
		}
		p.quota.Configure(u.ID, u.QuotaBytes, u.UsedBytes)
		p.limit.Configure(u.ID, u.RateLimitBps)
	}
}

func (p *policyEngine) deny(userID string) {
	p.mu.Lock()
	if p.denied == nil {
		p.denied = map[string]struct{}{}
	}
	p.denied[userID] = struct{}{}
	for i := range p.users {
		if p.users[i].ID == userID {
			p.users[i].Disabled = true
			indexLoginNames(p.users[i], p.byLogin)
		}
	}
	p.mu.Unlock()
	p.sess.CloseUser(userID)
	p.ips.clear(userID)
	p.dropCoreConns(userID)
}

func (p *policyEngine) userBlocked(userID string) bool {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.denied[userID]; ok {
		return true
	}
	for _, u := range p.users {
		if u.ID == userID {
			return !userLive(u)
		}
	}
	return false
}

func (p *policyEngine) trackCoreConn(userID string, conn net.Conn) func() {
	if userID == "" || conn == nil {
		return func() {}
	}
	p.mu.Lock()
	if p.coreConns == nil {
		p.coreConns = map[string]map[net.Conn]struct{}{}
	}
	if p.coreConns[userID] == nil {
		p.coreConns[userID] = map[net.Conn]struct{}{}
	}
	p.coreConns[userID][conn] = struct{}{}
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			delete(p.coreConns[userID], conn)
			if len(p.coreConns[userID]) == 0 {
				delete(p.coreConns, userID)
			}
			p.mu.Unlock()
		})
	}
}

func (p *policyEngine) dropCoreConns(userID string) {
	p.mu.Lock()
	conns := p.coreConns[userID]
	delete(p.coreConns, userID)
	p.mu.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
}

func (p *policyEngine) lookup(user, pass string) (UserSpec, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	spec, ok := p.byLogin[user]
	if !ok {
		return UserSpec{}, false
	}
	if _, denied := p.denied[spec.ID]; denied {
		return UserSpec{}, false
	}
	if !userLive(spec) {
		return UserSpec{}, false
	}
	if spec.Password != "" && spec.Password != pass && spec.UUID != pass {
		return UserSpec{}, false
	}
	return spec, true
}

func (p *policyEngine) trackSession(sess *sessions.Session) {
	if sess == nil {
		return
	}
	p.sess.Add(sess)
	if sess.IP != "" {
		p.noteIP(sess.UserID, sess.IP)
	}
}

func (p *policyEngine) noteIP(userID, ip string) {
	userID = strings.TrimSpace(userID)
	ip = strings.TrimSpace(ip)
	if userID == "" || ip == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]map[string]time.Time{}
	}
	if p.seen[userID] == nil {
		p.seen[userID] = map[string]time.Time{}
	}
	p.seen[userID][ip] = time.Now().UTC()
}

const presenceFresh = 45 * time.Second

func (p *policyEngine) presence() []Presence {
	live := p.sess.LiveIPs()
	counts := p.sess.OnlineCounts()
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := map[string]struct{}{}
	for id := range p.seen {
		ids[id] = struct{}{}
	}
	for id := range live {
		ids[id] = struct{}{}
	}
	for id := range counts {
		ids[id] = struct{}{}
	}
	out := make([]Presence, 0, len(ids))
	now := time.Now().UTC()
	nextSeen := map[string]map[string]time.Time{}
	for id := range ids {
		row := Presence{UserID: id, Online: counts[id] > 0 || len(live[id]) > 0}
		held := map[string]time.Time{}
		for _, ip := range live[id] {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			held[ip] = now
			row.Online = true
		}
		for ip, at := range held {
			row.IPs = append(row.IPs, PresenceIP{IP: ip, SeenAt: at})
		}
		sort.Slice(row.IPs, func(i, j int) bool {
			if row.IPs[i].SeenAt.Equal(row.IPs[j].SeenAt) {
				return row.IPs[i].IP < row.IPs[j].IP
			}
			return row.IPs[i].SeenAt.After(row.IPs[j].SeenAt)
		})
		if len(held) > 0 {
			nextSeen[id] = held
		}
		out = append(out, row)
	}
	p.seen = nextSeen
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out
}

func (p *policyEngine) takeBytes(userID string, n int, stop <-chan struct{}) (int, bool) {
	if n <= 0 {
		return 0, true
	}
	room := p.quota.Room(userID)
	if room == 0 {
		return 0, false
	}
	want := n
	if room > 0 && int64(want) > room {
		want = int(room)
	}
	got := p.limit.Wait(userID, want, stop)
	if got <= 0 {
		return 0, false
	}
	if _, _, ok := p.quota.Add(userID, int64(got)); !ok {
		return 0, false
	}
	p.mu.Lock()
	p.used[userID] += int64(got)
	p.mu.Unlock()
	return got, true
}

func (p *policyEngine) snapshots() []Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.captured != nil {
		out := make([]Snapshot, 0, len(p.captured))
		for id, n := range p.captured {
			delta := n - p.acked[id]
			if delta > 0 {
				out = append(out, Snapshot{UserID: id, Bytes: delta})
			}
		}
		return out
	}
	out := make([]Snapshot, 0, len(p.used))
	captured := map[string]int64{}
	for id, n := range p.used {
		delta := n - p.acked[id]
		if delta > 0 {
			out = append(out, Snapshot{UserID: id, Bytes: delta})
			captured[id] = n
		}
	}
	if len(out) == 0 {
		return nil
	}
	p.captured = captured
	return out
}

func (p *policyEngine) ack() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.captured == nil {
		return
	}
	if p.acked == nil {
		p.acked = map[string]int64{}
	}
	for id, n := range p.captured {
		p.acked[id] = n
	}
	p.captured = nil
}

func (p *policyEngine) lookupUUID(id string) (UserSpec, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	spec, ok := p.byUUID[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return UserSpec{}, false
	}
	if _, denied := p.denied[spec.ID]; denied {
		return UserSpec{}, false
	}
	if !userLive(spec) {
		return UserSpec{}, false
	}
	return spec, true
}

func (p *policyEngine) mapStatName(name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if spec, ok := p.byLogin[name]; ok {
		return spec.ID
	}
	if spec, ok := p.byUUID[strings.ToLower(strings.TrimSpace(name))]; ok {
		return spec.ID
	}
	for _, u := range p.users {
		if u.ID == name {
			return u.ID
		}
	}
	return name
}

func identityFront(in InboundSpec, users []UserSpec) bool {
	p := strings.ToLower(strings.TrimSpace(in.Protocol))
	if p == "" || p == "socks" || p == "http" {
		return true
	}
	if p != "vless" || coreOwnedTLS(in, users) {
		return false
	}
	switch inboundNetwork(in) {
	case "", "tcp", "raw", "ws", "websocket":
		return true
	default:
		return false
	}
}

func inboundVision(in InboundSpec) bool {
	return strings.Contains(strings.ToLower(inboundFlow(in)), "vision")
}

func flowHasVision(flow string) bool {
	return strings.Contains(strings.ToLower(flow), "vision")
}

func userFlowVision(users []UserSpec, inboundID string) bool {
	for _, u := range usersForInbound(users, inboundID) {
		if flowHasVision(u.Flow) {
			return true
		}
	}
	return false
}

func inboundPresentsTLS(in InboundSpec) bool {
	switch streamSecurity(in) {
	case "tls", "reality":
		return true
	}
	return strings.TrimSpace(in.CertPEM) != "" && strings.TrimSpace(in.KeyPEM) != ""
}

func coreOwnedTLS(in InboundSpec, users []UserSpec) bool {
	p := strings.ToLower(strings.TrimSpace(in.Protocol))
	if p == "anytls" {
		return inboundPresentsTLS(in)
	}
	if p != "vless" {
		return false
	}
	if inboundReality(in) || inboundVision(in) {
		return true
	}
	netw := inboundNetwork(in)
	if netw != "" && netw != "tcp" && netw != "raw" {
		return false
	}
	return inboundPresentsTLS(in) && userFlowVision(users, in.ID)
}

// policyExitNeeded is the quota SOCKS hop after the core decrypts TLS.
// Xray Reality/Vision bind the public port and go freedom (3x-ui); SOCKS
// would accept TCP then drop HTTP/3. sing-box has no Vision splice, so it
// still meters Reality through SOCKS.
func policyExitNeeded(in InboundSpec, users []UserSpec, xray bool) bool {
	return !xray && coreOwnedTLS(in, users)
}

func policyExitTag(userID string) string {
	return "nodemgt-policy-" + userID
}

func policyUsers(users []UserSpec) []UserSpec {
	out := make([]UserSpec, 0, len(users))
	for _, u := range users {
		if !userLive(u) {
			continue
		}
		if _, _, ok := socksIdentity(u); ok {
			out = append(out, u)
		}
	}
	return out
}

func newExitFront(port int, hops []egressHop) frontSpec {
	return frontSpec{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Exit: true, Egress: hops}
}

func policyRouteTag(userID, outTag string) string {
	if outTag == "" || outTag == "direct" {
		return policyExitTag(userID)
	}
	return policyExitTag(userID) + "-" + outTag
}

func findOutboundSpec(tag string, specs []OutboundSpec) (OutboundSpec, bool) {
	for _, spec := range specs {
		name := spec.Name
		if name == "" {
			name = spec.ID
		}
		if spec.ID == tag || name == tag {
			return spec, true
		}
	}
	return OutboundSpec{}, false
}

func outboundViaTag(settings string) string {
	var s struct {
		Via string `json:"via_outbound"`
	}
	_ = json.Unmarshal([]byte(settings), &s)
	return strings.TrimSpace(s.Via)
}

func hopFromOutbound(spec OutboundSpec) (egressHop, bool) {
	proto := strings.ToLower(spec.Protocol)
	if proto != "socks" && proto != "http" && proto != "vless" {
		return egressHop{}, false
	}
	var s struct {
		Address   string `json:"address"`
		Port      any    `json:"port"`
		Username  string `json:"username"`
		Password  string `json:"password"`
		UUID      string `json:"uuid"`
		Flow      string `json:"flow"`
		Transport string `json:"transport"`
		Security  string `json:"security"`
		SNI       string `json:"sni"`
		WSPath    string `json:"ws_path"`
		WSHost    string `json:"ws_host"`
	}
	_ = json.Unmarshal([]byte(spec.SettingsJSON), &s)
	port := jsonPort(s.Port)
	if s.Address == "" || port <= 0 {
		return egressHop{}, false
	}
	if proto == "vless" {
		if strings.TrimSpace(s.UUID) == "" || strings.TrimSpace(s.Flow) != "" {
			return egressHop{}, false
		}
		transport := strings.ToLower(strings.TrimSpace(s.Transport))
		if transport == "websocket" {
			transport = "ws"
		}
		security := strings.ToLower(strings.TrimSpace(s.Security))
		if transport != "" && transport != "tcp" && transport != "ws" {
			return egressHop{}, false
		}
		if security != "" && security != "none" && security != "tls" {
			return egressHop{}, false
		}
		return egressHop{
			Protocol:  proto,
			Addr:      net.JoinHostPort(s.Address, strconv.Itoa(port)),
			UUID:      strings.TrimSpace(s.UUID),
			Transport: transport,
			Security:  security,
			SNI:       strings.TrimSpace(s.SNI),
			WSPath:    strings.TrimSpace(s.WSPath),
			WSHost:    strings.TrimSpace(s.WSHost),
		}, true
	}
	return egressHop{Protocol: proto, Addr: net.JoinHostPort(s.Address, strconv.Itoa(port)), User: s.Username, Pass: s.Password}, true
}

func jsonPort(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		p, _ := n.Int64()
		return int(p)
	case string:
		p, _ := strconv.Atoi(n)
		return p
	case int:
		return n
	default:
		return 0
	}
}

func egressChain(tag string, specs []OutboundSpec, seen map[string]bool) ([]egressHop, bool) {
	if tag == "" || tag == "direct" || tag == "block" || seen[tag] {
		return nil, true
	}
	spec, ok := findOutboundSpec(tag, specs)
	if !ok {
		return nil, false
	}
	proto := strings.ToLower(spec.Protocol)
	if proto == "" || proto == "freedom" || proto == "direct" || proto == "blackhole" || proto == "block" {
		return nil, true
	}
	seen[tag] = true
	var hops []egressHop
	if via := outboundViaTag(spec.SettingsJSON); via != "" {
		viaHops, viaOK := egressChain(via, specs, seen)
		if !viaOK {
			return nil, false
		}
		hops = append(hops, viaHops...)
	}
	hop, hopOK := hopFromOutbound(spec)
	if !hopOK {
		return nil, false
	}
	return append(hops, hop), true
}

func policyViaTag(userID, outbound string) string {
	return "nodemgt-via-" + userID + "-" + outbound
}

func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func outboundByTag(obs []map[string]any, tag string) map[string]any {
	for _, ob := range obs {
		if t, _ := ob["tag"].(string); t == tag {
			return ob
		}
	}
	return nil
}

func ruleStringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intersectTags(tags, policy []string) []string {
	if len(tags) == 0 {
		return append([]string(nil), policy...)
	}
	set := map[string]struct{}{}
	for _, t := range policy {
		set[t] = struct{}{}
	}
	var out []string
	for _, t := range tags {
		if _, ok := set[t]; ok {
			out = append(out, t)
		}
	}
	return out
}

func ruleHasDestFilter(rule map[string]any) bool {
	for _, key := range []string{"domain", "ip", "ip_cidr", "protocol", "port", "source", "source_ip", "network"} {
		if len(ruleStringList(rule[key])) > 0 {
			return true
		}
		if s, ok := rule[key].(string); ok && s != "" {
			return true
		}
	}
	return false
}

func outboundKind(ob map[string]any) string {
	if ob == nil {
		return "direct"
	}
	kind, _ := ob["protocol"].(string)
	if kind == "" {
		kind, _ = ob["type"].(string)
	}
	return strings.ToLower(kind)
}

func outboundIsDirect(ob map[string]any) bool {
	switch outboundKind(ob) {
	case "", "freedom", "direct":
		return true
	default:
		return false
	}
}

func outboundIsBlock(ob map[string]any, tag string) bool {
	if tag == "block" {
		return true
	}
	switch outboundKind(ob) {
	case "blackhole", "block":
		return true
	default:
		return false
	}
}

func viaOutbound(base map[string]any, tag, proxy string, xray bool) map[string]any {
	ob := cloneAnyMap(base)
	if ob == nil {
		if xray {
			ob = map[string]any{
				"protocol": "freedom",
				"settings": map[string]any{"finalRules": []map[string]any{{"action": "allow"}}},
			}
		} else {
			ob = map[string]any{"type": "direct"}
		}
	}
	ob["tag"] = tag
	kind, _ := ob["protocol"].(string)
	if kind == "" {
		kind, _ = ob["type"].(string)
	}
	if strings.EqualFold(kind, "blackhole") || strings.EqualFold(kind, "block") {
		return ob
	}
	if xray {
		stream, _ := ob["streamSettings"].(map[string]any)
		if stream == nil {
			stream = map[string]any{}
		}
		sockopt, _ := stream["sockopt"].(map[string]any)
		if sockopt == nil {
			sockopt = map[string]any{}
		}
		sockopt["dialerProxy"] = proxy
		stream["sockopt"] = sockopt
		ob["streamSettings"] = stream
		return ob
	}
	ob["detour"] = proxy
	return ob
}

func attachPolicyExit(obs, rules []map[string]any, users []UserSpec, policyTags []string, xray bool, specs []OutboundSpec) ([]map[string]any, []map[string]any, []frontSpec, []map[string]any, error) {
	if len(policyTags) == 0 {
		return obs, rules, nil, nil, nil
	}
	inboundKey, outboundKey, userKey := "inbound", "outbound", "auth_user"
	if xray {
		inboundKey, outboundKey, userKey = "inboundTag", "outboundTag", "user"
	}
	type chainListen struct {
		hops []egressHop
		port int
	}
	chains := map[string]*chainListen{}
	added := map[string]struct{}{}
	live := policyUsers(users)
	byID := map[string]UserSpec{}
	for _, u := range live {
		byID[u.ID] = u
	}
	ensureChain := func(key string, hops []egressHop) (int, error) {
		if c, ok := chains[key]; ok {
			return c.port, nil
		}
		port, err := reserveLoopbackPort()
		if err != nil {
			return 0, err
		}
		chains[key] = &chainListen{hops: append([]egressHop(nil), hops...), port: port}
		return port, nil
	}
	addUserSocks := func(userID, key string, port int) {
		tag := policyRouteTag(userID, key)
		if _, ok := added[tag]; ok {
			return
		}
		u, ok := byID[userID]
		if !ok {
			return
		}
		user, pass, ok := socksIdentity(u)
		if !ok {
			return
		}
		if xray {
			obs = append(obs, map[string]any{
				"protocol": "socks",
				"tag":      tag,
				"settings": map[string]any{"servers": []map[string]any{{
					"address": "127.0.0.1",
					"port":    port,
					"users":   []map[string]any{{"user": user, "pass": pass}},
				}}},
			})
		} else {
			obs = append(obs, map[string]any{
				"type":        "socks",
				"tag":         tag,
				"server":      "127.0.0.1",
				"server_port": port,
				"username":    user,
				"password":    pass,
				"network":     "tcp",
			})
		}
		added[tag] = struct{}{}
	}
	var coreIn []map[string]any
	var detourRules []map[string]any
	detours := map[string][]egressHop{}
	ensureFallback := func(outTag string) ([]egressHop, error) {
		if hops, ok := detours[outTag]; ok {
			return hops, nil
		}
		port, err := reserveLoopbackPort()
		if err != nil {
			return nil, err
		}
		tag := "nodemgt-core-" + outTag
		if xray {
			coreIn = append(coreIn, map[string]any{
				"tag":      tag,
				"listen":   "127.0.0.1",
				"port":     port,
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": false},
			})
			detourRules = append(detourRules, map[string]any{
				"type":        "field",
				"inboundTag":  []string{tag},
				"outboundTag": outTag,
			})
		} else {
			coreIn = append(coreIn, map[string]any{
				"type":        "socks",
				"tag":         tag,
				"listen":      "127.0.0.1",
				"listen_port": port,
			})
			detourRules = append(detourRules, map[string]any{
				"inbound":  []string{tag},
				"outbound": outTag,
			})
		}
		hops := []egressHop{{Protocol: "socks", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}}
		detours[outTag] = hops
		return hops, nil
	}
	var chainErr error
	ensureVia := func(outTag, userID string) string {
		if chainErr != nil {
			return policyExitTag(userID)
		}
		base := outboundByTag(obs, outTag)
		if outboundIsBlock(base, outTag) {
			if outTag != "" {
				return outTag
			}
			return "block"
		}
		hops, complete := egressChain(outTag, specs, map[string]bool{})
		key := "direct"
		if complete && len(hops) > 0 {
			key = outTag
		} else if !complete && !outboundIsDirect(base) && outTag != "" && outTag != "direct" {
			key = outTag
			hops, err := ensureFallback(outTag)
			if err != nil {
				chainErr = err
				return policyExitTag(userID)
			}
			port, err := ensureChain(key, hops)
			if err != nil {
				chainErr = err
				return policyExitTag(userID)
			}
			addUserSocks(userID, key, port)
			return policyRouteTag(userID, key)
		}
		port, err := ensureChain(key, hops)
		if err != nil {
			chainErr = err
			return policyExitTag(userID)
		}
		addUserSocks(userID, key, port)
		return policyRouteTag(userID, key)
	}
	covered := map[string]struct{}{}
	var wrapped []map[string]any
	for _, rule := range rules {
		outTag, _ := rule[outboundKey].(string)
		inTags := ruleStringList(rule[inboundKey])
		policyIn := intersectTags(inTags, policyTags)
		if outTag == "" || strings.HasPrefix(outTag, "nodemgt-") || len(policyIn) == 0 {
			wrapped = append(wrapped, rule)
			continue
		}
		for _, u := range live {
			wr := cloneAnyMap(rule)
			if wr == nil {
				wr = map[string]any{}
			}
			if xray {
				wr["type"] = "field"
			}
			wr[inboundKey] = policyIn
			wr[userKey] = []string{u.ID}
			wr[outboundKey] = ensureVia(outTag, u.ID)
			wrapped = append(wrapped, wr)
		}
		if !ruleHasDestFilter(rule) {
			for _, tag := range policyIn {
				covered[tag] = struct{}{}
			}
		}
		wrapped = append(wrapped, rule)
	}
	var uncovered []string
	for _, tag := range policyTags {
		if _, ok := covered[tag]; !ok {
			uncovered = append(uncovered, tag)
		}
	}
	if len(uncovered) > 0 {
		for _, u := range live {
			item := map[string]any{
				inboundKey:  uncovered,
				userKey:     []string{u.ID},
				outboundKey: ensureVia("direct", u.ID),
			}
			if xray {
				item["type"] = "field"
			}
			wrapped = append(wrapped, item)
		}
	}
	if chainErr != nil {
		return obs, wrapped, nil, nil, chainErr
	}
	extra := make([]frontSpec, 0, len(chains))
	for _, c := range chains {
		extra = append(extra, newExitFront(c.port, c.hops))
	}
	return obs, append(detourRules, wrapped...), extra, coreIn, nil
}

func inboundReality(in InboundSpec) bool {
	return strings.EqualFold(streamSecurity(in), "reality")
}

func streamSecurity(in InboundSpec) string {
	var stream struct {
		Security string `json:"security"`
	}
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	return strings.ToLower(stream.Security)
}

func inboundNetwork(in InboundSpec) string {
	var stream struct {
		Network string `json:"network"`
	}
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	n := strings.ToLower(strings.TrimSpace(stream.Network))
	if n == "websocket" {
		return "ws"
	}
	return n
}

func inboundWSPath(in InboundSpec) string {
	var stream struct {
		WSSettings struct {
			Path string `json:"path"`
		} `json:"wsSettings"`
	}
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	path := strings.TrimSpace(stream.WSSettings.Path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func inboundServerTLS(in InboundSpec) *tls.Config {
	if in.TLS != nil {
		return in.TLS.Clone()
	}
	if strings.TrimSpace(in.CertPEM) == "" || strings.TrimSpace(in.KeyPEM) == "" {
		return nil
	}
	cert, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
	if err != nil {
		return nil
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func newFrontSpec(listen, dest, proto string, in InboundSpec, users []UserSpec) frontSpec {
	network := inboundNetwork(in)
	if network == "websocket" {
		network = "ws"
	}
	identity := identityFront(in, users)
	return frontSpec{
		Addr:          listen,
		Dest:          dest,
		Protocol:      proto,
		Identity:      identity,
		ProxyProtocol: !identity,
		TLS:           inboundServerTLS(in),
		Network:       network,
		WSPath:        inboundWSPath(in),
	}
}

func inboundsNeedCoreRestart(inbounds []InboundSpec, users []UserSpec) bool {
	for _, in := range inbounds {
		if identityFront(in, users) || coreOwnedTLS(in, users) {
			continue
		}
		return true
	}
	return false
}

func startPolicyFronts(policy *policyEngine, specs []frontSpec) ([]*spliceFront, error) {
	var started []*spliceFront
	for _, spec := range specs {
		spec := spec
		ln, err := listenFront(spec.Addr)
		if err != nil {
			for _, f := range started {
				f.close()
			}
			return nil, err
		}
		front := &spliceFront{ln: ln}
		switch {
		case spec.Exit:
			go servePolicyExit(front, spec, policy)
		case spec.Identity && strings.EqualFold(spec.Protocol, "vless"):
			go serveVLESSFront(front, spec, policy)
		case spec.Identity && strings.EqualFold(spec.Protocol, "http"):
			go serveIdentityHTTP(front, spec, policy)
		case spec.Identity:
			go serveIdentitySplice(front, spec.Dest, policy)
		default:
			go serveSplice(front, spec)
		}
		started = append(started, front)
	}
	return started, nil
}

func serveSplice(front *spliceFront, spec frontSpec) {
	for {
		client, err := front.ln.Accept()
		if err != nil {
			return
		}
		front.spawnTracked(client, func() {
			backend, err := net.DialTimeout("tcp", spec.Dest, 2*time.Second)
			if err != nil {
				_ = client.Close()
				return
			}
			front.track(backend)
			defer front.drop(backend)
			defer client.Close()
			defer backend.Close()
			if spec.ProxyProtocol {
				if err := writeProxyProtocolV1(backend, client, backend); err != nil {
					return
				}
			}
			go io.Copy(backend, client)
			io.Copy(client, backend)
		})
	}
}

func serveIdentitySplice(front *spliceFront, dest string, policy *policyEngine) {
	for {
		client, err := front.ln.Accept()
		if err != nil {
			return
		}
		front.spawnTracked(client, func() { handleIdentitySOCKS(front, client, dest, policy) })
	}
}

func serveIdentityHTTP(front *spliceFront, spec frontSpec, policy *policyEngine) {
	ln := net.Listener(front.ln)
	if spec.TLS != nil {
		ln = tls.NewListener(ln, spec.TLS)
	}
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		front.spawnTracked(client, func() { handleIdentityHTTP(front, client, spec.Dest, policy) })
	}
}

func handleIdentityHTTP(front *spliceFront, client net.Conn, dest string, policy *policyEngine) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	cr := bufio.NewReader(client)
	req, err := http.ReadRequest(cr)
	if err != nil {
		return
	}
	user, pass, ok := proxyBasicAuth(req)
	if !ok {
		writeProxyStatus(client, http.StatusProxyAuthRequired, map[string]string{"Proxy-Authenticate": `Basic realm="nodemgt"`})
		return
	}
	spec, ok := policy.lookup(user, pass)
	if !ok {
		writeProxyStatus(client, http.StatusProxyAuthRequired, map[string]string{"Proxy-Authenticate": `Basic realm="nodemgt"`})
		return
	}
	ip := connClientIP(client)
	if !policy.holdIP(spec.ID, ip, spec.DeviceLimit) {
		writeProxyStatus(client, http.StatusForbidden, nil)
		return
	}
	defer policy.releaseIP(spec.ID, ip)
	sessID := fmt.Sprintf("%s-%d", spec.ID, time.Now().UnixNano())
	policy.trackSession(&sessions.Session{ID: sessID, UserID: spec.ID, Conn: client})
	defer policy.sess.Remove(sessID)
	backend, err := net.DialTimeout("tcp", dest, 2*time.Second)
	if err != nil {
		writeProxyStatus(client, http.StatusBadGateway, nil)
		return
	}
	front.track(backend)
	defer front.drop(backend)
	defer backend.Close()
	_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
	if err := req.WriteProxy(backend); err != nil {
		return
	}
	br := bufio.NewReader(backend)
	if strings.EqualFold(req.Method, http.MethodConnect) {
		head, status, err := readHTTPHead(br)
		if err != nil {
			return
		}
		if _, err := client.Write(head); err != nil {
			return
		}
		if status != http.StatusOK {
			return
		}
	}
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	splicePolicy(client, backend, cr, br, spec.ID, policy)
}

func readHTTPHead(r *bufio.Reader) ([]byte, int, error) {
	var buf []byte
	tmp := make([]byte, 1)
	for len(buf) < 8192 {
		if _, err := io.ReadFull(r, tmp); err != nil {
			return nil, 0, err
		}
		buf = append(buf, tmp[0])
		if !bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
			continue
		}
		status := string(buf)
		if i := strings.Index(status, "\r\n"); i > 0 {
			status = status[:i]
		}
		parts := strings.SplitN(status, " ", 3)
		if len(parts) < 2 {
			return buf, 0, fmt.Errorf("http status")
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil {
			return buf, 0, err
		}
		return buf, code, nil
	}
	return nil, 0, fmt.Errorf("http head")
}

func proxyBasicAuth(req *http.Request) (user, pass string, ok bool) {
	if req == nil {
		return "", "", false
	}
	raw := strings.TrimSpace(req.Header.Get("Proxy-Authorization"))
	const prefix = "Basic "
	if !strings.HasPrefix(raw, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(decoded), ":")
	return strings.TrimSpace(user), pass, ok && strings.TrimSpace(user) != ""
}

func writeProxyStatus(w io.Writer, status int, extra map[string]string) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for key, value := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", key, value)
	}
	b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	_, _ = io.WriteString(w, b.String())
}

func servePolicyExit(front *spliceFront, spec frontSpec, policy *policyEngine) {
	for {
		client, err := front.ln.Accept()
		if err != nil {
			return
		}
		front.spawnTracked(client, func() { handlePolicyExitSOCKS(front, client, policy, spec.Egress) })
	}
}

func handlePolicyExitSOCKS(front *spliceFront, client net.Conn, policy *policyEngine, hops []egressHop) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	cr := bufio.NewReader(client)
	greeting, err := readSOCKS5Greeting(cr)
	if err != nil {
		return
	}
	if !socks5HasUserPass(greeting) {
		_, _ = client.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
		return
	}
	user, pass, _, err := readSOCKS5UserPass(cr)
	if err != nil {
		return
	}
	spec, ok := policy.lookup(user, pass)
	if !ok {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		return
	}
	req, err := readSOCKS5AddrHead(cr)
	if err != nil {
		return
	}
	dest, err := socks5Dest(req)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	sessID := fmt.Sprintf("%s-%d", spec.ID, time.Now().UnixNano())
	policy.trackSession(&sessions.Session{ID: sessID, UserID: spec.ID, Conn: client, HideIP: true})
	defer policy.sess.Remove(sessID)
	backend, err := dialThroughEgress(hops, dest)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	front.track(backend)
	defer front.drop(backend)
	defer backend.Close()
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	splicePolicy(client, backend, cr, backend, spec.ID, policy)
}

func dialThroughEgress(hops []egressHop, dest string) (net.Conn, error) {
	if len(hops) == 0 {
		return net.DialTimeout("tcp", dest, 2*time.Second)
	}
	conn, err := net.DialTimeout("tcp", hops[0].Addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	for i, hop := range hops {
		next := dest
		if i+1 < len(hops) {
			next = hops[i+1].Addr
		}
		nextConn, err := hopConnect(conn, hop, next)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = nextConn
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func hopConnect(conn net.Conn, hop egressHop, dest string) (net.Conn, error) {
	switch strings.ToLower(hop.Protocol) {
	case "http":
		if err := httpProxyConnect(conn, hop, dest); err != nil {
			return nil, err
		}
		return conn, nil
	case "vless":
		stream, err := wrapHopSecurity(conn, hop)
		if err != nil {
			return nil, err
		}
		stream, err = wrapHopWS(stream, hop)
		if err != nil {
			return nil, err
		}
		if err := vlessClientConnect(stream, hop.UUID, dest); err != nil {
			return nil, err
		}
		return newVLESSStreamConn(stream), nil
	default:
		if err := socks5ClientConnect(conn, hop.User, hop.Pass, dest); err != nil {
			return nil, err
		}
		return conn, nil
	}
}

func wrapHopSecurity(conn net.Conn, hop egressHop) (net.Conn, error) {
	switch strings.ToLower(strings.TrimSpace(hop.Security)) {
	case "", "none":
		return conn, nil
	case "tls":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hopTLSServerName(hop)}
		hopTLSMu.Lock()
		if hopTLSRootCAs != nil {
			cfg.RootCAs = hopTLSRootCAs
		}
		hopTLSMu.Unlock()
		inner := tls.Client(conn, cfg)
		if err := inner.Handshake(); err != nil {
			return nil, err
		}
		return inner, nil
	default:
		return nil, fmt.Errorf("hop security")
	}
}

func hopTLSServerName(hop egressHop) string {
	if sni := strings.TrimSpace(hop.SNI); sni != "" {
		return sni
	}
	host, _, err := net.SplitHostPort(hop.Addr)
	if err == nil && host != "" {
		return host
	}
	if hop.Addr != "" {
		return hop.Addr
	}
	return "localhost"
}

func wsRequestURL(addr, rawPath string) url.URL {
	if rawPath == "" {
		rawPath = "/"
	}
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	path, query, _ := strings.Cut(rawPath, "?")
	decoded, err := url.PathUnescape(path)
	if err != nil {
		decoded = path
	}
	u := url.URL{Scheme: "ws", Host: addr, Path: decoded, RawQuery: query}
	if path != decoded {
		u.RawPath = path
	}
	return u
}

func wrapHopWS(conn net.Conn, hop egressHop) (net.Conn, error) {
	if hop.Transport != "ws" {
		return conn, nil
	}
	u := wsRequestURL(hop.Addr, hop.WSPath)
	hdr := http.Header{}
	if hop.WSHost != "" {
		hdr.Set("Host", hop.WSHost)
	}
	dialer := websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		HandshakeTimeout: 3 * time.Second,
	}
	ws, _, err := dialer.Dial(u.String(), hdr)
	if err != nil {
		return nil, err
	}
	return newWSConn(ws), nil
}

func newVLESSStreamConn(conn net.Conn) net.Conn {
	return &vlessStreamConn{Conn: conn, skipper: vlessReplySkipper{r: conn}}
}

type vlessStreamConn struct {
	net.Conn
	skipper vlessReplySkipper
}

func (c *vlessStreamConn) Read(p []byte) (int, error) {
	return c.skipper.Read(p)
}

func vlessClientConnect(conn net.Conn, uuid, dest string) error {
	id, err := parseUUIDBytes(uuid)
	if err != nil {
		return err
	}
	req, err := vlessConnectRequest(id, dest)
	if err != nil {
		return err
	}
	_, err = conn.Write(req)
	return err
}

func parseUUIDBytes(s string) ([]byte, error) {
	raw := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	id, err := hex.DecodeString(raw)
	if err != nil || len(id) != 16 {
		return nil, fmt.Errorf("vless uuid")
	}
	return id, nil
}

func vlessConnectRequest(id []byte, dest string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("vless port")
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req := append([]byte{0}, id...)
	req = append(req, 0, 1)
	req = append(req, pb...)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append(req, 1), v4...), nil
		}
		return append(append(req, 3), ip.To16()...), nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("vless host")
	}
	return append(append(req, 2, byte(len(host))), host...), nil
}

func socks5ClientConnect(conn net.Conn, user, pass, dest string) error {
	if user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return err
	}
	if method[0] != 0x05 {
		return fmt.Errorf("socks ver")
	}
	switch method[1] {
	case 0x00:
	case 0x02:
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		auth := make([]byte, 2)
		if _, err := io.ReadFull(conn, auth); err != nil {
			return err
		}
		if auth[1] != 0 {
			return fmt.Errorf("socks auth")
		}
	default:
		return fmt.Errorf("socks method")
	}
	req, err := socks5ConnectRequest(dest)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	return socks5SkipReply(conn)
}

func socks5ConnectRequest(dest string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks port")
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append(append(req, 0x01), v4...), pb...), nil
		}
		return append(append(append(req, 0x04), ip.To16()...), pb...), nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("socks host")
	}
	return append(append(append(req, 0x03, byte(len(host))), host...), pb...), nil
}

func socks5SkipReply(r io.Reader) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] != 0 {
		return fmt.Errorf("socks reply")
	}
	switch head[3] {
	case 0x01:
		_, err := io.ReadFull(r, make([]byte, 6))
		return err
	case 0x04:
		_, err := io.ReadFull(r, make([]byte, 18))
		return err
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(n[0])+2))
		return err
	default:
		return fmt.Errorf("socks atyp")
	}
}

func httpProxyConnect(conn net.Conn, hop egressHop, dest string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", dest, dest)
	if hop.User != "" {
		token := base64.StdEncoding.EncodeToString([]byte(hop.User + ":" + hop.Pass))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", token)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return err
	}
	var buf []byte
	tmp := make([]byte, 1)
	for len(buf) < 8192 {
		if _, err := io.ReadFull(conn, tmp); err != nil {
			return err
		}
		buf = append(buf, tmp[0])
		if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
			status := string(buf)
			if i := strings.Index(status, "\r\n"); i > 0 {
				status = status[:i]
			}
			parts := strings.SplitN(status, " ", 3)
			if len(parts) < 2 || parts[1] != "200" {
				return fmt.Errorf("http connect")
			}
			return nil
		}
	}
	return fmt.Errorf("http head")
}

func socks5Dest(req []byte) (string, error) {
	if len(req) < 7 || req[0] != 0x05 || req[1] != 0x01 {
		return "", fmt.Errorf("socks dest")
	}
	switch req[3] {
	case 0x01:
		if len(req) < 10 {
			return "", fmt.Errorf("socks ipv4")
		}
		host := net.IP(req[4:8]).String()
		port := binary.BigEndian.Uint16(req[8:10])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	case 0x04:
		if len(req) < 22 {
			return "", fmt.Errorf("socks ipv6")
		}
		host := net.IP(req[4:20]).String()
		port := binary.BigEndian.Uint16(req[20:22])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	case 0x03:
		if len(req) < 5 {
			return "", fmt.Errorf("socks domain")
		}
		n := int(req[4])
		if len(req) < 7+n {
			return "", fmt.Errorf("socks domain")
		}
		host := string(req[5 : 5+n])
		port := binary.BigEndian.Uint16(req[5+n : 7+n])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
	default:
		return "", fmt.Errorf("socks atyp")
	}
}

func handleIdentitySOCKS(front *spliceFront, client net.Conn, dest string, policy *policyEngine) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	cr := bufio.NewReader(client)
	greeting, err := readSOCKS5Greeting(cr)
	if err != nil {
		return
	}
	if !socks5HasUserPass(greeting) {
		_, _ = client.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x02}); err != nil {
		return
	}
	user, pass, _, err := readSOCKS5UserPass(cr)
	if err != nil {
		return
	}
	spec, ok := policy.lookup(user, pass)
	if !ok {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	ip := connClientIP(client)
	if !policy.holdIP(spec.ID, ip, spec.DeviceLimit) {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	defer policy.releaseIP(spec.ID, ip)
	sessID := fmt.Sprintf("%s-%d", spec.ID, time.Now().UnixNano())
	policy.trackSession(&sessions.Session{ID: sessID, UserID: spec.ID, Conn: client})
	defer policy.sess.Remove(sessID)
	backend, err := net.DialTimeout("tcp", dest, 2*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	front.track(backend)
	defer front.drop(backend)
	defer backend.Close()
	_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(backend)
	if _, err := backend.Write(greeting); err != nil {
		return
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(br, method); err != nil || method[0] != 0x05 || method[1] != 0x02 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	auth := socks5UserPassBytes(user, pass)
	if _, err := backend.Write(auth); err != nil {
		return
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(br, authReply); err != nil || authReply[1] != 0 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return
	}
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		return
	}
	req, err := readSOCKS5AddrHead(cr)
	if err != nil {
		return
	}
	if _, err := backend.Write(req); err != nil {
		return
	}
	reply, err := readSOCKS5AddrHead(br)
	if err != nil {
		return
	}
	if _, err := client.Write(reply); err != nil {
		return
	}
	if len(reply) < 2 || reply[1] != 0 {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	splicePolicy(client, backend, cr, br, spec.ID, policy)
}

func serveVLESSFront(front *spliceFront, spec frontSpec, policy *policyEngine) {
	ln := net.Listener(front.ln)
	if spec.TLS != nil {
		ln = tls.NewListener(ln, spec.TLS)
	}
	if spec.Network == "ws" {
		serveVLESSWS(front, ln, spec, policy)
		return
	}
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		front.spawnTracked(client, func() { handleIdentityVLESS(front, client, spec.Dest, policy) })
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func serveVLESSWS(front *spliceFront, ln net.Listener, spec frontSpec, policy *policyEngine) {
	path := spec.WSPath
	if path == "" {
		path = "/"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		wc, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn := newWSConn(wc)
		front.spawnTracked(conn, func() { handleIdentityVLESS(front, conn, spec.Dest, policy) })
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	_ = srv.Serve(ln)
}

func handleIdentityVLESS(front *spliceFront, client net.Conn, dest string, policy *policyEngine) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	header, uuid, err := readVLESSRequest(client)
	if err != nil {
		return
	}
	spec, ok := policy.lookupUUID(uuid)
	if !ok {
		return
	}
	ip := connClientIP(client)
	if !policy.holdIP(spec.ID, ip, spec.DeviceLimit) {
		return
	}
	defer policy.releaseIP(spec.ID, ip)
	sessID := fmt.Sprintf("%s-%d", spec.ID, time.Now().UnixNano())
	policy.trackSession(&sessions.Session{ID: sessID, UserID: spec.ID, Conn: client})
	defer policy.sess.Remove(sessID)
	backend, err := net.DialTimeout("tcp", dest, 2*time.Second)
	if err != nil {
		return
	}
	front.track(backend)
	defer front.drop(backend)
	defer backend.Close()
	if _, err := backend.Write(header); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	splicePolicy(client, backend, client, &vlessReplyReader{r: backend, client: client}, spec.ID, policy)
}

type vlessReplySkipper struct {
	r      io.Reader
	primed bool
}

func (v *vlessReplySkipper) Read(p []byte) (int, error) {
	if !v.primed {
		v.primed = true
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(v.r, hdr); err != nil {
			return 0, err
		}
		if hdr[1] > 0 {
			if _, err := io.ReadFull(v.r, make([]byte, int(hdr[1]))); err != nil {
				return 0, err
			}
		}
	}
	return v.r.Read(p)
}

type vlessReplyReader struct {
	r      io.Reader
	client io.Writer
	primed bool
}

func (v *vlessReplyReader) Read(p []byte) (int, error) {
	if !v.primed {
		v.primed = true
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(v.r, hdr); err != nil {
			return 0, err
		}
		if hdr[1] > 0 {
			extra := make([]byte, int(hdr[1]))
			if _, err := io.ReadFull(v.r, extra); err != nil {
				return 0, err
			}
			hdr = append(hdr, extra...)
		}
		if _, err := v.client.Write(hdr); err != nil {
			return 0, err
		}
	}
	return v.r.Read(p)
}

func splicePolicy(client, backend net.Conn, cr, br io.Reader, userID string, policy *policyEngine) {
	stop := make(chan struct{})
	done := make(chan struct{}, 2)
	go func() {
		policyCopy(backend, cr, userID, policy, stop)
		done <- struct{}{}
	}()
	go func() {
		policyCopy(client, br, userID, policy, stop)
		done <- struct{}{}
	}()
	<-done
	close(stop)
	_ = client.Close()
	_ = backend.Close()
	<-done
}

func policyCopy(dst io.Writer, src io.Reader, userID string, policy *policyEngine, stop <-chan struct{}) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			off := 0
			for off < n {
				got, ok := policy.takeBytes(userID, n-off, stop)
				if !ok || got <= 0 {
					return
				}
				if _, werr := dst.Write(buf[off : off+got]); werr != nil {
					return
				}
				off += got
			}
		}
		if err != nil {
			return
		}
	}
}

func readVLESSRequest(r io.Reader) ([]byte, string, error) {
	hdr := make([]byte, 18)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, "", err
	}
	addonLen := int(hdr[17])
	mid := make([]byte, addonLen+1+2+1)
	if _, err := io.ReadFull(r, mid); err != nil {
		return nil, "", err
	}
	atyp := mid[len(mid)-1]
	var addr []byte
	switch atyp {
	case 1:
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, "", err
		}
	case 2:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, "", err
		}
		host := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return nil, "", err
		}
		addr = append(lb, host...)
	case 3:
		addr = make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("vless atyp")
	}
	raw := append(append(hdr, mid...), addr...)
	return raw, formatUUID(hdr[1:17]), nil
}

func formatUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func readSOCKS5Greeting(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("not socks5")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return append(hdr, methods...), nil
}

func socks5HasUserPass(greeting []byte) bool {
	if len(greeting) < 2 {
		return false
	}
	for _, m := range greeting[2:] {
		if m == 0x02 {
			return true
		}
	}
	return false
}

func readSOCKS5UserPass(r io.Reader) (user, pass string, raw []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return "", "", nil, err
	}
	userBytes := make([]byte, int(hdr[1]))
	if _, err = io.ReadFull(r, userBytes); err != nil {
		return "", "", nil, err
	}
	plen := make([]byte, 1)
	if _, err = io.ReadFull(r, plen); err != nil {
		return "", "", nil, err
	}
	passBytes := make([]byte, int(plen[0]))
	if _, err = io.ReadFull(r, passBytes); err != nil {
		return "", "", nil, err
	}
	raw = append(append(append([]byte{}, hdr...), userBytes...), append(plen, passBytes...)...)
	return string(userBytes), string(passBytes), raw, nil
}

func socks5UserPassBytes(user, pass string) []byte {
	out := []byte{0x01, byte(len(user))}
	out = append(out, []byte(user)...)
	out = append(out, byte(len(pass)))
	out = append(out, []byte(pass)...)
	return out
}

func readSOCKS5AddrHead(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	var n int
	switch hdr[3] {
	case 0x01:
		n = 4 + 2
	case 0x04:
		n = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return nil, err
		}
		rest := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		return append(append(hdr, l...), rest...), nil
	default:
		return nil, fmt.Errorf("bad atyp")
	}
	rest := make([]byte, n)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	return append(hdr, rest...), nil
}
