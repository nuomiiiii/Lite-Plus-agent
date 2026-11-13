package coreadapter

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/limiter"
	"github.com/nuomiiiii/lite-agent/nodemgt/quota"
	"github.com/nuomiiiii/lite-agent/nodemgt/sessions"
)

// Native is an in-process TLS inbound used to verify personal control with real
// connections. It is not a substitute for Xray or sing-box; those cores must be
// linked separately and started through their adapters.
type Native struct {
	name    string
	version string
	linked  bool
	quota   *quota.Ledger
	limit   *limiter.Set
	sess    *sessions.Set
	users   map[string]UserSpec
	byUUID  map[string]string
	mu      sync.Mutex
	ln      net.Listener
	cancel  context.CancelFunc
}

func newNative(name, version string, linked bool) *Native {
	return &Native{
		name:    name,
		version: version,
		linked:  linked,
		quota:   quota.New(),
		limit:   limiter.New(),
		sess:    sessions.New(),
		users:   map[string]UserSpec{},
		byUUID:  map[string]string{},
	}
}

func (n *Native) Name() string    { return n.name }
func (n *Native) Version() string { return n.version }
func (n *Native) Linked() bool    { return n.linked }

func (n *Native) LiveInbounds() bool {
	return n.ln != nil
}

func (n *Native) Start(ctx context.Context, inbounds []InboundSpec) error {
	_ = n.Stop()
	var spec *InboundSpec
	for i := range inbounds {
		if inbounds[i].Core == n.name || inbounds[i].Core == "" {
			spec = &inbounds[i]
			break
		}
	}
	if spec == nil {
		return nil
	}
	addr := fmt.Sprintf("%s:%d", spec.Listen, spec.Port)
	var ln net.Listener
	var err error
	if spec.TLS != nil {
		ln, err = tls.Listen("tcp", addr, spec.TLS)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	n.ln = ln
	n.cancel = cancel
	go n.serve(runCtx, ln)
	return nil
}

func (n *Native) Stop() error {
	if n.cancel != nil {
		n.cancel()
	}
	if n.ln != nil {
		_ = n.ln.Close()
		n.ln = nil
	}
	return nil
}

func (n *Native) ApplyUsers(users []UserSpec) error {
	n.mu.Lock()
	n.users = map[string]UserSpec{}
	n.byUUID = map[string]string{}
	for _, u := range users {
		n.users[u.ID] = u
		if u.UUID != "" {
			n.byUUID[u.UUID] = u.ID
		}
		n.quota.Configure(u.ID, u.QuotaBytes, u.UsedBytes)
		n.limit.Configure(u.ID, u.RateLimitBps)
		if u.Disabled || u.Expired {
			n.sess.CloseUser(u.ID)
		}
	}
	n.mu.Unlock()
	return nil
}

func (n *Native) CloseUserSessions(userID string) error {
	n.sess.CloseUser(userID)
	n.mu.Lock()
	if u, ok := n.users[userID]; ok {
		u.Disabled = true
		n.users[userID] = u
	}
	n.mu.Unlock()
	return nil
}

func (n *Native) AcknowledgeUsage() {}

func (n *Native) Presence() []Presence {
	live := n.sess.LiveIPs()
	counts := n.sess.OnlineCounts()
	ids := map[string]struct{}{}
	for id := range live {
		ids[id] = struct{}{}
	}
	for id := range counts {
		ids[id] = struct{}{}
	}
	out := make([]Presence, 0, len(ids))
	now := time.Now().UTC()
	for id := range ids {
		row := Presence{UserID: id, Online: counts[id] > 0}
		for _, ip := range live[id] {
			row.IPs = append(row.IPs, PresenceIP{IP: ip, SeenAt: now})
			row.Online = true
		}
		out = append(out, row)
	}
	return out
}

func (n *Native) TakeSnapshots() []Snapshot {
	m := n.quota.Snapshot()
	out := make([]Snapshot, 0, len(m))
	for id, b := range m {
		out = append(out, Snapshot{UserID: id, Bytes: b})
	}
	return out
}

func (n *Native) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		go n.handle(conn)
	}
}

func (n *Native) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 || !strings.EqualFold(parts[0], "AUTH") {
		_, _ = conn.Write([]byte("ERR auth\n"))
		return
	}
	uuid, pass := parts[1], parts[2]
	n.mu.Lock()
	userID := n.byUUID[uuid]
	user, ok := n.users[userID]
	n.mu.Unlock()
	if !ok || !userLive(user) || (user.Password != "" && user.Password != pass && user.UUID != pass) {
		_, _ = conn.Write([]byte("ERR forbidden\n"))
		return
	}
	ip := connClientIP(conn)
	if !nodeExec.ips.hold(user.ID, ip, user.DeviceLimit) {
		_, _ = conn.Write([]byte("ERR ips\n"))
		return
	}
	defer nodeExec.ips.release(user.ID, ip)
	sessID := fmt.Sprintf("%s-%d", user.ID, time.Now().UnixNano())
	n.sess.Add(&sessions.Session{ID: sessID, UserID: user.ID, Conn: conn})
	defer n.sess.Remove(sessID)
	_, _ = conn.Write([]byte("OK\n"))
	_ = conn.SetDeadline(time.Time{})
	buf := make([]byte, 32*1024)
	for {
		nr, err := r.Read(buf)
		if nr > 0 {
			if !n.limit.Allow(user.ID, nr) {
				return
			}
			if _, _, ok := n.quota.Add(user.ID, int64(nr)); !ok {
				return
			}
			if _, werr := conn.Write(buf[:nr]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}
