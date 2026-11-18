package coreadapter

import (
	"net"
	"strings"
	"sync"
	"time"
)

type ipBucket struct {
	counts map[string]int
}

// ipGuard counts concurrent unique client IPs per user. DeviceLimit on UserSpec
// is that live cap (0 = unlimited). Extra connections from an IP already held
// do not consume another slot. IPs are released when the last session from
// that address closes; historical addresses do not count.
type ipGuard struct {
	mu   sync.Mutex
	live map[string]*ipBucket
}

func newIPGuard() *ipGuard {
	return &ipGuard{live: map[string]*ipBucket{}}
}

func normalizeClientIP(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func connClientIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return normalizeClientIP(conn.RemoteAddr().String())
}

func (g *ipGuard) acquire(userID, ip string, limit int) (func(), bool) {
	ip = normalizeClientIP(ip)
	if userID == "" || ip == "" {
		if limit <= 0 {
			return func() {}, true
		}
		return nil, false
	}
	g.mu.Lock()
	bucket := g.live[userID]
	if bucket == nil {
		bucket = &ipBucket{counts: map[string]int{}}
		g.live[userID] = bucket
	}
	if bucket.counts[ip] > 0 {
		bucket.counts[ip]++
	} else {
		if limit > 0 && len(bucket.counts) >= limit {
			if len(bucket.counts) == 0 {
				delete(g.live, userID)
			}
			g.mu.Unlock()
			return nil, false
		}
		bucket.counts[ip] = 1
	}
	myBucket := bucket
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			n := myBucket.counts[ip]
			if n <= 1 {
				delete(myBucket.counts, ip)
				if len(myBucket.counts) == 0 && g.live[userID] == myBucket {
					delete(g.live, userID)
				}
				return
			}
			myBucket.counts[ip] = n - 1
		})
	}, true
}

func (g *ipGuard) clear(userID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.live, userID)
}

func (g *ipGuard) liveIPs() map[string][]string {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string][]string{}
	for userID, bucket := range g.live {
		if bucket == nil {
			continue
		}
		for ip, n := range bucket.counts {
			if n <= 0 || ip == "" {
				continue
			}
			out[userID] = append(out[userID], ip)
		}
	}
	return out
}

func ClearUserIPs(userID string) {
	userID = strings.TrimSpace(userID)
	if userID == "" || nodeExec == nil || nodeExec.ips == nil {
		return
	}
	nodeExec.ips.clear(userID)
}

func (p *policyEngine) clearUserIPs(userID string) {
	userID = strings.TrimSpace(userID)
	if userID == "" || p == nil {
		return
	}
	if p.ips != nil {
		p.ips.clear(userID)
	}
	now := time.Now().UTC()
	p.mu.Lock()
	delete(p.seen, userID)
	if p.clearedAt == nil {
		p.clearedAt = map[string]time.Time{}
	}
	p.clearedAt[userID] = now
	p.mu.Unlock()
}

func (p *policyEngine) ipClearedAt(userID string) time.Time {
	if p == nil || userID == "" {
		return time.Time{}
	}
	p.mu.Lock()
	at := p.clearedAt[userID]
	p.mu.Unlock()
	return at
}

func (p *policyEngine) acquireIP(userID, ip string, limit int) (func(), bool) {
	return p.ips.acquire(userID, ip, limit)
}

func (p *policyEngine) ipLimit(userID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.users {
		if u.ID == userID {
			return u.DeviceLimit
		}
	}
	return 0
}

func (p *policyEngine) setSkipCoreIP(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.skipCoreIP = map[string]struct{}{}
	for _, tag := range tags {
		if tag != "" {
			p.skipCoreIP[tag] = struct{}{}
		}
	}
}

func (p *policyEngine) skipCoreIPTag(tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.skipCoreIP[tag]
	return ok
}

func (p *policyEngine) setMeterCore(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.meterCore = map[string]struct{}{}
	for _, tag := range tags {
		if tag != "" {
			p.meterCore[tag] = struct{}{}
		}
	}
}

func (p *policyEngine) meterCoreTag(tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.meterCore[tag]
	return ok
}

func (p *policyEngine) accountLinkBytes(userID string, n int) bool {
	return p.accountLinkBytesContext(userID, n, nil)
}

func (p *policyEngine) accountLinkBytesContext(userID string, n int, stop <-chan struct{}) bool {
	if n <= 0 {
		return true
	}
	if p.userBlocked(userID) {
		return false
	}
	if p.quota.Room(userID) == 0 {
		p.deny(userID)
		return false
	}
	for rem := n; rem > 0; {
		if p.userBlocked(userID) {
			return false
		}
		got, ok := p.takeBytes(userID, rem, stop)
		if !ok {
			if stop != nil {
				select {
				case <-stop:
					if p.quota.Room(userID) == 0 {
						p.deny(userID)
					}
					return false
				default:
				}
			}
			if !p.userBlocked(userID) {
				p.deny(userID)
			}
			return false
		}
		rem -= got
	}
	if p.quota.Room(userID) == 0 {
		p.deny(userID)
	}
	return true
}
