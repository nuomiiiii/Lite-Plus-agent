package sessions

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var nextTrackedSessionID atomic.Uint64

type Session struct {
	ID     string
	UserID string
	IP     string
	SeenAt time.Time
	Conn   io.Closer
	HideIP bool
}

type Set struct {
	mu   sync.Mutex
	byID map[string]*Session
	byU  map[string]map[string]*Session
}

func New() *Set {
	return &Set{byID: map[string]*Session{}, byU: map[string]map[string]*Session{}}
}

func (s *Set) Add(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.IP == "" && !sess.HideIP && sess.Conn != nil {
		if c, ok := sess.Conn.(interface{ RemoteAddr() net.Addr }); ok && c.RemoteAddr() != nil {
			host, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				sess.IP = c.RemoteAddr().String()
			} else {
				sess.IP = host
			}
		}
	}
	if sess.SeenAt.IsZero() {
		sess.SeenAt = time.Now().UTC()
	}
	s.byID[sess.ID] = sess
	if s.byU[sess.UserID] == nil {
		s.byU[sess.UserID] = map[string]*Session{}
	}
	s.byU[sess.UserID][sess.ID] = sess
}

func (s *Set) Count(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byU[userID])
}

func (s *Set) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byID[id]
	if sess == nil {
		return
	}
	delete(s.byID, id)
	delete(s.byU[sess.UserID], id)
}

func (s *Set) OnlineCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for userID, byID := range s.byU {
		if n := len(byID); n > 0 {
			out[userID] = n
		}
	}
	return out
}

func (s *Set) LiveIPs() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	for userID, byID := range s.byU {
		seen := map[string]struct{}{}
		for _, sess := range byID {
			ip := sess.IP
			if sess.HideIP || ip == "" {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			out[userID] = append(out[userID], ip)
		}
	}
	return out
}

func (s *Set) Track(userID string, closer io.Closer) func() {
	if s == nil || userID == "" || closer == nil {
		return func() {}
	}
	id := fmt.Sprintf("core-%s-%d", userID, nextTrackedSessionID.Add(1))
	s.Add(&Session{ID: id, UserID: userID, Conn: closer, HideIP: true})
	var once sync.Once
	return func() {
		once.Do(func() {
			s.Remove(id)
		})
	}
}

func (s *Set) CloseUser(userID string) {
	s.mu.Lock()
	list := make([]*Session, 0, len(s.byU[userID]))
	for _, sess := range s.byU[userID] {
		list = append(list, sess)
	}
	s.mu.Unlock()
	for _, sess := range list {
		if sess.Conn != nil {
			_ = sess.Conn.Close()
		}
		s.Remove(sess.ID)
	}
}
