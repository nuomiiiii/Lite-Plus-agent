package limiter

import (
	"sync"
	"time"
)

type Bucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

type Set struct {
	mu   sync.Mutex
	rate map[string]*Bucket
}

func New() *Set { return &Set{rate: map[string]*Bucket{}} }

// Configure sets a per-user token bucket. bps is bits per second from the
// panel; the limiter consumes payload bytes, so the bucket rate is bps/8.
func (s *Set) Configure(userID string, bps int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bytesPerSec := bps / 8
	if bytesPerSec <= 0 {
		delete(s.rate, userID)
		return
	}
	s.rate[userID] = &Bucket{rate: float64(bytesPerSec), burst: float64(bytesPerSec), tokens: float64(bytesPerSec), last: time.Now()}
}

func (s *Set) Allow(userID string, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.rate[userID]
	if b == nil {
		return true
	}
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	need := float64(n)
	if b.tokens < need {
		return false
	}
	b.tokens -= need
	return true
}

func (s *Set) Wait(userID string, n int, stop <-chan struct{}) int {
	if n <= 0 {
		return 0
	}
	s.mu.Lock()
	b := s.rate[userID]
	if b == nil {
		s.mu.Unlock()
		return n
	}
	for {
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed < 0 {
			elapsed = 0
		}
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
		if b.tokens >= 1 {
			take := float64(n)
			if take > b.tokens {
				take = b.tokens
			}
			got := int(take)
			if got < 1 {
				got = 1
			}
			if got > n {
				got = n
			}
			b.tokens -= float64(got)
			if b.tokens < 0 {
				b.tokens = 0
			}
			s.mu.Unlock()
			return got
		}
		wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		if wait > 50*time.Millisecond {
			wait = 50 * time.Millisecond
		}
		s.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-stop:
			timer.Stop()
			return 0
		case <-timer.C:
		}
		s.mu.Lock()
		b = s.rate[userID]
		if b == nil {
			s.mu.Unlock()
			return n
		}
	}
}
