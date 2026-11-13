package protection

import (
	"sync"
	"time"
)

type windowCounter struct {
	start time.Time
	count int
}

type Counter struct {
	mu      sync.Mutex
	windows map[string]windowCounter
	maxKeys int
}

func NewCounter(maxKeys int) *Counter {
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &Counter{windows: map[string]windowCounter{}, maxKeys: maxKeys}
}

func (c *Counter) Add(key string, at time.Time, window time.Duration) int {
	if key == "" || window <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, ok := c.windows[key]
	if !ok || at.Before(cur.start) || !at.Before(cur.start.Add(window)) {
		if !ok && len(c.windows) >= c.maxKeys {
			c.evictLocked(at, window)
			if len(c.windows) >= c.maxKeys {
				return 0
			}
		}
		c.windows[key] = windowCounter{start: at, count: 1}
		return 1
	}
	cur.count++
	c.windows[key] = cur
	return cur.count
}

func (c *Counter) Reset(key string) {
	c.mu.Lock()
	delete(c.windows, key)
	c.mu.Unlock()
}

func (c *Counter) ResetPrefix(prefix string) {
	c.mu.Lock()
	for key := range c.windows {
		if stringsHasPrefix(key, prefix) {
			delete(c.windows, key)
		}
	}
	c.mu.Unlock()
}

func (c *Counter) evictLocked(now time.Time, window time.Duration) {
	for key, cur := range c.windows {
		if !now.Before(cur.start.Add(window)) {
			delete(c.windows, key)
		}
	}
}

func stringsHasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
