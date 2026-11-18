package monitoring

import (
	"sync"
	"time"
)

const (
	completePublicIPTTL   = 2 * time.Minute
	incompletePublicIPTTL = 30 * time.Second
	nicIPCacheTTL         = 30 * time.Second
)

type ttlCache[T any] struct {
	mu  sync.Mutex
	at  time.Time
	val T
	err error
	ok  bool
	key string
}

func (c *ttlCache[T]) get(ttl time.Duration, load func() T) T {
	val, _ := c.getErr(ttl, "", func() (T, error) {
		return load(), nil
	})
	return val
}

func (c *ttlCache[T]) getErr(ttl time.Duration, key string, load func() (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ok && c.key == key && (ttl <= 0 || time.Since(c.at) < ttl) {
		return c.val, c.err
	}
	c.val, c.err = load()
	c.at = time.Now()
	c.key = key
	c.ok = true
	return c.val, c.err
}

func (c *ttlCache[T]) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero T
	c.val = zero
	c.err = nil
	c.ok = false
	c.key = ""
	c.at = time.Time{}
}
