package coreadapter

import (
	"context"
	"io"
	"math"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// quotaTracker charges core-owned sing-box inbounds that have no policy front
// or SOCKS exit hop. It uses sing's CounterConn so copy/splice still runs and
// still reports bytes. IP limiting stays on ipLimitTracker.
type quotaTracker struct {
	policy *policyEngine
}

func newQuotaTracker(policy *policyEngine) *quotaTracker {
	return &quotaTracker{policy: policy}
}

func (t *quotaTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	userID := t.meterUser(metadata)
	if userID == "" || conn == nil {
		return conn
	}
	untrack := t.policy.trackCoreConn(userID, conn)
	count := quotaCount(t.policy, userID, conn)
	return &quotaCloseConn{Conn: bufio.NewCounterConn(conn, []N.CountFunc{count}, []N.CountFunc{count}), untrack: untrack}
}

func (t *quotaTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	userID := t.meterUser(metadata)
	if userID == "" || conn == nil {
		return conn
	}
	untrack := t.policy.trackCoreConn(userID, conn)
	count := quotaCount(t.policy, userID, conn)
	return &quotaClosePacketConn{PacketConn: bufio.NewCounterPacketConn(conn, []N.CountFunc{count}, []N.CountFunc{count}), untrack: untrack}
}

func (t *quotaTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

func (t *quotaTracker) meterUser(metadata adapter.InboundContext) string {
	if t.policy == nil || !t.policy.meterCoreTag(metadata.Inbound) {
		return ""
	}
	return t.policy.knownUserID(metadata.User)
}

func quotaCount(policy *policyEngine, userID string, closer io.Closer) N.CountFunc {
	var once sync.Once
	return func(n int64) {
		if n <= 0 || policy == nil {
			return
		}
		if n > int64(math.MaxInt) {
			n = int64(math.MaxInt)
		}
		if !policy.accountLinkBytes(userID, int(n)) {
			once.Do(func() {
				if closer != nil {
					_ = closer.Close()
				}
			})
		}
	}
}

type quotaCloseConn struct {
	net.Conn
	untrack func()
	once    sync.Once
}

func (c *quotaCloseConn) Close() error {
	c.once.Do(func() {
		if c.untrack != nil {
			c.untrack()
		}
	})
	return c.Conn.Close()
}

func (c *quotaCloseConn) Upstream() any {
	return c.Conn
}

func (c *quotaCloseConn) ReaderReplaceable() bool { return true }
func (c *quotaCloseConn) WriterReplaceable() bool { return true }

func (c *quotaCloseConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	if counter, ok := c.Conn.(N.ReadCounter); ok {
		return counter.UnwrapReader()
	}
	return c.Conn, nil
}

func (c *quotaCloseConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if counter, ok := c.Conn.(N.WriteCounter); ok {
		return counter.UnwrapWriter()
	}
	return c.Conn, nil
}

type quotaClosePacketConn struct {
	N.PacketConn
	untrack func()
	once    sync.Once
}

func (c *quotaClosePacketConn) Close() error {
	c.once.Do(func() {
		if c.untrack != nil {
			c.untrack()
		}
	})
	return c.PacketConn.Close()
}

func (c *quotaClosePacketConn) Upstream() any {
	return c.PacketConn
}

func (c *quotaClosePacketConn) ReaderReplaceable() bool { return true }
func (c *quotaClosePacketConn) WriterReplaceable() bool { return true }

func (c *quotaClosePacketConn) UnwrapPacketReader() (N.PacketReader, []N.CountFunc) {
	if counter, ok := c.PacketConn.(N.PacketReadCounter); ok {
		return counter.UnwrapPacketReader()
	}
	return c.PacketConn, nil
}

func (c *quotaClosePacketConn) UnwrapPacketWriter() (N.PacketWriter, []N.CountFunc) {
	if counter, ok := c.PacketConn.(N.PacketWriteCounter); ok {
		return counter.UnwrapPacketWriter()
	}
	return c.PacketConn, nil
}
