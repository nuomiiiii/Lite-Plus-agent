package coreadapter

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ common.WithUpstream = (*ipLimitConn)(nil)
	_ common.WithUpstream = (*ipLimitPacketConn)(nil)
)

type ipLimitTracker struct {
	policy *policyEngine
}

func newIPLimitTracker(policy *policyEngine) *ipLimitTracker {
	return &ipLimitTracker{policy: policy}
}

func (t *ipLimitTracker) holdMeta(metadata adapter.InboundContext, closer io.Closer) (func(), bool) {
	if strings.HasPrefix(metadata.Inbound, "nodemgt-core-") || t.policy.skipCoreIPTag(metadata.Inbound) || t.policy.isLoopUser(metadata.User) {
		return nil, true
	}
	userID := t.policy.mapStatName(metadata.User)
	if userID != "" && t.policy.userBlocked(userID) {
		return nil, false
	}
	if userID == "" {
		return nil, true
	}
	ip := ""
	if metadata.Source.Addr.IsValid() {
		ip = metadata.Source.Addr.String()
	}
	limit := t.policy.ipLimit(userID)
	releaseIP, ok := t.policy.acquireIP(userID, ip, limit)
	if !ok {
		return nil, false
	}
	untrackSess := t.policy.sess.Track(userID, closer)
	untrackCore := t.policy.trackCoreConn(userID, closer)
	var once sync.Once
	return func() {
		once.Do(func() {
			if releaseIP != nil {
				releaseIP()
			}
			untrackSess()
			untrackCore()
		})
	}, true
}

func (t *ipLimitTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	release, ok := t.holdMeta(metadata, conn)
	if !ok {
		_ = conn.Close()
		return deniedConn{Conn: conn}
	}
	if release == nil {
		return conn
	}
	return &ipLimitConn{Conn: conn, release: release}
}

func (t *ipLimitTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	release, ok := t.holdMeta(metadata, conn)
	if !ok {
		_ = conn.Close()
		return deniedPacketConn{PacketConn: conn}
	}
	if release == nil {
		return conn
	}
	return &ipLimitPacketConn{PacketConn: conn, release: release}
}

func (t *ipLimitTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

type ipLimitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *ipLimitConn) Close() error {
	if c.release != nil {
		c.once.Do(c.release)
	}
	return c.Conn.Close()
}

func (c *ipLimitConn) Upstream() any {
	return c.Conn
}

func (c *ipLimitConn) ReaderReplaceable() bool { return true }
func (c *ipLimitConn) WriterReplaceable() bool { return true }

type ipLimitPacketConn struct {
	N.PacketConn
	once    sync.Once
	release func()
}

func (c *ipLimitPacketConn) Close() error {
	if c.release != nil {
		c.once.Do(c.release)
	}
	return c.PacketConn.Close()
}

func (c *ipLimitPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *ipLimitPacketConn) ReaderReplaceable() bool { return true }
func (c *ipLimitPacketConn) WriterReplaceable() bool { return true }

type deniedConn struct {
	net.Conn
}

func (deniedConn) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (deniedConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

type deniedPacketConn struct {
	N.PacketConn
}

func (deniedPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (deniedPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	if buffer != nil {
		buffer.Release()
	}
	return net.ErrClosed
}
