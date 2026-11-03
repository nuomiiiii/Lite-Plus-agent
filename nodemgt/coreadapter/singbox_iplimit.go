package coreadapter

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// errQuotaExceeded mirrors the xray core path: once a metered user runs out of
// quota the core-owned connection is aborted instead of silently unmetered.
var errQuotaExceeded = errors.New("quota exceeded")

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

func (t *ipLimitTracker) holdMeta(metadata adapter.InboundContext) (func(), bool) {
	if t.policy.skipCoreIPTag(metadata.Inbound) {
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
	if !t.policy.holdIP(userID, ip, limit) {
		return nil, false
	}
	if normalizeClientIP(ip) == "" {
		return nil, true
	}
	var once sync.Once
	return func() { once.Do(func() { t.policy.releaseIP(userID, ip) }) }, true
}

// meteredUser returns the user ID this routed connection should be charged to.
// Core-owned inbounds (Hysteria2/TUIC/Shadowsocks and other protocols that
// authenticate inside sing-box without a policy front) have no other byte
// accounting path, so their traffic is metered here.
func (t *ipLimitTracker) meteredUser(metadata adapter.InboundContext) string {
	if !t.policy.meterCoreTag(metadata.Inbound) {
		return ""
	}
	return t.policy.meterUser(metadata.User)
}

func (t *ipLimitTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	release, ok := t.holdMeta(metadata)
	if !ok {
		_ = conn.Close()
		return conn
	}
	userID := t.meteredUser(metadata)
	if release == nil && userID == "" {
		return conn
	}
	return &ipLimitConn{Conn: conn, release: release, policy: t.policy, userID: userID}
}

func (t *ipLimitTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	release, ok := t.holdMeta(metadata)
	if !ok {
		_ = conn.Close()
		return conn
	}
	userID := t.meteredUser(metadata)
	if release == nil && userID == "" {
		return conn
	}
	return &ipLimitPacketConn{PacketConn: conn, release: release, policy: t.policy, userID: userID}
}

func (t *ipLimitTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

type ipLimitConn struct {
	net.Conn
	once    sync.Once
	release func()
	policy  *policyEngine
	userID  string
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

func (c *ipLimitConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.userID != "" && !c.policy.accountLinkBytes(c.userID, n) {
		_ = c.Conn.Close()
		return 0, io.EOF
	}
	return n, err
}

func (c *ipLimitConn) Write(p []byte) (int, error) {
	if len(p) > 0 && c.userID != "" && !c.policy.accountLinkBytes(c.userID, len(p)) {
		_ = c.Conn.Close()
		return 0, errQuotaExceeded
	}
	return c.Conn.Write(p)
}

func (c *ipLimitConn) ReaderReplaceable() bool { return c.userID == "" }
func (c *ipLimitConn) WriterReplaceable() bool { return c.userID == "" }

type ipLimitPacketConn struct {
	N.PacketConn
	once    sync.Once
	release func()
	policy  *policyEngine
	userID  string
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

func (c *ipLimitPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err == nil && buffer != nil && c.userID != "" {
		if n := buffer.Len(); n > 0 && !c.policy.accountLinkBytes(c.userID, n) {
			return destination, io.EOF
		}
	}
	return destination, err
}

func (c *ipLimitPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if buffer != nil && c.userID != "" {
		if n := buffer.Len(); n > 0 && !c.policy.accountLinkBytes(c.userID, n) {
			return errQuotaExceeded
		}
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *ipLimitPacketConn) ReaderReplaceable() bool { return c.userID == "" }
func (c *ipLimitPacketConn) WriterReplaceable() bool { return c.userID == "" }
