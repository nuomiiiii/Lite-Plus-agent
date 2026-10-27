package coreadapter

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

type headroomPacketConn struct {
	N.PacketConn
}

func (headroomPacketConn) FrontHeadroom() int { return 23 }
func (headroomPacketConn) RearHeadroom() int  { return 16 }
func (headroomPacketConn) Close() error       { return nil }

// udpnat.conn: Upstream only, no Replaceable.
type natHop struct{ N.PacketConn }

func (c natHop) Upstream() any { return c.PacketConn }
func (c natHop) Close() error  { return c.PacketConn.Close() }

// canceler.TimeoutPacketConn: same, sits outside Plus wrap on UDP.
type timeoutHop struct{ N.PacketConn }

func (c timeoutHop) Upstream() any { return c.PacketConn }
func (c timeoutHop) Close() error  { return c.PacketConn.Close() }

func TestIPLimitPacketConnReservesSSHeaderRoom(t *testing.T) {
	ss := headroomPacketConn{}
	nat := natHop{PacketConn: ss}
	wrapped := &ipLimitPacketConn{PacketConn: nat}
	outer := timeoutHop{PacketConn: wrapped}
	if got := N.CalculateFrontHeadroom(outer); got != 23 {
		t.Fatalf("front headroom=%d, want 23 (aes-128-gcm salt 16 + ipv4 7)", got)
	}
	if got := N.CalculateRearHeadroom(outer); got != 16 {
		t.Fatalf("rear headroom=%d, want 16 (AEAD tag)", got)
	}
}

func TestIPLimitPacketConnCloseReleasesIPOnce(t *testing.T) {
	n := 0
	c := &ipLimitPacketConn{PacketConn: headroomPacketConn{}, release: func() { n++ }}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("release count=%d", n)
	}
}

func TestIPLimitConnExposesUpstream(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	wrapped := &ipLimitConn{Conn: left}
	u, ok := any(wrapped).(common.WithUpstream)
	if !ok {
		t.Fatal("conn wrap must expose Upstream")
	}
	if u.Upstream() != left {
		t.Fatalf("upstream became %T", u.Upstream())
	}
}
