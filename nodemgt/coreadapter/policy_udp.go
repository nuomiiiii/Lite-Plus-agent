package coreadapter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func udpHopsOK(hops []egressHop) bool {
	if len(hops) == 0 {
		return true
	}
	if len(hops) != 1 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(hops[0].Protocol)) {
	case "", "socks":
		return hops[0].Addr != ""
	default:
		return false
	}
}

func handlePolicyExitUDP(front *spliceFront, client net.Conn, policy *policyEngine, spec UserSpec, hops []egressHop) {
	if !udpHopsOK(hops) {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var hopTCP net.Conn
	var relay net.Addr
	if len(hops) == 1 {
		var err error
		hopTCP, err = net.DialTimeout("tcp", hops[0].Addr, 2*time.Second)
		if err != nil {
			_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		setTCPNoDelay(hopTCP)
		front.track(hopTCP)
		defer front.drop(hopTCP)
		defer hopTCP.Close()
		_ = hopTCP.SetDeadline(time.Now().Add(3 * time.Second))
		relay, err = socks5ClientUDPAssociate(hopTCP, hops[0].User, hops[0].Pass)
		if err != nil {
			_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		_ = hopTCP.SetDeadline(time.Time{})
	}
	clientPC, err := listenClientUDP(client)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	wan, err := listenWANUDP()
	if err != nil {
		_ = clientPC.Close()
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	clientWrap := packetConnCloser{clientPC}
	front.track(clientWrap)
	defer front.drop(clientWrap)
	defer clientPC.Close()
	for _, pc := range wan.conns() {
		wrap := packetConnCloser{pc}
		front.track(wrap)
		defer front.drop(wrap)
	}
	defer wan.Close()
	if relay != nil {
		relay = rewriteUDPBind(relay, hopTCP)
	}
	reply, err := socks5UDPBindReply(clientPC.LocalAddr())
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := client.Write(reply); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(func() { close(stop) }) }
	defer stopFn()
	go func() {
		defer stopFn()
		_, _ = io.Copy(io.Discard, client)
	}()
	pkts := make(chan policyUDPPkt, 16)
	go readPolicyUDP(clientPC, false, pkts, stop)
	for _, pc := range wan.conns() {
		go readPolicyUDP(pc, true, pkts, stop)
	}
	var clientAddr net.Addr
	for {
		select {
		case <-stop:
			return
		case pkt, ok := <-pkts:
			if !ok {
				return
			}
			if pkt.wan {
				if relay != nil && addrEqual(pkt.from, relay) {
					if clientAddr == nil {
						continue
					}
					if _, payload, err := parseSocksUDP(pkt.data); err == nil {
						if !accountPolicyUDP(policy, spec.ID, len(payload), stop) {
							return
						}
					}
					if _, err := clientPC.WriteTo(pkt.data, clientAddr); err != nil {
						return
					}
					continue
				}
				if clientAddr == nil {
					continue
				}
				if !accountPolicyUDP(policy, spec.ID, len(pkt.data), stop) {
					return
				}
				wrapped, err := encodeSocksUDP(pkt.from.String(), pkt.data)
				if err != nil {
					continue
				}
				if _, err := clientPC.WriteTo(wrapped, clientAddr); err != nil {
					return
				}
				continue
			}
			dest, payload, err := parseSocksUDP(pkt.data)
			if err != nil {
				continue
			}
			clientAddr = pkt.from
			if !accountPolicyUDP(policy, spec.ID, len(payload), stop) {
				return
			}
			if relay != nil {
				if _, err := wan.WriteTo(pkt.data, relay); err != nil {
					return
				}
				continue
			}
			raddr, err := resolveUDPAddrWithStack(dest, policy.currentDialStack())
			if err != nil {
				continue
			}
			if _, err := wan.WriteTo(payload, raddr); err != nil {
				continue
			}
		}
	}
}

type policyUDPPkt struct {
	from net.Addr
	data []byte
	wan  bool
}

func readPolicyUDP(pc net.PacketConn, wan bool, out chan<- policyUDPPkt, stop <-chan struct{}) {
	buf := make([]byte, 64*1024)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
		select {
		case <-stop:
			return
		default:
		}
		if n == 0 {
			continue
		}
		pkt := policyUDPPkt{from: from, data: append([]byte(nil), buf[:n]...), wan: wan}
		select {
		case <-stop:
			return
		case out <- pkt:
		}
	}
}

func listenClientUDP(client net.Conn) (net.PacketConn, error) {
	host := udpBindHostForClient(client)
	network := "udp"
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	return net.ListenPacket(network, net.JoinHostPort(host, "0"))
}

type wanUDP struct {
	v4 net.PacketConn
	v6 net.PacketConn
}

func listenWANUDP() (*wanUDP, error) {
	w := &wanUDP{}
	w.v4, _ = net.ListenPacket("udp4", "0.0.0.0:0")
	w.v6, _ = net.ListenPacket("udp6", "[::]:0")
	if w.v4 == nil && w.v6 == nil {
		return nil, fmt.Errorf("wan udp")
	}
	return w, nil
}

func (w *wanUDP) conns() []net.PacketConn {
	if w == nil {
		return nil
	}
	out := make([]net.PacketConn, 0, 2)
	if w.v4 != nil {
		out = append(out, w.v4)
	}
	if w.v6 != nil {
		out = append(out, w.v6)
	}
	return out
}

func (w *wanUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	pc := w.connFor(addr)
	if pc == nil {
		return 0, fmt.Errorf("wan udp family")
	}
	return pc.WriteTo(p, addr)
}

func (w *wanUDP) Close() error {
	if w == nil {
		return nil
	}
	var err error
	if w.v4 != nil {
		err = w.v4.Close()
	}
	if w.v6 != nil {
		if e := w.v6.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (w *wanUDP) connFor(addr net.Addr) net.PacketConn {
	if w == nil {
		return nil
	}
	ua, err := udpAddrOf(addr)
	if err != nil || ua == nil || ua.IP == nil {
		return w.v4
	}
	if ua.IP.To4() == nil {
		return w.v6
	}
	return w.v4
}

func rewriteUDPBind(bind net.Addr, hop net.Conn) net.Addr {
	ua, err := udpAddrOf(bind)
	if err != nil || ua == nil {
		return bind
	}
	if ua.IP != nil && !ua.IP.IsUnspecified() {
		return ua
	}
	host := "127.0.0.1"
	if hop != nil && hop.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(hop.RemoteAddr().String()); err == nil {
			if ip := net.ParseIP(h); ip != nil && !ip.IsUnspecified() {
				host = h
			}
		}
	}
	return &net.UDPAddr{IP: net.ParseIP(host), Port: ua.Port}
}

func udpBindHostForClient(client net.Conn) string {
	if client == nil || client.LocalAddr() == nil {
		return "127.0.0.1"
	}
	host, _, err := net.SplitHostPort(client.LocalAddr().String())
	if err != nil {
		return "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return "127.0.0.1"
	}
	return host
}

func accountPolicyUDP(policy *policyEngine, userID string, n int, stop <-chan struct{}) bool {
	if n <= 0 {
		return true
	}
	got, ok := policy.takeBytes(userID, n, stop)
	return ok && got > 0
}

func parseSocksUDP(pkt []byte) (string, []byte, error) {
	if len(pkt) < 7 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		return "", nil, fmt.Errorf("socks udp")
	}
	dest, addrLen, err := socks5AddrDest(pkt[3:])
	if err != nil {
		return "", nil, err
	}
	if 3+addrLen > len(pkt) {
		return "", nil, fmt.Errorf("socks udp trunc")
	}
	return dest, pkt[3+addrLen:], nil
}

func encodeSocksUDP(dest string, payload []byte) ([]byte, error) {
	addr, err := socks5Addr(dest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(addr)+len(payload))
	out = append(out, 0, 0, 0)
	out = append(out, addr...)
	return append(out, payload...), nil
}

func socks5AddrDest(addr []byte) (string, int, error) {
	if len(addr) < 3 {
		return "", 0, fmt.Errorf("socks atyp")
	}
	switch addr[0] {
	case 0x01:
		if len(addr) < 7 {
			return "", 0, fmt.Errorf("socks ipv4")
		}
		host := net.IP(addr[1:5]).String()
		port := binary.BigEndian.Uint16(addr[5:7])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), 7, nil
	case 0x04:
		if len(addr) < 19 {
			return "", 0, fmt.Errorf("socks ipv6")
		}
		host := net.IP(addr[1:17]).String()
		port := binary.BigEndian.Uint16(addr[17:19])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), 19, nil
	case 0x03:
		n := int(addr[1])
		if len(addr) < 4+n {
			return "", 0, fmt.Errorf("socks domain")
		}
		host := string(addr[2 : 2+n])
		port := binary.BigEndian.Uint16(addr[2+n : 4+n])
		return net.JoinHostPort(host, strconv.Itoa(int(port))), 4 + n, nil
	default:
		return "", 0, fmt.Errorf("socks atyp")
	}
}

func socks5UDPBindReply(addr net.Addr) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks bind")
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		return append(append([]byte{0x05, 0x00, 0x00, 0x01}, v4...), pb...), nil
	}
	if ip != nil {
		return append(append([]byte{0x05, 0x00, 0x00, 0x04}, ip.To16()...), pb...), nil
	}
	return nil, fmt.Errorf("socks bind host")
}

func setTCPNoDelay(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
}

func socks5ClientUDPAssociate(conn net.Conn, user, pass string) (net.Addr, error) {
	setTCPNoDelay(conn)
	if user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return nil, err
		}
	} else if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return nil, err
	}
	if method[0] != 0x05 {
		return nil, fmt.Errorf("socks ver")
	}
	switch method[1] {
	case 0x00:
	case 0x02:
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		auth := make([]byte, 2)
		if _, err := io.ReadFull(conn, auth); err != nil {
			return nil, err
		}
		if auth[1] != 0 {
			return nil, fmt.Errorf("socks auth")
		}
	default:
		return nil, fmt.Errorf("socks method")
	}
	req, err := socks5CommandRequest(0x03, "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	return socks5ReadBindAddr(conn)
}

func socks5ReadBindAddr(r io.Reader) (net.Addr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0 {
		return nil, fmt.Errorf("socks reply")
	}
	rest, err := readSOCKS5AddrTail(r, head[3])
	if err != nil {
		return nil, err
	}
	dest, _, err := socks5AddrDest(append([]byte{head[3]}, rest...))
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", dest)
}

func readSOCKS5AddrTail(r io.Reader, atyp byte) ([]byte, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 6)
		_, err := io.ReadFull(r, buf)
		return buf, err
	case 0x04:
		buf := make([]byte, 18)
		_, err := io.ReadFull(r, buf)
		return buf, err
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return nil, err
		}
		rest := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		return append(n, rest...), nil
	default:
		return nil, fmt.Errorf("socks atyp")
	}
}

func addrEqual(a, b net.Addr) bool {
	if a == nil || b == nil {
		return false
	}
	ua, err := udpAddrOf(a)
	if err != nil {
		return a.String() == b.String()
	}
	ub, err := udpAddrOf(b)
	if err != nil {
		return a.String() == b.String()
	}
	return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
}

func udpAddrOf(addr net.Addr) (*net.UDPAddr, error) {
	if u, ok := addr.(*net.UDPAddr); ok && u != nil {
		return u, nil
	}
	return net.ResolveUDPAddr("udp", addr.String())
}

type packetConnCloser struct {
	net.PacketConn
}

func (c packetConnCloser) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func (c packetConnCloser) Write(p []byte) (int, error) {
	return 0, net.ErrClosed
}

func (c packetConnCloser) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c packetConnCloser) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c packetConnCloser) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

func (c packetConnCloser) RemoteAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

var _ net.Conn = packetConnCloser{}
