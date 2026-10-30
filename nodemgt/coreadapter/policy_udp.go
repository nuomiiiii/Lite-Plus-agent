package coreadapter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	wrap := packetConnCloser{pc}
	front.track(wrap)
	defer front.drop(wrap)
	defer pc.Close()
	reply, err := socks5UDPBindReply(pc.LocalAddr())
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := client.Write(reply); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		_, _ = io.Copy(io.Discard, client)
	}()
	buf := make([]byte, 64*1024)
	var clientAddr net.Addr
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
		pkt := append([]byte(nil), buf[:n]...)
		if relay != nil && addrEqual(from, relay) {
			if clientAddr == nil {
				continue
			}
			if _, payload, err := parseSocksUDP(pkt); err == nil {
				if !accountPolicyUDP(policy, spec.ID, len(payload), stop) {
					return
				}
			}
			if _, err := pc.WriteTo(pkt, clientAddr); err != nil {
				return
			}
			continue
		}
		if dest, payload, err := parseSocksUDP(pkt); err == nil {
			clientAddr = from
			if !accountPolicyUDP(policy, spec.ID, len(payload), stop) {
				return
			}
			if relay != nil {
				if _, err := pc.WriteTo(pkt, relay); err != nil {
					return
				}
				continue
			}
			raddr, err := net.ResolveUDPAddr("udp", dest)
			if err != nil {
				continue
			}
			if _, err := pc.WriteTo(payload, raddr); err != nil {
				return
			}
			continue
		}
		if clientAddr == nil {
			continue
		}
		if !accountPolicyUDP(policy, spec.ID, n, stop) {
			return
		}
		wrapped, err := encodeSocksUDP(from.String(), pkt)
		if err != nil {
			continue
		}
		if _, err := pc.WriteTo(wrapped, clientAddr); err != nil {
			return
		}
	}
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
