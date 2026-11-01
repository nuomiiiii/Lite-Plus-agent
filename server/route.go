package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/ws"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const routeHopTimeout = 900 * time.Millisecond

var routeProbeMu sync.Mutex
var routeProbeImplementation = traceRouteICMP

func NewRouteTask(conn *ws.SafeConn, task v2.RouteParams) {
	if task.TaskID == 0 || strings.TrimSpace(task.Target) == "" {
		return
	}
	if task.MaxHops < 1 || task.MaxHops > 64 {
		task.MaxHops = 30
	}
	if task.IPVersion != 4 && task.IPVersion != 6 {
		task.IPVersion = 4
	}
	routeProbeMu.Lock()
	hops, err := runRouteProbe(task.Target, task.IPVersion, task.MaxHops)
	routeProbeMu.Unlock()
	finishedAt := time.Now()
	errText := ""
	if err != nil {
		errText = err.Error()
		log.Printf("Return route task %d failed: %v", task.TaskID, err)
	}
	payload := v2.BuildRouteResultPayload(task, hops, errText, finishedAt, routeResolvedTarget(task.Target, task.IPVersion, hops), routeTargetReached(hops, task.Target, task.IPVersion))
	reportV2Result(conn, payload, "Failed to upload return route result")
}

func runRouteProbe(target string, version, maxHops int) (hops []v2.RouteHop, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			hops = nil
			err = fmt.Errorf("built-in route probe failed unexpectedly: %v", recovered)
		}
	}()
	return routeProbeImplementation(target, version, maxHops)
}

func resolveRouteTarget(target string, version int) (net.IP, error) {
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		if (version == 4 && ip.To4() != nil) || (version == 6 && ip.To4() == nil) {
			return ip, nil
		}
		return nil, fmt.Errorf("target does not have the requested IPv%d address", version)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	for _, ip := range addresses {
		if (version == 4 && ip.To4() != nil) || (version == 6 && ip.To4() == nil) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("target does not have the requested IPv%d address", version)
}

func traceRouteICMP(target string, version, maxHops int) ([]v2.RouteHop, error) {
	destination, err := resolveRouteTarget(target, version)
	if err != nil {
		return nil, err
	}
	if version == 6 {
		return traceRouteICMPv6(destination, maxHops)
	}
	return traceRouteICMPv4(destination, maxHops)
}

func traceRouteICMPv4(destination net.IP, maxHops int) ([]v2.RouteHop, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open built-in ICMP route probe (root/CAP_NET_RAW may be required): %w", err)
	}
	defer conn.Close()
	packet := conn.IPv4PacketConn()
	if packet == nil {
		return nil, fmt.Errorf("open built-in IPv4 route probe: packet connection is unavailable")
	}
	hops := make([]v2.RouteHop, 0, maxHops)
	id := os.Getpid() & 0xffff
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := packet.SetTTL(ttl); err != nil {
			return hops, fmt.Errorf("set IPv4 TTL: %w", err)
		}
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("lite-route")}}
		payload, err := message.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		deadline := start.Add(routeHopTimeout)
		_ = conn.SetWriteDeadline(deadline)
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: destination}); err != nil {
			return hops, fmt.Errorf("send IPv4 route probe: %w", err)
		}
		peer, reached, err := waitIPv4RouteReply(conn, destination, id, ttl, deadline)
		if err != nil {
			return hops, fmt.Errorf("read IPv4 route probe: %w", err)
		}
		if peer == nil {
			hops = append(hops, v2.RouteHop{TTL: ttl, Timeout: true})
			continue
		}
		ip := routePeerIP(peer)
		hops = append(hops, v2.RouteHop{TTL: ttl, IP: ip, LatencyMS: float64(time.Since(start).Microseconds()) / 1000})
		if reached {
			break
		}
	}
	return hops, nil
}

func traceRouteICMPv6(destination net.IP, maxHops int) ([]v2.RouteHop, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open built-in IPv6 ICMP route probe (root/CAP_NET_RAW may be required): %w", err)
	}
	defer conn.Close()
	packet := conn.IPv6PacketConn()
	if packet == nil {
		return nil, fmt.Errorf("open built-in IPv6 route probe: packet connection is unavailable")
	}
	hops := make([]v2.RouteHop, 0, maxHops)
	id := os.Getpid() & 0xffff
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := packet.SetHopLimit(ttl); err != nil {
			return hops, fmt.Errorf("set IPv6 hop limit: %w", err)
		}
		message := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("lite-route")}}
		payload, err := message.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		deadline := start.Add(routeHopTimeout)
		_ = conn.SetWriteDeadline(deadline)
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: destination}); err != nil {
			return hops, fmt.Errorf("send IPv6 route probe: %w", err)
		}
		peer, reached, err := waitIPv6RouteReply(conn, destination, id, ttl, deadline)
		if err != nil {
			return hops, fmt.Errorf("read IPv6 route probe: %w", err)
		}
		if peer == nil {
			hops = append(hops, v2.RouteHop{TTL: ttl, Timeout: true})
			continue
		}
		ip := routePeerIP(peer)
		hops = append(hops, v2.RouteHop{TTL: ttl, IP: ip, LatencyMS: float64(time.Since(start).Microseconds()) / 1000})
		if reached {
			break
		}
	}
	return hops, nil
}

func routePeerIP(addr net.Addr) string {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP.String()
	case *net.UDPAddr:
		return value.IP.String()
	default:
		return strings.Split(addr.String(), "%")[0]
	}
}

func routeResolvedTarget(target string, version int, _ []v2.RouteHop) string {
	dest, err := resolveRouteTarget(target, version)
	if err != nil || dest == nil {
		return ""
	}
	return dest.String()
}

func routeTargetReached(hops []v2.RouteHop, target string, version int) bool {
	dest, err := resolveRouteTarget(target, version)
	if err != nil || dest == nil {
		return false
	}
	for _, hop := range hops {
		if hop.Timeout {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(hop.IP)); ip != nil && ip.Equal(dest) {
			return true
		}
	}
	return false
}

func waitIPv4RouteReply(conn *icmp.PacketConn, dest net.IP, id, seq int, deadline time.Time) (net.Addr, bool, error) {
	return waitICMPRouteReply(conn, dest, id, seq, deadline, matchIPv4RouteReply)
}

func waitIPv6RouteReply(conn *icmp.PacketConn, dest net.IP, id, seq int, deadline time.Time) (net.Addr, bool, error) {
	return waitICMPRouteReply(conn, dest, id, seq, deadline, matchIPv6RouteReply)
}

func waitICMPRouteReply(
	conn *icmp.PacketConn,
	dest net.IP,
	id, seq int,
	deadline time.Time,
	match func(payload []byte, peer string, dest net.IP, id, seq int) (bool, bool),
) (net.Addr, bool, error) {
	buffer := make([]byte, 1500)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, false, nil
		}
		_ = conn.SetReadDeadline(time.Now().Add(remain))
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return nil, false, nil
			}
			return nil, false, err
		}
		matched, reached := match(buffer[:n], routePeerIP(addr), dest, id, seq)
		if matched {
			return addr, reached, nil
		}
	}
}

func matchIPv4RouteReply(payload []byte, peer string, dest net.IP, id, seq int) (bool, bool) {
	reply, err := icmp.ParseMessage(1, payload)
	if err != nil {
		return false, false
	}
	switch reply.Type {
	case ipv4.ICMPTypeEchoReply:
		if !icmpEchoMatches(reply.Body, id, seq) {
			return false, false
		}
		peerIP := net.ParseIP(peer)
		if peerIP == nil || dest == nil || !peerIP.Equal(dest) {
			return false, false
		}
		return true, true
	case ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeDestinationUnreachable:
		inner := icmpEmbeddedPayload(reply.Body)
		innerDest, echoID, echoSeq, ok := parseIPv4EmbeddedEcho(inner)
		if !ok || echoID != id || echoSeq != seq || dest == nil || !innerDest.Equal(dest) {
			return false, false
		}
		peerIP := net.ParseIP(peer)
		return true, peerIP != nil && dest != nil && peerIP.Equal(dest)
	default:
		return false, false
	}
}

func matchIPv6RouteReply(payload []byte, peer string, dest net.IP, id, seq int) (bool, bool) {
	reply, err := icmp.ParseMessage(58, payload)
	if err != nil {
		return false, false
	}
	switch reply.Type {
	case ipv6.ICMPTypeEchoReply:
		if !icmpEchoMatches(reply.Body, id, seq) {
			return false, false
		}
		peerIP := net.ParseIP(peer)
		if peerIP == nil || dest == nil || !peerIP.Equal(dest) {
			return false, false
		}
		return true, true
	case ipv6.ICMPTypeTimeExceeded, ipv6.ICMPTypeDestinationUnreachable:
		inner := icmpEmbeddedPayload(reply.Body)
		innerDest, echoID, echoSeq, ok := parseIPv6EmbeddedEcho(inner)
		if !ok || echoID != id || echoSeq != seq || dest == nil || !innerDest.Equal(dest) {
			return false, false
		}
		peerIP := net.ParseIP(peer)
		return true, peerIP != nil && dest != nil && peerIP.Equal(dest)
	default:
		return false, false
	}
}

func icmpEchoMatches(body icmp.MessageBody, id, seq int) bool {
	echo, ok := body.(*icmp.Echo)
	return ok && echo != nil && echo.ID == id && echo.Seq == seq
}

func icmpEmbeddedPayload(body icmp.MessageBody) []byte {
	switch value := body.(type) {
	case *icmp.TimeExceeded:
		return value.Data
	case *icmp.DstUnreach:
		return value.Data
	default:
		return nil
	}
}

func parseIPv4EmbeddedEcho(data []byte) (net.IP, int, int, bool) {
	if len(data) < 20 {
		return nil, 0, 0, false
	}
	if data[0]>>4 != 4 {
		return nil, 0, 0, false
	}
	headerLen := int(data[0]&0x0f) * 4
	if headerLen < 20 || len(data) < headerLen {
		return nil, 0, 0, false
	}
	dest := net.IPv4(data[16], data[17], data[18], data[19])
	id, seq, ok := parseICMPEchoIdentity(1, 8, data[headerLen:])
	if !ok {
		return nil, 0, 0, false
	}
	return dest, id, seq, true
}

func parseIPv6EmbeddedEcho(data []byte) (net.IP, int, int, bool) {
	if len(data) < 40 {
		return nil, 0, 0, false
	}
	if data[0]>>4 != 6 {
		return nil, 0, 0, false
	}
	dest := net.IP(append([]byte(nil), data[24:40]...))
	id, seq, ok := parseICMPEchoIdentity(58, 128, data[40:])
	if !ok {
		return nil, 0, 0, false
	}
	return dest, id, seq, true
}

func parseICMPEchoIdentity(proto, echoRequestType int, payload []byte) (int, int, bool) {
	if len(payload) >= 8 {
		if int(payload[0]) == echoRequestType {
			id := int(payload[4])<<8 | int(payload[5])
			seq := int(payload[6])<<8 | int(payload[7])
			return id, seq, true
		}
	}
	msg, err := icmp.ParseMessage(proto, payload)
	if err != nil {
		return 0, 0, false
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok || echo == nil {
		return 0, 0, false
	}
	return echo.ID, echo.Seq, true
}
