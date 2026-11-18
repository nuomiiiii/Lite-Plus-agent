package coreadapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestWrapQuotaIOWrapsPipeReader(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-pipe"}}, nil)
	r, w := pipe.New()
	gotR, gotW := wrapQuotaIO(p, "quota-pipe", r, w)
	if _, ok := gotR.(*quotaReader); !ok {
		t.Fatalf("pipe reader became %T", gotR)
	}
	if _, ok := gotW.(*quotaWriter); !ok {
		t.Fatalf("pipe writer became %T", gotW)
	}
}

func TestWrapQuotaIOWrapsNonPipeReader(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-nested"}}, nil)
	inner := buf.NewReader(bytes.NewReader(nil))
	gotR, _ := wrapQuotaIO(p, "quota-nested", inner, nil)
	if _, ok := gotR.(*quotaReader); !ok {
		t.Fatalf("non-pipe reader became %T", gotR)
	}
}

func TestXUDPSessionCloseWithMeteredWriter(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-xudp"}}, nil)
	p.setMeterCore([]string{"xudp-in"})
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:  "xudp-in",
		User: &protocol.MemoryUser{Email: "quota-xudp"},
	})
	stub := &captureDispatcher{done: make(chan struct{})}
	d := &ipLimitDispatcher{Dispatcher: stub, policy: p}
	link, err := d.Dispatch(ctx, xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), 53))
	if err != nil {
		t.Fatal(err)
	}
	defer common.Interrupt(link.Reader)
	s := &mux.Session{ID: 1, XUDP: &mux.XUDP{Status: mux.Active}}
	setMuxSessionIO(t, s, link.Reader, link.Writer)
	if err := s.Close(false); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestMeteredDispatchKeepsPipeReaderAndCountsBothDirections(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-dispatch"}}, nil)
	p.setMeterCore([]string{"public-in"})
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:  "public-in",
		User: &protocol.MemoryUser{Email: "quota-dispatch"},
	})
	stub := &captureDispatcher{done: make(chan struct{})}
	d := &ipLimitDispatcher{Dispatcher: stub, policy: p}

	link, err := d.Dispatch(ctx, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := link.Reader.(*pipe.Reader); !ok {
		t.Fatalf("inbound reader became %T", link.Reader)
	}
	if _, ok := link.Writer.(*quotaWriter); !ok {
		t.Fatalf("inbound writer became %T", link.Writer)
	}

	select {
	case <-stub.done:
	case <-time.After(2 * time.Second):
		t.Fatal("inner DispatchLink was not called")
	}
	if _, ok := stub.link.Writer.(*quotaWriter); !ok {
		t.Fatalf("outbound writer became %T", stub.link.Writer)
	}

	up := buf.FromBytes([]byte("up-bytes"))
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{up}); err != nil {
		t.Fatalf("uplink write: %v", err)
	}
	down := buf.FromBytes([]byte("down-byte"))
	if err := stub.link.Writer.WriteMultiBuffer(buf.MultiBuffer{down}); err != nil {
		t.Fatalf("downlink write: %v", err)
	}
	got := int64(0)
	for _, snap := range p.snapshots() {
		if snap.UserID == "quota-dispatch" {
			got += snap.Bytes
		}
	}
	if got != int64(len("up-bytes")+len("down-byte")) {
		t.Fatalf("accounted %d, want %d", got, len("up-bytes")+len("down-byte"))
	}
}

func TestDispatchLinkMetersPipeReaderAndSurvivesDownlinkHalfClose(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-halfclose", RateLimitBps: 80000}}, nil)
	p.setMeterCore([]string{"mux-in"})
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:  "mux-in",
		User: &protocol.MemoryUser{Email: "quota-halfclose"},
	})
	upR, upW := pipe.New()
	_, downW := pipe.New()
	stub := &captureDispatcher{done: make(chan struct{})}
	d := &ipLimitDispatcher{Dispatcher: stub, policy: p}
	link := &transport.Link{Reader: upR, Writer: downW}
	if err := d.DispatchLink(ctx, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), 9), link); err != nil {
		t.Fatal(err)
	}
	if _, ok := stub.link.Reader.(*quotaReader); !ok {
		t.Fatalf("DispatchLink pipe reader became %T, want *quotaReader", stub.link.Reader)
	}
	// Half-close downlink writer while uplink is still active:
	if err := common.Close(stub.link.Writer); err != nil {
		t.Fatalf("downlink half-close: %v", err)
	}
	// Uplink transfer exceeding burst after downlink half-close must still succeed (ls.stop not closed prematurely!):
	payload := bytes.Repeat([]byte("u"), 12000)
	if err := upW.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
		t.Fatal(err)
	}
	common.Close(upW)
	total := 0
	for {
		mb, err := stub.link.Reader.ReadMultiBuffer()
		if len(mb) > 0 {
			total += int(mb.Len())
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			break
		}
	}
	if total != len(payload) {
		t.Fatalf("uplink read after downlink half-close = %d, want %d", total, len(payload))
	}
	if snapped := totalUser(p.snapshots(), "quota-halfclose"); snapped != int64(len(payload)) {
		t.Fatalf("metered pipe reader bytes = %d, want %d", snapped, len(payload))
	}
}

type captureDispatcher struct {
	mu   sync.Mutex
	link *transport.Link
	done chan struct{}
}

func (*captureDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*captureDispatcher) Start() error      { return nil }
func (*captureDispatcher) Close() error      { return nil }

func (*captureDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, fmt.Errorf("Dispatch should not be used")
}

func (c *captureDispatcher) DispatchLink(_ context.Context, _ xnet.Destination, link *transport.Link) error {
	c.mu.Lock()
	c.link = link
	c.mu.Unlock()
	close(c.done)
	return nil
}

func TestRecoveringInboundCatchesProcessPanic(t *testing.T) {
	err := recoveringInbound{Inbound: panicInbound{}}.Process(context.Background(), xnet.Network_UDP, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "buffer overflow") {
		t.Fatalf("got %v", err)
	}
}

type panicInbound struct{}

func (panicInbound) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_UDP}
}

func (panicInbound) Process(context.Context, xnet.Network, stat.Connection, routing.Dispatcher) error {
	panic("buffer overflow: capacity 8192,start 0, need 47")
}

type stubWorker struct {
	proxy proxy.Inbound
}

type stubHandler struct {
	workers []any
}

func TestWrapHandlerWorkerProxyRecovers(t *testing.T) {
	h := &stubHandler{workers: []any{&stubWorker{proxy: panicInbound{}}}}
	wrapHandlerWorkerProxy(h)
	w := h.workers[0].(*stubWorker)
	got, ok := w.proxy.(recoveringInbound)
	if !ok {
		t.Fatalf("proxy became %T", w.proxy)
	}
	err := got.Process(context.Background(), xnet.Network_UDP, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "buffer overflow") {
		t.Fatalf("got %v", err)
	}
}

func TestXrayLiveSocksUDPSurvivesOversizedDatagramAndContinuesServing(t *testing.T) {
	// Real UDP echo server that also returns an 8188-byte datagram when asked
	// (8188B + 10B SOCKS5 UDP header = 8198B > 8192B Xray buf.Size, testing live Xray UDP
	// buffer-boundary overflow handling without exceeding Windows Winsock's 8192B ReadFrom limit).
	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 65535)
		bigReply := bytes.Repeat([]byte("Z"), 8188)
		for {
			n, addr, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "send-8188" {
				_, _ = udpEcho.WriteTo(bigReply, addr)
				continue
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()
	echoUDPAddr := udpEcho.LocalAddr().(*net.UDPAddr)

	// Start a live Xray instance with a core-owned UDP-enabled SOCKS5 inbound (wrapWorkerProxyRecover active).
	socksPort := freePort(t)
	rawCfg := fmt.Sprintf(`{
		"log": {"loglevel": "none"},
		"inbounds": [{
			"tag": "socks-udp-live",
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "socks",
			"settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}
		}],
		"outbounds": [{"protocol": "freedom", "tag": "direct"}]
	}`, socksPort)
	p := newPolicyEngine()
	inst, err := startXrayInstance([]byte(rawCfg), p)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	// Perform SOCKS5 UDP ASSOCIATE to get Xray's live UDP relay port.
	ctrl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := ctrl.Read(greet[:]); err != nil || greet != [2]byte{0x05, 0x00} {
		t.Fatalf("socks5 greet: %v err=%v", greet, err)
	}
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var assoc [10]byte
	if _, err := ctrl.Read(assoc[:]); err != nil || assoc[1] != 0x00 {
		t.Fatalf("socks5 udp associate: %v err=%v", assoc, err)
	}
	relayPort := int(binary.BigEndian.Uint16(assoc[8:10]))
	relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relayPort}

	cliUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cliUDP.Close()

	buildSocksUDPFrame := func(payload []byte) []byte {
		hdr := []byte{0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
		binary.BigEndian.PutUint16(hdr[8:10], uint16(echoUDPAddr.Port))
		return append(hdr, payload...)
	}

	// 1. Send truncated, fragmented, and invalid-ATYP SOCKS5 UDP frames plus trigger an
	// upstream 8188-byte response (> 8182B available in Xray's 8192B buf.Buffer after 10B header).
	_, _ = cliUDP.WriteToUDP([]byte{0x00, 0x01}, relayAddr)
	_, _ = cliUDP.WriteToUDP([]byte{0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 80, 'x'}, relayAddr)
	_, _ = cliUDP.WriteToUDP([]byte{0x00, 0x00, 0x00, 0x99, 1, 2, 3, 4}, relayAddr)
	if _, err := cliUDP.WriteToUDP(buildSocksUDPFrame([]byte("send-8188")), relayAddr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	// 2. Verify the live Xray UDP worker is still healthy and echoes a normal UDP datagram!
	want := []byte("xray-udp-still-alive")
	if _, err := cliUDP.WriteToUDP(buildSocksUDPFrame(want), relayAddr); err != nil {
		t.Fatal(err)
	}
	_ = cliUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	recvBuf := make([]byte, 65535)
	for {
		n, _, err := cliUDP.ReadFromUDP(recvBuf)
		if err != nil {
			t.Fatalf("live Xray UDP relay stopped responding after boundary/malformed datagrams: %v", err)
		}
		if n == 0 {
			continue
		}
		if n < 10+len(want) || !bytes.Equal(recvBuf[n-len(want):n], want) {
			t.Fatalf("unexpected UDP echo payload (%d bytes): %q", n, recvBuf[:n])
		}
		break
	}
}

func setMuxSessionIO(t *testing.T, s *mux.Session, reader buf.Reader, writer buf.Writer) {
	t.Helper()
	v := reflect.ValueOf(s).Elem()
	for name, value := range map[string]any{
		"input": reader, "output": writer, "parent": mux.NewSessionManager(),
	} {
		f := v.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("missing mux.Session field %s", name)
		}
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
	}
}
