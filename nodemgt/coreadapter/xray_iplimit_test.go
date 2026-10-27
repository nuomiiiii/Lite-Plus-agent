package coreadapter

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

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

func TestWrapQuotaIOKeepsPipeReader(t *testing.T) {
	p := newPolicyEngine()
	p.sync([]UserSpec{{ID: "quota-pipe"}}, nil)
	r, w := pipe.New()
	gotR, gotW := wrapQuotaIO(p, "quota-pipe", r, w)
	if _, ok := gotR.(*pipe.Reader); !ok {
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
	r, w := pipe.New()
	defer r.Interrupt()
	reader, writer := wrapQuotaIO(p, "quota-xudp", r, w)
	s := &mux.Session{ID: 1, XUDP: &mux.XUDP{Status: mux.Active}}
	setMuxSessionIO(t, s, reader, writer)
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

type captureDispatcher struct {
	mu   sync.Mutex
	link *transport.Link
	done chan struct{}
}

func (captureDispatcher) Type() interface{} { return routing.DispatcherType() }
func (captureDispatcher) Start() error      { return nil }
func (captureDispatcher) Close() error      { return nil }

func (captureDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
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
