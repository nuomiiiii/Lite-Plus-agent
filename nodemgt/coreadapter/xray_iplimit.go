package coreadapter

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

type ipLimitDispatcher struct {
	routing.Dispatcher
	policy *policyEngine
}

func (d *ipLimitDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	restoreXraySystemDialer()
	release, ok := d.hold(ctx)
	if !ok {
		return nil, fmt.Errorf("user denied")
	}
	inbound, outbound := newDispatcherLinks(ctx)
	d.meterLinks(ctx, inbound, outbound)
	go func() {
		if err := d.Dispatcher.DispatchLink(ctx, dest, outbound); err != nil {
			common.Close(inbound.Writer)
			common.Interrupt(inbound.Reader)
			if release != nil {
				release()
			}
		}
	}()
	return inbound, nil
}

func (d *ipLimitDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	restoreXraySystemDialer()
	release, ok := d.hold(ctx)
	if !ok {
		if link != nil {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
		}
		return fmt.Errorf("user denied")
	}
	d.meterLink(ctx, link)
	if err := d.Dispatcher.DispatchLink(ctx, dest, link); err != nil {
		if release != nil {
			release()
		}
		return err
	}
	return nil
}

func newDispatcherLinks(ctx context.Context) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)
	return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter},
		&transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
}

func (d *ipLimitDispatcher) prepareMeter(ctx context.Context) (string, bool) {
	if d.policy == nil {
		return "", false
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return "", false
	}
	if !d.policy.meterCoreTag(inbound.Tag) {
		return "", false
	}
	userID := d.policy.mapStatName(inbound.User.Email)
	if userID == "" {
		return "", false
	}
	inbound.CanSpliceCopy = 3
	for _, outbound := range session.OutboundsFromContext(ctx) {
		if outbound != nil {
			outbound.CanSpliceCopy = 3
		}
	}
	return userID, true
}

func (d *ipLimitDispatcher) meterLink(ctx context.Context, link *transport.Link) {
	userID, ok := d.prepareMeter(ctx)
	if !ok || link == nil {
		return
	}
	link.Reader, link.Writer = wrapQuotaIO(d.policy, userID, link.Reader, link.Writer)
}

func (d *ipLimitDispatcher) meterLinks(ctx context.Context, inbound, outbound *transport.Link) {
	userID, ok := d.prepareMeter(ctx)
	if !ok {
		return
	}
	if inbound != nil {
		_, inbound.Writer = wrapQuotaIO(d.policy, userID, nil, inbound.Writer)
	}
	if outbound != nil {
		_, outbound.Writer = wrapQuotaIO(d.policy, userID, nil, outbound.Writer)
	}
}

type quotaReader struct {
	buf.Reader
	userID string
	policy *policyEngine
}

func (r *quotaReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	return r.account(mb, err)
}

func (r *quotaReader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	tr, ok := r.Reader.(buf.TimeoutReader)
	if !ok {
		return r.ReadMultiBuffer()
	}
	mb, err := tr.ReadMultiBufferTimeout(d)
	return r.account(mb, err)
}

func (r *quotaReader) Interrupt() {
	common.Interrupt(r.Reader)
}

func (r *quotaReader) account(mb buf.MultiBuffer, err error) (buf.MultiBuffer, error) {
	if n := int(mb.Len()); n > 0 && !r.policy.accountLinkBytes(r.userID, n) {
		buf.ReleaseMulti(mb)
		return nil, fmt.Errorf("quota exceeded")
	}
	return mb, err
}

type quotaWriter struct {
	buf.Writer
	userID string
	policy *policyEngine
}

func (w *quotaWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 && !w.policy.accountLinkBytes(w.userID, n) {
		buf.ReleaseMulti(mb)
		return fmt.Errorf("quota exceeded")
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *quotaWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *quotaWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

func wrapQuotaIO(policy *policyEngine, userID string, r buf.Reader, w buf.Writer) (buf.Reader, buf.Writer) {
	if r != nil {
		if _, keep := r.(*pipe.Reader); !keep {
			r = &quotaReader{Reader: r, policy: policy, userID: userID}
		}
	}
	if w != nil {
		w = &quotaWriter{Writer: w, policy: policy, userID: userID}
	}
	return r, w
}

func (d *ipLimitDispatcher) hold(ctx context.Context) (func(), bool) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return nil, true
	}
	userID := d.policy.mapStatName(inbound.User.Email)
	if userID != "" && d.policy.userBlocked(userID) {
		return nil, false
	}
	if d.policy.skipCoreIPTag(inbound.Tag) {
		return nil, true
	}
	var releases []func()
	if inbound.Conn != nil && userID != "" {
		releases = append(releases, d.policy.trackCoreConn(userID, inbound.Conn))
	}
	limit := d.policy.ipLimit(userID)
	if limit > 0 {
		ip := ""
		if inbound.Source.Address != nil {
			ip = inbound.Source.Address.String()
		}
		if !d.policy.holdIP(userID, ip, limit) {
			for _, release := range releases {
				release()
			}
			return nil, false
		}
		var once sync.Once
		releases = append(releases, func() { once.Do(func() { d.policy.releaseIP(userID, ip) }) })
	}
	if len(releases) == 0 {
		return nil, true
	}
	release := func() {
		for _, fn := range releases {
			fn()
		}
	}
	context.AfterFunc(ctx, release)
	return release, true
}

func removeXrayUser(inst *xraycore.Instance, email string) {
	if inst == nil || email == "" {
		return
	}
	feat := inst.GetFeature(inbound.ManagerType())
	mgr, ok := feat.(inbound.Manager)
	if !ok || mgr == nil {
		return
	}
	ctx := context.Background()
	for _, h := range mgr.ListHandlers(ctx) {
		gi, ok := h.(proxy.GetInbound)
		if !ok {
			continue
		}
		um, ok := gi.GetInbound().(proxy.UserManager)
		if !ok {
			continue
		}
		_ = um.RemoveUser(ctx, email)
	}
}

var liveXrayDialer struct {
	mu sync.Mutex
	dc dns.Client
	om outbound.Manager
}

func captureXraySystemDialer(inst *xraycore.Instance) {
	dc, _ := inst.GetFeature(dns.ClientType()).(dns.Client)
	om, _ := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	liveXrayDialer.mu.Lock()
	liveXrayDialer.dc = dc
	liveXrayDialer.om = om
	liveXrayDialer.mu.Unlock()
	internet.InitSystemDialer(dc, om)
}

func restoreXraySystemDialer() {
	liveXrayDialer.mu.Lock()
	dc, om := liveXrayDialer.dc, liveXrayDialer.om
	liveXrayDialer.mu.Unlock()
	if om == nil {
		return
	}
	internet.InitSystemDialer(dc, om)
}

func startXrayInstance(raw []byte, policy *policyEngine) (*xraycore.Instance, error) {
	inst, err := xraycore.StartInstance("json", raw)
	if err != nil {
		return nil, err
	}
	captureXraySystemDialer(inst)
	wrapXrayDispatcher(inst, policy)
	return inst, nil
}

func wrapXrayDispatcher(inst *xraycore.Instance, policy *policyEngine) {
	feat := inst.GetFeature(routing.DispatcherType())
	inner, ok := feat.(routing.Dispatcher)
	if !ok || inner == nil {
		return
	}
	if _, wrapped := inner.(*ipLimitDispatcher); wrapped {
		return
	}
	next := &ipLimitDispatcher{Dispatcher: inner, policy: policy}
	replaceXrayFeature(inst, inner, next)
	patchInboundMuxDispatchers(inst, next)
}

func patchInboundMuxDispatchers(inst *xraycore.Instance, wrap routing.Dispatcher) {
	feat := inst.GetFeature(inbound.ManagerType())
	mgr, ok := feat.(inbound.Manager)
	if !ok || mgr == nil {
		return
	}
	for _, h := range mgr.ListHandlers(context.Background()) {
		setMuxDispatcher(h, wrap)
	}
}

func setMuxDispatcher(h any, wrap routing.Dispatcher) {
	v := reflect.ValueOf(h)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	muxField := v.FieldByName("mux")
	if !muxField.IsValid() || muxField.Kind() != reflect.Ptr || muxField.IsNil() {
		return
	}
	muxVal := reflect.NewAt(muxField.Type(), unsafe.Pointer(muxField.UnsafeAddr())).Elem()
	if muxVal.IsNil() {
		return
	}
	srv := muxVal.Elem()
	disp := srv.FieldByName("dispatcher")
	if !disp.IsValid() {
		return
	}
	reflect.NewAt(disp.Type(), unsafe.Pointer(disp.UnsafeAddr())).Elem().Set(reflect.ValueOf(wrap))
}

func replaceXrayFeature(inst *xraycore.Instance, old, next features.Feature) {
	v := reflect.ValueOf(inst).Elem().FieldByName("features")
	if !v.IsValid() {
		return
	}
	slice := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	for i := 0; i < slice.Len(); i++ {
		if slice.Index(i).Interface() == old {
			slice.Index(i).Set(reflect.ValueOf(next))
			return
		}
	}
}
