package coreadapter

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type ipLimitDispatcher struct {
	routing.Dispatcher
	policy *policyEngine
}

type xrayLinkSession struct {
	stop       chan struct{}
	stopOnce   sync.Once
	finishOnce sync.Once
	untrack    func()
	readers    []buf.Reader
	writers    []buf.Writer
	conn       io.Closer
	remDirs    atomic.Int32
}

func newXrayLinkSession(conn io.Closer, readers []buf.Reader, writers []buf.Writer, dirs int32) *xrayLinkSession {
	ls := &xrayLinkSession{
		stop:    make(chan struct{}),
		readers: readers,
		writers: writers,
		conn:    conn,
	}
	ls.remDirs.Store(dirs)
	return ls
}

func (ls *xrayLinkSession) closeStop() {
	if ls == nil {
		return
	}
	ls.stopOnce.Do(func() {
		close(ls.stop)
	})
}

func (ls *xrayLinkSession) dirDone() {
	if ls == nil {
		return
	}
	if ls.remDirs.Add(-1) <= 0 {
		ls.finish()
	}
}

func (ls *xrayLinkSession) finish() {
	if ls == nil {
		return
	}
	ls.closeStop()
	ls.finishOnce.Do(func() {
		if ls.untrack != nil {
			ls.untrack()
		}
	})
}

func (ls *xrayLinkSession) Close() error {
	if ls == nil {
		return nil
	}
	ls.finish()
	for _, w := range ls.writers {
		common.Close(w)
		common.Interrupt(w)
	}
	for _, r := range ls.readers {
		common.Interrupt(r)
	}
	if ls.conn != nil {
		_ = ls.conn.Close()
	}
	return nil
}

func (d *ipLimitDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	restoreXraySystemDialer()
	release, ok := d.hold(ctx)
	if !ok {
		return nil, fmt.Errorf("user denied")
	}
	inLink, outLink := newDispatcherLinks(ctx)
	ls := d.trackAndMeterLinks(ctx, inLink, outLink)
	go func() {
		if err := d.Dispatcher.DispatchLink(ctx, dest, outLink); err != nil {
			common.Close(inLink.Writer)
			common.Interrupt(inLink.Reader)
			if ls != nil {
				_ = ls.Close()
			}
			if release != nil {
				release()
			}
		}
	}()
	return inLink, nil
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
	ls := d.trackAndMeterLink(ctx, link)
	if err := d.Dispatcher.DispatchLink(ctx, dest, link); err != nil {
		if ls != nil {
			_ = ls.Close()
		}
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

func (d *ipLimitDispatcher) resolveSessionUser(ctx context.Context) (userID string, meter bool, conn io.Closer) {
	if d.policy == nil {
		return "", false, nil
	}
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" {
		return "", false, nil
	}
	if strings.HasPrefix(in.Tag, "nodemgt-core-") || d.policy.isLoopUser(in.User.Email) {
		return "", false, nil
	}
	userID = d.policy.mapStatName(in.User.Email)
	if userID == "" {
		return "", false, nil
	}
	meter = d.policy.meterCoreTag(in.Tag)
	if meter {
		in.CanSpliceCopy = 3
		for _, out := range session.OutboundsFromContext(ctx) {
			if out != nil {
				out.CanSpliceCopy = 3
			}
		}
	}
	if !d.policy.skipCoreIPTag(in.Tag) && in.Conn != nil {
		conn = in.Conn
	}
	return userID, meter, conn
}

func (d *ipLimitDispatcher) trackAndMeterLink(ctx context.Context, link *transport.Link) *xrayLinkSession {
	userID, meter, conn := d.resolveSessionUser(ctx)
	if userID == "" || link == nil {
		return nil
	}
	var readers []buf.Reader
	var writers []buf.Writer
	dirs := int32(0)
	if link.Reader != nil {
		readers = append(readers, link.Reader)
		if meter {
			dirs++
		}
	}
	if link.Writer != nil {
		writers = append(writers, link.Writer)
		if meter {
			dirs++
		}
	}
	if dirs == 0 {
		dirs = 1
	}
	ls := newXrayLinkSession(conn, readers, writers, dirs)
	if !d.policy.skipCoreIPTag(sessionInboundTag(ctx)) {
		ls.untrack = d.policy.sess.Track(userID, ls)
		context.AfterFunc(ctx, ls.finish)
	}
	if meter {
		link.Reader, link.Writer = wrapQuotaIOSession(d.policy, userID, link.Reader, link.Writer, ls)
	}
	return ls
}

func (d *ipLimitDispatcher) trackAndMeterLinks(ctx context.Context, inLink, outLink *transport.Link) *xrayLinkSession {
	userID, meter, conn := d.resolveSessionUser(ctx)
	if userID == "" {
		return nil
	}
	var readers []buf.Reader
	var writers []buf.Writer
	dirs := int32(0)
	if inLink != nil {
		if inLink.Reader != nil {
			readers = append(readers, inLink.Reader)
		}
		if inLink.Writer != nil {
			writers = append(writers, inLink.Writer)
			dirs++
		}
	}
	if outLink != nil {
		if outLink.Reader != nil {
			readers = append(readers, outLink.Reader)
		}
		if outLink.Writer != nil {
			writers = append(writers, outLink.Writer)
			dirs++
		}
	}
	if dirs == 0 {
		dirs = 1
	}
	ls := newXrayLinkSession(conn, readers, writers, dirs)
	if !d.policy.skipCoreIPTag(sessionInboundTag(ctx)) {
		ls.untrack = d.policy.sess.Track(userID, ls)
		context.AfterFunc(ctx, ls.finish)
	}
	if meter {
		if inLink != nil {
			_, inLink.Writer = wrapQuotaIOSession(d.policy, userID, nil, inLink.Writer, ls)
		}
		if outLink != nil {
			_, outLink.Writer = wrapQuotaIOSession(d.policy, userID, nil, outLink.Writer, ls)
		}
	}
	return ls
}

func sessionInboundTag(ctx context.Context) string {
	if in := session.InboundFromContext(ctx); in != nil {
		return in.Tag
	}
	return ""
}

type quotaReader struct {
	buf.Reader
	userID   string
	policy   *policyEngine
	stop     <-chan struct{}
	ls       *xrayLinkSession
	doneOnce sync.Once
}

func (r *quotaReader) markDone() {
	r.doneOnce.Do(func() {
		if r.ls != nil {
			r.ls.dirDone()
		}
	})
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
	r.markDone()
}

func (r *quotaReader) account(mb buf.MultiBuffer, err error) (buf.MultiBuffer, error) {
	if n := int(mb.Len()); n > 0 && !r.policy.accountLinkBytesContext(r.userID, n, r.stop) {
		buf.ReleaseMulti(mb)
		r.markDone()
		return nil, fmt.Errorf("quota exceeded")
	}
	if err != nil {
		r.markDone()
	}
	return mb, err
}

type quotaWriter struct {
	buf.Writer
	userID    string
	policy    *policyEngine
	stop      <-chan struct{}
	ls        *xrayLinkSession
	closeOnce sync.Once
}

func (w *quotaWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 && !w.policy.accountLinkBytesContext(w.userID, n, w.stop) {
		buf.ReleaseMulti(mb)
		w.closeOnce.Do(func() {
			if w.ls != nil {
				w.ls.dirDone()
			}
		})
		return fmt.Errorf("quota exceeded")
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *quotaWriter) Close() error {
	err := common.Close(w.Writer)
	w.closeOnce.Do(func() {
		if w.ls != nil {
			w.ls.dirDone()
		}
	})
	return err
}

func (w *quotaWriter) Interrupt() {
	common.Interrupt(w.Writer)
	w.closeOnce.Do(func() {
		if w.ls != nil {
			w.ls.dirDone()
		}
	})
}

func wrapQuotaIO(policy *policyEngine, userID string, r buf.Reader, w buf.Writer) (buf.Reader, buf.Writer) {
	return wrapQuotaIOSession(policy, userID, r, w, nil)
}

func wrapQuotaIOSession(policy *policyEngine, userID string, r buf.Reader, w buf.Writer, ls *xrayLinkSession) (buf.Reader, buf.Writer) {
	var stop <-chan struct{}
	if ls != nil {
		stop = ls.stop
	}
	if r != nil {
		r = &quotaReader{Reader: r, policy: policy, userID: userID, stop: stop, ls: ls}
	}
	if w != nil {
		w = &quotaWriter{Writer: w, policy: policy, userID: userID, stop: stop, ls: ls}
	}
	return r, w
}

func (d *ipLimitDispatcher) hold(ctx context.Context) (func(), bool) {
	in := session.InboundFromContext(ctx)
	if in == nil || in.User == nil || in.User.Email == "" {
		return nil, true
	}
	if strings.HasPrefix(in.Tag, "nodemgt-core-") || d.policy.isLoopUser(in.User.Email) {
		return nil, true
	}
	userID := d.policy.mapStatName(in.User.Email)
	if userID != "" && d.policy.userBlocked(userID) {
		return nil, false
	}
	if d.policy.skipCoreIPTag(in.Tag) {
		return nil, true
	}
	var releases []func()
	if in.Conn != nil && userID != "" {
		releases = append(releases, d.policy.trackCoreConn(userID, in.Conn))
	}
	ip := ""
	if in.Source.Address != nil {
		ip = in.Source.Address.String()
	}
	limit := d.policy.ipLimit(userID)
	if userID != "" {
		releaseIP, ok := d.policy.acquireIP(userID, ip, limit)
		if !ok {
			for _, release := range releases {
				release()
			}
			return nil, false
		}
		if releaseIP != nil {
			releases = append(releases, releaseIP)
		}
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

func unwrapXrayInbound(p proxy.Inbound) proxy.Inbound {
	for {
		rec, ok := p.(recoveringInbound)
		if !ok {
			return p
		}
		p = rec.Inbound
	}
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
		um, ok := unwrapXrayInbound(gi.GetInbound()).(proxy.UserManager)
		if !ok {
			continue
		}
		_ = um.RemoveUser(ctx, email)
	}
}

func xraySSCipherType(method string) shadowsocks.CipherType {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}

func xrayMemoryUser(in InboundSpec, u UserSpec) (*protocol.MemoryUser, string, bool) {
	proto := strings.ToLower(strings.TrimSpace(in.Protocol))
	if proto == "" {
		proto = "socks"
	}
	switch proto {
	case "vless":
		id := vlessUUID(u)
		if id == "" {
			return nil, "", false
		}
		flow := ""
		if inboundAllowsVLESSFlow(in) {
			flow = u.Flow
			if flow == "" {
				flow = inboundFlow(in)
			}
		}
		acc, err := (&vless.Account{Id: id, Flow: flow}).AsAccount()
		if err != nil {
			return nil, "", false
		}
		return &protocol.MemoryUser{Email: u.ID, Account: acc}, "vless:" + strings.ToLower(id) + ":" + flow, true
	case "vmess":
		id := vlessUUID(u)
		if id == "" {
			return nil, "", false
		}
		acc, err := (&vmess.Account{Id: id}).AsAccount()
		if err != nil {
			return nil, "", false
		}
		return &protocol.MemoryUser{Email: u.ID, Account: acc}, "vmess:" + strings.ToLower(id), true
	case "trojan":
		_, pass, ok := socksIdentity(u)
		if !ok {
			return nil, "", false
		}
		acc, err := (&trojan.Account{Password: pass}).AsAccount()
		if err != nil {
			return nil, "", false
		}
		return &protocol.MemoryUser{Email: u.ID, Account: acc}, "trojan:" + pass, true
	case "shadowsocks":
		pass, ok := ssUserPassword(u)
		if !ok {
			return nil, "", false
		}
		method := ssMethod(in)
		if ss2022Method(method) {
			if !strings.Contains(method, "aes") {
				return nil, "", false
			}
			key := ss2022Key(pass, method)
			acc, err := (&shadowsocks_2022.Account{Key: key}).AsAccount()
			if err != nil {
				return nil, "", false
			}
			return &protocol.MemoryUser{Email: u.ID, Account: acc}, "ss2022:" + method + ":" + key, true
		}
		ct := xraySSCipherType(method)
		if ct == shadowsocks.CipherType_UNKNOWN {
			return nil, "", false
		}
		acc, err := (&shadowsocks.Account{Password: pass, CipherType: ct}).AsAccount()
		if err != nil {
			return nil, "", false
		}
		return &protocol.MemoryUser{Email: u.ID, Account: acc}, "ss:" + method + ":" + pass, true
	default:
		return nil, "", false
	}
}

func syncXrayInboundUsers(inst *xraycore.Instance, tags []string, in InboundSpec, prevGranted, nextGranted []UserSpec) bool {
	if inst == nil || len(tags) == 0 {
		return false
	}
	feat := inst.GetFeature(inbound.ManagerType())
	mgr, ok := feat.(inbound.Manager)
	if !ok || mgr == nil {
		return false
	}
	ctx := context.Background()
	ums := make([]proxy.UserManager, 0, len(tags))
	for _, tag := range tags {
		h, err := mgr.GetHandler(ctx, tag)
		if err != nil || h == nil {
			return false
		}
		gi, ok := h.(proxy.GetInbound)
		if !ok {
			return false
		}
		um, ok := unwrapXrayInbound(gi.GetInbound()).(proxy.UserManager)
		if !ok || um == nil {
			return false
		}
		ums = append(ums, um)
	}
	prevKeys := make(map[string]string, len(prevGranted))
	for _, u := range prevGranted {
		if _, key, ok := xrayMemoryUser(in, u); ok {
			prevKeys[u.ID] = key
		}
	}
	nextUsers := make([]*protocol.MemoryUser, 0, len(nextGranted))
	nextKeys := make(map[string]string, len(nextGranted))
	for _, u := range nextGranted {
		memUser, key, ok := xrayMemoryUser(in, u)
		if !ok {
			return false
		}
		nextUsers = append(nextUsers, memUser)
		nextKeys[u.ID] = key
	}
	for id, oldKey := range prevKeys {
		if newKey, stillPresent := nextKeys[id]; !stillPresent || newKey != oldKey {
			for _, um := range ums {
				_ = um.RemoveUser(ctx, id)
			}
		}
	}
	for _, memUser := range nextUsers {
		id := memUser.Email
		needAdd := prevKeys[id] != nextKeys[id]
		for _, um := range ums {
			if needAdd || um.GetUser(ctx, id) == nil {
				_ = um.RemoveUser(ctx, id)
				if err := um.AddUser(ctx, memUser); err != nil {
					return false
				}
			}
		}
	}
	return true
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
	wrapWorkerProxyRecover(inst)
}

type recoveringInbound struct {
	proxy.Inbound
}

func (p recoveringInbound) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("inbound panic: %v", rec)
		}
	}()
	return p.Inbound.Process(ctx, network, conn, dispatcher)
}

func wrapWorkerProxyRecover(inst *xraycore.Instance) {
	feat := inst.GetFeature(inbound.ManagerType())
	mgr, ok := feat.(inbound.Manager)
	if !ok || mgr == nil {
		return
	}
	for _, h := range mgr.ListHandlers(context.Background()) {
		wrapHandlerWorkerProxy(h)
	}
}

func wrapHandlerWorkerProxy(h any) {
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
	workers := v.FieldByName("workers")
	if !workers.IsValid() || workers.Kind() != reflect.Slice {
		return
	}
	for i := 0; i < workers.Len(); i++ {
		w := workers.Index(i)
		if w.Kind() == reflect.Interface {
			if w.IsNil() {
				continue
			}
			w = w.Elem()
		}
		if w.Kind() == reflect.Ptr {
			if w.IsNil() {
				continue
			}
			w = w.Elem()
		}
		if w.Kind() != reflect.Struct {
			continue
		}
		field := w.FieldByName("proxy")
		if !field.IsValid() {
			continue
		}
		cur, ok := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(proxy.Inbound)
		if !ok || cur == nil {
			continue
		}
		if _, already := cur.(recoveringInbound); already {
			continue
		}
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(recoveringInbound{Inbound: cur}))
	}
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
