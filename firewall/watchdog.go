package firewall

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
	"github.com/nuomiiiii/lite-agent/dnsresolver"
)

const (
	watchdogDialTimeout = 2 * time.Second
	watchdogTotalWait   = 6 * time.Second
)

var (
	controlPeerMu sync.Mutex
	controlPeer   func() string
)

func SetControlPlanePeer(fn func() string) {
	controlPeerMu.Lock()
	controlPeer = fn
	controlPeerMu.Unlock()
}

func watchdogOK() bool {
	peer := liveControlPeer()
	if peer != "" && dialControlHost(peer) {
		return true
	}
	host := endpointHostPort()
	if host == "" {
		return true
	}
	return dialControlHost(host)
}

func liveControlPeer() string {
	controlPeerMu.Lock()
	fn := controlPeer
	controlPeerMu.Unlock()
	if fn == nil {
		return ""
	}
	return strings.TrimSpace(fn())
}

func endpointHostPort() string {
	endpoint := strings.TrimSpace(pkg_flags.GlobalConfig.Endpoint)
	if endpoint == "" {
		return ""
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	port := "443"
	if parsed.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func dialControlHost(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), watchdogTotalWait)
	defer cancel()
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if ipLiteral(host) {
		d := net.Dialer{Timeout: watchdogDialTimeout}
		conn, err := d.DialContext(ctx, "tcp", hostport)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	prefer := ""
	if pkg_flags.GlobalConfig != nil {
		prefer = pkg_flags.GlobalConfig.PreferIPVersion
	}
	dial := dnsresolver.GetDialContextWithPreference(watchdogDialTimeout, prefer)
	conn, err := dial(ctx, "tcp", hostport)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func ipLiteral(host string) bool {
	host = strings.Trim(host, "[]")
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host) != nil
}
