package firewall

import (
	"net"
	"net/url"
	"strings"
	"time"

	pkg_flags "github.com/nuomiiiii/lite-agent/cmd/flags"
)

func watchdogOK() bool {
	endpoint := strings.TrimSpace(pkg_flags.GlobalConfig.Endpoint)
	if endpoint == "" {
		return true
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return true
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
	}
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "http" {
			host += ":80"
		} else {
			host += ":443"
		}
	}
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
