package protection

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

const (
	maxLineBytes = 64 * 1024
)

type Record struct {
	Time       time.Time
	IP         string
	Method     string
	URI        string
	Path       string
	Host       string
	Status     int
	Proto      string
	Transport  string
	ServerPort int
	PeerAddr   string
	DestAddr   string
}

func ParseLine(format, line string) (Record, error) {
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line == "" {
		return Record{}, fmt.Errorf("empty line")
	}
	if len(line) > maxLineBytes {
		return Record{}, fmt.Errorf("line too long")
	}
	switch format {
	case v2.ProtectionLogCaddyJSON:
		return parseCaddyJSON(line)
	case v2.ProtectionLogNginxCombined:
		return parseNginxCombined(line)
	case v2.ProtectionLogNginxJSON:
		return parseNginxJSON(line)
	case v2.ProtectionLogSSHD:
		return parseSSHD(line, time.Now())
	default:
		return Record{}, fmt.Errorf("unsupported log format %q", format)
	}
}

type caddyLogLine struct {
	TS      json.RawMessage `json:"ts"`
	Status  json.RawMessage `json:"status"`
	Request *struct {
		RemoteIP   string          `json:"remote_ip"`
		ClientIP   string          `json:"client_ip"`
		RemotePort json.RawMessage `json:"remote_port"`
		Method     string          `json:"method"`
		URI        string          `json:"uri"`
		Proto      string          `json:"proto"`
		Host       string          `json:"host"`
	} `json:"request"`
}

func parseCaddyJSON(line string) (Record, error) {
	var raw caddyLogLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Record{}, fmt.Errorf("caddy json: %w", err)
	}
	if raw.Request == nil {
		return Record{}, fmt.Errorf("caddy json missing request")
	}
	rec := Record{
		Method: strings.TrimSpace(raw.Request.Method),
		URI:    raw.Request.URI,
		Host:   strings.TrimSpace(raw.Request.Host),
		Proto:  strings.TrimSpace(raw.Request.Proto),
		IP:     strings.TrimSpace(raw.Request.RemoteIP),
	}
	if rec.IP == "" {
		return Record{}, fmt.Errorf("caddy json missing remote_ip")
	}
	if ip, ok := v2.NormalizeProtectionIP(rec.IP); ok {
		rec.IP = ip
	} else {
		return Record{}, fmt.Errorf("caddy json invalid remote_ip")
	}
	if clientIP, ok := v2.NormalizeProtectionIP(raw.Request.ClientIP); ok {
		rec.PeerAddr = rec.IP
		rec.IP = clientIP
	}
	if ts, err := parseFlexibleTime(raw.TS); err == nil {
		rec.Time = ts
	} else {
		return Record{}, fmt.Errorf("caddy json ts: %w", err)
	}
	if status, err := parseFlexibleInt(raw.Status); err == nil {
		rec.Status = status
	}
	path, err := NormalizePath(rec.URI)
	if err != nil {
		return Record{}, err
	}
	rec.Path = path
	rec.Transport = transportOfProto(rec.Proto)
	return rec, nil
}

type nginxJSONLine struct {
	TS         json.RawMessage `json:"ts"`
	RemoteAddr string          `json:"remote_addr"`
	ServerAddr string          `json:"server_addr"`
	ServerPort json.RawMessage `json:"server_port"`
	Host       string          `json:"host"`
	Method     string          `json:"method"`
	URI        string          `json:"uri"`
	Protocol   string          `json:"protocol"`
	Status     json.RawMessage `json:"status"`
	PeerAddr   string          `json:"peer_addr"`
}

func parseNginxJSON(line string) (Record, error) {
	var raw nginxJSONLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Record{}, fmt.Errorf("nginx json: %w", err)
	}
	rec := Record{
		Method:   strings.TrimSpace(raw.Method),
		URI:      raw.URI,
		Host:     strings.TrimSpace(raw.Host),
		Proto:    strings.TrimSpace(raw.Protocol),
		IP:       strings.TrimSpace(raw.RemoteAddr),
		PeerAddr: strings.TrimSpace(raw.PeerAddr),
	}
	if rec.IP == "" {
		return Record{}, fmt.Errorf("nginx json missing remote_addr")
	}
	if ip, ok := v2.NormalizeProtectionIP(rec.IP); ok {
		rec.IP = ip
	} else {
		return Record{}, fmt.Errorf("nginx json invalid remote_addr")
	}
	if rec.PeerAddr != "" {
		if ip, ok := v2.NormalizeProtectionIP(rec.PeerAddr); ok {
			rec.PeerAddr = ip
		} else {
			return Record{}, fmt.Errorf("nginx json invalid peer_addr")
		}
	}
	if dest, ok := v2.NormalizeProtectionIP(raw.ServerAddr); ok {
		rec.DestAddr = dest
	} else if strings.TrimSpace(raw.ServerAddr) != "" {
		return Record{}, fmt.Errorf("nginx json invalid server_addr")
	}
	if ts, err := parseFlexibleTime(raw.TS); err == nil {
		rec.Time = ts
	} else {
		return Record{}, fmt.Errorf("nginx json ts: %w", err)
	}
	if status, err := parseFlexibleInt(raw.Status); err == nil {
		rec.Status = status
	} else {
		return Record{}, fmt.Errorf("nginx json status: %w", err)
	}
	if port, err := parseFlexibleInt(raw.ServerPort); err == nil {
		rec.ServerPort = port
	} else {
		return Record{}, fmt.Errorf("nginx json server_port: %w", err)
	}
	path, err := NormalizePath(rec.URI)
	if err != nil {
		return Record{}, err
	}
	rec.Path = path
	rec.Transport = transportOfProto(rec.Proto)
	return rec, nil
}

func parseNginxCombined(line string) (Record, error) {
	rest := line
	ip, rest, err := splitRemoteAddr(rest)
	if err != nil {
		return Record{}, err
	}
	norm, ok := v2.NormalizeProtectionIP(ip)
	if !ok {
		return Record{}, fmt.Errorf("nginx combined invalid remote_addr")
	}
	if _, rest, err = splitIdent(rest); err != nil {
		return Record{}, err
	}
	if _, rest, err = splitIdent(rest); err != nil {
		return Record{}, err
	}
	tsRaw, rest, err := splitBracket(rest)
	if err != nil {
		return Record{}, err
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", tsRaw)
	if err != nil {
		return Record{}, fmt.Errorf("nginx combined time: %w", err)
	}
	req, rest, err := splitQuoted(rest)
	if err != nil {
		return Record{}, err
	}
	method, uri, proto := splitRequest(req)
	statusStr, _, err := splitIdent(strings.TrimSpace(rest))
	if err != nil {
		return Record{}, err
	}
	status, err := strconv.Atoi(statusStr)
	if err != nil {
		return Record{}, fmt.Errorf("nginx combined status")
	}
	path, err := NormalizePath(uri)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Time:      ts,
		IP:        norm,
		Method:    method,
		URI:       uri,
		Path:      path,
		Status:    status,
		Proto:     proto,
		Transport: transportOfProto(proto),
	}, nil
}

func splitRemoteAddr(line string) (ip, rest string, err error) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") {
		end := strings.IndexByte(line, ']')
		if end < 1 {
			return "", "", fmt.Errorf("nginx combined ipv6")
		}
		ip = line[1:end]
		rest = strings.TrimSpace(line[end+1:])
		return ip, rest, nil
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 1 {
		return "", "", fmt.Errorf("nginx combined remote_addr")
	}
	return line[:sp], strings.TrimSpace(line[sp+1:]), nil
}

func splitIdent(line string) (tok, rest string, err error) {
	line = strings.TrimSpace(line)
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		if line == "" {
			return "", "", fmt.Errorf("nginx combined truncated")
		}
		return line, "", nil
	}
	return line[:sp], strings.TrimSpace(line[sp+1:]), nil
}

func splitBracket(line string) (inner, rest string, err error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return "", "", fmt.Errorf("nginx combined time")
	}
	end := strings.IndexByte(line, ']')
	if end < 1 {
		return "", "", fmt.Errorf("nginx combined time")
	}
	return line[1:end], strings.TrimSpace(line[end+1:]), nil
}

func splitQuoted(line string) (inner, rest string, err error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, `"`) {
		return "", "", fmt.Errorf("nginx combined request")
	}
	var b strings.Builder
	esc := false
	for i := 1; i < len(line); i++ {
		ch := line[i]
		if esc {
			b.WriteByte(ch)
			esc = false
			continue
		}
		if ch == '\\' {
			esc = true
			continue
		}
		if ch == '"' {
			return b.String(), strings.TrimSpace(line[i+1:]), nil
		}
		b.WriteByte(ch)
	}
	return "", "", fmt.Errorf("nginx combined request unterminated")
}

func splitRequest(req string) (method, uri, proto string) {
	req = strings.TrimSpace(req)
	parts := strings.SplitN(req, " ", 3)
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return parts[0], "", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], parts[2]
	}
}

func parseFlexibleTime(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, fmt.Errorf("missing")
	}
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, `"`) {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return time.Time{}, err
		}
		text = strings.TrimSpace(text)
		if unix, err := strconv.ParseFloat(text, 64); err == nil {
			return unixToTime(unix), nil
		}
		if ts, err := time.Parse(time.RFC3339Nano, text); err == nil {
			return ts, nil
		}
		return time.Parse(time.RFC3339, text)
	}
	var unix float64
	if err := json.Unmarshal(raw, &unix); err != nil {
		return time.Time{}, err
	}
	return unixToTime(unix), nil
}

func unixToTime(unix float64) time.Time {
	sec := int64(unix)
	nsec := int64((unix - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}

func parseFlexibleInt(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("missing")
	}
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, `"`) {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, err
		}
		return strconv.Atoi(strings.TrimSpace(text))
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func transportOfProto(proto string) string {
	p := strings.ToUpper(strings.TrimSpace(proto))
	p = strings.ReplaceAll(p, "_", "/")
	switch {
	case strings.Contains(p, "HTTP/3") || strings.HasPrefix(p, "H3"):
		return "udp"
	case strings.Contains(p, "HTTP/2") || strings.HasPrefix(p, "H2") || strings.Contains(p, "HTTP/1"):
		return "tcp"
	default:
		return ""
	}
}

func ValidIP(raw string) bool {
	return net.ParseIP(strings.TrimSpace(raw)) != nil
}
