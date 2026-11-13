package protection

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

var ErrSkip = errors.New("skip")

func IsSkip(err error) bool {
	return errors.Is(err, ErrSkip)
}

func parseSSHD(line string, now time.Time) (Record, error) {
	_, ident, msg, ts, err := splitSSHDLine(line, now)
	if err != nil {
		return Record{}, err
	}
	if !sshdIdent(ident) {
		return Record{}, ErrSkip
	}
	kind, user, ip := sshAuthFailure(msg)
	if kind == "" {
		return Record{}, ErrSkip
	}
	norm, ok := v2.NormalizeProtectionIP(ip)
	if !ok {
		return Record{}, fmt.Errorf("sshd invalid source ip")
	}
	return Record{
		Time:      ts,
		IP:        norm,
		Method:    kind,
		Path:      user,
		Transport: v2.FirewallProtoTCP,
	}, nil
}

func splitSSHDLine(line string, now time.Time) (host, ident, msg string, ts time.Time, err error) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "<") {
		if end := strings.IndexByte(line, '>'); end > 0 && end < 6 {
			line = strings.TrimSpace(line[end+1:])
		}
	}
	rest := line
	ts, rest, err = parseSSHDTimestamp(rest, now)
	if err != nil {
		return "", "", "", time.Time{}, ErrSkip
	}
	host, rest, err = splitIdent(rest)
	if err != nil {
		return "", "", "", time.Time{}, ErrSkip
	}
	ident, rest, err = splitIdent(rest)
	if err != nil {
		return "", "", "", time.Time{}, ErrSkip
	}
	ident = strings.TrimSuffix(ident, ":")
	if i := strings.IndexByte(ident, '['); i > 0 {
		ident = ident[:i]
	}
	msg = strings.TrimSpace(rest)
	msg = strings.TrimPrefix(msg, ": ")
	msg = strings.TrimPrefix(msg, ":")
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "", "", "", time.Time{}, ErrSkip
	}
	return host, ident, msg, ts, nil
}

func parseSSHDTimestamp(line string, now time.Time) (time.Time, string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return time.Time{}, "", ErrSkip
	}
	if ts, rest, ok := parseSSHDISOTimestamp(line); ok {
		return ts, rest, nil
	}
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return time.Time{}, "", ErrSkip
	}
	raw := fields[0] + " " + fields[1] + " " + fields[2]
	layouts := []string{"Jan _2 15:04:05", "Jan 2 15:04:05"}
	loc := now.Location()
	if loc == nil {
		loc = time.Local
	}
	year := now.Year()
	for _, layout := range layouts {
		ts, err := time.ParseInLocation(layout, raw, loc)
		if err != nil {
			continue
		}
		ts = ts.AddDate(year, 0, 0)
		if ts.After(now.Add(24 * time.Hour)) {
			ts = ts.AddDate(-1, 0, 0)
		}
		return ts, strings.Join(fields[3:], " "), nil
	}
	return time.Time{}, "", ErrSkip
}

func parseSSHDISOTimestamp(line string) (time.Time, string, bool) {
	sp := strings.IndexByte(line, ' ')
	if sp < 1 {
		return time.Time{}, "", false
	}
	raw := line[:sp]
	if !strings.Contains(raw, "T") {
		return time.Time{}, "", false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000000-07:00",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts, strings.TrimSpace(line[sp+1:]), true
		}
	}
	return time.Time{}, "", false
}

func sshdIdent(ident string) bool {
	ident = strings.ToLower(strings.TrimSpace(ident))
	return ident == "ssh" || ident == "sshd" || ident == "sshd-session"
}

func sshAuthFailure(msg string) (kind, user, ip string) {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "failed password"):
		kind = "password"
	case strings.Contains(lower, "failed keyboard-interactive"):
		kind = "keyboard-interactive"
	case strings.Contains(lower, "maximum authentication attempts exceeded"):
		kind = "max-attempts"
	default:
		return "", "", ""
	}
	user = sshAuthUser(msg)
	ip = sshAuthIP(msg)
	if ip == "" {
		return "", "", ""
	}
	return kind, user, ip
}

func sshAuthUser(msg string) string {
	lower := strings.ToLower(msg)
	const invalid = "invalid user "
	if i := strings.Index(lower, invalid); i >= 0 {
		return firstToken(msg[i+len(invalid):])
	}
	const forMark = " for "
	if i := strings.Index(lower, forMark); i >= 0 {
		rest := strings.TrimSpace(msg[i+len(forMark):])
		if strings.HasPrefix(strings.ToLower(rest), "invalid user ") {
			return firstToken(rest[len("invalid user "):])
		}
		tok := firstToken(rest)
		if tok != "" && tok != "from" {
			return tok
		}
	}
	return ""
}

func sshAuthIP(msg string) string {
	lower := strings.ToLower(msg)
	if i := strings.Index(lower, " rhost="); i >= 0 {
		return firstIPToken(msg[i+len(" rhost="):])
	}
	if i := strings.Index(lower, " from "); i >= 0 {
		return firstIPToken(msg[i+len(" from "):])
	}
	return ""
}

func firstToken(raw string) string {
	raw = strings.TrimSpace(raw)
	for i, r := range raw {
		if unicode.IsSpace(r) {
			return raw[:i]
		}
	}
	return raw
}

func firstIPToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	end := len(raw)
	for i, r := range raw {
		if unicode.IsSpace(r) || r == ']' {
			end = i
			break
		}
	}
	return strings.Trim(raw[:end], ",")
}
