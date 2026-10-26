package coreadapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrCoreNotLinked = errors.New("core library is not linked into this Agent build")

type InboundSpec struct {
	ID           string
	Core         string
	Listen       string
	Port         int
	Protocol     string
	TLS          *tls.Config
	CertPEM      string
	KeyPEM       string
	StreamJSON   string
	SettingsJSON string
	Flow         string
}

type OutboundSpec struct {
	ID           string
	Name         string
	Protocol     string
	SettingsJSON string
	Enabled      bool
}

type RouteSpec struct {
	ID       string
	Name     string
	Priority int
	RuleJSON string
	Enabled  bool
}

type UserSpec struct {
	ID            string
	UUID          string
	Username      string
	Password      string
	QuotaBytes    int64
	UsedBytes     int64
	RateLimitBps  int64
	DeviceLimit   int // unique client IP cap; 0 = unlimited. not a device/session cap.
	Disabled      bool
	Expired       bool
	Flow          string
	ExpiresAt     *time.Time
	CredExpiresAt *time.Time
	InboundIDs    []string
}

type Snapshot struct {
	UserID string
	Bytes  int64
}

type PresenceIP struct {
	IP     string
	SeenAt time.Time
}

type Presence struct {
	UserID string
	Online bool
	IPs    []PresenceIP
}

type Core interface {
	Name() string
	Version() string
	Linked() bool
	Start(ctx context.Context, inbounds []InboundSpec) error
	Stop() error
	ApplyUsers(users []UserSpec) error
	CloseUserSessions(userID string) error
	TakeSnapshots() []Snapshot
	AcknowledgeUsage()
	Presence() []Presence
}

func All() []Core {
	return []Core{NewXray(), NewSingBox()}
}

func userLive(u UserSpec) bool {
	if u.Disabled || u.Expired {
		return false
	}
	if u.ExpiresAt != nil && !u.ExpiresAt.After(time.Now().UTC()) {
		return false
	}
	if u.CredExpiresAt != nil && !u.CredExpiresAt.After(time.Now().UTC()) {
		return false
	}
	if u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes {
		return false
	}
	return true
}

func applyDenied(users []UserSpec, denied map[string]struct{}) []UserSpec {
	out := append([]UserSpec(nil), users...)
	for i := range out {
		if _, ok := denied[out[i].ID]; ok {
			out[i].Disabled = true
		}
	}
	return out
}

func markDenied(users []UserSpec, userID string) []UserSpec {
	out := append([]UserSpec(nil), users...)
	for i := range out {
		if out[i].ID == userID {
			out[i].Disabled = true
		}
	}
	return out
}

func inboundAuthEmpty(granted []UserSpec) bool {
	return len(granted) == 0
}

func inboundAccountID(proto, inboundID, user string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "socks", "mixed":
		proto = "socks"
	default:
		proto = "http"
	}
	return proto + "-acct:" + strings.TrimSpace(inboundID) + ":" + user
}

func inboundSettingsAccounts(in InboundSpec) []UserSpec {
	var s struct {
		Accounts []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"accounts"`
	}
	if strings.TrimSpace(in.SettingsJSON) != "" {
		_ = json.Unmarshal([]byte(in.SettingsJSON), &s)
	}
	out := make([]UserSpec, 0, len(s.Accounts))
	for _, row := range s.Accounts {
		user := strings.TrimSpace(row.User)
		pass := strings.TrimSpace(row.Pass)
		if user == "" || pass == "" {
			continue
		}
		out = append(out, UserSpec{
			ID:         inboundAccountID(in.Protocol, in.ID, user),
			Username:   user,
			Password:   pass,
			InboundIDs: []string{strings.TrimSpace(in.ID)},
		})
	}
	return out
}

func inboundAllowTransparent(in InboundSpec) bool {
	var s struct {
		AllowTransparent bool `json:"allow_transparent"`
	}
	if strings.TrimSpace(in.SettingsJSON) == "" {
		return false
	}
	_ = json.Unmarshal([]byte(in.SettingsJSON), &s)
	return s.AllowTransparent
}

func userLoginNames(u UserSpec) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	add(u.Username)
	add(u.UUID)
	return out
}

func mergeInboundAccountUsers(users []UserSpec, inbounds []InboundSpec) []UserSpec {
	out := append([]UserSpec(nil), users...)
	seen := map[string]struct{}{}
	mark := func(inboundID, name string) {
		inboundID = strings.TrimSpace(inboundID)
		name = strings.TrimSpace(name)
		if inboundID == "" || name == "" {
			return
		}
		seen[inboundID+"\x00"+name] = struct{}{}
	}
	for _, u := range users {
		names := userLoginNames(u)
		for _, in := range inbounds {
			if !grantedOn(u, in.ID) {
				continue
			}
			for _, name := range names {
				mark(in.ID, name)
			}
		}
	}
	for _, in := range inbounds {
		proto := strings.ToLower(strings.TrimSpace(in.Protocol))
		if proto != "http" && proto != "socks" && proto != "mixed" {
			continue
		}
		for _, acct := range inboundSettingsAccounts(in) {
			key := strings.TrimSpace(in.ID) + "\x00" + acct.Username
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, acct)
		}
	}
	return out
}

func liveUsers(users []UserSpec, denied map[string]struct{}, inbounds []InboundSpec) []UserSpec {
	return mergeInboundAccountUsers(applyDenied(users, denied), inbounds)
}

func usersForInbound(users []UserSpec, inboundID string) []UserSpec {
	out := make([]UserSpec, 0, len(users))
	for _, u := range users {
		if !userLive(u) {
			continue
		}
		if !grantedOn(u, inboundID) {
			continue
		}
		out = append(out, u)
	}
	return out
}

func grantedOn(u UserSpec, inboundID string) bool {
	if u.InboundIDs == nil {
		return true
	}
	for _, id := range u.InboundIDs {
		if id == inboundID {
			return true
		}
	}
	return false
}

func socksIdentity(u UserSpec) (user, pass string, ok bool) {
	user = strings.TrimSpace(u.UUID)
	pass = strings.TrimSpace(u.Password)
	if pass == "" {
		pass = user
	}
	if user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

func httpIdentity(u UserSpec) (user, pass string, ok bool) {
	user = strings.TrimSpace(u.Username)
	if user == "" {
		user = strings.TrimSpace(u.UUID)
	}
	pass = strings.TrimSpace(u.Password)
	if pass == "" {
		pass = strings.TrimSpace(u.UUID)
	}
	if user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

func proxyAccounts(u UserSpec) []map[string]string {
	_, pass, ok := socksIdentity(u)
	if !ok {
		if _, pass, ok = httpIdentity(u); !ok {
			return nil
		}
	}
	seen := map[string]bool{}
	var out []map[string]string
	add := func(user string) {
		user = strings.TrimSpace(user)
		if user == "" || seen[user] {
			return
		}
		seen[user] = true
		out = append(out, map[string]string{"user": user, "pass": pass})
	}
	add(u.Username)
	add(u.UUID)
	return out
}

func proxyAuthUsers(u UserSpec) []map[string]string {
	accounts := proxyAccounts(u)
	out := make([]map[string]string, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, map[string]string{"username": a["user"], "password": a["pass"]})
	}
	return out
}

func indexLoginNames(u UserSpec, dest map[string]UserSpec) {
	if dest == nil {
		return
	}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" {
			dest[name] = u
		}
	}
	if user, _, ok := socksIdentity(u); ok {
		add(user)
	}
	add(u.Username)
}

func vlessUUID(u UserSpec) string {
	id := strings.TrimSpace(u.UUID)
	if len(id) != 36 {
		return ""
	}
	return id
}

func splitPEM(block string) []string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(block), "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func coreInbounds(name string, inbounds []InboundSpec) []InboundSpec {
	out := make([]InboundSpec, 0, len(inbounds))
	for _, in := range inbounds {
		if in.Core == "" || in.Core == name {
			out = append(out, in)
		}
	}
	return out
}
