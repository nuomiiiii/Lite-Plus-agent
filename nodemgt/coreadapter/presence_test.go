package coreadapter

import (
	"testing"
	"time"

	"github.com/nuomiiiii/lite-agent/nodemgt/sessions"
)

func TestPolicyPresenceReportsOnlyLiveIPs(t *testing.T) {
	p := &policyEngine{
		sess: sessions.New(),
		seen: map[string]map[string]time.Time{},
	}
	p.noteIP("u1", "203.0.113.10")
	rows := p.presence()
	if len(rows) != 1 || rows[0].UserID != "u1" {
		t.Fatalf("historical user %+v", rows)
	}
	if rows[0].Online || len(rows[0].IPs) != 0 {
		t.Fatalf("history must not stay online %+v", rows[0])
	}
	p.trackSession(&sessions.Session{ID: "s1", UserID: "u1", IP: "203.0.113.10"})
	rows = p.presence()
	if len(rows) != 1 || !rows[0].Online || len(rows[0].IPs) != 1 || rows[0].IPs[0].IP != "203.0.113.10" {
		t.Fatalf("live ip %+v", rows)
	}
	p.sess.Remove("s1")
	rows = p.presence()
	if len(rows) != 1 || rows[0].Online || len(rows[0].IPs) != 0 {
		t.Fatalf("disconnect must drop ip %+v", rows)
	}
	if len(p.presence()) != 0 {
		t.Fatalf("offline user should leave presence after prune %+v", p.presence())
	}
}

func TestPolicyPresenceIncludesCoreHeldIPs(t *testing.T) {
	p := &policyEngine{
		sess: sessions.New(),
		ips:  newIPGuard(),
		seen: map[string]map[string]time.Time{},
	}
	if !p.holdIP("u1", "203.0.113.10", 0) {
		t.Fatal("hold unlimited")
	}
	rows := p.presence()
	if len(rows) != 1 || rows[0].UserID != "u1" || !rows[0].Online || len(rows[0].IPs) != 1 || rows[0].IPs[0].IP != "203.0.113.10" {
		t.Fatalf("core-held ip %+v", rows)
	}
	p.trackSession(&sessions.Session{ID: "exit", UserID: "u1", HideIP: true})
	rows = p.presence()
	if len(rows) != 1 || !rows[0].Online || len(rows[0].IPs) != 1 || rows[0].IPs[0].IP != "203.0.113.10" {
		t.Fatalf("policy-exit hideip must not replace core ip %+v", rows)
	}
	p.releaseIP("u1", "203.0.113.10")
	p.sess.Remove("exit")
	rows = p.presence()
	if len(rows) != 1 || rows[0].Online || len(rows[0].IPs) != 0 {
		t.Fatalf("release must drop ip %+v", rows)
	}
	if leftover := p.presence(); len(leftover) != 0 {
		t.Fatalf("offline user should leave presence after prune %+v", leftover)
	}
}
