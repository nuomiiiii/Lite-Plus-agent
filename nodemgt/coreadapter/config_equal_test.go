package coreadapter

import "testing"

func TestInboundSpecsEqualIgnoresTLSPointer(t *testing.T) {
	a := []InboundSpec{{ID: "in", Listen: "0.0.0.0", Port: 443, Protocol: "vless", SettingsJSON: `{"stack":"dual"}`}}
	b := []InboundSpec{{ID: "in", Listen: "0.0.0.0", Port: 443, Protocol: "vless", SettingsJSON: `{"stack":"dual"}`}}
	if !inboundSpecsEqual(a, b) {
		t.Fatal("equal specs compared unequal")
	}
	b[0].Port = 8443
	if inboundSpecsEqual(a, b) {
		t.Fatal("port change compared equal")
	}
}

func TestUserAuthEqualDetectsUsernameChange(t *testing.T) {
	a := []UserSpec{{ID: "u1", UUID: "alice", Username: "sms", Password: "pw"}}
	b := []UserSpec{{ID: "u1", UUID: "alice", Username: "node", Password: "pw"}}
	if userAuthEqual(a, b) {
		t.Fatal("http username change must restart the inbound account")
	}
}

func TestUserAuthEqualIgnoresQuotaAndRate(t *testing.T) {
	a := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 10, RateLimitBps: 1, DeviceLimit: 2}}
	b := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 99, RateLimitBps: 8, DeviceLimit: 0}}
	if !userAuthEqual(a, b) {
		t.Fatal("quota/rate/device should not force core restart")
	}
	b[0].UUID = "bob"
	if userAuthEqual(a, b) {
		t.Fatal("uuid change compared equal")
	}
}

func TestUserAuthEqualDetectsQuotaRestore(t *testing.T) {
	exhausted := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 64, UsedBytes: 64}}
	restored := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 64, UsedBytes: 0}}
	if userAuthEqual(exhausted, restored) {
		t.Fatal("quota restore should change auth membership")
	}
	used := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 64, UsedBytes: 10}}
	more := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 64, UsedBytes: 20}}
	if !userAuthEqual(used, more) {
		t.Fatal("usage inside quota should not force core restart")
	}
	stillDead := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw", QuotaBytes: 64, UsedBytes: 65}}
	if !userAuthEqual(exhausted, stillDead) {
		t.Fatal("still-exhausted usage should not force core restart")
	}
}

func TestRouteSpecsEqualIgnoresIDOrder(t *testing.T) {
	priorityOrder := []RouteSpec{
		{ID: "z-route", Priority: 10, RuleJSON: `{}`, Enabled: false},
		{ID: "a-route", Priority: 20, RuleJSON: `{}`, Enabled: false},
	}
	idOrder := []RouteSpec{priorityOrder[1], priorityOrder[0]}
	if !routeSpecsEqual(priorityOrder, append([]RouteSpec(nil), priorityOrder...)) {
		t.Fatal("identical route lists compared unequal")
	}
	if !routeSpecsEqual(priorityOrder, idOrder) {
		t.Fatal("same routes in non-id order compared unequal")
	}
	in := []InboundSpec{{ID: "in", Port: 1, Protocol: "socks"}}
	users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
	if coreShouldRestart(true, in, in, users, users, nil, nil, priorityOrder, idOrder) {
		t.Fatal("unchanged routes in non-id order should not restart")
	}
}

func TestCoreShouldRestartSkipsUnchangedRunningCore(t *testing.T) {
	in := []InboundSpec{{ID: "in", Port: 1, Protocol: "socks"}}
	users := []UserSpec{{ID: "u1", UUID: "alice", Password: "pw"}}
	if coreShouldRestart(true, in, in, users, users, nil, nil, nil, nil) {
		t.Fatal("running unchanged core should not restart")
	}
	if !coreShouldRestart(false, in, in, users, users, nil, nil, nil, nil) {
		t.Fatal("unstarted inbound still needs first start")
	}
	next := []InboundSpec{{ID: "in", Port: 2, Protocol: "socks"}}
	if !coreShouldRestart(true, next, in, users, users, nil, nil, nil, nil) {
		t.Fatal("changed inbound should restart")
	}
}
