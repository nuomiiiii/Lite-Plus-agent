package coreadapter

import "testing"

func TestInboundAccountIDUsesProtocolPrefix(t *testing.T) {
	httpID := inboundAccountID("http", "in1", "sms")
	socksID := inboundAccountID("socks", "in1", "sms")
	mixedID := inboundAccountID("mixed", "in1", "sms")
	if httpID != "http-acct:in1:sms" {
		t.Fatalf("http id %s", httpID)
	}
	if socksID != "socks-acct:in1:sms" || mixedID != "socks-acct:in1:sms" {
		t.Fatalf("socks id %s mixed %s", socksID, mixedID)
	}
}

func TestMergeKeepsInboundAccountWhenUsernameUsedOnOtherInbound(t *testing.T) {
	users := []UserSpec{{
		ID: "u1", Username: "sms", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Password: "node", InboundIDs: []string{"vless1"},
	}}
	inbounds := []InboundSpec{
		{ID: "vless1", Protocol: "vless"},
		{ID: "http1", Protocol: "http", SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`},
	}
	live := liveUsers(users, nil, inbounds)
	found := false
	for _, u := range live {
		if u.ID == "http-acct:http1:sms" && u.Password == "secret1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing http inbound account in %#v", live)
	}
}

func TestMergeSkipsInboundAccountWhenSameInboundAlreadyHasUsername(t *testing.T) {
	users := []UserSpec{{
		ID: "u1", Username: "sms", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Password: "node", InboundIDs: []string{"http1"},
	}}
	inbounds := []InboundSpec{
		{ID: "http1", Protocol: "http", SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`},
	}
	live := liveUsers(users, nil, inbounds)
	for _, u := range live {
		if u.ID == "http-acct:http1:sms" {
			t.Fatalf("duplicate inbound account %#v", u)
		}
	}
}

func TestMergeSOCKSSettingsAccountID(t *testing.T) {
	live := liveUsers(nil, nil, []InboundSpec{{
		ID: "socks1", Protocol: "socks",
		SettingsJSON: `{"accounts":[{"user":"sms","pass":"secret1"}]}`,
	}})
	if len(live) != 1 || live[0].ID != "socks-acct:socks1:sms" {
		t.Fatalf("socks account %#v", live)
	}
}
