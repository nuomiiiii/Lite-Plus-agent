package coreadapter

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func TestSingBoxContextOmitsTun(t *testing.T) {
	ctx := singBoxContext(context.Background())
	_, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"inbounds":[{"type":"tun","tag":"tun-in"}]}`))
	if err == nil {
		t.Fatal("tun inbound should not be linked")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tun") && !strings.Contains(strings.ToLower(err.Error()), "unknown") {
		t.Fatalf("want unknown tun, got %v", err)
	}
}

func TestSingBoxContextKeepsHysteria2(t *testing.T) {
	ctx := singBoxContext(context.Background())
	raw := []byte(`{"inbounds":[{"type":"hysteria2","tag":"hy2","listen":"127.0.0.1","listen_port":443}]}`)
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw); err != nil {
		t.Fatalf("hysteria2 must stay linked: %v", err)
	}
}

func TestSingBoxContextKeepsVLESS(t *testing.T) {
	ctx := singBoxContext(context.Background())
	raw := []byte(`{"inbounds":[{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":443,"users":[{"uuid":"11111111-1111-1111-1111-111111111111"}]}]}`)
	if _, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw); err != nil {
		t.Fatalf("vless must stay linked: %v", err)
	}
}
