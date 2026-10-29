package firewall

import (
	"testing"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func TestPlusRulesStaleDecision(t *testing.T) {
	tests := []struct {
		name          string
		kind          string
		leftoverPlus  bool
		hostOwns      bool
		iptablesLive  bool
		hasInetHooks  bool
		inetJumpLive  bool
		want          bool
	}{
		{
			name: "ufw host input is not a missing plus jump",
			kind: v2.FirewallBackendUFW,
			hostOwns: true,
			want: false,
		},
		{
			name: "ufw with inet filter missing plus jump is stale",
			kind: v2.FirewallBackendUFW,
			hasInetHooks: true,
			want: true,
		},
		{
			name: "ufw with inet filter plus jump is live",
			kind: v2.FirewallBackendUFW,
			hasInetHooks: true,
			inetJumpLive: true,
			want: false,
		},
		{
			name: "ufw still moves off a leftover plus table",
			kind: v2.FirewallBackendUFW,
			leftoverPlus: true,
			hostOwns: true,
			want: true,
		},
		{
			name: "iptables host without plus jump is stale",
			kind: v2.FirewallBackendIptables,
			hostOwns: true,
			want: true,
		},
		{
			name: "iptables host with plus jump is live",
			kind: v2.FirewallBackendIptables,
			hostOwns: true,
			iptablesLive: true,
			want: false,
		},
		{
			name: "firewalld missing plus jump is stale",
			kind: v2.FirewallBackendFirewalld,
			hostOwns: true,
			want: true,
		},
		{
			name: "nft inet input without plus jump is stale",
			kind: v2.FirewallBackendNFT,
			hasInetHooks: true,
			want: true,
		},
		{
			name: "nft inet input with plus jump is live",
			kind: v2.FirewallBackendNFT,
			hasInetHooks: true,
			inetJumpLive: true,
			want: false,
		},
		{
			name: "nft inet input with leftover plus table is stale",
			kind: v2.FirewallBackendNFT,
			leftoverPlus: true,
			hasInetHooks: true,
			inetJumpLive: true,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plusRulesStaleDecision(tt.kind, tt.leftoverPlus, tt.hostOwns, tt.iptablesLive, tt.hasInetHooks, tt.inetJumpLive)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
