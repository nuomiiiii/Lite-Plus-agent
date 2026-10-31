package monitoring

import (
	"net"
	"testing"
	"time"
)

func TestGetIPAddressCustomSkipsLookup(t *testing.T) {
	orig4, orig6 := flags.CustomIpv4, flags.CustomIpv6
	origNic := flags.GetIpAddrFromNic
	t.Cleanup(func() {
		flags.CustomIpv4 = orig4
		flags.CustomIpv6 = orig6
		flags.GetIpAddrFromNic = origNic
		publicIPCache.reset()
		nicIPCache.reset()
	})

	flags.GetIpAddrFromNic = false
	flags.CustomIpv4 = "203.0.113.9"
	flags.CustomIpv6 = "2001:db8::9"
	publicIPCache.reset()
	nicIPCache.reset()

	v4, v6, err := GetIPAddress()
	if err != nil {
		t.Fatal(err)
	}
	if v4 != "203.0.113.9" || v6 != "2001:db8::9" {
		t.Fatalf("GetIPAddress() = %s %s", v4, v6)
	}
}

func TestPublicIPCacheRetriesMissingFamilySoon(t *testing.T) {
	if publicIPCacheDuration(publicIPPair{v4: "203.0.113.9"}) != incompletePublicIPTTL {
		t.Fatal("v4-only must retry soon so a later v6 is not stuck for hours")
	}
	if publicIPCacheDuration(publicIPPair{v6: "2001:db8::9"}) != incompletePublicIPTTL {
		t.Fatal("v6-only must retry soon so a later v4 is not stuck for hours")
	}
	if publicIPCacheDuration(publicIPPair{v4: "203.0.113.9", v6: "2001:db8::9"}) != completePublicIPTTL {
		t.Fatal("a complete pair may cache longer")
	}
	if incompletePublicIPTTL >= time.Minute {
		t.Fatal("missing-family retry must be well under the old 6h public IP cache")
	}
}

func TestMergePublicIPKeepsLastGoodOnLookupMiss(t *testing.T) {
	got := mergePublicIP(publicIPPair{v4: "203.0.113.9", v6: "2001:db8::9"}, publicIPPair{v4: "203.0.113.10"})
	if got.v4 != "203.0.113.10" || got.v6 != "2001:db8::9" {
		t.Fatalf("mergePublicIP() = %+v", got)
	}
	got = mergePublicIP(publicIPPair{v4: "203.0.113.9"}, publicIPPair{v6: "2001:db8::2"})
	if got.v4 != "203.0.113.9" || got.v6 != "2001:db8::2" {
		t.Fatalf("mergePublicIP() missing family = %+v", got)
	}
}

func TestStacksFromLocalAddrsSkipLoopbackAndLinkLocal(t *testing.T) {
	v4, v6 := stacksFromLocalAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	})
	if v4 || v6 {
		t.Fatal("loopback and link-local must not count as a reported stack")
	}
	v4, v6 = stacksFromLocalAddrs([]net.Addr{
		&net.IPNet{IP: net.ParseIP("203.0.113.9"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8::9"), Mask: net.CIDRMask(64, 128)},
	})
	if !v4 || !v6 {
		t.Fatalf("global unicast must count, got v4=%v v6=%v", v4, v6)
	}
}

func TestCachedHostIdentityStable(t *testing.T) {
	osNameCache.reset()
	kernelCache.reset()
	if first, second := CachedOSName(), CachedOSName(); first == "" || first != second {
		t.Fatalf("CachedOSName %q vs %q", first, second)
	}
	if first, second := CachedKernelVersion(), CachedKernelVersion(); first != second {
		t.Fatalf("CachedKernelVersion %q vs %q", first, second)
	}
}
