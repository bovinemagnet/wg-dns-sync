package allowedips

import (
	"net/netip"
	"testing"
)

func TestBuildDedupAndSort(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("203.0.113.11"),
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("203.0.113.11"),
	}
	got, err := Build([]string{"10.0.0.0/8"}, ips, true)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	want := []string{"10.0.0.0/8", "203.0.113.10/32", "203.0.113.11/32", "2001:db8::2/128"}
	assertOrder(t, ToStrings(got), want)
}

func TestBuildPreservesOrderWhenUnsorted(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.11"),
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("203.0.113.11"),
	}
	got, err := Build([]string{"10.0.0.0/8"}, ips, false)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	want := []string{"10.0.0.0/8", "203.0.113.11/32", "203.0.113.10/32"}
	assertOrder(t, ToStrings(got), want)
}

func TestAggregateSummarisesHostRoutes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"),
		netip.MustParsePrefix("203.0.113.20/32"),
		netip.MustParsePrefix("10.0.0.0/8"),      // already broader than /24 — unchanged
		netip.MustParsePrefix("2001:db8::1/128"), // -> /64
	}
	got := Aggregate(in, 24, 64, true)
	want := []string{"10.0.0.0/8", "203.0.113.0/24", "2001:db8::/64"}
	assertOrder(t, ToStrings(got), want)
}

func TestAggregateLeavesShorterPrefixesAlone(t *testing.T) {
	in := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	got := Aggregate(in, 24, 64, true)
	if len(got) != 1 || got[0].String() != "192.168.0.0/16" {
		t.Fatalf("got %v, want [192.168.0.0/16]", ToStrings(got))
	}
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}
