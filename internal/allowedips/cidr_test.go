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
	got, err := Build([]string{"10.0.0.0/8"}, ips)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	want := []string{"10.0.0.0/8", "203.0.113.10/32", "203.0.113.11/32", "2001:db8::2/128"}
	gotStr := ToStrings(got)
	if len(gotStr) != len(want) {
		t.Fatalf("len = %d, want %d", len(gotStr), len(want))
	}
	for i := range want {
		if gotStr[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q", i, gotStr[i], want[i])
		}
	}
}
