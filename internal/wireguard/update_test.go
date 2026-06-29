package wireguard

import (
	"strings"
	"testing"
)

func TestUpdatePeerAllowedIPs(t *testing.T) {
	input := `[Interface]
PrivateKey = REDACTED

[Peer]
PublicKey = TARGET
AllowedIPs = 10.0.0.0/8, 198.51.100.10/32
Endpoint = example.com:51820
`
	out, err := UpdatePeerAllowedIPs(input, "TARGET", []string{"10.0.0.0/8", "203.0.113.10/32"})
	if err != nil {
		t.Fatalf("UpdatePeerAllowedIPs() error = %v", err)
	}
	if !strings.Contains(out, "AllowedIPs = 10.0.0.0/8, 203.0.113.10/32") {
		t.Fatalf("updated config missing AllowedIPs line: %s", out)
	}
	if !strings.Contains(out, "PrivateKey = REDACTED") {
		t.Fatalf("interface section was not preserved: %s", out)
	}
}

func TestPeerAllowedIPs(t *testing.T) {
	input := `[Peer]
PublicKey = TARGET
AllowedIPs = 10.0.0.0/8, 198.51.100.10/32
`
	got, err := PeerAllowedIPs(input, "TARGET")
	if err != nil {
		t.Fatalf("PeerAllowedIPs() error = %v", err)
	}
	want := []string{"10.0.0.0/8", "198.51.100.10/32"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPeerAllowedIPsMissingPeerErrors(t *testing.T) {
	if _, err := PeerAllowedIPs("[Peer]\nPublicKey = OTHER\n", "TARGET"); err == nil {
		t.Fatal("expected error for missing target peer")
	}
}

func TestUpdatePeerAllowedIPsDuplicateTargetReturnsError(t *testing.T) {
	input := `[Peer]
PublicKey = TARGET

[Peer]
PublicKey = TARGET
`
	_, err := UpdatePeerAllowedIPs(input, "TARGET", []string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("expected duplicate target error")
	}
}
