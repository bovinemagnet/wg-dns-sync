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

func TestUpdatePeerAllowedIPsDuplicateTargetFails(t *testing.T) {
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
