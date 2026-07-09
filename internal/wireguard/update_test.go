// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

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

func TestUpdatePeerAllowedIPsPreservesCRLF(t *testing.T) {
	input := "[Interface]\r\nPrivateKey = X\r\n\r\n[Peer]\r\nPublicKey = TARGET\r\nAllowedIPs = 10.0.0.0/8\r\nPersistentKeepalive = 25\r\n"
	out, err := UpdatePeerAllowedIPs(input, "TARGET", []string{"203.0.113.10/32"})
	if err != nil {
		t.Fatalf("UpdatePeerAllowedIPs() error = %v", err)
	}
	// After stripping CRLF pairs, no bare LF should remain (no mixed endings).
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatalf("output contains a bare LF (mixed line endings):\n%q", out)
	}
	if !strings.Contains(out, "AllowedIPs = 203.0.113.10/32\r\n") {
		t.Fatalf("rewritten AllowedIPs line lost its CRLF:\n%q", out)
	}
}

// TestUpdatePeerAllowedIPsInsertsBeforeTrailingCommentBlock guards against
// inserting a missing AllowedIPs line immediately before the next peer's
// section header, which lands it visually under any blank line and comment
// that precede that header and belong to the next peer.
func TestUpdatePeerAllowedIPsInsertsBeforeTrailingCommentBlock(t *testing.T) {
	input := `[Peer]
PublicKey = TARGET
Endpoint = example.com:51820

# Peer B - laptop
[Peer]
PublicKey = OTHER
AllowedIPs = 10.9.9.9/32
`
	out, err := UpdatePeerAllowedIPs(input, "TARGET", []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("UpdatePeerAllowedIPs() error = %v", err)
	}
	want := `[Peer]
PublicKey = TARGET
Endpoint = example.com:51820
AllowedIPs = 10.0.0.0/8

# Peer B - laptop
[Peer]
PublicKey = OTHER
AllowedIPs = 10.9.9.9/32
`
	if out != want {
		t.Fatalf("AllowedIPs inserted in the wrong place:\ngot:\n%q\nwant:\n%q", out, want)
	}
}

// TestUpdatePeerAllowedIPsToleratesStrayCRLF guards against detectNewline
// switching the whole file to CRLF splitting because of a single stray CRLF
// line ending (e.g. a comment pasted from a Windows editor) in an otherwise
// LF-terminated file — that misdetection breaks section parsing entirely.
func TestUpdatePeerAllowedIPsToleratesStrayCRLF(t *testing.T) {
	input := "[Interface]\nPrivateKey = X\r\n\n[Peer]\nPublicKey = TARGET\nAllowedIPs = 10.0.0.0/8\nEndpoint = example.com:51820\n"
	out, err := UpdatePeerAllowedIPs(input, "TARGET", []string{"203.0.113.10/32"})
	if err != nil {
		t.Fatalf("UpdatePeerAllowedIPs() error = %v", err)
	}
	if !strings.Contains(out, "AllowedIPs = 203.0.113.10/32\n") {
		t.Fatalf("predominantly-LF file with a stray CRLF was not updated correctly, got:\n%q", out)
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
