// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRequiresDNSNames(t *testing.T) {
	cfg := AppConfig{}
	cfg.ApplyDefaults()
	cfg.Output.Mode = "stdout"
	cfg.Output.Format = "plain"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty dns names")
	}
}

func TestPeerTargetsFallsBackToLegacyFields(t *testing.T) {
	cfg := AppConfig{
		WireGuard:  WireGuardConfig{TargetPeerPublicKey: "KEY"},
		AllowedIPs: AllowedIPsConfig{Static: []string{"10.0.0.0/8"}, DNSNames: []string{"a.example.com"}},
	}
	targets := cfg.PeerTargets()
	if len(targets) != 1 || targets[0].PublicKey != "KEY" || targets[0].DNSNames[0] != "a.example.com" {
		t.Fatalf("unexpected legacy targets: %+v", targets)
	}
}

func TestPeerTargetsUsesPeersList(t *testing.T) {
	cfg := AppConfig{Peers: []PeerConfig{
		{PublicKey: "A", DNSNames: []string{"a.example.com"}},
		{PublicKey: "B", DNSNames: []string{"b.example.com"}},
	}}
	targets := cfg.PeerTargets()
	if len(targets) != 2 || targets[1].PublicKey != "B" {
		t.Fatalf("unexpected peer targets: %+v", targets)
	}
}

func TestValidateMultiPeerRequiresPublicKeyForUpdate(t *testing.T) {
	cfg := AppConfig{
		WireGuard: WireGuardConfig{ConfigPath: "/etc/wireguard/wg0.conf"},
		Peers:     []PeerConfig{{DNSNames: []string{"a.example.com"}}}, // no public_key
	}
	cfg.ApplyDefaults() // mode defaults to update-config
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for peer missing public_key in update-config mode")
	}
}

func TestValidateRejectsDuplicatePublicKeys(t *testing.T) {
	cfg := AppConfig{
		WireGuard: WireGuardConfig{ConfigPath: "/etc/wireguard/wg0.conf"},
		Peers: []PeerConfig{
			{PublicKey: "SAME_KEY", DNSNames: []string{"a.example.com"}},
			{PublicKey: "SAME_KEY", DNSNames: []string{"b.example.com"}},
		},
	}
	cfg.ApplyDefaults()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for duplicate peer public_key")
	}
	if !strings.Contains(err.Error(), "SAME_KEY") {
		t.Fatalf("error should name the duplicated key, got: %v", err)
	}
}

func TestLoadRoundTripsGeneratedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if _, err := InitConfigFileWith(path, ConfigTemplateData{
		WireGuardPath: "/etc/wireguard/wg0.conf",
		PeerPublicKey: "KEY",
		DNSNames:      []string{"a.example.com"},
	}); err != nil {
		t.Fatalf("InitConfigFileWith() error = %v", err)
	}
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.PeerTargets()[0].DNSNames; len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("round-trip dns_names = %v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config file missing: %v", err)
	}
}
