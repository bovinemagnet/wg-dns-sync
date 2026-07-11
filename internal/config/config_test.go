// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigPath(t *testing.T) {
	path, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("DefaultConfigPath() error = %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("wg-dns-sync", "config.yaml")) {
		t.Fatalf("path = %q, want suffix wg-dns-sync/config.yaml", path)
	}
}

func TestEffectiveOutputPath(t *testing.T) {
	cfg := AppConfig{WireGuard: WireGuardConfig{ConfigPath: "/etc/wireguard/wg0.conf"}}
	if got := cfg.EffectiveOutputPath(); got != "/etc/wireguard/wg0.conf" {
		t.Fatalf("EffectiveOutputPath() = %q, want config_path fallback", got)
	}
	cfg.WireGuard.OutputPath = "/etc/wireguard/wg0.out.conf"
	if got := cfg.EffectiveOutputPath(); got != "/etc/wireguard/wg0.out.conf" {
		t.Fatalf("EffectiveOutputPath() = %q, want output_path override", got)
	}
}

func TestDNSLookupTimeout(t *testing.T) {
	cfg := AppConfig{DNS: DNSConfig{Timeout: "5s"}}
	got, err := cfg.DNSLookupTimeout()
	if err != nil {
		t.Fatalf("DNSLookupTimeout() error = %v", err)
	}
	if got.Seconds() != 5 {
		t.Fatalf("DNSLookupTimeout() = %v, want 5s", got)
	}
}

func TestApplyDefaultsSetsAggregateDefaults(t *testing.T) {
	cfg := AppConfig{Aggregate: AggregateConfig{Enabled: true}}
	cfg.ApplyDefaults()
	if cfg.Aggregate.MaxIPv4Prefix != 24 {
		t.Errorf("MaxIPv4Prefix = %d, want 24", cfg.Aggregate.MaxIPv4Prefix)
	}
	if cfg.Aggregate.MaxIPv6Prefix != 64 {
		t.Errorf("MaxIPv6Prefix = %d, want 64", cfg.Aggregate.MaxIPv6Prefix)
	}
}

func TestValidateRequiresDNSNames(t *testing.T) {
	cfg := AppConfig{}
	cfg.ApplyDefaults()
	cfg.Output.Mode = "stdout"
	cfg.Output.Format = "plain"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty dns names")
	}
}

// TestValidateAllowsStaticOnlyPeer confirms a peer whose AllowedIPs come
// entirely from static CIDRs (no DNS names) is a valid configuration.
// validConfig returns a config that passes Validate() outright, so each
// Validate error-path test can mutate a single field.
func validConfig() AppConfig {
	cfg := AppConfig{
		WireGuard:  WireGuardConfig{ConfigPath: "/etc/wireguard/wg0.conf", TargetPeerPublicKey: "KEY"},
		AllowedIPs: AllowedIPsConfig{DNSNames: []string{"a.example.com"}},
	}
	cfg.ApplyDefaults()
	return cfg
}

func TestValidateRejectsInvalidOutputMode(t *testing.T) {
	cfg := validConfig()
	cfg.Output.Mode = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid output.mode")
	}
}

func TestValidateRejectsInvalidOutputFormat(t *testing.T) {
	cfg := validConfig()
	cfg.Output.Format = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid output.format")
	}
}

func TestValidateCidrFileRequiresPath(t *testing.T) {
	cfg := validConfig()
	cfg.Output.Mode = "cidr-file"
	cfg.Output.Path = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when cidr-file mode has no output.path")
	}
}

func TestValidateRejectsInvalidDNSTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.DNS.Timeout = "not-a-duration"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid dns.timeout")
	}
}

func TestValidateRejectsNegativeRetries(t *testing.T) {
	cfg := validConfig()
	cfg.DNS.Retries = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative dns.retries")
	}
}

func TestValidateRejectsConcurrencyOutOfRange(t *testing.T) {
	cfg := validConfig()
	cfg.DNS.Concurrency = MaxDNSConcurrency + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for dns.concurrency above the maximum")
	}
}

func TestValidateRejectsInvalidFamily(t *testing.T) {
	cfg := validConfig()
	cfg.DNS.Families = []string{"ipv5"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid dns family")
	}
}

func TestValidateRejectsInvalidAggregatePrefixes(t *testing.T) {
	cfg := validConfig()
	cfg.Aggregate = AggregateConfig{Enabled: true, MaxIPv4Prefix: 33, MaxIPv6Prefix: 64}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for out-of-range aggregate.max_ipv4_prefix")
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("wireguard: [this is not valid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestInitConfigFileWithAppliesPlaceholderDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := InitConfigFileWith(path, ConfigTemplateData{DNSNames: []string{"a.example.com"}}); err != nil {
		t.Fatalf("InitConfigFileWith() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "/etc/wireguard/wg0.conf") {
		t.Errorf("expected placeholder wireguard path, got:\n%s", got)
	}
	if !strings.Contains(string(got), "REPLACE_WITH_PEER_PUBLIC_KEY") {
		t.Errorf("expected placeholder peer public key, got:\n%s", got)
	}
}

func TestInitConfigFileWithRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := ConfigTemplateData{WireGuardPath: "/etc/wireguard/wg0.conf", PeerPublicKey: "KEY", DNSNames: []string{"a.example.com"}}
	if _, err := InitConfigFileWith(path, data); err != nil {
		t.Fatalf("first InitConfigFileWith() error = %v", err)
	}
	if _, err := InitConfigFileWith(path, data); err == nil {
		t.Fatal("expected error when config file already exists")
	}
}

func TestValidateAllowsStaticOnlyPeer(t *testing.T) {
	cfg := AppConfig{
		WireGuard: WireGuardConfig{ConfigPath: "/etc/wireguard/wg0.conf"},
		Peers: []PeerConfig{
			{PublicKey: "KEY_STATIC", Static: []string{"10.0.0.0/8"}},
		},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected static-only peer to validate, got: %v", err)
	}
}

func TestValidateRejectsPeerWithNeitherDNSNorStatic(t *testing.T) {
	cfg := AppConfig{
		Peers: []PeerConfig{{PublicKey: "KEY"}},
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for peer with neither dns_names nor static")
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
