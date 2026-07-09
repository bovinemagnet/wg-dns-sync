// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	WireGuard  WireGuardConfig  `yaml:"wireguard"`
	AllowedIPs AllowedIPsConfig `yaml:"allowed_ips"`
	Peers      []PeerConfig     `yaml:"peers"`
	DNS        DNSConfig        `yaml:"dns"`
	Aggregate  AggregateConfig  `yaml:"aggregate"`
	Output     OutputConfig     `yaml:"output"`
}

// AggregateConfig optionally summarises generated host routes into larger
// prefixes. It applies to every peer's computed AllowedIPs set. Off by default
// because over-broad routes can be dangerous.
type AggregateConfig struct {
	Enabled       bool `yaml:"enabled"`
	MaxIPv4Prefix int  `yaml:"max_ipv4_prefix"`
	MaxIPv6Prefix int  `yaml:"max_ipv6_prefix"`
}

// PeerConfig describes one peer to update when the optional top-level `peers`
// list is used. When `peers` is empty the tool falls back to the single-peer
// fields (wireguard.target_peer_public_key + allowed_ips).
type PeerConfig struct {
	PublicKey string   `yaml:"public_key"`
	Static    []string `yaml:"static"`
	DNSNames  []string `yaml:"dns_names"`
}

// PeerTarget is the normalised, internal view of a peer to update, regardless of
// whether the config used the single-peer fields or the `peers` list.
type PeerTarget struct {
	PublicKey string
	Static    []string
	DNSNames  []string
}

type WireGuardConfig struct {
	ConfigPath          string `yaml:"config_path"`
	OutputPath          string `yaml:"output_path"`
	TargetPeerPublicKey string `yaml:"target_peer_public_key"`
	BackupDir           string `yaml:"backup_dir"`
	PreservePermissions bool   `yaml:"preserve_permissions"`
	Interface           string `yaml:"interface"`
	Sync                bool   `yaml:"sync"`
}

type AllowedIPsConfig struct {
	Static   []string `yaml:"static"`
	DNSNames []string `yaml:"dns_names"`
}

type DNSConfig struct {
	Concurrency       int      `yaml:"concurrency"`
	Timeout           string   `yaml:"timeout"`
	Retries           int      `yaml:"retries"`
	Families          []string `yaml:"families"`
	FailOnLookupError bool     `yaml:"fail_on_lookup_error"`
}

type OutputConfig struct {
	Mode        string `yaml:"mode"`
	Path        string `yaml:"path"`
	Format      string `yaml:"format"`
	Sort        bool   `yaml:"sort"`
	MetricsPath string `yaml:"metrics_path"`
}

const (
	MinDNSConcurrency = 1
	MaxDNSConcurrency = 32
)

func DefaultConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "wg-dns-sync", "config.yaml"), nil
}

func Load(path string) (AppConfig, string, error) {
	if path == "" {
		defaultPath, err := DefaultConfigPath()
		if err != nil {
			return AppConfig{}, "", err
		}
		path = defaultPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return AppConfig{}, path, err
	}

	cfg := AppConfig{
		WireGuard: WireGuardConfig{PreservePermissions: true},
		DNS:       DNSConfig{Retries: 1, FailOnLookupError: true},
		Output:    OutputConfig{Sort: true},
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return AppConfig{}, path, err
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return AppConfig{}, path, err
	}
	return cfg, path, nil
}

func (c *AppConfig) ApplyDefaults() {
	if c.DNS.Concurrency == 0 {
		c.DNS.Concurrency = 6
	}
	if c.DNS.Timeout == "" {
		c.DNS.Timeout = "3s"
	}
	if len(c.DNS.Families) == 0 {
		c.DNS.Families = []string{"ipv4"}
	}
	if c.Output.Mode == "" {
		c.Output.Mode = "update-config"
	}
	if c.Output.Format == "" {
		c.Output.Format = "wireguard"
	}
	if c.Aggregate.Enabled {
		if c.Aggregate.MaxIPv4Prefix == 0 {
			c.Aggregate.MaxIPv4Prefix = 24
		}
		if c.Aggregate.MaxIPv6Prefix == 0 {
			c.Aggregate.MaxIPv6Prefix = 64
		}
	}
}

// PeerTargets normalises the config into the list of peers to update. With a
// `peers` list it returns one target per entry; otherwise it returns a single
// target synthesised from the legacy single-peer fields.
func (c AppConfig) PeerTargets() []PeerTarget {
	if len(c.Peers) > 0 {
		out := make([]PeerTarget, len(c.Peers))
		for i, p := range c.Peers {
			out[i] = PeerTarget{PublicKey: p.PublicKey, Static: p.Static, DNSNames: p.DNSNames}
		}
		return out
	}
	return []PeerTarget{{
		PublicKey: c.WireGuard.TargetPeerPublicKey,
		Static:    c.AllowedIPs.Static,
		DNSNames:  c.AllowedIPs.DNSNames,
	}}
}

func (c AppConfig) dnsNamesField(i int) string {
	if len(c.Peers) > 0 {
		return fmt.Sprintf("peers[%d].dns_names", i)
	}
	return "allowed_ips.dns_names"
}

func (c AppConfig) publicKeyField(i int) string {
	if len(c.Peers) > 0 {
		return fmt.Sprintf("peers[%d].public_key", i)
	}
	return "wireguard.target_peer_public_key"
}

func (c AppConfig) Validate() error {
	targets := c.PeerTargets()
	seenKeys := map[string]int{}
	for i, t := range targets {
		if len(t.DNSNames) == 0 {
			return fmt.Errorf("%s must not be empty", c.dnsNamesField(i))
		}
		for _, cidr := range t.Static {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("invalid static CIDR %q: %w", cidr, err)
			}
		}
		if key := strings.TrimSpace(t.PublicKey); key != "" {
			if j, ok := seenKeys[key]; ok {
				return fmt.Errorf("duplicate public_key %q: %s and %s target the same peer", key, c.publicKeyField(j), c.publicKeyField(i))
			}
			seenKeys[key] = i
		}
	}
	if c.DNS.Concurrency < MinDNSConcurrency || c.DNS.Concurrency > MaxDNSConcurrency {
		return fmt.Errorf("dns.concurrency must be between %d and %d", MinDNSConcurrency, MaxDNSConcurrency)
	}
	if c.DNS.Retries < 0 {
		return errors.New("dns.retries must be >= 0")
	}
	if _, err := time.ParseDuration(c.DNS.Timeout); err != nil {
		return fmt.Errorf("invalid dns.timeout: %w", err)
	}
	if len(c.DNS.Families) == 0 {
		return errors.New("dns.families must not be empty")
	}
	seenFamily := map[string]struct{}{}
	for _, family := range c.DNS.Families {
		n := strings.ToLower(strings.TrimSpace(family))
		if n != "ipv4" && n != "ipv6" {
			return fmt.Errorf("invalid dns family %q", family)
		}
		seenFamily[n] = struct{}{}
	}
	if len(seenFamily) == 0 {
		return errors.New("dns.families must include ipv4 and/or ipv6")
	}

	if c.Aggregate.Enabled {
		if c.Aggregate.MaxIPv4Prefix < 1 || c.Aggregate.MaxIPv4Prefix > 32 {
			return fmt.Errorf("aggregate.max_ipv4_prefix must be between 1 and 32")
		}
		if c.Aggregate.MaxIPv6Prefix < 1 || c.Aggregate.MaxIPv6Prefix > 128 {
			return fmt.Errorf("aggregate.max_ipv6_prefix must be between 1 and 128")
		}
	}

	switch c.Output.Mode {
	case "stdout", "cidr-file", "update-config":
	default:
		return fmt.Errorf("invalid output.mode %q", c.Output.Mode)
	}
	switch c.Output.Format {
	case "plain", "wireguard", "json":
	default:
		return fmt.Errorf("invalid output.format %q", c.Output.Format)
	}
	if c.Output.Mode == "cidr-file" && strings.TrimSpace(c.Output.Path) == "" {
		return errors.New("output.path is required when output.mode is cidr-file")
	}
	if c.Output.Mode == "update-config" {
		if strings.TrimSpace(c.WireGuard.ConfigPath) == "" {
			return errors.New("wireguard.config_path is required for update-config mode")
		}
		for i, t := range targets {
			if strings.TrimSpace(t.PublicKey) == "" {
				return fmt.Errorf("%s is required for update-config mode", c.publicKeyField(i))
			}
		}
	}
	return nil
}

func (c AppConfig) DNSLookupTimeout() (time.Duration, error) {
	return time.ParseDuration(c.DNS.Timeout)
}

func (c AppConfig) EffectiveOutputPath() string {
	if strings.TrimSpace(c.WireGuard.OutputPath) != "" {
		return c.WireGuard.OutputPath
	}
	return c.WireGuard.ConfigPath
}

const defaultConfigTemplate = `wireguard:
  config_path: "{{ .WireGuardPath }}"
  output_path: ""
  target_peer_public_key: "{{ .PeerPublicKey }}"
  backup_dir: ""
  preserve_permissions: true

allowed_ips:
  static:
{{- range .Static }}
    - "{{ . }}"
{{- end }}
  dns_names:
{{- range .DNSNames }}
    - "{{ . }}"
{{- end }}

dns:
  concurrency: 6
  timeout: "3s"
  retries: 1
  families:
    - "ipv4"
  fail_on_lookup_error: true

output:
  mode: "update-config"
  format: "wireguard"
  sort: true
`

// ConfigTemplateData is the data used to render a starter config file.
type ConfigTemplateData struct {
	WireGuardPath string
	PeerPublicKey string
	Static        []string
	DNSNames      []string
}

// InitConfigFile writes a starter config using example static CIDRs and DNS
// names. wgConfigPath and peerPublicKey fall back to placeholders when empty.
func InitConfigFile(configPath, wgConfigPath, peerPublicKey string) (string, error) {
	return InitConfigFileWith(configPath, ConfigTemplateData{
		WireGuardPath: wgConfigPath,
		PeerPublicKey: peerPublicKey,
		Static:        []string{"10.0.0.0/8"},
		DNSNames:      []string{"service-a.example.com", "service-b.example.com"},
	})
}

// InitConfigFileWith writes a starter config from the supplied data. It creates
// the parent directory, refuses to overwrite an existing config, and applies
// placeholder defaults for an empty WireGuard path or peer key.
func InitConfigFileWith(configPath string, data ConfigTemplateData) (string, error) {
	if strings.TrimSpace(configPath) == "" {
		var err error
		configPath, err = DefaultConfigPath()
		if err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return "", err
	}
	if _, err := os.Stat(configPath); err == nil {
		return "", fmt.Errorf("config already exists: %s", configPath)
	}
	if strings.TrimSpace(data.WireGuardPath) == "" {
		data.WireGuardPath = "/etc/wireguard/wg0.conf"
	}
	if strings.TrimSpace(data.PeerPublicKey) == "" {
		data.PeerPublicKey = "REPLACE_WITH_PEER_PUBLIC_KEY"
	}
	tmpl, err := template.New("default-config").Parse(defaultConfigTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	if err := os.WriteFile(configPath, buf.Bytes(), 0o600); err != nil {
		return "", err
	}
	return configPath, nil
}
