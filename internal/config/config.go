package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	WireGuard  WireGuardConfig  `yaml:"wireguard"`
	AllowedIPs AllowedIPsConfig `yaml:"allowed_ips"`
	DNS        DNSConfig        `yaml:"dns"`
	Output     OutputConfig     `yaml:"output"`
}

type WireGuardConfig struct {
	ConfigPath          string `yaml:"config_path"`
	OutputPath          string `yaml:"output_path"`
	TargetPeerPublicKey string `yaml:"target_peer_public_key"`
	BackupDir           string `yaml:"backup_dir"`
	PreservePermissions bool   `yaml:"preserve_permissions"`
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
	Mode   string `yaml:"mode"`
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
	Sort   bool   `yaml:"sort"`
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
}

func (c AppConfig) Validate() error {
	if len(c.AllowedIPs.DNSNames) == 0 {
		return errors.New("allowed_ips.dns_names must not be empty")
	}
	for _, cidr := range c.AllowedIPs.Static {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid static CIDR %q: %w", cidr, err)
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
		if strings.TrimSpace(c.WireGuard.TargetPeerPublicKey) == "" {
			return errors.New("wireguard.target_peer_public_key is required for update-config mode")
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
  config_path: "/etc/wireguard/wg0.conf"
  output_path: ""
  target_peer_public_key: "REPLACE_WITH_PEER_PUBLIC_KEY"
  backup_dir: ""
  preserve_permissions: true

allowed_ips:
  static:
    - "10.0.0.0/8"
  dns_names:
    - "service-a.example.com"
    - "service-b.example.com"

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

func InitConfigFile(configPath, wgConfigPath, peerPublicKey string) (string, error) {
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
	content := defaultConfigTemplate
	if strings.TrimSpace(wgConfigPath) != "" {
		content = strings.Replace(content, "/etc/wireguard/wg0.conf", wgConfigPath, 1)
	}
	if strings.TrimSpace(peerPublicKey) != "" {
		content = strings.Replace(content, "REPLACE_WITH_PEER_PUBLIC_KEY", peerPublicKey, 1)
	}
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		return "", err
	}
	return configPath, nil
}
