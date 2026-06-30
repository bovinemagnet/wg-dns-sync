// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bovinemagnet/wg-dns-sync/internal/config"
	"github.com/bovinemagnet/wg-dns-sync/internal/dns"
	"github.com/bovinemagnet/wg-dns-sync/internal/wgsync"
)

// fakeResolver returns canned answers so command tests never touch real DNS.
type fakeResolver struct {
	data map[string][]net.IPAddr
	errs map[string]error
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	if ips, ok := f.data[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

func ipv4(addrs ...string) []net.IPAddr {
	out := make([]net.IPAddr, len(addrs))
	for i, a := range addrs {
		out[i] = net.IPAddr{IP: net.ParseIP(a)}
	}
	return out
}

type configOpts struct {
	mode              string
	format            string
	wgPath            string
	failOnLookupError bool
}

func writeConfig(t *testing.T, opts configOpts) string {
	t.Helper()
	if opts.mode == "" {
		opts.mode = "stdout"
	}
	if opts.format == "" {
		opts.format = "plain"
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`wireguard:
  config_path: '%s'
  target_peer_public_key: "TARGET_PUBLIC_KEY"
  preserve_permissions: true
allowed_ips:
  static:
    - "10.0.0.0/8"
  dns_names:
    - "service-a.example.com"
    - "service-b.example.com"
dns:
  concurrency: 4
  timeout: "1s"
  retries: 0
  families:
    - "ipv4"
  fail_on_lookup_error: %t
output:
  mode: "%s"
  format: "%s"
  sort: true
`, opts.wgPath, opts.failOnLookupError, opts.mode, opts.format)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// run executes the CLI with an injected resolver, capturing stdout and stderr.
func run(resolver dns.IPResolver, args ...string) (stdout, stderr string, err error) {
	return runWithSyncer(resolver, nil, args...)
}

// runWithSyncer is like run but also injects a wg syncconf runner.
func runWithSyncer(resolver dns.IPResolver, syncer wgsync.Syncer, args ...string) (stdout, stderr string, err error) {
	root := newRootCommand(resolver, syncer)
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errb.String(), err
}

// fakeSyncer records Sync calls instead of shelling out.
type fakeSyncer struct {
	calls      int
	iface      string
	configPath string
	err        error
}

func (f *fakeSyncer) Sync(_ context.Context, iface, configPath string) error {
	f.calls++
	f.iface = iface
	f.configPath = configPath
	return f.err
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var exitErr ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error is not an ExitError: %v", err)
	}
	return exitErr.Code
}

func TestResolveUniqueIPv4(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	cfg := writeConfig(t, configOpts{})

	out, _, err := run(resolver, "resolve", "--config", cfg)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	want := "10.0.0.0/8\n203.0.113.10/32\n203.0.113.11/32\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestResolveDeduplicatesIPv4(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.10"),
	}}
	cfg := writeConfig(t, configOpts{})

	out, _, err := run(resolver, "resolve", "--config", cfg)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	want := "10.0.0.0/8\n203.0.113.10/32\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestResolveSingleFailureFailsRun(t *testing.T) {
	resolver := fakeResolver{
		data: map[string][]net.IPAddr{"service-a.example.com": ipv4("203.0.113.10")},
		errs: map[string]error{"service-b.example.com": errors.New("timeout")},
	}
	cfg := writeConfig(t, configOpts{failOnLookupError: true})

	_, _, err := run(resolver, "resolve", "--config", cfg)
	if got := exitCode(t, err); got != ExitCodeDNSFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitCodeDNSFailure)
	}
}

func TestResolvePartialSuccessWarns(t *testing.T) {
	resolver := fakeResolver{
		data: map[string][]net.IPAddr{"service-a.example.com": ipv4("203.0.113.10")},
		errs: map[string]error{"service-b.example.com": errors.New("timeout")},
	}
	cfg := writeConfig(t, configOpts{failOnLookupError: false})

	out, errOut, err := run(resolver, "resolve", "--config", cfg)
	if err != nil {
		t.Fatalf("expected partial success, got error: %v", err)
	}
	if want := "10.0.0.0/8\n203.0.113.10/32\n"; out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if !strings.Contains(errOut, "failed to resolve 1 of 2 DNS names.") ||
		!strings.Contains(errOut, "Generated AllowedIPs from remaining 1 names.") {
		t.Fatalf("stderr missing partial-failure warning: %q", errOut)
	}
}

func TestResolveFullFailureFailsRun(t *testing.T) {
	resolver := fakeResolver{errs: map[string]error{
		"service-a.example.com": errors.New("timeout"),
		"service-b.example.com": errors.New("timeout"),
	}}
	cfg := writeConfig(t, configOpts{failOnLookupError: true})

	_, _, err := run(resolver, "resolve", "--config", cfg)
	if got := exitCode(t, err); got != ExitCodeDNSFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitCodeDNSFailure)
	}
}

func TestRenderMatchesGolden(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: "testdata/wg0.conf"})

	out, _, err := run(resolver, "render", "--config", cfg)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	want, err := os.ReadFile("testdata/wg0.expected.conf")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("render output mismatch:\n got: %q\nwant: %q", out, want)
	}
}

func TestUpdateWritesConfigAndBackup(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, err := os.ReadFile("testdata/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: wgPath})

	if _, _, err := run(resolver, "update", "--config", cfg); err != nil {
		t.Fatalf("update error: %v", err)
	}

	got, err := os.ReadFile(wgPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/wg0.expected.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("updated config mismatch:\n got: %q\nwant: %q", got, want)
	}

	backups := glob(t, dir, "wg0.conf.bak.*")
	if len(backups) != 1 {
		t.Fatalf("expected exactly one backup, found %d: %v", len(backups), backups)
	}
	if content, _ := os.ReadFile(backups[0]); string(content) != string(original) {
		t.Fatalf("backup content does not match original config")
	}
}

func TestUpdateDryRunWritesNothing(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, err := os.ReadFile("testdata/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: wgPath})

	out, _, err := run(resolver, "update", "--config", cfg, "--dry-run")
	if err != nil {
		t.Fatalf("dry-run error: %v", err)
	}
	if !strings.Contains(out, "Dry run enabled") {
		t.Fatalf("missing dry-run notice: %q", out)
	}
	if got, _ := os.ReadFile(wgPath); string(got) != string(original) {
		t.Fatal("dry-run modified the config file")
	}
	if backups := glob(t, dir, "wg0.conf.bak.*"); len(backups) != 0 {
		t.Fatalf("dry-run created backups: %v", backups)
	}
}

func TestResolveAggregatesWhenEnabled(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.20"),
	}}
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `allowed_ips:
  static: []
  dns_names:
    - "service-a.example.com"
    - "service-b.example.com"
aggregate:
  enabled: true
  max_ipv4_prefix: 24
dns:
  concurrency: 2
  timeout: "1s"
  retries: 0
  families: ["ipv4"]
  fail_on_lookup_error: true
output:
  mode: "stdout"
  format: "plain"
  sort: true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := run(resolver, "resolve", "--config", path)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	if out != "203.0.113.0/24\n" {
		t.Fatalf("expected aggregated /24, got %q", out)
	}
}

func TestUpdateWritesMetricsFile(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, err := os.ReadFile("testdata/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	metricsPath := filepath.Join(dir, "wg-dns-sync.prom")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`wireguard:
  config_path: '%s'
  target_peer_public_key: "TARGET_PUBLIC_KEY"
  preserve_permissions: true
allowed_ips:
  static: ["10.0.0.0/8"]
  dns_names: ["service-a.example.com", "service-b.example.com"]
dns:
  concurrency: 4
  timeout: "1s"
  retries: 0
  families: ["ipv4"]
  fail_on_lookup_error: true
output:
  mode: "update-config"
  format: "wireguard"
  sort: true
  metrics_path: '%s'
`, wgPath, metricsPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := run(resolver, "update", "--config", cfgPath)
	if err != nil {
		t.Fatalf("update error: %v", err)
	}
	if !strings.Contains(out, "Metrics written to") {
		t.Fatalf("summary missing metrics line: %q", out)
	}
	data, err := os.ReadFile(metricsPath)
	if err != nil {
		t.Fatalf("metrics file not written: %v", err)
	}
	for _, want := range []string{
		"wg_dns_sync_resolved_total 2",
		"wg_dns_sync_failed_total 0",
		"wg_dns_sync_allowedips_entries 3",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("metrics file missing %q:\n%s", want, data)
		}
	}
}

func TestUpdateSyncInvokesSyncer(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, err := os.ReadFile("testdata/wg0.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: wgPath})

	syncer := &fakeSyncer{}
	out, _, err := runWithSyncer(resolver, syncer, "update", "--config", cfg, "--sync")
	if err != nil {
		t.Fatalf("update --sync error: %v", err)
	}
	if syncer.calls != 1 {
		t.Fatalf("syncer called %d times, want 1", syncer.calls)
	}
	if syncer.iface != "wg0" {
		t.Errorf("syncer interface = %q, want wg0", syncer.iface)
	}
	if syncer.configPath != wgPath {
		t.Errorf("syncer configPath = %q, want %q", syncer.configPath, wgPath)
	}
	if !strings.Contains(out, "Applied changes to interface wg0") {
		t.Errorf("summary missing sync line: %q", out)
	}
}

func TestUpdateWithoutSyncDoesNotInvokeSyncer(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, _ := os.ReadFile("testdata/wg0.conf")
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: wgPath})

	syncer := &fakeSyncer{}
	if _, _, err := runWithSyncer(resolver, syncer, "update", "--config", cfg); err != nil {
		t.Fatalf("update error: %v", err)
	}
	if syncer.calls != 0 {
		t.Fatalf("syncer should not be called without --sync, got %d", syncer.calls)
	}
}

func TestUpdateSyncFailureReturnsExitCode(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	original, _ := os.ReadFile("testdata/wg0.conf")
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: wgPath})

	syncer := &fakeSyncer{err: errors.New("wg syncconf: boom")}
	_, _, err := runWithSyncer(resolver, syncer, "update", "--config", cfg, "--sync")
	if got := exitCode(t, err); got != ExitCodeWireGuardFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitCodeWireGuardFailure)
	}
}

func writeMultiPeerConfig(t *testing.T, wgPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`wireguard:
  config_path: '%s'
  preserve_permissions: true
peers:
  - public_key: "KEY_A"
    static:
      - "10.0.0.0/8"
    dns_names:
      - "a.example.com"
  - public_key: "KEY_B"
    dns_names:
      - "b.example.com"
dns:
  concurrency: 4
  timeout: "1s"
  retries: 0
  families:
    - "ipv4"
  fail_on_lookup_error: true
output:
  mode: "update-config"
  format: "wireguard"
  sort: true
`, wgPath)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRenderMultiPeerMatchesGolden(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"a.example.com": ipv4("203.0.113.10"),
		"b.example.com": ipv4("203.0.113.20"),
	}}
	cfg := writeMultiPeerConfig(t, "testdata/wg0-multipeer.conf")

	out, _, err := run(resolver, "render", "--config", cfg)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	want, err := os.ReadFile("testdata/wg0-multipeer.expected.conf")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("multi-peer render mismatch:\n got: %q\nwant: %q", out, want)
	}
}

func TestUpdateMultiPeerWritesBothPeers(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"a.example.com": ipv4("203.0.113.10"),
		"b.example.com": ipv4("203.0.113.20"),
	}}
	original, err := os.ReadFile("testdata/wg0-multipeer.conf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	wgPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(wgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeMultiPeerConfig(t, wgPath)

	out, _, err := run(resolver, "update", "--config", cfg)
	if err != nil {
		t.Fatalf("update error: %v", err)
	}

	got, err := os.ReadFile(wgPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/wg0-multipeer.expected.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("multi-peer update mismatch:\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(out, "Updated peer KEY_A") || !strings.Contains(out, "Updated peer KEY_B") {
		t.Fatalf("summary missing per-peer lines: %q", out)
	}
}

func TestDiffShowsAddedAndRemoved(t *testing.T) {
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("203.0.113.10"),
		"service-b.example.com": ipv4("203.0.113.11"),
	}}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: "testdata/wg0.conf"})

	out, _, err := run(resolver, "diff", "--config", cfg)
	if err != nil {
		t.Fatalf("diff error: %v", err)
	}
	// Stale 198.51.100.10/32 removed; the two resolved hosts added; static unchanged.
	for _, want := range []string{
		"Peer TARGET_PUBLIC_KEY AllowedIPs:",
		"- 198.51.100.10/32",
		"+ 203.0.113.10/32",
		"+ 203.0.113.11/32",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "10.0.0.0/8") {
		t.Fatalf("static entry should be unchanged, not shown in diff:\n%s", out)
	}
}

func TestDiffUnchanged(t *testing.T) {
	// Resolve to exactly what the config already contains (static + the one stale IP).
	resolver := fakeResolver{data: map[string][]net.IPAddr{
		"service-a.example.com": ipv4("198.51.100.10"),
		"service-b.example.com": ipv4("198.51.100.10"),
	}}
	cfg := writeConfig(t, configOpts{mode: "update-config", format: "wireguard", wgPath: "testdata/wg0.conf"})

	out, _, err := run(resolver, "diff", "--config", cfg)
	if err != nil {
		t.Fatalf("diff error: %v", err)
	}
	if !strings.Contains(out, "unchanged") {
		t.Fatalf("expected unchanged diff, got:\n%s", out)
	}
}

func TestCompletionGeneratesForEachShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out, _, err := run(nil, "completion", shell)
		if err != nil {
			t.Fatalf("completion %s error: %v", shell, err)
		}
		if len(strings.TrimSpace(out)) == 0 {
			t.Fatalf("completion %s produced no output", shell)
		}
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	if _, _, err := run(nil, "completion", "tcsh"); err == nil {
		t.Fatal("expected error for unsupported shell")
	}
}

func TestInitInteractiveWritesConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	root := newRootCommand(nil, nil)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetIn(strings.NewReader("/tmp/wg0.conf\nMYKEY\nx.example.com, y.example.com\n"))
	root.SetArgs([]string{"init", "--interactive", "--config", cfgPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("init --interactive error: %v", err)
	}

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("generated config invalid: %v", err)
	}
	if cfg.WireGuard.ConfigPath != "/tmp/wg0.conf" || cfg.WireGuard.TargetPeerPublicKey != "MYKEY" {
		t.Fatalf("wizard values not applied: %+v", cfg.WireGuard)
	}
	names := cfg.AllowedIPs.DNSNames
	if len(names) != 2 || names[0] != "x.example.com" || names[1] != "y.example.com" {
		t.Fatalf("dns names = %v", names)
	}
}

func TestInitInteractiveRequiresDNSName(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	root := newRootCommand(nil, nil)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetIn(strings.NewReader("/tmp/wg0.conf\nMYKEY\n\n")) // no DNS names
	root.SetArgs([]string{"init", "--interactive", "--config", cfgPath})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error when no DNS names entered")
	}
}

func glob(t *testing.T, dir, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}
