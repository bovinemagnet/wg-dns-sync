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

	"github.com/bovinemagnet/wg-dns-sync/internal/dns"
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
	root := newRootCommand(resolver)
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errb.String(), err
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

func glob(t *testing.T, dir, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}
