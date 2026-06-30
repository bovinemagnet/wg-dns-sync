// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package wgsync

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInterfaceName(t *testing.T) {
	cases := []struct {
		configPath string
		override   string
		want       string
	}{
		{"/etc/wireguard/wg0.conf", "", "wg0"},
		{"/etc/wireguard/wg0.conf", "wg-home", "wg-home"},
		{"wg1.conf", "", "wg1"},
		{"/etc/wireguard/wg0.conf", "  ", "wg0"},
	}
	for _, c := range cases {
		if got := InterfaceName(c.configPath, c.override); got != c.want {
			t.Errorf("InterfaceName(%q, %q) = %q, want %q", c.configPath, c.override, got, c.want)
		}
	}
}

// TestSync_StripFailureIncludesStderr reproduces a real failure mode seen
// running against the actual wg-quick binary on macOS: a non-root invocation
// makes wg-quick re-exec itself via sudo, which fails with a clear stderr
// message ("sudo: a password is required") that the caller needs to see
// rather than a bare "exit status 1".
func TestSync_StripFailureIncludesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake wg-quick shell script is unix-only")
	}
	fakeBin(t, "wg-quick", "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")

	err := CommandSyncer{}.Sync(context.Background(), "wg0", "/tmp/wg0.conf")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Errorf("error %q does not include wg-quick's stderr", err.Error())
	}
}

// fakeBin writes an executable script named name into a temp dir and
// prepends that dir to PATH for the duration of the test.
func fakeBin(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
