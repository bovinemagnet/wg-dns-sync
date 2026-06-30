// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderContainsAllSeries(t *testing.T) {
	out := Render(Metrics{LastRunSeconds: 1717000000, ResolvedTotal: 4, FailedTotal: 1, AllowedIPsTotal: 5})
	for _, want := range []string{
		"wg_dns_sync_last_run_seconds 1717000000",
		"wg_dns_sync_resolved_total 4",
		"wg_dns_sync_failed_total 1",
		"wg_dns_sync_allowedips_entries 5",
		"# TYPE wg_dns_sync_resolved_total gauge",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered metrics missing %q:\n%s", want, out)
		}
	}
}

func TestWriteCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-dns-sync.prom")
	if err := Write(path, Metrics{ResolvedTotal: 2}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "wg_dns_sync_resolved_total 2") {
		t.Fatalf("file missing metric: %s", data)
	}
}
