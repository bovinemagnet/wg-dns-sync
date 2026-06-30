// Package metrics writes a Prometheus textfile-collector file summarising the
// most recent run, suitable for scraping via the node_exporter textfile
// collector.
package metrics

import (
	"fmt"
	"strings"

	"github.com/bovinemagnet/wg-dns-sync/internal/backup"
)

// Metrics holds the values written for a run.
type Metrics struct {
	LastRunSeconds  int64
	ResolvedTotal   int
	FailedTotal     int
	AllowedIPsTotal int
}

// Render returns the Prometheus exposition-format text for the metrics, with a
// HELP and TYPE header per series.
func Render(m Metrics) string {
	var b strings.Builder
	metric := func(name, help, typ string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
		fmt.Fprintf(&b, "%s %d\n", name, value)
	}
	metric("wg_dns_sync_last_run_seconds", "Unix timestamp of the last run.", "gauge", m.LastRunSeconds)
	metric("wg_dns_sync_resolved_total", "DNS names resolved successfully in the last run.", "gauge", int64(m.ResolvedTotal))
	metric("wg_dns_sync_failed_total", "DNS names that failed to resolve in the last run.", "gauge", int64(m.FailedTotal))
	metric("wg_dns_sync_allowedips_entries", "AllowedIPs entries written in the last run.", "gauge", int64(m.AllowedIPsTotal))
	return b.String()
}

// Write atomically writes the rendered metrics to path.
func Write(path string, m Metrics) error {
	return backup.WriteAtomic(path, []byte(Render(m)), 0o644)
}
