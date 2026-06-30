// Package wgsync optionally applies an updated WireGuard configuration to a
// running interface with `wg syncconf`, without restarting the tunnel.
package wgsync

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Syncer applies the configuration at configPath to the live WireGuard
// interface named iface.
type Syncer interface {
	Sync(ctx context.Context, iface, configPath string) error
}

// CommandSyncer applies changes by running `wg-quick strip` to produce a
// syncconf-compatible config and then `wg syncconf`.
type CommandSyncer struct{}

// Sync strips wg-quick-only directives from configPath and applies the result
// to the running interface. It shells out to `wg-quick` and `wg`, which must be
// installed and is normally run with sufficient privileges.
func (CommandSyncer) Sync(ctx context.Context, iface, configPath string) error {
	stripped, err := exec.CommandContext(ctx, "wg-quick", "strip", configPath).Output()
	if err != nil {
		return fmt.Errorf("wg-quick strip %s: %w", configPath, err)
	}
	tmp, err := os.CreateTemp("", "wg-dns-sync-*.conf")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(stripped); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "wg", "syncconf", iface, tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("wg syncconf %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// InterfaceName returns override when set, otherwise derives the interface name
// from the config file name (for example /etc/wireguard/wg0.conf -> wg0).
func InterfaceName(configPath, override string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	base := filepath.Base(configPath)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
