package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bovinemagnet/wg-dns-sync/internal/allowedips"
	"github.com/bovinemagnet/wg-dns-sync/internal/backup"
	"github.com/bovinemagnet/wg-dns-sync/internal/config"
	"github.com/bovinemagnet/wg-dns-sync/internal/dns"
	"github.com/bovinemagnet/wg-dns-sync/internal/output"
	"github.com/bovinemagnet/wg-dns-sync/internal/wireguard"
)

func NewRootCommand() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "wg-dns-sync",
		Short: "Sync WireGuard AllowedIPs from DNS",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config file")

	cmd.AddCommand(newInitCmd(&configPath))
	cmd.AddCommand(newResolveCmd(&configPath))
	cmd.AddCommand(newRenderCmd(&configPath))
	cmd.AddCommand(newUpdateCmd(&configPath))
	cmd.AddCommand(newValidateCmd(&configPath))
	return cmd
}

func newInitCmd(configPath *string) *cobra.Command {
	var wgConfig, peer string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := config.InitConfigFile(*configPath, wgConfig, peer)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created config: %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&wgConfig, "wg-config", "", "WireGuard config path")
	cmd.Flags().StringVar(&peer, "peer-public-key", "", "Target peer public key")
	return cmd
}

func newResolveCmd(configPath *string) *cobra.Command {
	var concurrency int
	var format string
	cmd := &cobra.Command{
		Use:   "resolve",
		Short: "Resolve DNS names and emit AllowedIPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			if concurrency > 0 {
				cfg.DNS.Concurrency = concurrency
			}
			if strings.TrimSpace(format) != "" {
				cfg.Output.Format = format
			}
			prefixes, summary, err := resolveAllowedIPs(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			text, err := allowedips.Format(prefixes, cfg.Output.Format)
			if err != nil {
				return wrapExit(ExitCodeInvalidArguments, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), text)
			if summary.WarningCount > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: failed to resolve %d of %d DNS names.\n", summary.WarningCount, summary.HostCount)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "DNS worker count override")
	cmd.Flags().StringVar(&format, "format", "", "Output format: plain|wireguard|json")
	return cmd
}

func newRenderCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render updated WireGuard config to stdout",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			prefixes, _, err := resolveAllowedIPs(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			next, err := wireguard.UpdatePeerAllowedIPs(string(current), cfg.WireGuard.TargetPeerPublicKey, allowedips.ToStrings(prefixes))
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			fmt.Fprint(cmd.OutOrStdout(), next)
			return nil
		},
	}
	return cmd
}

func newUpdateCmd(configPath *string) *cobra.Command {
	var dryRun bool
	var backupDir string
	var outputPathFlag string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Safely update WireGuard config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			if strings.TrimSpace(backupDir) != "" {
				cfg.WireGuard.BackupDir = backupDir
			}
			if strings.TrimSpace(outputPathFlag) != "" {
				cfg.WireGuard.OutputPath = outputPathFlag
			}
			prefixes, summary, err := resolveAllowedIPs(cmd.Context(), cfg)
			if err != nil {
				return err
			}

			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			next, err := wireguard.UpdatePeerAllowedIPs(string(current), cfg.WireGuard.TargetPeerPublicKey, allowedips.ToStrings(prefixes))
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Resolved %d DNS names.\n", summary.HostCount)
				fmt.Fprintf(cmd.OutOrStdout(), "Generated %d AllowedIPs entries.\n", len(prefixes))
				fmt.Fprintln(cmd.OutOrStdout(), "Dry run enabled: no files were written.")
				return nil
			}

			backupPath, perm, err := backup.Create(cfg.WireGuard.ConfigPath, cfg.WireGuard.BackupDir)
			if err != nil {
				return wrapExit(ExitCodeWriteFailure, err)
			}
			if !cfg.WireGuard.PreservePermissions {
				perm = 0o600
			}
			outputPath := cfg.EffectiveOutputPath()
			if err := backup.WriteAtomic(outputPath, []byte(next), perm); err != nil {
				return wrapExit(ExitCodeWriteFailure, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Resolved %d DNS names.\n", summary.HostCount)
			fmt.Fprintf(cmd.OutOrStdout(), "Generated %d AllowedIPs entries.\n", len(prefixes))
			fmt.Fprintf(cmd.OutOrStdout(), "Updated peer %s...\n", cfg.WireGuard.TargetPeerPublicKey)
			fmt.Fprintf(cmd.OutOrStdout(), "Backup written to %s\n", backupPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Config written to %s\n", outputPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Render and validate, but do not write files")
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Backup directory override")
	cmd.Flags().StringVar(&outputPathFlag, "output", "", "Output config path override")
	return cmd
}

func newValidateCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate app and WireGuard config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			if err := wireguard.ValidateTargetPeer(string(current), cfg.WireGuard.TargetPeerPublicKey); err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Validation successful")
			return nil
		},
	}
	return cmd
}

type resolveSummary struct {
	HostCount    int
	WarningCount int
}

func resolveAllowedIPs(ctx context.Context, cfg config.AppConfig) ([]netip.Prefix, resolveSummary, error) {
	results, err := dns.ResolveHosts(ctx, nil, cfg.AllowedIPs.DNSNames, cfg.DNS)
	if err != nil {
		return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, err)
	}

	resolved := make([]netip.Addr, 0)
	warningCount := 0
	for _, result := range results {
		if result.Err != nil {
			warningCount++
			if cfg.DNS.FailOnLookupError {
				return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, result.Err)
			}
			continue
		}
		resolved = append(resolved, result.IPs...)
	}

	prefixes, err := allowedips.Build(cfg.AllowedIPs.Static, resolved)
	if err != nil {
		return nil, resolveSummary{}, wrapExit(ExitCodeInvalidConfig, err)
	}
	if cfg.Output.Mode == "cidr-file" {
		text, formatErr := allowedips.Format(prefixes, cfg.Output.Format)
		if formatErr != nil {
			return nil, resolveSummary{}, wrapExit(ExitCodeInvalidArguments, formatErr)
		}
		if writeErr := output.WriteText(cfg.Output.Path, text); writeErr != nil {
			return nil, resolveSummary{}, wrapExit(ExitCodeWriteFailure, writeErr)
		}
	}
	if len(resolved) == 0 && len(cfg.AllowedIPs.Static) == 0 {
		return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, errors.New("no AllowedIPs generated"))
	}
	return prefixes, resolveSummary{HostCount: len(cfg.AllowedIPs.DNSNames), WarningCount: warningCount}, nil
}
