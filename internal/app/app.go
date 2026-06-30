package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bovinemagnet/wg-dns-sync/internal/allowedips"
	"github.com/bovinemagnet/wg-dns-sync/internal/backup"
	"github.com/bovinemagnet/wg-dns-sync/internal/config"
	"github.com/bovinemagnet/wg-dns-sync/internal/dns"
	"github.com/bovinemagnet/wg-dns-sync/internal/metrics"
	"github.com/bovinemagnet/wg-dns-sync/internal/output"
	"github.com/bovinemagnet/wg-dns-sync/internal/wgsync"
	"github.com/bovinemagnet/wg-dns-sync/internal/wireguard"
)

// NewRootCommand builds the CLI using the system DNS resolver and the real
// `wg syncconf` runner.
func NewRootCommand() *cobra.Command {
	return newRootCommand(nil, nil)
}

// newRootCommand builds the CLI with an injectable resolver and syncer. A nil
// resolver falls back to the system resolver and a nil syncer to the real
// command runner; tests pass fakes to avoid real lookups or shelling out.
func newRootCommand(resolver dns.IPResolver, syncer wgsync.Syncer) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "wg-dns-sync",
		Short: "Sync WireGuard AllowedIPs from DNS",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config file")

	cmd.AddCommand(newInitCmd(&configPath))
	cmd.AddCommand(newResolveCmd(&configPath, resolver))
	cmd.AddCommand(newRenderCmd(&configPath, resolver))
	cmd.AddCommand(newDiffCmd(&configPath, resolver))
	cmd.AddCommand(newUpdateCmd(&configPath, resolver, syncer))
	cmd.AddCommand(newValidateCmd(&configPath))
	cmd.AddCommand(newCompletionCmd())
	return cmd
}

func newInitCmd(configPath *string) *cobra.Command {
	var wgConfig, peer string
	var interactive bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			data := config.ConfigTemplateData{
				WireGuardPath: wgConfig,
				PeerPublicKey: peer,
				Static:        []string{"10.0.0.0/8"},
				DNSNames:      []string{"service-a.example.com", "service-b.example.com"},
			}
			if interactive {
				prompted, err := runInitWizard(cmd.InOrStdin(), cmd.OutOrStdout(), wgConfig, peer)
				if err != nil {
					return wrapExit(ExitCodeInvalidConfig, err)
				}
				data = prompted
			}
			path, err := config.InitConfigFileWith(*configPath, data)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Created config: %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&wgConfig, "wg-config", "", "WireGuard config path")
	cmd.Flags().StringVar(&peer, "peer-public-key", "", "Target peer public key")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Prompt for config values instead of writing a template")
	return cmd
}

// runInitWizard prompts for the essential config values. An empty answer keeps
// the bracketed default; DNS names are entered as a comma-separated list.
func runInitWizard(in io.Reader, out io.Writer, wgConfig, peer string) (config.ConfigTemplateData, error) {
	reader := bufio.NewReader(in)
	prompt := func(label, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(out, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(out, "%s: ", label)
		}
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		if line = strings.TrimSpace(line); line != "" {
			return line, nil
		}
		return def, nil
	}

	wgDefault := wgConfig
	if strings.TrimSpace(wgDefault) == "" {
		wgDefault = "/etc/wireguard/wg0.conf"
	}
	wg, err := prompt("WireGuard config path", wgDefault)
	if err != nil {
		return config.ConfigTemplateData{}, err
	}
	key, err := prompt("Target peer public key", peer)
	if err != nil {
		return config.ConfigTemplateData{}, err
	}
	namesLine, err := prompt("DNS names (comma-separated)", "")
	if err != nil {
		return config.ConfigTemplateData{}, err
	}
	names := splitNames(namesLine)
	if len(names) == 0 {
		return config.ConfigTemplateData{}, errors.New("at least one DNS name is required")
	}
	return config.ConfigTemplateData{WireGuardPath: wg, PeerPublicKey: key, DNSNames: names}, nil
}

// splitNames splits a comma-separated list into trimmed, non-empty entries.
func splitNames(line string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(line, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func newResolveCmd(configPath *string, resolver dns.IPResolver) *cobra.Command {
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
			prefixes, summary, err := resolveAllowedIPs(cmd.Context(), resolver, cfg)
			if err != nil {
				return err
			}
			text, err := allowedips.Format(prefixes, cfg.Output.Format)
			if err != nil {
				return wrapExit(ExitCodeInvalidArguments, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), text)
			summary.printWarnings(cmd.ErrOrStderr())
			return nil
		},
	}
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "DNS worker count override")
	cmd.Flags().StringVar(&format, "format", "", "Output format: plain|wireguard|json")
	return cmd
}

func newRenderCmd(configPath *string, resolver dns.IPResolver) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render updated WireGuard config to stdout",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			peers, _, err := resolvePeerPrefixes(cmd.Context(), resolver, cfg)
			if err != nil {
				return err
			}
			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			next, err := applyPeerUpdates(string(current), peers)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			fmt.Fprint(cmd.OutOrStdout(), next)
			return nil
		},
	}
	return cmd
}

func newUpdateCmd(configPath *string, resolver dns.IPResolver, syncer wgsync.Syncer) *cobra.Command {
	var dryRun bool
	var backupDir string
	var outputPathFlag string
	var sync bool
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
			peers, summary, err := resolvePeerPrefixes(cmd.Context(), resolver, cfg)
			if err != nil {
				return err
			}

			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			next, err := applyPeerUpdates(string(current), peers)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Resolved %d DNS names.\n", summary.HostCount)
				for _, p := range peers {
					fmt.Fprintf(cmd.OutOrStdout(), "Would update peer %s: %d AllowedIPs entries.\n", p.PublicKey, len(p.Prefixes))
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Dry run enabled: no files were written.")
				summary.printWarnings(cmd.ErrOrStderr())
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
			for _, p := range peers {
				fmt.Fprintf(cmd.OutOrStdout(), "Updated peer %s: %d AllowedIPs entries.\n", p.PublicKey, len(p.Prefixes))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Backup written to %s\n", backupPath)
			fmt.Fprintf(cmd.OutOrStdout(), "Config written to %s\n", outputPath)

			if sync || cfg.WireGuard.Sync {
				s := syncer
				if s == nil {
					s = wgsync.CommandSyncer{}
				}
				iface := wgsync.InterfaceName(cfg.WireGuard.ConfigPath, cfg.WireGuard.Interface)
				if err := s.Sync(cmd.Context(), iface, outputPath); err != nil {
					return wrapExit(ExitCodeWireGuardFailure, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Applied changes to interface %s with wg syncconf.\n", iface)
			}

			if path := strings.TrimSpace(cfg.Output.MetricsPath); path != "" {
				if err := metrics.Write(path, runMetrics(summary, peers)); err != nil {
					return wrapExit(ExitCodeWriteFailure, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Metrics written to %s\n", path)
			}
			summary.printWarnings(cmd.ErrOrStderr())
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Render and validate, but do not write files")
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Backup directory override")
	cmd.Flags().StringVar(&outputPathFlag, "output", "", "Output config path override")
	cmd.Flags().BoolVar(&sync, "sync", false, "Apply the new config to the live interface with wg syncconf")
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
			for _, t := range cfg.PeerTargets() {
				if err := wireguard.ValidateTargetPeer(string(current), t.PublicKey); err != nil {
					return wrapExit(ExitCodeWireGuardFailure, err)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Validation successful")
			return nil
		},
	}
	return cmd
}

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate a shell completion script",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(out, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(out)
			case "fish":
				return cmd.Root().GenFishCompletion(out, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(out)
			default:
				return wrapExit(ExitCodeInvalidArguments, fmt.Errorf("unsupported shell %q", args[0]))
			}
		},
	}
	return cmd
}

func newDiffCmd(configPath *string, resolver dns.IPResolver) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show AllowedIPs changes without writing any files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := config.Load(*configPath)
			if err != nil {
				return wrapExit(ExitCodeInvalidConfig, err)
			}
			peers, summary, err := resolvePeerPrefixes(cmd.Context(), resolver, cfg)
			if err != nil {
				return err
			}
			current, err := os.ReadFile(cfg.WireGuard.ConfigPath)
			if err != nil {
				return wrapExit(ExitCodeWireGuardFailure, err)
			}
			for _, p := range peers {
				old, err := wireguard.PeerAllowedIPs(string(current), p.PublicKey)
				if err != nil {
					return wrapExit(ExitCodeWireGuardFailure, err)
				}
				added, removed := diffEntries(old, allowedips.ToStrings(p.Prefixes))
				printPeerDiff(cmd.OutOrStdout(), p.PublicKey, added, removed)
			}
			summary.printWarnings(cmd.ErrOrStderr())
			return nil
		},
	}
	return cmd
}

// diffEntries reports which entries are new (in next, not old) and which are
// removed (in old, not next), preserving each list's original order.
func diffEntries(old, next []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(old))
	for _, e := range old {
		oldSet[e] = struct{}{}
	}
	nextSet := make(map[string]struct{}, len(next))
	for _, e := range next {
		nextSet[e] = struct{}{}
	}
	for _, e := range next {
		if _, ok := oldSet[e]; !ok {
			added = append(added, e)
		}
	}
	for _, e := range old {
		if _, ok := nextSet[e]; !ok {
			removed = append(removed, e)
		}
	}
	return added, removed
}

func printPeerDiff(w io.Writer, publicKey string, added, removed []string) {
	fmt.Fprintf(w, "Peer %s AllowedIPs:\n", publicKey)
	if len(added) == 0 && len(removed) == 0 {
		fmt.Fprintln(w, "  unchanged")
		return
	}
	for _, e := range removed {
		fmt.Fprintf(w, "- %s\n", e)
	}
	for _, e := range added {
		fmt.Fprintf(w, "+ %s\n", e)
	}
}

type resolveSummary struct {
	HostCount    int
	WarningCount int
}

// printWarnings reports partial DNS-resolution failures to stderr, matching the
// two-line format in the PRD. It is a no-op when every name resolved.
func (s resolveSummary) printWarnings(w io.Writer) {
	if s.WarningCount == 0 {
		return
	}
	fmt.Fprintf(w, "WARNING: failed to resolve %d of %d DNS names.\n", s.WarningCount, s.HostCount)
	fmt.Fprintf(w, "Generated AllowedIPs from remaining %d names.\n", s.HostCount-s.WarningCount)
}

// peerPrefixes is the resolved AllowedIPs for a single target peer.
type peerPrefixes struct {
	PublicKey string
	Prefixes  []netip.Prefix
}

// uniqueDNSNames returns the de-duplicated union of every peer's DNS names so a
// name shared by several peers is only resolved once.
func uniqueDNSNames(targets []config.PeerTarget) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, t := range targets {
		for _, host := range t.DNSNames {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out
}

// resolveHostMap resolves hosts once and returns successful lookups keyed by
// host, honouring dns.fail_on_lookup_error. Failed lookups are counted in the
// summary when not fatal.
func resolveHostMap(ctx context.Context, resolver dns.IPResolver, hosts []string, cfg config.AppConfig) (map[string][]netip.Addr, resolveSummary, error) {
	results, err := dns.ResolveHosts(ctx, resolver, hosts, cfg.DNS)
	if err != nil {
		return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, err)
	}
	out := make(map[string][]netip.Addr, len(hosts))
	warningCount := 0
	for _, result := range results {
		if result.Err != nil {
			warningCount++
			if cfg.DNS.FailOnLookupError {
				return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, result.Err)
			}
			continue
		}
		out[result.Host] = result.IPs
	}
	return out, resolveSummary{HostCount: len(hosts), WarningCount: warningCount}, nil
}

// resolveAllowedIPs resolves every configured DNS name and returns one combined,
// deduplicated AllowedIPs set across all peers. Used by the resolve command for
// a "show me all routes" view; it also writes the cidr-file when configured.
func resolveAllowedIPs(ctx context.Context, resolver dns.IPResolver, cfg config.AppConfig) ([]netip.Prefix, resolveSummary, error) {
	targets := cfg.PeerTargets()
	hostMap, summary, err := resolveHostMap(ctx, resolver, uniqueDNSNames(targets), cfg)
	if err != nil {
		return nil, resolveSummary{}, err
	}

	resolved := make([]netip.Addr, 0)
	static := make([]string, 0)
	for _, t := range targets {
		static = append(static, t.Static...)
		for _, host := range t.DNSNames {
			resolved = append(resolved, hostMap[host]...)
		}
	}

	prefixes, err := allowedips.Build(static, resolved, cfg.Output.Sort)
	if err != nil {
		return nil, resolveSummary{}, wrapExit(ExitCodeInvalidConfig, err)
	}
	prefixes = aggregatePrefixes(cfg, prefixes)
	if cfg.Output.Mode == "cidr-file" {
		text, formatErr := allowedips.Format(prefixes, cfg.Output.Format)
		if formatErr != nil {
			return nil, resolveSummary{}, wrapExit(ExitCodeInvalidArguments, formatErr)
		}
		if writeErr := output.WriteText(cfg.Output.Path, text); writeErr != nil {
			return nil, resolveSummary{}, wrapExit(ExitCodeWriteFailure, writeErr)
		}
	}
	if len(resolved) == 0 && len(static) == 0 {
		return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, errors.New("no AllowedIPs generated"))
	}
	return prefixes, summary, nil
}

// runMetrics derives the Prometheus metrics for a completed update from its
// resolution summary and the per-peer results.
func runMetrics(summary resolveSummary, peers []peerPrefixes) metrics.Metrics {
	entries := 0
	for _, p := range peers {
		entries += len(p.Prefixes)
	}
	return metrics.Metrics{
		LastRunSeconds:  time.Now().Unix(),
		ResolvedTotal:   summary.HostCount - summary.WarningCount,
		FailedTotal:     summary.WarningCount,
		AllowedIPsTotal: entries,
	}
}

// aggregatePrefixes summarises the prefixes when aggregation is enabled,
// otherwise returns them unchanged.
func aggregatePrefixes(cfg config.AppConfig, prefixes []netip.Prefix) []netip.Prefix {
	if !cfg.Aggregate.Enabled {
		return prefixes
	}
	return allowedips.Aggregate(prefixes, cfg.Aggregate.MaxIPv4Prefix, cfg.Aggregate.MaxIPv6Prefix, cfg.Output.Sort)
}

// resolvePeerPrefixes resolves DNS once and returns the AllowedIPs set for each
// peer separately. Used by render, update, and diff to update peers individually.
func resolvePeerPrefixes(ctx context.Context, resolver dns.IPResolver, cfg config.AppConfig) ([]peerPrefixes, resolveSummary, error) {
	targets := cfg.PeerTargets()
	hostMap, summary, err := resolveHostMap(ctx, resolver, uniqueDNSNames(targets), cfg)
	if err != nil {
		return nil, resolveSummary{}, err
	}

	out := make([]peerPrefixes, 0, len(targets))
	for _, t := range targets {
		resolved := make([]netip.Addr, 0)
		for _, host := range t.DNSNames {
			resolved = append(resolved, hostMap[host]...)
		}
		prefixes, buildErr := allowedips.Build(t.Static, resolved, cfg.Output.Sort)
		if buildErr != nil {
			return nil, resolveSummary{}, wrapExit(ExitCodeInvalidConfig, buildErr)
		}
		if len(resolved) == 0 && len(t.Static) == 0 {
			return nil, resolveSummary{}, wrapExit(ExitCodeDNSFailure, fmt.Errorf("peer %s: no AllowedIPs generated", t.PublicKey))
		}
		out = append(out, peerPrefixes{PublicKey: t.PublicKey, Prefixes: aggregatePrefixes(cfg, prefixes)})
	}
	return out, summary, nil
}

// applyPeerUpdates rewrites the AllowedIPs of every target peer in the config
// content, threading the result so all peers are updated in one pass.
func applyPeerUpdates(content string, peers []peerPrefixes) (string, error) {
	next := content
	for _, p := range peers {
		updated, err := wireguard.UpdatePeerAllowedIPs(next, p.PublicKey, allowedips.ToStrings(p.Prefixes))
		if err != nil {
			return "", err
		}
		next = updated
	}
	return next, nil
}
