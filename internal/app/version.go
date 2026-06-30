// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Build metadata, injected at release time via -ldflags -X by GoReleaser.
// The defaults apply to `go build`/`go install` and local development.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// licenceNotice is the short copyright and warranty notice printed by the
// version command, as suggested by the GNU Affero General Public License.
const licenceNotice = `wg-dns-sync  Copyright (C) 2026  Paul Snow
License AGPL-3.0-or-later: GNU AGPL version 3 or later <https://www.gnu.org/licenses/agpl-3.0.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
`

// versionInfo returns the effective version, commit, and date. Values injected
// at release time via -ldflags take precedence. Otherwise, for `go build` and
// `go install` binaries, it falls back to the module version and VCS stamps that
// Go embeds in the binary, so those builds still self-describe.
func versionInfo() (version, commit, date string) {
	info, _ := debug.ReadBuildInfo()
	return resolveVersion(Version, Commit, Date, info)
}

// resolveVersion applies the build-info fallback to the compiled-in defaults.
// It is pure so the fallback logic can be tested without a real build.
func resolveVersion(version, commit, date string, info *debug.BuildInfo) (string, string, string) {
	if version != "dev" || info == nil {
		return version, commit, date // ldflags injected, or no build info available
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		version = v
	}
	modified := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				commit = s.Value
			}
		case "vcs.time":
			if s.Value != "" {
				date = s.Value
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified && commit != "none" {
		commit += "+dirty"
	}
	return version, commit, date
}

// resolvedVersion is the version string for cobra's --version flag.
func resolvedVersion() string {
	v, _, _ := versionInfo()
	return v
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			version, commit, date := versionInfo()
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "version: %s\ncommit:  %s\ndate:    %s\ngo:      %s\n",
				version, commit, date, runtime.Version())
			fmt.Fprint(out, "\n"+licenceNotice)
			return nil
		},
	}
}
