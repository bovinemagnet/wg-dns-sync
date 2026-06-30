// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"runtime"

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

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "version: %s\ncommit:  %s\ndate:    %s\ngo:      %s\n",
				Version, Commit, Date, runtime.Version())
			fmt.Fprint(out, "\n"+licenceNotice)
			return nil
		},
	}
}
