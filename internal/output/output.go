// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"strings"

	"github.com/bovinemagnet/wg-dns-sync/internal/backup"
)

func WriteText(path, text string) error {
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return backup.WriteAtomic(path, []byte(text), 0o600)
}
