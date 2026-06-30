// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"runtime"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origVersion, origCommit, origDate })
	Version, Commit, Date = "1.2.3", "abc1234", "2026-06-30T00:00:00Z"

	stdout, _, err := run(nil, "version")
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	for _, want := range []string{"1.2.3", "abc1234", "2026-06-30T00:00:00Z", runtime.Version()} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output missing %q\ngot:\n%s", want, stdout)
		}
	}
}

func TestRootVersionFlag(t *testing.T) {
	origVersion := Version
	t.Cleanup(func() { Version = origVersion })
	Version = "9.9.9"

	stdout, _, err := run(nil, "--version")
	if err != nil {
		t.Fatalf("--version failed: %v", err)
	}
	if !strings.Contains(stdout, "9.9.9") {
		t.Errorf("--version output missing version\ngot:\n%s", stdout)
	}
}
