// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveVersionLdflagsWin(t *testing.T) {
	info := &debug.BuildInfo{
		Main:     debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "feedface"}},
	}
	// A non-"dev" version means ldflags injected; build info must be ignored.
	v, c, d := resolveVersion("1.2.3", "abc1234", "2026-06-30", info)
	if v != "1.2.3" || c != "abc1234" || d != "2026-06-30" {
		t.Fatalf("ldflags should win, got %q %q %q", v, c, d)
	}
}

func TestResolveVersionFallsBackToBuildInfo(t *testing.T) {
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v1.4.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.time", Value: "2026-06-30T00:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	v, c, d := resolveVersion("dev", "none", "unknown", info)
	if v != "v1.4.0" {
		t.Errorf("version = %q, want v1.4.0", v)
	}
	if c != "deadbeef+dirty" {
		t.Errorf("commit = %q, want deadbeef+dirty", c)
	}
	if d != "2026-06-30T00:00:00Z" {
		t.Errorf("date = %q, want the vcs.time", d)
	}
}

func TestResolveVersionLocalDevelKeepsDev(t *testing.T) {
	info := &debug.BuildInfo{
		Main:     debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "cafe"}},
	}
	v, c, _ := resolveVersion("dev", "none", "unknown", info)
	if v != "dev" {
		t.Errorf("version = %q, want dev for a local (devel) build", v)
	}
	if c != "cafe" {
		t.Errorf("commit = %q, want cafe", c)
	}
}

func TestResolveVersionNilInfo(t *testing.T) {
	v, c, d := resolveVersion("dev", "none", "unknown", nil)
	if v != "dev" || c != "none" || d != "unknown" {
		t.Fatalf("nil build info should keep defaults, got %q %q %q", v, c, d)
	}
}

func TestVersionCommand(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origVersion, origCommit, origDate })
	Version, Commit, Date = "1.2.3", "abc1234", "2026-06-30T00:00:00Z"

	stdout, _, err := run(nil, "version")
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	for _, want := range []string{
		"1.2.3", "abc1234", "2026-06-30T00:00:00Z", runtime.Version(),
		"Copyright (C) 2026  Paul Snow",
		"AGPL-3.0-or-later",
		"NO WARRANTY",
	} {
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
