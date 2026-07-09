// SPDX-FileCopyrightText: 2026 Paul Snow
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteTextAppendsTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.cidr")
	if err := WriteText(path, "10.0.0.0/8"); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "10.0.0.0/8\n" {
		t.Fatalf("content = %q, want trailing newline appended", got)
	}
}

func TestWriteTextDoesNotDoubleNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.cidr")
	if err := WriteText(path, "10.0.0.0/8\n"); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "10.0.0.0/8\n" {
		t.Fatalf("content = %q, want no extra newline", got)
	}
}

// TestWriteTextCreatesParentDirectory guards the atomic-write fix: WriteText
// must go through backup.WriteAtomic (which creates the destination
// directory) rather than a plain os.WriteFile.
func TestWriteTextCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "allowed.cidr")
	if err := WriteText(path, "10.0.0.0/8"); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
}

func TestWriteTextLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowed.cidr")
	if err := WriteText(path, "10.0.0.0/8"); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "allowed.cidr" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("unexpected leftover files: %v", names)
	}
}

func TestWriteTextSetsPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on windows")
	}
	path := filepath.Join(t.TempDir(), "allowed.cidr")
	if err := WriteText(path, "10.0.0.0/8"); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 600", info.Mode().Perm())
	}
}
