package backup

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

// backupName matches "<base>.bak.<UTC timestamp>.<8 hex chars>".
var backupName = regexp.MustCompile(`^wg0\.conf\.bak\.\d{8}T\d{6}\.\d{9}\.[0-9a-f]{8}$`)

func TestCreateBacksUpAndPreservesSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wg0.conf")
	content := []byte("[Interface]\nPrivateKey = SECRET\n")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	backupPath, perm, err := Create(src, "")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if got := filepath.Base(backupPath); !backupName.MatchString(got) {
		t.Errorf("backup filename %q does not match expected pattern", got)
	}
	if got, err := os.ReadFile(backupPath); err != nil || string(got) != string(content) {
		t.Errorf("backup content = %q (err %v), want %q", got, err, content)
	}
	if got, err := os.ReadFile(src); err != nil || string(got) != string(content) {
		t.Errorf("source was modified: %q (err %v)", got, err)
	}
	if runtime.GOOS != "windows" && perm.Perm() != 0o600 {
		t.Errorf("preserved perm = %o, want 600", perm.Perm())
	}
}

func TestCreateNeverOverwritesExistingBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, _, err := Create(src, "")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Create(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("two backups share a path: %s", first)
	}
}

func TestWriteAtomicWritesContentAndPerm(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.conf")

	if err := WriteAtomic(dst, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteAtomic() error = %v", err)
	}
	// Atomic replace of an existing destination.
	if err := WriteAtomic(dst, []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteAtomic() replace error = %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "second" {
		t.Fatalf("content = %q (err %v), want %q", got, err, "second")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("perm = %o, want 600", info.Mode().Perm())
		}
	}

	// No temporary files should linger after a successful write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.conf" {
		t.Errorf("unexpected leftover files: %v", names(entries))
	}
}

func names(entries []os.DirEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name()
	}
	return out
}
