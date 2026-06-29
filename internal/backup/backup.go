package backup

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func Create(srcPath, backupDir string) (string, fs.FileMode, error) {
	st, err := os.Stat(srcPath)
	if err != nil {
		return "", 0, err
	}
	if backupDir == "" {
		backupDir = filepath.Dir(srcPath)
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", 0, err
	}
	suffix, err := randomSuffix(4)
	if err != nil {
		return "", 0, err
	}
	name := fmt.Sprintf("%s.bak.%s.%s", filepath.Base(srcPath), time.Now().UTC().Format("20060102T150405.000000000"), suffix)
	backupPath := filepath.Join(backupDir, name)
	if _, err := os.Stat(backupPath); err == nil {
		return "", 0, fmt.Errorf("backup already exists: %s", backupPath)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer src.Close()

	perm := st.Mode().Perm()
	if perm == 0 {
		perm = 0o600
	}
	dst, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return "", 0, err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return "", 0, err
	}
	if err := dst.Close(); err != nil {
		return "", 0, err
	}
	return backupPath, perm, nil
}

func randomSuffix(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func WriteAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if perm == 0 {
		perm = 0o600
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
