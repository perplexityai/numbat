//go:build unix

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func validateParentMode(info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("directory must not be group- or other-writable")
	}
	return nil
}

func openExistingDatabaseFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, 0)
}

func validateDatabaseMode(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("existing database permissions are %04o, want 0600 or stricter", info.Mode().Perm())
	}
	return nil
}

func installDatabaseFile(candidate, path string) error {
	if err := os.Link(candidate, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
