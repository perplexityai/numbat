//go:build !unix && !windows

package spool

import (
	"errors"
	"os"
)

func validateParentMode(os.FileInfo) error { return nil }

func openExistingDatabaseFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0)
}

func validateDatabaseMode(os.FileInfo) error { return nil }

func installDatabaseFile(candidate, path string) error {
	if err := os.Link(candidate, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	return nil
}
