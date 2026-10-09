//go:build windows

package spool

import (
	"errors"
	"os"

	"github.com/perplexityai/numbat/internal/winfile"
	"golang.org/x/sys/windows"
)

func validateParentMode(os.FileInfo) error { return nil }

func openExistingDatabaseFile(path string, flag int) (*os.File, error) {
	if flag == os.O_RDONLY {
		return winfile.OpenRegular(path)
	}
	return winfile.OpenExistingReadWrite(path)
}

func validateDatabaseMode(os.FileInfo) error { return nil }

func installDatabaseFile(candidate, path string) error {
	if err := winfile.RenameNoReplace(candidate, path); err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil
		}
		return err
	}
	return nil
}
