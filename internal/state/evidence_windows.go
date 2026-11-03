//go:build windows

package state

import (
	"os"
	"path/filepath"

	"github.com/perplexityai/numbat/internal/winfile"
)

func prepareEvidenceDirectory(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := winfile.PrivateDirectory(path); err != nil {
		return err
	}
	return winfile.CheckProtectedParents(filepath.Join(path, "state.db"))
}

func openEvidenceFile(path string, _ int, _ os.FileMode) (*os.File, error) {
	return winfile.OpenPrivate(path)
}
