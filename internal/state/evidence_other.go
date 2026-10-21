//go:build !unix && !windows

package state

import (
	"errors"
	"os"
)

func openEvidenceFile(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.New("state: evidence storage currently requires Unix")
}

func prepareEvidenceDirectory(string) error {
	return errors.New("state: protected evidence storage unsupported on this platform")
}
