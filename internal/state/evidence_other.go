//go:build !unix

package state

import (
	"errors"
	"os"
)

func openEvidenceFile(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.New("state: evidence storage currently requires Unix")
}
