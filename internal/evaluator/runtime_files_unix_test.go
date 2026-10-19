//go:build unix

package evaluator

import (
	"path/filepath"
	"testing"
)

func runtimePrivateDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
