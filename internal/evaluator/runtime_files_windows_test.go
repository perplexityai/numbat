//go:build windows

package evaluator

import (
	"path/filepath"
	"testing"

	"github.com/perplexityai/numbat/internal/winfile"
)

func runtimePrivateDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := winfile.PrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	return path
}
