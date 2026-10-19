//go:build unix

package evaluator

import "testing"

func runtimePrivateDir(t *testing.T) string { t.Helper(); return t.TempDir() }
