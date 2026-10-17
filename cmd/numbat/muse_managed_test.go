package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMuseManagedRequiresExplicitFile(t *testing.T) {
	setTestHome(t, t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, action := range []string{"install", "status", "uninstall"} {
		out, errb, code := runCLI("hook", action, "--agent", "muse", "--managed")
		if code != 2 || out != "" || !strings.Contains(errb, "requires --settings PATH") {
			t.Fatalf("%s: exit=%d stdout=%q stderr=%q", action, code, out, errb)
		}
	}
}

func TestMuseManagedExplicitFileRoundTrip(t *testing.T) {
	setTestHome(t, t.TempDir())
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	userPath := filepath.Join(config, "muse", "settings.json")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(filepath.Dir(userPath), "existing-managed.json")
	if err := os.WriteFile(unrelated, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A pre-existing pointer is not followed or repointed by the installer.
	seed := `{"schema_version":1,"managed_hooks_path":"existing-managed.json","provider":"echo"}`
	if err := os.WriteFile(userPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "managed", "hooks.json")
	for _, action := range []string{"install", "install", "status", "uninstall", "uninstall"} {
		out, errb, code := runCLI("hook", action, "--agent", "muse", "--managed", "--settings", path)
		if code != 0 || !strings.Contains(out, path) {
			t.Fatalf("%s: exit=%d stdout=%q stderr=%q", action, code, out, errb)
		}
		if action == "install" {
			if !strings.Contains(out, "configure managed_hooks_path separately") {
				t.Fatalf("missing activation guidance: %s", out)
			}
			body := testHookCommandText(readFileString(t, path))
			if !strings.Contains(body, "$HOME/.numbat/findings.ndjson") || strings.Contains(body, "--enforce") {
				t.Fatalf("incorrect managed monitor defaults: %s", body)
			}
		}
		if got := readFileString(t, userPath); got != seed {
			t.Fatalf("%s rewrote user settings: %s", action, got)
		}
		if got := readFileString(t, unrelated); got != `{"hooks":{}}` {
			t.Fatalf("%s rewrote an unrelated file: %s", action, got)
		}
	}
	out, errb, code := runCLI("hook", "status", "--agent", "muse", "--managed", "--settings", path)
	if code != 0 || !strings.Contains(out, "not installed") {
		t.Fatalf("uninstalled status: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}
