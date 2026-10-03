package hook

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestMuseUserInstallInjectsSchemaVersionAndPreservesForeignKeys covers the
// one hard requirement Phase 0 confirmed against a real settings.json: Muse
// refuses to start without a top-level "schema_version": 1. numbat must add
// it on a fresh install and never disturb it or any other foreign key.
func TestMuseUserInstallInjectsSchemaVersionAndPreservesForeignKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "muse", "settings.json")
	rep, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{Enforce: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentMuse, path).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentMuse, path))
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(sf.values["schema_version"]) != "1" {
		t.Fatalf("schema_version = %s, want 1", sf.values["schema_version"])
	}
	for _, ev := range museHookEvents {
		groups := sf.hooks[ev.settingsKey]
		if len(groups) != 1 || groups[0].Matcher != "*" || len(groups[0].Hooks) != 1 {
			t.Fatalf("muse %s = %#v", ev.settingsKey, groups)
		}
		ref := groups[0].Hooks[0]
		if !isNumbatHookCommand(ref.Command) || ref.Args != nil || ref.Timeout != ev.timeout {
			t.Errorf("muse %s hook = %#v", ev.settingsKey, ref)
		}
		wantEnforce := ev.settingsKey == "PreToolUse"
		if got := strings.Contains(hookCommandText(ref.Command), "--enforce"); got != wantEnforce {
			t.Errorf("muse %s enforce=%t, want %t: %q", ev.settingsKey, got, wantEnforce, ref.Command)
		}
	}
	if _, ok := sf.hooks["PermissionRequest"]; ok {
		t.Fatal("PermissionRequest must not be installed: Phase 0 showed it never gates a real Muse action")
	}

	// Reinstall is idempotent: no duplicated groups, schema_version untouched.
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.hooks["PreToolUse"]) != 1 {
		t.Fatalf("reinstall duplicated PreToolUse: %#v", sf.hooks["PreToolUse"])
	}
	if string(sf.values["schema_version"]) != "1" {
		t.Fatalf("reinstall disturbed schema_version: %s", sf.values["schema_version"])
	}
}

// TestMuseUserInstallPreservesExistingSchemaVersionAndForeignHooks matches an
// existing real-world settings.json (schema_version, provider, model, tui,
// plus a foreign hook under an event numbat also installs) and confirms
// numbat adds its own group alongside the foreign one without touching
// anything else.
func TestMuseUserInstallPreservesExistingSchemaVersionAndForeignHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	seed := `{
  "schema_version": 2,
  "provider": "meta",
  "model": "muse-spark-1.3-contributor",
  "tui": {"foreign_context_notice_shown": true},
  "hooks": {"SessionStart": [{"matcher":"*","hooks":[{"type":"command","command":"/opt/foreign.sh"}]}]}
}`
	if err := writeFileAtomic(path, []byte(seed)); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["schema_version"]) != "2" || string(doc["provider"]) != `"meta"` {
		t.Fatalf("foreign top-level keys not preserved: %#v", doc)
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.hooks["SessionStart"]) != 2 {
		t.Fatalf("foreign SessionStart hook was not kept alongside numbat's: %#v", sf.hooks["SessionStart"])
	}
	foreignKept := false
	for _, g := range sf.hooks["SessionStart"] {
		for _, h := range g.Hooks {
			if h.Command == "/opt/foreign.sh" {
				foreignKept = true
			}
		}
	}
	if !foreignKept {
		t.Fatal("foreign SessionStart command was dropped")
	}

	if _, err := Uninstall(AgentMuse, path); err != nil {
		t.Fatal(err)
	}
	sf, err = readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.hooks["SessionStart"]) != 1 || sf.hooks["SessionStart"][0].Hooks[0].Command != "/opt/foreign.sh" {
		t.Fatalf("uninstall changed foreign hook: %#v", sf.hooks["SessionStart"])
	}
	if string(sf.values["schema_version"]) != "2" {
		t.Fatal("uninstall must never touch schema_version")
	}
}

// TestMuseProjectHooksFileNeverGetsSchemaVersion matches Phase 0's finding
// that a project .muse/hooks.json only ever verified as a bare
// {"hooks": {...}} file; numbat must not speculatively add an unverified key
// there the way it does for the user-scope settings.json.
func TestMuseProjectHooksFileNeverGetsSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo", ".muse", "hooks.json")
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sf.values["schema_version"]; ok {
		t.Fatalf("project hooks.json must not get schema_version: %#v", sf.values)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readTestFile(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 {
		t.Fatalf("project hooks.json should have only the hooks key: %#v", doc)
	}
}

// TestMuseStatusReportsPartialInstall matches every other portable
// installer's contract: removing one wired event is reported as partial, not
// fully installed, since Phase 0 found a fully healthy hooks file prints no
// confirming summary line, so numbat's own status check must be the source
// of truth.
func TestMuseStatusReportsPartialInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	sf, err := readSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	delete(sf.hooks, "SessionEnd")
	if err := writeSettings(path, sf); err != nil {
		t.Fatal(err)
	}
	rep := Status(AgentMuse, path)
	if rep.Installed || !strings.Contains(rep.Message, "partial") {
		t.Fatalf("status after removing one event = %+v, want partial", rep)
	}

	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if !Status(AgentMuse, path).Installed {
		t.Fatal("reinstall did not restore full status")
	}
}

func TestMuseUserSettingsPathHonorsXDGConfigHome(t *testing.T) {
	home := t.TempDir()
	if got, want := MuseUserSettingsPath(home), filepath.Join(home, ".config", "muse", "settings.json"); got != want {
		t.Fatalf("MuseUserSettingsPath (no XDG) = %q, want %q", got, want)
	}
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got, want := MuseUserSettingsPath(home), filepath.Join(xdg, "muse", "settings.json"); got != want {
		t.Fatalf("MuseUserSettingsPath (XDG set) = %q, want %q", got, want)
	}
}

func TestMuseNeedsSchemaVersionOnlyForSettingsBasename(t *testing.T) {
	if !museNeedsSchemaVersion(filepath.Join("home", ".config", "muse", "settings.json")) {
		t.Error("settings.json should need schema_version")
	}
	if museNeedsSchemaVersion(filepath.Join("repo", ".muse", "hooks.json")) {
		t.Error("hooks.json should not need schema_version")
	}
}

func TestMuseForeignFileWithCommentsIsRefusedNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	// A trailing comma after the last member is invalid strict JSON; Muse's
	// docs never claim JSONC support the way Devin's do, so numbat must
	// refuse rather than silently mangle it.
	if err := writeFileAtomic(path, []byte(`{"schema_version":1,"provider":"meta",}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("trailing-comma settings.json should be refused, not rewritten")
	}
}
