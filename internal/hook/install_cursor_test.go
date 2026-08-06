package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readCursorHooks loads the hooks block from a Cursor hooks.json for assertions.
func readCursorHooks(t *testing.T, path string) map[string][]json.RawMessage {
	t.Helper()
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	return cs.hooks
}

// countCursorNumbatHooks counts numbat-installed entries across all events.
func countCursorNumbatHooks(hooks map[string][]json.RawMessage) int {
	n := 0
	for _, entries := range hooks {
		for _, raw := range entries {
			if entryIsNumbat(raw) {
				n++
			}
		}
	}
	return n
}

func TestCursorInstallCreatesAllEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cursor", "hooks.json")
	rep, err := Install(AgentCursor, path, numbatBinary, "", false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !rep.Supported || !rep.Installed || !rep.Changed {
		t.Fatalf("report = %+v, want supported+installed+changed", rep)
	}
	hooks := readCursorHooks(t, path)
	if got, want := countCursorNumbatHooks(hooks), len(cursorHookEvents); got != want {
		t.Fatalf("installed %d numbat hooks, want one per event (%d)", got, want)
	}
	// The schema must carry version 1 and a hooks map keyed by the Cursor event
	// names (one entry list per event).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version int                          `json:"version"`
		Hooks   map[string][]cursorHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json is not valid: %v", err)
	}
	if parsed.Version != 1 {
		t.Errorf("version = %d, want 1", parsed.Version)
	}
	for _, spec := range cursorHookEvents {
		entries, ok := parsed.Hooks[spec.event]
		if !ok || len(entries) == 0 {
			t.Errorf("event %q missing from installed hooks", spec.event)
			continue
		}
		cmd := entries[0].Command
		cmd = hookCommandText(cmd)
		if !strings.Contains(cmd, "hook "+spec.event) || !strings.Contains(cmd, "--agent cursor") {
			t.Errorf("event %q command malformed: %q", spec.event, cmd)
		}
		if entries[0].Timeout != spec.timeout {
			t.Errorf("event %q timeout = %d, want %d", spec.event, entries[0].Timeout, spec.timeout)
		}
		if entries[0].Matcher != spec.matcher {
			t.Errorf("event %q matcher = %q, want %q", spec.event, entries[0].Matcher, spec.matcher)
		}
	}
	for _, duplicate := range []string{"beforeShellExecution", "afterShellExecution", "beforeMCPExecution", "afterMCPExecution", "afterFileEdit"} {
		if _, ok := parsed.Hooks[duplicate]; ok {
			t.Errorf("overlapping specialized event %q should not be installed", duplicate)
		}
	}
	// The file must be 0600 since a hooks file can carry tokens.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms = %o, want 600", perm)
	}
}

func TestCursorInstallIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("install 1: %v", err)
	}
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("install 2: %v", err)
	}
	hooks := readCursorHooks(t, path)
	if got, want := countCursorNumbatHooks(hooks), len(cursorHookEvents); got != want {
		t.Fatalf("after two installs got %d numbat hooks, want %d (no duplicates)", got, want)
	}
}

func TestCursorReinstallMigratesOwnedSpecializedHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"beforeShellExecution": []any{
				map[string]any{"command": cursorCommandWithArgs(numbatBinary, "beforeShellExecution", nil, false)},
				map[string]any{"command": "/opt/user-audit shell"},
			},
			"afterFileEdit": []any{
				map[string]any{"command": cursorCommandWithArgs(numbatBinary, "afterFileEdit", nil, false)},
			},
		},
	}
	writeJSON(t, path, seed)
	before := Status(AgentCursor, path)
	if before.Installed || !strings.Contains(before.Message, "incomplete") {
		t.Fatalf("status for legacy event set = %+v, want incomplete", before)
	}

	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	hooks := readCursorHooks(t, path)
	if got := countCursorNumbatHooks(hooks); got != len(cursorHookEvents) {
		t.Fatalf("numbat hooks = %d, want %d", got, len(cursorHookEvents))
	}
	if _, ok := hooks["afterFileEdit"]; ok {
		t.Fatal("stale owned afterFileEdit hook survived generic-hook migration")
	}
	entries := hooks["beforeShellExecution"]
	if len(entries) != 1 || rawEntryCommand(entries[0]) != "/opt/user-audit shell" {
		t.Fatalf("specialized user hook was not preserved exactly: %s", entries)
	}
	if after := Status(AgentCursor, path); !after.Installed {
		t.Fatalf("status after migration = %+v, want installed", after)
	}
}

func TestCursorEnforceInstallWiresOnlyBlockingHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := InstallWithOptions(AgentCursor, path, numbatBinary, InstallOptions{Enforce: true}); err != nil {
		t.Fatal(err)
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := countCursorNumbatHooks(cs.hooks), len(cursorHookEvents); got != want {
		t.Fatalf("enforce install hooks = %d, want %d", got, want)
	}
	enforceEvents := map[string]bool{
		"preToolUse":     true,
		"beforeReadFile": true,
	}
	for event, entries := range cs.hooks {
		for _, raw := range entries {
			if !entryIsNumbat(raw) {
				continue
			}
			var entry cursorHookEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(decodedHookCommand(entry.Command), enforceFlag); got != enforceEvents[event] {
				t.Errorf("%s enforce flag = %v, want %v: %s", event, got, enforceEvents[event], entry.Command)
			}
			specMatcher := ""
			for _, spec := range cursorHookEvents {
				if spec.event == event {
					specMatcher = spec.matcher
					break
				}
			}
			if entry.Matcher != specMatcher {
				t.Errorf("%s matcher = %q, want %q", event, entry.Matcher, specMatcher)
			}
		}
	}

	if _, err := InstallWithOptions(AgentCursor, path, numbatBinary, InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	cs, err = readCursorSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := countCursorNumbatHooks(cs.hooks), len(cursorHookEvents); got != want {
		t.Fatalf("monitor reinstall hooks = %d, want %d", got, want)
	}
	if _, ok := cs.hooks["preToolUse"]; !ok {
		t.Fatal("monitor reinstall removed the generic preToolUse sensor")
	}
	for _, entries := range cs.hooks {
		for _, raw := range entries {
			if entryIsNumbat(raw) && strings.Contains(decodedHookCommand(rawEntryCommand(raw)), enforceFlag) {
				t.Fatalf("monitor reinstall left --enforce in %s", raw)
			}
		}
	}
}

func TestCursorInstallPreservesUnrelatedKeysAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// A pre-existing hooks.json with an unrelated top-level key and a user-defined
	// beforeShellExecution hook numbat must not disturb. A user entry may carry
	// extra keys (timeout) that must round-trip untouched.
	seed := map[string]any{
		"version":      1,
		"customConfig": map[string]any{"foo": "bar"},
		"hooks": map[string]any{
			"beforeShellExecution": []any{
				map[string]any{"command": "/opt/user-audit shell", "timeout": 10},
			},
		},
	}
	writeJSON(t, path, seed)

	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := parsed["customConfig"]; !ok {
		t.Error("unrelated top-level key customConfig was dropped")
	}

	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	// The user's audit hook must still be present alongside numbat's, with its
	// extra timeout key intact.
	foundUser := false
	for _, raw := range cs.hooks["beforeShellExecution"] {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}
		if m["command"] == "/opt/user-audit shell" {
			foundUser = true
			if m["timeout"] != float64(10) {
				t.Errorf("user entry lost its timeout key: %v", m)
			}
		}
	}
	if !foundUser {
		t.Error("user's beforeShellExecution hook was dropped")
	}
	if countCursorNumbatHooks(cs.hooks) != len(cursorHookEvents) {
		t.Errorf("numbat hooks = %d, want %d", countCursorNumbatHooks(cs.hooks), len(cursorHookEvents))
	}
}

func TestCursorUninstallRemovesOnlyNumbatHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"beforeShellExecution": []any{
				map[string]any{"command": "/opt/user-audit shell"},
			},
		},
	}
	writeJSON(t, path, seed)
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rep, err := Uninstall(AgentCursor, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	if countCursorNumbatHooks(cs.hooks) != 0 {
		t.Errorf("numbat hooks remain after uninstall: %+v", cs.hooks)
	}
	// The user's hook survives.
	foundUser := false
	for _, raw := range cs.hooks["beforeShellExecution"] {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if m["command"] == "/opt/user-audit shell" {
			foundUser = true
		}
	}
	if !foundUser {
		t.Error("uninstall removed the user's unrelated hook")
	}
}

// Uninstalling from a file that held ONLY numbat entries must still leave a
// valid Cursor hooks.json — {version,hooks:{...}} — not collapse to a
// version-only object. The hooks map must be present (even if empty) so Cursor
// can still read the file.
func TestCursorUninstallLeavesValidSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	// Start from nothing: install writes only numbat entries.
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(AgentCursor, path); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version int                          `json:"version"`
		Hooks   map[string][]cursorHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("post-uninstall hooks.json is not valid: %v (%s)", err, data)
	}
	if parsed.Version != 1 {
		t.Errorf("version = %d, want 1", parsed.Version)
	}
	// The hooks key must be present (a hooks map), not absent. Decoding a missing
	// key yields nil; an empty object yields a non-nil empty map, so assert the
	// raw JSON actually carries the key.
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall file dropped the hooks map: %s", data)
	}
	if countCursorNumbatHooks(readCursorHooks(t, path)) != 0 {
		t.Errorf("numbat hooks remain after uninstall: %s", data)
	}
}

func TestCursorUninstallNoFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	rep, err := Uninstall(AgentCursor, path)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if rep.Changed {
		t.Error("uninstall on a missing file must not report a change")
	}
}

func TestCursorStatusReflectsInstallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if rep := Status(AgentCursor, path); rep.Installed {
		t.Error("status before install should be not-installed")
	}
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if rep := Status(AgentCursor, path); !rep.Installed {
		t.Error("status after install should be installed")
	}
}

func TestCursorMalformedSettingsErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err == nil {
		t.Error("Install on malformed hooks.json should error rather than corrupt the file")
	}
}

func TestCursorRejectsInvalidRootAndSchemaVersion(t *testing.T) {
	tests := map[string]string{
		"null root":           `null`,
		"array root":          `[]`,
		"string root":         `"invalid"`,
		"string version":      `{"version":"1","hooks":{}}`,
		"unsupported version": `{"version":2,"hooks":{}}`,
		"null hooks":          `{"version":1,"hooks":null}`,
		"array hooks":         `{"version":1,"hooks":[]}`,
	}
	for name, original := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := StatusErr(AgentCursor, path); err == nil {
				t.Fatal("StatusErr should reject the invalid Cursor schema")
			}
			if _, err := Install(AgentCursor, path, numbatBinary, "", false); err == nil {
				t.Fatal("Install should reject the invalid Cursor schema")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != original {
				t.Fatalf("failed install rewrote invalid input: %q", after)
			}
		})
	}
}

// Detection keys on the numbat marker, not the binary path, so a binary with no
// "numbat" in its name still installs, reports installed, uninstalls cleanly, and
// reinstalls without duplicating entries.
func TestCursorInstallDetectionIsRenameProof(t *testing.T) {
	const renamed = "/opt/tools/agent-watch"
	if strings.Contains(renamed, "numbat") {
		t.Fatalf("test binary path %q must not contain numbat", renamed)
	}
	path := filepath.Join(t.TempDir(), "hooks.json")
	if _, err := Install(AgentCursor, path, renamed, "", false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if rep := Status(AgentCursor, path); !rep.Installed {
		t.Fatalf("status after install with renamed binary = not-installed, want installed")
	}
	if got := countCursorNumbatHooks(readCursorHooks(t, path)); got != len(cursorHookEvents) {
		t.Fatalf("after install got %d hooks, want %d", got, len(cursorHookEvents))
	}
	if _, err := Install(AgentCursor, path, renamed, "", false); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if got := countCursorNumbatHooks(readCursorHooks(t, path)); got != len(cursorHookEvents) {
		t.Fatalf("after reinstall got %d hooks, want %d (no duplicates)", got, len(cursorHookEvents))
	}
	rep, err := Uninstall(AgentCursor, path)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Changed {
		t.Error("uninstall should report a change")
	}
	if got := countCursorNumbatHooks(readCursorHooks(t, path)); got != 0 {
		t.Errorf("hooks remain after uninstall: %d", got)
	}
}

// The backup must preserve the pristine pre-numbat original across repeated
// install / install→uninstall→install cycles.
func TestCursorBackupPreservesPristineOriginal(t *testing.T) {
	const pristine = `{"version":1,"hooks":{"beforeShellExecution":[{"command":"/opt/keep me"}]}}`
	check := func(t *testing.T, mutate func(path string)) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if err := os.WriteFile(path, []byte(pristine), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		mutate(path)
		data, err := os.ReadFile(path + backupSuffix)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if !strings.Contains(string(data), "/opt/keep me") {
			t.Fatalf("backup is not the pristine original: %s", data)
		}
	}
	t.Run("install twice", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
	t.Run("install uninstall install", func(t *testing.T) {
		check(t, func(path string) {
			if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
				t.Fatalf("install 1: %v", err)
			}
			if _, err := Uninstall(AgentCursor, path); err != nil {
				t.Fatalf("uninstall: %v", err)
			}
			if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
				t.Fatalf("install 2: %v", err)
			}
		})
	})
}

// A pre-existing 0644 hooks.json must be tightened to 0600 after an in-place
// rewrite, since it can carry tokens.
func TestCursorInstallEnforces0600OnPreExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := Install(AgentCursor, path, numbatBinary, "", false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); !modeMatches(perm, 0o600) {
		t.Errorf("hooks.json perms after install = %o, want 600", perm)
	}
}

// When an output file is supplied, every installed command wires durable findings
// output so a hook-detected finding is not lost to stderr.
func TestCursorInstallWiresDurableOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const out = "/home/u/.numbat/findings.ndjson"
	if _, err := Install(AgentCursor, path, numbatBinary, out, false); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cs, err := readCursorSettings(path)
	if err != nil {
		t.Fatalf("readCursorSettings: %v", err)
	}
	n := 0
	for _, entries := range cs.hooks {
		for _, raw := range entries {
			if !entryIsNumbat(raw) {
				continue
			}
			n++
			var e cursorHookEntry
			_ = json.Unmarshal(raw, &e)
			command := hookCommandText(e.Command)
			if !strings.Contains(command, "--output=file") || !strings.Contains(command, out) {
				t.Errorf("command missing durable output wiring: %q", e.Command)
			}
		}
	}
	if n != len(cursorHookEvents) {
		t.Fatalf("wired %d numbat commands, want %d", n, len(cursorHookEvents))
	}
}
