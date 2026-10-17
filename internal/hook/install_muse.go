// Copyright (c) Meta Platforms, Inc. and affiliates.

package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// install_muse.go wires numbat into Muse Code's hooks.json contract. Both the
// user-scope settings.json and project/ordinary managed hook files embed the same
// {"hooks": {"<Event>": [{"matcher":...,"hooks":[{"type":"command",...}]}]}}
// shape numbat already reads/writes generically for Claude via settingsFile,
// so this file only supplies Muse's own event list, path resolution, and the
// one real per-scope difference: the user settings file requires a top-level
// "schema_version": 1 or every muse command fails at startup; a project
// hooks.json does not. The hook shape and reserved hooks.state metadata are
// documented at https://meta-models.github.io/muse-code-sdk/next/guides/extend/hooks/.

// museSettingsBasename names Muse's user-scope config file. Only a path with
// this exact basename gets the schema_version invariant.
const museSettingsBasename = "settings.json"

// museHookEvents is the hook set numbat installs for Muse Code by default,
// and the matcher/shape covered by the Muse 1.3.0 fixtures:
//   - PermissionRequest is omitted; PreToolUse is the supported pre-action
//     enforcement point. The vendor also allows PermissionRequest to deny
//     a tool call awaiting approval.
//   - PreCompact, PostCompact, Notification, PreLLMCall, and PostLLMCall
//     are not installed or mapped by numbat.
var museHookEvents = []claudeHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", matcher: "*", timeout: promptHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUse", lifecycle: "post-tool", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUseFailure", lifecycle: "post-tool", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStart", lifecycle: "session-start", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStop", lifecycle: "session-end", matcher: "*", timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: "stop", matcher: "*", timeout: stopHookTimeoutSeconds},
	{settingsKey: "SessionEnd", lifecycle: "session-end", matcher: "*", timeout: fastHookTimeoutSeconds},
}

// MuseUserSettingsPath returns Muse's user-scope settings.json path:
// ${XDG_CONFIG_HOME:-home/.config}/muse/settings.json. Confirmed empirically
// (an isolated XDG_CONFIG_HOME test against a real settings.json, never
// touching the real file) and by the installed binary's own config-root
// resolution logic; no separate MUSE_CONFIG_DIR override exists.
func MuseUserSettingsPath(home string) string {
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" {
		root = filepath.Join(home, ".config")
	}
	return filepath.Join(root, "muse", museSettingsBasename)
}

// museNeedsSchemaVersion reports whether path is Muse's user-scope settings
// file. A project .muse/hooks.json only ever verified as a bare
// {"hooks": {...}} file; speculatively adding an unverified top-level key
// there is exactly the kind of unverified vendor behavior numbat's contract
// rules out, so only the settings.json basename gets the injected key.
func museNeedsSchemaVersion(path string) bool {
	return filepath.Base(path) == museSettingsBasename
}

func museCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentMuse, runtimeArgs, enforce)
}

// applyMuseHooksWithArgs (re)builds numbat's groups for each event, replacing
// any prior numbat group so a re-install is idempotent. Muse's command field
// is a shell string (matching Kimi/Qwen/Devin), not Claude's execv-style
// command+args array: Muse's own docs describe hooks as running "directly
// through your shell," and the captured fixtures use a single command
// string successfully.
func applyMuseHooksWithArgs(sf settingsFile, binary string, runtimeArgs []string, enforce bool) {
	for _, ev := range museHookEvents {
		groups := stripNumbatGroups(sf.hooks[ev.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: ev.matcher,
			Hooks: []hookRef{{
				Type:    "command",
				Command: museCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.settingsKey == "PreToolUse"),
				Timeout: ev.timeout,
			}},
		})
		sf.hooks[ev.settingsKey] = groups
	}
}

// installMuseWithArgs writes numbat's hook entries into a Muse settings.json,
// project hooks.json, or explicit managed file, preserving foreign entries and
// keeping one pristine backup. readSettings' strict JSON parse already
// refuses (rather than silently mangles) a file with comments or trailing
// commas, matching the Qwen/Auggie installers' contract; Muse's own docs
// never claim JSONC support the way Devin's do.
func installMuseWithArgs(path, binary string, runtimeArgs []string, enforce, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentMuse, SettingsPath: path, Supported: true}
	sf, err := readMuseSettings(path, managed)
	if err != nil {
		return rep, err
	}
	if !managed && museNeedsSchemaVersion(path) {
		if _, ok := sf.values["schema_version"]; !ok {
			if err := setJSONField(sf.values, "schema_version", 1); err != nil {
				return rep, err
			}
		}
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	applyMuseHooksWithArgs(sf, binary, runtimeArgs, enforce)
	if err := writeMuseSettings(path, sf, managed); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = installMessage(enforce)
	if managed {
		rep.Message += "; managed file only: configure managed_hooks_path separately"
	}
	return rep, nil
}

// uninstallMuse removes only numbat-owned hook entries, leaving foreign hooks
// and every other top-level key untouched.
func uninstallMuse(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentMuse, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	sf, err := readMuseSettings(path, managed)
	if err != nil {
		return rep, err
	}
	if !sf.removeNumbatHooks() {
		rep.Message = "no numbat hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeMuseSettings(path, sf, managed); err != nil {
		return rep, err
	}
	rep.Changed, rep.Message = true, "removed numbat hooks"
	return rep, nil
}

// museHookState reports whether every default event is wired (complete) and
// whether any numbat hook is present at all (any). This checks configuration,
// not whether a Muse session loaded or executed the hooks.
func museHookState(sf settingsFile) (complete, any bool) {
	complete = true
	for _, ev := range museHookEvents {
		present := hasNumbatGroup(sf.hooks[ev.settingsKey])
		complete = complete && present
		any = any || present
	}
	return complete, any
}

// statusMuse validates the file and reports whether numbat's hooks are fully
// present, without modifying anything.
func statusMuse(path string) InstallReport {
	rep, _ := statusMuseWithScope(path, false)
	return rep
}

func statusMuseWithScope(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentMuse, SettingsPath: path, Supported: true}
	sf, err := readMuseSettings(path, managed)
	if err != nil {
		rep.Message = err.Error()
		return rep, err
	}
	complete, any := museHookState(sf)
	rep.Installed = complete
	switch {
	case complete:
		rep.Message = "numbat hooks installed"
	case any:
		rep.Message = "partial numbat Muse hook install"
	default:
		rep.Message = "numbat hooks not installed"
	}
	return rep, nil
}

func writeMuseSettings(path string, sf settingsFile, managed bool) error {
	if managed {
		return writeManagedSettings(path, sf)
	}
	return writeSettings(path, sf)
}

func readMuseSettings(path string, managed bool) (settingsFile, error) {
	sf, err := readHookSettings(path, true)
	if err != nil || !managed {
		return sf, err
	}
	if _, ok := sf.values["managed_hooks_env_vars"]; ok {
		return settingsFile{}, fmt.Errorf("%s: managed_hooks_env_vars belongs in Muse settings, not a managed hooks file", path)
	}
	// Either field opts the whole file into Muse's different, stricter schema.
	// Do not mix ordinary hooks into it or rewrite someone else's policy.
	for _, groups := range sf.hooks {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if err := checkMuseManagedHook(ref.fields); err != nil {
					return settingsFile{}, fmt.Errorf("%s: %w", path, err)
				}
			}
		}
	}
	return sf, nil
}

func checkMuseManagedHook(fields map[string]json.RawMessage) error {
	for len(fields) > 0 {
		for _, key := range []string{"name", "timeout_ms"} {
			if _, ok := fields[key]; ok {
				return fmt.Errorf("strict Muse managed hooks (%s) are unsupported; use an ordinary managed hooks file", key)
			}
		}
		raw, ok := fields["onFailure"]
		if !ok {
			break
		}
		// Fallback handlers also select the format of the entire document.
		var fallback map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fallback); err != nil {
			return fmt.Errorf("invalid Muse onFailure handler: %w", err)
		}
		fields = fallback
	}
	return nil
}

// MuseLifecycleArgs returns the lifecycle argument names numbat wires for
// Muse, in event order, for diagnostics and tests.
func MuseLifecycleArgs() []string {
	out := make([]string, 0, len(museHookEvents))
	for _, ev := range museHookEvents {
		out = append(out, ev.lifecycle)
	}
	return out
}
