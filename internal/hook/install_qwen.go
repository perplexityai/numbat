package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const qwenHookName = "numbat--installed-by=numbat"

type qwenHookEvent struct {
	settingsKey string
	lifecycle   string
	matcher     string
	timeoutMs   int
}

var qwenHookEvents = []qwenHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", timeoutMs: promptHookTimeoutSeconds * 1000},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PostToolUse", lifecycle: "post-tool", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PostToolUseFailure", lifecycle: "post-tool", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PermissionRequest", lifecycle: "permission-request", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "PermissionDenied", lifecycle: "permission-denied", matcher: ".*", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "Stop", lifecycle: "stop", timeoutMs: stopHookTimeoutSeconds * 1000},
	{settingsKey: "SessionEnd", lifecycle: "session-end", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "SubagentStart", lifecycle: "session-start", timeoutMs: fastHookTimeoutSeconds * 1000},
	{settingsKey: "SubagentStop", lifecycle: "session-end", timeoutMs: fastHookTimeoutSeconds * 1000},
}

func QwenSettingsPath(home string) string {
	root := strings.TrimSpace(os.Getenv("QWEN_HOME"))
	if root == "" {
		root = filepath.Join(home, ".qwen")
	} else if root == "~" {
		root = home
	} else if strings.HasPrefix(root, "~/") || strings.HasPrefix(root, `~\`) {
		root = filepath.Join(home, root[2:])
	}
	return filepath.Join(root, "settings.json")
}

func qwenCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentQwen, runtimeArgs, enforce)
}

func isNumbatQwenHook(ref geminiHookRef) bool {
	return ref.Name == qwenHookName || isNumbatHookCommand(ref.Command)
}

func stripNumbatQwenGroups(groups []geminiHookGroup) []geminiHookGroup {
	out := make([]geminiHookGroup, 0, len(groups))
	for _, group := range groups {
		kept := group.Hooks[:0:0]
		for _, ref := range group.Hooks {
			if !isNumbatQwenHook(ref) {
				kept = append(kept, ref)
			}
		}
		if len(kept) > 0 {
			group.Hooks = kept
			out = append(out, group)
		}
	}
	return out
}

func qwenHookState(gs geminiSettings) (complete, any bool) {
	complete = true
	for _, groups := range gs.hooks {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if isNumbatQwenHook(ref) {
					any = true
				}
			}
		}
	}
	for _, event := range qwenHookEvents {
		present := false
		for _, group := range gs.hooks[event.settingsKey] {
			for _, ref := range group.Hooks {
				present = present || isNumbatQwenHook(ref)
			}
		}
		complete = complete && present
	}
	return complete, any
}

func hasNumbatQwenHooks(gs geminiSettings) bool {
	_, any := qwenHookState(gs)
	return any
}

func removeNumbatQwenHooks(gs geminiSettings) bool {
	changed := false
	for key, groups := range gs.hooks {
		keptGroups := make([]geminiHookGroup, 0, len(groups))
		for _, group := range groups {
			keptRefs := group.Hooks[:0:0]
			for _, ref := range group.Hooks {
				if isNumbatQwenHook(ref) {
					changed = true
					continue
				}
				keptRefs = append(keptRefs, ref)
			}
			if len(keptRefs) > 0 {
				group.Hooks = keptRefs
				keptGroups = append(keptGroups, group)
			}
		}
		if len(keptGroups) == 0 {
			delete(gs.hooks, key)
		} else {
			gs.hooks[key] = keptGroups
		}
	}
	return changed
}

func applyQwenHooks(gs geminiSettings, binary string, runtimeArgs []string, enforce bool) geminiSettings {
	for _, event := range qwenHookEvents {
		groups := stripNumbatQwenGroups(gs.hooks[event.settingsKey])
		groups = append(groups, geminiHookGroup{
			Matcher: event.matcher,
			Hooks: []geminiHookRef{{
				Name:        qwenHookName,
				Type:        "command",
				Command:     qwenCommandWithArgs(binary, event.lifecycle, runtimeArgs, enforce && event.settingsKey == "PreToolUse"),
				Timeout:     event.timeoutMs,
				Description: "numbat endpoint activity monitor",
			}},
		})
		gs.hooks[event.settingsKey] = groups
	}
	return gs
}

func installQwenWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installQwenWithArgsMode(path, binary, runtimeArgs, enforce, false)
}

func installQwenManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	return installQwenWithArgsMode(path, binary, runtimeArgs, enforce, true)
}

func installQwenWithArgsMode(path, binary string, runtimeArgs []string, enforce, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentQwen, SettingsPath: path, Supported: true}
	gs, err := readGeminiSettings(path)
	if err != nil {
		return rep, fmt.Errorf("parse Qwen settings (comments and trailing commas must be removed before automatic install): %w", err)
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	gs = applyQwenHooks(gs, binary, runtimeArgs, enforce)
	if err := writeGeminiSettings(path, gs, managed); err != nil {
		return rep, err
	}
	rep.Installed, rep.Changed = true, true
	rep.Message = installMessage(enforce)
	if managed {
		rep.Message = strings.Replace(rep.Message, "installed", "installed managed", 1)
	}
	return rep, nil
}

func uninstallQwen(path string) (InstallReport, error) {
	return uninstallQwenMode(path, false)
}

func uninstallQwenManaged(path string) (InstallReport, error) {
	return uninstallQwenMode(path, true)
}

func uninstallQwenMode(path string, managed bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentQwen, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	gs, err := readGeminiSettings(path)
	if err != nil {
		return rep, err
	}
	if !removeNumbatQwenHooks(gs) {
		rep.Message = "no numbat hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeGeminiSettings(path, gs, managed); err != nil {
		return rep, err
	}
	rep.Changed, rep.Message = true, "removed numbat hooks"
	if managed {
		rep.Message = "removed numbat managed hooks"
	}
	return rep, nil
}

func statusQwen(path string) InstallReport {
	rep := InstallReport{Agent: AgentQwen, SettingsPath: path, Supported: true}
	gs, err := readGeminiSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	complete, any := qwenHookState(gs)
	rep.Installed = complete
	if complete {
		rep.Message = "numbat hooks installed"
	} else if any {
		rep.Message = "partial numbat Qwen hook install"
	} else {
		rep.Message = "numbat hooks not installed"
	}
	return rep
}
