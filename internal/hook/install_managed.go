package hook

import (
	"fmt"
	"os"
	"strings"
)

// installClaudeManagedWithArgs writes Claude Code managed settings JSON. The
// default path is a managed-settings.d drop-in, but callers may pass an explicit
// managed settings file path.
func installClaudeManagedWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentClaude, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	sf.applyNumbatHooksWithArgs(binary, runtimeArgs, enforce)
	if err := writeManagedSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	if enforce {
		rep.Message = "installed numbat managed hooks (enforce mode: requests denies for enforcement-enabled rules or configured decision policies)"
	} else {
		rep.Message = "installed numbat managed hooks"
	}
	return rep, nil
}

func uninstallClaudeManaged(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentClaude, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	sf, err := readSettings(path)
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
	if err := writeManagedSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed numbat managed hooks"
	return rep, nil
}

func statusClaudeManagedErr(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentClaude, SettingsPath: path, Supported: true}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep, err
	}
	rep.Installed = sf.hasNumbatHooks()
	if rep.Installed {
		rep.Message = "numbat managed hooks installed"
	} else {
		rep.Message = "numbat managed hooks not installed"
	}
	return rep, nil
}

const (
	codexNumbatFeatureBlockStart = "# BEGIN numbat managed codex features"
	codexNumbatFeatureBlockEnd   = "# END numbat managed codex features"
	codexNumbatHookBlockStart    = "# BEGIN numbat managed codex hooks"
	codexNumbatHookBlockEnd      = "# END numbat managed codex hooks"
	codexNumbatFeatureLine       = "hooks = true # numbat-managed"
)

func installCodexRequirementsWithArgs(path, binary string, runtimeArgs []string, enforce bool) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	body, err := readOptionalText(path)
	if err != nil {
		return rep, err
	}
	body, err = codexRequirementsWithNumbatHooks(body, binary, runtimeArgs, enforce)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeManagedFileAtomic(path, []byte(body)); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	if enforce {
		rep.Message = "installed numbat managed hooks in requirements.toml (enforce mode)"
	} else {
		rep.Message = "installed numbat managed hooks in requirements.toml"
	}
	return rep, nil
}

func uninstallCodexRequirements(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no requirements file; nothing to remove"
		return rep, nil
	}
	bodyBytes, err := readHookConfigFile(path)
	if err != nil {
		return rep, err
	}
	body := removeNumbatCodexRequirements(string(bodyBytes))
	if body == string(bodyBytes) {
		rep.Message = "no numbat managed hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeManagedFileAtomic(path, []byte(body)); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed numbat managed hooks from requirements.toml"
	return rep, nil
}

func statusCodexRequirements(path string) (InstallReport, error) {
	rep := InstallReport{Agent: AgentCodex, SettingsPath: path, Supported: true}
	body, err := readOptionalText(path)
	if err != nil {
		rep.Message = err.Error()
		return rep, err
	}
	rep.Installed = strings.Contains(body, codexNumbatHookBlockStart)
	if rep.Installed {
		rep.Message = "numbat managed hooks installed"
	} else {
		rep.Message = "numbat managed hooks not installed"
	}
	return rep, nil
}

func readOptionalText(path string) (string, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

func codexRequirementsWithNumbatHooks(body, binary string, runtimeArgs []string, enforce bool) (string, error) {
	body = removeNumbatCodexRequirements(body)
	var err error
	body, err = ensureCodexHooksFeature(body)
	if err != nil {
		return "", err
	}
	body = strings.TrimRight(body, "\n")
	if body != "" {
		body += "\n\n"
	}
	body += renderCodexRequirementsHookBlock(binary, runtimeArgs, enforce)
	return body, nil
}

func removeNumbatCodexRequirements(body string) string {
	var changed bool
	body, changed = removeMarkedBlock(body, codexNumbatHookBlockStart, codexNumbatHookBlockEnd)
	body, changed = removeMarkedBlockChanged(body, codexNumbatFeatureBlockStart, codexNumbatFeatureBlockEnd, changed)
	body, changed = removeMarkedLineChanged(body, codexNumbatFeatureLine, changed)
	if !changed {
		return body
	}
	body = strings.TrimRight(body, "\n")
	if strings.TrimSpace(body) == "" {
		return ""
	}
	return body + "\n"
}

func renderCodexRequirementsHookBlock(binary string, runtimeArgs []string, enforce bool) string {
	var b strings.Builder
	b.WriteString(codexNumbatHookBlockStart)
	b.WriteByte('\n')
	for _, ev := range codexHookEvents {
		fmt.Fprintf(&b, "[[hooks.%s]]\n", ev.settingsKey)
		if ev.matcher != "" {
			fmt.Fprintf(&b, "matcher = %s\n", tomlString(ev.matcher))
		}
		fmt.Fprintf(&b, "[[hooks.%s.hooks]]\n", ev.settingsKey)
		b.WriteString(`type = "command"` + "\n")
		fmt.Fprintf(&b, "command = %s\n", tomlString(codexCommandWithArgs(binary, ev.lifecycle, runtimeArgs, enforce && ev.settingsKey == "PreToolUse")))
		if ev.timeout > 0 {
			fmt.Fprintf(&b, "timeout = %d\n", ev.timeout)
		}
		b.WriteByte('\n')
	}
	b.WriteString(codexNumbatHookBlockEnd)
	b.WriteByte('\n')
	return b.String()
}

func ensureCodexHooksFeature(body string) (string, error) {
	lines := splitLines(body)
	start, end := findTomlTable(lines, "features")
	if start == -1 {
		body = strings.TrimRight(body, "\n")
		if body != "" {
			body += "\n\n"
		}
		body += codexNumbatFeatureBlockStart + "\n[features]\n" + codexNumbatFeatureLine + "\n" + codexNumbatFeatureBlockEnd + "\n"
		return body, nil
	}
	for i := start + 1; i < end; i++ {
		key, value, ok := parseTomlAssignment(lines[i])
		if !ok || key != "hooks" {
			continue
		}
		switch value {
		case "true":
			return body, nil
		case "false":
			return "", fmt.Errorf("requirements.toml has [features].hooks=false; set it true before installing managed Codex hooks")
		default:
			return "", fmt.Errorf("requirements.toml has unsupported [features].hooks value %s", value)
		}
	}
	insert := append([]string{}, lines[:start+1]...)
	insert = append(insert, codexNumbatFeatureLine)
	insert = append(insert, lines[start+1:]...)
	return strings.Join(insert, "\n"), nil
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func findTomlTable(lines []string, name string) (int, int) {
	want := "[" + name + "]"
	for i, line := range lines {
		if normalizedTomlHeader(line) != want {
			continue
		}
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if h := normalizedTomlHeader(lines[j]); h != "" {
				end = j
				break
			}
		}
		return i, end
	}
	return -1, -1
}

func normalizedTomlHeader(line string) string {
	code := stripTomlComment(line)
	if strings.HasPrefix(code, "[") && strings.HasSuffix(code, "]") {
		return code
	}
	return ""
}

func parseTomlAssignment(line string) (key, value string, ok bool) {
	code := stripTomlComment(line)
	before, after, found := strings.Cut(code, "=")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(before), strings.TrimSpace(after), true
}

func stripTomlComment(line string) string {
	inBasic := false
	inLiteral := false
	escaped := false
	for i, r := range line {
		if inBasic {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inBasic = false
			}
			continue
		}
		if inLiteral {
			if r == '\'' {
				inLiteral = false
			}
			continue
		}
		switch r {
		case '#':
			return strings.TrimSpace(line[:i])
		case '"':
			inBasic = true
		case '\'':
			inLiteral = true
		}
	}
	return strings.TrimSpace(line)
}

func removeMarkedBlockChanged(body, start, end string, changed bool) (string, bool) {
	body, removed := removeMarkedBlock(body, start, end)
	return body, changed || removed
}

func removeMarkedBlock(body, start, end string) (string, bool) {
	lines := splitLines(body)
	if len(lines) == 0 {
		return body, false
	}
	out := make([]string, 0, len(lines))
	changed := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) != start {
			out = append(out, line)
			continue
		}
		endAt := -1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == end {
				endAt = j
				break
			}
		}
		if endAt == -1 {
			out = append(out, line)
			continue
		}
		changed = true
		i = endAt
	}
	if !changed {
		return body, false
	}
	return strings.Join(out, "\n"), true
}

func removeMarkedLineChanged(body, marker string, changed bool) (string, bool) {
	body, removed := removeMarkedLine(body, marker)
	return body, changed || removed
}

func removeMarkedLine(body, marker string) (string, bool) {
	lines := splitLines(body)
	out := make([]string, 0, len(lines))
	changed := false
	for _, line := range lines {
		if strings.TrimSpace(line) == marker {
			changed = true
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return body, false
	}
	return strings.Join(out, "\n"), true
}

func tomlString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
