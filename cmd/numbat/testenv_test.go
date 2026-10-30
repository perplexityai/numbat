package main

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func setTestHome(t *testing.T, home string) {
	t.Helper()
	previousManagedHooksPath := inventoryManagedHooksPath
	inventoryManagedHooksPath = func(string) (string, bool) { return "", false }
	t.Cleanup(func() { inventoryManagedHooksPath = previousManagedHooksPath })
	previousApplicationsDir := systemApplicationsDir
	systemApplicationsDir = filepath.Join(home, ".test-system-applications")
	t.Cleanup(func() { systemApplicationsDir = previousApplicationsDir })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PI_CODING_AGENT_SESSION_DIR", "")
	t.Setenv("PI_CODING_AGENT_DIR", "")
	t.Setenv("KIMI_CODE_HOME", "")
	t.Setenv("QWEN_HOME", "")
	t.Setenv("QWEN_CODE_SYSTEM_SETTINGS_PATH", "")
	t.Setenv("CLINE_DIR", "")
	t.Setenv("CLINE_HOOKS_DIR", "")
	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_CONFIG_PATH", "")
	t.Setenv("OPENCLAW_HOME", "")
	t.Setenv("OPENCLAW_PROFILE", "")
	if home == "" {
		t.Setenv("APPDATA", "")
		t.Setenv("LOCALAPPDATA", "")
		return
	}
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
}

func testHookCommandText(raw string) string {
	const flag = "-encodedcommand"
	lower := strings.ToLower(raw)
	var scripts []string
	for offset := 0; offset < len(raw); {
		i := strings.Index(lower[offset:], flag)
		if i < 0 {
			break
		}
		start := offset + i + len(flag)
		for start < len(raw) && (raw[start] == ' ' || raw[start] == '\t') {
			start++
		}
		end := start
		for end < len(raw) && isTestBase64Byte(raw[end]) {
			end++
		}
		if data, err := base64.StdEncoding.DecodeString(raw[start:end]); err == nil && len(data)%2 == 0 {
			units := make([]uint16, len(data)/2)
			for i := range units {
				units[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
			}
			script := string(utf16.Decode(units))
			scripts = append(scripts, strings.ReplaceAll(script, "' '", " "))
		}
		if end > start {
			offset = end
		} else if start < len(raw) {
			offset = start + 1
		} else {
			break
		}
	}
	if len(scripts) == 0 {
		return raw
	}
	return raw + "\n" + strings.Join(scripts, "\n")
}

func isTestBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' ||
		b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
}

func TestHookCommandTextDecodesPowerShell(t *testing.T) {
	const script = "'hook' 'codex-pre-tool' '--agent' 'codex' '--enforce'"
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		data[i*2], data[i*2+1] = byte(unit), byte(unit>>8)
	}
	raw := `command = "powershell.exe -EncodedCommand ` + base64.StdEncoding.EncodeToString(data) + `"`
	if got := testHookCommandText(raw); !strings.Contains(got, "hook codex-pre-tool") || !strings.Contains(got, "--agent codex") || !strings.Contains(got, "--enforce") {
		t.Fatalf("decoded command text = %q", got)
	}
}
