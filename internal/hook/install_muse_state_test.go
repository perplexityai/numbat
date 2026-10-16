package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMusePreservesHookState(t *testing.T) {
	for _, basename := range []string{"settings.json", "hooks.json"} {
		t.Run(basename, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), basename)
			original := []byte(`{"schema_version":1,"provider":"echo","hooks":{"state":{"enabled":false,"counter":9007199254740993},"PreToolUse":[{"matcher":"foreign","hooks":[{"type":"command","command":"echo foreign"}]}]}}`)
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err != nil {
					t.Fatal(err)
				}
				if !Status(AgentMuse, path).Installed {
					t.Fatal("complete install not recognized")
				}
			}
			if _, err := Uninstall(AgentMuse, path); err != nil {
				t.Fatal(err)
			}
			if Status(AgentMuse, path).Installed {
				t.Fatal("uninstalled hooks still present")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			decode := func(data []byte) any {
				t.Helper()
				var value any
				decoder := json.NewDecoder(bytes.NewReader(data))
				decoder.UseNumber()
				if err := decoder.Decode(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			if !reflect.DeepEqual(decode(original), decode(got)) {
				t.Fatalf("foreign configuration changed: %s", got)
			}
		})
	}
}

func TestMuseNullSettingsRejectedWithoutWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentMuse, path, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("null configuration accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "null" {
		t.Fatalf("invalid configuration modified: %q, %v", got, err)
	}
}
