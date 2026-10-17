package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMuseManagedInstallLifecycle(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		t.Run(map[bool]string{false: "monitor", true: "enforce"}[enforce], func(t *testing.T) {
			// Even this basename names a hook file when --managed is explicit.
			path := filepath.Join(t.TempDir(), "managed", "settings.json")
			seed := `{"metadata":{"owner":"example"},"hooks":{"state":{"foreign":false},"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"echo foreign","statusMessage":"Keep this","onFailure":{"type":"command","command":"echo failed"}}]}]}}`
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
				t.Fatal(err)
			}
			opts := InstallOptions{
				Enforce:     enforce,
				RuntimeArgs: []string{"--emit", "all", "--output-file", "$HOME/.numbat/records.ndjson"},
			}
			var first string
			for i := range 2 {
				rep, err := InstallManagedWithOptions(AgentMuse, path, numbatBinary, opts)
				if err != nil || !rep.Supported || !rep.Installed || !rep.Changed {
					t.Fatalf("install: %+v, %v", rep, err)
				}
				if !strings.Contains(rep.Message, "configure managed_hooks_path separately") {
					t.Fatalf("install must distinguish file creation from activation: %+v", rep)
				}
				body := readTestFile(t, path)
				if i == 0 {
					first = body
				} else if body != first {
					t.Fatal("reinstall changed hook content")
				}
				sf, err := readHookSettings(path, true)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := sf.values["schema_version"]; ok {
					t.Fatal("managed hook file acquired a user-settings schema_version")
				}
				for _, ev := range museHookEvents {
					count := 0
					for _, group := range sf.hooks[ev.settingsKey] {
						for _, ref := range group.Hooks {
							if !isNumbatHookRef(ref) {
								continue
							}
							count++
							command := hookCommandText(ref.Command)
							if ref.Type != "command" || ref.Args != nil || ref.Timeout != ev.timeout ||
								!strings.Contains(command, "$HOME/.numbat/records.ndjson") {
								t.Fatalf("incorrect %s hook: %+v", ev.settingsKey, ref)
							}
							if strings.Contains(command, "--enforce") != (enforce && ev.settingsKey == "PreToolUse") {
								t.Fatalf("incorrect %s enforcement: %s", ev.settingsKey, command)
							}
						}
					}
					if count != 1 {
						t.Fatalf("%s has %d numbat hooks, want one", ev.settingsKey, count)
					}
				}
				status, err := StatusManagedErr(AgentMuse, path)
				if err != nil || !status.Installed {
					t.Fatalf("status: %+v, %v", status, err)
				}
			}
			removed, err := UninstallManaged(AgentMuse, path)
			if err != nil || !removed.Changed {
				t.Fatalf("uninstall: %+v, %v", removed, err)
			}
			status, err := StatusManagedErr(AgentMuse, path)
			if err != nil || status.Installed {
				t.Fatalf("uninstalled status: %+v, %v", status, err)
			}
			var want, got any
			if err := json.Unmarshal([]byte(seed), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(readTestFile(t, path)), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("foreign configuration changed: %#v, want %#v", got, want)
			}
			if backup := readTestFile(t, path+backupSuffix); backup != seed {
				t.Fatalf("pristine backup changed: %s", backup)
			}
			if rep, err := UninstallManaged(AgentMuse, path); err != nil || rep.Changed {
				t.Fatalf("second uninstall: %+v, %v", rep, err)
			}
			info, err := os.Stat(path)
			if err != nil || !modeMatches(info.Mode().Perm(), 0o644) {
				t.Fatalf("managed file must remain user-readable after uninstall: %v, %v", info, err)
			}
		})
	}
}

func TestMuseManagedFreshFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed", "hooks.json")
	if _, err := InstallManagedWithOptions(AgentMuse, path, numbatBinary, InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{path: 0o644, filepath.Dir(path): 0o755} {
		info, err := os.Stat(name)
		if err != nil || !modeMatches(info.Mode().Perm(), mode) {
			t.Fatalf("%s: info=%v, err=%v, want mode %o", name, info, err, mode)
		}
	}
}

func TestMuseManagedRefusesIncompatibleFiles(t *testing.T) {
	seeds := map[string]string{
		"malformed":      `{`,
		"null":           `null`,
		"typed timeout":  `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign","timeout":"10"}]}]}}`,
		"strict name":    `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign","name":"foreign"}]}]}}`,
		"strict timeout": `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign","timeout_ms":1000}]}]}}`,
		"strict null":    `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo foreign","name":null}]}]}}`,
		"env grant":      `{"managed_hooks_env_vars":[],"hooks":{}}`,
	}
	for name, fallback := range map[string]string{
		"nested name":         `{"type":"command","command":"echo failed","name":"fallback"}`,
		"nested timeout":      `{"type":"command","command":"echo failed","timeout_ms":1000}`,
		"nested both":         `{"type":"command","command":"echo failed","name":"fallback","timeout_ms":1000}`,
		"nested null":         `{"type":"command","command":"echo failed","name":null}`,
		"nested timeout null": `{"type":"command","command":"echo failed","timeout_ms":null}`,
		"nested twice":        `{"type":"command","command":"echo failed","onFailure":{"type":"command","command":"echo failed again","name":"fallback"}}`,
		"malformed fallback":  `[]`,
	} {
		seeds[name] = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo foreign","onFailure":` + fallback + `}]}]}}`
	}
	for name, seed := range seeds {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := InstallManagedWithOptions(AgentMuse, path, numbatBinary, InstallOptions{}); err == nil {
				t.Fatal("incompatible install accepted")
			}
			if rep, err := StatusManagedErr(AgentMuse, path); err == nil || rep.Installed {
				t.Fatalf("incompatible status: %+v, %v", rep, err)
			}
			if _, err := UninstallManaged(AgentMuse, path); err == nil {
				t.Fatal("incompatible uninstall accepted")
			}
			if got := readTestFile(t, path); got != seed {
				t.Fatal("incompatible file modified")
			}
			if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
				t.Fatalf("incompatible file backed up: %v", err)
			}
		})
	}
}

func TestMuseManagedHasNoDefaultPath(t *testing.T) {
	if !AgentSupportsManagedHooks(AgentMuse) {
		t.Fatal("explicit managed files should be supported")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if path, ok := managedHooksPath(AgentMuse, goos, "", ""); ok || path != "" {
			t.Fatalf("%s invented a managed path: %q", goos, path)
		}
	}
	path := filepath.Join(t.TempDir(), "absent.json")
	if rep, err := StatusManagedErr(AgentMuse, path); err != nil || rep.Installed {
		t.Fatalf("missing status: %+v, %v", rep, err)
	}
	if rep, err := UninstallManaged(AgentMuse, path); err != nil || rep.Changed {
		t.Fatalf("missing uninstall: %+v, %v", rep, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("read/no-op created a file: %v", err)
	}
}
