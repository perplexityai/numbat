package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestKiroSessionEnd(t *testing.T) {
	// Sanitized native payloads from CLI 2.13.0 (Stop) and 2.27.1 (SessionEnd).
	// Native SessionEnd was introduced in https://kiro.dev/changelog/cli/2-25/.
	for _, tc := range []struct {
		name, agent, event, payload string
		want                        model.EventType
	}{
		{"native", AgentKiro, "SessionEnd", `{"session_id":"s1","hook_event_name":"SessionEnd","cwd":"/workspace/project","reason":"client_disconnect"}`, model.EventSessionEnd},
		{"installed alias", AgentKiro, "session-end", `{"session_id":"s1","hook_event_name":"SessionEnd","cwd":"/workspace/project","reason":"client_disconnect"}`, model.EventSessionEnd},
		{"older alias", AgentKiro, "session-end", `{"session_id":"s1","hook_event_name":"Stop","cwd":"/workspace/project"}`, ""},
		{"normal stop", AgentKiro, "stop", `{"session_id":"s1","hook_event_name":"Stop","cwd":"/workspace/project"}`, model.EventMessageAssistant},
		{"other agent", AgentJunie, "session-end", `{"session_id":"s1","hook_event_name":"Stop","cwd":"/workspace/project"}`, model.EventSessionEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal([]byte(tc.payload), &payload); err != nil {
				t.Fatal(err)
			}
			lc, err := ResolveLifecycle(tc.agent, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			source, err := ParseAgent(tc.agent)
			if err != nil {
				t.Fatal(err)
			}
			events := MapEvents(lc, tc.agent, source, "event-1", payload)
			if tc.want == "" {
				if len(events) != 0 {
					t.Fatalf("aliased Stop produced events: %+v", events)
				}
				return
			}
			if len(events) != 1 || events[0].EventType != tc.want ||
				events[0].SessionID != "s1" || events[0].ProjectPath != "/workspace/project" {
				t.Fatalf("events = %+v, want %s with native context", events, tc.want)
			}
		})
	}
}

func TestKiroOwnershipRequiresCompletePrefix(t *testing.T) {
	full := kiroHookDocument("/opt/numbat", nil, false)
	for mask := 0; mask < 1<<len(full.Hooks); mask++ {
		doc := kiroHookFileDocument{Version: "v1"}
		for i, entry := range full.Hooks {
			if mask&(1<<i) != 0 {
				doc.Hooks = append(doc.Hooks, entry)
			}
		}
		want := mask != 0 && mask&(mask+1) == 0
		for range 2 {
			if got := isNumbatKiroHookDocument(doc); got != want {
				t.Fatalf("subset %b ownership = %t, want %t", mask, got, want)
			}
			slices.Reverse(doc.Hooks)
		}
	}
	full.Hooks = append(full.Hooks, full.Hooks[0])
	if isNumbatKiroHookDocument(full) {
		t.Fatal("duplicate trigger accepted")
	}
	full.Hooks[len(full.Hooks)-1].Trigger = "Unknown"
	if isNumbatKiroHookDocument(full) {
		t.Fatal("unknown trigger accepted")
	}
}

func TestKiroPreviousInstallUpgradeAndUninstall(t *testing.T) {
	for _, operation := range []string{"upgrade", "uninstall", "non-prefix"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "numbat.json")
			doc := kiroHookDocument("/opt/numbat", nil, false)
			doc.Hooks = doc.Hooks[:5] // The release before SessionEnd installed five hooks.
			if operation == "non-prefix" {
				doc.Hooks = doc.Hooks[2:3]
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if Status(AgentKiro, path).Installed {
				t.Fatal("old file reported complete")
			}
			if operation == "non-prefix" {
				if _, err := InstallWithOptions(AgentKiro, path, "/opt/numbat", InstallOptions{}); err == nil {
					t.Fatal("install accepted a non-prefix file")
				}
				if rep, err := Uninstall(AgentKiro, path); err != nil || rep.Changed {
					t.Fatalf("non-prefix uninstall = %+v, %v", rep, err)
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != string(data) {
					t.Fatalf("non-prefix file changed: %v", err)
				}
				return
			}
			if operation == "upgrade" {
				if _, err := InstallWithOptions(AgentKiro, path, "/opt/numbat", InstallOptions{}); err != nil {
					t.Fatal(err)
				}
				if !Status(AgentKiro, path).Installed {
					t.Fatal("upgraded file reported incomplete")
				}
				doc, err = readKiroHookFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.ContainsFunc(doc.Hooks, func(h kiroHook) bool { return h.Trigger == "SessionEnd" }) {
					t.Fatal("upgrade omitted SessionEnd")
				}
			}
			if rep, err := Uninstall(AgentKiro, path); err != nil || !rep.Changed {
				t.Fatalf("uninstall = %+v, %v", rep, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("hook file remains: %v", err)
			}
		})
	}
}
