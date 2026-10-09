package hook

import (
	"encoding/json"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestJunieNativeContext(t *testing.T) {
	// Sanitized CLI 3646.2 payloads; 2144.6, 2777.8 and 2929.5 omit context
	// on PreToolUse, Stop and SessionEnd. https://junie.jetbrains.com/docs/junie-cli-hooks.html
	for _, tc := range []struct {
		event, payload string
		want           model.EventType
	}{
		{"SessionStart", `{"hook_event_name":"SessionStart","session_id":"s1","cwd":"/home/user/.junie","project_path":"/workspace/project","source":"startup"}`, model.EventSessionStart},
		{"UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","session_id":"s1","cwd":"/home/user/.junie","project_path":"/workspace/project","prompt":"Check the project."}`, model.EventPromptUser},
		{"PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/home/user/.junie","project_path":"/workspace/project","tool_name":"Bash","tool_input":{"run_in_background":false,"command":"git status"}}`, model.EventCommandExec},
		{"Stop", `{"hook_event_name":"Stop","session_id":"s1","cwd":"/home/user/.junie","project_path":"/workspace/project","stop_hook_active":false,"last_assistant_message":"Done."}`, model.EventMessageAssistant},
		{"SessionEnd", `{"hook_event_name":"SessionEnd","session_id":"s1","cwd":"/home/user/.junie","project_path":"/workspace/project","reason":"other"}`, model.EventSessionEnd},
	} {
		t.Run(tc.event, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal([]byte(tc.payload), &payload); err != nil {
				t.Fatal(err)
			}
			lc, err := ResolveLifecycle(AgentJunie, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			events := MapEvents(lc, AgentJunie, model.AgentJunie, "event-1", payload)
			if len(events) != 1 || events[0].EventType != tc.want ||
				events[0].ProjectPath != "/workspace/project" || events[0].SessionID != "s1" {
				t.Fatalf("events = %+v, want %s with project/session context", events, tc.want)
			}
			if tc.event == "PreToolUse" || tc.event == "Stop" || tc.event == "SessionEnd" {
				delete(payload, "session_id")
				delete(payload, "cwd")
				delete(payload, "project_path")
				events = MapEvents(lc, AgentJunie, model.AgentJunie, "event-2", payload)
				if len(events) != 1 || events[0].EventType != tc.want ||
					events[0].SessionID != "" || events[0].ProjectPath != "" {
					t.Fatalf("older payload gained context: %+v", events)
				}
			}
		})
	}
}

func TestJunieProjectFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"project only", map[string]any{"project_path": "/project"}, "/project"},
		{"missing", map[string]any{"cwd": "/fallback"}, "/fallback"},
		{"empty", map[string]any{"project_path": "", "cwd": "/fallback"}, "/fallback"},
		{"null", map[string]any{"project_path": nil, "cwd": "/fallback"}, "/fallback"},
		{"object", map[string]any{"project_path": map[string]any{}, "cwd": "/fallback"}, "/fallback"},
		{"legacy key", map[string]any{"working_directory": "/fallback"}, "/fallback"},
		{"no context", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newResolver(AgentJunie, tc.payload).cwd(); got != tc.want {
				t.Fatalf("cwd() = %q, want %q", got, tc.want)
			}
		})
	}
	payload := map[string]any{"cwd": "/working", "project_path": "/project"}
	if got := newResolver(AgentClaude, payload).cwd(); got != "/working" {
		t.Fatalf("changed non-Junie cwd to %q", got)
	}
}
