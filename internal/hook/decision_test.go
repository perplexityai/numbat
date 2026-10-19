package hook

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestDecisionParentTargetsAndPositionalBoundaries(t *testing.T) {
	for _, tc := range []struct {
		agent, raw                   string
		payload                      map[string]any
		session, tree, child, parent string
	}{
		{AgentCodex, "SubagentStart", map[string]any{"session_id": "root", "agent_id": "child", "hook_event_name": "SubagentStart"}, "child", "root", "child", "root"},
		{AgentHermes, "subagent_start", map[string]any{"session_id": "root", "extra": map[string]any{"child_session_id": "child"}}, "child", "", "", "root"},
		{AgentCursor, "subagentStart", map[string]any{"conversation_id": "root"}, "root", "", "", ""},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			ev := model.Event{EventID: "e", SourceAgent: tc.agent, SessionID: tc.session, SessionTreeID: tc.tree, SubAgentID: tc.child}
			o, ok := DecisionObservation(tc.raw, LifecycleSessionStart, tc.agent, []model.Event{ev}, tc.payload, "raw")
			if !ok || o.NewSession || o.Phase != "gap" {
				t.Fatalf("child boundary anchored: %+v", o)
			}
			if tc.parent != "" && (o.Parent == nil || o.Parent.Session != tc.parent || o.Parent.SessionTree != "" || o.Parent.SubAgentID != "") {
				t.Fatalf("wrong parent target: %+v", o.Parent)
			}
		})
	}
}

func TestDecisionFreshnessDoesNotGuessFromGenericStart(t *testing.T) {
	for _, tc := range []struct {
		agent, raw string
		payload    map[string]any
		fresh      bool
	}{
		{AgentClaude, "SessionStart", map[string]any{"source": "startup"}, true},
		{AgentClaude, "SessionStart", map[string]any{"source": "resume"}, false},
		{AgentCline, "TaskStart", map[string]any{}, true},
		{AgentCline, "TaskResume", map[string]any{}, false},
		{AgentCline, "session-start", map[string]any{"taskStart": nil}, false},
		{AgentCline, "session-start", map[string]any{"taskStart": map[string]any{}, "taskResume": map[string]any{}}, false},
		{AgentOpenCode, "session-start", map[string]any{}, true},
		{AgentOpenClaw, "session-start", map[string]any{"resumed_from": map[string]any{}}, false},
		{AgentGemini, "SessionStart", map[string]any{}, false},
	} {
		t.Run(tc.agent+"/"+tc.raw, func(t *testing.T) {
			ev := model.Event{EventID: "e", SourceAgent: tc.agent, SessionID: "root"}
			o, ok := DecisionObservation(tc.raw, LifecycleSessionStart, tc.agent, []model.Event{ev}, tc.payload, "raw")
			if !ok || o.NewSession != tc.fresh {
				t.Fatalf("fresh=%v want=%v observation=%+v", o.NewSession, tc.fresh, o)
			}
		})
	}
}

func TestDecisionObservationProjectionAndCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name, lifecycle, hook string
		input                 any
		result                json.RawMessage
		redacted, want        bool
	}{
		{"empty input", "pre-tool", "PreToolUse", map[string]any{}, nil, false, true},
		{"missing input", "pre-tool", "PreToolUse", nil, nil, false, false},
		{"null input", "pre-tool", "PreToolUse", json.RawMessage("null"), nil, false, false},
		{"wrong event", "pre-tool", "PostToolUse", map[string]any{}, nil, false, false},
		{"background", "pre-tool", "PreToolUse", map[string]any{"run_in_background": true}, nil, false, true},
		{"null result", "post-tool", "PostToolUse", map[string]any{}, json.RawMessage("null"), false, true},
		{"empty result", "post-tool", "PostToolUse", map[string]any{}, json.RawMessage(`{}`), false, true},
		{"missing result", "post-tool", "PostToolUse", map[string]any{}, nil, false, false},
		{"redacted", "pre-tool", "PreToolUse", map[string]any{"token": "ghp_012345678901234567890123456789012345"}, nil, true, false},
		{"pretty JSON string", "pre-tool", "PreToolUse", map[string]any{"body": " { \"count\": 7 } "}, nil, true, true},
		{"unredactable string", "pre-tool", "PreToolUse", map[string]any{"command": `"$HOME/bin/tool" --flag`}, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"session_id": "s1", "tool_use_id": "c1", "tool_name": "mcp__fixture__call",
				"hook_event_name": tc.hook, "cwd": "/private-cwd",
				"transcript_path": "/private-transcript", "env": map[string]any{"PRIVATE": "not-for-model"},
			}
			if tc.input != nil {
				payload["tool_input"] = tc.input
			}
			if tc.result != nil {
				payload["tool_response"] = tc.result
			}
			// Exercise the same decoded value types as native JSON input.
			raw, _ := json.Marshal(payload)
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			lc := Lifecycle(tc.lifecycle)
			events := MapEvents(lc, AgentClaude, model.AgentClaudeCode, "e1", payload)
			content := "raw"
			if tc.redacted {
				content = "redacted"
			}
			o, supported := DecisionObservation("", lc, AgentClaude, events, payload, content)
			if !supported || o.Complete != tc.want {
				t.Fatalf("supported=%t observation=%+v", supported, o)
			}
			if tc.name == "background" && !o.HistoryGap {
				t.Fatal("background action must invalidate context without invalidating its own input")
			}
			encoded, _ := json.Marshal(o)
			for _, private := range []string{"private-cwd", "private-transcript", "not-for-model"} {
				if bytes.Contains(encoded, []byte(private)) {
					t.Fatalf("unapproved envelope field in projection: %s", encoded)
				}
			}
		})
	}
}

func TestDecisionObservationFailureAndSessionStart(t *testing.T) {
	payload := map[string]any{
		"session_id": "s1", "tool_use_id": "c1", "tool_name": "mcp__fixture__call",
		"hook_event_name": "PostToolUseFailure", "tool_input": map[string]any{},
		"error": "synthetic failure", "is_interrupt": true,
	}
	events := MapEvents(LifecyclePostTool, AgentClaude, model.AgentClaudeCode, "e1", payload)
	o, _ := DecisionObservation("", LifecyclePostTool, AgentClaude, events, payload, "raw")
	if o.Phase != "failed" || !o.Complete || !bytes.Contains(o.Result, []byte(`synthetic failure`)) {
		t.Fatalf("failure not retained: %+v", o)
	}
	for _, source := range []string{"startup", "resume", "compact", "fork"} {
		payload := map[string]any{"session_id": "s1", "hook_event_name": "SessionStart", "source": source}
		events := MapEvents(LifecycleSessionStart, AgentClaude, model.AgentClaudeCode, "e1", payload)
		o, _ := DecisionObservation("", LifecycleSessionStart, AgentClaude, events, payload, "raw")
		if o.NewSession != (source == "startup") {
			t.Fatalf("unverified new prefix for %s", source)
		}
	}
}

func TestDecisionObservationDistinguishesSessionAndSubagentEnd(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
	}{
		{"SessionEnd", "end"}, {"SubagentStop", "gap"}, {"", ""},
	} {
		payload := map[string]any{"session_id": "s1", "hook_event_name": tc.name}
		events := MapEvents(LifecycleSessionEnd, AgentClaude, model.AgentClaudeCode, "e1", payload)
		o, supported := DecisionObservation("", LifecycleSessionEnd, AgentClaude, events, payload, "raw")
		if supported != (tc.phase != "") || (supported && o.Phase != tc.phase) {
			t.Fatalf("%q: supported=%t phase=%q", tc.name, supported, o.Phase)
		}
	}
}

// Child identity is common to tool and lifecycle inputs, not a tool-name hint.
// https://code.claude.com/docs/en/hooks
func TestDecisionObservationChildScope(t *testing.T) {
	for _, tc := range []struct {
		name, phase string
		lifecycle   Lifecycle
	}{
		{"SessionStart", "start", LifecycleSessionStart},
		{"SubagentStart", "gap", LifecycleSessionStart},
		{"PreToolUse", "pre", LifecyclePreTool},
		{"PostToolUse", "result", LifecyclePostTool},
		{"PostToolUseFailure", "failed", LifecyclePostTool},
		{"PermissionDenied", "denied", LifecyclePermissionDenied},
		{"SubagentStop", "gap", LifecycleSessionEnd},
		{"SessionEnd", "end", LifecycleSessionEnd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{
				"session_id": "s1", "agent_id": "child-1", "agent_type": "Explore",
				"hook_event_name": tc.name, "source": "startup",
				"tool_use_id": "c1", "tool_name": "mcp__fixture__call",
				"tool_input": map[string]any{}, "tool_response": "result",
			}
			if tc.name == "PostToolUseFailure" {
				payload["error"] = "failure"
			}
			events := MapEvents(tc.lifecycle, AgentClaude, model.AgentClaudeCode, "e1", payload)
			o, supported := DecisionObservation("", tc.lifecycle, AgentClaude, events, payload, "raw")
			if !supported || o.Phase != tc.phase || o.Subject.SubAgentID != "child-1" ||
				o.Subject.Session != "s1" || o.NewSession {
				t.Fatalf("child projection: %+v supported=%t", o, supported)
			}
			for _, ev := range events {
				if ev.SubAgentID != "child-1" || ev.SessionID != "s1" {
					t.Fatalf("child event identity: %+v", ev)
				}
			}
		})
	}
}

func TestDecisionObservationInvalidChildIdentityIsGap(t *testing.T) {
	for _, id := range []any{nil, "", json.Number("7"), true, map[string]any{}} {
		payload := map[string]any{
			"session_id": "s1", "agent_id": id, "hook_event_name": "PreToolUse",
			"tool_use_id": "c1", "tool_name": "mcp__fixture__call", "tool_input": map[string]any{},
		}
		events := MapEvents(LifecyclePreTool, AgentClaude, model.AgentClaudeCode, "e1", payload)
		o, supported := DecisionObservation("", LifecyclePreTool, AgentClaude, events, payload, "raw")
		if !supported || o.Phase != "gap" || o.Complete || o.NewSession {
			t.Fatalf("ambiguous child identity %v: %+v supported=%t", id, o, supported)
		}
	}
}
