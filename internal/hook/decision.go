package hook

import (
	"encoding/json"
	"slices"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

// DecisionObservation deliberately supports one verified host contract first.
// It projects only tool identity, arguments and observed results; cwd,
// transcript paths, environment and unrelated envelope fields never egress.
// See https://code.claude.com/docs/en/hooks for the native field contract.
func DecisionObservation(lc Lifecycle, agent string, events []model.Event, payload map[string]any, content string) (decision.Observation, bool) {
	if agent != AgentClaude || len(events) == 0 {
		return decision.Observation{}, false
	}
	ev := events[len(events)-1]
	o := decision.Observation{Subject: decision.Subject{
		Agent: ev.SourceAgent, Session: ev.SessionID, SessionTree: ev.SessionTreeID,
		SubAgentID: ev.SubAgentID, CallID: ev.ToolCallID, EventID: ev.EventID,
	}, Complete: true}
	name, _ := payload["hook_event_name"].(string)
	_, agentIDPresent := payload["agent_id"]
	if ev.SubAgentID == "" && (agentIDPresent || name == "SubagentStart" || name == "SubagentStop") {
		// Missing or malformed child identity cannot establish main-agent
		// evidence or a fresh session anchor.
		o.Phase, o.Complete = "gap", false
		return o, true
	}
	switch lc {
	case LifecycleSessionStart:
		o.Phase = "start"
		o.NewSession = name == "SessionStart" && payload["source"] == "startup" && ev.SubAgentID == ""
	case LifecycleSessionEnd:
		if name == "SubagentStop" {
			// A child can resume after this response boundary.
			o.Phase, o.Complete = "gap", false
			return o, true
		}
		if name != "SessionEnd" {
			return o, false
		}
		o.Phase = "end"
	case LifecyclePreTool:
		if name != "PreToolUse" {
			o.Phase, o.Complete = "gap", false
			return o, true
		}
		o.Phase = "pre"
	case LifecyclePostTool:
		switch name {
		case "PostToolUse":
			o.Phase = "result"
		case "PostToolUseFailure":
			o.Phase = "failed"
		default:
			o.Phase, o.Complete = "gap", false
			return o, true
		}
	case LifecyclePermissionDenied:
		o.Phase = "denied"
	default:
		return o, false
	}
	if o.Phase == "start" || o.Phase == "end" {
		return o, true
	}
	input, present := payload["tool_input"]
	inputObject, object := input.(map[string]any)
	o.Complete = present && object && inputObject != nil && ev.ToolName != "" &&
		ev.ToolCallID != "" && !ev.ToolInputTruncatedForAnalysis()
	// A background launch result does not delimit the operation's effects.
	if inputObject["run_in_background"] == true {
		o.Complete = false
	}
	action := map[string]any{"tool": ev.ToolName, "arguments_present": present}
	if present {
		action["arguments"] = input
	}
	o.Action, _ = json.Marshal(action)
	switch o.Phase {
	case "result":
		if result, ok := payload["tool_response"]; ok {
			o.Result, _ = json.Marshal(result)
		}
		o.Complete = o.Complete && len(o.Result) != 0 && !ev.ToolResultTruncatedForAnalysis()
		if slices.Contains(ev.Tags, model.TagToolError) {
			o.Phase = "failed"
		}
	case "failed":
		if value, ok := payload["error"]; ok {
			failure := map[string]any{"error": value}
			if interrupt, ok := payload["is_interrupt"]; ok {
				failure["is_interrupt"] = interrupt
			}
			o.Result, _ = json.Marshal(failure)
		}
		o.Complete = o.Complete && len(o.Result) != 0
	}
	if content == "redacted" {
		for _, field := range []*json.RawMessage{&o.Action, &o.Result} {
			if len(*field) == 0 {
				continue
			}
			clean, masked, err := redact.JSONWithRedaction(*field)
			if err != nil {
				*field = nil
				o.Complete = false
				continue
			}
			if masked {
				o.Complete = false
			}
			*field = clean
		}
	}
	return o, true
}
