package decision

import (
	"encoding/json"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

// ProjectBatch retains the whole native action. Matching an earlier normalized
// event must not cause a different, last-event-only action to be classified.
func ProjectBatch(events []model.Event, phase, content string) Observation {
	if len(events) == 0 {
		return Observation{}
	}
	o := Project(events[len(events)-1], phase, content)
	if len(events) < 2 || phase == "start" || phase == "end" || phase == "gap" {
		return o
	}
	actions := make([]json.RawMessage, 0, len(events))
	seen := make(map[string]bool)
	for _, ev := range events {
		part := Project(ev, phase, content)
		o.Complete = o.Complete && part.Complete && part.Subject.CallID == o.Subject.CallID &&
			part.Subject.Session == o.Subject.Session && part.Subject.SubAgentID == o.Subject.SubAgentID
		if !seen[string(part.Action)] {
			actions = append(actions, part.Action)
			seen[string(part.Action)] = true
		}
	}
	if len(actions) > 1 {
		o.Action, _ = json.Marshal(struct {
			Actions []json.RawMessage `json:"actions"`
		}{actions})
	}
	o.EventType = ""
	return o
}

// Project uses the same retained originals as deterministic rules, not an
// output preview. It deliberately excludes the unrelated event envelope.
func Project(ev model.Event, phase, content string) Observation {
	o := Observation{Subject: Subject{
		Agent: ev.SourceAgent, Session: ev.SessionID, SessionTree: ev.SessionTreeID,
		SubAgentID: ev.SubAgentID, CallID: ev.ToolCallID, EventID: ev.EventID,
	}, Phase: phase, Complete: true, EventType: string(ev.EventType), ExitCode: ev.ExitCode}
	if phase == "start" || phase == "end" || phase == "gap" {
		return o
	}
	input := ev.ToolInputForAnalysis()
	action := map[string]any{"tool": ev.ToolName, "arguments_present": input != ""}
	if input != "" && ValidJSON([]byte(input)) {
		action["arguments"] = json.RawMessage(input)
		o.Complete = strings.TrimSpace(input) != "null" && !ev.ToolInputTruncatedForAnalysis()
	} else {
		// Some adapters expose a typed command/path rather than argument JSON.
		// Preserve those observed fields without inventing a tool payload.
		for name, value := range map[string]string{
			"command": ev.Command, "file_path": ev.FilePath, "url": ev.URL,
			"mcp_server": ev.MCPServer, "mcp_tool": ev.MCPTool,
		} {
			if value != "" {
				action[name] = value
			}
		}
		o.Complete = input == "" && (ev.Command != "" || ev.FilePath != "" || ev.URL != "") &&
			!ev.ToolInputTruncatedForAnalysis()
	}
	o.Action, _ = json.Marshal(action)
	if phase == "result" || phase == "failed" {
		result := ev.ToolResultForAnalysis()
		if ValidJSON([]byte(result)) {
			o.Result = json.RawMessage(result)
		}
		o.Complete = o.Complete && o.Result != nil && !ev.ToolResultTruncatedForAnalysis()
	}
	if content == "redacted" {
		for _, field := range []*json.RawMessage{&o.Action, &o.Result} {
			if len(*field) == 0 {
				continue
			}
			clean, masked, err := redact.JSONWithRedaction(*field)
			if err != nil {
				*field, o.Complete = nil, false
			} else {
				*field = clean
				o.Complete = o.Complete && !masked
			}
		}
	}
	return o
}

func (o Observation) Current() json.RawMessage {
	current, _ := json.Marshal(struct {
		Phase     string          `json:"phase"`
		EventType string          `json:"event_type,omitempty"`
		ExitCode  *int            `json:"exit_code,omitempty"`
		Action    json.RawMessage `json:"action"`
		Result    json.RawMessage `json:"result,omitempty"`
	}{o.Phase, o.EventType, o.ExitCode, o.Action, o.Result})
	return current
}
