package extract

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// retainToolContent preserves the source result at the mapper's evidence
// pointer, including fields the typed status/preview decoder does not use.
// It never follows filesystem or network references carried in a result.
func retainToolContent(events []model.Event, raw json.RawMessage) {
	var root any
	decoded := false
	for i := range events {
		ev := &events[i]
		isResult := ev.EventType == model.EventToolResult || ev.EventType == model.EventCommandResult
		keys := missingToolInputKeys(*ev)
		if (isResult && ev.ToolResultForAnalysis() != "") || (!isResult && len(keys) == 0) {
			continue
		}
		if !decoded {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if decoder.Decode(&root) != nil {
				return
			}
			decoded = true
		}
		if value, ok := sourceJSONValue(root, ev.Evidence.JSONPointer); ok {
			if !isResult {
				object, ok := value.(map[string]any)
				if !ok {
					continue
				}
				for _, key := range keys {
					if input, present := object[key]; present {
						if input == nil {
							input = json.RawMessage("null")
						}
						ev.SetToolInput(input)
						break
					}
				}
				continue
			}
			if value == nil {
				value = json.RawMessage("null")
			}
			ev.SetToolResult(value)
		}
	}
}

// Typed argument maps distinguish empty objects from absence, but JSON null
// also decodes to a nil map. Recover that presence from the source call block.
func missingToolInputKeys(ev model.Event) []string {
	if ev.ToolName == "" || ev.ToolInputForAnalysis() != "" {
		return nil
	}
	switch ev.SourceAgent {
	case model.AgentClaudeCode:
		return []string{"input"}
	case model.AgentPi:
		return []string{"arguments"}
	case model.AgentCursor, model.AgentWindsurf:
		return []string{"input", "args", "parameters"}
	default:
		return nil
	}
}

// Decode a record once; many results in one record must not repeatedly parse
// the same source array. UseNumber above preserves integers wider than float64.
func sourceJSONValue(root any, pointer string) (any, bool) {
	if pointer == "" {
		return root, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch value := root.(type) {
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(value) {
				return nil, false
			}
			root = value[index]
		case map[string]any:
			var ok bool
			root, ok = value[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return root, true
}

func retainCodexToolContent(events []model.Event, kind string, raw, native json.RawMessage) {
	var field string
	var result bool
	switch kind {
	case codexRIFunctionCall, codexRIToolSearchCall:
		field = "arguments"
	case codexRICustomToolCall:
		field = "input"
	case codexRILocalShellCall, codexRIWebSearchCall:
		field = "action"
	case codexRIFunctionCallOutput, codexRICustomToolCallOut:
		field, result = "output", true
	case codexRIToolSearchOutput:
		field, result = "tools", true
	case codexRIImageGenerationCall:
		field, result = "result", true
	default:
		return
	}
	var source map[string]json.RawMessage
	if json.Unmarshal(raw, &source) != nil {
		return
	}
	var captured model.Event
	if result {
		if kind == codexRIImageGenerationCall && len(source[field]) > 0 {
			// This item contains the result and revised prompt together; retain
			// their source envelope without treating the revised prompt as input.
			captured.SetToolResult(raw)
		} else {
			captured.SetToolResult(source[field])
		}
		if len(native) > 0 {
			mergeMCPResult(&captured, native)
		}
	} else {
		captured.SetToolInput(source[field])
	}
	for i := range events {
		events[i].CopyToolContentFrom(captured)
	}
}

// Codex records the model-facing output and native MCP result separately.
// Retaining both under their source field names avoids choosing the lossy view.
func mergeMCPResult(ev *model.Event, native json.RawMessage) {
	output := ev.ToolResultForAnalysis()
	if !json.Valid([]byte(output)) {
		return
	}
	ev.SetToolResult(map[string]json.RawMessage{"output": json.RawMessage(output), "result": native})
}

func attachMCPResult(res *Result, id string, native json.RawMessage) bool {
	if id == "" || len(native) == 0 {
		return false
	}
	for i := len(res.Events) - 1; i >= 0; i-- {
		ev := &res.Events[i]
		if ev.ToolCallID != id {
			continue
		}
		if ev.EventType != model.EventToolResult {
			return false
		}
		mergeMCPResult(ev, native)
		return true
	}
	return false
}
