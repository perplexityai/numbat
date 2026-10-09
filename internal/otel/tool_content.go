package otel

import (
	"encoding/json"

	"github.com/perplexityai/numbat/internal/model"
)

const attrGenAIToolCallResult = "gen_ai.tool.call.result"

func retainToolContent(ev *model.Event, rec logRecord) {
	switch ev.EventType {
	case model.EventToolCall, model.EventToolResult, model.EventCommandExec, model.EventCommandResult,
		model.EventFileRead, model.EventFileWrite, model.EventFileDelete, model.EventNetworkIndicator:
	default:
		return
	}
	a := newAttrs(nil, rec.attributes)
	inputKeys := []string{attrGenAIToolCallArgs, attrToolCallArgs}
	resultKeys := []string{attrGenAIToolCallResult}
	switch ev.SourceAgent {
	case model.AgentClaudeCode:
		inputKeys = append(inputKeys, attrClaudeToolInput)
	case model.AgentCodex:
		resultKeys = append(resultKeys, attrOutput)
	}
	retainAttribute := func(keys []string, set func(any)) {
		for _, key := range keys {
			if value, ok := a.m[key]; ok {
				native := value.nativeValue()
				if native == nil {
					native = json.RawMessage("null")
				}
				set(native)
				return
			}
		}
	}
	retainAttribute(inputKeys, ev.SetToolInput)
	retainAttribute(resultKeys, ev.SetToolResult)
}
