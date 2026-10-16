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
	// Use the native event discriminator, as the classifier does. Resource
	// service.name can be absent or describe a collector rather than the agent.
	formatAgent := ev.SourceAgent
	switch eventName(&a, rec) {
	case claudeToolResult, claudeToolDecision:
		formatAgent = model.AgentClaudeCode
	case codexToolResult, codexToolDecision:
		formatAgent = model.AgentCodex
	case geminiToolCall, qwenToolCall:
		formatAgent = model.AgentGeminiCLI
	}
	switch formatAgent {
	case model.AgentClaudeCode:
		inputKeys = append(inputKeys, attrClaudeToolInput)
	case model.AgentCodex:
		inputKeys = append(inputKeys, attrArguments)
		resultKeys = append(resultKeys, attrOutput)
	case model.AgentGeminiCLI, model.AgentQwenCode:
		inputKeys = append(inputKeys, attrFunctionArgs)
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
