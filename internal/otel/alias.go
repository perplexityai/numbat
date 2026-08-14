package otel

// Exact event-name aliases for documented Claude Code, Codex, Gemini CLI, Qwen
// Code, and OpenCode OTLP logs. Unknown private events fall through to the standard
// semantic-convention classifier and are skipped when no mapping exists.

import (
	"encoding/json"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// Private event.name values emitted through OTLP logs.
const (
	claudeUserPrompt            = "claude_code.user_prompt"
	claudeAssistantResponse     = "claude_code.assistant_response"
	claudeToolResult            = "claude_code.tool_result"
	claudeToolDecision          = "claude_code.tool_decision"
	claudePermissionModeChanged = "claude_code.permission_mode_changed"

	codexConversationStarts = "codex.conversation_starts"
	codexUserPrompt         = "codex.user_prompt"
	codexToolDecision       = "codex.tool_decision"
	codexToolResult         = "codex.tool_result"
)

// Qwen Code's current native telemetry is a separate forked namespace, even
// though its payload fields remain close to Gemini CLI's.
const (
	qwenConfig               = "qwen-code.config"
	qwenUserPrompt           = "qwen-code.user_prompt"
	qwenToolCall             = "qwen-code.tool_call"
	qwenFileOperation        = "qwen-code.file_operation"
	qwenAPIResponse          = "qwen-code.api_response"
	qwenConversationFinished = "qwen-code.conversation_finished"
	qwenSubagentExecution    = "qwen-code.subagent_execution"
)

// Gemini CLI (google-gemini/gemini-cli) event.name values.
const (
	geminiConfig               = "gemini_cli.config"
	geminiUserPrompt           = "gemini_cli.user_prompt"
	geminiToolCall             = "gemini_cli.tool_call"
	geminiFileOperation        = "gemini_cli.file_operation"
	geminiAPIResponse          = "gemini_cli.api_response"
	geminiConversationFinished = "gemini_cli.conversation_finished"
	geminiAgentStart           = "gemini_cli.agent.start"
	geminiAgentFinish          = "gemini_cli.agent.finish"
	geminiApprovalModeSwitch   = "gemini_cli.plan.approval_mode_switch"
	// Older Gemini CLI builds used the class-local name in event.name.
	geminiApprovalModeSwitchLegacy = "approval_mode_switch"
)

// OpenCode (DEVtheOPS/opencode-plugin-otel) event.name values. Unlike Codex and
// Gemini these are BARE — not namespaced — so they are matched by exact name and
// only when no namespaced alias claimed the record first. Only the five
// security-relevant events are aliased; api_request/api_error/subtask_invoked/
// commit/session.error are left to skip, exactly as the base classifier does.
const (
	opencodeUserPrompt     = "user_prompt"
	opencodeToolResult     = "tool_result"
	opencodeToolDecision   = "tool_decision"
	opencodeSessionCreated = "session.created"
	opencodeSessionDeleted = "session.deleted"
)

// Codex/Gemini private attribute keys carried on the records above.
const (
	attrProviderName = "provider_name"

	attrPrompt = "prompt"

	// attrModel is OpenCode's bare "model" attribute on user_prompt
	// ("providerID/modelID"); it is NOT the gen_ai.request.model semconv key.
	attrModel = "model"

	// Codex and Gemini both name the invoked tool, its decision, and its success
	// flag, but under different keys per record; tool_name/decision/success are
	// shared, function_name/call_id/error_type/mcp_server* are agent-specific.
	attrAliasToolName = "tool_name"
	attrCallID        = "call_id"
	attrDecision      = "decision"
	attrSuccess       = "success"
	attrApprovalMode  = "approval_mode"
	attrActiveMode    = "active_approval_mode"

	attrMCPServer       = "mcp_server"
	attrMCPServerOrigin = "mcp_server_origin"
	attrMCPServerName   = "mcp_server_name"

	attrFunctionName = "function_name"
	attrFunctionArgs = "function_args"
	attrErrorType    = "error_type"
	attrError        = "error"
	attrResponseText = "response_text"
	attrAgentName    = "agent_name"
	attrAgentID      = "agent_id"
	attrSubagentName = "subagent_name"
	attrStatus       = "status"
	attrToolCallID   = "tool.call_id"

	// attrOutput is the Codex tool_result output snippet.
	attrOutput    = "output"
	attrArguments = "arguments"

	attrClaudeResponse       = "response"
	attrClaudeToolUseID      = "tool_use_id"
	attrClaudeToolParameters = "tool_parameters"
	attrClaudeToolInput      = "tool_input"
	attrClaudeToMode         = "to_mode"

	// argCommand / argFilePath are the keys inside Gemini's function_args JSON
	// object (matching internal/extract/gemini's run_shell_command / file tools).
	argCommand  = "command"
	argFilePath = "file_path"
)

// classifyAgentAlias maps a Claude, Codex, Gemini, or OpenCode private record onto
// numbat's vocabulary by exact event.name. It returns true when it recognized
// and classified the record. A false return means "not one of these aliases" —
// the caller then falls through to the standard semconv classifier, so a
// standards-compliant record is unaffected.
//
// The Codex (codex.*) and Gemini (gemini_cli.*) names are namespaced, so an
// exact match alone scopes them to their emitter. OpenCode's five names are
// BARE (user_prompt/tool_result/…) and would otherwise match a same-named
// record from any other exporter — a false positive numbat's high-precision
// rule forbids — so they are additionally gated on ev.SourceAgent, which
// mapRecord has already resolved from the resource's service.name.
func classifyAgentAlias(ev *model.Event, a *attrs, rec logRecord, name string) bool {
	if ev.SourceAgent == model.AgentClaudeCode {
		switch name {
		case "user_prompt":
			name = claudeUserPrompt
		case "assistant_response":
			name = claudeAssistantResponse
		case "tool_result":
			name = claudeToolResult
		case "tool_decision":
			name = claudeToolDecision
		case "permission_mode_changed":
			name = claudePermissionModeChanged
		}
	}
	switch name {
	case claudeUserPrompt:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		ev.SetContent(a.str(attrPrompt), true)
		return true

	case claudeAssistantResponse:
		ev.EventType = model.EventMessageAssistant
		ev.Model = a.str(attrModel)
		ev.SetContent(a.str(attrClaudeResponse), true)
		return true

	case claudeToolResult:
		classifyClaudeToolResult(ev, a, rec)
		return true

	case claudeToolDecision:
		classifyClaudeToolDecision(ev, a)
		return true

	case claudePermissionModeChanged:
		classifyClaudePermissionMode(ev, a)
		return true

	case codexConversationStarts:
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.ModelProvider = a.str(attrProviderName, attrGenAIProvider, attrGenAISystem)
		ev.GitBranch = a.str(attrGitBranch)
		ev.CLIVersion = a.str(attrAppVersion, attrServiceVersion)
		return true

	case codexUserPrompt, geminiUserPrompt, qwenUserPrompt:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		// prompt is "[REDACTED]" unless the agent was configured to log it.
		// Numbat still applies its output redaction to mapped message content.
		ev.SetContent(firstNonEmpty(a.str(attrPrompt, attrGenAIPrompt), bodyText(rec)), true)
		return true

	case codexToolDecision:
		classifyCodexDecision(ev, a)
		return true

	case codexToolResult:
		classifyCodexToolResult(ev, a, rec)
		return true

	case geminiConfig, qwenConfig:
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.Model = a.str(attrModel, attrGenAIReqModel, attrGenAIRespModel)
		ev.ModelProvider = a.str(attrGenAIProvider, attrGenAISystem)
		ev.CLIVersion = a.str(attrAppVersion, attrServiceVersion)
		if mode := a.str(attrApprovalMode, attrActiveMode); mode != "" {
			ev.ContentPreview = preview(mode)
			if geminiModeElevated(mode) {
				ev.Tags = append(ev.Tags, model.TagPermissionModeElevated)
			}
		}
		return true

	case geminiToolCall, qwenToolCall:
		classifyGeminiToolCall(ev, a, rec)
		return true

	case geminiAPIResponse, qwenAPIResponse:
		ev.EventType = model.EventMessageAssistant
		ev.Model = a.str(attrModel, attrGenAIRespModel, attrGenAIReqModel)
		ev.ModelProvider = a.str(attrGenAIProvider, attrGenAISystem)
		ev.SetContent(a.str(attrResponseText), true)
		return true

	case geminiConversationFinished, qwenConversationFinished:
		ev.EventType = model.EventSessionEnd
		ev.Actor = model.ActorSystem
		return true

	case qwenSubagentExecution:
		ev.Actor = model.ActorSystem
		ev.SubAgent = a.str(attrSubagentName, attrGenAIAgentName, attrGenAIAgentID)
		switch strings.ToLower(strings.TrimSpace(a.str(attrStatus))) {
		case "started":
			ev.EventType = model.EventSessionStart
		case "completed", "failed", "cancelled":
			ev.EventType = model.EventSessionEnd
		default:
			return false
		}
		return true

	case geminiAgentStart, geminiAgentFinish:
		ev.Actor = model.ActorSystem
		ev.SubAgent = a.str(attrAgentName, attrAgentID)
		if name == geminiAgentStart {
			ev.EventType = model.EventSessionStart
		} else {
			ev.EventType = model.EventSessionEnd
		}
		return true

	case geminiApprovalModeSwitch, geminiApprovalModeSwitchLegacy:
		if ev.SourceAgent != model.AgentGeminiCLI {
			return false
		}
		classifyGeminiPermissionMode(ev, a)
		return true

	case opencodeUserPrompt, opencodeToolResult, opencodeToolDecision,
		opencodeSessionCreated, opencodeSessionDeleted:
		// OpenCode's names are bare, so they only alias when this record's
		// service.name resolved to OpenCode; a same-named record from any other
		// emitter falls through to skip rather than misclassify.
		if ev.SourceAgent != model.AgentOpenCode {
			return false
		}
		return classifyOpenCodeAlias(ev, a, rec, name)

	default:
		return false
	}
}

func classifyClaudeToolResult(ev *model.Event, a *attrs, rec logRecord) {
	name := a.str(attrAliasToolName)
	params := jsonObject(a.str(attrClaudeToolParameters))
	input := jsonObject(a.str(attrClaudeToolInput))
	ev.ToolName = name
	ev.ToolCallID = a.str(attrClaudeToolUseID)
	ev.SubAgent = firstMapString([]map[string]any{params, input}, "subagent_type")

	switch strings.ToLower(name) {
	case "bash", "workspacebash":
		ev.EventType = model.EventCommandResult
		ev.Command = firstMapString([]map[string]any{params, input}, "bash_command", "full_command", "command")
		if ms, ok := nonNegativeInt(a, attrDurationMs); ok {
			ev.DurationMs = &ms
		}
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstMapString([]map[string]any{input, params}, "file_path", "path")
	case "write", "edit", "multiedit", "notebookedit":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstMapString([]map[string]any{input, params}, "file_path", "notebook_path", "path")
	case "webfetch":
		rawURL := firstMapString([]map[string]any{input, params}, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = otelNetworkTargetURL(rawURL)
		ev.ContentPreview = preview(rawURL)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "websearch":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstMapString([]map[string]any{input, params}, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		ev.EventType = model.EventToolResult
		if server := mapString(params, "mcp_server_name"); server != "" {
			ev.MCPServer = server
			ev.MCPTool = firstNonEmpty(mapString(params, "mcp_tool_name"), name)
		} else if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if ev.EventType == model.EventCommandResult || ev.EventType == model.EventToolResult {
		ev.Actor = model.ActorTool
	}
	if claudeFailed(a) || errored(a, rec) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func classifyClaudeToolDecision(ev *model.Event, a *attrs) {
	ev.ToolName = a.str(attrAliasToolName)
	ev.ToolCallID = a.str(attrClaudeToolUseID)
	params := jsonObject(a.str(attrClaudeToolParameters))
	ev.SubAgent = mapString(params, "subagent_type")
	required := true
	ev.ApprovalRequired = &required
	switch normalizeDecision(a.str(attrDecision)) {
	case model.DecisionAllowed:
		ev.EventType = model.EventPermissionApproved
		ev.Decision = model.DecisionAllowed
		ev.ApprovalDecision = model.DecisionAllowed
	case model.DecisionDenied:
		ev.EventType = model.EventPermissionDenied
		ev.Decision = model.DecisionDenied
		ev.ApprovalDecision = model.DecisionDenied
	default:
		ev.EventType = model.EventPermissionRequested
		ev.Decision = model.DecisionAsked
		ev.ApprovalDecision = model.DecisionAsked
	}
}

func classifyClaudePermissionMode(ev *model.Event, a *attrs) {
	mode := a.str(attrClaudeToMode)
	ev.EventType = model.EventConfigAgent
	ev.Actor = model.ActorSystem
	ev.ContentPreview = preview(mode)
	if claudeElevatedMode(mode) {
		ev.Tags = append(ev.Tags, model.TagPermissionModeElevated)
	}
}

func claudeElevatedMode(mode string) bool {
	switch mode {
	case "acceptEdits", "auto", "bypassPermissions":
		return true
	default:
		return false
	}
}

func claudeFailed(a *attrs) bool {
	if strings.EqualFold(strings.TrimSpace(a.str(attrSuccess)), "false") {
		return true
	}
	return a.str(attrErrorType) != ""
}

func jsonObject(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var object map[string]any
	if json.Unmarshal([]byte(raw), &object) != nil {
		return nil
	}
	return object
}

func mapString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := object[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func firstMapString(objects []map[string]any, keys ...string) string {
	for _, object := range objects {
		if value := mapString(object, keys...); value != "" {
			return value
		}
	}
	return ""
}

// classifyOpenCodeAlias maps one of OpenCode's five bare event.name records onto
// numbat's vocabulary. The caller has already confirmed ev.SourceAgent is
// OpenCode, so these bare names cannot collide with another emitter's stream.
func classifyOpenCodeAlias(ev *model.Event, a *attrs, rec logRecord, name string) bool {
	switch name {
	case opencodeUserPrompt:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		// OpenCode emits prompt_length (a number), never the prompt text, so there
		// is no content to preview — a redaction-friendly emission left as-is.
		ev.Model = a.str(attrModel)
		return true

	case opencodeToolResult:
		classifyOpenCodeToolResult(ev, a, rec)
		return true

	case opencodeToolDecision:
		classifyOpenCodeDecision(ev, a)
		return true

	case opencodeSessionCreated:
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		return true

	case opencodeSessionDeleted:
		ev.EventType = model.EventSessionEnd
		ev.Actor = model.ActorSystem
		return true

	default:
		return false
	}
}

// classifyOpenCodeToolResult maps OpenCode's tool_result onto tool.result ONLY.
// OpenCode does not distinguish shell exec from any other tool at emit time —
// tool_name is the only signal and there is no process.command — so numbat does
// NOT synthesize a command.result here: a missed command.result is an acceptable
// false negative, a wrong one is not. duration_ms is dropped: the contract gates
// it onto command.result, the very event we decline to synthesize. success is a
// real bool (a false stamps tool_error), unlike Codex's string-valued success.
func classifyOpenCodeToolResult(ev *model.Event, a *attrs, rec logRecord) {
	ev.EventType = model.EventToolResult
	ev.Actor = model.ActorTool
	ev.ToolName = a.str(attrAliasToolName)
	if b, ok := a.boolval(attrSuccess); ok && !b {
		ev.Tags = append(ev.Tags, model.TagToolError)
	} else if errored(a, rec) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// classifyOpenCodeDecision maps OpenCode's tool_decision onto permission.* via
// the same normalizeDecision the semconv path uses. OpenCode pre-normalizes its
// decision to accept/reject, both of which normalizeDecision already handles.
func classifyOpenCodeDecision(ev *model.Event, a *attrs) {
	ev.ToolName = a.str(attrAliasToolName)
	ev.ToolCallID = a.str(attrCallID, attrGenAIToolCallID)
	required := true
	ev.ApprovalRequired = &required
	switch normalizeDecision(a.str(attrDecision)) {
	case model.DecisionAllowed:
		ev.EventType = model.EventPermissionApproved
		ev.Decision = model.DecisionAllowed
		ev.ApprovalDecision = model.DecisionAllowed
	case model.DecisionDenied:
		ev.EventType = model.EventPermissionDenied
		ev.Decision = model.DecisionDenied
		ev.ApprovalDecision = model.DecisionDenied
	default:
		ev.EventType = model.EventPermissionRequested
		ev.Decision = model.DecisionAsked
		ev.ApprovalDecision = model.DecisionAsked
	}
}

// classifyCodexDecision maps codex.tool_decision onto the permission.* vocabulary
// via the same normalizeDecision the semconv path uses. The decision is a
// lowercased ReviewDecision string (approved/denied/abort/…). call_id preserves
// the join to the matching tool result.
func classifyCodexDecision(ev *model.Event, a *attrs) {
	ev.ToolName = a.str(attrAliasToolName, attrGenAIToolName, attrToolName)
	ev.ToolCallID = a.str(attrCallID, attrGenAIToolCallID)
	required := true
	ev.ApprovalRequired = &required
	switch normalizeDecision(a.str(attrDecision)) {
	case model.DecisionAllowed:
		ev.EventType = model.EventPermissionApproved
		ev.Decision = model.DecisionAllowed
		ev.ApprovalDecision = model.DecisionAllowed
	case model.DecisionDenied:
		ev.EventType = model.EventPermissionDenied
		ev.Decision = model.DecisionDenied
		ev.ApprovalDecision = model.DecisionDenied
	default:
		ev.EventType = model.EventPermissionRequested
		ev.Decision = model.DecisionAsked
		ev.ApprovalDecision = model.DecisionAsked
	}
}

// classifyCodexToolResult maps codex.tool_result. A shell/exec tool becomes a
// command.result (carrying the wall-clock duration the record reports); an MCP
// or other tool becomes a tool.result with the mcp_server/mcp_tool split. Codex
// reports success as the STRING "true"/"false", so a failure stamps tool_error.
// The contract gates duration_ms off tool.result and mcp_* off command.result,
// so each branch sets only the fields its event_type allows.
func classifyCodexToolResult(ev *model.Event, a *attrs, rec logRecord) {
	name := a.str(attrAliasToolName, attrGenAIToolName, attrToolName)
	arguments := jsonObject(a.str(attrArguments))
	ev.ToolName = name
	ev.ToolCallID = a.str(attrCallID, attrGenAIToolCallID)

	if isShellToolName(name) {
		ev.EventType = model.EventCommandResult
		ev.Command = mapString(arguments, "cmd", "command")
		if ms, ok := nonNegativeInt(a, attrDurationMs); ok {
			ev.DurationMs = &ms
		}
	} else {
		ev.EventType = model.EventToolResult
		if server := a.str(attrMCPServer, attrMCPServerOrigin); server != "" {
			ev.MCPServer = server
			ev.MCPTool = name
		} else if s, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = s, tool
		}
	}
	ev.Actor = model.ActorTool

	// content_preview is an existing, universally-allowed field; retain the
	// tool_result output snippet there (redacted downstream) rather than dropping
	// it. No new model.Event field is introduced.
	if out := a.str(attrOutput); out != "" {
		ev.ContentPreview = preview(out)
	}

	if codexFailed(a) || errored(a, rec) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// classifyGeminiToolCall maps Gemini's terminal tool log. The event is emitted
// after execution and carries duration/success, so shell and generic tools map
// to result events; file and network tools retain their more specific action
// types. This mirrors the at-rest Gemini tool vocabulary without inventing
// aliases for unknown tool names.
func classifyGeminiToolCall(ev *model.Event, a *attrs, rec logRecord) {
	name := a.str(attrFunctionName, attrGenAIToolName, attrToolName)
	args := jsonObject(a.str(attrFunctionArgs))
	ev.ToolName = name
	ev.ToolCallID = a.str(attrGenAIToolCallID, attrToolCallID, attrCallID)

	switch strings.ToLower(name) {
	case "run_shell_command", "bash", "shell", "exec", "exec_command", "shell_command", "run_command":
		ev.EventType = model.EventCommandResult
		ev.Actor = model.ActorTool
		ev.Command = firstNonEmpty(
			mapString(args, argCommand, "cmd"),
			a.str(attrCommand, attrProcessCommandLine, attrProcessCommand),
			toolCommandArg(a),
		)
		if ms, ok := nonNegativeInt(a, attrDurationMs); ok {
			ev.DurationMs = &ms
		}
	case "read_file", "readfile":
		ev.EventType = model.EventFileRead
		ev.FilePath = mapString(args, argFilePath, "path")
	case "write_file", "writefile", "edit", "replace":
		ev.EventType = model.EventFileWrite
		ev.FilePath = mapString(args, argFilePath, "path")
	case "web_fetch", "webfetch", "fetchurl":
		prompt := mapString(args, "prompt", "url")
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(prompt)
		ev.URL = otelNetworkTargetURL(prompt)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "google_web_search", "websearch":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(mapString(args, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		ev.EventType = model.EventToolResult
		ev.Actor = model.ActorTool
		if server := a.str(attrMCPServerName); server != "" {
			ev.MCPServer = server
			ev.MCPTool = name
		} else if s, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = s, tool
		}
	}

	if d := normalizeGeminiDecision(a.str(attrDecision)); d != "" {
		ev.Decision = d
	}
	if geminiFailed(a) || errored(a, rec) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func classifyGeminiPermissionMode(ev *model.Event, a *attrs) {
	mode := a.str(attrClaudeToMode)
	ev.EventType = model.EventConfigAgent
	ev.Actor = model.ActorSystem
	ev.ContentPreview = preview(mode)
	if geminiModeElevated(mode) {
		ev.Tags = append(ev.Tags, model.TagPermissionModeElevated)
	}
}

func geminiModeElevated(mode string) bool {
	normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(mode)))
	return normalized == "yolo" || normalized == "autoedit"
}

// isShellToolName reports whether a tool name denotes shell/command execution,
// using the same exact set as the semconv tool classifier so Codex and Gemini
// shell calls route to command.* exactly as a standards-compliant one would.
func isShellToolName(name string) bool {
	switch strings.ToLower(name) {
	case "bash", "shell", "exec", "exec_command", "shell_command", "run_shell_command", "run_command":
		return true
	}
	return false
}

// codexFailed reports a Codex tool_result failure. Codex emits success as the
// STRING "true"/"false" (NOT a bool), so a string compare is the reliable read;
// boolval also accepts the string form as a fallback.
func codexFailed(a *attrs) bool {
	if strings.EqualFold(strings.TrimSpace(a.str(attrSuccess)), "false") {
		return true
	}
	if b, ok := a.boolval(attrSuccess); ok && !b {
		return true
	}
	return false
}

// geminiFailed reports a Gemini tool_call failure. Gemini emits success as a
// BOOL (the divergence from Codex's string), and also exposes error_type on a
// failure; either signal stamps tool_error.
func geminiFailed(a *attrs) bool {
	if b, ok := a.boolval(attrSuccess); ok && !b {
		return true
	}
	if a.str(attrErrorType) != "" {
		return true
	}
	v, ok := a.m[attrError]
	return ok && v.kind == valueString && strings.TrimSpace(v.stringValue) != ""
}

func nonNegativeInt(a *attrs, keys ...string) (int64, bool) {
	v, ok := a.intval(keys...)
	return v, ok && v >= 0
}

// normalizeGeminiDecision maps Gemini's tool-call decision vocabulary
// (accept/auto_accept/reject/modify) onto numbat's permission decision values.
// A modify is a user-edited acceptance, so it counts as allowed. An unknown or
// absent value yields "" so the caller leaves decision unset.
func normalizeGeminiDecision(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "accept", "auto_accept", "modify":
		return model.DecisionAllowed
	case "reject":
		return model.DecisionDenied
	default:
		return ""
	}
}
