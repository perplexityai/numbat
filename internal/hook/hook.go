// Package hook maps an endpoint agent's lifecycle hook payload into numbat's
// normalized model.Event. A hook fires live, inside the running agent, and
// hands numbat a JSON object on stdin describing what the agent is about to do
// or just did. This package is the boundary that turns that loosely-typed,
// per-agent payload into the same flat Event the on-disk extractors produce, so
// the shared pipeline detects on a hook event exactly as it does on an artifact
// event.
//
// Two honesty constraints shape the mapping:
//
//   - source_type is always "hook". A hook event is a live observation, not a
//     parse of a durable artifact, and downstream consumers must be able to tell
//     the two apart.
//   - Evidence is deliberately thin. A hook payload carries no artifact path,
//     line number, rowid, or content hash — there is no on-disk record to point
//     back to — so Evidence holds only the synthetic artifact type. The reported
//     working directory lives in Event.ProjectPath, not Evidence.LocalPath.
//     Fabricating a file/line/hash here would forge forensic provenance, so we
//     do not.
package hook

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/perplexityai/numbat/internal/applypatch"
	"github.com/perplexityai/numbat/internal/model"
)

// Agent identifiers the hook command accepts via --agent. They map onto the
// model.Agent* source identifiers stamped on the resulting event.
const (
	AgentClaude   = "claude"
	AgentCodex    = "codex"
	AgentGemini   = "gemini"
	AgentCursor   = "cursor"
	AgentWindsurf = "windsurf"
	AgentCopilot  = "copilot"
	// VS Code Copilot Chat is distinct from GitHub Copilot CLI on the wire.
	AgentVSCode      = "vscode"
	AgentOpenCode    = "opencode"
	AgentOpenClaw    = "openclaw"
	AgentAntigravity = "antigravity"
	AgentFactory     = "factory"
	AgentGrok        = "grok"
	AgentDevin       = "devin"
	AgentHermes      = "hermes"
	AgentPi          = "pi"
	AgentKimi        = "kimi"
	AgentQwen        = "qwen"
	AgentCline       = "cline"
	AgentAmp         = "amp"
	AgentAuggie      = "auggie"
	AgentKiro        = "kiro"
	AgentGoose       = "goose"
	AgentKilo        = "kilo"
	AgentOpenHands   = "openhands"
	AgentCrush       = "crush"
	AgentJunie       = "junie"
)

var agentModelByCLI = map[string]string{
	AgentClaude:      model.AgentClaudeCode,
	AgentCodex:       model.AgentCodex,
	AgentGemini:      model.AgentGeminiCLI,
	AgentCursor:      model.AgentCursor,
	AgentWindsurf:    model.AgentWindsurf,
	AgentCopilot:     model.AgentCopilot,
	AgentVSCode:      model.AgentVSCode,
	AgentOpenCode:    model.AgentOpenCode,
	AgentOpenClaw:    model.AgentOpenClaw,
	AgentAntigravity: model.AgentAntigravity,
	AgentFactory:     model.AgentFactory,
	AgentGrok:        model.AgentGrok,
	AgentDevin:       model.AgentDevinCLI,
	AgentHermes:      model.AgentHermesCLI,
	AgentPi:          model.AgentPi,
	AgentKimi:        model.AgentKimiCode,
	AgentQwen:        model.AgentQwenCode,
	AgentCline:       model.AgentCline,
	AgentAmp:         model.AgentAmp,
	AgentAuggie:      model.AgentAuggie,
	AgentKiro:        model.AgentKiro,
	AgentGoose:       model.AgentGoose,
	AgentKilo:        model.AgentKilo,
	AgentOpenHands:   model.AgentOpenHands,
	AgentCrush:       model.AgentCrush,
	AgentJunie:       model.AgentJunie,
}

var agentList = []string{
	AgentClaude,
	AgentCodex,
	AgentGemini,
	AgentCursor,
	AgentWindsurf,
	AgentCopilot,
	AgentVSCode,
	AgentOpenCode,
	AgentOpenClaw,
	AgentAntigravity,
	AgentFactory,
	AgentGrok,
	AgentDevin,
	AgentHermes,
	AgentPi,
	AgentKimi,
	AgentQwen,
	AgentCline,
	AgentAmp,
	AgentAuggie,
	AgentKiro,
	AgentGoose,
	AgentKilo,
	AgentOpenHands,
	AgentCrush,
	AgentJunie,
}

const (
	codexTagPatchRequested       = "patch_apply_requested"
	openClawTagTransportBoundary = "openclaw_transport_boundary"
	openClawTagModelBoundary     = "openclaw_model_boundary"
)

// AgentNames returns the closed set of supported --agent values in stable CLI
// order. The returned slice is a copy so callers may sort or modify it without
// mutating hook's source of truth.
func AgentNames() []string {
	out := append([]string(nil), agentList...)
	return out
}

// AgentUsage lists the supported --agent values in the CLI's canonical
// pipe-delimited form.
func AgentUsage() string {
	return strings.Join(agentList, "|")
}

// SortAgentNames returns a sorted copy of names, for parity tests and callers
// that need order-insensitive comparison.
func SortAgentNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}

// Lifecycle is the normalized positional event accepted by `numbat hook`.
type Lifecycle string

const (
	LifecycleSessionStart     Lifecycle = "session-start"
	LifecyclePromptSubmit     Lifecycle = "prompt-submit"
	LifecyclePreTool          Lifecycle = "pre-tool"
	LifecyclePostTool         Lifecycle = "post-tool"
	LifecyclePermission       Lifecycle = "permission-request"
	LifecyclePermissionDenied Lifecycle = "permission-denied"
	LifecycleStop             Lifecycle = "stop"
	LifecycleSessionEnd       Lifecycle = "session-end"
	LifecycleFileRead         Lifecycle = "file-read"
	LifecycleFileWrite        Lifecycle = "file-write"
	LifecycleMCPCall          Lifecycle = "mcp-call"
	LifecycleCommandExec      Lifecycle = "command-exec"
	LifecycleCommandResult    Lifecycle = "command-result"
	LifecycleAssistant        Lifecycle = "assistant"

	LifecycleCopilotPreTool         Lifecycle = "copilot-pre-tool"
	LifecycleCopilotPostTool        Lifecycle = "copilot-post-tool"
	LifecycleCopilotPermission      Lifecycle = "copilot-permission-request"
	LifecycleCursorPreTool          Lifecycle = "cursor-pre-tool"
	LifecycleCursorPostTool         Lifecycle = "cursor-post-tool"
	LifecycleCursorPostToolFailure  Lifecycle = "cursor-post-tool-failure"
	LifecycleVSCodePreTool          Lifecycle = "vscode-pre-tool"
	LifecycleVSCodePostTool         Lifecycle = "vscode-post-tool"
	LifecycleCodexPreTool           Lifecycle = "codex-pre-tool"
	LifecycleCodexPostTool          Lifecycle = "codex-post-tool"
	LifecycleCodexPermission        Lifecycle = "codex-permission-request"
	LifecycleGeminiPreTool          Lifecycle = "gemini-pre-tool"
	LifecycleGeminiPostTool         Lifecycle = "gemini-post-tool"
	LifecycleOpenCodePreTool        Lifecycle = "opencode-pre-tool"
	LifecycleOpenCodePostTool       Lifecycle = "opencode-post-tool"
	LifecycleAntigravityPreTool     Lifecycle = "antigravity-pre-tool"
	LifecycleAntigravityPostTool    Lifecycle = "antigravity-post-tool"
	LifecycleFactoryPreTool         Lifecycle = "factory-pre-tool"
	LifecycleFactoryPostTool        Lifecycle = "factory-post-tool"
	LifecycleGrokPreTool            Lifecycle = "grok-pre-tool"
	LifecycleGrokPostTool           Lifecycle = "grok-post-tool"
	LifecycleDevinPreTool           Lifecycle = "devin-pre-tool"
	LifecycleDevinPostTool          Lifecycle = "devin-post-tool"
	LifecycleDevinPermission        Lifecycle = "devin-permission-request"
	LifecycleHermesPreTool          Lifecycle = "hermes-pre-tool"
	LifecycleHermesPostTool         Lifecycle = "hermes-post-tool"
	LifecycleHermesPermission       Lifecycle = "hermes-permission-request"
	LifecycleHermesPermissionResult Lifecycle = "hermes-permission-result"
)

// lifecycles is the closed set of supported lifecycle names, used to validate
// the command's positional argument.
var lifecycles = map[Lifecycle]struct{}{
	LifecycleSessionStart: {}, LifecyclePromptSubmit: {}, LifecyclePreTool: {},
	LifecyclePostTool: {}, LifecyclePermission: {}, LifecyclePermissionDenied: {},
	LifecycleStop: {}, LifecycleSessionEnd: {}, LifecycleFileRead: {}, LifecycleFileWrite: {},
	LifecycleMCPCall: {}, LifecycleCommandExec: {}, LifecycleCommandResult: {},
	LifecycleAssistant: {}, LifecycleCopilotPreTool: {}, LifecycleCopilotPostTool: {}, LifecycleCopilotPermission: {},
	LifecycleCursorPreTool: {}, LifecycleCursorPostTool: {}, LifecycleCursorPostToolFailure: {},
	LifecycleVSCodePreTool: {}, LifecycleVSCodePostTool: {},
	LifecycleCodexPreTool: {}, LifecycleCodexPostTool: {}, LifecycleCodexPermission: {},
	LifecycleGeminiPreTool: {}, LifecycleGeminiPostTool: {},
	LifecycleOpenCodePreTool: {}, LifecycleOpenCodePostTool: {},
	LifecycleAntigravityPreTool: {}, LifecycleAntigravityPostTool: {},
	LifecycleFactoryPreTool: {}, LifecycleFactoryPostTool: {},
	LifecycleGrokPreTool: {}, LifecycleGrokPostTool: {},
	LifecycleDevinPreTool: {}, LifecycleDevinPostTool: {}, LifecycleDevinPermission: {},
	LifecycleHermesPreTool: {}, LifecycleHermesPostTool: {}, LifecycleHermesPermission: {}, LifecycleHermesPermissionResult: {},
}

// ParseLifecycle validates a lifecycle name from the CLI.
func ParseLifecycle(s string) (Lifecycle, error) {
	lc := Lifecycle(s)
	if _, ok := lifecycles[lc]; !ok {
		return "", fmt.Errorf("unknown hook lifecycle %q", s)
	}
	return lc, nil
}

// ResolveLifecycle accepts an agent's native event name or the normalized alias
// written by numbat's installer.
func ResolveLifecycle(agent, raw string) (Lifecycle, error) {
	switch agent {
	case AgentClaude:
		if lc, ok := resolveClaudeEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown claude hook event %q", raw)
	case AgentCursor:
		if lc, ok := resolveCursorEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown cursor hook event %q", raw)
	case AgentWindsurf:
		if lc, ok := resolveWindsurfEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown windsurf hook event %q", raw)
	case AgentCopilot:
		if lc, ok := resolveCopilotEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown copilot hook event %q", raw)
	case AgentVSCode:
		if lc, ok := resolveVSCodeEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown vscode hook event %q", raw)
	case AgentCodex:
		if lc, ok := resolveCodexEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown codex hook event %q", raw)
	case AgentGemini:
		if lc, ok := resolveGeminiEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown gemini hook event %q", raw)
	case AgentOpenCode:
		if lc, ok := resolveOpenCodeEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown opencode hook event %q", raw)
	case AgentOpenClaw:
		if lc, ok := resolveOpenClawEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown openclaw hook event %q", raw)
	case AgentAntigravity:
		if lc, ok := resolveAntigravityEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown antigravity hook event %q", raw)
	case AgentFactory:
		if lc, ok := resolveFactoryEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown factory hook event %q", raw)
	case AgentGrok:
		if lc, ok := resolveGrokEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown grok hook event %q", raw)
	case AgentDevin:
		if lc, ok := resolveDevinEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown devin hook event %q", raw)
	case AgentHermes:
		if lc, ok := resolveHermesEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown hermes hook event %q", raw)
	case AgentPi:
		if lc, ok := resolvePiEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown pi hook event %q", raw)
	case AgentKimi, AgentQwen, AgentAuggie, AgentGoose, AgentOpenHands:
		if lc, ok := resolveClaudeEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown %s hook event %q", agent, raw)
	case AgentCrush:
		if lc, ok := resolveCrushEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown crush hook event %q", raw)
	case AgentJunie:
		if lc, ok := resolveJunieEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown junie hook event %q", raw)
	case AgentCline:
		if lc, ok := resolveClineEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown cline hook event %q", raw)
	case AgentAmp:
		if lc, ok := resolveAmpEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown amp hook event %q", raw)
	case AgentKiro:
		if lc, ok := resolveKiroEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown kiro hook event %q", raw)
	case AgentKilo:
		if lc, ok := resolveKiloEvent(raw); ok {
			return lc, nil
		}
		return "", fmt.Errorf("unknown kilo hook event %q", raw)
	default:
		return ParseLifecycle(raw)
	}
}

// resolveOpenClawEvent accepts only the typed plugin callbacks emitted by the
// generated OpenClaw package and their normalized CLI aliases. The llm_input
// and llm_output callbacks require OpenClaw's explicit conversation-access
// policy; the other eight callbacks remain available without it.
func resolveOpenClawEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "session_start", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "message_received", "llm_input", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "before_tool_call", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "after_tool_call", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "message_sent", "llm_output", string(LifecycleAssistant), string(LifecycleStop):
		return LifecycleAssistant, true
	case "session_end", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "subagent_spawned":
		return LifecycleSessionStart, true
	case "subagent_ended":
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

func resolvePiEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "session_start", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "before_agent_start", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "tool_call", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "tool_result", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "message_end", string(LifecycleAssistant), string(LifecycleStop):
		return LifecycleAssistant, true
	case "session_shutdown", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveCrushEvent deliberately accepts only the event Crush currently
// implements. Keeping this narrower than the Claude-compatible output shape
// prevents unsupported future-looking lifecycle names from appearing wired.
func resolveCrushEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", "pre_tool_use", string(LifecyclePreTool):
		return LifecyclePreTool, true
	default:
		return "", false
	}
}

// resolveJunieEvent is limited to the callbacks numbat installs. Junie's
// PermissionRequest success semantics can auto-approve an action, and its
// StopFailure callback has no honest normalized action type, so neither is
// accepted as a wired lifecycle here.
func resolveJunieEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "sessionstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case string(LifecycleStop), string(LifecycleAssistant):
		return LifecycleStop, true
	case "sessionend", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

func resolveClineEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "taskstart", "taskresume", "agent_start", "agent_resume", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", "prompt_submit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", "tool_call", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "posttooluse", "tool_result", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "taskcomplete", "taskcancel", "taskerror", "sessionshutdown",
		"agent_end", "agent_abort", "agent_error", "session_shutdown", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

func resolveAmpEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "session.start", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "agent.start", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "tool.call", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "tool.result", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "agent.end", string(LifecycleAssistant), string(LifecycleStop):
		return LifecycleAssistant, true
	default:
		return "", false
	}
}

func resolveKiloEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "session.created", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "chat.message", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "tool.execute.before", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "tool.execute.after", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "message.updated", string(LifecycleAssistant), string(LifecycleStop):
		return LifecycleAssistant, true
	case "session.deleted", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveKiroEvent accepts Kiro's PascalCase versioned global-hook
// triggers and the lower-camel names retained by the 2.x embedded-hook API.
func resolveKiroEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "sessionstart", "agentspawn", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "posttooluse", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case string(LifecycleStop), string(LifecycleAssistant):
		return LifecycleStop, true
	default:
		return "", false
	}
}

// resolveClaudeEvent accepts the lifecycles numbat installs plus the raw Claude
// Code hook names for those same events.
func resolveClaudeEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "sessionstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", string(LifecyclePreTool):
		return LifecyclePreTool, true
	case "posttooluse", "posttoolusefailure", string(LifecyclePostTool):
		return LifecyclePostTool, true
	case "permissionrequest", "permissionresult", string(LifecyclePermission):
		return LifecyclePermission, true
	case "permissiondenied", string(LifecyclePermissionDenied):
		return LifecyclePermissionDenied, true
	case string(LifecycleStop), string(LifecycleAssistant):
		return LifecycleStop, true
	case "sessionend", "subagentstop", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "subagentstart":
		return LifecycleSessionStart, true
	default:
		return "", false
	}
}

// resolveAntigravityEvent accepts the events and aliases numbat installs.
func resolveAntigravityEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", string(LifecycleAntigravityPreTool):
		return LifecycleAntigravityPreTool, true
	case "posttooluse", string(LifecycleAntigravityPostTool):
		return LifecycleAntigravityPostTool, true
	case string(LifecycleStop):
		return LifecycleStop, true
	default:
		return "", false
	}
}

// resolveFactoryEvent accepts the documented Factory events numbat installs.
func resolveFactoryEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", string(LifecycleFactoryPreTool):
		return LifecycleFactoryPreTool, true
	case "posttooluse", string(LifecycleFactoryPostTool):
		return LifecycleFactoryPostTool, true
	case "sessionstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "stop", string(LifecycleAssistant):
		return LifecycleAssistant, true
	case "subagentstop":
		return LifecycleSessionEnd, true
	case "sessionend", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveGrokEvent accepts the Grok events numbat installs and their
// installer-written lifecycle names. Stop is a turn boundary; SessionEnd is the
// true session boundary.
func resolveGrokEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", string(LifecycleGrokPreTool):
		return LifecycleGrokPreTool, true
	case "posttooluse", "posttoolusefailure", string(LifecycleGrokPostTool):
		return LifecycleGrokPostTool, true
	case "sessionstart", "subagentstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "subagentstop":
		return LifecycleSessionEnd, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "permissiondenied", string(LifecyclePermissionDenied):
		return LifecyclePermissionDenied, true
	case string(LifecycleStop), string(LifecycleAssistant):
		return LifecycleStop, true
	case "sessionend", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveDevinEvent keeps Devin's turn stop distinct from its session end.
func resolveDevinEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", string(LifecycleDevinPreTool):
		return LifecycleDevinPreTool, true
	case "posttooluse", string(LifecycleDevinPostTool):
		return LifecycleDevinPostTool, true
	case "permissionrequest", string(LifecycleDevinPermission):
		return LifecycleDevinPermission, true
	case "sessionstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case string(LifecycleStop):
		return LifecycleStop, true
	case "sessionend", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveHermesEvent accepts the Hermes events numbat installs and their
// installer-written lifecycle names.
func resolveHermesEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pre_tool_call", string(LifecycleHermesPreTool):
		return LifecycleHermesPreTool, true
	case "post_tool_call", string(LifecycleHermesPostTool):
		return LifecycleHermesPostTool, true
	case "pre_approval_request", string(LifecycleHermesPermission):
		return LifecycleHermesPermission, true
	case "post_approval_response", string(LifecycleHermesPermissionResult):
		return LifecycleHermesPermissionResult, true
	case "on_session_start", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "pre_llm_call", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "post_llm_call", string(LifecycleAssistant), string(LifecycleStop):
		return LifecycleAssistant, true
	case "subagent_start":
		return LifecycleSessionStart, true
	case "subagent_stop", "on_session_finalize", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveOpenCodeEvent accepts the four moments forwarded by the generated
// plugin. session.idle is a turn boundary, not a session end, and is not wired.
func resolveOpenCodeEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "tool.execute.before", string(LifecycleOpenCodePreTool):
		return LifecycleOpenCodePreTool, true
	case "tool.execute.after", string(LifecycleOpenCodePostTool):
		return LifecycleOpenCodePostTool, true
	case "chat.message", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "message.updated", string(LifecycleAssistant):
		return LifecycleAssistant, true
	case "session.created", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "session.deleted", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveCodexEvent accepts the Codex events numbat installs and their
// installer-written lifecycle names. Compaction hooks are intentionally omitted:
// numbat has no compaction event type and must not mislabel them as sessions.
func resolveCodexEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "pretooluse", string(LifecycleCodexPreTool):
		return LifecycleCodexPreTool, true
	case "posttooluse", string(LifecycleCodexPostTool):
		return LifecycleCodexPostTool, true
	case "userpromptsubmit", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "permissionrequest", string(LifecyclePermission), string(LifecycleCodexPermission):
		return LifecycleCodexPermission, true
	case "sessionstart", "subagentstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "subagentstop", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "stop", string(LifecycleAssistant):
		return LifecycleStop, true
	default:
		return "", false
	}
}

// resolveGeminiEvent accepts prompt/turn, tool, and session moments. Model and
// compression hooks are intentionally not installed.
func resolveGeminiEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "beforetool", string(LifecycleGeminiPreTool):
		return LifecycleGeminiPreTool, true
	case "aftertool", string(LifecycleGeminiPostTool):
		return LifecycleGeminiPostTool, true
	case "beforeagent", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "afteragent", string(LifecycleAssistant):
		return LifecycleAssistant, true
	case "sessionstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "sessionend", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveCopilotEvent accepts Copilot CLI's VS Code-compatible event names and
// numbat's installer-written lifecycle aliases.
func resolveCopilotEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "userpromptsubmit", "userpromptsubmitted", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", "pre-tool", "pre_tool", string(LifecycleCopilotPreTool):
		return LifecycleCopilotPreTool, true
	case "posttooluse", "posttoolusefailure", "post-tool", "post_tool", string(LifecycleCopilotPostTool):
		return LifecycleCopilotPostTool, true
	case "permissionrequest", string(LifecycleCopilotPermission):
		return LifecycleCopilotPermission, true
	case "sessionstart", "subagentstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "sessionend", "subagentstop", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "stop", "agentstop", string(LifecycleAssistant):
		return LifecycleAssistant, true
	default:
		return "", false
	}
}

// resolveVSCodeEvent maps VS Code's payload vocabulary from the shared Copilot
// hook file onto numbat lifecycles.
func resolveVSCodeEvent(raw string) (Lifecycle, bool) {
	switch strings.ToLower(raw) {
	case "userpromptsubmit", "userpromptsubmitted", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", string(LifecycleVSCodePreTool):
		return LifecycleVSCodePreTool, true
	case "posttooluse", string(LifecycleVSCodePostTool):
		return LifecycleVSCodePostTool, true
	case "sessionstart", "subagentstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "subagentstop", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "stop":
		return LifecycleSessionEnd, true
	default:
		return "", false
	}
}

// resolveWindsurfEvent accepts the documented Cascade event names and numbat's
// normalized lifecycle aliases. Exact matching prevents a future or malformed
// event from being silently classified as a known action.
func resolveWindsurfEvent(raw string) (Lifecycle, bool) {
	s := strings.ToLower(raw)
	switch s {
	case "pre_user_prompt", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pre_run_command", string(LifecycleCommandExec):
		return LifecycleCommandExec, true
	case "post_run_command", string(LifecycleCommandResult):
		return LifecycleCommandResult, true
	case "pre_mcp_tool_use", "post_mcp_tool_use", string(LifecycleMCPCall):
		return LifecycleMCPCall, true
	case "pre_write_code", "post_write_code", string(LifecycleFileWrite):
		return LifecycleFileWrite, true
	case "pre_read_code", "post_read_code", string(LifecycleFileRead):
		return LifecycleFileRead, true
	case "post_cascade_response", "post_cascade_response_with_transcript", string(LifecycleAssistant):
		return LifecycleAssistant, true
	default:
		return "", false
	}
}

// resolveCursorEvent accepts Cursor's documented event names, known older
// aliases, and numbat's normalized lifecycle aliases. It deliberately does not
// use substring matching: unknown labels must surface as wiring errors.
func resolveCursorEvent(raw string) (Lifecycle, bool) {
	s := strings.ToLower(raw)
	switch s {
	case "sessionstart", "subagentstart", string(LifecycleSessionStart):
		return LifecycleSessionStart, true
	case "sessionend", "subagentstop", string(LifecycleSessionEnd):
		return LifecycleSessionEnd, true
	case "beforesubmitprompt", "pre_user_prompt", string(LifecyclePromptSubmit):
		return LifecyclePromptSubmit, true
	case "pretooluse", string(LifecycleCursorPreTool):
		return LifecycleCursorPreTool, true
	case "posttooluse", string(LifecycleCursorPostTool):
		return LifecycleCursorPostTool, true
	case "posttoolusefailure", string(LifecycleCursorPostToolFailure):
		return LifecycleCursorPostToolFailure, true
	case "beforeshellexecution", "beforeshellcommand", string(LifecycleCommandExec):
		return LifecycleCommandExec, true
	case "aftershellexecution", "aftershellcommand", string(LifecycleCommandResult):
		return LifecycleCommandResult, true
	case "beforemcpexecution", "aftermcpexecution", string(LifecycleMCPCall):
		return LifecycleMCPCall, true
	case "afterfileedit", "beforefilewrite", "afterfilewrite", string(LifecycleFileWrite):
		return LifecycleFileWrite, true
	case "beforereadfile", string(LifecycleFileRead):
		return LifecycleFileRead, true
	case string(LifecycleStop):
		return LifecycleStop, true
	default:
		return "", false
	}
}

// ParseAgent validates an --agent value and returns the model.Agent* source id
// it maps to.
func ParseAgent(s string) (string, error) {
	if src, ok := agentModelByCLI[s]; ok {
		return src, nil
	}
	return "", fmt.Errorf("unknown agent %q: want %s", s, AgentUsage())
}

// PassthroughResponse returns the non-blocking response for one hook event.
// Most agents use an empty object for "no directive". Antigravity requires a
// decision on PreToolUse and Stop: ask preserves its normal approval policy,
// while stop permits the already-requested termination.
func PassthroughResponse(agent string, lc Lifecycle) map[string]any {
	if agent == AgentCline {
		return map[string]any{"cancel": false}
	}
	if agent == AgentAmp && lc == LifecyclePreTool {
		return map[string]any{"action": "allow"}
	}
	if agent == AgentAntigravity {
		switch lc {
		case LifecycleAntigravityPreTool:
			return map[string]any{"decision": "ask"}
		case LifecycleStop:
			return map[string]any{"decision": "stop"}
		}
	}
	return map[string]any{}
}

// ClaudeDenyResponse is the stdout object for opt-in Claude enforcement. It is
// emitted only after a clean explicitly enforceable match; recover and error
// paths always fall open.
func ClaudeDenyResponse(reason string) map[string]any {
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
}

// CodexDenyResponse is the stdout object for opt-in Codex PreToolUse
// enforcement.
func CodexDenyResponse(reason string) map[string]any {
	return ClaudeDenyResponse(reason)
}

// DenyResponse returns the agent's documented structured pre-tool block. A
// false result means that the agent either uses process exit status or does not
// support numbat enforcement.
func DenyResponse(agent, reason string) (map[string]any, bool) {
	switch agent {
	case AgentClaude, AgentCodex:
		return ClaudeDenyResponse(reason), true
	case AgentCursor:
		return map[string]any{
			"permission":    "deny",
			"user_message":  reason,
			"agent_message": reason,
		}, true
	case AgentCopilot:
		return map[string]any{
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		}, true
	case AgentVSCode:
		return ClaudeDenyResponse(reason), true
	case AgentGemini, AgentAntigravity, AgentGrok:
		return map[string]any{"decision": "deny", "reason": reason}, true
	case AgentFactory:
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		}, true
	case AgentDevin:
		return map[string]any{"decision": "block", "reason": reason}, true
	case AgentHermes:
		return map[string]any{"action": "block", "message": reason}, true
	case AgentPi:
		return map[string]any{"block": true, "reason": reason}, true
	case AgentOpenClaw:
		return map[string]any{"block": true, "blockReason": reason}, true
	case AgentCline:
		return map[string]any{"cancel": true, "errorMessage": reason}, true
	case AgentAmp:
		return map[string]any{"action": "reject-and-continue", "message": reason}, true
	case AgentKilo:
		return map[string]any{"block": true, "reason": reason}, true
	default:
		return nil, false
	}
}

// DenyUsesExitCode reports whether a clean deny is communicated with exit 2
// and the reason on stderr instead of stdout JSON.
func DenyUsesExitCode(agent string) bool {
	return agent == AgentWindsurf || agent == AgentKimi || agent == AgentQwen || agent == AgentAuggie || agent == AgentKiro || agent == AgentGoose || agent == AgentOpenHands || agent == AgentCrush || agent == AgentJunie
}

// EnforceEligible restricts blocking to the synchronous pre-tool callback for
// each supported agent. event is needed for Windsurf because its pre/post file
// and MCP events normalize to the same lifecycle.
func EnforceEligible(agent, event string, lc Lifecycle) bool {
	switch agent {
	case AgentClaude:
		return lc == LifecyclePreTool
	case AgentCodex:
		return CodexEnforceEligible(lc)
	case AgentCursor:
		if lc == LifecycleCursorPreTool {
			return true
		}
		// Retain control semantics for older/manual specialized configurations.
		// Current installs use only the generic lifecycle above.
		switch strings.ToLower(event) {
		case "beforeshellexecution", "beforemcpexecution", "beforereadfile":
			return true
		}
	case AgentCopilot:
		return lc == LifecycleCopilotPreTool
	case AgentVSCode:
		return lc == LifecycleVSCodePreTool
	case AgentGemini:
		return lc == LifecycleGeminiPreTool
	case AgentAntigravity:
		return lc == LifecycleAntigravityPreTool
	case AgentFactory:
		return lc == LifecycleFactoryPreTool
	case AgentGrok:
		return lc == LifecycleGrokPreTool
	case AgentDevin:
		return lc == LifecycleDevinPreTool
	case AgentHermes:
		return lc == LifecycleHermesPreTool
	case AgentWindsurf:
		switch strings.ToLower(event) {
		case "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use":
			return true
		}
	case AgentOpenClaw, AgentPi, AgentKimi, AgentQwen, AgentCline, AgentAmp, AgentAuggie, AgentKiro, AgentGoose, AgentKilo, AgentOpenHands, AgentCrush, AgentJunie:
		return lc == LifecyclePreTool
	}
	return false
}

// CodexEnforceEligible reports whether the lifecycle uses Codex's documented
// PreToolUse deny response. Hook coverage is not a complete security boundary:
// Codex may execute tools that do not currently emit PreToolUse.
func CodexEnforceEligible(lc Lifecycle) bool {
	return lc == LifecycleCodexPreTool
}

// Map turns a decoded hook payload into a model.Event for the given lifecycle
// moment and agent. agent is the validated --agent value; sourceAgent is its
// model.Agent* id. The payload is the raw stdin JSON decoded into a map; fields
// are resolved through per-agent key fallbacks so the small naming differences
// between agents (session_id vs sessionId, tool_input vs toolInput) do not need
// a parser each.
//
// Map never fails: an unrecognized or empty payload still yields a well-formed
// event (with whatever fields could be resolved), because the hook command must
// not block the agent on a mapping problem. eventID makes the event addressable
// and is generated by the caller so it can incorporate a run id.
func Map(lc Lifecycle, agent, sourceAgent, eventID string, payload map[string]any) model.Event {
	// Copilot CLI and VS Code load the same user hook file. The lower-camel
	// events numbat installs produce native camelCase payloads in Copilot CLI;
	// VS Code converts them to PascalCase and includes hook_event_name in its
	// snake_case envelope. Keep one hook command while retaining the real source.
	if agent == AgentCopilot {
		if _, ok := payload["hook_event_name"]; ok {
			sourceAgent = model.AgentVSCode
		}
	}
	r := newResolver(agent, payload)
	ev := model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       eventID,
		SourceAgent:   sourceAgent,
		SourceType:    model.SourceHook,
		Timestamp:     r.timestamp(),
		SessionID:     r.sessionID(),
		ProjectPath:   r.cwd(),
		Actor:         model.ActorAssistant,
		// A hook is a live signal with no artifact line to verify against, so its
		// confidence is medium: the action is real but the evidence is the agent's
		// own report, not a durable record. The artifact type names the sensor.
		Confidence: model.ConfidenceMedium,
		Evidence:   model.Evidence{ArtifactType: model.SourceHook},
	}
	ev.Model = r.envStr("model", "model_name", "modelName")
	ev.ModelProvider = r.envStr("model_provider", "modelProvider", "provider_name", "providerName")
	if agent == AgentCursor {
		// Cursor reports the parent model in the common field and the delegated
		// child's model separately on subagent boundaries. Prefer the child when
		// present so a subagent session is not attributed to its parent.
		if childModel := r.envStr("subagent_model", "subagentModel"); childModel != "" {
			ev.Model = childModel
		}
		ev.GitBranch = r.envStr("git_branch", "gitBranch")
	}
	if agent == AgentCline {
		if active, ok := payload["model"].(map[string]any); ok {
			ev.Model = firstString(active, "slug", "model")
			ev.ModelProvider = firstString(active, "provider")
		}
	}
	if agent == AgentHermes {
		if ev.Model == "" {
			ev.Model = r.extraStr("model")
		}
		if ev.ModelProvider == "" {
			ev.ModelProvider = r.extraStr("model_provider", "provider")
		}
	}

	switch lc {
	case LifecycleSessionStart:
		ev.EventType = model.EventSessionStart
		ev.Actor = model.ActorSystem
		ev.SubAgent = r.subAgent()
	case LifecyclePromptSubmit:
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
		// prompt.user carries only content_preview (a context field). Cursor's
		// beforeSubmitPrompt may attach files; their paths are folded into the
		// preview so the references are visible without inventing a field — the
		// flat Event has no attachment list, and fabricating one would forge a
		// shape the schema does not define.
		prompt := r.prompt()
		if agent == AgentHermes && prompt == "" {
			prompt = r.extraStr("user_message")
		}
		ev.ContentPreview = preview(promptWithAttachments(prompt, r.attachmentPaths()))
	case LifecyclePreTool:
		classifyPortableTool(&ev, &r, false)
	case LifecyclePostTool:
		classifyPortableTool(&ev, &r, true)
	case LifecycleCommandExec:
		ev.EventType = model.EventCommandExec
		ev.Command = r.command()
	case LifecycleCommandResult:
		ev.EventType = model.EventCommandResult
		ev.Command = r.command()
		if code, ok := r.exitCode(); ok {
			ev.ExitCode = &code
		}
		if ms, ok := r.durationMs(); ok {
			ev.DurationMs = &ms
		}
		if r.toolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
	case LifecycleFileRead:
		// file.read names the path only — the read's content is never stored, in
		// keeping with numbat's evidence-not-content philosophy.
		ev.EventType = model.EventFileRead
		ev.FilePath = r.filePath()
	case LifecycleFileWrite:
		ev.EventType = model.EventFileWrite
		ev.FilePath = r.filePath()
		if sha, n, ok := r.editsDiff(); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		} else if sha, n, ok := r.diff(); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case LifecycleMCPCall:
		mapMCPCall(&ev, &r)
	case LifecycleCopilotPreTool:
		classifyCopilotTool(&ev, &r, false)
	case LifecycleCopilotPostTool:
		classifyCopilotTool(&ev, &r, true)
	case LifecycleCopilotPermission:
		mapCopilotPermission(&ev, &r)
	case LifecycleVSCodePreTool:
		classifyVSCodeTool(&ev, &r, false)
	case LifecycleCursorPreTool:
		classifyCursorTool(&ev, &r, false, false)
	case LifecycleCursorPostTool:
		classifyCursorTool(&ev, &r, true, false)
	case LifecycleCursorPostToolFailure:
		classifyCursorTool(&ev, &r, true, true)
	case LifecycleVSCodePostTool:
		classifyVSCodeTool(&ev, &r, true)
	case LifecycleCodexPreTool:
		classifyCodexTool(&ev, &r, false)
	case LifecycleCodexPostTool:
		classifyCodexTool(&ev, &r, true)
	case LifecycleGeminiPreTool:
		classifyGeminiTool(&ev, &r, false)
	case LifecycleGeminiPostTool:
		classifyGeminiTool(&ev, &r, true)
	case LifecycleOpenCodePreTool:
		classifyOpenCodeHookTool(&ev, &r, false)
		// callID correlates a tool.execute.before with its later .after (the plugin
		// forwards OpenCode's input.callID on both moments); stamp it so the pre/post
		// pair pairs up, mirroring the at-rest OpenCode extractor's part.CallID.
		ev.ToolCallID = r.envStr("callID", "call_id", "callId")
	case LifecycleOpenCodePostTool:
		classifyOpenCodeHookTool(&ev, &r, true)
		ev.ToolCallID = r.envStr("callID", "call_id", "callId")
	case LifecycleAntigravityPreTool:
		classifyAntigravityTool(&ev, &r, false)
	case LifecycleAntigravityPostTool:
		classifyAntigravityTool(&ev, &r, true)
	case LifecycleFactoryPreTool:
		classifyFactoryTool(&ev, &r, false)
	case LifecycleFactoryPostTool:
		classifyFactoryTool(&ev, &r, true)
	case LifecycleGrokPreTool:
		classifyGrokTool(&ev, &r, false)
	case LifecycleGrokPostTool:
		classifyGrokTool(&ev, &r, true)
	case LifecycleDevinPreTool:
		classifyDevinTool(&ev, &r, false)
	case LifecycleDevinPostTool:
		classifyDevinTool(&ev, &r, true)
	case LifecycleHermesPreTool:
		classifyHermesTool(&ev, &r, false)
		ev.ToolCallID = r.extraStr("tool_call_id")
	case LifecycleHermesPostTool:
		classifyHermesTool(&ev, &r, true)
		ev.ToolCallID = r.extraStr("tool_call_id")
	case LifecycleAssistant, LifecycleStop:
		// Generated Pi/Amp integrations and OpenClaw's authorized model callback
		// expose finalized assistant text. Retain only the bounded preview.
		ev.EventType = model.EventMessageAssistant
		if agent == AgentOpenClaw || agent == AgentPi || agent == AgentAmp {
			ev.ContentPreview = preview(r.envStr("assistant_text", "assistantText"))
		}
	case LifecyclePermission:
		mapPermission(&ev, &r)
	case LifecyclePermissionDenied:
		mapDeniedPermission(&ev, &r)
	case LifecycleCodexPermission:
		mapCodexPermission(&ev, &r)
	case LifecycleDevinPermission:
		mapDevinPermission(&ev, &r)
	case LifecycleHermesPermission:
		mapHermesPermission(&ev, &r)
	case LifecycleHermesPermissionResult:
		mapHermesPermissionResult(&ev, &r)
	case LifecycleSessionEnd:
		ev.EventType = model.EventSessionEnd
		ev.Actor = model.ActorSystem
		ev.SubAgent = r.subAgent()
	}
	if agent == AgentOpenClaw && (lc == LifecyclePromptSubmit || lc == LifecycleAssistant || lc == LifecycleStop) {
		switch r.envStr("boundary") {
		case "transport":
			ev.Tags = append(ev.Tags, openClawTagTransportBoundary)
		case "model":
			ev.Tags = append(ev.Tags, openClawTagModelBoundary)
		}
	}
	if ev.SubAgent == "" {
		ev.SubAgent = r.subAgent()
	}
	if ev.EventType == model.EventCommandResult || ev.EventType == model.EventToolResult {
		ev.Actor = model.ActorTool
	}
	if eventSupportsToolCallID(ev.EventType) && ev.ToolCallID == "" {
		ev.ToolCallID = r.toolCallID()
	}
	return ev
}

// MapEvents maps one hook payload. Structured multi-file operations produce one
// event per path so file evidence remains first-class.
func MapEvents(lc Lifecycle, agent, sourceAgent, eventID string, payload map[string]any) []model.Event {
	base := Map(lc, agent, sourceAgent, eventID, payload)
	if agent == AgentCodex && lc == LifecycleCodexPreTool && base.ToolName == "apply_patch" {
		return mapPatchEvents(base, eventID, firstString(newResolver(agent, payload).toolInput(), "command", "patch"))
	}
	if agent == AgentOpenCode && lc == LifecycleOpenCodePreTool && base.ToolName == "apply_patch" {
		return mapPatchEvents(base, eventID, firstString(newResolver(agent, payload).openCodeToolInput(), "patchText", "patch_text", "patch"))
	}
	if agent == AgentOpenClaw && lc == LifecyclePreTool && base.ToolName == "apply_patch" {
		input := newResolver(agent, payload).toolInput()
		patch := firstString(input, "input", "patch", "patchText", "patch_text")
		if len(applypatch.Parse(patch)) > 0 {
			return mapPatchEvents(base, eventID, patch)
		}
		paths, truncated := hookFilePaths(map[string]any{"paths": payload["derived_paths"]})
		if len(paths) > 0 {
			return mapFilePathEvents(base, eventID, paths, truncated)
		}
		if patch != "" {
			return mapPatchEvents(base, eventID, patch)
		}
	}
	if (agent == AgentCopilot || agent == AgentVSCode) &&
		(lc == LifecycleCopilotPreTool || lc == LifecycleVSCodePreTool) &&
		(base.EventType == model.EventFileRead || base.EventType == model.EventFileWrite) {
		paths, truncated := hookFilePaths(newResolver(agent, payload).toolInput())
		if len(paths) > 0 {
			return mapFilePathEvents(base, eventID, paths, truncated)
		}
	}
	return []model.Event{base}
}

func mapPatchEvents(base model.Event, eventID, patch string) []model.Event {
	changes := applypatch.Parse(patch)
	diffSHA, diffBytes := applypatch.Digest(patch)
	base.DiffSHA256, base.DiffBytes = diffSHA, diffBytes
	if len(changes) == 0 {
		return []model.Event{base}
	}

	events := make([]model.Event, 0, len(changes))
	for i, change := range changes {
		ev := base
		ev.Tags = append([]string(nil), base.Tags...)
		ev.FilePath = change.Path
		if change.Delete {
			ev.EventType = model.EventFileDelete
		} else {
			ev.EventType = model.EventFileWrite
		}
		if len(changes) > 1 {
			ev.EventID = fmt.Sprintf("%s-%d", eventID, i+1)
		}
		events = append(events, ev)
	}
	return events
}

const maxHookFileEvents = 1024

func hookFilePaths(input map[string]any) ([]string, bool) {
	seen := map[string]struct{}{}
	paths := make([]string, 0)
	add := func(path string) bool {
		path = strings.TrimSpace(path)
		if path == "" {
			return true
		}
		if _, ok := seen[path]; ok {
			return true
		}
		if len(paths) == maxHookFileEvents {
			return false
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
		return true
	}
	for _, key := range []string{"files", "paths"} {
		raw, ok := input[key]
		if !ok {
			continue
		}
		items, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			var path string
			switch v := item.(type) {
			case string:
				path = v
			case map[string]any:
				path = firstString(v, "path", "file_path", "filePath")
			}
			if !add(path) {
				return paths, true
			}
		}
	}
	return paths, false
}

func mapFilePathEvents(base model.Event, eventID string, paths []string, truncated bool) []model.Event {
	events := make([]model.Event, 0, len(paths))
	for i, path := range paths {
		ev := base
		ev.Tags = append([]string(nil), base.Tags...)
		ev.FilePath = path
		if truncated {
			ev.Tags = append(ev.Tags, "hook_paths_truncated")
		}
		if len(paths) > 1 {
			ev.EventID = fmt.Sprintf("%s-%d", eventID, i+1)
		}
		events = append(events, ev)
	}
	return events
}

func eventSupportsToolCallID(eventType model.EventType) bool {
	switch eventType {
	case model.EventToolCall, model.EventToolResult,
		model.EventCommandExec, model.EventCommandResult,
		model.EventFileRead, model.EventFileWrite, model.EventFileDelete,
		model.EventPermissionRequested, model.EventPermissionApproved, model.EventPermissionDenied,
		model.EventNetworkIndicator:
		return true
	default:
		return false
	}
}

func mapToolResult(ev *model.Event, name string) {
	ev.EventType = model.EventToolResult
	if server, tool, ok := splitMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
}

// mapMCPCall maps a direct MCP invocation (Cursor beforeMCPExecution) onto the
// tool vocabulary. The server and tool names arrive as first-class fields
// (server, tool_name) rather than the mcp__server__tool encoding the pre-tool
// classifier parses, so they are read directly. When the invocation carries a
// url it is a network egress and classifies as a network.indicator (carrying the
// url and the mcp split); otherwise it is a generic tool.call. The MCP command
// text, when present, is not stored: tool.call/network.indicator do not admit a
// command field, and the server/tool split already identifies the invocation.
func mapMCPCall(ev *model.Event, r *resolver) {
	server := r.str("server", "server_name", "mcp_server_name", "mcpServerName")
	tool := r.str("tool_name", "toolName", "tool", "name", "mcp_tool_name", "mcpToolName")
	if url := r.str("url", "endpoint"); url != "" {
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		ev.MCPServer, ev.MCPTool = server, tool
		return
	}
	eventName := strings.ToLower(r.hookEventName())
	if eventName == "" {
		eventName = strings.ToLower(r.envStr("agent_action_name"))
	}
	if strings.HasPrefix(eventName, "post") || strings.HasPrefix(eventName, "after") {
		ev.EventType = model.EventToolResult
	} else {
		ev.EventType = model.EventToolCall
	}
	ev.ToolName = tool
	ev.MCPServer, ev.MCPTool = server, tool
}

// copilotToolFamily classifies a GitHub Copilot CLI tool name into one of the
// activity families numbat reasons about. Copilot names its built-in tools
// differently from Claude (ShellCommand/ReadFile/WriteFile/WebFetch, with
// snake_case and Claude-style aliases also seen in the wild), so the names are
// matched here rather than reusing the Claude classifier's vocabulary. An
// unrecognized name yields "" so the caller falls back to the generic tool
// vocabulary (and the MCP split when the name looks like an MCP tool).
func copilotToolFamily(name string) string {
	switch strings.ToLower(name) {
	case "bash", "powershell", "shellcommand", "shell_command", "run_shell_command",
		"runcommand", "run_command", "runterminalcommand", "run_terminal_command", "terminal":
		return "shell"
	case "view", "read", "readfile", "read_file", "readfiles", "read_files":
		return "read"
	case "create", "edit", "write", "writefile", "write_file", "editfile", "edit_file",
		"createfile", "create_file", "editfiles", "edit_files", "replace_string_in_file",
		"apply_patch", "copilot_insertedit", "copilot_createfile", "copilot_applypatch":
		return "write"
	case "webfetch", "web_fetch", "websearch", "web_search", "fetch", "fetchurl", "fetch_url":
		return "web"
	default:
		return ""
	}
}

// classifyCopilotTool maps pre-tool actions and post-tool results. Only a shell
// result carries command metadata; all other post moments are tool.result.
func classifyCopilotTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	ev.ToolName = name
	family := copilotToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.toolErrored() || strings.EqualFold(r.hookEventName(), "PostToolUseFailure") {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	input := r.copilotToolArgs()
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd")
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			if code, ok := r.exitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.durationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "read":
		// file.read names the path only — read content is never stored.
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "path", "filePath", "file_path")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "path", "filePath", "file_path")
		// Copilot nests edits inside the decoded toolArgs object, so the digest is
		// read from input (not the top-level payload as Cursor does).
		if sha, n, ok := editsDiffFrom(input); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case "web":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		if url != "" {
			ev.ContentPreview = preview(url)
		} else {
			ev.ContentPreview = preview(firstString(input, "query"))
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if post && (r.toolErrored() || strings.EqualFold(r.hookEventName(), "PostToolUseFailure")) {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// vscodeToolFamily classifies VS Code Copilot Chat / Agent Mode preview-hook
// tool names into the activity families numbat reasons about. The set is
// intentionally small and explicit: if a tool name is not one of the observed
// VS Code/Copilot spellings below, numbat emits a generic tool.call/result
// rather than guessing from a fuzzy substring.
func vscodeToolFamily(name string) string {
	return copilotToolFamily(name)
}

// classifyVSCodeTool maps VS Code Copilot Chat / Agent Mode preview-hook tool
// moments onto numbat's event vocabulary. VS Code payloads are close to the
// generic hook shape (tool_name/toolName plus tool_input/toolInput/input), so
// the shared strict accessors are enough: values are read only from structured
// fields, never inferred from prose. Unknown tools fall back to tool.call/result
// while preserving the tool name and MCP split if the name is mcp__server__tool.
func classifyVSCodeTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	ev.ToolName = name
	family := vscodeToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.toolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	input := r.toolInput()
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd", "commandLine", "command_line")
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			if code, ok := r.exitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.durationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
		if sha, n, ok := editsDiffFrom(input); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		} else if sha, n, ok := r.diff(); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case "web":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		if url != "" {
			ev.ContentPreview = preview(url)
		} else {
			ev.ContentPreview = preview(firstString(input, "query"))
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if post && r.toolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// classifyCursorTool maps Cursor's generic preToolUse, postToolUse, and
// postToolUseFailure payloads. New installs use these generic events instead of
// the overlapping specialized shell/MCP/file callbacks, so one tool invocation
// produces one pre event and exactly one success-or-failure event.
func classifyCursorTool(ev *model.Event, r *resolver, post, failed bool) {
	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name

	if post {
		if strings.EqualFold(name, "Shell") {
			ev.EventType = model.EventCommandResult
			ev.Command = firstString(input, "command", "command_line", "commandLine")
			if code, ok := r.cursorExitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.cursorDurationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventToolResult
			if tool, ok := splitCursorMCPName(name); ok {
				ev.MCPTool = tool
			}
		}
		if failed || r.cursorToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		if strings.EqualFold(r.cursorFailureType(), "permission_denied") {
			ev.Decision = model.DecisionDenied
		}
		return
	}

	switch strings.ToLower(name) {
	case "shell":
		ev.EventType = model.EventCommandExec
		ev.Command = firstString(input, "command", "command_line", "commandLine")
	case "read", "readfile", "grep":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
	case "write", "edit", "strreplace":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
		if sha, n, ok := editsDiffFrom(input); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case "delete":
		ev.EventType = model.EventFileDelete
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
	case "task":
		ev.EventType = model.EventToolCall
		ev.SubAgent = firstString(input, "subagent_type", "subagentType", "agent", "agent_type", "agentType")
	case "webfetch", "web_fetch":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "websearch", "web_search":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		tool, isMCP := splitCursorMCPName(name)
		if isMCP {
			if url := firstString(input, "url", "uri", "endpoint"); url != "" {
				ev.EventType = model.EventNetworkIndicator
				ev.URL = hookNetworkTargetURL(url)
				ev.ContentPreview = preview(url)
				ev.Tags = append(ev.Tags, model.TagNetwork)
			} else {
				ev.EventType = model.EventToolCall
			}
			ev.MCPTool = tool
		} else {
			ev.EventType = model.EventToolCall
		}
	}
}

// splitCursorMCPName recognizes Cursor's documented MCP:<tool_name> generic
// hook spelling. Cursor does not provide a separate server field on this
// surface, so numbat retains the reported tool without inventing a server.
func splitCursorMCPName(name string) (string, bool) {
	const prefix = "MCP:"
	if len(name) <= len(prefix) || !strings.EqualFold(name[:len(prefix)], prefix) {
		return "", false
	}
	tool := strings.TrimSpace(name[len(prefix):])
	return tool, tool != ""
}

// codexToolFamily classifies a Codex tool name into one of the activity
// families numbat reasons about. Codex surfaces use Bash, shell, shell_command,
// or exec_command for shell execution. File edits arrive as the
// "apply_patch" unified-diff envelope plus the explicit read_file/create_file/
// edit_file tools, and web egress is "web_search_call". This vocabulary is the
// same artifact-backed set the Codex at-rest extractor classifies on, so a hook
// event and a transcript entry for the same tool classify identically. An
// unrecognized name yields "" so the caller falls back to the generic tool
// vocabulary (and the MCP split when the name looks like an MCP tool) — the same
// narrow, no-generic-aliases approach as Copilot.
func codexToolFamily(name string) string {
	switch strings.ToLower(name) {
	case "shell", "shell_command", "exec_command", "bash", "powershell":
		return "shell"
	case "apply_patch":
		return "patch"
	case "read_file":
		return "read"
	case "create_file", "edit_file":
		return "write"
	case "web_search_call":
		return "web"
	default:
		return ""
	}
}

// classifyCodexTool maps pre-tool actions and post-tool results. MapEvents
// expands an apply_patch request into one event per file; patch text is hashed
// but never retained.
func classifyCodexTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	ev.ToolName = name
	family := codexToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.toolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	input := r.toolInput()
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd")
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			if code, ok := r.exitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.durationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "patch":
		ev.EventType = model.EventFileWrite
		patch := firstString(input, "command", "patch")
		if changes := applypatch.Parse(patch); len(changes) > 0 {
			ev.FilePath = changes[0].Path
			if changes[0].Delete {
				ev.EventType = model.EventFileDelete
			}
		} else {
			ev.FilePath = firstString(input, "path", "file_path", "filePath")
		}
		ev.DiffSHA256, ev.DiffBytes = applypatch.Digest(patch)
		ev.Tags = append(ev.Tags, codexTagPatchRequested)
	case "read":
		// file.read names the path only — read content is never stored.
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "path", "file_path", "filePath")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "path", "file_path", "filePath")
		if sha, n, ok := r.diff(); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case "web":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		if url != "" {
			ev.ContentPreview = preview(url)
		} else {
			ev.ContentPreview = preview(firstString(input, "query"))
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if post && r.toolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// geminiToolFamily classifies a Gemini CLI tool name into one of the activity
// families numbat reasons about. Gemini names its built-in tools differently from
// Claude/Codex/Copilot: the shell tool is "run_shell_command", file reads are
// "read_file", file writes are "write_file" and the edit tool's name is "replace",
// and web egress is "web_fetch" / "google_web_search". This vocabulary is the same
// artifact-backed set the Gemini at-rest extractor classifies on (see
// internal/extract/gemini_entry.go), so a BeforeTool/AfterTool hook event and a
// transcript entry for the same tool classify identically. An unrecognized name
// yields "" so the caller falls back to the generic tool vocabulary (and the MCP
// split when the name looks like an MCP tool) — the same narrow,
// no-generic-aliases approach as Codex and Copilot.
func geminiToolFamily(name string) string {
	switch name {
	case "run_shell_command":
		return "shell"
	case "read_file":
		return "read"
	case "write_file", "replace":
		return "write"
	case "web_fetch", "google_web_search":
		return "web"
	default:
		return ""
	}
}

// classifyGeminiTool reads Gemini's documented tool_input/tool_response shape.
// It maps pre-tool actions, shell results, and generic non-shell results without
// inferring status or URLs from prose.
func classifyGeminiTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	ev.ToolName = name
	if ctx := r.geminiMCPContext(); ctx != nil {
		mapGeminiMCP(ev, ctx, post)
		if post && r.geminiToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	family := geminiToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.geminiToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	input := r.geminiToolInput()
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd")
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			if code, ok := r.geminiExitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.geminiDurationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "read":
		// file.read names the path only — read content is never stored.
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "file_path", "path", "filePath")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "path", "filePath")
		if sha, n, ok := r.geminiDiff(); ok {
			ev.DiffSHA256, ev.DiffBytes = sha, n
		}
	case "web":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		if url != "" {
			ev.ContentPreview = preview(url)
		} else {
			// web_fetch carries the URL inside the free-text "prompt" arg;
			// google_web_search carries a "query". Either is the preview when no
			// explicit url field is present — no URL is fabricated from the free text.
			ev.ContentPreview = preview(firstString(input, "prompt", "query"))
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	if post && r.geminiToolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func mapGeminiMCP(ev *model.Event, ctx map[string]any, post bool) {
	ev.MCPServer = firstString(ctx, "server_name")
	ev.MCPTool = firstString(ctx, "tool_name")
	if ev.ToolName == "" {
		ev.ToolName = ev.MCPTool
	}
	if post {
		ev.EventType = model.EventToolResult
		return
	}
	if rawURL := firstString(ctx, "url"); rawURL != "" {
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(rawURL)
		ev.ContentPreview = preview(rawURL)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		return
	}
	ev.EventType = model.EventToolCall
}

// openCodeToolFamily classifies an OpenCode built-in tool id into one of the
// activity families numbat reasons about. OpenCode names its built-in tools with
// short lowercase ids: the shell tool is "bash" (shell.ts ShellID.ToolID="bash"),
// file reads are "read", file writes are "write"/"edit", a structured multi-file
// edit is "apply_patch", and web egress is "webfetch"/"websearch". This vocabulary
// is the same artifact-backed set the OpenCode at-rest extractor classifies on,
// so a live tool.execute.before/after hook event and a storage record for the same
// tool classify identically. An unrecognized id yields "" so the caller falls back to
// the generic tool vocabulary (and the MCP split when the name looks like an MCP
// tool) — the same narrow, no-generic-aliases approach as Codex/Copilot/Gemini.
func openCodeToolFamily(name string) string {
	switch name {
	case "bash":
		return "shell"
	case "read":
		return "read"
	case "write", "edit":
		return "write"
	case "apply_patch":
		return "patch"
	case "fetch", "webfetch":
		return "fetch"
	case "search", "websearch", "code":
		return "search"
	default:
		return ""
	}
}

// classifyOpenCodeHookTool maps the plugin's before/after payload. Pre moments
// use OpenCode's exact tool vocabulary; non-shell after moments are tool.result.
func classifyOpenCodeHookTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	ev.ToolName = name
	family := openCodeToolFamily(name)
	input := r.openCodeToolInput()
	if name == "task" {
		ev.SubAgent = firstString(input, "subagent_type", "agent", "agent_type")
	}
	if post && family != "shell" {
		mapToolResult(ev, name)
		return
	}
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd")
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			// Exit code is read STRICTLY from OpenCode's structured post-tool metadata
			// (the bash tool's camelCase `exitCode`), never inferred. OpenCode's live
			// after-event reports NO wall-clock duration field, so DurationMs is left
			// unset — a documented gap, not a fabricated value.
			if code, ok := r.openCodeExitCode(); ok {
				ev.ExitCode = &code
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "read":
		// file.read names the path only — read content is never stored.
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "filePath", "file_path", "path")
	case "write":
		// OpenCode's live write/edit after-event carries no structured diff digest in
		// its metadata, so file.write records the path only — numbat never hashes the
		// edit body at the hook boundary (a documented gap, not a fabricated digest).
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "filePath", "file_path", "path")
	case "patch":
		// MapEvents expands patchText into per-file operations and a diff digest.
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "filePath", "file_path", "path")
	case "fetch":
		ev.EventType = model.EventNetworkIndicator
		raw := firstString(input, "url")
		if httpURL := hookNetworkTargetURL(raw); httpURL != "" {
			ev.URL = httpURL
		} else if raw != "" {
			ev.ContentPreview = preview(raw)
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "search":
		// A web search performs outbound discovery but fetches no single url; the
		// query is the lead, and no url is fabricated.
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
	// No tool_error tag for OpenCode live events. Unlike the at-rest parser (which
	// reads state.status=="error"), OpenCode's tool.execute.after hook fires AFTER
	// item.execute SUCCEEDS — a tool FAILURE raises an Effect ToolFailure and the
	// after-hook may not fire at all — so there is NO reliable structured "errored"
	// boolean on the live after-event. High precision: a documented false negative
	// beats a fabricated false positive, and prose-scraping the output string is
	// forbidden. A non-zero exitCode is still surfaced as the exit-code value above,
	// but a non-zero exit alone is not a tool error.
}

// classifyAntigravityTool maps the documented toolCall object. PostToolUse only
// reports stepIdx and error, so result events intentionally carry no tool name.
func classifyAntigravityTool(ev *model.Event, r *resolver, post bool) {
	if post {
		ev.EventType = model.EventToolResult
		if r.envStr("error") != "" {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}

	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name
	switch name {
	case "run_command":
		ev.EventType = model.EventCommandExec
		ev.Command = firstString(input, "CommandLine", "command")
	case "view_file":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "AbsolutePath", "path")
	case "list_dir":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "DirectoryPath", "path")
	case "find_by_name":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "SearchDirectory", "path")
	case "grep_search":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "SearchPath", "path")
	case "write_to_file", "replace_file_content", "multi_replace_file_content":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "TargetFile", "path")
	case "search_web":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "read_url_content":
		rawURL := firstString(input, "Url", "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(rawURL)
		ev.ContentPreview = preview(rawURL)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "invoke_subagent":
		ev.EventType = model.EventToolCall
		if specs, ok := input["Subagents"].([]any); ok && len(specs) > 0 {
			if spec, ok := specs[0].(map[string]any); ok {
				ev.SubAgent = firstString(spec, "Role", "TypeName")
			}
		}
	case "define_subagent":
		ev.EventType = model.EventToolCall
		ev.SubAgent = firstString(input, "name")
	default:
		ev.EventType = model.EventToolCall
	}
	if server, tool, ok := splitMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
}

// classifyFactoryTool maps Factory's documented tool names and structured
// tool_input without inferring undocumented result metadata.
func classifyFactoryTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name
	if post {
		if name == "Execute" {
			ev.EventType = model.EventCommandResult
			ev.Command = firstString(input, "command", "cmd")
		} else {
			mapToolResult(ev, name)
		}
		if r.factoryToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
	} else {
		switch name {
		case "Execute":
			ev.EventType = model.EventCommandExec
			ev.Command = firstString(input, "command", "cmd")
		case "Read":
			ev.EventType = model.EventFileRead
			ev.FilePath = firstString(input, "file_path", "path")
		case "Edit", "Create", "ApplyPatch":
			ev.EventType = model.EventFileWrite
			ev.FilePath = firstString(input, "file_path", "path")
		case "FetchUrl":
			url := firstString(input, "url")
			ev.EventType = model.EventNetworkIndicator
			ev.URL = hookNetworkTargetURL(url)
			ev.ContentPreview = preview(url)
			ev.Tags = append(ev.Tags, model.TagNetwork)
		case "WebSearch":
			ev.EventType = model.EventNetworkIndicator
			ev.ContentPreview = preview(firstString(input, "query"))
			ev.Tags = append(ev.Tags, model.TagNetwork)
		default:
			ev.EventType = model.EventToolCall
		}
	}
	if server, tool, ok := splitMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
}

// classifyGrokTool recognizes Grok's documented Claude-compatible tool names.
// Unknown tools remain generic, and result metadata is not inferred from fields
// outside Grok's public hook contract.
func classifyGrokTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name
	if post {
		if name == "Bash" {
			ev.EventType = model.EventCommandResult
			ev.Command = firstString(input, "command")
		} else {
			ev.EventType = model.EventToolResult
		}
	} else {
		classifyTool(ev, name, input)
	}
	if server, tool, ok := splitGrokMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
	if post && strings.EqualFold(r.hookEventName(), "PostToolUseFailure") {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func devinToolFamily(name string) string {
	switch name {
	case "exec":
		return "shell"
	case "read":
		return "read"
	case "edit":
		return "write"
	default:
		return ""
	}
}

// classifyDevinTool uses Devin CLI's documented public tool names and payload.
func classifyDevinTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name
	family := devinToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.devinToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	switch family {
	case "shell":
		ev.Command = firstString(input, "command")
		if post {
			ev.EventType = model.EventCommandResult
		} else {
			ev.EventType = model.EventCommandExec
		}
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "path", "file_path")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "path", "file_path")
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
	}
	if server, tool, ok := splitMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
	if post && r.devinToolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func hermesToolFamily(name string) string {
	switch name {
	case "terminal":
		return "shell"
	case "read_file":
		return "read"
	case "write_file", "patch":
		return "write"
	case "web_search":
		return "search"
	case "web_extract":
		return "fetch"
	default:
		return ""
	}
}

// classifyHermesTool uses Hermes's documented tool payload and exact public
// tool names. Unknown tools remain generic tool.call/tool.result events.
func classifyHermesTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	input := r.toolInput()
	ev.ToolName = name
	family := hermesToolFamily(name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.hermesToolErrored() {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	switch family {
	case "shell":
		ev.Command = firstString(input, "command")
		if post {
			ev.EventType = model.EventCommandResult
			if ms, ok := r.hermesDurationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
		}
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "path", "file_path")
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "path", "file_path")
	case "search":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "fetch":
		raw := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(raw)
		ev.ContentPreview = preview(raw)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
	}
	if server, tool, ok := splitMCPName(name); ok {
		ev.MCPServer, ev.MCPTool = server, tool
	}
	if post && r.hermesToolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// hookNetworkTargetURL returns raw iff it parses as an absolute http:// or
// https:// URL with a host, else "". It is the live-hook twin of the at-rest
// networkTargetURL helper (internal/extract/extract.go): a network.indicator's
// URL must be a real egress target, so a webfetch arg carrying file://,
// javascript:, data:, a relative path, or junk is rejected here rather than
// promoted into Event.URL. The two are kept as separate small helpers — rather
// than exporting one — so the hook package stays free of an extract import (the
// same boundary discipline mcpFetchToolName/splitMCPName encode). The returned
// value is the trimmed original, not a re-serialized form.
func hookNetworkTargetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Hostname() == "" {
		return ""
	}
	return raw
}

// classifyTool maps a pre-tool invocation onto numbat's event vocabulary using
// the same tool-name rules the Claude artifact extractor applies, so a Bash
// pre-tool hook and a Bash transcript entry classify identically. Unknown tools
// fall back to the generic tool.call.
func classifyTool(ev *model.Event, name string, input map[string]any) {
	ev.ToolName = name
	switch name {
	case "Bash":
		ev.EventType = model.EventCommandExec
		ev.Command = firstString(input, "command")
	case "Read", "NotebookRead":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "file_path", "notebook_path", "path")
	case "Write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "path")
	case "Edit", "MultiEdit", "NotebookEdit", "Update":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "notebook_path", "path")
	case "WebFetch":
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case "WebSearch":
		ev.EventType = model.EventNetworkIndicator
		ev.ContentPreview = preview(firstString(input, "query"))
		ev.Tags = append(ev.Tags, model.TagNetwork)
	case mcpFetchToolName:
		url := firstString(input, "url")
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(url)
		ev.ContentPreview = preview(url)
		ev.Tags = append(ev.Tags, model.TagNetwork)
		ev.MCPServer, ev.MCPTool = "fetch", "fetch"
	default:
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		}
	}
}

// portableToolFamily maps the documented built-in tool names for hook-only or
// newly hook-enabled agents. Names are exact and agent-scoped: unknown tools
// stay generic instead of being guessed from substrings.
func portableToolFamily(agent, name string) string {
	lower := strings.ToLower(name)
	switch agent {
	case AgentPi:
		switch lower {
		case "bash":
			return "shell"
		case "read", "grep", "find", "ls":
			return "read"
		case "write", "edit":
			return "write"
		}
	case AgentKimi, AgentQwen:
		return copilotToolFamily(name)
	case AgentCline:
		switch lower {
		case "execute_command", "bash", "shell":
			return "shell"
		case "read_file", "list_files", "search_files", "list_code_definition_names":
			return "read"
		case "write_to_file", "replace_in_file", "apply_diff", "edit_file":
			return "write"
		case "browser_action", "web_fetch", "web_search":
			return "web"
		}
	case AgentAmp:
		switch lower {
		case "bash", "shell_command":
			return "shell"
		case "read", "finder", "grep", "glob":
			return "read"
		case "create_file", "edit_file", "apply_patch", "undo_edit":
			return "write"
		case "read_web_page", "web_search":
			return "web"
		}
	case AgentAuggie:
		switch lower {
		case "launch-process":
			return "shell"
		case "view", "codebase-retrieval":
			return "read"
		case "str-replace-editor", "save-file", "remove-files":
			return "write"
		case "web-fetch", "web-search", "github-api", "linear":
			return "web"
		}
	case AgentKiro:
		switch lower {
		case "execute_bash", "shell":
			return "shell"
		case "fs_read", "read":
			return "read"
		case "fs_write", "write", "str_replace":
			return "write"
		}
	case AgentGoose:
		switch lower {
		case "developer__shell", "shell":
			return "shell"
		case "developer__tree", "developer__read_image":
			return "read"
		case "developer__write", "developer__edit":
			return "write"
		}
	case AgentKilo:
		switch lower {
		case "bash":
			return "shell"
		case "read", "glob", "grep":
			return "read"
		case "edit", "write", "apply_patch":
			return "write"
		case "webfetch", "websearch":
			return "web"
		}
	case AgentOpenClaw:
		switch lower {
		case "exec":
			return "shell"
		case "read":
			return "read"
		case "write", "edit", "apply_patch":
			return "write"
		case "web_fetch", "web_search", "browser":
			return "web"
		}
	case AgentOpenHands:
		if lower == "terminal" {
			return "shell"
		}
	case AgentCrush:
		switch lower {
		case "bash":
			return "shell"
		case "view", "ls", "glob", "grep":
			return "read"
		case "write", "edit", "multiedit":
			return "write"
		case "fetch", "web_fetch", "web_search", "sourcegraph", "download":
			return "web"
		}
	}
	return ""
}

func classifyPortableTool(ev *model.Event, r *resolver, post bool) {
	name := r.toolName()
	switch r.agent {
	case AgentOpenClaw, AgentPi, AgentKimi, AgentQwen, AgentCline, AgentAmp, AgentAuggie, AgentKiro, AgentGoose, AgentKilo, AgentOpenHands, AgentCrush:
		// Continue with the agent-scoped portable vocabulary below.
	default:
		if post {
			mapPostTool(ev, r)
		} else {
			classifyTool(ev, name, r.toolInput())
		}
		return
	}
	ev.ToolName = name
	input := r.toolInput()
	// OpenClaw's outer code-mode tool intentionally reuses the name "exec" for
	// JavaScript/TypeScript input. It is not a shell command, so retain it as a
	// generic tool call instead of fabricating command telemetry. Stable
	// before_tool_call supplies the authoritative toolKind; after_tool_call does
	// not, so the persisted code/language shape is the structured fallback.
	_, hasCode := input["code"]
	_, hasLanguage := input["language"]
	if r.agent == AgentOpenClaw && (r.envStr("tool_kind", "toolKind") == "code_mode_exec" ||
		(strings.EqualFold(name, "exec") && (hasCode || hasLanguage))) {
		if post {
			mapToolResult(ev, name)
			if r.toolErrored() {
				ev.Tags = append(ev.Tags, model.TagToolError)
			}
		} else {
			ev.EventType = model.EventToolCall
		}
		return
	}
	family := portableToolFamily(r.agent, name)
	if post && family != "shell" {
		mapToolResult(ev, name)
		if r.toolErrored() || strings.EqualFold(r.hookEventName(), "PostToolUseFailure") {
			ev.Tags = append(ev.Tags, model.TagToolError)
		}
		return
	}
	switch family {
	case "shell":
		cmd := firstString(input, "command", "cmd", "command_line", "commandLine")
		if r.agent == AgentOpenClaw && cmd == "" {
			if post {
				mapToolResult(ev, name)
				if r.toolErrored() {
					ev.Tags = append(ev.Tags, model.TagToolError)
				}
			} else {
				ev.EventType = model.EventToolCall
			}
			return
		}
		if post {
			ev.EventType = model.EventCommandResult
			ev.Command = cmd
			if code, ok := r.exitCode(); ok {
				ev.ExitCode = &code
			}
			if ms, ok := r.durationMs(); ok {
				ev.DurationMs = &ms
			}
		} else {
			ev.EventType = model.EventCommandExec
			ev.Command = cmd
		}
	case "read":
		ev.EventType = model.EventFileRead
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
		if ev.FilePath == "" && r.agent == AgentKiro {
			ev.FilePath = firstOperationPath(input)
		}
	case "write":
		ev.EventType = model.EventFileWrite
		ev.FilePath = firstString(input, "file_path", "filePath", "path")
		if ev.FilePath == "" && r.agent == AgentKiro {
			ev.FilePath = firstOperationPath(input)
		}
		if r.agent == AgentAuggie && strings.EqualFold(name, "remove-files") {
			ev.EventType = model.EventFileDelete
		}
	case "web":
		rawURL := firstString(input, "url", "uri", "targetUrl", "target_url")
		query := firstString(input, "query")
		if r.agent == AgentOpenClaw && strings.EqualFold(name, "browser") && rawURL == "" && query == "" {
			ev.EventType = model.EventToolCall
			return
		}
		ev.EventType = model.EventNetworkIndicator
		ev.URL = hookNetworkTargetURL(rawURL)
		if rawURL != "" {
			ev.ContentPreview = preview(rawURL)
		} else {
			ev.ContentPreview = preview(query)
		}
		ev.Tags = append(ev.Tags, model.TagNetwork)
	default:
		if post {
			ev.EventType = model.EventToolResult
		} else {
			ev.EventType = model.EventToolCall
		}
		if server, tool, ok := splitMCPName(name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if r.agent == AgentKiro && strings.HasPrefix(name, "@") {
			parts := strings.SplitN(strings.TrimPrefix(name, "@"), "/", 2)
			ev.MCPServer = parts[0]
			if len(parts) == 2 {
				ev.MCPTool = parts[1]
			}
		} else if strings.HasPrefix(name, "mcp:") {
			ev.MCPTool = strings.TrimPrefix(name, "mcp:")
		}
	}
	if post && r.toolErrored() {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

func firstOperationPath(input map[string]any) string {
	operations, _ := input["operations"].([]any)
	for _, raw := range operations {
		operation, _ := raw.(map[string]any)
		if path := firstString(operation, "path", "file_path", "filePath"); path != "" {
			return path
		}
	}
	return ""
}

// mapPostTool maps a completed invocation to command.result or tool.result.
func mapPostTool(ev *model.Event, r *resolver) {
	name := r.toolName()
	ev.ToolName = name
	input := r.toolInput()
	if name == "Bash" {
		ev.EventType = model.EventCommandResult
		ev.Command = firstString(input, "command")
		if code, ok := r.exitCode(); ok {
			ev.ExitCode = &code
		}
		if ms, ok := r.durationMs(); ok {
			ev.DurationMs = &ms
		}
	} else {
		mapToolResult(ev, name)
	}
	if r.toolErrored() || strings.EqualFold(r.hookEventName(), "PostToolUseFailure") {
		ev.Tags = append(ev.Tags, model.TagToolError)
	}
}

// mapPermission maps a permission gate onto the permission.* vocabulary. The
// outcome is read from the payload's decision when present: allowed/denied route
// to the matching event, and an absent or "ask"/"requested" decision is an open
// request. The approval_* fields record the gate explicitly.
func mapPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	decision := r.decision()
	switch decision {
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
	ev.ApprovalReason = r.str("reason", "permission_reason")
}

// mapDeniedPermission records a hook event that is already a denial, such as
// Claude Code PermissionDenied.
func mapDeniedPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	ev.EventType = model.EventPermissionDenied
	ev.Decision = model.DecisionDenied
	ev.ApprovalDecision = model.DecisionDenied
	ev.ApprovalReason = r.str("reason", "permission_reason")
}

// mapCodexPermission maps Codex's PermissionRequest moment onto permission.requested
// only. Codex runs this hook before the normal approval prompt; any allow/deny is a
// hook output decision, not evidence present in the input payload. The request
// reason, when Codex has one, lives at tool_input.description.
func mapCodexPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	ev.EventType = model.EventPermissionRequested
	ev.Decision = model.DecisionAsked
	ev.ApprovalDecision = model.DecisionAsked
	ev.ApprovalReason = firstString(r.toolInput(), "description")
}

// mapCopilotPermission records the open request; the hook output, not its
// input, determines whether Copilot allows or denies the tool.
func mapCopilotPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	ev.EventType = model.EventPermissionRequested
	ev.Decision = model.DecisionAsked
	ev.ApprovalDecision = model.DecisionAsked
}

// mapDevinPermission records Devin's PermissionRequest as requested-only. The
// allow/deny decision is hook output, not stdin input, so numbat does not read
// generic verdict keys or synthesize approval reasons.
func mapDevinPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	ev.EventType = model.EventPermissionRequested
	ev.Decision = model.DecisionAsked
	ev.ApprovalDecision = model.DecisionAsked
}

// mapHermesPermission records Hermes's pre-decision approval request.
func mapHermesPermission(ev *model.Event, r *resolver) {
	ev.ToolName = r.toolName()
	required := true
	ev.ApprovalRequired = &required
	ev.EventType = model.EventPermissionRequested
	ev.Decision = model.DecisionAsked
	ev.ApprovalDecision = model.DecisionAsked
	ev.ApprovalReason = r.extraStr("description")
}

// mapHermesPermissionResult records Hermes's documented final approval choice.
func mapHermesPermissionResult(ev *model.Event, r *resolver) {
	required := true
	ev.ApprovalRequired = &required
	ev.ApprovalReason = r.extraStr("description")
	switch strings.ToLower(r.extraStr("choice")) {
	case "once", "session", "always", "smart_approve":
		ev.EventType = model.EventPermissionApproved
		ev.Decision = model.DecisionAllowed
		ev.ApprovalDecision = model.DecisionAllowed
	case "deny", "timeout", "smart_deny":
		ev.EventType = model.EventPermissionDenied
		ev.Decision = model.DecisionDenied
		ev.ApprovalDecision = model.DecisionDenied
	default:
		ev.EventType = model.EventPermissionRequested
		ev.Decision = model.DecisionAsked
		ev.ApprovalDecision = model.DecisionAsked
	}
}

// promptWithAttachments appends any attached file paths to the prompt text so a
// prompt-submit preview reflects the files the user pulled into context, without
// a dedicated attachment field. An empty attachment list returns the prompt
// unchanged.
func promptWithAttachments(prompt string, paths []string) string {
	if len(paths) == 0 {
		return prompt
	}
	return prompt + " [attachments: " + strings.Join(paths, " ") + "]"
}

// previewMax bounds a retained excerpt, in runes, matching the extractor.
const previewMax = model.ContentPreviewMaxRunes

func preview(s string) string {
	return model.NormalizeContentPreview(s)
}

// mcpFetchToolName and the mcp__ split mirror the extractor's shared constants;
// they are duplicated here (a handful of lines) rather than exported from
// extract so the parser package stays a pure-artifact boundary with no live-hook
// coupling.
const (
	mcpFetchToolName = "mcp__fetch__fetch"
	mcpNamePrefix    = "mcp__"
)

func splitMCPName(name string) (server, tool string, ok bool) {
	if !strings.HasPrefix(name, mcpNamePrefix) {
		return "", "", false
	}
	rest := name[len(mcpNamePrefix):]
	i := strings.Index(rest, "__")
	if i <= 0 || i+2 >= len(rest) {
		return "", "", false
	}
	return rest[:i], rest[i+2:], true
}

// Grok exposes MCP tools as <server>__<tool>; its Claude-compatibility layer can
// also surface the mcp__<server>__<tool> spelling.
func splitGrokMCPName(name string) (server, tool string, ok bool) {
	if server, tool, ok := splitMCPName(name); ok {
		return server, tool, true
	}
	i := strings.Index(name, "__")
	if i <= 0 || i+2 >= len(name) {
		return "", "", false
	}
	return name[:i], name[i+2:], true
}
