package extract

import (
	"encoding/json"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// Codex-flavor mapping for OpenClaw transcripts. OpenClaw embeds Codex as one of
// its harnesses; when a Codex harness writes into the ~/.openclaw/agents tree it
// persists the Codex rollout wire format (outer {timestamp,type,payload} rows,
// response_item payloads), NOT the Anthropic ContentBlock shape. This path
// decodes that format with full fidelity, reusing the Codex wire helpers
// (codex_entry.go) so the two extractors stay in lockstep on the on-disk shape.
//
// The mapping follows the native Codex extractor: explicit lifecycle records
// identify human prompts, response_item carries assistant/tool activity, and
// structured event_msg outcomes enrich correlated results.

// mapCodexLine dispatches an embedded Codex rollout row while retaining
// OpenClaw's identity and event IDs.
func (e OpenClawExtractor) mapCodexLine(res *Result, src Source, sha string, st *openClawState, line int, raw []byte) {
	var lineRec codexLine
	if err := json.Unmarshal(raw, &lineRec); err != nil {
		res.diag(src.Path, line, "malformed JSON line")
		return
	}
	if st.pendingCodexResponsePrompt != nil && !codexUserPromptContinuation(lineRec) {
		st.pendingCodexResponsePrompt = nil
	}
	// Codex rollout rows carry their timestamp on the outer envelope. Reset it
	// for every row so a legacy/malformed row cannot inherit its predecessor.
	st.currentTimestamp = lineRec.Timestamp
	switch lineRec.Type {
	case openClawTypeSessionMeta:
		st.recognizedRows++
		st.codexMetaSeen = true
		var meta codexSessionMeta
		if json.Unmarshal(lineRec.Payload, &meta) == nil {
			if st.sessionID == "" {
				st.sessionID = meta.ID
			}
			if st.projectPath == "" {
				st.projectPath = meta.Cwd
			}
		}
	case openClawTypeTurnContext:
		st.recognizedRows++
		var tc codexTurnContext
		if json.Unmarshal(lineRec.Payload, &tc) == nil && tc.Cwd != "" {
			st.projectPath = tc.Cwd
		}
	case openClawTypeResponseItem:
		st.recognizedRows++
		e.mapCodexResponseItem(res, src, sha, st, line, lineRec.Payload)
	case openClawTypeEventMsg:
		// Most event_msg types duplicate a response_item record and are skipped, but
		// a few carry forensic signal with NO response_item twin: the structured MCP
		// tool-error and the no-twin state transitions. mapCodexEventMsg mirrors the
		// canonical Codex extractor (codex.go mapEventMsg) so an embedded-Codex
		// OpenClaw transcript does not silently drop those signals.
		st.recognizedRows++
		e.mapCodexEventMsg(res, src, sha, st, line, lineRec.Payload)
	case codexTypeCompacted:
		// A history-compaction summary, not agent activity. Treat it as a
		// recognized no-op, matching codex.go.
		st.recognizedRows++
	case "":
		res.diag(src.Path, line, "openclaw codex entry missing type")
	default:
		// A future/unknown Codex outer type: surface the gap rather than dropping it.
		res.diag(src.Path, line, "openclaw codex entry type is not modeled")
	}
}

// mapCodexResponseItem decodes a Codex response_item payload and emits an event
// for the variant. The mapping mirrors the Codex extractor (codex.go
// mapResponseItem) but routes through OpenClaw's event id/state so call↔result
// correlation and the tool-activity counter stay consistent with the native
// path. Reasoning/prose are emitted as message events (no preview beyond the
// prose norm); unknown variants are skipped quietly so a format addition is not
// flagged as corruption.
func (e OpenClawExtractor) mapCodexResponseItem(res *Result, src Source, sha string, st *openClawState, line int, payload json.RawMessage) {
	var ri codexResponseItem
	if err := json.Unmarshal(payload, &ri); err != nil {
		res.diag(src.Path, line, "malformed response_item payload")
		return
	}
	switch ri.Type {
	case codexRIMessage:
		e.emitCodexMessage(res, src, sha, st, line, &ri)
	case codexRIFunctionCall:
		st.resetCall(ri.CallID)
		if ri.Name == codexToolWait && ri.Namespace == "" && st.codexCodeMode.noteWait(ri.CallID, string(ri.Arguments)) {
			return
		}
		e.emitCodexFunctionCall(res, src, sha, st, line, &ri)
	case codexRILocalShellCall:
		st.resetCall(ri.CallID)
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = codexToolShell
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = decodeCodexShellAction(ri.Action)
		ev.Evidence.JSONPointer = "/payload/action"
		st.noteCommandCall(ri.CallID)
		res.appendEvent(st, ev, true)
	case codexRIFunctionCallOutput, codexRICustomToolCallOut:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload/output"
		resultBody := decodeCodexOutput(ri.Output)
		// Outputs correlated to a shell call are command.result updates. Static
		// code-mode calls may traverse internal wait/write_stdin calls; those are
		// folded back into the original command identity.
		var codeModeRef codexCodeModeResultRef
		var codeModeResult bool
		switch ri.Type {
		case codexRICustomToolCallOut:
			codeModeRef, codeModeResult = st.codexCodeMode.takeCustomCall(ri.CallID)
		case codexRIFunctionCallOutput:
			codeModeRef, codeModeResult = st.codexCodeMode.takeWaitCall(ri.CallID)
		}
		commandResult := ri.Type == codexRIFunctionCallOutput && st.takeCommandCall(ri.CallID)
		if codeModeResult || commandResult {
			ev.EventType = model.EventCommandResult
			if codeModeResult {
				ev.ToolName = codexToolExecCommand
				outcome := st.codexCodeMode.trackOutcome(codeModeRef, ri.Output)
				if outcome.cellID != "" {
					return
				}
				ev.ToolCallID = codeModeRef.commandCallID
				resultBody = outcome.output
				ev.ExitCode = outcome.exitCode
				ev.DurationMs = outcome.durationMs
				if outcome.toolError {
					ev.Tags = append(ev.Tags, model.TagToolError)
				}
				if !outcome.recognized {
					res.diag(src.Path, line, "unrecognized code-mode result envelope")
				}
			}
		} else {
			ev.EventType = model.EventToolResult
			// An mcp_tool_call_end may have recorded this call's failure before its
			// output landed (out-of-order); carry the structured tool-error forward so
			// the late output is not a false negative, matching codex.go.
			if st.takeFailedMCPCall(ri.CallID) {
				ev.Tags = append(ev.Tags, model.TagToolError)
			}
		}
		ev.ContentPreview = preview(resultBody)
		res.appendEvent(st, ev, true)
	case codexRIWebSearchCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventNetworkIndicator
		ev.ToolCallID = ri.CallID
		// Preview the action locator (search query, opened url, find-in-page
		// pattern) so the indicator names WHAT left the box, not just that egress
		// occurred — mirroring codex.go so a bare query keeps its investigative
		// lead even with no url to promote.
		ev.ContentPreview = preview(decodeCodexWebSearchAction(ri.Action))
		// The egress target must be a real http(s) url with a host; a bare search
		// query (no url) leaves URL empty rather than fabricating a target.
		if httpURL := networkTargetURL(codexWebSearchURL(ri.Action)); httpURL != "" {
			ev.URL = httpURL
		}
		ev.Tags = []string{model.TagNetwork}
		ev.Evidence.JSONPointer = "/payload/action"
		res.appendEvent(st, ev, true)
	case codexRICustomToolCall:
		// A new call owns a reused id and its next output.
		st.resetCall(ri.CallID)
		if ri.Namespace == "" && ri.Name == codexToolCodeModeExec {
			if call, ok := parseCodexCodeModeExec(string(ri.Input)); ok {
				ev := e.base(src, sha, st, line, 0)
				ev.Actor = model.ActorAssistant
				ev.Confidence = model.ConfidenceHigh
				ev.ToolName = codexToolExecCommand
				ev.ToolCallID = ri.CallID
				ev.EventType = model.EventCommandExec
				ev.Command = call.command
				ev.Evidence.JSONPointer = "/payload/input"
				st.codexCodeMode.noteExec(ri.CallID, call.resultKind)
				res.appendEvent(st, ev, true)
				return
			}
			if st.codexCodeMode.noteWriteStdinPoll(ri.CallID, string(ri.Input)) {
				return
			}
		}
		// A freeform/custom (often MCP-routed) tool call. The name is the only
		// reliably structured field; the input is previewed so a reviewer sees
		// WHAT was requested. An MCP-qualified name splits into typed server/tool
		// fields, falling back to the separate namespace — mirroring codex.go.
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventToolCall
		ev.ContentPreview = preview(string(ri.Input))
		ev.Evidence.JSONPointer = "/payload/input"
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.appendEvent(st, ev, true)
	case codexRIToolSearchOutput:
		// The result of a tool_search_call: a list of discovered tool definitions
		// under "tools" (no free-form output string), surfaced as the lead.
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorTool
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolResult
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(decodeCodexToolSearchTools(ri.Tools))
		ev.Evidence.JSONPointer = "/payload/tools"
		res.appendEvent(st, ev, true)
	case codexRIToolSearchCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolSearch
		ev.ToolCallID = ri.CallID
		ev.ContentPreview = preview(codexArgString(string(ri.Arguments), "query"))
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	case codexRIImageGenerationCall:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.EventType = model.EventToolCall
		ev.ToolName = codexToolImage
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload"
		res.appendEvent(st, ev, true)
	case codexRIReasoning:
		// Model reasoning is context, not an action record (mirrors Claude's
		// thinking-block handling and Codex's reasoning posture). It is prose, so it
		// is a NO-OP under data minimization — recognized, never previewed.
	case codexRICompaction, codexRICompactionSummary, codexRIContextCompaction:
		// History-compaction inner variants carry only opaque encrypted content;
		// an explicit, recognized no-op.
	case "":
		res.diag(src.Path, line, "openclaw codex response_item missing inner type")
	default:
		// Unknown response_item variant: skip rather than diagnose so a format
		// addition is not flagged as corruption (mirrors the Codex extractor).
	}
}

// mapCodexEventMsg mirrors codex.go for explicit prompts, state transitions,
// and structured MCP failures. Duplicate lifecycle records are skipped.
func (e OpenClawExtractor) mapCodexEventMsg(res *Result, src Source, sha string, st *openClawState, line int, payload json.RawMessage) {
	var em codexEventMsg
	if err := json.Unmarshal(payload, &em); err != nil {
		res.diag(src.Path, line, "malformed event_msg payload")
		return
	}
	switch em.Type {
	case codexEMUserMessage:
		e.emitCodexUserPrompt(res, src, sha, st, line, em.Message, "/payload/message")
	case codexEMItemCompleted:
		if message, ok := decodeCodexCompletedUserMessage(em.Item); ok {
			e.emitCodexUserPrompt(res, src, sha, st, line, message, "/payload/item/content")
		}
	case codexEMTaskStarted:
		st.codexUserPromptExpected = true
	case codexEMTurnAborted:
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		if em.Reason != "" {
			ev.ContentPreview = preview("turn aborted: " + em.Reason)
		}
		ev.Tags = []string{codexEMTurnAborted}
		res.appendEvent(st, ev, false)
	case codexEMThreadRolledBack, codexEMEnteredReviewMode, codexEMExitedReviewMode, codexEMThreadGoalUpdated:
		// State transitions with NO response_item twin: emitted as low-confidence
		// system notes tagged with the transition type so the state change is on the
		// timeline rather than silently lost (same posture as codex.go mapEventMsg).
		ev := e.base(src, sha, st, line, 0)
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorSystem
		ev.Confidence = model.ConfidenceLow
		ev.Evidence.JSONPointer = "/payload"
		ev.Tags = []string{em.Type}
		res.appendEvent(st, ev, false)
	case codexEMMcpToolCallEnd:
		// The response_item layer already emitted the tool.call/tool.result for this
		// MCP invocation, so this end-event is NOT re-emitted (that would double-count
		// the timeline). It is read ONLY for its structured Result: on a recorded
		// failure the matching tool.result for the call_id is tagged TagToolError,
		// falling back to noting the failed call_id when the output has not landed yet
		// (out-of-order). Success / unrecognized shape leaves the result untagged; no
		// prose body is scraped.
		if isErr, ok := codexMcpResultIsError(em.Result); ok && isErr {
			if !markToolResultError(res, em.CallID) {
				st.noteFailedMCPCall(em.CallID)
			}
		}
	default:
		// agent_message / patch_apply_end / ... duplicate response_item records;
		// unknown and unpersisted types are skipped too.
	}
}

// emitCodexMessage emits assistant prose and the compatibility prompt fallback
// used only when no explicit user-message lifecycle record appears.
func (e OpenClawExtractor) emitCodexMessage(res *Result, src Source, sha string, st *openClawState, line int, ri *codexResponseItem) {
	text := strings.TrimSpace(decodeCodexContentText(ri.Content))
	if text == "" {
		return
	}
	ev := e.base(src, sha, st, line, 0)
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, text)
	ev.Evidence.JSONPointer = "/payload/content"
	switch ri.Role {
	case "user":
		if st.codexMetaSeen || st.codexExplicitUserMessages {
			if !st.codexExplicitUserMessages || st.codexUserPromptExpected {
				ev.EventType = model.EventPromptUser
				ev.Actor = model.ActorUser
				ev.Confidence = model.ConfidenceMedium
				ev.SessionID = st.sessionID
				ev.ProjectPath = st.projectPath
				st.pendingCodexResponsePrompt = &ev
			}
			return
		}
		ev.EventType = model.EventPromptUser
		ev.Actor = model.ActorUser
	case "assistant":
		ev.EventType = model.EventMessageAssistant
		ev.Actor = model.ActorAssistant
	default:
		// developer/system: instructions injected into context, not agent activity.
		return
	}
	res.appendEvent(st, ev, false)
	if ri.Role == "user" {
		if st.codexResponsePromptIDs == nil {
			st.codexResponsePromptIDs = map[string]struct{}{}
		}
		st.codexResponsePromptIDs[ev.EventID] = struct{}{}
	}
}

func (e OpenClawExtractor) emitCodexUserPrompt(res *Result, src Source, sha string, st *openClawState, line int, message, pointer string) {
	st.pendingCodexResponsePrompt = nil
	st.codexUserPromptExpected = false
	if !st.codexExplicitUserMessages {
		st.codexExplicitUserMessages = true
		res.Events = discardResponsePromptEvents(res.Events, st.codexResponsePromptIDs)
		st.codexResponsePromptIDs = nil
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	ev := e.base(src, sha, st, line, 0)
	ev.EventType = model.EventPromptUser
	ev.Actor = model.ActorUser
	ev.Confidence = model.ConfidenceHigh
	setMessageContent(&ev, src, message)
	ev.Evidence.JSONPointer = pointer
	res.appendEvent(st, ev, false)
}

func flushOpenClawCodexResponsePrompt(res *Result, st *openClawState) {
	if st.pendingCodexResponsePrompt == nil {
		return
	}
	res.Events = append(res.Events, *st.pendingCodexResponsePrompt)
	st.pendingCodexResponsePrompt = nil
}

// emitCodexFunctionCall maps a Codex response_item function_call onto the
// normalized vocabulary, lifting the forensically salient argument out of the
// tool's JSON-encoded arguments string: shell→command.exec, apply_patch→one
// file.write/file.delete per touched file (with the diff digest/size, REQUESTED
// not confirmed), read/write/edit file→file.read/write, canonical MCP
// fetch→network.indicator, and every other tool→a generic tool.call. Mirrors
// codex.go emitFunctionCall but routes through OpenClaw's id/state/counter.
func (e OpenClawExtractor) emitCodexFunctionCall(res *Result, src Source, sha string, st *openClawState, line int, ri *codexResponseItem) {
	switch {
	case ri.Namespace == "" && (ri.Name == codexToolShell || ri.Name == codexToolShellCommand || ri.Name == codexToolExecCommand):
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventCommandExec
		ev.Command = codexShellCommand(string(ri.Arguments))
		ev.Evidence.JSONPointer = "/payload/arguments"
		st.noteCommandCall(ri.CallID)
		res.appendEvent(st, ev, true)
	case ri.Namespace == "" && ri.Name == codexToolApplyPatch:
		// apply_patch is a REQUEST to change files, not a confirmed write: the
		// function_call records intent. numbat emits the requested changes at
		// medium confidence with an intent tag, the same single-layer posture
		// as the Codex extractor (no cross-layer correlation to a patch_apply_end).
		changes := codexApplyPatchChanges(string(ri.Arguments))
		diffSHA, diffBytes := codexApplyPatchDiff(string(ri.Arguments))
		if len(changes) == 0 {
			ev := e.base(src, sha, st, line, 0)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceMedium
			ev.ToolName = ri.Name
			ev.ToolCallID = ri.CallID
			ev.EventType = model.EventFileWrite
			ev.DiffSHA256 = diffSHA
			ev.DiffBytes = diffBytes
			ev.Tags = []string{codexTagPatchRequested}
			ev.Evidence.JSONPointer = "/payload/arguments"
			res.appendEvent(st, ev, true)
			return
		}
		for i, c := range changes {
			ev := e.base(src, sha, st, line, i)
			ev.Actor = model.ActorAssistant
			ev.Confidence = model.ConfidenceMedium
			ev.ToolName = ri.Name
			ev.ToolCallID = ri.CallID
			if c.Delete {
				ev.EventType = model.EventFileDelete
			} else {
				ev.EventType = model.EventFileWrite
			}
			ev.FilePath = c.Path
			ev.DiffSHA256 = diffSHA
			ev.DiffBytes = diffBytes
			ev.Tags = []string{codexTagPatchRequested}
			ev.Evidence.JSONPointer = "/payload/arguments"
			res.appendEvent(st, ev, true)
		}
	case ri.Namespace == "" && ri.Name == codexToolReadFile:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileRead
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	case ri.Namespace == "" && (ri.Name == codexToolWriteFile || ri.Name == codexToolEditFile):
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.EventType = model.EventFileWrite
		ev.FilePath = codexArgString(string(ri.Arguments), "path")
		ev.Evidence.JSONPointer = "/payload/arguments"
		res.appendEvent(st, ev, true)
	default:
		ev := e.base(src, sha, st, line, 0)
		ev.Actor = model.ActorAssistant
		ev.Confidence = model.ConfidenceHigh
		ev.ToolName = ri.Name
		ev.ToolCallID = ri.CallID
		ev.Evidence.JSONPointer = "/payload/arguments"
		if isCodexMCPFetch(ri.Namespace, ri.Name) {
			// Network egress via the canonical MCP fetch server. The url must be a
			// real http(s) target; reuse the networkTargetURL validator so a hostless
			// or non-http value leaves URL empty rather than fabricating a target.
			if httpURL := networkTargetURL(codexArgString(string(ri.Arguments), "url")); httpURL != "" {
				ev.URL = httpURL
			}
			ev.EventType = model.EventNetworkIndicator
			ev.Tags = []string{model.TagNetwork}
			ev.MCPServer, ev.MCPTool = "fetch", "fetch"
			res.appendEvent(st, ev, true)
			return
		}
		ev.EventType = model.EventToolCall
		if server, tool, ok := splitMCPName(ri.Name); ok {
			ev.MCPServer, ev.MCPTool = server, tool
		} else if server, ok := codexMCPNamespaceServer(ri.Namespace); ok {
			ev.MCPServer, ev.MCPTool = server, ri.Name
		}
		res.appendEvent(st, ev, true)
	}
}
