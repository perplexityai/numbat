package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// OpenCode's earlier storage layouts persist one JSON object per record. The
// forensic signal lives in the per-part files:
//
//   - storage/part/<messageID>/<partID>.json    — one part per file (the tool
//     /shell signal). A part's "type" discriminator selects its shape.
//   - storage/message/<sessionID>/<messageID>.json — one message per file,
//     carrying role (user | assistant) and bookkeeping.
//   - storage/session/<projectID>/<sessionID>.json — session info.
//
// This parser maps a single part or message file to events. A "tool" part is
// the primary signal: its state is a tagged union on state.status
// (pending | running | completed | error), and a state.status=="error" is the
// ONLY tool-error signal — never prose-scraped, never inferred from an exit
// code. A legacy "shell" part (older OpenCode internal layouts) carries a
// command/output pair directly. A "patch" part is a structured multi-file edit
// carrying a content hash. "text"/"reasoning" parts are prose; a message file
// carries the user prompt / assistant turn role.
//
// All field/shape facts are taken from anomalyco/opencode's SDK type schema
// (packages/sdk/js/src/gen/types.gen.ts: ToolPart, ToolState*, PatchPart,
// TextPart, ReasoningPart, UserMessage, AssistantMessage) and the tool registry
// (packages/opencode/src/tool/*.ts), so each typed mapping below is
// artifact-backed rather than guessed.

// artifactOpenCode is the Evidence.ArtifactType stamped on every event derived
// from an OpenCode storage record.
const artifactOpenCode = "opencode_storage"

// OpenCode part type discriminators (the "type" field of a part .json). Only
// the kinds numbat maps are named; any other part type (file, step-start,
// step-finish, snapshot, agent, retry, compaction, subtask) is surfaced as a
// coverage gap rather than guessed at.
const (
	openCodePartTool      = "tool"
	openCodePartShell     = "shell" // legacy direct shell-exec part
	openCodePartPatch     = "patch"
	openCodePartText      = "text"
	openCodePartReasoning = "reasoning"
)

// OpenCode tool-state status values (ToolState's tagged union on status). A
// completed state is SUCCESS; an error state is the sole tool-error signal.
const (
	openCodeStatusCompleted = "completed"
	openCodeStatusError     = "error"
)

// OpenCode message roles (Message.role). A tool part is an assistant action
// regardless of the carrying message; a message file's role distinguishes a
// human prompt from an assistant turn.
const (
	openCodeRoleUser      = "user"
	openCodeRoleAssistant = "assistant"
)

// OpenCode built-in tool ids — the literal ToolPart.tool values recorded on
// disk, from anomalyco/opencode's tool registry (packages/opencode/src/tool/).
// Only the ids numbat promotes to a typed event are listed; every other id —
// future built-ins, plugin tools, MCP tools — falls through to a generic
// tool.call with NO alias promotion. WHY each is artifact-backed:
//   - "bash": shell.ts defines ShellID.ToolID = "bash" (kept as the exposed id
//     and permission key for compatibility); the bash tool is OpenCode's shell
//     executor, input.command is the command string.
//   - "read": read.ts Tool.define("read"); input.filePath is the path read.
//   - "write"/"edit": write.ts/edit.ts Tool.define("write"|"edit");
//     input.filePath is the path written.
//   - "apply_patch": apply_patch.ts Tool.define("apply_patch"); a multi-file
//     edit (its structured result is a PatchPart with a hash + files list).
//   - "webfetch": webfetch.ts Tool.define("webfetch"); input.url is the egress
//     target (the tool rejects a non-http(s) url, so it is a real URL).
//   - "websearch": websearch.ts Tool.define("websearch"); input.query is the
//     search query (no url is fetched).
const (
	openCodeToolBash       = "bash"
	openCodeToolRead       = "read"
	openCodeToolWrite      = "write"
	openCodeToolEdit       = "edit"
	openCodeToolApplyPatch = "apply_patch"
	openCodeToolWebFetch   = "webfetch"
	openCodeToolWebSearch  = "websearch"
)

// OpenCode tool input argument keys, from the same tool sources. Numbat reads
// only the fields it maps onto a typed event; everything else in input is
// ignored.
const (
	openCodeArgCommand  = "command"  // bash
	openCodeArgFilePath = "filePath" // read / write / edit
	openCodeArgURL      = "url"      // webfetch
	openCodeArgQuery    = "query"    // websearch
)

// openCodePart is a tolerant view of one part .json. Only the fields numbat
// maps are decoded. Type is the discriminator; the remaining fields are
// populated only for the part kind that carries them.
type openCodePart struct {
	Type      string        `json:"type"`
	SessionID string        `json:"sessionID"`
	CallID    string        `json:"callID"` // tool/shell correlation id
	Tool      string        `json:"tool"`   // tool part: the tool id
	State     openCodeState `json:"state"`  // tool part: the tagged-union state
	// Legacy "shell" part fields: a direct command/output pair.
	Command string `json:"command"`
	Output  string `json:"output"`
	// "patch" part fields: a structured multi-file edit with a content hash.
	Hash  string   `json:"hash"`
	Files []string `json:"files"`
	// "text"/"reasoning" part field: the prose body.
	Text string       `json:"text"`
	Time openCodeTime `json:"time"`
}

// openCodeState is a tool part's tagged-union state. Status selects the variant
// (pending | running | completed | error). Input is the tool's argument map
// (kept raw so each tool's well-known keys are decoded only when recognized);
// Output is the completed result body; Error is the failure message present
// ONLY on a status=="error" state — the sole, structured tool-error signal.
type openCodeState struct {
	Status string                     `json:"status"`
	Input  map[string]json.RawMessage `json:"input"`
	Output string                     `json:"output"`
	Error  string                     `json:"error"`
	Time   openCodeTime               `json:"time"`
}

type openCodeTime struct {
	Created int64 `json:"created"`
	Start   int64 `json:"start"`
	End     int64 `json:"end"`
}

// openCodeMessage is the common context carried by user and assistant message
// records. User messages nest the model identity; assistant messages keep it
// flat and also expose the working directory.
type openCodeMessage struct {
	Role       string       `json:"role"`
	SessionID  string       `json:"sessionID"`
	Time       openCodeTime `json:"time"`
	ModelID    string       `json:"modelID"`
	ProviderID string       `json:"providerID"`
	Model      struct {
		ModelID    string `json:"modelID"`
		ProviderID string `json:"providerID"`
	} `json:"model"`
	Path struct {
		CWD string `json:"cwd"`
	} `json:"path"`
}

func (m openCodeMessage) modelIdentity() (string, string) {
	if m.ModelID != "" || m.ProviderID != "" {
		return m.ModelID, m.ProviderID
	}
	return m.Model.ModelID, m.Model.ProviderID
}

// openCodeArgString returns the string value of a tool input arg, or "" when
// the arg is absent or not a JSON string. It mirrors geminiArgString.
func openCodeArgString(input map[string]json.RawMessage, key string) string {
	raw, ok := input[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// openCodeHexHash returns h iff it is a 64-char lowercase/uppercase hex digest
// (so it can be stamped on Event.DiffSHA256, whose convention is a bare SHA-256
// hex digest with no "sha256:" prefix), else "". A PatchPart.hash is a content
// hash of the applied patch; numbat surfaces it as the edit's diff digest only
// when it matches the published event schema, never as a fabricated value.
func openCodeHexHash(h string) string {
	h = strings.TrimSpace(h)
	if len(h) != 64 {
		return ""
	}
	for _, r := range h {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return ""
		}
	}
	return strings.ToLower(h)
}

// openCodeEventID returns a stable, unique identifier for an event derived from
// a part/message at a known on-disk path. A part file holds exactly one record,
// so the path plus a sub-index (a single part can emit a call+result pair, or a
// patch can emit one event per touched file) is enough to be deterministic and
// collision-free across runs. A tool callID is NOT used as the event id: it
// correlates a call to its result but is shared between them, so it is not
// unique per event.
func openCodeEventID(path string, sub int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d", path, sub))
	return "opencode-" + hex.EncodeToString(sum[:16])
}
