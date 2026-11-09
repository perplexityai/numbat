package extract

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// artifactClaudeSettings is the evidence family for Claude Code settings files
// (user ~/.claude/settings.json, project .claude/settings.json and
// .claude/settings.local.json). The local file is where an interactive
// "don't ask again" approval is persisted by default.
const artifactClaudeSettings = "claude_settings"

// isClaudeSettingsName selects the settings parser. Discovery only routes these
// names to the Claude extractor when they sit directly under a .claude
// directory or CLAUDE_CONFIG_DIR, so the extractor matches on the base name and
// stays independent of the host environment.
func isClaudeSettingsName(path string) bool {
	switch filepath.Base(path) {
	case "settings.json", "settings.local.json":
		return true
	}
	return false
}

// claudeSettings is the subset of the settings schema the parser reads. Other
// keys (hooks, env, model, ...) are intentionally ignored here.
type claudeSettings struct {
	Permissions *struct {
		Allow []json.RawMessage `json:"allow"`
	} `json:"permissions"`
}

// extractSettings emits one permission.approved event per persisted
// permissions.allow rule. The rule string is retained as the event's tool
// input for local rule evaluation only. It is never part of emitted output
// unless the operator explicitly selects full content. Settings files carry no
// session, actor or time, so none are synthesized.
func (e ClaudeExtractor) extractSettings(data []byte, sha string, src Source) (*Result, error) {
	res := &Result{}
	if len(bytes.TrimSpace(data)) == 0 {
		return res, nil
	}
	var settings claudeSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		// The decoder error can quote source bytes, so the diagnostic does not
		// include it.
		res.diag(src.Path, 0, "malformed settings file; skipped")
		return res, nil
	}
	if settings.Permissions == nil {
		return res, nil
	}
	for i, raw := range settings.Permissions.Allow {
		var ruleText string
		if err := json.Unmarshal(raw, &ruleText); err != nil {
			res.diag(src.Path, 0, "permissions.allow entry "+strconv.Itoa(i)+" is not a string; skipped")
			continue
		}
		ruleText = strings.TrimSpace(ruleText)
		if ruleText == "" {
			continue
		}
		ev := model.Event{
			SchemaVersion:    model.SchemaVersion,
			CaseID:           src.CaseID,
			EventID:          historyEventID("claude-settings", src.Path, i),
			SourceAgent:      e.Agent(),
			SourceType:       model.SourceArtifact,
			EventType:        model.EventPermissionApproved,
			ToolName:         claudePermissionRuleTool(ruleText),
			Decision:         model.DecisionAllowed,
			ApprovalDecision: model.DecisionAllowed,
			Confidence:       model.ConfidenceHigh,
			Evidence: model.Evidence{
				ArtifactType: artifactClaudeSettings,
				LocalPath:    src.Path,
				JSONPointer:  "/permissions/allow/" + strconv.Itoa(i),
				SHA256:       sha,
			},
		}
		ev.SetToolInput(raw)
		res.Events = append(res.Events, ev)
	}
	return res, nil
}

// claudePermissionRuleTool returns the tool named by a permission rule such as
// "Bash(npm run test *)" or "WebFetch(domain:example.com)". A rule without a
// specifier, such as "WebSearch" or an MCP tool name, names the tool directly.
func claudePermissionRuleTool(ruleText string) string {
	if open := strings.IndexByte(ruleText, '('); open > 0 && strings.HasSuffix(ruleText, ")") {
		return strings.TrimSpace(ruleText[:open])
	}
	if strings.ContainsAny(ruleText, "() \t") {
		return ""
	}
	return ruleText
}
