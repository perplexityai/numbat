package output

import (
	"errors"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/model"
)

const RecordAssessment = "assessment"

// DecisionAssessment is a flat audit record. ProviderModel names the classifier,
// not the agent model. Neither raw evidence nor provider free text is retained.
type DecisionAssessment struct {
	decision.Assessment
	AssessmentID   string   `json:"assessment_id"`
	SchemaVersion  string   `json:"schema_version"`
	Timestamp      string   `json:"timestamp"`
	CaseID         string   `json:"case_id,omitempty"`
	SourceAgent    string   `json:"source_agent"`
	SourceType     string   `json:"source_type"`
	SessionID      string   `json:"session_id,omitempty"`
	SessionTreeID  string   `json:"session_tree_id,omitempty"`
	SubAgentID     string   `json:"sub_agent_id,omitempty"`
	ToolCallID     string   `json:"tool_call_id,omitempty"`
	ActionEventIDs []string `json:"action_event_ids"`
	Provider       string   `json:"provider"`
	ProviderModel  string   `json:"provider_model"`
	ConfigDigest   string   `json:"config_digest"`
	BindingMode    string   `json:"mode"`        // Configured binding mode, not the hook's global mode.
	AllowUserOwned bool     `json:"user_config"` // Permission to use current-user-owned files, not observed ownership.
}

func (e *Emitter) EmitAssessment(a DecisionAssessment) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a.SchemaVersion != model.SchemaVersion || a.Version != decision.Version ||
		a.AssessmentID == "" || a.Status == "" || a.Reason == "" || a.SourceType != model.SourceHook ||
		len(a.ActionEventIDs) == 0 {
		e.recordErrors++
		return errors.New("invalid decision assessment record")
	}
	if err := e.emitLocked(RecordAssessment, a); err != nil {
		e.recordErrors++
		return err
	}
	return nil
}
