package model

import (
	"fmt"
	"strings"
)

// Enforcement modes identify whether a hook was observing or allowed to deny.
const (
	EnforcementModeMonitor = "monitor"
	EnforcementModeEnforce = "enforce"
)

// Enforcement decisions are Numbat's portable effects on the host permission
// flow. NoOverride preserves that flow; Deny selects the host's deny contract.
const (
	EnforcementDecisionNoOverride = "no_override"
	EnforcementDecisionDeny       = "deny"
)

// Enforcement reasons explain why Numbat selected its decision.
const (
	EnforcementReasonMonitorMode            = "monitor_mode"
	EnforcementReasonNoEnforceEligibleMatch = "no_enforce_eligible_match"
	EnforcementReasonFailOpen               = "fail_open"
	EnforcementReasonEnforceRuleMatch       = "enforce_rule_match"
)

// EnforcementDecision records Numbat's computed policy decision for a matched
// synchronous pre-action hook. When findings are selected, it is emitted with
// their batch before the control response. It does not assert response delivery
// or host behavior. Join fields contain identifiers only; the record never
// repeats command, file, URL, prompt, or other observed content.
type EnforcementDecision struct {
	SchemaVersion string `json:"schema_version"`
	DecisionID    string `json:"decision_id"`
	CaseID        string `json:"case_id,omitempty"`
	Timestamp     string `json:"timestamp"`

	Decision string `json:"decision"`
	Mode     string `json:"mode"`
	Reason   string `json:"reason"`

	SourceAgent     string `json:"source_agent"`
	SourceType      string `json:"source_type"`
	SessionID       string `json:"session_id,omitempty"`
	SessionTreeID   string `json:"session_tree_id,omitempty"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	Model           string `json:"model,omitempty"`
	ModelProvider   string `json:"model_provider,omitempty"`
	SubAgent        string `json:"sub_agent,omitempty"`
	SubAgentID      string `json:"sub_agent_id,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	ToolCallID      string `json:"tool_call_id,omitempty"`

	ActionEventIDs []string `json:"action_event_ids"`
	FindingIDs     []string `json:"finding_ids,omitempty"`
	RuleIDs        []string `json:"rule_ids"`

	DenyRuleID      string `json:"deny_rule_id,omitempty"`
	DenyRuleVersion string `json:"deny_rule_version,omitempty"`
}

// Validate enforces the closed enforcement-decision wire contract.
func (d EnforcementDecision) Validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("enforcement decision %s: invalid schema_version %q", d.DecisionID, d.SchemaVersion)
	}
	if !validEnforcementDecisionID(d.DecisionID) {
		return fmt.Errorf("enforcement decision: invalid decision_id %q", d.DecisionID)
	}
	if d.Timestamp == "" {
		return fmt.Errorf("enforcement decision %s: empty timestamp", d.DecisionID)
	}
	if d.Decision != EnforcementDecisionNoOverride && d.Decision != EnforcementDecisionDeny {
		return fmt.Errorf("enforcement decision %s: invalid decision %q", d.DecisionID, d.Decision)
	}
	if d.Mode != EnforcementModeMonitor && d.Mode != EnforcementModeEnforce {
		return fmt.Errorf("enforcement decision %s: invalid mode %q", d.DecisionID, d.Mode)
	}
	if !IsValidSourceAgent(d.SourceAgent) {
		return fmt.Errorf("enforcement decision %s: invalid source_agent %q", d.DecisionID, d.SourceAgent)
	}
	if d.SourceType != SourceHook {
		return fmt.Errorf("enforcement decision %s: source_type must be %q", d.DecisionID, SourceHook)
	}
	if err := validateUniqueNonEmpty("action_event_ids", d.ActionEventIDs, true); err != nil {
		return fmt.Errorf("enforcement decision %s: %w", d.DecisionID, err)
	}
	if err := validateUniqueNonEmpty("finding_ids", d.FindingIDs, false); err != nil {
		return fmt.Errorf("enforcement decision %s: %w", d.DecisionID, err)
	}
	if err := validateUniqueNonEmpty("rule_ids", d.RuleIDs, true); err != nil {
		return fmt.Errorf("enforcement decision %s: %w", d.DecisionID, err)
	}

	switch {
	case d.Mode == EnforcementModeMonitor:
		if d.Decision != EnforcementDecisionNoOverride || d.Reason != EnforcementReasonMonitorMode {
			return fmt.Errorf("enforcement decision %s: monitor mode requires no_override with monitor_mode", d.DecisionID)
		}
	case d.Decision == EnforcementDecisionDeny:
		if d.Reason != EnforcementReasonEnforceRuleMatch || d.DenyRuleID == "" || d.DenyRuleVersion == "" {
			return fmt.Errorf("enforcement decision %s: deny requires enforce_rule_match and a deny rule id/version", d.DecisionID)
		}
		if !containsValue(d.RuleIDs, d.DenyRuleID) {
			return fmt.Errorf("enforcement decision %s: deny rule %q is absent from rule_ids", d.DecisionID, d.DenyRuleID)
		}
	case d.Reason != EnforcementReasonNoEnforceEligibleMatch && d.Reason != EnforcementReasonFailOpen:
		return fmt.Errorf("enforcement decision %s: invalid no_override enforce-mode reason %q", d.DecisionID, d.Reason)
	}
	if d.Decision != EnforcementDecisionDeny && (d.DenyRuleID != "" || d.DenyRuleVersion != "") {
		return fmt.Errorf("enforcement decision %s: no_override decision names a deny rule", d.DecisionID)
	}
	return nil
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validEnforcementDecisionID(id string) bool {
	const prefix = "enf-"
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+24 {
		return false
	}
	for _, c := range id[len(prefix):] {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

func validateUniqueNonEmpty(name string, values []string, required bool) error {
	if required && len(values) == 0 {
		return fmt.Errorf("empty %s", name)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s contains an empty value", name)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s contains duplicate %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
