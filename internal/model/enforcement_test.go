package model

import (
	"strings"
	"testing"
)

func validEnforcementDecision() EnforcementDecision {
	return EnforcementDecision{
		SchemaVersion:  SchemaVersion,
		DecisionID:     "enf-0123456789abcdef01234567",
		Timestamp:      "2026-07-23T18:00:00Z",
		Decision:       EnforcementDecisionNoOverride,
		Mode:           EnforcementModeMonitor,
		Reason:         EnforcementReasonMonitorMode,
		SourceAgent:    AgentCodex,
		SourceType:     SourceHook,
		ActionEventIDs: []string{"event-1"},
		FindingIDs:     []string{"finding-1"},
		RuleIDs:        []string{"test.rule"},
	}
}

func TestEnforcementDecisionValidate(t *testing.T) {
	monitor := validEnforcementDecision()
	if err := monitor.Validate(); err != nil {
		t.Fatalf("valid monitor decision: %v", err)
	}

	deny := validEnforcementDecision()
	deny.Decision = EnforcementDecisionDeny
	deny.Mode = EnforcementModeEnforce
	deny.Reason = EnforcementReasonEnforceRuleMatch
	deny.DenyRuleID = "test.rule"
	deny.DenyRuleVersion = "1.0"
	if err := deny.Validate(); err != nil {
		t.Fatalf("valid deny decision: %v", err)
	}

	failOpen := validEnforcementDecision()
	failOpen.Mode = EnforcementModeEnforce
	failOpen.Reason = EnforcementReasonFailOpen
	if err := failOpen.Validate(); err != nil {
		t.Fatalf("valid fail-open decision: %v", err)
	}
}

func TestEnforcementDecisionRejectsContradictions(t *testing.T) {
	tests := []struct {
		name string
		edit func(*EnforcementDecision)
		want string
	}{
		{"bad id", func(d *EnforcementDecision) { d.DecisionID = "enf-no" }, "decision_id"},
		{"unknown decision", func(d *EnforcementDecision) { d.Decision = "maybe" }, "decision"},
		{"monitor deny", func(d *EnforcementDecision) { d.Decision = EnforcementDecisionDeny }, "monitor mode"},
		{"deny without rule", func(d *EnforcementDecision) {
			d.Mode = EnforcementModeEnforce
			d.Decision = EnforcementDecisionDeny
			d.Reason = EnforcementReasonEnforceRuleMatch
		}, "deny rule"},
		{"deny rule absent from matches", func(d *EnforcementDecision) {
			d.Mode = EnforcementModeEnforce
			d.Decision = EnforcementDecisionDeny
			d.Reason = EnforcementReasonEnforceRuleMatch
			d.DenyRuleID = "other.rule"
			d.DenyRuleVersion = "1.0"
		}, "absent from rule_ids"},
		{"no override with deny rule", func(d *EnforcementDecision) {
			d.Mode = EnforcementModeEnforce
			d.Reason = EnforcementReasonFailOpen
			d.DenyRuleID = "test.rule"
			d.DenyRuleVersion = "1.0"
		}, "no_override"},
		{"empty events", func(d *EnforcementDecision) { d.ActionEventIDs = nil }, "action_event_ids"},
		{"duplicate rules", func(d *EnforcementDecision) { d.RuleIDs = []string{"test.rule", "test.rule"} }, "duplicate"},
		{"not hook", func(d *EnforcementDecision) { d.SourceType = SourceArtifact }, "source_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := validEnforcementDecision()
			tc.edit(&decision)
			err := decision.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSemanticEnforcementUsesDistinctEvidence(t *testing.T) {
	d := validEnforcementDecision()
	d.RuleIDs = []string{"local.policy"}
	d.AssessmentIDs = []string{"asm-0123456789abcdef01234567"}
	if err := d.Validate(); err != nil {
		t.Fatalf("semantic monitor record invalid: %v", err)
	}
	d.Mode, d.Decision, d.Reason = EnforcementModeEnforce, EnforcementDecisionDeny, EnforcementReasonSemanticPolicyMatch
	d.DenyRuleID, d.DenyRuleVersion, d.DenyAssessmentID = "local.policy", "1", d.AssessmentIDs[0]
	if err := d.Validate(); err != nil {
		t.Fatalf("semantic deny record invalid: %v", err)
	}
	for _, change := range []func(*EnforcementDecision){
		func(d *EnforcementDecision) { d.DenyRuleID = "test.rule" },
		func(d *EnforcementDecision) { d.DenyRuleVersion = "" },
		func(d *EnforcementDecision) { d.DenyAssessmentID = "foreign" },
		func(d *EnforcementDecision) { d.AssessmentIDs = nil },
		func(d *EnforcementDecision) { d.Reason = EnforcementReasonEnforceRuleMatch },
		func(d *EnforcementDecision) {
			d.Decision, d.Reason = EnforcementDecisionNoOverride, EnforcementReasonFailOpen
		},
	} {
		bad := d
		change(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("contradictory semantic record accepted: %+v", bad)
		}
	}
}
