package pipeline

import (
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

// RecordDecisionMatch uses the same accumulator as local rules. Callers must
// successfully emit both the assessment and finding before contributing a deny.
func (d *EnforceDecision) RecordDecisionMatch(ev model.Event, r rule.Rule, findingID, assessmentID string, deny bool, actionIDs []string) {
	d.recordMatch(ev, r, findingID)
	for _, id := range actionIDs {
		d.ActionEventIDs = appendUnique(d.ActionEventIDs, id)
	}
	d.AssessmentIDs = appendUnique(d.AssessmentIDs, assessmentID)
	if deny && !d.Blocked && !d.Tainted && !d.ObserveOnly {
		d.Blocked = true
		d.Reason = denyMessage(r)
		d.DenyRuleID, d.DenyRuleVersion = r.ID, r.Version
		d.DenyAssessmentID = assessmentID
	}
}
