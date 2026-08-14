// Package finding renders a rule match into the redaction-safe model.Finding
// that Numbat emits. It is the single place that applies emission policy —
// redaction, project-path hashing, evidence selection, and finding identity —
// so every command produces findings the same way.
package finding

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
)

var rfc3339Timestamp = regexp.MustCompile(
	`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[Tt]` +
		`([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?` +
		`([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`,
)

// Options controls emission policy for a render.
type Options struct {
	// Now stamps detected_at. A zero value uses time.Now().
	// Tests set it for deterministic output.
	Now time.Time
}

// FromMatch renders a rule match into a Finding. The finding carries no raw
// transcript content: the project path is hashed, the observed artifact fields
// are redacted (see observed), and only Evidence references point back to the
// source. Redacted reports whether a finding value was actually masked; raw
// retention would be a separate, explicit policy.
func FromMatch(m rule.Match, opts Options) model.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	ev := m.Event

	f := model.Finding{
		SchemaVersion: model.SchemaVersion,
		FindingID:     findingID(m.Rule.ID, m.Rule.Version, ev.EventID),
		CaseID:        ev.CaseID,
		Timestamp:     activityTimestamp(ev.Timestamp),
		DetectedAt:    now.UTC().Format(time.RFC3339Nano),
		RuleID:        m.Rule.ID,
		RuleVersion:   m.Rule.Version,
		Severity:      m.Rule.Severity,
		SourceAgent:   ev.SourceAgent,
		SourceType:    ev.SourceType,
		SessionID:     ev.SessionID,
		Model:         ev.Model,
		ModelProvider: ev.ModelProvider,
		SubAgent:      ev.SubAgent,
		Title:         m.Rule.Title,
		Tags:          model.MergeTags(ev.Tags, m.Rule.Tags),
		EvidenceRefs:  []model.Evidence{ev.Evidence},
		CitedEventIDs: []string{ev.EventID},
		Confidence:    ev.Confidence,
	}
	f.Redacted = observed(ev, &f)
	if ev.ProjectPath != "" {
		f.ProjectPathHash = model.HashPath(ev.ProjectPath)
	}
	return f
}

// FromSequence renders a completed chain into the one Finding a sequence rule
// emits. The contract is unchanged from FromMatch — same schema, same
// redaction, same evidence-by-reference posture — extended to many events:
// EvidenceRefs carries each contributing event's source reference and
// CitedEventIDs carries its event id, both in chain order. The finding id
// hashes the rule id, rule version, and every chain event id (so an
// identical chain re-renders to an identical id and receivers deduplicate),
// tags are the union over the rule and every chain event, and confidence
// is the chain's WEAKEST link — a chain is never more certain than its least
// certain event. The observed_* fields show the completing event, the moment
// the chain became a detection.
func FromSequence(m sequence.Match, opts Options) model.Finding {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	final := m.Final

	ids := make([]string, 0, len(m.Links))
	refs := make([]model.Evidence, 0, len(m.Links))
	tags := m.Rule.Tags
	for _, l := range m.Links {
		ids = append(ids, l.EventID)
		refs = append(refs, l.Evidence)
		tags = model.MergeTags(tags, l.Tags)
	}

	f := model.Finding{
		SchemaVersion: model.SchemaVersion,
		FindingID:     findingID(m.Rule.ID, m.Rule.Version, ids...),
		CaseID:        final.CaseID,
		Timestamp:     activityTimestamp(final.Timestamp),
		DetectedAt:    now.UTC().Format(time.RFC3339Nano),
		RuleID:        m.Rule.ID,
		RuleVersion:   m.Rule.Version,
		Severity:      m.Rule.Severity,
		SourceAgent:   final.SourceAgent,
		SourceType:    final.SourceType,
		SessionID:     final.SessionID,
		Model:         final.Model,
		ModelProvider: final.ModelProvider,
		SubAgent:      final.SubAgent,
		Title:         m.Rule.Title,
		Tags:          tags,
		EvidenceRefs:  refs,
		CitedEventIDs: ids,
		Confidence:    weakestConfidence(m.Links),
	}
	f.Redacted = observed(final, &f)
	if final.ProjectPath != "" {
		f.ProjectPathHash = model.HashPath(final.ProjectPath)
	}
	return f
}

func activityTimestamp(raw string) string {
	if !rfc3339Timestamp.MatchString(raw) {
		return ""
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.ToUpper(raw)); err != nil {
		return ""
	}
	return raw
}

// confidenceRank orders confidence levels for the weakest-link fold. Anything
// outside the closed vocabulary (including empty) ranks below low, so a
// malformed link can only weaken a chain, never strengthen it.
var confidenceRank = map[string]int{
	model.ConfidenceHigh:   3,
	model.ConfidenceMedium: 2,
	model.ConfidenceLow:    1,
}

// weakestConfidence returns the lowest confidence across the chain's links;
// an unrecognized level degrades the whole chain to low.
func weakestConfidence(links []sequence.Link) string {
	weakest := model.ConfidenceHigh
	for _, l := range links {
		if confidenceRank[l.Confidence] < confidenceRank[weakest] {
			weakest = l.Confidence
		}
	}
	if confidenceRank[weakest] == 0 {
		return model.ConfidenceLow
	}
	return weakest
}

// observed copies the matched event's artifact onto the finding so a reader
// sees what actually fired. event_type and actor are closed-vocabulary enums
// copied verbatim; every externally supplied value that can carry sensitive
// content — command, file_path, url, content_preview, MCP server, MCP tool — is
// routed through redact.String so a secret or a presigned-URL token never reaches
// an emitted finding. Empty sources are skipped so omitempty drops them. The
// return value reports whether any emitted value changed during redaction.
func observed(ev model.Event, f *model.Finding) bool {
	var changed bool
	f.ObservedEventType = string(ev.EventType)
	f.ObservedActor = ev.Actor
	if ev.MCPServer != "" {
		f.ObservedMCPServer, changed = redactValue(ev.MCPServer, changed)
	}
	if ev.MCPTool != "" {
		f.ObservedMCPTool, changed = redactValue(ev.MCPTool, changed)
	}
	if ev.Command != "" {
		f.ObservedCommand, changed = redactValue(ev.Command, changed)
	}
	if ev.FilePath != "" {
		f.ObservedFilePath, changed = redactValue(ev.FilePath, changed)
	}
	if ev.URL != "" {
		f.ObservedURL, changed = redactValue(ev.URL, changed)
	}
	f.ObservedContentPreviewTruncated = ev.ContentPreviewTruncated
	if ev.ContentPreview != "" {
		redacted := redact.String(ev.ContentPreview)
		changed = changed || redacted != ev.ContentPreview
		var outputTruncated bool
		f.ObservedContentPreview, outputTruncated = model.NormalizeContentPreviewWithTruncation(redacted)
		f.ObservedContentPreviewTruncated = f.ObservedContentPreviewTruncated || outputTruncated
	}
	return changed
}

func redactValue(raw string, alreadyChanged bool) (string, bool) {
	out := redact.String(raw)
	return out, alreadyChanged || out != raw
}

// findingID is stable for one rule revision and its contributing events. Length
// prefixes make the input unambiguous even if an event id contains a separator.
func findingID(ruleID, ruleVersion string, eventIDs ...string) string {
	h := sha256.New()
	writePart := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	writePart(ruleID)
	writePart(ruleVersion)
	for _, id := range eventIDs {
		writePart(id)
	}
	return "fnd-" + hex.EncodeToString(h.Sum(nil)[:12])
}
