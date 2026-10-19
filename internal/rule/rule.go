// Package rule defines Numbat's detection rules and the CEL-backed engine
// that evaluates them against normalized events.
//
// Rules are authored in YAML and matched with CEL. The `event` variable exposes
// selected normalized fields under their emitted JSON names; `shell_commands`
// is a rule-only projection of statically visible command invocations.
//
// Two rule shapes share the contract: a single-event rule (`expr`) evaluates
// one event in isolation, and a sequence rule (`sequence:`) correlates an
// ordered chain within one correlation partition, each step an ordinary CEL
// expr evaluated by the same engine. Exactly one shape must be present.
package rule

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// maxDenyMessageBytes keeps text embedded in host deny responses bounded and
// concise.
const maxDenyMessageBytes = 512

// Rule is one detection authored in YAML.
type Rule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description,omitempty"`
	Severity    string `yaml:"severity"`
	Version     string `yaml:"version"`
	// Expr is a CEL boolean expression. When it evaluates true for an event, the
	// rule produces a Finding. A rule carries exactly one of Expr or Sequence,
	// never both.
	Expr string `yaml:"expr,omitempty"`
	// Sequence makes this a multi-step correlation rule. When an event matches
	// the final step, the rule produces one finding citing each contributing
	// event.
	Sequence *SequenceSpec `yaml:"sequence,omitempty"`
	// Decision selects model evaluation. Selection alone is never a finding.
	Decision *DecisionSpec `yaml:"decision,omitempty"`
	// Tags are attached to findings this rule produces.
	Tags []string `yaml:"tags,omitempty"`
	// Enabled controls evaluation. Disabled rules are still validated and
	// compiled so configuration errors cannot hide behind enabled: false.
	// Omitting the field enables the rule.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Enforce opts a rule into the live hook deny path. Severity describes the
	// finding; this explicit policy flag controls whether a clean match may block
	// when the hook also runs with --enforce.
	Enforce *bool `yaml:"enforce,omitempty"`
	// DenyMessage overrides the generic message returned when this rule blocks
	// an action.
	DenyMessage string `yaml:"deny_message,omitempty"`
}

// IsEnabled reports whether the rule should be compiled. A nil Enabled
// (field omitted in YAML) means enabled.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// IsEnforceEligible reports whether a match may block in live hook enforce
// mode. The caller still owns the mode check and fail-open behavior.
func (r Rule) IsEnforceEligible() bool {
	return r.Enforce != nil && *r.Enforce
}

// Sequence validation bounds. Loader errors are preferred over silent runtime
// truncation, so a rule author always knows the contract.
const (
	// minSequenceSteps and maxSequenceSteps bound the chain length. One step is
	// a single-event rule (use expr); past eight the chain is no longer a
	// reviewable detection.
	minSequenceSteps = 2
	maxSequenceSteps = 8
	// maxWithinEvents caps the event-count window so per-partition buffering
	// stays bounded no matter what a rule declares.
	maxWithinEvents = 4096
	// maxSequenceMatches caps max_matches so the per-partition emitted-chain
	// cache stays bounded.
	maxSequenceMatches = 16
	// defaultSequenceMatches is the max_matches default: one canonical finding
	// per (rule, partition). Re-triggering chains stay quiet unless the rule
	// explicitly asks for more.
	defaultSequenceMatches = 1
)

// SequenceSpec is the `sequence:` block of a multi-step rule. Each step's Expr
// is an ordinary single-event CEL predicate compiled by the same engine as
// `expr` rules; the spec only adds the chain shape and its window.
type SequenceSpec struct {
	// Within is the wall-clock window (Go duration syntax, e.g. "30m") between
	// the first and final chain event, measured on event timestamps. When set,
	// a chain whose endpoints lack a parseable timestamp never matches: a
	// documented false negative beats a window we cannot verify.
	Within string `yaml:"within,omitempty"`
	// WithinEvents is the event-count window: the whole chain must fall inside
	// this many consecutive events of one partition (endpoints included).
	WithinEvents int `yaml:"within_events,omitempty"`
	// MaxMatches caps findings per (rule, partition); 0 means the default of
	// one. At least one of Within/WithinEvents is required; when both are
	// set, a chain must satisfy both.
	MaxMatches int `yaml:"max_matches,omitempty"`
	// Steps are the ordered per-event predicates, 2..8 (validated at load).
	Steps []SequenceStep `yaml:"steps"`
}

// SequenceStep is one link of a sequence rule: a single-event CEL predicate.
type SequenceStep struct {
	Expr string `yaml:"expr"`
}

// withinDuration parses the Within window. Zero with nil error means no
// wall-clock window is set.
func (s SequenceSpec) withinDuration() (time.Duration, error) {
	if s.Within == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s.Within)
	if err != nil {
		return 0, fmt.Errorf("invalid within %q: %w", s.Within, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("within %q must be positive", s.Within)
	}
	return d, nil
}

// resolvedMaxMatches returns the per-(rule, session) finding cap with the
// default applied.
func (s SequenceSpec) resolvedMaxMatches() int {
	if s.MaxMatches == 0 {
		return defaultSequenceMatches
	}
	return s.MaxMatches
}

// validate checks every structural constraint of the sequence block except
// step compilation, which needs the CEL env and stays in the engine.
func (s SequenceSpec) validate() error {
	var errs []error
	if len(s.Steps) < minSequenceSteps || len(s.Steps) > maxSequenceSteps {
		errs = append(errs, fmt.Errorf("sequence needs %d..%d steps, got %d", minSequenceSteps, maxSequenceSteps, len(s.Steps)))
	}
	for i, st := range s.Steps {
		if strings.TrimSpace(st.Expr) == "" {
			errs = append(errs, fmt.Errorf("step %d: empty expr", i+1))
		}
	}
	if s.Within == "" && s.WithinEvents == 0 {
		errs = append(errs, errors.New("sequence needs a window: set within and/or within_events"))
	}
	if _, err := s.withinDuration(); err != nil {
		errs = append(errs, err)
	}
	if s.WithinEvents < 0 {
		errs = append(errs, fmt.Errorf("within_events %d cannot be negative", s.WithinEvents))
	}
	if s.WithinEvents > maxWithinEvents {
		errs = append(errs, fmt.Errorf("within_events %d exceeds the %d cap", s.WithinEvents, maxWithinEvents))
	}
	if s.WithinEvents > 0 && s.WithinEvents < len(s.Steps) {
		errs = append(errs, fmt.Errorf("within_events %d cannot hold a %d-step chain", s.WithinEvents, len(s.Steps)))
	}
	if s.MaxMatches < 0 || s.MaxMatches > maxSequenceMatches {
		errs = append(errs, fmt.Errorf("max_matches %d must be 0 (default) or 1..%d", s.MaxMatches, maxSequenceMatches))
	}
	return errors.Join(errs...)
}

// Source is the internal collection passed to the engine. User-authored YAML is
// one rule per file; Source labels loaded rules by file path so diagnostics can
// name where they came from.
type Source struct {
	Name  string
	Rules []Rule
	// Path is the origin path the rule was loaded from, set by the loader and
	// never decoded from YAML. It disambiguates duplicate-id diagnostics.
	Path string
}

// Match is the in-memory result of a rule firing against an event, before it
// is rendered into a model.Finding by the caller (which owns ID/time/redaction
// policy).
type Match struct {
	Rule             Rule
	Event            model.Event
	EnforcementMatch bool
}

func cloneRule(r Rule) Rule {
	if r.Decision != nil {
		spec := *r.Decision
		spec.Options = make(map[string]string, len(r.Decision.Options))
		for key, value := range r.Decision.Options {
			spec.Options[key] = value
		}
		r.Decision = &spec
	}
	r.Tags = append([]string(nil), r.Tags...)
	if r.Enabled != nil {
		enabled := *r.Enabled
		r.Enabled = &enabled
	}
	if r.Enforce != nil {
		enforce := *r.Enforce
		r.Enforce = &enforce
	}
	if r.Sequence != nil {
		sequence := *r.Sequence
		sequence.Steps = append([]SequenceStep(nil), r.Sequence.Steps...)
		r.Sequence = &sequence
	}
	return r
}
