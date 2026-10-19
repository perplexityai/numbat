// Package decision defines the pure, opt-in decision-evaluation contract.
// It performs no network, credential, filesystem or host-control operations.
package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

const (
	Version = "numbat.evaluation.v1"
	Action  = "action"
	Session = "session"
	Monitor = "monitor"
	Enforce = "enforce"
)

// Policy is the immutable model-facing projection of a decision rule.
type Policy struct {
	ID       string   `json:"id" yaml:"id"`
	Version  string   `json:"version" yaml:"version"`
	Title    string   `json:"title" yaml:"title"`
	Severity string   `json:"severity" yaml:"severity"`
	Enforce  bool     `json:"enforce" yaml:"enforce"`
	Decision Question `json:"decision" yaml:"decision"`
}

// Question defines one mutually exclusive classification with an explicit
// non-matching abstention. Select controls dispatch, not the classification.
type Question = rule.DecisionSpec

// Binding is the internal resolved rule/runtime contract, not a configuration
// catalog. Zero values do not enable I/O.
type Binding struct {
	Enabled         bool    `json:"enabled" yaml:"enabled"`
	PolicySHA256    string  `json:"policy_sha256" yaml:"policy_sha256"`
	View            string  `json:"view" yaml:"view"`
	Mode            string  `json:"mode" yaml:"mode"`
	MatchThreshold  float64 `json:"match_threshold" yaml:"match_threshold"`
	DenyThreshold   float64 `json:"deny_threshold" yaml:"deny_threshold"`
	BudgetMS        int     `json:"budget_ms" yaml:"budget_ms"`
	MaxRequestBytes int     `json:"max_request_bytes" yaml:"max_request_bytes"`
	EnvelopeBytes   int     `json:"envelope_bytes"`
	MaxHistoryCalls int     `json:"max_history_calls" yaml:"max_history_calls"`
	SendContent     bool    `json:"send_content" yaml:"send_content"`
}

// Compiled owns a copy of its policy so caller mutation cannot change its digest.
type Compiled struct {
	policy   Policy
	selector *rule.Engine
	digest   string
}

// LoadPolicy decodes one bounded YAML document and validates its policy.
func LoadPolicy(r io.Reader) (*Compiled, error) {
	data, err := io.ReadAll(io.LimitReader(r, 512*1024+1))
	if err != nil || len(data) > 512*1024 {
		return nil, errors.New("decision policy unreadable or oversized")
	}
	var p Policy
	if err := DecodeYAML(data, &p); err != nil {
		return nil, fmt.Errorf("decision policy: %w", err)
	}
	return Compile(p)
}

// Compile reuses rule metadata and CEL validation without assigning rule effects.
func Compile(p Policy) (*Compiled, error) {
	p = clonePolicy(p)
	q := p.Decision
	if err := q.ValidateQuestion(); err != nil {
		return nil, err
	}
	engine, err := rule.NewEngine([]rule.Source{{Name: "decision-selector", Rules: []rule.Rule{{
		ID: p.ID, Version: p.Version, Title: p.Title, Severity: p.Severity, Expr: q.Select,
	}}}})
	if err != nil {
		return nil, fmt.Errorf("decision policy: %w", err)
	}
	return &Compiled{policy: p, selector: engine, digest: hashJSON(p)}, nil
}

func FromRule(r rule.Rule) (*Compiled, error) {
	if r.Decision == nil {
		return nil, errors.New("rule has no decision")
	}
	return Compile(Policy{
		ID: r.ID, Version: r.Version, Title: r.Title, Severity: r.Severity,
		Enforce: r.IsEnforceEligible(), Decision: *r.Decision,
	})
}

func (c *Compiled) Policy() Policy { return clonePolicy(c.policy) }
func (c *Compiled) Digest() string { return c.digest }

func (c *Compiled) Select(event model.Event) (bool, error) {
	matches, err := c.selector.Eval(event)
	return len(matches) != 0, err
}

func (b Binding) Validate(c *Compiled) error {
	if c == nil || b.PolicySHA256 != c.Digest() {
		return errors.New("policy_sha256 does not match the canonical decision policy")
	}
	if b.View != Action && b.View != Session {
		return errors.New("view must be action or session")
	}
	if b.Mode != Monitor && b.Mode != Enforce {
		return errors.New("mode must be monitor or enforce")
	}
	if !probability(b.MatchThreshold) || b.MatchThreshold == 0 {
		return errors.New("match_threshold must be greater than 0 and at most 1")
	}
	if b.DenyThreshold != 0 || b.Mode == Enforce {
		if !probability(b.DenyThreshold) || b.DenyThreshold <= .5 ||
			b.DenyThreshold < b.MatchThreshold {
			return errors.New("deny_threshold must be greater than 0.5, at most 1, and at least match_threshold; required in enforce mode")
		}
	}
	if b.BudgetMS < 1 || b.BudgetMS > 8000 {
		return errors.New("budget_ms must be between 1 and 8000")
	}
	if b.MaxRequestBytes < 1 || b.MaxRequestBytes > 1024*1024 {
		return errors.New("max_request_bytes must be between 1 and 1048576")
	}
	if b.EnvelopeBytes < 0 || b.EnvelopeBytes >= b.MaxRequestBytes {
		return errors.New("provider envelope leaves no evidence budget")
	}
	if b.MaxHistoryCalls < 0 || b.MaxHistoryCalls > maxContextCalls || (b.View == Session && b.MaxHistoryCalls == 0) {
		return fmt.Errorf("max_history_calls must be between 1 and %d for session view; may be omitted for action view", maxContextCalls)
	}
	return nil
}

func probability(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1
}

func hashJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func clonePolicy(p Policy) Policy {
	opts := make(map[string]string, len(p.Decision.Options))
	for k, v := range p.Decision.Options {
		opts[k] = v
	}
	p.Decision.Options = opts
	return p
}
