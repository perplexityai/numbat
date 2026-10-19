package rule

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// DecisionSpec is an alternative to expr or sequence. Provider credentials and
// process-wide resource limits belong to the separately enabled evaluator.
type DecisionSpec struct {
	Select          string            `json:"select" yaml:"select"`
	Instructions    string            `json:"instructions" yaml:"instructions"`
	Options         map[string]string `json:"options" yaml:"options"`
	MatchOption     string            `json:"match_option" yaml:"match_option"`
	AbstainOption   string            `json:"abstain_option" yaml:"abstain_option"`
	View            string            `json:"view,omitempty" yaml:"view,omitempty"`
	MatchThreshold  float64           `json:"match_threshold" yaml:"match_threshold"`
	DenyThreshold   float64           `json:"deny_threshold,omitempty" yaml:"deny_threshold,omitempty"`
	MaxHistoryCalls int               `json:"max_history_calls,omitempty" yaml:"max_history_calls,omitempty"`
}

var decisionOptionKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (s DecisionSpec) ValidateQuestion() error {
	if strings.TrimSpace(s.Select) == "" {
		return errors.New("decision.select is required")
	}
	if strings.TrimSpace(s.Instructions) == "" || len(s.Instructions) > 32768 {
		return errors.New("decision.instructions must contain 1..32768 bytes of non-blank text")
	}
	if len(s.Options) < 2 || len(s.Options) > 32 {
		return errors.New("decision.options must contain 2..32 entries")
	}
	for key, description := range s.Options {
		if !decisionOptionKey.MatchString(key) {
			return errors.New("decision.options keys must match ^[a-z][a-z0-9_]{0,63}$")
		}
		if strings.TrimSpace(description) == "" || len(description) > 8192 {
			return fmt.Errorf("decision.options[%q] must contain 1..8192 bytes of non-blank text", key)
		}
	}
	if s.MatchOption == s.AbstainOption || s.Options[s.MatchOption] == "" || s.Options[s.AbstainOption] == "" {
		return errors.New("decision needs distinct match and abstain options")
	}
	return nil
}

func (s DecisionSpec) validate(enforce bool) error {
	if err := s.ValidateQuestion(); err != nil {
		return err
	}
	if s.View != "" && s.View != "action" && s.View != "session" {
		return errors.New("decision.view must be action or session")
	}
	probability := func(v float64) bool {
		return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0 && v <= 1
	}
	if !probability(s.MatchThreshold) {
		return errors.New("decision.match_threshold must be greater than 0 and at most 1")
	}
	if enforce || s.DenyThreshold != 0 {
		if !probability(s.DenyThreshold) || s.DenyThreshold <= .5 || s.DenyThreshold < s.MatchThreshold {
			return errors.New("decision.deny_threshold must exceed 0.5 and be at least match_threshold; required with enforce: true")
		}
	}
	if s.MaxHistoryCalls < 0 || s.MaxHistoryCalls > 4096 {
		return errors.New("decision.max_history_calls must be 0..4096; 0 inherits retained history")
	}
	return nil
}

// DecisionRules returns independent copies in ordinary catalog order. The
// deterministic Eval path never treats a matching decision selector as a match.
func (e *Engine) DecisionRules() []Rule {
	var rules []Rule
	if e != nil {
		for _, c := range e.rules {
			if c.rule.Decision != nil {
				rules = append(rules, cloneRule(c.rule))
			}
		}
	}
	return rules
}

// HasDeterministicEnforcement excludes model rules when no evaluator is enabled.
func (e *Engine) HasDeterministicEnforcement() bool {
	if e != nil {
		for _, c := range e.rules {
			if c.rule.Decision == nil && c.rule.IsEnforceEligible() {
				return true
			}
		}
	}
	return false
}
