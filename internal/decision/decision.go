package decision

import (
	"encoding/json"
	"errors"
	"maps"
	"math"
	"slices"
	"time"
)

// Subject is derived by a trusted adapter, not read from a provider response.
type Subject struct {
	Installation string `json:"installation"`
	Agent        string `json:"agent"`
	SessionTree  string `json:"session_tree,omitempty"`
	Session      string `json:"session"`
	SubAgentID   string `json:"sub_agent_id,omitempty"`
	Generation   string `json:"generation"`
	CallID       string `json:"call_id"`
	EventID      string `json:"event_id"`
}

// Evidence is already projected for the approved egress policy. The native
// adapter derives coverage from capture/state, never agent claims.
// Each history entry retains its observed outcome; absent results stay absent.
type Evidence struct {
	Subject         Subject
	Revision        uint64
	Current         json.RawMessage
	History         []json.RawMessage
	OperatorContext json.RawMessage
	CurrentComplete bool
	PrefixComplete  bool
	Concurrent      bool
	Gaps            []string
}

// Request is an immutable invocation snapshot. Digest binds all fields except
// itself, including eligibility, deadlines and the exact serialized evidence.
type Request struct {
	Version       string          `json:"version"`
	Kind          string          `json:"kind"`
	ID            string          `json:"id"`
	Subject       Subject         `json:"subject"`
	Revision      uint64          `json:"revision"`
	PolicyDigest  string          `json:"policy_digest"`
	BindingDigest string          `json:"binding_digest"`
	ProfileDigest string          `json:"profile_digest"`
	Model         string          `json:"model"`
	View          string          `json:"view"`
	Deadline      time.Time       `json:"deadline"`
	State         json.RawMessage `json:"state"`
	Eligible      bool            `json:"eligible"`
	Gaps          []string        `json:"gaps,omitempty"`
	Digest        string          `json:"digest"`
}

type Reply struct {
	RequestDigest string
	Model         string
	Choice        string
	Probabilities map[string]float64
}

// Assessment is model evidence and a local policy result, not a host outcome.
// It intentionally contains no raw input, provider text, or credentials.
type Assessment struct {
	Version        string             `json:"version"`
	RequestID      string             `json:"request_id,omitempty"`
	RequestDigest  string             `json:"request_digest,omitempty"`
	PolicyID       string             `json:"rule_id,omitempty"`
	PolicyVersion  string             `json:"rule_version,omitempty"`
	RuleDigest     string             `json:"rule_digest,omitempty"`
	ReturnedModel  string             `json:"returned_model,omitempty"`
	View           string             `json:"view,omitempty"`
	Status         string             `json:"status"`
	Reason         string             `json:"reason"`
	Choice         string             `json:"choice,omitempty"`
	Probabilities  map[string]float64 `json:"probabilities,omitempty"`
	MatchThreshold float64            `json:"match_threshold,omitempty"`
	DenyThreshold  float64            `json:"deny_threshold,omitempty"`
	InputEligible  bool               `json:"input_eligible"`
	Gaps           []string           `json:"gaps,omitempty"`
	Matched        bool               `json:"matched"`
	DenyCandidate  bool               `json:"deny_candidate"`
}

func Failure(status, reason string) Assessment {
	return Assessment{Version: Version, Status: status, Reason: reason}
}

// Prepare bounds and copies the inference view. Oldest history may be removed
// for monitoring, but removing any prefix disables contextual enforcement.
func Prepare(c *Compiled, b Binding, e Evidence, id, profileDigest, model string, deadline time.Time) (Request, error) {
	if err := b.Validate(c); err != nil {
		return Request{}, err
	}
	if !b.Enabled || !b.SendContent {
		return Request{}, errors.New("decision egress not enabled")
	}
	s := e.Subject
	if id == "" || profileDigest == "" || model == "" || deadline.IsZero() ||
		s.Installation == "" || s.Agent == "" ||
		s.Generation == "" || s.EventID == "" {
		return Request{}, errors.New("decision invocation identity incomplete")
	}
	limit := b.MaxRequestBytes - b.EnvelopeBytes
	if len(e.Current) > limit || len(e.OperatorContext) > limit ||
		!jsonObject(e.Current) || !jsonObject(e.OperatorContext) {
		return Request{}, errors.New("decision evidence requires JSON objects")
	}
	r := Request{
		Version: Version, Kind: "choice", ID: id, Subject: s, Revision: e.Revision,
		PolicyDigest: c.Digest(), BindingDigest: hashJSON(b), ProfileDigest: profileDigest,
		Model: model, View: b.View, Deadline: deadline, Eligible: e.CurrentComplete,
	}
	if !e.CurrentComplete {
		r.Gaps = append(r.Gaps, "current_incomplete")
	}
	history := []json.RawMessage(nil)
	coverage := "omitted_by_view"
	if b.View == Session {
		r.Gaps = append(r.Gaps, e.Gaps...)
		if s.Session == "" || s.CallID == "" {
			r.Gaps = append(r.Gaps, "missing_call_identity_or_input")
		}
		history = e.History
		coverage = "complete_prefix"
		if !e.PrefixComplete {
			r.Gaps = append(r.Gaps, "prefix_incomplete")
		}
		if e.Concurrent {
			r.Gaps = append(r.Gaps, "concurrent_actions")
		}
		if len(history) > b.MaxHistoryCalls {
			history = history[len(history)-b.MaxHistoryCalls:]
			r.Gaps = append(r.Gaps, "history_limit")
		}
		for _, entry := range history {
			if !jsonObject(entry) {
				return Request{}, errors.New("decision history requires JSON objects")
			}
		}
		if len(r.Gaps) != 0 {
			r.Eligible = false
			coverage = "partial_prefix"
		}
	}
	state := struct {
		Current  json.RawMessage   `json:"current_event"`
		History  []json.RawMessage `json:"history,omitempty"`
		Coverage string            `json:"history_coverage"`
		Operator json.RawMessage   `json:"operator_context"`
	}{e.Current, history, coverage, e.OperatorContext}
	data, err := json.Marshal(state)
	if err == nil && len(data) > limit && len(state.History) != 0 {
		remaining := len(data) - limit
		for len(state.History) > 0 && remaining > 0 {
			entry, marshalErr := json.Marshal(state.History[0])
			if marshalErr != nil {
				return Request{}, marshalErr
			}
			remaining -= len(entry) + 1
			state.History = state.History[1:]
		}
		r.Gaps = append(r.Gaps, "history_bytes_limit")
		r.Eligible, state.Coverage = false, "partial_prefix"
		data, err = json.Marshal(state)
	}
	if err != nil || len(data) > limit {
		return Request{}, errors.New("decision request exceeds evidence limit")
	}
	r.State = data
	r.Digest = r.digest()
	return r, nil
}

func jsonObject(data json.RawMessage) bool {
	var v map[string]json.RawMessage
	return ValidJSON(data) && json.Unmarshal(data, &v) == nil && v != nil
}

func (r Request) digest() string {
	r.Digest = ""
	return hashJSON(r)
}

func (r Request) Valid() bool {
	return r.Version == Version && r.Kind == "choice" && r.Digest != "" && r.Digest == r.digest()
}

// Reduce is deterministic. currentRevision is independently re-read by the
// caller; a stale session snapshot never produces an enforcement candidate.
func Reduce(c *Compiled, b Binding, r Request, reply Reply, currentRevision uint64, now time.Time) Assessment {
	a := Failure("invalid_response", "request_binding")
	if c == nil {
		return a
	}
	a.RequestID, a.RequestDigest = r.ID, r.Digest
	a.PolicyID, a.PolicyVersion, a.View = c.policy.ID, c.policy.Version, b.View
	a.MatchThreshold, a.DenyThreshold = b.MatchThreshold, b.DenyThreshold
	a.InputEligible, a.Gaps = r.Eligible, append([]string(nil), r.Gaps...)
	if b.View == Session && currentRevision != r.Revision {
		a.InputEligible = false
		a.Gaps = append(a.Gaps, "stale_snapshot")
	}
	if b.Validate(c) != nil || !r.Valid() || r.PolicyDigest != c.Digest() ||
		r.BindingDigest != hashJSON(b) || reply.RequestDigest != r.Digest || reply.Model != r.Model {
		return a
	}
	if !now.Before(r.Deadline) {
		a.Status, a.Reason = "timeout", "deadline"
		return a
	}
	q := c.policy.Decision
	if len(reply.Probabilities) != len(q.Options) {
		a.Reason = "option_set"
		return a
	}
	sum, top, winners := 0.0, -1.0, 0
	for _, k := range slices.Sorted(maps.Keys(q.Options)) {
		v, ok := reply.Probabilities[k]
		if !ok || !probability(v) {
			a.Reason = "probabilities"
			return a
		}
		sum += v
		switch {
		case v > top:
			top, winners = v, 1
		case v == top:
			winners++
		}
	}
	v, found := reply.Probabilities[reply.Choice]
	if math.Abs(sum-1) > 1e-5 || !found || v != top {
		a.Reason = "probabilities"
		return a
	}
	a.Status, a.Reason, a.Choice = "completed", "not_matched", reply.Choice
	a.Probabilities = make(map[string]float64, len(reply.Probabilities))
	for k, p := range reply.Probabilities {
		a.Probabilities[k] = p
	}
	if winners != 1 || reply.Choice == q.AbstainOption {
		a.Reason = "abstained"
		return a
	}
	a.Matched = reply.Choice == q.MatchOption && v >= b.MatchThreshold
	if b.View == Session && currentRevision != r.Revision {
		a.InputEligible, a.Reason = false, "stale_snapshot"
		return a
	}
	if !r.Eligible {
		a.Reason = "incomplete_evidence"
		return a
	}
	if !a.Matched {
		return a
	}
	switch {
	case !b.Enabled || !b.SendContent:
		a.Reason = "disabled"
	case b.Mode != Enforce:
		a.Reason = "monitor_mode"
	case !c.policy.Enforce:
		a.Reason = "policy_monitor_only"
	case v < b.DenyThreshold:
		a.Reason = "below_deny_threshold"
	default:
		a.Reason, a.DenyCandidate = "semantic_match", true
	}
	return a
}
