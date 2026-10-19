package evaluator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/perplexityai/numbat/internal/decision"
)

// Profile contains the non-secret provider settings bound to each request.
type Profile struct {
	Protocol         string   `json:"protocol" yaml:"protocol"`
	Endpoint         string   `json:"endpoint" yaml:"endpoint"`
	Model            string   `json:"model" yaml:"model"`
	MaxResponseBytes int      `json:"max_response_bytes" yaml:"max_response_bytes"`
	ExpectedModel    string   `json:"expected_model,omitempty" yaml:"expected_model,omitempty"`
	Routing          *Routing `json:"routing,omitempty" yaml:"routing,omitempty"`
}

// Routing is the explicit OpenRouter extension, not an arbitrary request patch.
type Routing struct {
	AllowFallbacks bool   `json:"allow_fallbacks" yaml:"allow_fallbacks"`
	DataCollection string `json:"data_collection" yaml:"data_collection"`
	ZDR            bool   `json:"zdr,omitempty" yaml:"zdr,omitempty"`
}

func (p Profile) Validate() error {
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("endpoint must be an HTTPS URL without userinfo, query or fragment")
	}
	if p.Protocol != "decisions-v1" {
		return errors.New("protocol must be decisions-v1")
	}
	if strings.TrimSpace(p.Model) != p.Model || p.Model == "" || len(p.Model) > 256 {
		return errors.New("model must contain 1..256 bytes without surrounding whitespace")
	}
	if strings.TrimSpace(p.ExpectedModel) != p.ExpectedModel || len(p.ExpectedModel) > 256 {
		return errors.New("expected_model must contain at most 256 bytes without surrounding whitespace")
	}
	if p.Routing != nil && p.Routing.DataCollection != "deny" && p.Routing.DataCollection != "allow" {
		return errors.New("routing.data_collection must be deny or allow")
	}
	if p.MaxResponseBytes < 1024 || p.MaxResponseBytes > 1024*1024 {
		return errors.New("max_response_bytes must be between 1024 and 1048576")
	}
	return nil
}

func (p Profile) responseModel() string {
	if p.ExpectedModel != "" {
		return p.ExpectedModel
	}
	return p.Model
}

func (p Profile) Digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HTTP is the read-only Decisions adapter for one fixed provider profile.
type HTTP struct {
	profile Profile
	token   string
	client  *http.Client
}

// NewHTTP receives credentials from trusted caller wiring, never evidence.
// It performs no I/O; Config.Factory owns the protected token-file loader.
func NewHTTP(p Profile, token string) (*HTTP, error) {
	if p.Validate() != nil || strings.TrimSpace(token) != token ||
		token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("invalid provider configuration or credential")
	}
	if p.Routing != nil {
		routing := *p.Routing
		p.Routing = &routing
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{}).DialContext,
		ForceAttemptHTTP2: true, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 16384,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &HTTP{
		profile: p, token: token,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (h *HTTP) Evaluate(ctx context.Context, r decision.Request, c *decision.Compiled, maxBytes int) (decision.Reply, error) {
	if c == nil || c.Digest() == "" || !r.Valid() || r.PolicyDigest != c.Digest() ||
		r.ProfileDigest != h.profile.Digest() || r.Model != h.profile.responseModel() ||
		maxBytes < 1 || maxBytes > 1024*1024 {
		return decision.Reply{}, ErrInput
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	p := c.Policy()
	body, err := requestBody(h.profile, p, r.State)
	if err != nil || len(body) > maxBytes {
		return decision.Reply{}, ErrInput
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.profile.Endpoint, bytes.NewReader(body))
	if err != nil {
		return decision.Reply{}, errors.New("provider request unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token)
	res, err := h.client.Do(req)
	if err != nil {
		return decision.Reply{}, errors.New("provider transport unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return decision.Reply{}, errors.New("provider returned non-success")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, int64(h.profile.MaxResponseBytes)+1))
	if err != nil || len(data) > h.profile.MaxResponseBytes {
		return decision.Reply{}, ErrResponse
	}
	if !decision.ValidJSON(data) || !exactResponseFields(data) {
		return decision.Reply{}, ErrResponse
	}
	var wire struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Answers  map[string]struct {
			Type          string              `json:"type"`
			Choice        string              `json:"choice"`
			Probabilities map[string]*float64 `json:"probabilities"`
			Confidence    json.RawMessage     `json:"confidence"`
		} `json:"answers"`
		Usage json.RawMessage `json:"usage"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil || wire.Model != h.profile.responseModel() || len(wire.Answers) != 1 {
		return decision.Reply{}, ErrResponse
	}
	truncated, err := reportedTruncation(wire.Usage)
	if err != nil || truncated {
		return decision.Reply{}, ErrResponse
	}
	answer, ok := wire.Answers["policy"]
	if !ok || answer.Type != "choice" {
		return decision.Reply{}, ErrResponse
	}
	probabilities := make(map[string]float64, len(answer.Probabilities))
	for option, p := range answer.Probabilities {
		if p == nil {
			return decision.Reply{}, ErrResponse
		}
		probabilities[option] = *p
	}
	// The adapter binds a response to its own request, not a model-supplied ID.
	return decision.Reply{
		RequestDigest: r.Digest, Model: wire.Model, Choice: answer.Choice, Probabilities: probabilities,
	}, nil
}

// Missing metadata is not proof of complete input. Reject positive reports
// and malformed flags; leave unrelated, provider-specific usage fields opaque.
func reportedTruncation(data json.RawMessage) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	var usage map[string]json.RawMessage
	if json.Unmarshal(data, &usage) != nil {
		return false, ErrResponse
	}
	var truncated bool
	if raw, ok := usage["truncated"]; ok && json.Unmarshal(raw, &truncated) != nil {
		return false, ErrResponse
	}
	var questions []string
	if raw, ok := usage["truncated_questions"]; ok && json.Unmarshal(raw, &questions) != nil {
		return false, ErrResponse
	}
	return truncated || len(questions) != 0, nil
}

func requestBody(profile Profile, p decision.Policy, state json.RawMessage) ([]byte, error) {
	return json.Marshal(struct {
		Model     string                    `json:"model"`
		State     json.RawMessage           `json:"state"`
		Questions map[string]map[string]any `json:"questions"`
		Provider  *Routing                  `json:"provider,omitempty"`
	}{
		Model: profile.Model, State: state,
		Provider: profile.Routing,
		Questions: map[string]map[string]any{"policy": {
			"type": "choice", "instructions": p.Decision.Instructions, "criteria": p.Decision.Options,
		}},
	})
}

// encoding/json matches struct fields case-insensitively. Validate the actual
// wire spellings first so aliases cannot overwrite a security-sensitive value.
// Option keys remain case-sensitive data, not schema field names.
func exactResponseFields(data []byte) bool {
	top, ok := exactFields(data, "id", "provider", "model", "answers", "usage")
	if !ok {
		return false
	}
	answers, ok := exactFields(top["answers"], "policy")
	if !ok || len(answers) != 1 {
		return false
	}
	_, ok = exactFields(answers["policy"], "type", "choice", "probabilities", "confidence")
	return ok
}

func exactFields(data []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return nil, false
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return nil, false
		}
	}
	return fields, true
}
