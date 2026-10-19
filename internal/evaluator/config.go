package evaluator

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/rule"
)

// Config owns provider access and process-wide limits, never a second rule
// catalog. Rules come from the same effective catalog as expr and sequence.
type Config struct {
	Version         string           `yaml:"version" json:"version"`
	InstallationID  string           `yaml:"installation_id" json:"installation_id"`
	BudgetMS        int              `yaml:"budget_ms" json:"budget_ms"`
	MaxRequestBytes int              `yaml:"max_request_bytes" json:"max_request_bytes"`
	Content         string           `yaml:"content" json:"content"`
	TimeoutMS       int              `yaml:"timeout_ms" json:"timeout_ms"`
	OperatorContext map[string]any   `yaml:"operator_context" json:"operator_context"`
	Provider        ProviderConfig   `yaml:"provider" json:"provider"`
	State           StateConfig      `yaml:"state" json:"state"`
	Rules           []ConfiguredRule `yaml:"-" json:"-"`

	digest string
}

type ProviderConfig struct {
	Profile   `yaml:",inline"`
	TokenFile string `yaml:"token_file" json:"token_file"`
	CAFile    string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
}

// ConfiguredRule freezes the ordinary rule and its resolved runtime limits.
type ConfiguredRule struct {
	decision.Binding
	Rule     rule.Rule
	Compiled *decision.Compiled
}

type StateConfig = decision.ContextLimits

// LoadConfig does not read credentials, load rules or contact a provider.
func LoadConfig(path string) (*Config, error) {
	raw, err := readProtected(path, 512<<10, true, false)
	if err != nil {
		return nil, fmt.Errorf("decision configuration: %w", err)
	}
	c := &Config{
		InstallationID: "local", BudgetMS: 1000, MaxRequestBytes: 128 << 10,
		Content: "redacted", TimeoutMS: 1000,
		Provider: ProviderConfig{Profile: Profile{Protocol: "decisions-v1", MaxResponseBytes: 64 << 10}},
		State:    StateConfig{MaxSessions: 128, MaxCalls: 64, MaxBytes: 32 << 20, IdleTTLMS: 3600000},
	}
	if err := decision.DecodeYAML(raw, c); err != nil {
		return nil, fmt.Errorf("decision configuration: %w", err)
	}
	if c.Version != "1" {
		return nil, errors.New("decision configuration version must be \"1\"")
	}
	if c.InstallationID == "" || strings.TrimSpace(c.InstallationID) != c.InstallationID || len(c.InstallationID) > 128 {
		return nil, errors.New("installation_id must contain 1..128 bytes without surrounding whitespace")
	}
	if c.BudgetMS < 1 || c.BudgetMS > 8000 {
		return nil, errors.New("budget_ms must be between 1 and 8000")
	}
	if c.TimeoutMS < 1 || c.TimeoutMS > 8000 {
		return nil, errors.New("timeout_ms must be between 1 and 8000")
	}
	if c.MaxRequestBytes < 1 || c.MaxRequestBytes > 1<<20 {
		return nil, errors.New("max_request_bytes must be between 1 and 1048576")
	}
	if c.Content != "raw" && c.Content != "redacted" {
		return nil, errors.New("content must be redacted or raw")
	}
	if err := c.Provider.Validate(); err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}
	if !absolutePath(c.Provider.TokenFile) || (c.Provider.CAFile != "" && !absolutePath(c.Provider.CAFile)) {
		return nil, errors.New("provider.token_file and optional ca_file must be absolute clean paths")
	}
	if err := c.State.Validate(); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if c.OperatorContext == nil {
		c.OperatorContext = map[string]any{}
	}
	context, err := json.Marshal(c.OperatorContext)
	if err != nil || len(context) > 32768 {
		return nil, errors.New("decision operator context invalid or oversized")
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		return nil, errors.New("invalid decision configuration encoding")
	}
	sum := sha256.Sum256(canonical)
	c.digest = hex.EncodeToString(sum[:])
	return c, nil
}

// ConfigureRules resolves limits after ordinary catalog validation. No rule can
// increase the operator's request or time budget.
func (c *Config) ConfigureRules(rules []rule.Rule) error {
	c.Rules = nil
	for _, r := range rules {
		if !r.IsEnabled() || r.Decision == nil {
			continue
		}
		p, err := decision.FromRule(r)
		if err != nil {
			return err
		}
		q := r.Decision
		b := decision.Binding{
			Enabled: true, SendContent: true, PolicySHA256: p.Digest(),
			View: q.View, Mode: decision.Monitor, MatchThreshold: q.MatchThreshold,
			DenyThreshold: q.DenyThreshold, BudgetMS: min(c.TimeoutMS, c.BudgetMS),
			MaxRequestBytes: c.MaxRequestBytes, MaxHistoryCalls: q.MaxHistoryCalls,
		}
		if r.IsEnforceEligible() {
			b.Mode = decision.Enforce
		}
		if b.View == "" {
			b.View = decision.Action
		}
		if b.View == decision.Session && b.MaxHistoryCalls == 0 {
			b.MaxHistoryCalls = max(1, c.State.MaxCalls-1)
		}
		if b.BudgetMS > c.BudgetMS || b.MaxRequestBytes > c.MaxRequestBytes {
			return fmt.Errorf("rule %q: decision limits exceed evaluator limits", r.ID)
		}
		if err := b.Validate(p); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
		minimum, err := requestBody(c.Provider.Profile, p.Policy(), json.RawMessage(`{}`))
		if err != nil || len(minimum) > b.MaxRequestBytes {
			return fmt.Errorf("rule %q: max_request_bytes is smaller than the policy envelope", r.ID)
		}
		b.EnvelopeBytes = len(minimum) - len(`{}`)
		c.Rules = append(c.Rules, ConfiguredRule{Binding: b, Rule: r, Compiled: p})
	}
	return nil
}

func absolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func (c *Config) Digest() string { return c.digest }

func (c *Config) EnforcementBlockers(r ConfiguredRule) []string {
	var reasons []string
	if !r.Enabled {
		reasons = append(reasons, "rule disabled")
	}
	if r.Compiled == nil || !r.Compiled.Policy().Enforce {
		reasons = append(reasons, "rule enforce is false")
	}
	return reasons
}

// Factory reads credentials only for a selected, budgeted evaluation.
func (c *Config) Factory() Factory {
	return func(profile Profile) (Provider, error) {
		p := c.Provider
		if p.Digest() != profile.Digest() {
			return nil, errors.New("decision provider identity mismatch")
		}
		token, err := readProtected(p.TokenFile, 4096, true, true)
		if err != nil {
			return nil, err
		}
		h, err := NewHTTP(profile, strings.TrimSpace(string(token)))
		if err != nil {
			return nil, err
		}
		if p.CAFile != "" {
			pem, err := readProtected(p.CAFile, 128<<10, true, false)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return nil, errors.New("invalid decision CA bundle")
			}
			h.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12, RootCAs: roots,
			}
		}
		return h, nil
	}
}
