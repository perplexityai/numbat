package evaluator

import (
	"bytes"
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
)

// Config is loaded only from an explicit operator-supplied path. The default
// loader requires root-owned configuration; user-owned mode is a separate CLI
// opt-in and is not a security boundary against the agent's OS user.
type Config struct {
	Version             string                    `yaml:"version" json:"version"`
	Enabled             bool                      `yaml:"enabled" json:"enabled"`
	InstallationID      string                    `yaml:"installation_id" json:"installation_id"`
	BudgetMS            int                       `yaml:"budget_ms" json:"budget_ms"`
	Content             string                    `yaml:"content" json:"content"`
	NoArgumentRewriters bool                      `yaml:"no_argument_rewriters" json:"no_argument_rewriters"`
	OperatorContext     map[string]any            `yaml:"operator_context" json:"operator_context"`
	Providers           map[string]ProviderConfig `yaml:"providers" json:"providers"`
	Bindings            []ConfiguredBinding       `yaml:"bindings" json:"bindings"`
	State               StateConfig               `yaml:"state" json:"state"`
	digest              string
	userOwned           bool
}

// ProviderConfig adds protected credential paths to the non-secret wire profile.
type ProviderConfig struct {
	Profile   `yaml:",inline"`
	TokenFile string `yaml:"token_file" json:"token_file"`
	CAFile    string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
}

// ConfiguredBinding attaches a policy source and compiled snapshot to its settings.
type ConfiguredBinding struct {
	decision.Binding `yaml:",inline"`
	PolicyFile       string             `yaml:"policy_file" json:"policy_file"`
	Provider         string             `yaml:"provider" json:"provider"`
	Compiled         *decision.Compiled `yaml:"-" json:"-"`
}

// StateConfig bounds the logical retained evidence, not bbolt's physical file
// size or secure erasure of pages.
type StateConfig = decision.ContextLimits

// LoadConfig validates enabled bindings without reading credentials or state.
// Disabled bindings remain uncompiled. Callers must not mutate a loaded config
// while using its digest, compiled policies or provider factories.
func LoadConfig(path string, allowUserOwned bool) (*Config, error) {
	raw, err := readProtected(path, 512<<10, allowUserOwned, false)
	if err != nil {
		return nil, fmt.Errorf("decision configuration: %w", err)
	}
	c := &Config{
		InstallationID: "local", BudgetMS: 1000, Content: "redacted", userOwned: allowUserOwned,
		State: StateConfig{MaxSessions: 128, MaxCalls: 64, MaxBytes: 32 << 20, IdleTTLMS: 3600000},
	}
	if err := decision.DecodeYAML(raw, c); err != nil {
		return nil, fmt.Errorf("decision configuration: %w", err)
	}
	if c.Version != "1" {
		return nil, errors.New("decision configuration version must be \"1\"")
	}
	if !c.Enabled {
		return c, nil
	}
	if c.InstallationID == "" || strings.TrimSpace(c.InstallationID) != c.InstallationID || len(c.InstallationID) > 128 {
		return nil, errors.New("installation_id must contain 1..128 bytes without surrounding whitespace")
	}
	if c.BudgetMS < 1 || c.BudgetMS > 8000 {
		return nil, errors.New("budget_ms must be between 1 and 8000 for native hooks")
	}
	if c.Content != "raw" && c.Content != "redacted" {
		return nil, errors.New("content must be redacted or raw")
	}
	if len(c.Bindings) < 1 || len(c.Bindings) > 16 {
		return nil, errors.New("bindings must contain 1..16 entries")
	}
	if len(c.Providers) > 16 {
		return nil, errors.New("providers must contain at most 16 entries")
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
	seen := map[string]bool{}
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if !b.Enabled {
			continue
		}
		p, ok := c.Providers[b.Provider]
		if !ok {
			return nil, fmt.Errorf("bindings[%d].provider must name a configured provider", i)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("bindings[%d].provider: %w", i, err)
		}
		if !absolutePath(p.TokenFile) || (p.CAFile != "" && !absolutePath(p.CAFile)) {
			return nil, fmt.Errorf("bindings[%d].provider: token_file and optional ca_file must be absolute clean paths", i)
		}
		if b.BudgetMS > c.BudgetMS {
			return nil, fmt.Errorf("bindings[%d].budget_ms must not exceed the global budget_ms", i)
		}
		raw, err := readProtected(b.PolicyFile, 512<<10, allowUserOwned, false)
		if err != nil {
			return nil, fmt.Errorf("bindings[%d].policy_file: %w", i, err)
		}
		b.Compiled, err = decision.LoadPolicy(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("bindings[%d].policy_file: %w", i, err)
		}
		// Always bind requests and configuration identity to the loaded policy,
		// even when the operator has not supplied an optional change-control pin.
		if b.PolicySHA256 == "" {
			b.PolicySHA256 = b.Compiled.Digest()
		}
		if err := b.Validate(b.Compiled); err != nil {
			return nil, fmt.Errorf("bindings[%d]: %w", i, err)
		}
		minimum, err := requestBody(p.Profile, b.Compiled.Policy(), json.RawMessage(`{}`))
		if err != nil || len(minimum) > b.MaxRequestBytes {
			return nil, fmt.Errorf("bindings[%d].max_request_bytes is smaller than the policy request envelope", i)
		}
		key := b.Compiled.Policy().ID + "\x00" + b.View
		if seen[key] {
			return nil, fmt.Errorf("bindings[%d]: duplicate decision policy and view", i)
		}
		seen[key] = true
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		return nil, errors.New("invalid decision configuration encoding")
	}
	sum := sha256.Sum256(canonical)
	c.digest = hex.EncodeToString(sum[:])
	return c, nil
}

func absolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func (c *Config) Digest() string { return c.digest }

// EnforcementBlockers reports configuration prerequisites only. An empty list
// does not establish host activation, final arguments, complete input, a valid
// model response, or successful output delivery.
func (c *Config) EnforcementBlockers(b ConfiguredBinding) []string {
	var reasons []string
	if c == nil || !c.Enabled {
		reasons = append(reasons, "configuration disabled")
	}
	if !b.Enabled {
		reasons = append(reasons, "binding disabled")
	}
	if !b.SendContent {
		reasons = append(reasons, "send_content not authorized")
	}
	if b.Mode != decision.Enforce {
		reasons = append(reasons, "binding not in enforce mode")
	}
	if b.Compiled == nil {
		reasons = append(reasons, "policy not validated")
	} else if !b.Compiled.Policy().Enforce {
		reasons = append(reasons, "policy enforce is false")
	}
	if c == nil || !c.NoArgumentRewriters {
		reasons = append(reasons, "no_argument_rewriters not asserted")
	}
	return reasons
}

// Factory reads credentials only after Run has selected a policy and bounded
// the invocation. It never consults environment variables or retries providers.
func (c *Config) Factory(name string) Factory {
	return func(profile Profile) (Provider, error) {
		p, ok := c.Providers[name]
		if !ok || p.Profile != profile {
			return nil, errors.New("decision provider identity mismatch")
		}
		token, err := readProtected(p.TokenFile, 4096, c.userOwned, true)
		if err != nil {
			return nil, err
		}
		h, err := NewHTTP(profile, strings.TrimSpace(string(token)))
		if err != nil {
			return nil, err
		}
		if p.CAFile != "" {
			pem, err := readProtected(p.CAFile, 128<<10, c.userOwned, false)
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
