//go:build unix

package evaluator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/rule"
)

func TestDocumentedConfigurationsAndRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "decision-evaluators.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```yaml\\n(.*?)\\n```").FindAllSubmatch(raw, -1)
	var configured *Config
	var rules []rule.Rule
	for _, block := range blocks {
		value := string(block[1])
		if strings.HasPrefix(value, "id:") {
			source, err := rule.LoadSource(strings.NewReader(value), "example.yaml")
			if err != nil {
				t.Fatal(err)
			}
			engine, err := rule.NewEngine([]rule.Source{source})
			if err != nil {
				t.Fatal(err)
			}
			rules = append(rules, engine.DecisionRules()...)
			continue
		}
		if strings.HasPrefix(value, "provider:") {
			value = "version: \"1\"\n" + value
		}
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		configured, err = LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if configured == nil || len(rules) == 0 {
		t.Fatal("missing executable examples")
	}
	if err := configured.ConfigureRules(rules); err != nil {
		t.Fatal(err)
	}
}

func configFixture(t *testing.T) (string, Config) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "config.yaml"), Config{
		Version: "1", InstallationID: "test", BudgetMS: 1000, TimeoutMS: 1000,
		MaxRequestBytes: 4096, Content: "raw",
		State: StateConfig{MaxSessions: 2, MaxCalls: 4, MaxBytes: 4096, IdleTTLMS: 10000},
		Provider: ProviderConfig{
			Profile:   Profile{Protocol: "decisions-v1", Endpoint: "https://provider.example/v1/decisions", Model: "test", MaxResponseBytes: 4096},
			TokenFile: filepath.Join(dir, "absent.token"),
		},
	}
}

func configRule() rule.Rule {
	enforce := true
	return rule.Rule{
		ID: "local.transfer", Version: "1", Title: "Transfer", Severity: "high", Enforce: &enforce,
		Decision: &rule.DecisionSpec{
			Select: `event.event_type == "tool.call"`, Instructions: "Classify the action.",
			Options:     map[string]string{"blocked": "Prohibited.", "unknown": "Insufficient evidence."},
			MatchOption: "blocked", AbstainOption: "unknown", View: decision.Session,
			MatchThreshold: .9, DenyThreshold: .99,
		},
	}
}

func writeConfigFixture(t *testing.T, path string, c Config) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationDefersCredentialsAndUsesOrdinaryRules(t *testing.T) {
	path, c := configFixture(t)
	writeConfigFixture(t, path, c)
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Rules) != 0 || loaded.Digest() == "" {
		t.Fatal("loading configuration must not invent or load a rule catalog")
	}
	r := configRule()
	if err := loaded.ConfigureRules([]rule.Rule{r}); err != nil {
		t.Fatal(err)
	}
	first := loaded.Rules[0]
	if len(loaded.EnforcementBlockers(first)) != 0 || first.PolicySHA256 != first.Compiled.Digest() ||
		first.BudgetMS != c.TimeoutMS || first.MaxRequestBytes != c.MaxRequestBytes || first.MaxHistoryCalls != 3 {
		t.Fatalf("wrong resolved rule: %+v", first)
	}
	r.Decision.Instructions = "Changed definition."
	if err := loaded.ConfigureRules([]rule.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if first.Compiled.Digest() == loaded.Rules[0].Compiled.Digest() {
		t.Fatal("rule identity ignored an instruction edit")
	}
	if _, err := loaded.Factory()(loaded.Provider.Profile); err == nil {
		t.Fatal("absent credential must fail only when initializing a provider")
	}
}

func TestConfigurationRejectsUnboundedOrInvalidSettings(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"budget":   func(c *Config) { c.BudgetMS = 9000 },
		"timeout":  func(c *Config) { c.TimeoutMS = -1 },
		"bytes":    func(c *Config) { c.MaxRequestBytes = 1 << 21 },
		"content":  func(c *Config) { c.Content = "DO_NOT_ECHO" },
		"state":    func(c *Config) { c.State.MaxCalls = 5000 },
		"endpoint": func(c *Config) { c.Provider.Endpoint = "http://example.test" },
		"token":    func(c *Config) { c.Provider.TokenFile = "relative" },
		"identity": func(c *Config) { c.InstallationID = " bad " },
	} {
		t.Run(name, func(t *testing.T) {
			path, c := configFixture(t)
			edit(&c)
			writeConfigFixture(t, path, c)
			_, err := LoadConfig(path)
			if err == nil || strings.Contains(err.Error(), "DO_NOT_ECHO") {
				t.Fatalf("unsafe or missing validation: %v", err)
			}
		})
	}
	path, c := configFixture(t)
	c.MaxRequestBytes = 32
	writeConfigFixture(t, path, c)
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.ConfigureRules([]rule.Rule{configRule()}); err == nil {
		t.Fatal("policy larger than request budget accepted")
	}
}

func TestProtectedConfigurationFiles(t *testing.T) {
	path, c := configFixture(t)
	writeConfigFixture(t, path, c)
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("writable configuration accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Provider.TokenFile, []byte("synthetic-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Factory()(loaded.Provider.Profile); err == nil {
		t.Fatal("world-readable credential accepted")
	}
}

func TestConfigurationDefaultsAndRemovedFields(t *testing.T) {
	path, c := configFixture(t)
	raw, _ := json.Marshal(c)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"installation_id", "budget_ms", "timeout_ms", "max_request_bytes", "content", "state"} {
		delete(fields, key)
	}
	raw, _ = json.Marshal(fields)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || got.InstallationID != "local" || got.BudgetMS != 1000 ||
		got.TimeoutMS != 1000 || got.Content != "redacted" || got.MaxRequestBytes != 128<<10 {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	for _, key := range []string{"bindings", "providers", "enabled", "send_content", "no_argument_rewriters"} {
		fields[key] = json.RawMessage("null")
		data, _ := json.Marshal(fields)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("obsolete field %q accepted", key)
		}
		delete(fields, key)
	}
}

func TestConfigurationYAMLErrorsDoNotEchoValues(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"version: '1'\nunknown: DO_NOT_ECHO\n", "unknown field"},
		{"version: '1'\nbudget_ms: DO_NOT_ECHO\n", "invalid field type"},
		{"version: '1'\nversion: DO_NOT_ECHO\n", "duplicate key"},
		{"version: '1'\n---\nversion: '1'", "one YAML document"},
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "DO_NOT_ECHO") {
			t.Fatalf("unsafe or unactionable diagnostic: %v", err)
		}
	}
}
