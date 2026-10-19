//go:build unix

package evaluator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/decision"
)

func configFixture(t *testing.T) (string, Config) {
	t.Helper()
	dir := t.TempDir()
	p := decision.Policy{
		ID: "local.transfer", Version: "1", Title: "Transfer", Severity: "high", Enforce: true,
		Decision: decision.Question{
			Select: `event.event_type == "tool.call"`, Instructions: "Classify the pending action.",
			Options:     map[string]string{"blocked": "Prohibited.", "unknown": "Insufficient evidence."},
			MatchOption: "blocked", AbstainOption: "unknown",
		},
	}
	compiled, err := decision.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	data, _ := json.Marshal(p)
	if err := os.WriteFile(policyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c := Config{
		Version: "1", Enabled: true, InstallationID: "test", BudgetMS: 1000, Content: "raw",
		NoArgumentRewriters: true,
		State:               StateConfig{MaxSessions: 2, MaxCalls: 4, MaxBytes: 4096, IdleTTLMS: 10000},
		Providers: map[string]ProviderConfig{"test": {
			Profile:   Profile{Protocol: "decisions-v1", Endpoint: "https://provider.example/v1/decisions", Model: "test", MaxResponseBytes: 4096},
			TokenFile: filepath.Join(dir, "absent.token"),
		}},
		Bindings: []ConfiguredBinding{{
			PolicyFile: policyPath, Provider: "test",
			Binding: decision.Binding{
				Enabled: true, SendContent: true, PolicySHA256: compiled.Digest(),
				View: decision.Session, Mode: decision.Enforce, MatchThreshold: .9, DenyThreshold: .99,
				BudgetMS: 1000, MaxRequestBytes: 4096, MaxHistoryCalls: 4,
			},
		}},
	}
	return filepath.Join(dir, "config.yaml"), c
}

func writeConfigFixture(t *testing.T, path string, c Config) {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationDefersCredentialRead(t *testing.T) {
	path, c := configFixture(t)
	writeConfigFixture(t, path, c)
	loaded, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.EnforcementBlockers(loaded.Bindings[0])) != 0 || loaded.Digest() == "" {
		t.Fatal("valid activation not retained")
	}
	if _, err := loaded.Factory("test")(loaded.Providers["test"].Profile); err == nil {
		t.Fatal("absent credential must fail only when provider is initialized")
	}
	loaded.Bindings[0].Enabled = false
	called := false
	a := Run(context.Background(), Invocation{Binding: loaded.Bindings[0].Binding}, func(Profile) (Provider, error) {
		called = true
		return nil, nil
	})
	if called || a.Reason != "disabled" {
		t.Fatal("disabled evaluator constructed a provider")
	}
}

func TestOptionalPolicyPinUsesLoadedPolicy(t *testing.T) {
	path, c := configFixture(t)
	writeConfigFixture(t, path, c)
	pinned, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	c.Bindings[0].PolicySHA256 = ""
	writeConfigFixture(t, path, c)
	unpinned, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if unpinned.Digest() != pinned.Digest() ||
		unpinned.Bindings[0].PolicySHA256 != pinned.Bindings[0].Compiled.Digest() {
		t.Fatal("automatic and explicit policy identities differ")
	}
	policy := pinned.Bindings[0].Compiled.Policy()
	policy.Decision.Instructions += " Apply the updated operator policy."
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Bindings[0].PolicyFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	updated, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Digest() == unpinned.Digest() ||
		updated.Bindings[0].PolicySHA256 == unpinned.Bindings[0].PolicySHA256 ||
		updated.Bindings[0].PolicySHA256 != updated.Bindings[0].Compiled.Digest() {
		t.Fatal("loaded policy change did not update its bound identity")
	}
	c.Bindings[0].PolicySHA256 = pinned.Bindings[0].PolicySHA256
	writeConfigFixture(t, path, c)
	if _, err := LoadConfig(path, true); err == nil {
		t.Fatal("explicit stale policy pin was ignored")
	}
}

func TestDisabledConfigurationDoesNotLoadReferencedFiles(t *testing.T) {
	path, c := configFixture(t)
	c.Enabled = false
	c.Bindings[0].PolicyFile = "/does/not/exist"
	writeConfigFixture(t, path, c)
	if _, err := LoadConfig(path, true); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedConfigurationFiles(t *testing.T) {
	path, c := configFixture(t)
	writeConfigFixture(t, path, c)
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link, true); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path, true); err == nil {
		t.Fatal("writable configuration accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := LoadConfig(path, false); err == nil {
			t.Fatal("user-owned configuration accepted without opt-in")
		}
	}
	token := c.Providers["test"].TokenFile
	if err := os.WriteFile(token, []byte("synthetic-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Factory("test")(loaded.Providers["test"].Profile); err == nil {
		t.Fatal("world-readable credential accepted")
	}
}

func TestConfigurationRejectsAmbiguousOrUnboundedActivation(t *testing.T) {
	tests := map[string]func(*Config){
		"budget":    func(c *Config) { c.BudgetMS = 9000 },
		"state":     func(c *Config) { c.State.MaxCalls = 100000 },
		"pin":       func(c *Config) { c.Bindings[0].PolicySHA256 = "wrong" },
		"duplicate": func(c *Config) { c.Bindings = append(c.Bindings, c.Bindings[0]) },
		"provider":  func(c *Config) { c.Bindings[0].Provider = "missing" },
		"envelope":  func(c *Config) { c.Bindings[0].MaxRequestBytes = 100 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			path, c := configFixture(t)
			change(&c)
			writeConfigFixture(t, path, c)
			if _, err := LoadConfig(path, true); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestConfigurationErrorsIdentifyFieldsWithoutEchoingValues(t *testing.T) {
	const sensitive = "DO_NOT_ECHO_OPERATOR_VALUE"
	tests := []struct {
		name   string
		change func(*Config)
		fields []string
	}{
		{"view", func(c *Config) { c.Bindings[0].View = sensitive }, []string{"bindings[0]", "view"}},
		{"mode", func(c *Config) { c.Bindings[0].Mode = sensitive }, []string{"bindings[0]", "mode"}},
		{"pin", func(c *Config) { c.Bindings[0].PolicySHA256 = sensitive }, []string{"bindings[0]", "policy_sha256"}},
		{"provider", func(c *Config) { c.Bindings[0].Provider = sensitive }, []string{"bindings[0]", "provider"}},
		{"budget", func(c *Config) { c.Bindings[0].BudgetMS = 1001 }, []string{"bindings[0]", "budget_ms"}},
		{"state", func(c *Config) { c.State.MaxCalls = 0 }, []string{"state", "max_calls"}},
		{"response", func(c *Config) {
			p := c.Providers["test"]
			p.MaxResponseBytes = 0
			c.Providers["test"] = p
		}, []string{"bindings[0]", "max_response_bytes"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, c := configFixture(t)
			tc.change(&c)
			writeConfigFixture(t, path, c)
			_, err := LoadConfig(path, true)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			for _, field := range tc.fields {
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("error %q does not identify %q", err, field)
				}
			}
			if strings.Contains(err.Error(), sensitive) {
				t.Fatalf("error disclosed a supplied value: %v", err)
			}
		})
	}
}

func TestConfigurationDefaultsAndExplicitZero(t *testing.T) {
	path, c := configFixture(t)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"installation_id", "budget_ms", "content", "no_argument_rewriters", "state"} {
		delete(fields, key)
	}
	write := func() {
		t.Helper()
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	got, err := LoadConfig(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallationID != "local" || got.BudgetMS != 1000 || got.Content != "redacted" ||
		got.NoArgumentRewriters || got.State != (StateConfig{MaxSessions: 128, MaxCalls: 64, MaxBytes: 32 << 20, IdleTTLMS: 3600000}) {
		t.Fatalf("unexpected defaults: %+v", got)
	}
	fields["budget_ms"] = json.RawMessage("0")
	write()
	if _, err := LoadConfig(path, true); err == nil || !strings.Contains(err.Error(), "budget_ms") {
		t.Fatalf("explicit zero budget accepted: %v", err)
	}
}

func TestConfigurationRejectsOldBindingFieldNames(t *testing.T) {
	for _, pair := range [][2]string{
		{"match_threshold", "match_probability"},
		{"deny_threshold", "deny_probability"},
		{"max_history_calls", "max_history_events"},
	} {
		t.Run(pair[1], func(t *testing.T) {
			path, c := configFixture(t)
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.Replace(string(raw), `"`+pair[0]+`"`, `"`+pair[1]+`"`, 1))
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path, true); err == nil {
				t.Fatal("obsolete field silently accepted")
			}
		})
	}
}

func TestConfigurationYAMLErrorsDoNotEchoValues(t *testing.T) {
	for _, tc := range []struct {
		body, want string
	}{
		{"version: '1'\nunknown: DO_NOT_ECHO\n", "unknown field"},
		{"version: '1'\nbudget_ms: DO_NOT_ECHO\n", "invalid field type"},
		{"version: '1'\nversion: DO_NOT_ECHO\n", "duplicate key"},
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig(path, true)
		if err == nil || !strings.Contains(err.Error(), "line 2") ||
			!strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "DO_NOT_ECHO") {
			t.Fatalf("unsafe or unactionable diagnostic: %v", err)
		}
	}
}

func TestEnforcementBlockersMatchConfigurationCapability(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"configured", func(*Config) {}, ""},
		{"global off", func(c *Config) { c.Enabled = false }, "configuration disabled"},
		{"binding off", func(c *Config) { c.Bindings[0].Enabled = false }, "binding disabled"},
		{"egress off", func(c *Config) { c.Bindings[0].SendContent = false }, "send_content not authorized"},
		{"monitor", func(c *Config) { c.Bindings[0].Mode = decision.Monitor }, "binding not in enforce mode"},
		{"finality", func(c *Config) { c.NoArgumentRewriters = false }, "no_argument_rewriters not asserted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, c := configFixture(t)
			tc.edit(&c)
			writeConfigFixture(t, path, c)
			got, err := LoadConfig(path, true)
			if err != nil {
				t.Fatal(err)
			}
			reasons := got.EnforcementBlockers(got.Bindings[0])
			if (tc.want == "" && len(reasons) != 0) ||
				(tc.want != "" && !strings.Contains(strings.Join(reasons, "; "), tc.want)) {
				t.Fatalf("reasons=%v want=%q", reasons, tc.want)
			}
		})
	}
}

func TestDocumentedDecisionExample(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "decision-evaluators.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Split(string(doc), "```yaml\n")
	if len(blocks) != 3 {
		t.Fatalf("expected one policy and one config YAML example, got %d", len(blocks)-1)
	}
	policy := strings.SplitN(blocks[1], "```", 2)[0]
	config := strings.SplitN(blocks[2], "```", 2)[0]
	if _, err := decision.LoadPolicy(strings.NewReader(policy)); err != nil {
		t.Fatalf("documented policy: %v", err)
	}
	dir := t.TempDir()
	policyPath, configPath := filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	config = strings.NewReplacer(
		"/etc/numbat/decision-policies/protected-transfer.yaml", policyPath,
		"/etc/numbat/credentials/decisions.token", filepath.Join(dir, "intentionally-absent.token"),
	).Replace(config)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(configPath, true)
	if err != nil {
		t.Fatalf("documented configuration: %v", err)
	}
	if len(c.Bindings) != 1 || c.Bindings[0].Mode != decision.Monitor || len(c.EnforcementBlockers(c.Bindings[0])) == 0 {
		t.Fatal("documented first-run example must stay monitor-only")
	}
}
