package evaluator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/rule"
)

func loadTestProvider(t *testing.T, p ProviderConfig) (*Config, error) {
	t.Helper()
	raw, err := json.Marshal(struct {
		Version  string         `json:"version"`
		Provider ProviderConfig `json:"provider"`
	}{"1", p})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runtimePrivateDir(t), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestProviderCredentialSelection(t *testing.T) {
	file := filepath.Join(runtimePrivateDir(t), "absent.token")
	for _, tc := range []struct {
		name, file, env string
		valid           bool
	}{
		{"file", file, "", true},
		{"environment", "", "NUMBAT_TEST_DECISION_TOKEN", true},
		{"neither", "", "", false},
		{"both", file, "NUMBAT_TEST_DECISION_TOKEN", false},
		{"relative file", "relative.token", "", false},
		{"template", "", "${DO_NOT_ECHO}", false},
		{"assignment", "", "DO_NOT_ECHO=value", false},
		{"numeric prefix", "", "1DO_NOT_ECHO", false},
		{"hyphen", "", "DO_NOT_ECHO-KEY", false},
		{"space", "", "DO_NOT_ECHO KEY", false},
		{"non ASCII", "", "DO_NOT_ECHO_é", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ProviderConfig{Profile: invocation(t).Profile, TokenFile: tc.file, TokenEnv: tc.env}
			c, err := loadTestProvider(t, p)
			if (err == nil) != tc.valid || err != nil && strings.Contains(err.Error(), "DO_NOT_ECHO") {
				t.Fatalf("unexpected validation result: %v", err)
			}
			if tc.valid && c.Digest() == "" {
				t.Fatal("missing configuration identity")
			}
		})
	}
}

func TestEnvironmentCredentialsAreDeferredAndNotSerialized(t *testing.T) {
	const key = "NUMBAT_TEST_DECISION_TOKEN"
	t.Setenv(key, "")
	p := ProviderConfig{Profile: invocation(t).Profile, TokenEnv: key}
	c, err := loadTestProvider(t, p)
	if err != nil {
		t.Fatal("configuration must not require the credential:", err)
	}
	digest, profileDigest := c.Digest(), c.Provider.Digest()
	for _, token := range []string{"synthetic-token-first", "synthetic-token-second"} {
		t.Setenv(key, token)
		if _, err := c.Factory()(c.Provider.Profile); err != nil {
			t.Fatal("factory did not read the current credential:", err)
		}
		reloaded, err := loadTestProvider(t, p)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), token) || reloaded.Digest() != digest ||
			reloaded.Provider.Digest() != profileDigest {
			t.Fatal("resolved credential changed serialized configuration or identity")
		}
	}
}

func TestInvalidEnvironmentCredentialsCannotEvaluate(t *testing.T) {
	const key = "NUMBAT_TEST_DECISION_TOKEN"
	for _, tc := range []struct {
		name, value string
		unset       bool
	}{
		{"unset", "", true},
		{"empty", "", false},
		{"whitespace", " \t\n", false},
		{"oversized", strings.Repeat("x", maxTokenBytes+1), false},
		{"oversized before trimming", strings.Repeat(" ", maxTokenBytes) + "x", false},
		{"CRLF", "DO_NOT_ECHO\r\nX-Injected: value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(key, tc.value)
			if tc.unset {
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			in := invocation(t)
			c, err := loadTestProvider(t, ProviderConfig{Profile: in.Profile, TokenEnv: key})
			if err != nil {
				t.Fatal("configuration resolved the credential:", err)
			}
			if _, err := c.Factory()(in.Profile); err == nil || strings.Contains(err.Error(), "DO_NOT_ECHO") {
				t.Fatalf("missing or unsafe credential error: %v", err)
			}
			got := Run(context.Background(), in, c.Factory())
			if got.Status != "unavailable" || got.Matched || got.DenyCandidate {
				t.Fatalf("credential failure became a verdict: %+v", got)
			}
			raw, err := json.Marshal(got)
			if err != nil || strings.Contains(string(raw), "DO_NOT_ECHO") {
				t.Fatal("credential leaked into assessment:", err)
			}
		})
	}
}

func TestCredentialSourcesUseTheSameHTTPContract(t *testing.T) {
	for _, source := range []string{"file", "environment"} {
		t.Run(source, func(t *testing.T) {
			c, hits := runtimeConfig(t, func(body []byte) {
				for _, secret := range []string{"synthetic-token", "NUMBAT_TEST_DECISION_TOKEN"} {
					if strings.Contains(string(body), secret) {
						t.Error("credential or source leaked into inference evidence")
					}
				}
			})
			if source == "environment" {
				t.Setenv("NUMBAT_TEST_DECISION_TOKEN", "synthetic-token")
				c.Provider.TokenFile, c.Provider.TokenEnv = "", "NUMBAT_TEST_DECISION_TOKEN"
			}
			c, err := loadTestProvider(t, c.Provider)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.ConfigureRules([]rule.Rule{runtimeRule(decision.Action)}); err != nil {
				t.Fatal(err)
			}
			in := invocation(t)
			in.Policy, in.Binding, in.Profile = c.Rules[0].Compiled, c.Rules[0].Binding, c.Provider.Profile
			got := Run(context.Background(), in, c.Factory())
			if !got.DenyCandidate || hits.Load() != 1 {
				t.Fatalf("credential source %s failed: %+v, requests=%d", source, got, hits.Load())
			}
		})
	}
}
