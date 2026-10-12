package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONPreservesStructureWhileRedacting(t *testing.T) {
	raw := []byte(`{"total_token_usage":{"input_tokens":42},"time_to_first_token_ms":7,"access_tokens":"opaque-credential","otp_tokens":123456,"password_tokens":123456,"unsafe_token_usage":{"note":"opaque-credential"},"nested":{"api_key":"plain-secret","count":7},"text":"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`)
	got, err := JSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(got) {
		t.Fatalf("redacted JSON is invalid: %s", got)
	}
	if strings.Contains(string(got), "plain-secret") || strings.Contains(string(got), "ghp_") {
		t.Fatalf("redacted JSON leaked a secret: %s", got)
	}
	var value map[string]any
	if err := json.Unmarshal(got, &value); err != nil {
		t.Fatal(err)
	}
	usage, ok := value["total_token_usage"].(map[string]any)
	if !ok || usage["input_tokens"] != float64(42) || value["time_to_first_token_ms"] != float64(7) {
		t.Fatalf("token metrics = %#v / %#v", value["total_token_usage"], value["time_to_first_token_ms"])
	}
	if value["access_tokens"] != Mask || value["otp_tokens"] != Mask || value["password_tokens"] != Mask || value["unsafe_token_usage"] != Mask {
		t.Fatalf("credential fields = %#v / %#v / %#v / %#v", value["access_tokens"], value["otp_tokens"], value["password_tokens"], value["unsafe_token_usage"])
	}
	nested := value["nested"].(map[string]any)
	if nested["api_key"] != Mask || nested["count"] != float64(7) {
		t.Fatalf("nested value = %#v", nested)
	}
}

func TestJSONRejectsCredentialInObjectKey(t *testing.T) {
	raw := []byte(`{"ghp_abcdefghijklmnopqrstuvwxyz0123456789":"value"}`)
	if _, err := JSON(raw); err == nil || !strings.Contains(err.Error(), "object key") {
		t.Fatalf("JSON returned err %v, want unsafe-key rejection", err)
	}
}

func FuzzJSONProducesValidJSON(f *testing.F) {
	f.Add([]byte(`{"api_key":"secret","input_tokens":42}`))
	f.Add([]byte(`{"broken":`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := JSON(raw)
		if err == nil && !json.Valid(got) {
			t.Fatalf("JSON returned invalid output: %q", got)
		}
	})
}

func TestJSONRejectsMalformedAndTrailingValues(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"token":`),
		[]byte(`{"ok":true} {"extra":true}`),
	} {
		if _, err := JSON(raw); err == nil {
			t.Fatalf("JSON(%q) succeeded", raw)
		}
	}
}

func TestJSONCredentialFields(t *testing.T) {
	for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "auth", "credentials", "pwd"} {
		raw, err := json.Marshal(map[string]any{key: []string{"private"}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := JSON(raw)
		if err != nil || strings.Contains(string(got), "private") || !strings.Contains(string(got), Mask) {
			t.Fatalf("JSON(%s) = %s, %v", raw, got, err)
		}
	}
}
