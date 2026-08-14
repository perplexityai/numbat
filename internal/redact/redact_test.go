package redact

import (
	"net/url"
	"strings"
	"testing"
)

func TestStringMasksKnownTokens(t *testing.T) {
	cases := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		"xoxb-123456789012-abcdefABCDEF",
		"sk-abcdefghijklmnopqrstuvwxyz0123",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, c := range cases {
		got := String("value: " + c)
		if strings.Contains(got, c) {
			t.Fatalf("token not masked: %q -> %q", c, got)
		}
		if !strings.Contains(got, Mask) {
			t.Fatalf("mask absent for %q -> %q", c, got)
		}
	}
}

// Assignment forms preserve their key/delimiter shape while masking values.
func TestStringMasksAssignments(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		leaks  string // substring that must NOT survive
		prefix string // expected key shape preserved at the start
	}{
		{"unquoted", "API_KEY=supersecretvalue123", "supersecretvalue123", "API_KEY="},
		{"double-quoted multiword", `PASSWORD="hunter two three"`, "hunter two three", `PASSWORD="`},
		{"single-quoted multiword", `PASSWORD='hunter two three'`, "hunter two three", `PASSWORD='`},
		{"json", `{"api_key":"supersecretvalue123"}`, "supersecretvalue123", `"api_key":"`},
		{"json with spaces", `{"api_key": "super secret value"}`, "super secret value", `"api_key"`},
		{"yaml colon space", "secret_token: value with spaces", "value with spaces", "secret_token"},
		{"access key", "AWS_ACCESS_KEY=AKIAEXAMPLE12345678", "AKIAEXAMPLE12345678", "AWS_ACCESS_KEY="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.leaks) {
				t.Fatalf("value leaked: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
			if c.prefix != "" && !strings.Contains(got, c.prefix) {
				t.Fatalf("key shape not preserved: want prefix %q in %q", c.prefix, got)
			}
		})
	}
}

func TestStringMasksCredentialAfterLongAssignmentPrefix(t *testing.T) {
	in := strings.Repeat("ordinary=value ", 4096) + "api_key=final-secret"
	got := String(in)
	if strings.Contains(got, "final-secret") || !strings.Contains(got, "ordinary=value") {
		t.Fatalf("long-prefix masking failed")
	}
}

func TestStringMasksWhitespaceObfuscatedCredentialKey(t *testing.T) {
	in := "api" + strings.Repeat(" ", 256) + "_key=final-secret"
	got := String(in)
	if strings.Contains(got, "final-secret") || !strings.Contains(got, Mask) {
		t.Fatalf("whitespace-obfuscated credential was not masked")
	}
}

// TestStringMasksMultipleSecrets ensures every secret in one string is masked.
func TestStringMasksMultipleSecrets(t *testing.T) {
	in := `PASSWORD="a b c" and API_KEY=xyz123 and token ghp_0123456789abcdefghijklmnopqrstuvwxyz`
	got := String(in)
	for _, leak := range []string{"a b c", "xyz123", "ghp_0123456789abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(got, leak) {
			t.Fatalf("secret leaked %q in %q", leak, got)
		}
	}
}

func TestStringMasksCredentialNestedInEarlierValueSpan(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		secrets []string
	}{
		{"quoted nested", `api_key=FIRST_SECRET token="SECOND_SECRET"`, []string{"FIRST_SECRET", "SECOND_SECRET"}},
		{"padded quoted nested", `api_key=FIRST_SECRET token = "SECOND_SECRET"`, []string{"FIRST_SECRET", "SECOND_SECRET"}},
		{"padded quoted", `token = "SECOND_SECRET"`, []string{"SECOND_SECRET"}},
		{"single quoted", `token=   'SECOND_SECRET'`, []string{"SECOND_SECRET"}},
		{"encoded padding", `token=%20"SECOND_SECRET"`, []string{"SECOND_SECRET"}},
		{"angle wrapped nested", `api_key=FIRST_SECRET token=<SECOND_SECRET>`, []string{"FIRST_SECRET", "SECOND_SECRET"}},
		{"unquoted nested", `api_key=FIRST_SECRET token=SECOND_SECRET`, []string{"FIRST_SECRET", "SECOND_SECRET"}},
		{"delimited", `token=FIRST_SECRET&api_key=SECOND_SECRET;password=THIRD_SECRET`, []string{"FIRST_SECRET", "SECOND_SECRET", "THIRD_SECRET"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.input)
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Fatalf("credential %q survived: %q -> %q", secret, tt.input, got)
				}
			}
		})
	}
}

func TestStringMasksCredentialAfterRepeatedTargetAssignments(t *testing.T) {
	const secret = "TAIL_SECRET"
	in := strings.Repeat("token=value ", 8192) + `token = "` + secret + `"`
	got := String(in)
	if strings.Contains(got, secret) {
		t.Fatalf("trailing credential survived")
	}
	if !strings.Contains(got, Mask) {
		t.Fatal("mask absent")
	}
	if len(got) >= len(in) {
		t.Fatalf("overlapping credential spans were not coalesced")
	}
}

// TestStringPreservesStructure verifies redaction does not eat trailing JSON
// structure after an unquoted-looking value.
func TestStringPreservesStructure(t *testing.T) {
	got := String(`{"api_key":"secretval","user":"alice"}`)
	if !strings.Contains(got, `"user":"alice"`) {
		t.Fatalf("trailing structure damaged: %q", got)
	}
	if strings.Contains(got, "secretval") {
		t.Fatalf("value leaked: %q", got)
	}
}

func TestStringLeavesBenignText(t *testing.T) {
	in := "the agent read main.go and ran go build"
	if got := String(in); got != in {
		t.Fatalf("benign text changed: %q -> %q", in, got)
	}
}

// TestStringKnownFalseNegatives documents secret shapes redaction does NOT
// catch today. These assertions lock current behavior so a future redaction
// change that starts (or stops) catching them is an intentional, reviewed edit.
func TestStringKnownFalseNegatives(t *testing.T) {
	cases := []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // bare AWS secret access key, no key= prefix
	}
	for _, c := range cases {
		if got := String(c); !strings.Contains(got, c) {
			t.Fatalf("behavior changed (now masked) for known false negative %q -> %q", c, got)
		}
	}
}

func TestStringMasksURLUserinfo(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"postgres://user:p4ssw0rd@host:5432/db", "postgres://user:***@host:5432/db"},
		{"redis://user:pa:ss@cache.example/0", "redis://user:***@cache.example/0"},
		{"amqp://user:p@ss@broker.example/vhost", "amqp://user:***@broker.example/vhost"},
		{"postgres://user:p!$&'()*+,;=ss@db.example/app", "postgres://user:***@db.example/app"},
		{"postgres://user:secret@db.example:5432;ops@example.com", "postgres://user:***@db.example:5432;ops@example.com"},
		{"redis://user:secret@cache.example:6379,admin@example.com", "redis://user:***@cache.example:6379,admin@example.com"},
		{"postgres://user:secret@db.example:5432&owner@example.com", "postgres://user:***@db.example:5432&owner@example.com"},
		{"https://user:secret@[2001:db8::1]/", "https://user:***@[2001:db8::1]/"},
		{
			"postgres://a:first@one.example/db redis://b:second@two.example/0",
			"postgres://a:***@one.example/db redis://b:***@two.example/0",
		},
	}
	for _, tt := range tests {
		if got := String(tt.in); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got := String(tt.want); got != tt.want {
			t.Errorf("String is not idempotent: %q -> %q", tt.want, got)
		}
	}
}

func TestStringURLUserinfoMaskRemainsParseable(t *testing.T) {
	got := String("postgres://user:secret@db.example/app")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", got, err)
	}
	if u.User == nil || u.Host != "db.example" {
		t.Fatalf("parsed URL lost userinfo or host: %#v", u)
	}
}

func TestStringPreservesURLWithoutUserinfo(t *testing.T) {
	tests := []string{
		"https://api.example:8443;user=ops@example.com",
		"api.example,https://api.example:8443,ops@example.com",
		"https://api.example:8443&user=ops@example.com",
		"https://api.example:8443 then ops@example.com",
		"https://[2001:db8::1]:8443/",
	}
	for _, in := range tests {
		if got := String(in); got != in {
			t.Errorf("String(%q) = %q", in, got)
		}
	}
}

func TestStringMasksAuthorizationCredentials(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Authorization: Bearer abcdef123456", "Authorization: Bearer " + Mask},
		{"Authorization: Bearer test", "Authorization: Bearer " + Mask},
		{"authorization=basic dXNlcjpwYXNz", "authorization=basic " + Mask},
		{`{"Authorization":"Bearer abcdef123456"}`, `{"Authorization":"Bearer ` + Mask + `"}`},
		{`headers["Authorization"] = "Bearer abcdef123456"`, `headers["Authorization"] = "Bearer ` + Mask + `"`},
		{"Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: Basic " + Mask},
	}
	for _, tt := range tests {
		if got := String(tt.in); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if got := String(tt.want); got != tt.want {
			t.Errorf("String is not idempotent: %q -> %q", tt.want, got)
		}
	}
	if got := String("Bearer abcdef123456"); got != "Bearer abcdef123456" {
		t.Errorf("unanchored bearer text changed: %q", got)
	}
}

// TestStringMasksPresignedURLParams covers the no-leak invariant for observed
// URLs: a presigned S3 URL embeds live credential and signature material in its
// query string, and none of it may survive redaction. The host, path, and
// benign params (algorithm, expiry) stay readable so the indicator is still
// actionable.
func TestStringMasksPresignedURLParams(t *testing.T) {
	url := "https://bucket.s3.amazonaws.com/key.txt?" +
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&" +
		"X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260603/us-east-1/s3/aws4_request&" +
		"X-Amz-Date=20260603T000000Z&X-Amz-Expires=900&" +
		"X-Amz-SignedHeaders=host&" +
		"X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789&" +
		"X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	got := String(url)
	leaks := []string{
		"abcdef0123456789abcdef0123456789",                        // signature
		"AKIAIOSFODNN7EXAMPLE/20260603/us-east-1/s3/aws4_request", // credential scope
		"AKIAIOSFODNN7EXAMPLE",                                    // bare access key id within it
		"FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789",              // security token
	}
	for _, leak := range leaks {
		if strings.Contains(got, leak) {
			t.Fatalf("credential material survived: %q in %q", leak, got)
		}
	}
	// Structure and benign params stay readable.
	for _, keep := range []string{"bucket.s3.amazonaws.com/key.txt", "X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Expires=900"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("over-redacted, lost %q in %q", keep, got)
		}
	}
}

// TestStringMasksTokenQueryParams covers the generic token-bearing query keys
// beyond the AWS family: access_token, token, sig, signature.
func TestStringMasksTokenQueryParams(t *testing.T) {
	cases := []struct {
		in, leak string
	}{
		{"https://api.example.com/v1?access_token=ya29.SECRETOAUTHVALUE123", "ya29.SECRETOAUTHVALUE123"},
		{"https://x.test/cb?token=eyJhbGciOiJSUzI1NiJ9.payload.sig", "eyJhbGciOiJSUzI1NiJ9.payload.sig"},
		{"https://blob.core.windows.net/c/b?sig=2Fr%2BliveSASsignature%3D", "2Fr%2BliveSASsignature%3D"},
		{"https://x.test/d?signature=deadbeefcafelivesig", "deadbeefcafelivesig"},
	}
	for _, c := range cases {
		got := String(c.in)
		if strings.Contains(got, c.leak) {
			t.Fatalf("token query value survived: %q -> %q", c.in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Fatalf("mask absent: %q -> %q", c.in, got)
		}
	}
}

func TestStringMasksCredentialQueryParams(t *testing.T) {
	cases := []struct {
		key  string
		leak string
	}{
		{"api_key", "generic-api-key-value"},
		{"apikey", "generic-apikey-value"},
		{"api-key", "generic-api-dash-key-value"},
		{"password", "generic-password-value"},
		{"passwd", "generic-passwd-value"},
		{"pwd", "generic-pwd-value"},
		{"client_secret", "generic-client-secret-value"},
		{"client-secret", "generic-client-dash-secret-value"},
		{"client_assertion", "generic-client-assertion-value"},
		{"auth", "generic-auth-value"},
		{"secret", "generic-secret-value"},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			in := "https://api.example/v1?" + c.key + "=" + c.leak + "&id=1"
			got := String(in)
			if strings.Contains(got, c.leak) {
				t.Fatalf("query credential leaked: %q -> %q", in, got)
			}
			if !strings.Contains(got, c.key+"="+Mask) || !strings.Contains(got, "&id=1") {
				t.Fatalf("query structure damaged: %q -> %q", in, got)
			}
		})
	}
}

// TestStringMasksURLQueryByExactKey verifies the masker is precise: it masks the
// VALUE of an exact credential-bearing key (case-insensitively) and nothing else
// — not a key that merely contains or is a prefix/suffix of a credential key,
// and not a path segment shaped like key=value.
func TestStringMasksURLQueryByExactKey(t *testing.T) {
	keep := []struct {
		name, in string
	}{
		{"path token segment", "https://example.test/path/token=abc123/file?foo=bar"},
		{"token suffix key", "https://x.test?mytoken=abc&foo=bar"},
		{"id_token key", "https://x.test?id_token=abceyJhbGci&foo=bar"},
		{"signature prefix key", "https://x.test?presignature=abc&foo=bar"},
	}
	for _, c := range keep {
		t.Run(c.name, func(t *testing.T) {
			if got := String(c.in); got != c.in {
				t.Fatalf("URL over-redacted: %q -> %q", c.in, got)
			}
		})
	}

	mask := []struct {
		name, in, leak string
	}{
		{"mixed-case signature", "https://x.test/d?X-Amz-SIGNATURE=deadbeefcafelivesig&foo=bar", "deadbeefcafelivesig"},
		{"mixed-case access_token", "https://api.test/v1?Access_Token=ya29.SECRETOAUTHVALUE123&x=1", "ya29.SECRETOAUTHVALUE123"},
	}
	for _, c := range mask {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.leak) {
				t.Fatalf("exact credential key not masked: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, "foo=bar") && !strings.Contains(got, "x=1") {
				t.Fatalf("benign param lost: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringMasksPresignedURLKeepsBenignParams strengthens the presigned-S3
// no-leak invariant: every credential value (signature, full credential scope
// incl. the AKIA id and aws4_request, security token) is masked while the
// algorithm, expiry, host, and path stay readable.
func TestStringMasksPresignedURLKeepsBenignParams(t *testing.T) {
	url := "https://bucket.s3.amazonaws.com/key.txt?" +
		"X-Amz-Algorithm=AWS4-HMAC-SHA256&" +
		"X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20260603/us-east-1/s3/aws4_request&" +
		"X-Amz-Date=20260603T000000Z&X-Amz-Expires=900&" +
		"X-Amz-SignedHeaders=host&" +
		"X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789&" +
		"X-Amz-Signature=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	got := String(url)
	for _, leak := range []string{
		"abcdef0123456789abcdef0123456789",
		"AKIAIOSFODNN7EXAMPLE/20260603/us-east-1/s3/aws4_request",
		"AKIAIOSFODNN7EXAMPLE",
		"aws4_request",
		"FwoGZXIvYXdzEXAMPLESECURITYTOKEN0123456789",
	} {
		if strings.Contains(got, leak) {
			t.Fatalf("credential material survived: %q in %q", leak, got)
		}
	}
	for _, keep := range []string{"bucket.s3.amazonaws.com/key.txt", "X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Expires=900", "X-Amz-SignedHeaders=host"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("over-redacted, lost %q in %q", keep, got)
		}
	}
}

// TestStringMasksURLInsideText ensures a presigned URL embedded in a larger
// command line is still scrubbed, without disturbing ordinary non-URL key=value
// text elsewhere on the line.
func TestStringMasksURLInsideText(t *testing.T) {
	in := `curl -o out.bin "https://x.test/d?X-Amz-Signature=livesig123&foo=bar" && echo done`
	got := String(in)
	if strings.Contains(got, "livesig123") {
		t.Fatalf("URL signature in command not masked: %q", got)
	}
	for _, keep := range []string{"curl -o out.bin", "foo=bar", "echo done"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("command structure damaged, lost %q: %q", keep, got)
		}
	}
}

// TestStringMasksMalformedURLQuery covers spans that do not parse as a URL (bad
// escape, bad port, unterminated IPv6 host). The structured fast path cannot be
// taken, so the value-driven safety pass must still mask the target value while
// leaving the benign param readable — a redaction path may never emit an
// unmasked credential, even for a malformed URL.
func TestStringMasksMalformedURLQuery(t *testing.T) {
	cases := []string{
		"https://x.test/%zz?token=abc&foo=bar",
		"https://x.test:badport/path?token=abc&foo=bar",
		"https://[::1/path?token=abc&foo=bar",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := String(in)
			if strings.Contains(got, "token=abc") {
				t.Fatalf("malformed-URL token value survived: %q -> %q", in, got)
			}
			if !strings.Contains(got, "foo=bar") {
				t.Fatalf("benign param lost: %q -> %q", in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", in, got)
			}
		})
	}
}

// TestStringMasksPercentEncodedKeys covers credential keys whose spelling is
// percent-encoded so the raw bytes don't match a target. The key is decoded
// before the exact-membership test, so the value is still masked.
func TestStringMasksPercentEncodedKeys(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"token", "https://x.test?tok%65n=abc"},
		{"access_token", "https://x.test?access%5Ftoken=abc"},
		{"x-amz-signature", "https://x.test?X-Amz%2dSignature=abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, "=abc") {
				t.Fatalf("percent-encoded credential key not masked: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringMasksDeepMultiEncodedKeys covers LEAK: a deeply multi-encoded
// credential key must collapse to its real spelling. The fixed-point decode
// loop (not a 5-cap) unwinds tok%252525252565n -> ... -> token, so the value is
// masked.
func TestStringMasksDeepMultiEncodedKeys(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"double-encoded token", "https://x.test?tok%2565n=abc&foo=bar"},
		{"double-encoded access_token", "https://x.test?access%255Ftoken=abc&foo=bar"},
		{"double-encoded x-amz-signature", "https://x.test?X-Amz%252dSignature=abc&foo=bar"},
		{"triple-encoded token", "https://x.test?tok%252565n=abc&foo=bar"},
		{"deep-encoded token", "https://x.test?tok%252525252565n=abc&foo=bar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, "=abc") || strings.Contains(got, "abc&") {
				t.Fatalf("multi-encoded credential key value survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, "foo=bar") {
				t.Fatalf("benign param lost: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringPreservesPercentEncodedNonTargetKey verifies decoding the key for
// matching does not reintroduce suffix/substring matches: my%74oken decodes to
// "mytoken", which is NOT an exact credential key, so its value is preserved.
func TestStringPreservesPercentEncodedNonTargetKey(t *testing.T) {
	in := "https://x.test?my%74oken=abc&foo=bar"
	if got := String(in); got != in {
		t.Fatalf("non-target percent-encoded key over-redacted: %q -> %q", in, got)
	}
}

// TestStringMasksURLQueryEdgeValues exercises a target key with an empty value,
// a repeated target key, a target key with no '=' at all, and an empty key —
// all must be handled without panic and without leaking.
func TestStringMasksURLQueryEdgeValues(t *testing.T) {
	t.Run("empty value", func(t *testing.T) {
		got := String("https://x.test?token=")
		if !strings.Contains(got, "token="+Mask) {
			t.Fatalf("empty-value target key not masked: %q", got)
		}
	})
	t.Run("repeated key", func(t *testing.T) {
		got := String("https://x.test?token=a&token=b")
		if strings.Contains(got, "token=a") || strings.Contains(got, "token=b") {
			t.Fatalf("repeated target key values survived: %q", got)
		}
	})
	t.Run("target key no equals", func(t *testing.T) {
		in := "https://x.test?token"
		if got := String(in); got != in {
			t.Fatalf("key without '=' altered: %q -> %q", in, got)
		}
	})
	t.Run("empty key", func(t *testing.T) {
		in := "https://x.test?=abc"
		if got := String(in); got != in {
			t.Fatalf("empty key altered: %q -> %q", in, got)
		}
	})
	t.Run("target key last param no trailing delim", func(t *testing.T) {
		got := String("https://x.test?foo=bar&token=abc")
		if strings.Contains(got, "token=abc") {
			t.Fatalf("trailing target value survived: %q", got)
		}
		if !strings.Contains(got, "foo=bar") {
			t.Fatalf("benign param lost: %q", got)
		}
	})
}

// TestStringMasksKeyAfterWhitespaceBoundary covers ASCII whitespace as a key
// left boundary, so a target key that immediately follows a
// space is detected and masked even with no '?'/'&'/';' before it
// ("foo signature=abc"). Whitespace is a boundary rather than strippable in-key
// noise, so a space SPLITTING a key ("to ken=") makes the candidate the run
// AFTER the space ("ken"), which is not a target — see
// TestStringPreservesWhitespaceSplitKey. A real key never contains a raw space;
// only an injected space does, and over- vs under-redaction there favors the
// boundary rule that fixes the bare-key leak.
func TestStringMasksKeyAfterWhitespaceBoundary(t *testing.T) {
	cases := []struct{ in, leak string }{
		{"foo signature=livesig123", "livesig123"},
		{"foo\tsignature=livesig123", "livesig123"},
		{"prefix token=livetoken456 trailing&foo=bar", "livetoken456"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.leak) {
				t.Fatalf("target key after whitespace boundary not masked: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
		})
	}
}

// Whitespace inside a credential key cannot hide its normalized spelling.
func TestStringMasksWhitespaceSplitKey(t *testing.T) {
	cases := []string{
		"https://x.test?to ken=secretval123&foo=bar",
		"https://x.test?tok en=secretval123&foo=bar",
		"https://x.test?to\tken=secretval123&foo=bar",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := String(in)
			if strings.Contains(got, "secretval123") {
				t.Fatalf("whitespace-split target value survived: %q -> %q", in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", in, got)
			}
			if !strings.Contains(got, "foo=bar") {
				t.Fatalf("benign param lost: %q -> %q", in, got)
			}
		})
	}
}

// TestStringMasksKeyAfterCRLFBoundary covers a target key immediately after a CR
// or LF, AND — under the normalization-aware
// model — a CR/LF SPLITTING a target key is stripped so the key normalizes to a
// member and is also masked. Both the leading-CRLF and the split-by-CRLF forms
// now mask; there is no longer a "preserved split key"
// case for target keys.
func TestStringMasksKeyAfterCRLFBoundary(t *testing.T) {
	cases := []string{
		"https://x.test?\ntoken=abc&foo=bar",               // leading LF before target key
		"https://x.test?\rtoken=abc&foo=bar",               // leading CR before target key
		"https://x.test?to\nken=abc&foo=bar",               // LF splits key -> token
		"https://x.test?to\rken=abc&foo=bar",               // CR splits key -> token
		"https://x.test?X-Amz-Sig\nnature=live123&foo=bar", // LF splits key -> x-amz-signature
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := String(in)
			for _, leak := range []string{"=abc", "abc&", "live123"} {
				if strings.Contains(got, leak) {
					t.Fatalf("target key around CRLF not masked: %q -> %q", in, got)
				}
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", in, got)
			}
			if !strings.Contains(got, "foo=bar") {
				t.Fatalf("benign param lost: %q -> %q", in, got)
			}
		})
	}
}

// TestStringMasksControlByteCorruptedKeys covers a leading or embedded ASCII
// control byte (NUL) in a credential key. normalizeKeyForMatch strips control
// bytes before the membership test, so the value is masked while the original
// (corrupted) key spelling is preserved in the output.
func TestStringMasksControlByteCorruptedKeys(t *testing.T) {
	cases := []string{
		"https://x.test?\x00token=abc&foo=bar",               // leading NUL
		"https://x.test?to\x00ken=abc&foo=bar",               // embedded NUL
		"https://x.test?X-Amz-Sig\x00nature=live123&foo=bar", // embedded NUL in AWS key
		"https://x.test?\x01\x02signature=live123",           // multiple control bytes
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got := String(in)
			for _, leak := range []string{"=abc", "abc&", "live123"} {
				if strings.Contains(got, leak) {
					t.Fatalf("control-byte-corrupted key value survived: %q -> %q", in, got)
				}
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", in, got)
			}
		})
	}
}

// TestStringPreservesNonTargetCorruptedKeys is the anti-over-redaction guard: an
// UNCORRUPTED non-target key (or one whose only transform is percent-decoding to
// a non-member) stays a non-member after normalization, so its value is
// preserved.
//
// NOTE the deliberate boundary of this guard: a non-target key corrupted by an
// INJECTED whitespace/control byte (e.g. "my\x00token") is intentionally NOT
// listed here. Such a byte collapses to the wsMarker, and candidateIsTarget reads
// the marker both as removable noise AND as a soft boundary (the run after it,
// "token", is a member), so it over-masks. That is the accepted cost of closing
// the encoded-boundary leak class (foo=A%20token=) under the no-leak invariant:
// over-masking an adversarially corrupted non-target key beats any chance of a
// surviving target value. The clean "mytoken"/"my%74oken" forms below still
// preserve because they contain no marker.
func TestStringPreservesNonTargetCorruptedKeys(t *testing.T) {
	cases := []string{
		"https://x.test?mytoken=abc&foo=bar",
		"https://x.test?id_token=abceyJhbGci&foo=bar",
		"https://x.test?presignature=abc&foo=bar",
		"https://x.test?token_type=bearer&foo=bar",
		"https://x.test?my%74oken=abc&foo=bar",             // decodes to mytoken
		"https://x.test?my%2574oken=abc&foo=bar",           // double-encodes to mytoken
		"https://example.test/path/token=abc/file?foo=bar", // path segment ('/' not a boundary), no target query key
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := String(in); got != in {
				t.Fatalf("non-target key over-redacted: %q -> %q", in, got)
			}
		})
	}
}

// TestStringMasksSecondURLOnLine covers LEAK: a second URL on the same line. The
// value-driven pass does not depend on isolating a single URL span, so a target
// key in the second URL is masked while the first URL's benign params and the
// surrounding prose are preserved.
func TestStringMasksSecondURLOnLine(t *testing.T) {
	in := "first https://a.test?foo=1 then https://b.test?token=abc&bar=2 done"
	got := String(in)
	if strings.Contains(got, "token=abc") {
		t.Fatalf("token in second URL survived: %q -> %q", in, got)
	}
	for _, keep := range []string{"first", "foo=1", "then", "bar=2", "done"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("benign content lost %q: %q -> %q", keep, in, got)
		}
	}
}

// TestStringMasksSemicolonSeparatedParams covers LEAK: ';'-separated query
// params. ';' is both a key-start separator (so a target key after ';' matches)
// and a value terminator (so a masked value stops at ';' and the following param
// survives).
func TestStringMasksSemicolonSeparatedParams(t *testing.T) {
	t.Run("token after semicolon", func(t *testing.T) {
		got := String("https://x.test?foo=bar;token=abc")
		if strings.Contains(got, "token=abc") {
			t.Fatalf("';'-separated token value survived: %q", got)
		}
		if !strings.Contains(got, "foo=bar") {
			t.Fatalf("benign param lost: %q", got)
		}
	})
	t.Run("signature after semicolon", func(t *testing.T) {
		got := String("https://x.test?foo=bar;X-Amz-Signature=abc")
		if strings.Contains(got, "Signature=abc") {
			t.Fatalf("';'-separated signature value survived: %q", got)
		}
		if !strings.Contains(got, "foo=bar") {
			t.Fatalf("benign param lost: %q", got)
		}
	})
	t.Run("semicolon param after token preserved", func(t *testing.T) {
		got := String("https://x.test?token=abc;foo=bar")
		if strings.Contains(got, "token=abc") {
			t.Fatalf("token value survived: %q", got)
		}
		if !strings.Contains(got, ";foo=bar") {
			t.Fatalf("trailing ';foo=bar' not preserved: %q", got)
		}
	})
}

// TestStringMasksSecretInFragment covers LEAK: a credential after a '#fragment'.
// The value-driven pass scans the whole input, so a target key inside the
// fragment is masked. ('#' is a value terminator, so a fragment that follows a
// masked value also bounds it.)
func TestStringMasksSecretInFragment(t *testing.T) {
	got := String("https://x.test#frag?token=abc&foo=bar")
	if strings.Contains(got, "token=abc") {
		t.Fatalf("token in fragment survived: %q", got)
	}
	if !strings.Contains(got, "foo=bar") {
		t.Fatalf("benign param lost: %q", got)
	}
}

// TestStringMasksSpaceInValue covers LEAK: a raw space inside an unquoted value
// followed by more query. No part of "abc def" may survive, and the trailing
// "&foo=bar" is preserved (the value ends at '&', not at the space).
func TestStringMasksSpaceInValue(t *testing.T) {
	in := "https://x.test?token=abc def&foo=bar"
	got := String(in)
	for _, leak := range []string{"abc", "def", "abc def"} {
		if strings.Contains(got, leak) {
			t.Fatalf("space-separated value fragment survived %q: %q -> %q", leak, in, got)
		}
	}
	if !strings.Contains(got, "&foo=bar") {
		t.Fatalf("trailing param after spaced value lost: %q -> %q", in, got)
	}
}

// TestStringMasksValueThroughSpaceNoClamp locks the no-first-word-clamp
// behavior. A space is not a value terminator, so a target value runs through
// spaces to the next terminator or end-of-line. WHY no clamp: clamping to the
// first word left a tail — "token=abc def" masked only "abc" and LEAKED "def",
// which is still part of the value when the space was injected. The cost is
// over-masking trailing prose in the rare unterminated case
// ("token=abc and tell bob"); the owner accepts over-mask over any leak. A real
// following param survives because '&' IS a terminator.
func TestStringMasksValueThroughSpaceNoClamp(t *testing.T) {
	t.Run("space then end-of-line masks fully", func(t *testing.T) {
		in := "token=abc def"
		got := String(in)
		for _, leak := range []string{"abc", "def", "abc def"} {
			if strings.Contains(got, leak) {
				t.Fatalf("value fragment survived past space %q: %q -> %q", leak, in, got)
			}
		}
		if !strings.Contains(got, "token="+Mask) {
			t.Fatalf("value not masked: %q -> %q", in, got)
		}
	})
	t.Run("unterminated prose over-masked, not leaked", func(t *testing.T) {
		in := "see https://x.test?token=abc and tell bob about it"
		got := String(in)
		for _, leak := range []string{"abc", "token=abc", "abc and"} {
			if strings.Contains(got, leak) {
				t.Fatalf("value/prose tail survived %q: %q -> %q", leak, in, got)
			}
		}
		if !strings.Contains(got, "token="+Mask) {
			t.Fatalf("value not masked: %q -> %q", in, got)
		}
	})
	t.Run("ampersand param preserved after spaced value", func(t *testing.T) {
		in := "https://x.test?token=abc def&foo=bar"
		got := String(in)
		for _, leak := range []string{"abc", "def", "abc def"} {
			if strings.Contains(got, leak) {
				t.Fatalf("spaced value fragment survived %q: %q -> %q", leak, in, got)
			}
		}
		if !strings.Contains(got, "&foo=bar") {
			t.Fatalf("trailing &param lost: %q -> %q", in, got)
		}
	})
}

// TestStringMasksFragmentAfterQuery ensures a URL fragment following the query
// is handled without panic and bounds the masked value at '#'.
func TestStringMasksFragmentAfterQuery(t *testing.T) {
	got := String("https://x.test/p?token=abc#section")
	if strings.Contains(got, "token=abc") {
		t.Fatalf("token value survived before fragment: %q", got)
	}
	if !strings.Contains(got, "#section") {
		t.Fatalf("fragment lost: %q", got)
	}
}

// TestStringMasksSecretInsideAndOutsideURL covers a secret present both as a
// non-URL assignment and inside a URL query in the same string: both must be
// masked and benign structure preserved.
func TestStringMasksSecretInsideAndOutsideURL(t *testing.T) {
	// The URL token is the LAST param and is terminated by '&' before the benign
	// trailing param, so masking stops at '&' (no clamp needed) and "done"
	// survives as a real following query param rather than swallowed prose.
	in := "API_KEY=topsecret123 then fetch https://x.test?token=livetoken456&done=1"
	got := String(in)
	for _, leak := range []string{"topsecret123", "livetoken456"} {
		if strings.Contains(got, leak) {
			t.Fatalf("secret survived: %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "&done=1") {
		t.Fatalf("trailing param lost: %q", got)
	}
}

// TestStringMasksKeyAtAnyLeftBoundary proves a target key is detected at any
// left boundary, not just after '?'/'&'/';'. Each case below would leak if the
// scanner only walked back to query separators.
func TestStringMasksKeyAtAnyLeftBoundary(t *testing.T) {
	cases := []struct{ name, in, leak string }{
		{"bare sig at start of string", "sig=livesigvalue", "livesigvalue"},
		{"bare token at start of string", "token=livetokenvalue", "livetokenvalue"},
		{"signature after a space", "foo signature=livesigvalue", "livesigvalue"},
		{"x-amz-signature after fragment", "https://x.test#x-amz-signature=livesigvalue", "livesigvalue"},
		{"access_token after fragment", "https://x.test/callback#access_token=livetokenvalue", "livetokenvalue"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.leak) {
				t.Fatalf("target value at left boundary survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringMasksFragmentTargetPreservesTokenType also guards the maximal-run
// rule: in "#access_token=secret&token_type=bearer"
// the access_token VALUE must be masked (key after '#') while token_type — a
// non-member whose maximal run is "token_type", not a bare "token" — is fully
// preserved (key AND value).
func TestStringMasksFragmentTargetPreservesTokenType(t *testing.T) {
	in := "https://x.test#access_token=secretoauthvalue&token_type=bearer"
	got := String(in)
	if strings.Contains(got, "secretoauthvalue") {
		t.Fatalf("access_token value survived: %q -> %q", in, got)
	}
	if !strings.Contains(got, "token_type=bearer") {
		t.Fatalf("non-target token_type masked or damaged: %q -> %q", in, got)
	}
}

// TestStringMasksQuoteStartValues proves that when the value begins with a
// quote/bracket/backslash, the inner secret is fully masked. The surrounding
// quote/bracket may remain.
func TestStringMasksQuoteStartValues(t *testing.T) {
	cases := []struct{ name, in, leak string }{
		{"double-quoted", `token="abcsecret"`, "abcsecret"},
		{"single-quoted", `token='abcsecret'`, "abcsecret"},
		{"backtick-quoted", "token=`abcsecret`", "abcsecret"},
		{"angle-bracketed", "token=<abcsecret>", "abcsecret"},
		{"backslash-led", `token=\abcsecret`, "abcsecret"},
		{"empty value", "token=", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if c.leak != "" && strings.Contains(got, c.leak) {
				t.Fatalf("quote-start value survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, "token="+Mask) && !strings.Contains(got, "token=\""+Mask) &&
				!strings.Contains(got, "token='"+Mask) && !strings.Contains(got, "token=`"+Mask) &&
				!strings.Contains(got, "token=<"+Mask) && !strings.Contains(got, "token=\\"+Mask) {
				t.Fatalf("value not masked in place: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringMasksAdversarialKeyLayouts covers the layouts the task requires the
// fix to withstand: repeated separators, double '=', back-to-back target params,
// and an encoded terminator inside the value (a literal '&' terminates; '%26'
// does not, so the whole encoded value is masked to the next LITERAL terminator).
func TestStringMasksAdversarialKeyLayouts(t *testing.T) {
	cases := []struct {
		name, in     string
		leaks, keeps []string
	}{
		{
			"double question mark", "https://x.test??token=abcsecret&foo=bar",
			[]string{"abcsecret"},
			[]string{"foo=bar"},
		},
		{
			"question-then-amp", "https://x.test?&token=abcsecret&foo=bar",
			[]string{"abcsecret"},
			[]string{"foo=bar"},
		},
		{
			"double semicolon", "https://x.test?foo=bar;;token=abcsecret",
			[]string{"abcsecret"},
			[]string{"foo=bar"},
		},
		{
			"double equals", "https://x.test?token==abcsecret&foo=bar",
			[]string{"abcsecret"},
			[]string{"foo=bar"},
		},
		{
			"back-to-back targets", "https://x.test?token=aaaa&sig=bbbb",
			[]string{"aaaa", "bbbb"},
			nil,
		},
		{
			"encoded ampersand in value", "https://x.test?token=ab%26cd&foo=bar",
			[]string{"ab%26cd", "ab", "cd"},
			[]string{"foo=bar"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			for _, leak := range c.leaks {
				if strings.Contains(got, leak) {
					t.Fatalf("adversarial value survived %q: %q -> %q", leak, c.in, got)
				}
			}
			for _, keep := range c.keeps {
				if !strings.Contains(got, keep) {
					t.Fatalf("benign content lost %q: %q -> %q", keep, c.in, got)
				}
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
		})
	}
}

// Key, boundary, and wrapper decisions all use normalized bytes.
func TestStringMasksNormalizationLeakClasses(t *testing.T) {
	const secret = "normalization-secret-value-123"
	cases := []struct {
		name, in string
	}{
		// Whitespace inside a target key.
		{"space in key", "https://x.test?to ken=" + secret + "&foo=bar"},
		{"tab in key", "https://x.test?to\tken=" + secret + "&foo=bar"},
		{"cr in key", "https://x.test?to\rken=" + secret + "&foo=bar"},
		{"lf in key", "https://x.test?to\nken=" + secret + "&foo=bar"},
		// Deep percent encoding.
		{"21-deep encoding", "https://x.test?tok%252525252525252525252525252525252525252565n=" + secret + "&foo=bar"},
		// Encoded boundaries before a target key.
		{"encoded & boundary", "https://x.test?foo=A%26token=" + secret + "&bar=2"},
		{"encoded # boundary", "https://x.test?foo=A%23token=" + secret + "&bar=2"},
		{"encoded ; boundary", "https://x.test?foo=A%3Btoken=" + secret + "&bar=2"},
		{"encoded space boundary", "https://x.test?foo=A%20token=" + secret + "&bar=2"},
		{"double-encoded & boundary", "https://x.test?foo=A%2526token=" + secret + "&bar=2"},
		// Leading wrapper runs.
		{"leading >", "https://x.test?token=>" + secret + "&bar=2"},
		{"leading double quote run", "https://x.test?token=\"\"" + secret + "&bar=2"},
		{"leading quote then >", "https://x.test?token='>" + secret + "&bar=2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, secret) {
				t.Fatalf("normalization leak survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
		})
	}
}

// Interior marker windows and encoded equals retain correct raw mask offsets.
func TestStringMasksInteriorSegmentAndEncodedEqualsLeakClasses(t *testing.T) {
	const secret = "INTERIOR_SEGMENT_SECRET_VALUE_DO_NOT_LEAK"
	cases := []struct {
		name, in string
	}{
		// Leak 1: a target member between two normalized sentinels. Candidate is
		// `foo<ws>token<ws>`; the member `token` is the interior segment, not the
		// whole-removed `footoken` nor the empty suffix after the last marker.
		{"interior-segment token", "https://x.test?foo token =" + secret + "&bar=2"},
		// Leak 2: a mixed-normalization member straddling interior sentinels.
		// `foo=A%20acce%09ss%255ftoken` normalizes to `a<ws>acce<ws>ss_token`; the
		// suffix after the FIRST marker removes to the member `access_token`.
		{"interior-segment access_token", "https://x.test?foo=A%20acce%09ss%255ftoken=" + secret + "&bar=2"},
		// Leak 3: '=' present only after one decode (`%3d`) with a leading wrapper.
		// The value must mask past the WHOLE escape, not start inside it.
		{"encoded = depth1 then >", "https://x.test?token%3d>" + secret + "&bar=2"},
		// Leak 3: two-deep encoded '=' (`%253d`).
		{"encoded = depth2 then >", "https://x.test?token%253d>" + secret + "&bar=2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, secret) {
				t.Fatalf("interior/encoded-equals leak survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, "bar=2") {
				t.Fatalf("benign trailing param lost: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringMasksWrapperSplitEqualsAndPlusLeakClasses guards three edge leak
// classes: a single leading wrapper byte as the whole value, a split encoded '=',
// and '+' as injected whitespace inside a target key.
func TestStringMasksWrapperSplitEqualsAndPlusLeakClasses(t *testing.T) {
	cases := []struct {
		name, in, secret string
	}{
		{"leading-wrapper-byte value", "https://x.test?token=>&bar=2", ">"},
		{"split encoded =", "https://x.test?token%3%00dSPLIT_ENCODED_EQUALS_SECRET&bar=2", "SPLIT_ENCODED_EQUALS_SECRET"},
		{"plus-as-space split key", "https://x.test?to+ken=PLUS_SPACE_SECRET&bar=2", "PLUS_SPACE_SECRET"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.secret) {
				t.Fatalf("wrapper/split-equals/plus leak survived: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", c.in, got)
			}
			if !strings.Contains(got, "bar=2") {
				t.Fatalf("benign trailing param lost: %q -> %q", c.in, got)
			}
		})
	}
}

// TestStringSegmentWindowMatrix exercises the contiguous-segment-window matcher
// across single, interior, and overlapping wsMarker layouts for every target key
// so the window logic keeps recognizing members split or surrounded by markers.
func TestStringSegmentWindowMatrix(t *testing.T) {
	targets := []string{
		"x-amz-signature", "x-amz-credential", "x-amz-security-token",
		"access_token", "token", "sig", "signature",
	}
	const secret = "SEGWINDOWsecret0123456789"
	seps := []string{" ", "+", "%20", "\t", "%09", "\x00", "%00"}
	for _, key := range targets {
		for _, sep := range seps {
			layouts := []string{
				"https://x.test?" + key + "=" + secret + "&bar=2",                    // bare
				"https://x.test?foo=A" + sep + key + "=" + secret + "&bar=2",         // suffix window after boundary
				"https://x.test?pre" + sep + key + sep + "post=" + secret + "&bar=2", // interior window
			}
			for _, in := range layouts {
				got := String(in)
				if strings.Contains(got, secret) {
					t.Fatalf("segment-window value survived (key %q sep %q): %q -> %q", key, sep, in, got)
				}
				if !strings.Contains(got, Mask) {
					t.Fatalf("mask absent (key %q sep %q): %q -> %q", key, sep, in, got)
				}
			}
		}
	}
}

// Encoded equals at several depths preserve the full raw-end offset.
func TestStringRawEndMatrix(t *testing.T) {
	const secret = "RAWENDsecret0123456789"
	wrappers := []string{"", "\"", "'", "`", "<", ">", "\\"}
	for depth := 1; depth <= 20; depth++ {
		eq := encodedEqualsAtDepth(depth)
		// Depth-1 split form: a control byte between the two hex digits of `%3d`.
		split := ""
		if depth == 1 {
			split = "%3\x00d"
		}
		for _, w := range wrappers {
			forms := []string{"https://x.test?token" + eq + w + secret + "&bar=2"}
			if split != "" {
				forms = append(forms, "https://x.test?token"+split+w+secret+"&bar=2")
			}
			for _, in := range forms {
				got := String(in)
				if strings.Contains(got, secret) {
					t.Fatalf("raw-end value survived (depth %d wrapper %q): %q -> %q", depth, w, in, got)
				}
				if !strings.Contains(got, Mask) {
					t.Fatalf("mask absent (depth %d wrapper %q): %q -> %q", depth, w, in, got)
				}
			}
		}
	}
}

// TestStringInvalidPercentAndBoundaryMatrix confirms malformed percent forms and
// double-encoded boundaries do not panic and do not leak: invalid escapes stay
// literal (so a non-target key is preserved) while encoded boundaries before a
// target key still resolve to a masked value.
func TestStringInvalidPercentAndBoundaryMatrix(t *testing.T) {
	const secret = "INVALIDPCTsecret0123456789"
	// Invalid percent forms inside a NON-target key must leave it readable.
	for _, bad := range []string{"%", "%2", "%zz", "%g0", "%3+d"} {
		in := "https://x.test?myto" + bad + "ken=val&bar=2"
		got := String(in)
		if !strings.Contains(got, "bar=2") {
			t.Fatalf("benign param lost on invalid percent %q: %q -> %q", bad, in, got)
		}
	}
	// Double-encoded boundary before a target key still masks.
	for _, bnd := range []string{"%2526", "%252523", "%25253b"} {
		in := "https://x.test?foo=A" + bnd + "token=" + secret + "&bar=2"
		got := String(in)
		if strings.Contains(got, secret) {
			t.Fatalf("double-encoded boundary leaked: %q -> %q", in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Fatalf("mask absent: %q -> %q", in, got)
		}
	}
}

// TestStringCombinedLayoutMatrix stacks every leak vector at once — encoded
// boundary + split key + encoded key bytes + encoded/split '=' + leading wrapper
// + trailing benign param — and asserts the credential never survives.
func TestStringCombinedLayoutMatrix(t *testing.T) {
	const secret = "COMBINEDsecret0123456789"
	cases := []string{
		// encoded '&' boundary, '+'-split key, encoded '=' depth1, leading '>'.
		"https://x.test?foo=A%26to+ken%3d>" + secret + "&bar=2",
		// encoded space boundary, control-split key, split encoded '=', wrapper run.
		"https://x.test?foo=A%20acce\x00ss_token%3\x00d\"\"" + secret + "&bar=2",
		// double-encoded boundary, encoded key bytes, '+'-as-space, single wrapper.
		"https://x.test?foo=A%2526x-amz-sig%6eature=>" + secret + "&bar=2",
	}
	for _, in := range cases {
		got := String(in)
		if strings.Contains(got, secret) {
			t.Fatalf("combined-layout value survived: %q -> %q", in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Fatalf("mask absent: %q -> %q", in, got)
		}
		if !strings.Contains(got, "bar=2") {
			t.Fatalf("benign trailing param lost: %q -> %q", in, got)
		}
	}
}

// Every target key is recognized in an interior marker-delimited segment.
func TestStringMasksInteriorSentinelSegments(t *testing.T) {
	targets := []string{
		"x-amz-signature", "x-amz-credential", "x-amz-security-token",
		"access_token", "token", "sig", "signature",
	}
	const secret = "INTERIORSENTINELsecret0123456789"
	ws := []struct{ raw, enc string }{
		{" ", "%20"}, {"\t", "%09"}, {"\r", "%0D"}, {"\n", "%0A"}, {"\x00", "%00"},
	}
	for _, key := range targets {
		for _, w := range ws {
			for _, sep := range []string{w.raw, w.enc} {
				in := "https://x.test?foo" + sep + key + sep + "junk=" + secret + "&bar=2"
				got := String(in)
				if strings.Contains(got, secret) {
					t.Fatalf("interior-sentinel value survived: %q -> %q", in, got)
				}
				if !strings.Contains(got, Mask) {
					t.Fatalf("mask absent: %q -> %q", in, got)
				}
			}
		}
	}
}

// TestStringMasksEncodedEqualsAtDepth is the focused property table for the
// encoded-'=' offset class: the '=' between key and value is percent-encoded to
// depths 1..30, optionally behind each leading wrapper byte, and the credential
// value must never survive. Without carrying the raw END of
// the decoded '=' the mask would begin inside the escape and copy the secret tail.
func TestStringMasksEncodedEqualsAtDepth(t *testing.T) {
	const secret = "ENCODEDEQUALSsecret0123456789"
	wrappers := []string{"", "\"", "'", "`", "<", ">", "\\"}
	for depth := 1; depth <= 30; depth++ {
		eq := encodedEqualsAtDepth(depth)
		for _, w := range wrappers {
			in := "https://x.test?token" + eq + w + secret + "&bar=2"
			got := String(in)
			if strings.Contains(got, secret) {
				t.Fatalf("encoded-'=' value survived (depth %d wrapper %q): %q -> %q", depth, w, in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent (depth %d wrapper %q): %q -> %q", depth, w, in, got)
			}
			if !strings.Contains(got, "bar=2") {
				t.Fatalf("benign trailing param lost (depth %d wrapper %q): %q -> %q", depth, w, in, got)
			}
		}
	}
}

func TestStringMasksVeryDeepEncodedEquals(t *testing.T) {
	const depth = 10_000
	const secret = "DEEP_ENCODING_SECRET"
	equals := "%" + strings.Repeat("25", depth-1) + "3d"
	got := String("https://x.test?token" + equals + secret + "&bar=2")
	if strings.Contains(got, secret) || !strings.Contains(got, Mask) {
		t.Fatalf("deeply encoded credential was not masked")
	}
	if !strings.Contains(got, "bar=2") {
		t.Fatalf("trailing parameter was lost")
	}
}

func TestStringMasksTargetAfterManyMarkerSegments(t *testing.T) {
	const secret = "MARKER_SEGMENT_SECRET"
	in := "https://x.test?" + strings.Repeat("x ", 20_000) + "token=" + secret + "&bar=2"
	got := String(in)
	if strings.Contains(got, secret) || !strings.Contains(got, Mask) {
		t.Fatalf("marker-heavy credential was not masked")
	}
	if !strings.Contains(got, "bar=2") {
		t.Fatalf("trailing parameter was lost")
	}
}

func TestCredentialQueryKeysFitMatcherBound(t *testing.T) {
	for key := range credentialQueryKeys {
		if len(key) > maxCredentialQueryKeyLen {
			t.Fatalf("credential key %q exceeds matcher bound %d", key, maxCredentialQueryKeyLen)
		}
	}
}

// encodedEqualsAtDepth returns '=' percent-encoded depth times: depth 1 is "%3d",
// each further depth re-encodes the leading '%' as "%25" so the byte only resolves
// to '=' after exactly depth decode passes.
func encodedEqualsAtDepth(depth int) string {
	eq := "%3d"
	for d := 1; d < depth; d++ {
		eq = "%25" + eq[1:]
	}
	return eq
}

// TestStringMasksLeadingWrapperRuns proves that whatever the run of leading
// wrapper/terminator bytes after '=', the credential tail after it must never
// appear verbatim in the output.
func TestStringMasksLeadingWrapperRuns(t *testing.T) {
	const secret = "leadwrapsecret789"
	leads := []string{">", "\"\"", "'>", "\"'", "<<", "``", "\\\\", ">>>", "\"<'`>"}
	for _, lead := range leads {
		in := "https://x.test?token=" + lead + secret + "&bar=2"
		t.Run(lead, func(t *testing.T) {
			got := String(in)
			if strings.Contains(got, secret) {
				t.Fatalf("secret tail survived after leading wrapper run %q: %q -> %q", lead, in, got)
			}
			if !strings.Contains(got, Mask) {
				t.Fatalf("mask absent: %q -> %q", in, got)
			}
		})
	}
}

// Generated normalization variants must never expose a target credential value.
func TestStringMasksTargetKeyUnderNormalizationFuzz(t *testing.T) {
	targets := []string{
		"x-amz-signature", "x-amz-credential", "x-amz-security-token",
		"access_token", "token", "sig", "signature",
	}
	const secret = "FUZZSECRETvalue0123456789"
	assertMasked := func(t *testing.T, in string) {
		t.Helper()
		got := String(in)
		if strings.Contains(got, secret) {
			t.Fatalf("fuzz value survived: %q -> %q", in, got)
		}
		if !strings.Contains(got, Mask) {
			t.Fatalf("fuzz mask absent: %q -> %q", in, got)
		}
	}

	// (1) Inject a corrupting byte between every pair of key chars, raw and
	// percent-encoded. Each form must still normalize to the target.
	injections := []struct {
		name, raw, enc string
	}{
		{"space", " ", "%20"},
		{"tab", "\t", "%09"},
		{"cr", "\r", "%0D"},
		{"lf", "\n", "%0A"},
		{"nul", "\x00", "%00"},
	}
	for _, key := range targets {
		for _, inj := range injections {
			for pos := 1; pos < len(key); pos++ {
				rawSplit := key[:pos] + inj.raw + key[pos:]
				encSplit := key[:pos] + inj.enc + key[pos:]
				assertMasked(t, "https://x.test?"+rawSplit+"="+secret+"&foo=bar")
				assertMasked(t, "https://x.test?"+encSplit+"="+secret+"&foo=bar")
			}
		}
	}

	// (2) Percent-encode the whole key to depths 1..25. Depth 1 encodes each byte
	// as %XX; each further depth re-encodes the '%' of the previous depth as %25.
	for _, key := range targets {
		enc := percentEncodeAll(key)
		for depth := 1; depth <= 25; depth++ {
			assertMasked(t, "https://x.test?"+enc+"="+secret+"&foo=bar")
			enc = strings.ReplaceAll(enc, "%", "%25")
		}
	}

	// (3) Prefix the key with each boundary byte, literal and percent-encoded. The
	// encoded boundary must be decoded in the normalized view so the candidate is
	// the bare target, not boundary+target.
	boundaries := []struct{ ch, enc string }{
		{"&", "%26"},
		{";", "%3B"},
		{"#", "%23"},
		{"?", "%3F"},
		{" ", "%20"},
		{",", "%2C"},
		{"=", "%3D"},
	}
	for _, key := range targets {
		for _, bnd := range boundaries {
			assertMasked(t, "https://x.test?foo=A"+bnd.ch+key+"="+secret+"&bar=2")
			assertMasked(t, "https://x.test?foo=A"+bnd.enc+key+"="+secret+"&bar=2")
		}
	}

	// (4) Split the encoded '=' boundary with a removable control/space byte
	// between its two hex digits (`%3<noise>d`), raw and percent-encoded. The
	// decoder must consume the noise so '=' still materializes and the value path
	// runs.
	splitNoise := []string{"\x00", "%00", "\t", "%09", " ", "%20", "\r", "%0D", "\n", "%0A", "\x7f", "%7F"}
	for _, key := range targets {
		for _, n := range splitNoise {
			assertMasked(t, "https://x.test?"+key+"%3"+n+"d"+secret+"&bar=2")
		}
	}

	// (5) '+'-as-space at EVERY key position: between every pair of key chars (a
	// split key that must normalize back to the target) and as a soft boundary
	// before the key. Both must mask.
	for _, key := range targets {
		for pos := 1; pos < len(key); pos++ {
			assertMasked(t, "https://x.test?"+key[:pos]+"+"+key[pos:]+"="+secret+"&foo=bar")
		}
		assertMasked(t, "https://x.test?foo=A+"+key+"="+secret+"&bar=2")
	}

	// (6) Single-wrapper-byte values: when the entire value is one leading wrapper
	// byte, that byte must be masked, never preserved at the credential start.
	// Also the wrapper-byte-then-secret form.
	for _, key := range targets {
		for _, w := range []string{">", "<", "\"", "'", "`", "\\"} {
			assertMasked(t, "https://x.test?"+key+"="+w+secret+"&bar=2")
		}
	}
}

// percentEncodeAll percent-encodes every byte of s as %XX (depth-1 encoding) for
// the fuzz table's multi-depth generator.
func percentEncodeAll(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte('%')
		b.WriteByte(hex[s[i]>>4])
		b.WriteByte(hex[s[i]&0xF])
	}
	return b.String()
}

// FuzzString asserts the no-leak invariant on a generated target-key value. The
// input is reconstructed as prefix + "&token=" + secret + suffix: the leading
// '&' is a hard literal boundary that survives normalization no matter what the
// fuzzed prefix is, so the secret is ALWAYS genuinely the value of a bare member
// key "token" and "secret survived" is a true leak — never an artifact of the
// fuzzer relocating the secret or appending identifier bytes onto the key. The
// fuzzer freely mutates the surrounding bytes (and, via the second call, fully
// arbitrary text) to hunt for panics. Seeds start from adversarial normalization shapes;
// `go test -fuzz=FuzzString` explores outward. The leak property across the full
// key set, every injection position, and encoding depths 1..25 is covered
// deterministically by TestStringMasksTargetKeyUnderNormalizationFuzz.
func FuzzString(f *testing.F) {
	const secret = "FUZZsecretDoNotLeak42"
	seeds := []struct{ prefix, suffix string }{
		{"https://x.test?foo=1", "&bar=2"},
		{"https://x.test?foo=A%26", "&bar=2"},
		{"https://x.test#frag", ""},
		{"%zz?x=", "&sig=%"},
		{"", ">tail"},
	}
	for _, s := range seeds {
		f.Add(s.prefix, s.suffix)
	}
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		in := prefix + "&token=" + secret + suffix
		got := String(in) // must not panic
		if strings.Contains(got, secret) {
			t.Fatalf("secret survived redaction: %q -> %q", in, got)
		}
		for _, positioned := range []string{
			prefix + " postgres://user:" + secret + "@db.example/app " + suffix,
			prefix + "\nAuthorization: Bearer " + secret + "\n" + suffix,
		} {
			if got := String(positioned); strings.Contains(got, secret) {
				t.Fatalf("positioned secret survived redaction: %q -> %q", positioned, got)
			}
		}
		_ = String(prefix + suffix) // exercise arbitrary non-secret text for panics
	})
}

func TestStringIsDeterministic(t *testing.T) {
	in := "token: ghp_0123456789abcdefghijklmnopqrstuvwxyz and PASSWORD: hunter2hunter2"
	if String(in) != String(in) {
		t.Fatalf("redaction not deterministic")
	}
}

// TestStringNoPanicOnAdversarialInput throws a pile of malformed and hostile
// inputs at String to assert it never panics, regardless of how badly the URL,
// query, or encoding is mangled.
func TestStringNoPanicOnAdversarialInput(t *testing.T) {
	cases := []string{
		"",
		"=",
		"?=",
		"&&&",
		";;;",
		"?token=",
		"token=",
		"https://x.test?",
		"https://x.test?token=abc#frag?token=def&sig=ghi",
		"https://x.test?to\nken=\r\nabc def\tghi&token=%%%",
		"https://x.test?token=" + strings.Repeat("%25", 100) + "65n=abc",
		"%zz?token=%zz&sig=%",
		strings.Repeat("?token=abc&", 1000),
		"https://[::1]:99999/p?signature=\x00\x01\x02 end",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_ = String(in) // must not panic
		})
	}
}
