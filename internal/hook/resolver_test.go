package hook

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestResolverTimestamp(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"RFC3339", "2026-07-13T12:34:56.123Z", "2026-07-13T12:34:56.123Z"},
		{"Unix milliseconds", json.Number("1783946096123"), "2026-07-13T12:34:56.123Z"},
		{"Unix seconds", json.Number("1783946096"), "2026-07-13T12:34:56Z"},
		{"invalid", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := (resolver{payload: map[string]any{"timestamp": tc.value}}).timestamp()
			if got != tc.want {
				t.Fatalf("timestamp() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolverCodexSubagentIdentity(t *testing.T) {
	r := newResolver(AgentCodex, map[string]any{
		"session_id": "tree-1",
		"agent_id":   "child-1",
		"agent_type": "default",
	})
	if r.sessionID() != "child-1" || r.sessionTreeID() != "tree-1" || r.subAgentID() != "child-1" || r.subAgent() != "default" {
		t.Fatalf("Codex context = session %q tree %q id %q role %q", r.sessionID(), r.sessionTreeID(), r.subAgentID(), r.subAgent())
	}

	main := newResolver(AgentCodex, map[string]any{
		"session_id": "main-1",
		"agent_id":   "main-1",
	})
	if main.sessionID() != "main-1" || main.sessionTreeID() != "" || main.subAgentID() != "" || main.subAgent() != "" {
		t.Fatalf("Codex main context = session %q tree %q id %q role %q", main.sessionID(), main.sessionTreeID(), main.subAgentID(), main.subAgent())
	}

	claude := newResolver(AgentClaude, map[string]any{
		"session_id": "session-1",
		"agent_id":   "legacy-child",
	})
	if claude.sessionID() != "session-1" || claude.sessionTreeID() != "" || claude.subAgentID() != "" || claude.subAgent() != "legacy-child" {
		t.Fatalf("non-Codex semantics changed: session %q tree %q id %q role %q", claude.sessionID(), claude.sessionTreeID(), claude.subAgentID(), claude.subAgent())
	}
}

// TestResolverIntFromRejectsFractional is the Regression: a
// fractional exit_code / duration_ms / diff_bytes must NOT be truncated into a
// fabricated integer. A fractional value yields ok=false (field absent); an
// integral float (2.0), a real int, and an integer string still resolve, and a
// clean exit 0 stays distinct from absent.
func TestResolverIntFromRejectsFractional(t *testing.T) {
	resp := func(v any) resolver {
		return resolver{payload: map[string]any{"tool_response": map[string]any{
			"exit_code":   v,
			"duration_ms": v,
			"diff_bytes":  v,
		}}}
	}

	t.Run("fractional exit_code is absent", func(t *testing.T) {
		if code, ok := resp(1.7).exitCode(); ok {
			t.Fatalf("exitCode fabricated %d from 1.7; want ok=false", code)
		}
	})
	t.Run("fractional duration_ms is absent", func(t *testing.T) {
		if ms, ok := resp(0.5).durationMs(); ok {
			t.Fatalf("durationMs fabricated %d from 0.5; want ok=false", ms)
		}
	})
	t.Run("fractional diff_bytes is absent", func(t *testing.T) {
		if _, n, ok := resp(12.9).diff(); ok || n != 0 {
			t.Fatalf("diff fabricated %d bytes from 12.9; want ok=false, n=0", n)
		}
	})
	t.Run("fractional json.Number exit_code is absent", func(t *testing.T) {
		if code, ok := resp(json.Number("1.7")).exitCode(); ok {
			t.Fatalf("exitCode fabricated %d from json.Number 1.7; want ok=false", code)
		}
	})
	t.Run("fractional string exit_code is absent", func(t *testing.T) {
		if code, ok := resp("1.7").exitCode(); ok {
			t.Fatalf("exitCode fabricated %d from \"1.7\"; want ok=false", code)
		}
	})

	t.Run("integral float exit_code resolves", func(t *testing.T) {
		if code, ok := resp(2.0).exitCode(); !ok || code != 2 {
			t.Fatalf("exitCode = (%d, %v) from 2.0; want (2, true)", code, ok)
		}
	})
	t.Run("real int exit_code resolves", func(t *testing.T) {
		if code, ok := resp(float64(7)).exitCode(); !ok || code != 7 {
			t.Fatalf("exitCode = (%d, %v) from 7; want (7, true)", code, ok)
		}
	})
	t.Run("clean exit zero is distinct from absent", func(t *testing.T) {
		if code, ok := resp(float64(0)).exitCode(); !ok || code != 0 {
			t.Fatalf("exitCode = (%d, %v) from 0; want (0, true)", code, ok)
		}
		if _, ok := (resolver{payload: map[string]any{}}).exitCode(); ok {
			t.Fatalf("exitCode resolved from empty payload; want ok=false")
		}
	})
	t.Run("integral duration and diff still resolve", func(t *testing.T) {
		if ms, ok := resp(float64(1500)).durationMs(); !ok || ms != 1500 {
			t.Fatalf("durationMs = (%d, %v); want (1500, true)", ms, ok)
		}
		r := resolver{payload: map[string]any{"tool_response": map[string]any{
			"diff_sha256": testDiffSHA256,
			"diff_bytes":  float64(42),
		}}}
		if sha, n, ok := r.diff(); !ok || sha != testDiffSHA256 || n != 42 {
			t.Fatalf("diff = (%q, %d, %v); want (%q, 42, true)", sha, n, ok, testDiffSHA256)
		}
	})
}

func TestResolverDiffNormalizesIndependentFields(t *testing.T) {
	upperSHA := strings.ToUpper(testDiffSHA256)
	cases := []struct {
		name    string
		resp    map[string]any
		wantSHA string
		wantN   int
		wantOK  bool
	}{
		{"sha and bytes", map[string]any{"diff_sha256": testDiffSHA256, "diff_bytes": float64(12)}, testDiffSHA256, 12, true},
		{"uppercase sha", map[string]any{"diff_sha256": upperSHA, "diff_bytes": float64(12)}, testDiffSHA256, 12, true},
		{"sha only", map[string]any{"diff_sha256": testDiffSHA256}, testDiffSHA256, 0, true},
		{"bytes only", map[string]any{"diff_bytes": float64(12)}, "", 12, true},
		{"short sha with bytes", map[string]any{"diff_sha256": "abc", "diff_bytes": float64(12)}, "", 12, true},
		{"non-hex sha with bytes", map[string]any{"diff_sha256": strings.Repeat("z", 64), "diff_bytes": float64(12)}, "", 12, true},
		{"short sha only", map[string]any{"diff_sha256": "abc"}, "", 0, false},
		{"zero bytes only", map[string]any{"diff_bytes": float64(0)}, "", 0, false},
		{"negative bytes only", map[string]any{"diff_bytes": float64(-1)}, "", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := resolver{payload: map[string]any{"tool_response": c.resp}}
			sha, n, ok := r.diff()
			if sha != c.wantSHA || n != c.wantN || ok != c.wantOK {
				t.Fatalf("diff = (%q, %d, %v); want (%q, %d, %v)", sha, n, ok, c.wantSHA, c.wantN, c.wantOK)
			}
		})
	}
}

// TestResolverIntFromInt64Boundary is the Regression: a faithful
// 64-bit integer arriving as json.Number or an integer string must be preserved
// EXACTLY (parsed with integer APIs), not round-tripped through float64 where
// math.MaxInt64 collapses to a wrapped negative. A value one past max (2^63)
// must be absent rather than wrapped. The hook payload decoder uses UseNumber(),
// so top-level integers really do arrive as json.Number — the faithful path.
func TestResolverIntFromInt64Boundary(t *testing.T) {
	exit := func(v any) (int, bool) {
		return resolver{payload: map[string]any{"tool_response": map[string]any{"exit_code": v}}}.exitCode()
	}

	t.Run("max int64 json.Number is faithful", func(t *testing.T) {
		code, ok := exit(json.Number("9223372036854775807"))
		if !ok || int64(code) != 9223372036854775807 {
			t.Fatalf("exitCode = (%d, %v) from json.Number max-int64; want (9223372036854775807, true) — NOT a wrapped negative", code, ok)
		}
	})
	t.Run("max int64 string is faithful", func(t *testing.T) {
		code, ok := exit("9223372036854775807")
		if !ok || int64(code) != 9223372036854775807 {
			t.Fatalf("exitCode = (%d, %v) from string max-int64; want (9223372036854775807, true) — NOT a wrapped negative", code, ok)
		}
	})
	t.Run("min int64 json.Number is faithful", func(t *testing.T) {
		code, ok := exit(json.Number("-9223372036854775808"))
		if !ok || int64(code) != -9223372036854775808 {
			t.Fatalf("exitCode = (%d, %v) from json.Number min-int64; want (-9223372036854775808, true)", code, ok)
		}
	})
	t.Run("one past max json.Number is absent", func(t *testing.T) {
		if code, ok := exit(json.Number("9223372036854775808")); ok {
			t.Fatalf("exitCode fabricated %d from 2^63 (one past max); want ok=false", code)
		}
	})
	t.Run("one past max string is absent", func(t *testing.T) {
		if code, ok := exit("9223372036854775808"); ok {
			t.Fatalf("exitCode fabricated %d from 2^63 string; want ok=false", code)
		}
	})
	t.Run("2^63 float64 is absent (not wrapped)", func(t *testing.T) {
		// A genuine JSON float of exactly 2^63: the integral-float guard must use a
		// strict < against 2^63, else int64(2^63) wraps to math.MinInt64.
		if code, ok := exit(float64(1 << 63)); ok {
			t.Fatalf("exitCode fabricated %d from 2^63 float64; want ok=false (must not wrap to MinInt64)", code)
		}
	})
}

// TestResolverIntFromAsIntPlatformNarrow is the CodeQL go/incorrect-integer-conversion
// regression: the resolver fields model.Event carries (ExitCode *int, DiffBytes int)
// are platform int, so the int64 from intFrom is narrowed by intFromAsInt. A bare
// int(v) would truncate on a 32-bit build; the checked narrow must instead preserve
// any value that fits the platform int and report ABSENT (never a wrapped value) for
// one that does not. On the 64-bit build this runs on, a value above the 32-bit int
// range (math.MaxInt32+1) still fits int and so must be preserved faithfully.
func TestResolverIntFromAsIntPlatformNarrow(t *testing.T) {
	exit := func(v any) (int, bool) {
		return resolver{payload: map[string]any{"tool_response": map[string]any{"exit_code": v}}}.exitCode()
	}
	diffBytes := func(v any) (int, bool) {
		_, n, ok := resolver{payload: map[string]any{"tool_response": map[string]any{
			"diff_sha256": testDiffSHA256,
			"diff_bytes":  v,
		}}}.diff()
		return n, ok
	}

	const above32 = int64(math.MaxInt32) + 1 // 2147483648 — overflows a 32-bit int, fits a 64-bit int

	// On a 64-bit build (the CI matrix; int is int64) a value above the 32-bit
	// range fits the platform int and MUST be preserved faithfully — a bare int(v)
	// would have been fine here but is unsafe on 32-bit, which the guard subtest
	// below covers. On a 32-bit build the same value must be ABSENT, never wrapped.
	if math.MaxInt > math.MaxInt32 {
		t.Run("exit_code above 32-bit range is faithful on 64-bit int", func(t *testing.T) {
			code, ok := exit(json.Number("2147483648"))
			if !ok || int64(code) != above32 {
				t.Fatalf("exitCode = (%d, %v) from 2^31; want (%d, true) — preserved on 64-bit int, never truncated", code, ok, above32)
			}
		})
		t.Run("diff_bytes above 32-bit range is faithful on 64-bit int", func(t *testing.T) {
			n, ok := diffBytes(json.Number("2147483648"))
			if !ok || int64(n) != above32 {
				t.Fatalf("diff bytes = (%d, %v) from 2^31; want (%d, true) — preserved on 64-bit int, never truncated", n, ok, above32)
			}
		})
	} else {
		t.Run("exit_code above 32-bit range is absent on 32-bit int (not truncated)", func(t *testing.T) {
			if code, ok := exit(json.Number("2147483648")); ok {
				t.Fatalf("exitCode truncated %d from 2^31 on 32-bit int; want ok=false (absent, never wrapped)", code)
			}
		})
		t.Run("diff_bytes above 32-bit range is absent on 32-bit int (not truncated)", func(t *testing.T) {
			if n, ok := diffBytes(json.Number("2147483648")); ok {
				t.Fatalf("diff bytes truncated %d from 2^31 on 32-bit int; want ok=false (absent, never wrapped)", n)
			}
		})
	}
	t.Run("intFromAsInt guards the platform int bound", func(t *testing.T) {
		// A value that fits int64 but not the platform int must be reported absent,
		// never wrapped. math.MaxInt is the platform int max; one past it (as a
		// string, so intFrom parses it faithfully) must yield ok=false. On a 64-bit
		// build math.MaxInt == math.MaxInt64, so this exercises the int64 ceiling too.
		if math.MaxInt < math.MaxInt64 {
			// 32-bit platform: a value above MaxInt32 must be rejected by the narrow.
			if v, ok := intFromAsInt(map[string]any{"x": above32}, "x"); ok {
				t.Fatalf("intFromAsInt fabricated %d from a value past platform int max; want ok=false", v)
			}
		}
		// A value strictly past the platform int max is always absent.
		past := map[string]any{"x": json.Number("9223372036854775808")} // 2^63, past int64 and int
		if v, ok := intFromAsInt(past, "x"); ok {
			t.Fatalf("intFromAsInt fabricated %d from 2^63; want ok=false", v)
		}
		// A value exactly at the platform int max is preserved.
		atMax := map[string]any{"x": int64(math.MaxInt)}
		if v, ok := intFromAsInt(atMax, "x"); !ok || int64(v) != int64(math.MaxInt) {
			t.Fatalf("intFromAsInt = (%d, %v) at platform int max; want (%d, true)", v, ok, math.MaxInt)
		}
	})
}
