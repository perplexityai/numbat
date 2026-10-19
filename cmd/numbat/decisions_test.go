package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecisionsHelpAndArguments(t *testing.T) {
	for _, action := range []string{"check", "digest"} {
		for _, args := range [][]string{
			{"help", "decisions", action},
			{"decisions", action, "--help"},
		} {
			out, stderr, code := runCLI(args...)
			if code != 0 || !strings.Contains(out+stderr, "usage: numbat decisions "+action) {
				t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out, stderr)
			}
		}
	}
	for _, args := range [][]string{
		{"decisions"},
		{"decisions", "unknown"},
		{"decisions", "check"},
		{"decisions", "digest"},
		{"decisions", "check", "--config", "unused", "extra"},
		{"decisions", "digest", "--policy", "unused", "extra"},
		{"decisions", "digest", "--policy", "unused", "--decision-user-config"},
	} {
		out, stderr, code := runCLI(args...)
		if code != 2 || out != "" || stderr == "" {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out, stderr)
		}
	}
}

func TestOldDecisionCommandDoesNotReportSuccess(t *testing.T) {
	out, stderr, code := runCLI("hook", "decision-check", "--policy", "unused.yaml")
	if code != 2 || out != "" || !strings.Contains(stderr, "moved to: numbat decisions") {
		t.Fatalf("old command silently succeeded: exit=%d stdout=%q stderr=%q", code, out, stderr)
	}
}

func TestDecisionDigestIsCanonicalAndScriptable(t *testing.T) {
	const policy = `id: local.transfer
version: "1"
title: Transfer
severity: high
decision:
  select: 'event.event_type == "tool.call"'
  instructions: Classify only the pending action.
  options:
    prohibited: Prohibited by operator policy.
    unknown: Insufficient evidence.
  match_option: prohibited
  abstain_option: unknown
`
	path := filepath.Join(t.TempDir(), "policy.yaml")
	var digest string
	for _, text := range []string{policy, "# Formatting is not policy identity.\n" + strings.Replace(policy, `version: "1"`, "version: 1", 1)} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		out, stderr, code := runCLI("decisions", "digest", "--policy", path)
		if code != 0 || stderr != "" || len(out) != 65 || strings.Trim(out, "0123456789abcdef\n") != "" {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, stderr)
		}
		if digest != "" && out != digest {
			t.Fatal("formatting or equivalent version spelling changed canonical policy digest")
		}
		digest = out
	}
}
