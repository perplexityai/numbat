package main

import (
	"strings"
	"testing"
)

func TestDecisionsHelpAndArguments(t *testing.T) {
	for _, args := range [][]string{
		{"help", "decisions", "check"},
		{"decisions", "check", "--help"},
		{"decisions", "--help"},
	} {
		out, stderr, code := runCLI(args...)
		if code != 0 || !strings.Contains(out+stderr, "usage: numbat decisions check") {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out, stderr)
		}
	}
	for _, args := range [][]string{
		{"decisions"},
		{"decisions", "unknown"},
		{"decisions", "check"},
		{"decisions", "digest"},
		{"decisions", "check", "--config", "unused", "extra"},
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
