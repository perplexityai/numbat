package main

import (
	"path/filepath"
	"testing"
)

func TestMuseHookDecisionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, lifecycle, payload string
		enforce, deny            bool
	}{
		{"monitor", "pre-tool", `{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}"}`, false, false},
		{"enforce", "pre-tool", `{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}"}`, true, true},
		{"post", "post-tool", `{"hook_event_name":"PostToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}","tool_response":"{\"exit_code\":0}"}`, true, false},
		{"malformed", "pre-tool", `{bad`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeEnforceRuleFile(t, criticalEnforceRule)
			args := []string{
				"hook", tc.lifecycle, "--agent", "muse", "--rules-dir", dir,
				"--no-builtin-rules", "--output", "file", "--output-file", filepath.Join(t.TempDir(), "records.ndjson"),
			}
			if tc.enforce {
				args = append(args, "--enforce")
			}
			out, stderr, code := runCLIStdin(tc.payload, args...)
			if code != 0 || (decodeDecision(t, out) == "deny") != tc.deny {
				t.Fatalf("exit=%d output=%q stderr=%q want deny=%v", code, out, stderr, tc.deny)
			}
		})
	}
}
