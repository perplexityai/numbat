package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/state"
	builtinrules "github.com/perplexityai/numbat/rules"
)

// These tests drive the live handler end to end with temporary rule files.

// shortDenyWriter accepts a deny prefix, then errors; later writes succeed.
type shortDenyWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *shortDenyWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		n := 8
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		return n, fmt.Errorf("short write: only %d of %d bytes accepted", n, len(p))
	}
	return w.buf.Write(p)
}

// partialDenyPanicWriter accepts a deny prefix, then panics before returning.
type partialDenyPanicWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *partialDenyPanicWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		n := 8
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		panic("injected panic mid deny write after a partial prefix")
	}
	return w.buf.Write(p)
}

// lyingProbePanicWriter under-reports bytes accepted before a panic.
type lyingProbePanicWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *lyingProbePanicWriter) bytesAccepted() int { return 0 }

func (w *lyingProbePanicWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		n := 8
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		panic("injected panic mid deny write; probe will lie about progress")
	}
	return w.buf.Write(p)
}

// countingWriter records output and the number of writes.
type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.buf.Write(p)
}

// byteZeroFailWriter fails its first write without committing bytes.
type byteZeroFailWriter struct {
	buf    bytes.Buffer
	writes int
}

func (w *byteZeroFailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return 0, fmt.Errorf("byte-zero write failure: nothing committed")
	}
	return w.buf.Write(p)
}

func writeEnforceRuleFile(t *testing.T, body string) string {
	t.Helper()
	setTestHome(t, t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enforce.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	return dir
}

func writeEnforceRuleFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	setTestHome(t, t.TempDir())
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write rule file %s: %v", name, err)
		}
	}
	return dir
}

func writeEnforcedBuiltinRule(t *testing.T, path string) string {
	t.Helper()
	body, err := builtinrules.FS.ReadFile(path)
	if err != nil {
		t.Fatalf("read embedded rule %s: %v", path, err)
	}
	const enabled = "enabled: true\n"
	if !strings.Contains(string(body), enabled) {
		t.Fatalf("embedded rule %s has no explicit enabled field", path)
	}
	return writeEnforceRuleFile(t, strings.Replace(string(body), enabled, enabled+"enforce: true\n", 1))
}

func enforceHookArgs(t *testing.T, args ...string) []string {
	t.Helper()
	args = append([]string(nil), args...)
	return append(args,
		"--output", "file",
		"--output-file", filepath.Join(t.TempDir(), "findings.ndjson"),
	)
}

const criticalEnforceRule = `id: enforce_test.critical_block
version: "1.0"
title: Critical enforce-eligible match
severity: critical
enforce: true
expr: |
  event.event_type == "command.exec" &&
  shell_commands.exists(command,
    command.name == "cat" &&
    command.argv.slice(1, command.argv.size()).exists(arg, arg == ".env")
  )
`

const mediumEnforceRule = `id: enforce_test.medium_block
version: "1.0"
title: Medium operator policy match
severity: medium
enforce: true
expr: |
  event.event_type == "command.exec" &&
  shell_commands.exists(command,
    command.name == "cat" &&
    command.argv.slice(1, command.argv.size()).exists(arg, arg == ".env")
  )
`

const defaultDenyMessage = "Action denied. Do not retry or attempt an equivalent action."

const customMessageEnforceRule = `id: enforce_test.custom_message
version: "1.0"
title: Custom deny message
severity: critical
enforce: true
deny_message: Contact the workspace owner.
expr: |
  event.event_type == "command.exec" &&
  shell_commands.exists(command,
    command.name == "cat" &&
    command.argv.slice(1, command.argv.size()).exists(arg, arg == ".env")
  )
`

func TestBuiltinOverrideCanEnableEnforcement(t *testing.T) {
	setTestHome(t, t.TempDir())
	payload := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"OVERRIDE_ONLY"}}`
	out, errb, code := runCLIStdin(payload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", "testdata/rules_dup")...)
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("same-id operator override did not deny: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestHookEnforceKeepsStatelessDenyWhenSequenceStateUnavailable(t *testing.T) {
	rulesDir := writeEnforceRuleFile(t, criticalEnforceRule)
	statePath := filepath.Join(t.TempDir(), "state.db")
	findings := filepath.Join(t.TempDir(), "findings.ndjson")
	lock, err := state.Open(statePath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	out, errb, code := runCLIStdin(
		`{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"cat .env"}}`,
		"hook", "pre-tool", "--agent", "claude", "--enforce",
		"--rules-dir", rulesDir, "--state-db", statePath,
		"--output", "file", "--output-file", findings,
	)
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("locked sequence state disabled a stateless deny: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if errb != "" {
		t.Fatalf("clean deny stderr leaked state diagnostics: %q", errb)
	}
	records, err := os.ReadFile(findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(records), "enforce_test.critical_block") {
		t.Fatalf("operator sink missing stateless finding: %s", records)
	}
	if !strings.Contains(string(records), `"record_type":"diagnostic"`) || !strings.Contains(string(records), "state database unavailable") {
		t.Fatalf("operator sink missing sequence-state diagnostic: %s", records)
	}
}

const sessionEndEnforceRule = `id: enforce_test.session_end_block
version: "1.0"
title: Critical session-end boundary match
severity: critical
enforce: true
expr: |
  event.event_type == "session.end"
`

const unconditionalEnforceRule = `id: enforce_test.unconditional_block
version: "1.0"
title: Unconditional enforce-eligible match
severity: critical
enforce: true
expr: |
  true
`

const criticalNoEnforceRule = `id: enforce_test.critical_no_enforce
version: "1.0"
title: Critical without enforce flag
severity: critical
expr: |
  event.event_type == "command.exec" && event.command.contains(".env")
`

const evalErrorEnforceRule = `id: enforce_test.eval_boom
version: "1.0"
title: Enforce-eligible rule that errors at eval
severity: critical
enforce: true
expr: |
  shell_commands.exists(command, command.argv[50] == "x")
`

const (
	catEnvPayload     = `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	sessionEndPayload = `{"session_id":"s-sub"}`
)

func decodeDecision(t *testing.T, out string) string {
	t.Helper()
	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("stdout %q is not valid JSON: %v", out, err)
	}
	return resp.HookSpecificOutput.PermissionDecision
}

func readHookRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid NDJSON record: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	return records
}

func enforcementRecord(t *testing.T, records []map[string]any) map[string]any {
	t.Helper()
	var found map[string]any
	for _, record := range records {
		if record["record_type"] != output.RecordEnforcement {
			continue
		}
		if found != nil {
			t.Fatal("multiple enforcement records for one hook callback")
		}
		found = record
	}
	if found == nil {
		t.Fatal("missing enforcement record")
	}
	return found
}

func assertAllow(t *testing.T, out string, code int) {
	t.Helper()
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != "{}" {
		t.Fatalf("stdout = %q, want the inert allow passthrough {}", got)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("response written on %d lines, want exactly 1", n)
	}
}

func TestNewAgentEnforcementContracts(t *testing.T) {
	rulesDir := writeEnforceRuleFile(t, criticalEnforceRule)
	tests := []struct {
		agent       string
		payload     string
		exitCode    int
		responseKey string
		responseVal string
	}{
		{agent: "openclaw", payload: `{"session_id":"t1","cwd":"/proj","tool_name":"exec","tool_input":{"command":"cat .env"}}`, responseKey: "block", responseVal: "true"},
		{agent: "pi", payload: `{"tool_name":"bash","tool_input":{"command":"cat .env"}}`, responseKey: "block", responseVal: "true"},
		{agent: "kimi", payload: catEnvPayload, exitCode: 2},
		{agent: "qwen", payload: catEnvPayload, exitCode: 2},
		{agent: "cline", payload: `{"hookName":"tool_call","taskId":"t1","workspaceRoots":["/proj"],"preToolUse":{"toolName":"execute_command","parameters":{"command":"cat .env"}}}`, responseKey: "cancel", responseVal: "true"},
		{agent: "amp", payload: `{"session_id":"t1","tool_name":"Bash","tool_input":{"command":"cat .env"}}`, responseKey: "action", responseVal: "reject-and-continue"},
		{agent: "auggie", payload: `{"session_id":"t1","tool_name":"launch-process","tool_input":{"command":"cat .env"}}`, exitCode: 2},
		{agent: "kiro", payload: `{"session_id":"t1","tool_name":"execute_bash","tool_input":{"command":"cat .env"}}`, exitCode: 2},
		{agent: "goose", payload: `{"session_id":"t1","working_dir":"/proj","tool_name":"developer__shell","tool_input":{"command":"cat .env"}}`, exitCode: 2},
		{agent: "kilo", payload: `{"session_id":"t1","cwd":"/proj","tool_name":"bash","tool_input":{"command":"cat .env"}}`, responseKey: "block", responseVal: "true"},
		{agent: "openhands", payload: `{"event_type":"PreToolUse","session_id":"t1","working_dir":"/proj","tool_name":"terminal","tool_input":{"command":"cat .env"}}`, exitCode: 2},
		{agent: "crush", payload: `{"event":"PreToolUse","session_id":"t1","cwd":"/proj","tool_name":"bash","tool_input":{"command":"cat .env"}}`, exitCode: 2},
		{agent: "junie", payload: `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}`, exitCode: 2},
	}
	for _, tc := range tests {
		t.Run(tc.agent, func(t *testing.T) {
			findings := filepath.Join(t.TempDir(), "findings.ndjson")
			out, errb, code := runCLIStdin(tc.payload, "hook", "pre-tool", "--agent", tc.agent, "--enforce", "--rules-dir", rulesDir,
				"--output", "file", "--output-file", findings)
			if code != tc.exitCode {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, tc.exitCode, out, errb)
			}
			if tc.exitCode == 2 {
				if strings.TrimSpace(out) != "" || strings.TrimSpace(errb) != defaultDenyMessage {
					t.Fatalf("exit-code deny stdout=%q stderr=%q", out, errb)
				}
			} else {
				var response map[string]any
				if err := json.Unmarshal([]byte(out), &response); err != nil {
					t.Fatalf("decode response %q: %v", out, err)
				}
				if got := fmt.Sprint(response[tc.responseKey]); got != tc.responseVal {
					t.Fatalf("response[%s]=%q want=%q: %#v", tc.responseKey, got, tc.responseVal, response)
				}
				if !strings.Contains(out, defaultDenyMessage) || strings.Contains(out, "enforce_test.critical_block") {
					t.Fatalf("agent response leaked rule details: %s", out)
				}
			}
		})
	}
}

func TestEnforceOffCriticalMatchAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--rules-dir", dir)
	assertAllow(t, out, code)
}

func TestSessionEndDefaultObserveOnlyAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, sessionEndEnforceRule)
	w := &countingWriter{}
	code := runHookEvent("session-end",
		[]string{"--agent", "claude", "--rules-dir", dir},
		strings.NewReader(sessionEndPayload), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if w.writes != 1 {
		t.Fatalf("session-end observe-only path performed %d Write calls, want exactly 1", w.writes)
	}
	out := w.buf.String()
	assertAllow(t, out, code)
	if got := decodeDecision(t, out); got != "" {
		t.Fatalf("stdout = %q, want no hookSpecificOutput deny payload", out)
	}
}

func TestSessionEndEnforceStillAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, sessionEndEnforceRule)
	out, _, code := runCLIStdin(sessionEndPayload,
		enforceHookArgs(t, "hook", "session-end", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	assertAllow(t, out, code)
	if got := decodeDecision(t, out); got != "" {
		t.Fatalf("stdout = %q, want no permissionDecision deny payload", out)
	}
}

func TestEnforceOnCriticalEnforceMatchDenies(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (deny uses stdout JSON, never exit 2)", code)
	}
	if decodeDecision(t, out) != "deny" {
		t.Fatalf("stdout = %q, want a permissionDecision=deny response", out)
	}
	var resp struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("deny stdout not valid JSON: %v", err)
	}
	if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", resp.HookSpecificOutput.HookEventName)
	}
	if resp.HookSpecificOutput.PermissionDecisionReason != defaultDenyMessage {
		t.Errorf("reason = %q, want %q", resp.HookSpecificOutput.PermissionDecisionReason, defaultDenyMessage)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("response written on %d lines, want exactly 1", n)
	}
}

func TestEnforceOnMediumEnforceMatchDenies(t *testing.T) {
	dir := writeEnforceRuleFile(t, mediumEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if decodeDecision(t, out) != "deny" {
		t.Fatalf("stdout = %q, want a permissionDecision=deny response", out)
	}
}

func TestEnforceUsesCustomDenyMessage(t *testing.T) {
	dir := writeEnforceRuleFile(t, customMessageEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	var resp struct {
		HookSpecificOutput struct {
			Reason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.HookSpecificOutput.Reason != "Contact the workspace owner." {
		t.Fatalf("reason = %q", resp.HookSpecificOutput.Reason)
	}
}

func TestEnforcePersistsDenyDecision(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	out, errb, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", outFile)
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	records := readHookRecords(t, outFile)
	if len(records) < 2 || records[len(records)-1]["record_type"] != output.RecordEnforcement {
		t.Fatalf("records = %#v, want findings then enforcement", records)
	}
	decision := enforcementRecord(t, records)
	if decision["decision"] != model.EnforcementDecisionDeny || decision["mode"] != model.EnforcementModeEnforce || decision["reason"] != model.EnforcementReasonEnforceRuleMatch {
		t.Fatalf("deny decision = %#v", decision)
	}
	if decision["deny_rule_id"] != "enforce_test.critical_block" {
		t.Fatalf("deny rule = %#v", decision["deny_rule_id"])
	}
	findingIDs, _ := decision["finding_ids"].([]any)
	if len(findingIDs) != len(records)-1 {
		t.Fatalf("decision/finding join count = %d, findings = %d", len(findingIDs), len(records)-1)
	}
	for i, findingID := range findingIDs {
		if findingID != records[i]["finding_id"] {
			t.Fatalf("decision finding %d = %#v, record = %#v", i, findingID, records[i]["finding_id"])
		}
	}
	if decision["run_id"] != records[0]["run_id"] {
		t.Fatalf("run ids differ: decision=%v finding=%v", decision["run_id"], records[0]["run_id"])
	}
}

func TestEnforcePersistsNoOverrideForNonEnforceableFinding(t *testing.T) {
	setTestHome(t, t.TempDir())
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	out, errb, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce",
		"--output", "file", "--output-file", outFile)
	assertAllow(t, out, code)
	_ = errb
	decision := enforcementRecord(t, readHookRecords(t, outFile))
	if decision["decision"] != model.EnforcementDecisionNoOverride || decision["mode"] != model.EnforcementModeEnforce || decision["reason"] != model.EnforcementReasonNoEnforceEligibleMatch {
		t.Fatalf("no-override decision = %#v", decision)
	}
	if _, ok := decision["deny_rule_id"]; ok {
		t.Fatalf("no-override decision names a deny rule: %#v", decision)
	}
}

func TestEnforcePersistsDenyDespiteSiblingEvalError(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFiles(t, map[string]string{
		"critical.yaml": criticalEnforceRule,
		"eval.yaml":     evalErrorEnforceRule,
	})
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	out, _, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", outFile)
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("deny response: exit=%d stdout=%q", code, out)
	}
	decision := enforcementRecord(t, readHookRecords(t, outFile))
	if decision["decision"] != model.EnforcementDecisionDeny || decision["mode"] != model.EnforcementModeEnforce {
		t.Fatalf("deny decision = %#v", decision)
	}
	if decision["deny_rule_id"] != "enforce_test.critical_block" {
		t.Fatalf("deny decision rule = %#v", decision)
	}
}

func TestMonitorPersistsNoOverrideDespiteHostAskSyntax(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	payload := `{"conversationId":"s1","workspacePaths":["/proj"],"stepIdx":1,"toolCall":{"name":"run_command","args":{"CommandLine":"cat .env"}}}`
	out, errb, code := runCLIStdin(payload,
		"hook", "PreToolUse", "--agent", "antigravity", "--rules-dir", dir,
		"--output", "file", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(out), &response); err != nil || response["decision"] != "ask" {
		t.Fatalf("response=%q err=%v", out, err)
	}
	decision := enforcementRecord(t, readHookRecords(t, outFile))
	if decision["decision"] != model.EnforcementDecisionNoOverride || decision["mode"] != model.EnforcementModeMonitor || decision["reason"] != model.EnforcementReasonMonitorMode {
		t.Fatalf("monitor decision = %#v", decision)
	}
}

func TestEnforceOnDenyIsSingleWrite(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	w := &countingWriter{}
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if w.writes != 1 {
		t.Fatalf("deny performed %d Write calls, want exactly 1", w.writes)
	}
	out := w.buf.String()
	if decodeDecision(t, out) != "deny" {
		t.Fatalf("stdout = %q, want a permissionDecision=deny response", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("deny response ended with %d newlines, want exactly 1", n)
	}
}

func TestEnforceOnAllowIsSingleWrite(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	benign := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	w := &countingWriter{}
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(benign), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if w.writes != 1 {
		t.Fatalf("allow performed %d Write calls, want exactly 1", w.writes)
	}
	if got := strings.TrimSpace(w.buf.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert allow passthrough {}", got)
	}
}

func TestEnforceOffAllowIsSingleWrite(t *testing.T) {
	w := &countingWriter{}
	code := runHookEvent("pre-tool",
		[]string{"--agent", "claude"},
		strings.NewReader(`{"session_id":"s1"}`), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if w.writes != 1 {
		t.Fatalf("enforce-off allow performed %d Write calls, want exactly 1", w.writes)
	}
	if got := strings.TrimSpace(w.buf.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert allow passthrough {}", got)
	}
}

func TestEnforceOnDenyByteZeroWriteFailureAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	w := &byteZeroFailWriter{}
	var errb bytes.Buffer
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), w, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 when the deny write fails at byte zero", code)
	}
	if w.buf.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (allow per contract) after a byte-zero deny failure", w.buf.String())
	}
	if w.writes != 1 {
		t.Fatalf("byte-zero deny failure performed %d Write calls, want exactly 1 (no retry of the same response)", w.writes)
	}
	if got := strings.TrimSpace(errb.String()); got != noDecisionMessage {
		t.Fatalf("agent stderr = %q, want only the generic no-decision message", errb.String())
	}
}

func TestEnforceOnCriticalWithoutEnforceFlagAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalNoEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnNoMatchAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	benign := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	out, _, code := runCLIStdin(benign,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestBuiltinSSHDetectionsRemainMonitorOnly(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	statePath := filepath.Join(home, "state.db")
	findings := filepath.Join(home, "findings.ndjson")
	baseArgs := []string{
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--state-db", statePath,
		"--output", "file", "--output-file", findings,
	}

	for _, path := range []string{
		"/Users/dev/.ssh/authorized_keys",
		`C:\Users\dev\.ssh\authorized_keys`,
		`C:\ProgramData\ssh\administrators_authorized_keys`,
	} {
		payload := fmt.Sprintf(`{"session_id":"s1","cwd":"/repo","tool_name":"Write","tool_input":{"file_path":%q,"content":"ssh-ed25519 AAAA"}}`, path)
		out, errb, code := runCLIStdin(payload, baseArgs...)
		if code != 0 || strings.TrimSpace(out) != "{}" {
			t.Fatalf("path %q: exit=%d stdout=%q stderr=%q, shipped rule must not deny", path, code, out, errb)
		}
	}

	fixture := `{"session_id":"s1","cwd":"/repo","tool_name":"Write","tool_input":{"file_path":"/repo/testdata/.ssh/authorized_keys","content":"fixture"}}`
	if out, _, code := runCLIStdin(fixture, baseArgs...); code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("project fixture must allow: exit=%d stdout=%q", code, out)
	}

	command := `{"session_id":"s1","cwd":"/repo","tool_name":"Bash","tool_input":{"command":"cat key.pub >> ~/.ssh/authorized_keys"}}`
	out, errb, code := runCLIStdin(command, baseArgs...)
	if code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("command-derived detection must allow: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	records, err := os.ReadFile(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"rule_id":"persistence.ssh_authorized_keys"`,
		`"rule_id":"persistence.ssh_authorized_keys_command"`,
		`"decision":"no_override"`,
	} {
		if !strings.Contains(string(records), want) {
			t.Fatalf("monitor-only finding or decision %q missing from records: %q", want, records)
		}
	}
}

func TestEnforceOnMalformedStdinAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin("not json at all",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnEmptyStdinAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin("",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnNullStdinAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	recordsPath := filepath.Join(t.TempDir(), "records.ndjson")
	out, errb, code := runCLIStdin("null",
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", recordsPath)
	assertAllow(t, out, code)
	if errb != "" {
		t.Fatalf("agent stderr leaked payload diagnostic: %q", errb)
	}
	records, err := os.ReadFile(recordsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(records), "hook payload must be a JSON object") {
		t.Fatalf("operator sink missing invalid-object diagnostic: %s", records)
	}
}

func TestEnforceRejectsStdoutFindingSink(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	out, errb, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "stdout")
	assertAllow(t, out, code)
	if !strings.Contains(errb, noDecisionMessage) {
		t.Fatalf("stderr = %q, want generic fail-open message", errb)
	}
	if strings.Contains(errb, "enforce_test.unconditional_block") || strings.Contains(errb, "Unconditional enforce-eligible match") {
		t.Fatalf("agent-visible stderr leaked rule details: %q", errb)
	}
}

func TestEnforceOnUnconditionalRuleCleanDecodeDenies(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (deny uses stdout JSON, never exit 2)", code)
	}
	if decodeDecision(t, out) != "deny" {
		t.Fatalf("stdout = %q, want a permissionDecision=deny on a clean decode", out)
	}
}

func TestEnforceOnUnconditionalRuleMalformedStdinAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	out, _, code := runCLIStdin("not json at all",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnUnconditionalRuleEmptyStdinAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	out, _, code := runCLIStdin("",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnUnconditionalRuleTrailingGarbageAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload+"\ntrailing-garbage",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnRuleEvalErrorAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, evalErrorEnforceRule)
	recordsPath := filepath.Join(t.TempDir(), "records.ndjson")
	out, errb, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", recordsPath)
	assertAllow(t, out, code)
	if strings.Contains(errb, "enforce_test.eval_boom") {
		t.Fatalf("agent stderr leaked rule id: %q", errb)
	}
	records, err := os.ReadFile(recordsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(records), `"record_type":"diagnostic"`) || !strings.Contains(string(records), "enforce_test.eval_boom") {
		t.Fatalf("operator sink missing rule-evaluation diagnostic: %s", records)
	}
}

func TestEnforceOnPassthroughWritePanicAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	stdout := &firstWritePanicWriter{}
	var errb bytes.Buffer
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"true"}}`), stdout, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the passthrough write panics under enforce", code)
	}
	if got := strings.TrimSpace(stdout.buf.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert allow {} after a recovered panic under enforce", got)
	}
	if n := strings.Count(stdout.buf.String(), "{}"); n != 1 {
		t.Fatalf("passthrough written %d times, want exactly 1", n)
	}
	if strings.Contains(stdout.buf.String(), "deny") {
		t.Fatalf("a recovered panic must never emit a deny; stdout = %q", stdout.buf.String())
	}
	if got := strings.TrimSpace(errb.String()); got != noDecisionMessage {
		t.Fatalf("agent stderr = %q, want generic no-decision message", errb.String())
	}
}

func TestEnforceOnMixedRulesEvalErrorStillDeniesCleanMatch(t *testing.T) {
	dir := writeEnforceRuleFiles(t, map[string]string{
		"critical.yaml": criticalEnforceRule,
		"eval.yaml":     evalErrorEnforceRule,
	})
	out, _, code := runCLIStdin(catEnvPayload,
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("deny response: exit=%d stdout=%q", code, out)
	}
}

func TestEnforceOnFindingsSinkErrorAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	notDir := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	sinkPath := filepath.Join(notDir, "findings.ndjson")
	out, _, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", sinkPath)
	assertAllow(t, out, code)
}

func TestEnforceOnTrailingGarbageAfterValidJSONAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin(catEnvPayload+"\nnot-json",
		enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir)...)
	assertAllow(t, out, code)
}

func TestEnforceOnDenyStdoutWriteErrorNoCorruption(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	w := &shortDenyWriter{}
	var errb bytes.Buffer
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), w, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the deny stdout write errors", code)
	}
	got := w.buf.String()
	trimmed := strings.TrimRight(got, "\n")
	if trimmed == "{}" {
		return // clean allow, no deny bytes ever written — fine
	}
	denyAttempted := strings.HasPrefix(trimmed, `{"hookSp`)
	if denyAttempted && strings.HasSuffix(trimmed, "{}") {
		t.Fatalf("allow backstop appended {} after partial deny bytes (corrupted response): %q", got)
	}
	if strings.Contains(got, "}{}") || strings.Contains(got, "}\n{}") {
		t.Fatalf("output contains a deny-then-allow concatenation: %q", got)
	}
	if stderr := strings.TrimSpace(errb.String()); stderr != noDecisionMessage {
		t.Fatalf("agent stderr = %q, want only the generic no-decision message", errb.String())
	}
}

func TestEnforcePersistsComputedDenyBeforePartialControlWrite(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	w := &shortDenyWriter{}
	code := runHookEvent("pre-tool",
		[]string{"--agent", "claude", "--enforce", "--rules-dir", dir, "--output", "file", "--output-file", outFile},
		strings.NewReader(catEnvPayload), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	decision := enforcementRecord(t, readHookRecords(t, outFile))
	if decision["decision"] != model.EnforcementDecisionDeny || decision["reason"] != model.EnforcementReasonEnforceRuleMatch {
		t.Fatalf("computed decision = %#v, want deny regardless of later response write", decision)
	}
}

func TestEnforcementDecisionSharesFindingHTTPBatch(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	var requests atomic.Int32
	body := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body <- b
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	out, errb, code := runCLIStdin(catEnvPayload,
		"hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir,
		"--output", "http", "--http-url", server.URL, "--http-allow-insecure")
	if code != 0 || decodeDecision(t, out) != "deny" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP requests = %d, want one finding/decision batch", requests.Load())
	}
	if errb != "" {
		t.Fatalf("stderr = %q, want empty agent control channel", errb)
	}
	batch := string(<-body)
	if !strings.Contains(batch, `"record_type":"finding"`) || !strings.Contains(batch, `"record_type":"enforcement"`) || !strings.Contains(batch, `"decision":"deny"`) {
		t.Fatalf("HTTP batch lacks finding and deny decision:\n%s", batch)
	}
}

func TestEnforceOnDenyStdoutWritePanicFailsOpenNoCorruption(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	stdout := &firstWritePanicWriter{}
	var errb bytes.Buffer
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), stdout, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the deny stdout write panics", code)
	}
	got := stdout.buf.String()
	if strings.Contains(got, "deny") {
		t.Fatalf("a panicked deny must never leave a deny on the wire; stdout = %q", got)
	}
	if strings.Contains(got, "{}") {
		t.Fatalf("recover appended {} after a panicked deny write (risked corruption): %q", got)
	}
	if stderr := strings.TrimSpace(errb.String()); stderr != noDecisionMessage {
		t.Fatalf("agent stderr = %q, want only the generic no-decision message", errb.String())
	}
}

func TestEnforceOnDenyStdoutPartialThenPanicLyingProbeNoCorruption(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	w := &lyingProbePanicWriter{}
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the deny write panics with a lying probe", code)
	}
	got := w.buf.String()
	if !strings.HasPrefix(got, `{"hookSp`) {
		t.Fatalf("expected a partial deny prefix on the wire, got %q", got)
	}
	if strings.Contains(got, "{}") {
		t.Fatalf("recover appended {} after a partial deny prefix despite a lying probe (corrupted): %q", got)
	}
	if strings.HasSuffix(strings.TrimRight(got, "\n"), "{}") {
		t.Fatalf("partial deny spliced with a trailing allow object: %q", got)
	}
}

func TestEnforceOnDenyStdoutPartialThenPanicNoCorruption(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	w := &partialDenyPanicWriter{}
	code := runHookEvent("pre-tool",
		enforceHookArgs(t, "--agent", "claude", "--enforce", "--rules-dir", dir),
		strings.NewReader(catEnvPayload), w, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the deny stdout write panics mid-prefix", code)
	}
	got := w.buf.String()
	if !strings.HasPrefix(got, `{"hookSp`) {
		t.Fatalf("expected a partial deny prefix on the wire, got %q", got)
	}
	if strings.Contains(got, "{}") {
		t.Fatalf("recover appended {} after a partial deny prefix (corrupted response): %q", got)
	}
	if strings.HasSuffix(strings.TrimRight(got, "\n"), "{}") {
		t.Fatalf("partial deny spliced with a trailing allow object: %q", got)
	}
}

func TestCursorEnforceUsesNativeDeny(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	tests := []struct {
		name, event, payload string
	}{
		{"generic shell", "preToolUse", `{"conversation_id":"s1","cwd":"/proj","tool_name":"Shell","tool_input":{"command":"cat .env"},"tool_use_id":"tool-1"}`},
		{"specialized file read", "beforeReadFile", `{"conversation_id":"s1","file_path":"/proj/.env","content":"SECRET=value"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, _, code := runCLIStdin(tc.payload,
				enforceHookArgs(t, "hook", tc.event, "--agent", "cursor", "--enforce", "--rules-dir", dir)...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			var response map[string]any
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("invalid Cursor response %q: %v", out, err)
			}
			if got := nestedString(response, "permission"); got != "deny" {
				t.Fatalf("permission = %q, want deny; response=%s", got, out)
			}
			for _, field := range []string{"user_message", "agent_message"} {
				if got := nestedString(response, field); got != defaultDenyMessage {
					t.Fatalf("%s = %q, want %q", field, got, defaultDenyMessage)
				}
			}
		})
	}
}

func TestWindsurfEnforceUsesExitTwo(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	payload := `{"agent_action_name":"pre_run_command","execution_id":"e1","cwd":"/proj","tool_info":{"command":"cat .env"}}`
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	out, errOut, code := runCLIStdin(payload,
		"hook", "pre_run_command", "--agent", "windsurf", "--enforce", "--rules-dir", dir,
		"--output", "file", "--output-file", outFile)
	if code != 2 {
		t.Fatalf("exit = %d, want 2; stderr = %q", code, errOut)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty for Windsurf exit-code deny", out)
	}
	if strings.TrimSpace(errOut) != defaultDenyMessage {
		t.Fatalf("stderr = %q, want %q", errOut, defaultDenyMessage)
	}
	decision := enforcementRecord(t, readHookRecords(t, outFile))
	if decision["decision"] != model.EnforcementDecisionDeny || decision["deny_rule_id"] != "enforce_test.unconditional_block" {
		t.Fatalf("exit-code enforcement decision = %#v", decision)
	}
}

func TestExitCodeDenyStderrContainsOnlyReason(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	longURL := "https://" + strings.Repeat("a", 5000) + ".example"
	payload, err := json.Marshal(map[string]any{
		"agent_action_name": "pre_run_command",
		"execution_id":      "e1",
		"cwd":               "/proj",
		"tool_info":         map[string]any{"command": "curl " + longURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	monitorRecords := filepath.Join(t.TempDir(), "monitor.ndjson")
	_, monitorErr, monitorCode := runCLIStdin(string(payload),
		"hook", "pre_run_command", "--agent", "windsurf", "--rules-dir", dir,
		"--emit", "all", "--output", "file", "--output-file", monitorRecords)
	if monitorCode != 0 || !strings.Contains(monitorErr, "indicator catalog reached its safety limit") {
		t.Fatalf("fixture did not produce the diagnostic: exit %d stderr %q", monitorCode, monitorErr)
	}
	findings := filepath.Join(t.TempDir(), "records.ndjson")
	out, errOut, code := runCLIStdin(string(payload),
		"hook", "pre_run_command", "--agent", "windsurf", "--enforce", "--rules-dir", dir,
		"--emit", "all", "--output", "file", "--output-file", findings)
	if code != 2 || out != "" || strings.TrimSpace(errOut) != defaultDenyMessage {
		t.Fatalf("exit-code deny = exit %d, stdout %q, stderr %q; want only neutral reason", code, out, errOut)
	}
	records, err := os.ReadFile(findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(records), `"record_type":"finding"`) {
		t.Fatalf("operator sink missing finding: %s", records)
	}
	if !strings.Contains(string(records), `"record_type":"diagnostic"`) || !strings.Contains(string(records), "indicator catalog reached its safety limit") {
		t.Fatalf("operator sink missing diagnostic: %s", records)
	}
}

func TestExitCodeDenyWriteFailureFallsOpen(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	payload := `{"agent_action_name":"pre_run_command","execution_id":"e1","cwd":"/proj","tool_info":{"command":"cat .env"}}`
	var stdout bytes.Buffer
	stderr := &byteZeroFailWriter{}
	code := runHookEvent("pre_run_command",
		enforceHookArgs(t, "--agent", "windsurf", "--enforce", "--rules-dir", dir),
		strings.NewReader(payload), &stdout, stderr)
	if code != 0 || strings.TrimSpace(stdout.String()) != "{}" {
		t.Fatalf("failed deny write must fall open: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.buf.String())
	}
}

func TestStructuredAgentEnforcementResponses(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	tests := []struct {
		name, agent, event, payload, decisionPath, decision string
	}{
		{"copilot", "copilot", "PreToolUse", `{"hookEventName":"PreToolUse","toolName":"ShellCommand","toolArgs":"{\"command\":\"cat .env\"}","cwd":"/proj"}`, "permissionDecision", "deny"},
		{"vscode shared hook", "copilot", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"runTerminalCommand","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`, "hookSpecificOutput.permissionDecision", "deny"},
		{"gemini", "gemini", "BeforeTool", `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`, "decision", "deny"},
		{"antigravity", "antigravity", "PreToolUse", `{"conversationId":"s1","workspacePaths":["/proj"],"stepIdx":1,"toolCall":{"name":"run_command","args":{"CommandLine":"cat .env"}}}`, "decision", "deny"},
		{"factory", "factory", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Execute","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`, "hookSpecificOutput.permissionDecision", "deny"},
		{"grok", "grok", "PreToolUse", `{"hookEventName":"PreToolUse","toolName":"Bash","toolInput":{"command":"cat .env"},"cwd":"/proj","sessionId":"s1"}`, "decision", "deny"},
		{"devin", "devin", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`, "decision", "block"},
		{"hermes", "hermes", "pre_tool_call", `{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`, "action", "block"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := runCLIStdin(tc.payload,
				enforceHookArgs(t, "hook", tc.event, "--agent", tc.agent, "--enforce", "--rules-dir", dir)...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr = %q", code, errOut)
			}
			var response map[string]any
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("invalid response %q: %v", out, err)
			}
			value := nestedString(response, strings.Split(tc.decisionPath, ".")...)
			if value != tc.decision {
				t.Fatalf("%s = %q, want %q; response = %s", tc.decisionPath, value, tc.decision, out)
			}
			if !strings.Contains(out, defaultDenyMessage) || strings.Contains(out, "enforce_test.unconditional_block") {
				t.Fatalf("agent response leaked rule details: %s", out)
			}
		})
	}
}

func TestEnforceCapableAgentsMapWindowsDestructiveCommand(t *testing.T) {
	const command = `Remove-Item -Recurse -Force C:\`
	rulesDir := writeEnforcedBuiltinRule(t, "exec/destructive_recursive_delete.yaml")
	tests := []struct {
		name, agent, event, decisionPath, decision string
		payload                                    map[string]any
		exitCode                                   int
	}{
		{"claude", "claude", "pre-tool", "hookSpecificOutput.permissionDecision", "deny", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}}, 0},
		{"codex", "codex", "codex-pre-tool", "hookSpecificOutput.permissionDecision", "deny", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec_command", "tool_input": map[string]any{"cmd": command}}, 0},
		{"cursor", "cursor", "preToolUse", "permission", "deny", map[string]any{"conversation_id": "s1", "tool_name": "Shell", "tool_input": map[string]any{"command": command}}, 0},
		{"copilot", "copilot", "copilot-pre-tool", "permissionDecision", "deny", map[string]any{"hookEventName": "PreToolUse", "toolName": "ShellCommand", "toolArgs": map[string]any{"command": command}}, 0},
		{"vscode shared hook", "copilot", "copilot-pre-tool", "hookSpecificOutput.permissionDecision", "deny", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "runTerminalCommand", "tool_input": map[string]any{"command": command}}, 0},
		{"gemini", "gemini", "gemini-pre-tool", "decision", "deny", map[string]any{"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": map[string]any{"command": command}}, 0},
		{"antigravity", "antigravity", "antigravity-pre-tool", "decision", "deny", map[string]any{"conversationId": "s1", "workspacePaths": []any{"C:/repo"}, "stepIdx": 1, "toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": command}}}, 0},
		{"factory", "factory", "factory-pre-tool", "hookSpecificOutput.permissionDecision", "deny", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Execute", "tool_input": map[string]any{"command": command}}, 0},
		{"grok", "grok", "grok-pre-tool", "decision", "deny", map[string]any{"hookEventName": "PreToolUse", "toolName": "Bash", "toolInput": map[string]any{"command": command}}, 0},
		{"devin", "devin", "devin-pre-tool", "decision", "block", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": map[string]any{"command": command}}, 0},
		{"hermes", "hermes", "hermes-pre-tool", "action", "block", map[string]any{"hook_event_name": "pre_tool_call", "tool_name": "terminal", "tool_input": map[string]any{"command": command}}, 0},
		{"windsurf", "windsurf", "pre_run_command", "", "", map[string]any{"agent_action_name": "pre_run_command", "execution_id": "e1", "tool_info": map[string]any{"command_line": command}}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setTestHome(t, t.TempDir())
			payload, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			outFile := filepath.Join(t.TempDir(), "findings.ndjson")
			out, errOut, code := runCLIStdin(string(payload), "hook", tc.event,
				"--agent", tc.agent, "--enforce", "--rules-dir", rulesDir,
				"--output=file", "--output-file", outFile)
			if code != tc.exitCode {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", code, tc.exitCode, out, errOut)
			}
			if tc.exitCode == 2 {
				if out != "" || strings.TrimSpace(errOut) != defaultDenyMessage {
					t.Fatalf("Windsurf deny = stdout %q, stderr %q", out, errOut)
				}
			} else {
				var response map[string]any
				if err := json.Unmarshal([]byte(out), &response); err != nil {
					t.Fatalf("invalid response %q: %v", out, err)
				}
				if got := nestedString(response, strings.Split(tc.decisionPath, ".")...); got != tc.decision {
					t.Fatalf("%s = %q, want %q; response=%s", tc.decisionPath, got, tc.decision, out)
				}
				if !strings.Contains(out, defaultDenyMessage) || strings.Contains(out, "exec.destructive_recursive_delete") {
					t.Fatalf("agent response leaked rule details: %s", out)
				}
			}
		})
	}
}

func nestedString(value map[string]any, path ...string) string {
	var current any = value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	result, _ := current.(string)
	return result
}

func TestOpenCodeEnforceStillAllowsRuntime(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	payload := `{"tool":"bash","args":{"command":"cat .env"},"sessionID":"s1","callID":"c1","cwd":"/proj"}`
	out, _, code := runCLIStdin(payload,
		enforceHookArgs(t, "hook", "opencode-pre-tool", "--agent", "opencode", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (OpenCode is observe-only; never denies)", code)
	}
	if got := strings.TrimSpace(out); got != `{}` {
		t.Fatalf("stdout = %q, want OpenCode's inert empty-object passthrough {}", got)
	}
	if strings.Contains(out, "deny") || strings.Contains(out, "permissionDecision") {
		t.Fatalf("OpenCode under --enforce must never emit a deny; stdout = %q", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("response written on %d lines, want exactly 1", n)
	}
}

func TestInstallEnforceThreadsFlagIntoClaudeCommand(t *testing.T) {
	rulesDir := writeEnforceRuleFile(t, criticalEnforceRule)
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, _, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--rules-dir", rulesDir, "--enforce"); code != 0 {
		t.Fatalf("install --enforce exit = %d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), "--enforce") {
		t.Fatalf("installed command missing --enforce flag: %s", data)
	}

	plain := filepath.Join(t.TempDir(), "settings.json")
	if _, _, code := runCLI("hook", "install", "--agent", "claude", "--settings", plain); code != 0 {
		t.Fatalf("plain install exit = %d", code)
	}
	pdata, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if strings.Contains(string(pdata), "--enforce") {
		t.Fatalf("default install must not carry --enforce: %s", pdata)
	}
}

func TestInstallEnforceRejectsCatalogWithoutEnabledEnforceRule(t *testing.T) {
	monitorOnly := strings.Replace(criticalEnforceRule, "enforce: true\n", "", 1)
	disabledEnforce := strings.Replace(criticalEnforceRule, "enforce: true\n", "enabled: false\nenforce: true\n", 1)
	tests := []struct {
		name string
		args func(*testing.T) []string
		want string
	}{
		{
			name: "shipped monitor-only catalog",
			args: func(*testing.T) []string { return nil },
			want: "--enforce requires at least one enabled rule with enforce: true in the effective catalog",
		},
		{
			name: "operator catalog is monitor-only",
			args: func(t *testing.T) []string {
				return []string{"--rules-dir", writeEnforceRuleFile(t, monitorOnly)}
			},
			want: "--enforce requires at least one enabled rule with enforce: true in the effective catalog",
		},
		{
			name: "enforce rule is disabled",
			args: func(t *testing.T) []string {
				return []string{"--rules-dir", writeEnforceRuleFile(t, disabledEnforce)}
			},
			want: "--enforce requires at least one enabled rule with enforce: true in the effective catalog",
		},
		{
			name: "deferred rule directory",
			args: func(*testing.T) []string { return []string{"--rules-dir", "$HOME/numbat-rules"} },
			want: "--enforce requires a concrete --rules-dir path that can be validated at install time",
		},
		{
			name: "missing rule directory",
			args: func(t *testing.T) []string {
				return []string{"--rules-dir", filepath.Join(t.TempDir(), "missing")}
			},
			want: "validate --enforce rule catalog: rules dir",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			args := []string{"hook", "install", "--agent", "claude", "--settings", path, "--enforce"}
			_, errb, code := runCLI(append(args, tc.args(t)...)...)
			if code != 2 || !strings.Contains(errb, tc.want) {
				t.Fatalf("exit=%d stderr=%q, want usage error containing %q", code, errb, tc.want)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("refused install changed target %q: %v", path, err)
			}
		})
	}
}

func TestInstallEnforceAcceptsBuiltinOverridePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--rules-dir", "testdata/rules_dup", "--enforce")
	if code != 0 {
		t.Fatalf("same-id enforce override install exit=%d stderr=%q", code, errb)
	}
}

func TestInstallEnforcePolicyRejectionLeavesExistingSettingsUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := []byte("{\"theme\":\"dark\"}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, code := runCLI("hook", "install", "--agent", "claude", "--settings", path, "--enforce")
	if code != 2 {
		t.Fatalf("install exit=%d, want policy-validation refusal", code)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("settings changed after policy rejection: got %q want %q", got, original)
	}
	if _, err := os.Stat(path + ".numbat-bak"); !os.IsNotExist(err) {
		t.Fatalf("policy rejection created a backup before validation: %v", err)
	}
}

func TestInstallEnforceRequiresOperatorFindingSink(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "stdout output",
			args: []string{"--output", "stdout"},
			want: "--enforce does not support --output stdout",
		},
		{
			name: "events only",
			args: []string{"--emit", "events"},
			want: "--enforce requires --emit findings",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			args := []string{"hook", "install", "--agent", "claude", "--settings", path, "--enforce"}
			_, errb, code := runCLI(append(args, tc.args...)...)
			if code != 2 || !strings.Contains(errb, tc.want) {
				t.Fatalf("exit=%d stderr=%q, want usage error containing %q", code, errb, tc.want)
			}
		})
	}
}

const codexShellPayload = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"},"cwd":"/proj","session_id":"s1"}`

func TestCodexEnforceShellMatchDenies(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin(codexShellPayload,
		enforceHookArgs(t, "hook", "PreToolUse", "--agent", "codex", "--enforce", "--rules-dir", dir)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (deny uses stdout JSON, never exit 2)", code)
	}
	if decodeDecision(t, out) != "deny" {
		t.Fatalf("stdout = %q, want a permissionDecision=deny response", out)
	}
	var resp struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("deny stdout not valid JSON: %v", err)
	}
	if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", resp.HookSpecificOutput.HookEventName)
	}
	if resp.HookSpecificOutput.PermissionDecisionReason != defaultDenyMessage {
		t.Errorf("reason = %q, want %q", resp.HookSpecificOutput.PermissionDecisionReason, defaultDenyMessage)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("response written on %d lines, want exactly 1", n)
	}
}

func TestBuiltinDestructiveDetectionsRemainMonitorOnly(t *testing.T) {
	for _, tc := range []struct {
		agent   string
		tool    string
		command string
		ruleID  string
	}{
		{agent: "claude", tool: "Bash", command: "rm -rf /", ruleID: "exec.destructive_recursive_delete"},
		{agent: "codex", tool: "Bash", command: "rm -rf /", ruleID: "exec.destructive_recursive_delete"},
		{agent: "codex", tool: "exec_command", command: "rm -rf /", ruleID: "exec.destructive_recursive_delete"},
		{agent: "claude", tool: "Bash", command: `Remove-Item -Recurse -Force C:\`, ruleID: "exec.destructive_recursive_delete"},
		{agent: "codex", tool: "powershell", command: `Remove-Item -Recurse -Force C:\`, ruleID: "exec.destructive_recursive_delete"},
		{agent: "claude", tool: "Bash", command: "kill -9 -1", ruleID: "impact.mass_process_termination"},
		{agent: "codex", tool: "exec_command", command: "kill -9 -1", ruleID: "impact.mass_process_termination"},
		{agent: "claude", tool: "Bash", command: `:(){ :|:& };:`, ruleID: "impact.fork_bomb"},
		{agent: "codex", tool: "exec_command", command: `:(){ :|:& };:`, ruleID: "impact.fork_bomb"},
	} {
		t.Run(tc.agent+"_"+tc.tool+"_"+strings.ReplaceAll(tc.command, " ", "_"), func(t *testing.T) {
			setTestHome(t, t.TempDir())
			recordsPath := filepath.Join(t.TempDir(), "records.ndjson")
			payloadBytes, err := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       tc.tool,
				"tool_input":      map[string]any{"command": tc.command},
				"cwd":             `C:\repo`,
				"session_id":      "s1",
			})
			if err != nil {
				t.Fatal(err)
			}
			out, errOut, code := runCLIStdin(string(payloadBytes),
				"hook", "PreToolUse", "--agent", tc.agent, "--enforce",
				"--output", "file", "--output-file", recordsPath)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr = %q", code, errOut)
			}
			if strings.TrimSpace(out) != "{}" {
				t.Fatalf("stdout = %q, shipped rule must not deny", out)
			}
			records, err := os.ReadFile(recordsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(records), `"rule_id":"`+tc.ruleID+`"`) ||
				!strings.Contains(string(records), `"decision":"no_override"`) {
				t.Fatalf("monitor-only finding or decision missing from records: %s", records)
			}
		})
	}
}

func TestCodexEnforcePreToolMatchesDeny(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "apply_patch",
			payload: `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: secrets.txt\n+leak\n*** End Patch"},"cwd":"/proj","session_id":"s1"}`,
		},
		{
			name:    "read_file",
			payload: `{"hook_event_name":"PreToolUse","tool_name":"read_file","tool_input":{"path":"/proj/.env"},"cwd":"/proj","session_id":"s1"}`,
		},
		{
			name:    "mcp_tool",
			payload: `{"hook_event_name":"PreToolUse","tool_name":"mcp__server__do","tool_input":{"arg":"x"},"cwd":"/proj","session_id":"s1"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, code := runCLIStdin(c.payload,
				enforceHookArgs(t, "hook", "PreToolUse", "--agent", "codex", "--enforce", "--rules-dir", dir)...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if decodeDecision(t, out) != "deny" {
				t.Fatalf("stdout = %q, want deny", out)
			}
			if n := strings.Count(out, "\n"); n != 1 {
				t.Fatalf("response written on %d lines, want exactly 1", n)
			}
		})
	}
}

func TestCodexEnforcePostToolStillAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, unconditionalEnforceRule)
	payload := `{"hook_event_name":"PostToolUse","tool_name":"apply_patch","tool_input":{},"session_id":"s1"}`
	out, _, code := runCLIStdin(payload,
		enforceHookArgs(t, "hook", "PostToolUse", "--agent", "codex", "--enforce", "--rules-dir", dir)...)
	if code != 0 || strings.TrimSpace(out) != `{}` {
		t.Fatalf("exit/stdout = %d/%q, want 0/{}", code, out)
	}
}

func TestCodexNoEnforceShellMatchStillAllows(t *testing.T) {
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	out, _, code := runCLIStdin(codexShellPayload,
		"hook", "PreToolUse", "--agent", "codex", "--rules-dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (no --enforce: passthrough-safe default)", code)
	}
	if got := strings.TrimSpace(out); got != `{}` {
		t.Fatalf("stdout = %q, want Codex's inert empty-object passthrough {}", got)
	}
	if strings.Contains(out, "deny") || strings.Contains(out, "permissionDecision") {
		t.Fatalf("Codex without --enforce must never deny; stdout = %q", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("response written on %d lines, want exactly 1", n)
	}
}

func TestInstallEnforceAcceptedForCursor(t *testing.T) {
	rulesDir := writeEnforceRuleFile(t, criticalEnforceRule)
	path := filepath.Join(t.TempDir(), "hooks.json")
	_, errb, code := runCLI("hook", "install", "--agent", "cursor", "--settings", path,
		"--rules-dir", rulesDir, "--enforce")
	if code != 0 {
		t.Fatalf("install --enforce for cursor exit = %d: %s", code, errb)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if commandText := testHookCommandText(string(data)); !strings.Contains(commandText, `"preToolUse"`) || !strings.Contains(commandText, "--enforce") {
		t.Fatalf("Cursor enforce hooks missing from config: %s", data)
	}
}

func TestInstallEnforceRejectedForOpenCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "numbat.ts")
	_, errb, code := runCLI("hook", "install", "--agent", "opencode", "--settings", path, "--enforce")
	if code == 0 {
		t.Fatalf("install --enforce for opencode exit = 0, want non-zero refusal")
	}
	if !strings.Contains(errb, "enforce") {
		t.Errorf("stderr = %q, want an enforce-not-supported message", errb)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("plugin should not exist after a refused enforce install, stat err = %v", statErr)
	}
}
