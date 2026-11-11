package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// TestRulesListWithRulesDir loads a custom rule alongside the built-ins: the
// list must contain both the custom rule and a known built-in.
func TestRulesListWithRulesDir(t *testing.T) {
	out, _, code := runCLI("rules", "list", "--rules-dir", "testdata/rules_custom")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "custom.terraform_destroy") {
		t.Fatalf("custom rule missing: %q", out)
	}
	if !strings.Contains(out, "secrets.agent_read_env") {
		t.Fatalf("built-in rule missing: %q", out)
	}
}

// TestRulesListNoBuiltinOnlyUserRules loads only the user rule: the custom rule
// is present and the built-ins are absent.
func TestRulesListNoBuiltinOnlyUserRules(t *testing.T) {
	out, _, code := runCLI("rules", "list", "--no-builtin-rules", "--rules-dir", "testdata/rules_custom")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "custom.terraform_destroy") {
		t.Fatalf("custom rule missing: %q", out)
	}
	if strings.Contains(out, "secrets.") || strings.Contains(out, "exfil.") {
		t.Fatalf("built-ins should be absent with --no-builtin-rules: %q", out)
	}
}

// TestRulesListNoBuiltinNoDirErrors: --no-builtin-rules with no --rules-dir has
// no rules to run and must error rather than silently list nothing.
func TestRulesListNoBuiltinNoDirErrors(t *testing.T) {
	_, errb, code := runCLI("rules", "list", "--no-builtin-rules")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "--no-builtin-rules requires at least one --rules-dir") {
		t.Fatalf("missing error: %q", errb)
	}
}

// TestRulesDirOverridesBuiltinByID proves that an explicitly supplied rule may
// replace every field of a built-in while the rest of the catalog stays loaded.
func TestRulesDirOverridesBuiltinByID(t *testing.T) {
	eng, err := buildEngine([]string{"testdata/rules_dup"}, false)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, Command: "run OVERRIDE_ONLY now"})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range matches {
		if m.Rule.ID != "secrets.agent_read_env" {
			continue
		}
		found = true
		if m.Rule.Version != "9.9" || m.Rule.Title != "Operator replacement for the built-in rule" ||
			m.Rule.Severity != model.SeverityLow || !m.Rule.IsEnforceEligible() ||
			len(m.Rule.Tags) != 1 || m.Rule.Tags[0] != "operator_override" {
			t.Fatalf("operator fields were not preserved: %+v", m.Rule)
		}
	}
	if !found {
		t.Fatal("operator replacement did not match")
	}

	matches, err = eng.Eval(model.Event{EventType: model.EventCommandExec, Command: "cat .env"})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if m.Rule.ID == "secrets.agent_read_env" {
			t.Fatal("embedded expression remained active after same-id override")
		}
	}

	count := 0
	for _, id := range eng.RuleIDs() {
		if id == "secrets.agent_read_env" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("effective catalog contains %d copies of secrets.agent_read_env, want 1", count)
	}
}

func TestRulesDirCanDisableBuiltinByID(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "disabled.yaml"), []byte(`
id: secrets.agent_read_env
version: "1.1"
enabled: false
title: Disabled environment-file rule
severity: high
expr: 'event.event_type == "command.exec" && event.command.contains(".env")'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := buildEngine([]string{dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range eng.RuleIDs() {
		if id == "secrets.agent_read_env" {
			t.Fatal("disabled operator replacement left the embedded rule active")
		}
	}
}

func TestRulesDirMalformedBuiltinOverrideFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte(`
id: secrets.agent_read_env
version: "2.0"
enabled: true
title: Broken replacement
severity: high
expr: 'event.not_a_real_field == "x"'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildEngine([]string{dir}, false); err == nil || !strings.Contains(err.Error(), "not_a_real_field") {
		t.Fatalf("malformed replacement should fail instead of falling back to the built-in: %v", err)
	}
}

func TestRulesDirOperatorDuplicatesRemainErrors(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	const body = `
id: secrets.agent_read_env
version: "2.0"
enabled: true
title: Operator replacement
severity: high
expr: 'event.event_type == "command.exec"'
`
	for _, dir := range []string{dirA, dirB} {
		if err := os.WriteFile(filepath.Join(dir, "override.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wantA := strconv.Quote(filepath.Join(dirA, "override.yaml"))
	wantB := strconv.Quote(filepath.Join(dirB, "override.yaml"))
	if _, err := buildEngine([]string{dirA, dirB}, false); err == nil ||
		!strings.Contains(err.Error(), "duplicate operator rule id") ||
		!strings.Contains(err.Error(), wantA) ||
		!strings.Contains(err.Error(), wantB) {
		t.Fatalf("operator duplicate error should name the id and both sources: %v", err)
	}
}

func TestNoBuiltinRulesAcceptsShippedID(t *testing.T) {
	eng, err := buildEngine([]string{"testdata/rules_dup"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if eng.Len() != 1 || len(eng.RuleIDs()) != 1 || eng.RuleIDs()[0] != "secrets.agent_read_env" {
		t.Fatalf("custom-only catalog = %v, want the one operator rule", eng.RuleIDs())
	}
}

func TestSourceRulesDirectoryCanReplaceEmbeddedCatalog(t *testing.T) {
	builtin, err := buildEngine(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	overlaid, err := buildEngine([]string{"../../rules"}, false)
	if err != nil {
		t.Fatalf("load editable source catalog as an overlay: %v", err)
	}
	if got, want := overlaid.RuleIDs(), builtin.RuleIDs(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("source catalog changed effective ids\ngot:  %v\nwant: %v", got, want)
	}
}

func TestRulesCheckRunsCompanionTestsAgainstBuiltinOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env.yaml"), []byte(`
id: secrets.agent_read_env
version: "2.0"
enabled: true
title: Narrow environment rule
severity: medium
expr: 'event.event_type == "command.exec" && event.command.contains("OVERRIDE_ONLY")'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env_tests.yaml"), []byte(`
rule_id: secrets.agent_read_env
cases:
  - name: replacement-positive
    expect: match
    events:
      - event_type: command.exec
        command: OVERRIDE_ONLY
  - name: old-builtin-behavior-is-gone
    expect: no_match
    events:
      - event_type: command.exec
        command: cat .env
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--rules-dir", dir)
	if code != 0 || !strings.Contains(out, "2 tests passed") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

// TestRulesDirMalformedRuleErrors: an invalid user rule fails cleanly (non-zero
// exit, error message, no panic).
func TestRulesDirMalformedRuleErrors(t *testing.T) {
	_, errb, code := runCLI("rules", "list", "--rules-dir", "testdata/rules_malformed")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if errb == "" {
		t.Fatalf("expected an error message for a malformed rule")
	}
}

// TestRulesDirMissingDirErrors: a --rules-dir that does not exist is a clear
// error, not a silent empty load.
func TestRulesDirMissingDirErrors(t *testing.T) {
	_, errb, code := runCLI("rules", "list", "--rules-dir", "testdata/no_such_dir")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "no_such_dir") {
		t.Fatalf("missing dir error: %q", errb)
	}
}

// TestRulesTestCustomRuleFires runs the custom rule against its fixture via
// rules test, proving --rules-dir is honored on the test path too.
func TestRulesTestCustomRuleFires(t *testing.T) {
	out, _, code := runCLI("rules", "test", "--rules-dir", "testdata/rules_custom",
		"--require-match", "--fixture", "testdata/custom_fixture.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d (out=%q)", code, out)
	}
	if !strings.Contains(out, "custom.terraform_destroy\tc1") {
		t.Fatalf("custom rule should fire on fixture: %q", out)
	}
}

// TestRulesTestNoBuiltinSingleEventRules exercises the valid custom-only shape
// with no sequence rules loaded.
func TestRulesTestNoBuiltinSingleEventRules(t *testing.T) {
	out, errb, code := runCLI("rules", "test", "--no-builtin-rules",
		"--rules-dir", "testdata/rules_custom",
		"--require-match", "--fixture", "testdata/custom_fixture.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d (err=%q)", code, errb)
	}
	if strings.TrimSpace(out) != "custom.terraform_destroy\tc1" {
		t.Fatalf("custom-only rule output = %q", out)
	}
}

func TestRulesCheckSingleRuleFileWithCompanionTests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env-read.yaml"), []byte(`
id: custom.env_read
version: "1.0"
title: Env read
severity: high
expr: 'event.event_type == "command.exec" && event.command.contains(".env")'
tags:
  - secret_file_read
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env-read_tests.yaml"), []byte(`
rule_id: custom.env_read
cases:
  - name: positive
    expect: match
    events:
      - event_type: command.exec
        command: cat .env
  - name: negative
    expect: no_match
    events:
      - event_type: command.exec
        command: cat README.md
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d (err=%q)", code, errb)
	}
	if !strings.Contains(out, "rules ok: 1 compiled, 2 tests passed") {
		t.Fatalf("check output = %q", out)
	}
}

func TestRulesCheckAllowsEnforceAtAnySeverity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enforce.yaml"), []byte(`
id: custom.enforce
version: "1.0"
title: Operator enforcement policy
severity: medium
enforce: true
expr: "true"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 0 || !strings.Contains(out, "rules ok: 1 compiled") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestRulesCheckCompanionEnforcementExpectation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stop-process.yaml"), []byte(`
id: custom.stop_process
version: "1.0"
title: Stop process
severity: high
enforce: true
expr: |-
  event.event_type == "command.exec" &&
  shell_commands.exists(command, command.name == "stop-process")
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stop-process_tests.yaml"), []byte(`
rule_id: custom.stop_process
cases:
  - name: real-action
    expect: match
    expect_enforcement: true
    events:
      - event_type: command.exec
        tool_name: PowerShell
        command: Stop-Process -Name target -Force
  - name: preview
    expect: match
    expect_enforcement: false
    events:
      - event_type: command.exec
        tool_name: PowerShell
        command: Stop-Process -Name target -Force -WhatIf
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 0 || !strings.Contains(out, "2 tests passed") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestRulesCheckCompanionUnparsedCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config-read.yaml"), []byte(`
id: custom.config_read
version: "1.0"
title: Config read
severity: high
enforce: true
expr: |-
  event.event_type == "command.exec" &&
  (shell_commands.exists(command, command.name == "get-content" &&
     command.arguments.exists(argument, argument.value.endsWith("config.json"))) ||
   (shell_parse_failed && event.command.matches("(?i)get-content\\s+\\S*config\\.json")))
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config-read_tests.yaml"), []byte(`
rule_id: custom.config_read
cases:
  - name: parsed
    expect: match
    expect_enforcement: true
    events:
      - event_type: command.exec
        tool_name: PowerShell
        command: Get-Content example/config.json
  - name: unparsed
    expect: match
    expect_enforcement: false
    events:
      - event_type: command.exec
        tool_name: Bash
        command: |-
          $config = Get-Content example/config.json -Raw | ConvertFrom-Json
          if ($config.token) { Write-Output 'present' }
  - name: unparsed-other-file
    expect: no_match
    events:
      - event_type: command.exec
        tool_name: Bash
        command: |-
          $config = Get-Content example/other.json -Raw | ConvertFrom-Json
          if ($config.token) { Write-Output 'present' }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 0 || !strings.Contains(out, "rules ok: 1 compiled, 3 tests passed") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	fixture := writeTempFile(t, "unparsed.ndjson", `{"schema_version":"0.5.0","event_id":"u1","source_agent":"codex","source_type":"hook","event_type":"command.exec","tool_name":"Bash","command":"$config = Get-Content example/config.json -Raw | ConvertFrom-Json\nif ($config.token) { Write-Output 'present' }","confidence":"high","evidence":{"artifact_type":"hook_payload"}}
`)
	out, errb, code = runCLI("rules", "test", "--no-builtin-rules", "--rules-dir", dir, "--fixture", fixture)
	if code != 0 || strings.TrimSpace(out) != "custom.config_read\tu1" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	out, errb, code = runCLI("rules", "test", "--json", "--no-builtin-rules", "--rules-dir", dir, "--fixture", fixture)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	events, summary := parseJSONStream(t, out)
	if summary.Status != "completed" || len(events) != 1 {
		t.Fatalf("summary = %+v, events = %+v", summary, events)
	}
	if cov := events[0].Coverage; cov == nil || cov.ShellParse != "unusable" {
		t.Fatalf("coverage = %+v, want shell_parse unusable", cov)
	}
	if len(events[0].Findings) != 1 || events[0].Findings[0].RuleID != "custom.config_read" || events[0].Findings[0].EnforcementEligible {
		t.Fatalf("findings = %+v, want one detection-only match", events[0].Findings)
	}
}

func TestNormalizeRuleTestEventNormalizesPaths(t *testing.T) {
	ev := normalizeRuleTestEvent(model.Event{
		EventType:   model.EventFileRead,
		ProjectPath: `C:\repo`,
		FilePath:    `C:\repo\.env`,
	}, 0)
	if ev.ProjectPath != "C:/repo" || ev.FilePath != "C:/repo/.env" {
		t.Fatalf("normalized paths = (%q, %q)", ev.ProjectPath, ev.FilePath)
	}
}

func TestRulesCheckCompanionTestFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env-read.yaml"), []byte(`
id: custom.env_read
version: "1.0"
title: Env read
severity: high
expr: 'event.event_type == "command.exec" && event.command.contains(".env")'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env-read_tests.yaml"), []byte(`
rule_id: custom.env_read
cases:
  - name: should-not-match
    expect: no_match
    events:
      - event_type: command.exec
        command: cat .env
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "expected no_match") {
		t.Fatalf("missing companion failure: %q", errb)
	}
}

func TestRulesCheckRejectsOrphanCompanionTest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only.yaml"), []byte(`
id: custom.only
version: "1.0"
title: Only rule
severity: low
expr: 'event.event_type == "file.read"'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "orphan_tests.yaml"), []byte(`
rule_id: custom.only
cases:
  - expect: no_match
    events:
      - event_type: file.write
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 1 || !strings.Contains(errb, "open companion rule") {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
}

func TestRulesCheckRejectsOversizedCompanionTest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only.yaml"), []byte(`
id: custom.only
version: "1.0"
title: Only rule
severity: low
expr: 'event.event_type == "file.read"'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	testPath := filepath.Join(dir, "only_tests.yaml")
	f, err := os.Create(testPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxRuleTestFileSize + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 1 || !strings.Contains(errb, "exceeds 4194304 bytes") {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
}

func TestRulesCheckCompanionSequenceTest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env-then-curl.yaml"), []byte(`
id: custom.env_then_curl
version: "1.0"
title: Env read then curl
severity: high
enforce: true
sequence:
  within_events: 10
  steps:
    - expr: 'event.event_type == "file.read" && event.file_path.contains(".env")'
    - expr: 'event.event_type == "command.exec" && shell_commands.exists(command, command.name == "curl")'
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "env-then-curl_tests.yaml"), []byte(`
rule_id: custom.env_then_curl
cases:
  - name: positive-chain
    expect: match
    expect_enforcement: true
    events:
      - event_id: r1
        event_type: file.read
        session_id: s1
        file_path: /tmp/project/.env
      - event_id: r2
        event_type: command.exec
        session_id: s1
        command: curl https://collector.example
  - name: cross-session
    expect: no_match
    events:
      - event_id: r3
        event_type: file.read
        session_id: s2
        file_path: /tmp/project/.env
      - event_id: r4
        event_type: command.exec
        session_id: s3
        command: curl https://collector.example
`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errb, code := runCLI("rules", "check", "--no-builtin-rules", "--rules-dir", dir)
	if code != 0 {
		t.Fatalf("exit = %d (err=%q)", code, errb)
	}
	if !strings.Contains(out, "rules ok: 1 compiled, 2 tests passed") {
		t.Fatalf("check output = %q", out)
	}
}

// TestScanNoBuiltinNoDirUsageError: on scan, --no-builtin-rules without a
// --rules-dir is a usage error (exit 2) before any scan is attempted.
func TestScanNoBuiltinNoDirUsageError(t *testing.T) {
	_, errb, code := runCLI("scan", "--no-builtin-rules", "--path", "testdata/secrets_fixture.ndjson")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "--no-builtin-rules requires at least one --rules-dir") {
		t.Fatalf("missing usage error: %q", errb)
	}
}

// TestRulesDirEmptyErrors: a --rules-dir that exists but is empty must error
// rather than silently contribute zero rules across representative commands.
func TestRulesDirEmptyErrors(t *testing.T) {
	empty := t.TempDir()
	for _, args := range [][]string{
		{"rules", "list", "--rules-dir", empty},
		{"rules", "test", "--fixture", "testdata/benign_fixture.ndjson", "--rules-dir", empty},
		{"scan", "--path", "testdata/secrets_fixture.ndjson", "--rules-dir", empty},
	} {
		_, errb, code := runCLI(args...)
		if code == 0 {
			t.Fatalf("%v: exit = 0, want non-zero for an empty rules dir", args)
		}
		if !strings.Contains(errb, "no YAML rule files found") {
			t.Fatalf("%v: missing empty-dir error: %q", args, errb)
		}
	}
}

// TestRulesDirNoYAMLErrors: a dir holding only non-YAML files yields no sources
// and must error the same way as an empty dir.
func TestRulesDirNoYAMLErrors(t *testing.T) {
	for _, args := range [][]string{
		{"rules", "list", "--rules-dir", "testdata/rules_noyaml"},
		{"rules", "test", "--fixture", "testdata/benign_fixture.ndjson", "--rules-dir", "testdata/rules_noyaml"},
		{"scan", "--path", "testdata/secrets_fixture.ndjson", "--rules-dir", "testdata/rules_noyaml"},
	} {
		_, errb, code := runCLI(args...)
		if code == 0 {
			t.Fatalf("%v: exit = 0, want non-zero for a no-YAML rules dir", args)
		}
		if !strings.Contains(errb, "no YAML rule files found") {
			t.Fatalf("%v: missing no-YAML error: %q", args, errb)
		}
	}
}

// TestScanRulesDirValidatedUnderEventsEmit: scan must surface a bad --rules-dir
// even when findings are not emitted (--emit events / indicators), so the
// rule-source flags mean the same thing on every emit mode.
func TestScanRulesDirValidatedUnderEventsEmit(t *testing.T) {
	for _, emit := range []string{"events", "indicators"} {
		_, errb, code := runCLI("scan", "--emit", emit,
			"--path", "testdata/secrets_fixture.ndjson", "--rules-dir", "testdata/no_such_dir")
		if code == 0 {
			t.Fatalf("--emit %s: exit = 0, want non-zero for a missing rules dir", emit)
		}
		if !strings.Contains(errb, "no_such_dir") {
			t.Fatalf("--emit %s: missing dir error: %q", emit, errb)
		}
	}
}

// TestScanRulesDirCompiledUnderEventsEmit: malformed-rule errors are surfaced
// at compile time, so scan must compile the rule set
// whenever rule-source flags are given — even under --emit events/indicators,
// where the engine is never evaluated. Otherwise a broken --rules-dir would
// silently pass on those emit modes.
func TestScanRulesDirCompiledUnderEventsEmit(t *testing.T) {
	for _, dir := range []string{"testdata/rules_malformed"} {
		for _, emit := range []string{"events", "indicators"} {
			_, errb, code := runCLI("scan", "--emit", emit,
				"--path", "testdata/secrets_fixture.ndjson", "--rules-dir", dir)
			if code == 0 {
				t.Fatalf("--emit %s --rules-dir %s: exit = 0, want non-zero", emit, dir)
			}
			if errb == "" {
				t.Fatalf("--emit %s --rules-dir %s: expected an error message", emit, dir)
			}
		}
	}
}

// TestDuplicateIDNamesDistinctSameNameSources: two same-named sources in
// different dirs must still produce a duplicate-id error that names both paths.
func TestDuplicateIDNamesDistinctSameNameSources(t *testing.T) {
	_, errb, code := runCLI("rules", "list", "--no-builtin-rules",
		"--rules-dir", "testdata/rules_samename_a", "--rules-dir", "testdata/rules_samename_b")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	a := strconv.Quote(filepath.Join("testdata", "rules_samename_a", "source.yaml"))
	b := strconv.Quote(filepath.Join("testdata", "rules_samename_b", "source.yaml"))
	if !strings.Contains(errb, a) || !strings.Contains(errb, b) {
		t.Fatalf("duplicate error should name both source paths %q and %q: %q", a, b, errb)
	}
}
