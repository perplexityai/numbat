package main

import (
	"bytes"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

func runCLI(args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

// runCLIStdin drives the CLI with an explicit stdin body, for the hook handler
// which reads its payload from stdin.
func runCLIStdin(stdin string, args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

func TestVersion(t *testing.T) {
	out, _, code := runCLI("version")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "numbat") || !strings.Contains(out, "schema 0.3.0") {
		t.Fatalf("version output = %q", out)
	}
}

func TestVersionRejectsStrayArg(t *testing.T) {
	for _, args := range [][]string{{"version", "extra"}, {"--version", "extra"}, {"--version", "--help"}, {"help", "version", "extra"}} {
		_, errb, code := runCLI(args...)
		if code != 2 || !strings.Contains(errb, "unexpected argument") {
			t.Fatalf("%v: exit=%d stderr=%q", args, code, errb)
		}
	}
}

func TestVersionHelp(t *testing.T) {
	for _, args := range [][]string{{"version", "--help"}, {"version", "-h"}, {"help", "version"}} {
		out, errb, code := runCLI(args...)
		if code != 0 || errb != "" || !strings.Contains(out, "usage: numbat version") {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out, errb)
		}
	}
}

func TestTopLevelHelpListsHookAdminActions(t *testing.T) {
	out, errb, code := runCLI("--help")
	if code != 0 || errb != "" {
		t.Fatalf("exit=%d stderr=%q", code, errb)
	}
	for _, want := range []string{
		"observe, detect, block, and reconstruct AI agent activity on the endpoint",
		"numbat hook install",
		"numbat hook uninstall",
		"numbat hook status",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q", want)
		}
	}
}

func TestHelpDescribesOperationalBoundaries(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "scan artifacts",
			args: []string{"help", "scan"},
			want: []string{"supported on-disk agent artifacts", envHTTPToken, envHTTPHMACKey},
		},
		{
			name: "collect endpoint",
			args: []string{"help", "collect"},
			want: []string{"OTLP/HTTP protobuf logs", "http://127.0.0.1:4318/v1/logs", "HTTP record-delivery auth secrets"},
		},
		{
			name: "ship delivery",
			args: []string{"help", "ship"},
			want: []string{"Retained records up to 8 MiB are delivered at least once", "Receivers must tolerate duplicates", "larger than 8 MiB"},
		},
		{
			name: "hook enforcement",
			args: []string{"help", "hook"},
			want: []string{"deny supported pre-action requests", "does not verify execution or record delivery"},
		},
		{
			name: "hook status",
			args: []string{"help", "hook", "status"},
			want: []string{"does not verify agent trust", "activation, execution, or record delivery"},
		},
		{
			name: "agents wired state",
			args: []string{"help", "agents"},
			want: []string{"WIRED means numbat-owned configuration is present", "does not verify runtime activation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, errb, code := runCLI(tt.args...)
			if code != 0 || errb != "" {
				t.Fatalf("%v: exit=%d stderr=%q", tt.args, code, errb)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("%v help missing %q; output=%q", tt.args, want, out)
				}
			}
		})
	}
}

func TestNoArgsUsage(t *testing.T) {
	_, errb, code := runCLI()
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "usage:") {
		t.Fatalf("missing usage: %q", errb)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	_, errb, code := runCLI("frobnicate")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unknown subcommand") {
		t.Fatalf("missing error: %q", errb)
	}
}

func TestHelpSubcommandDispatch(t *testing.T) {
	out, errb, code := runCLI("help", "scan")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb)
	}
	if errb != "" {
		t.Fatalf("numbat help scan should write help to stdout, stderr=%q", errb)
	}
	if !strings.Contains(out, "usage: numbat scan") {
		t.Fatalf("scan help should come from the scan command, got stdout=%q stderr=%q", out, errb)
	}

	out, errb, code = runCLI("help", "ship")
	if code != 0 || errb != "" || !strings.Contains(out, "usage: numbat ship") {
		t.Fatalf("ship help dispatch: exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	out, errb, code = runCLI("help", "rules", "test")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb)
	}
	if errb != "" {
		t.Fatalf("numbat help rules test should write help to stdout, stderr=%q", errb)
	}
	if !strings.Contains(out, "usage: numbat rules test") {
		t.Fatalf("rules test help should come from the rules command, got stdout=%q stderr=%q", out, errb)
	}

	out, errb, code = runCLI("help", "rules", "check")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb)
	}
	if errb != "" {
		t.Fatalf("numbat help rules check should write help to stdout, stderr=%q", errb)
	}
	if !strings.Contains(out, "usage: numbat rules check") {
		t.Fatalf("rules check help should come from the rules command, got stdout=%q stderr=%q", out, errb)
	}

	out, errb, code = runCLI("help", "hook", "install")
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb)
	}
	if errb != "" {
		t.Fatalf("numbat help hook install should write help to stdout, stderr=%q", errb)
	}
	if !strings.Contains(out, "usage: numbat hook install") {
		t.Fatalf("hook install help should come from the hook admin command, got stdout=%q stderr=%q", out, errb)
	}
}

func TestHelpRejectsUnknownOrTrailingTopics(t *testing.T) {
	for _, args := range [][]string{
		{"help", "scan", "extra"},
		{"help", "ship", "extra"},
		{"help", "hook", "install", "extra"},
		{"help", "rules", "test", "extra"},
		{"help", "case", "build", "extra"},
		{"help", "hook", "unknown"},
		{"help", "rules", "unknown"},
		{"help", "case", "unknown"},
	} {
		_, errb, code := runCLI(args...)
		if code != 2 {
			t.Fatalf("%v: exit=%d, want 2", args, code)
		}
		if !strings.Contains(errb, "unexpected argument") && !strings.Contains(errb, "unknown help topic") {
			t.Fatalf("%v: stderr=%q", args, errb)
		}
	}
}

func TestRulesList(t *testing.T) {
	out, _, code := runCLI("rules", "list")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "secrets.agent_read_env") {
		t.Fatalf("rules list missing built-in rule: %q", out)
	}
}

func TestRulesListHelpExitsZero(t *testing.T) {
	_, _, code := runCLI("rules", "list", "--help")
	if code != 0 {
		t.Fatalf("rules list --help exit = %d, want 0", code)
	}
}

func TestRulesFieldsRemoved(t *testing.T) {
	_, errb, code := runCLI("rules", "fields")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, `unknown rules subcommand "fields"`) {
		t.Fatalf("missing unknown-subcommand error: %q", errb)
	}
}

func TestRepeatablePathFlagsRejectEmptyValue(t *testing.T) {
	cases := [][]string{
		{"scan", "--path", ""},
		{"timeline", "--path", ""},
		{"rules", "list", "--rules-dir", ""},
	}
	for _, args := range cases {
		t.Run(strings.Join(args[:len(args)-1], "_"), func(t *testing.T) {
			_, errb, code := runCLI(args...)
			if code != 2 {
				t.Fatalf("%v exit = %d, want 2", args, code)
			}
			if !strings.Contains(errb, "value must not be empty") {
				t.Fatalf("%v missing empty-value error: %q", args, errb)
			}
		})
	}
}

func TestArtifactAgentSelection(t *testing.T) {
	sourceAgents := make([]string, 0, len(artifactAgentByCLI))
	names := make([]string, 0, len(artifactAgentByCLI))
	for name, sourceAgent := range artifactAgentByCLI {
		names = append(names, name)
		sourceAgents = append(sourceAgents, sourceAgent)
	}
	sort.Strings(names)
	sort.Strings(sourceAgents)
	if !slices.Equal(names, artifactAgentNames) {
		t.Fatalf("artifact agent names = %v, displayed names = %v", names, artifactAgentNames)
	}
	if want := extract.RegisteredAgents(); !slices.Equal(sourceAgents, want) {
		t.Fatalf("selectable source agents = %v, registered parsers = %v", sourceAgents, want)
	}

	got, err := parseArtifactAgents([]string{"codex", "claude", "codex", "cowork"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{model.AgentCodex, model.AgentClaudeCode, model.AgentCowork}
	if !slices.Equal(got, want) {
		t.Fatalf("selected agents = %v, want %v", got, want)
	}

	for _, name := range []string{"qwen", "not-an-agent"} {
		if _, err := parseArtifactAgents([]string{name}); err == nil {
			t.Errorf("parseArtifactAgents(%q) succeeded, want error", name)
		}
	}
	usage := artifactAgentUsage()
	for _, name := range []string{"claude", "codex", "cowork", "gemini", "kimi", "openclaw"} {
		if !strings.Contains(usage, name) {
			t.Errorf("artifact agent usage %q missing %q", usage, name)
		}
	}
	if strings.Contains(usage, "qwen") {
		t.Errorf("artifact agent usage %q includes hook-only qwen", usage)
	}
	for name, sourceAgent := range artifactAgentByCLI {
		if name == "cowork" {
			continue
		}
		got, err := hook.ParseAgent(name)
		if err != nil || got != sourceAgent {
			t.Errorf("artifact alias %q = %q, hook alias = %q (%v)", name, sourceAgent, got, err)
		}
	}
}

func TestArtifactAgentFlagsRejectInvalidCombinations(t *testing.T) {
	for _, command := range []string{"scan", "timeline"} {
		t.Run(command, func(t *testing.T) {
			for _, args := range [][]string{
				{command, "--agent", ""},
				{command, "--agent", "not-an-agent"},
				{command, "--agent", "qwen"},
				{command, "--agent", "codex", "--path", t.TempDir()},
			} {
				_, errb, code := runCLI(args...)
				if code != 2 {
					t.Fatalf("%v exit = %d, want 2 (stderr=%q)", args, code, errb)
				}
			}
		})
	}
}

func TestRulesCheck(t *testing.T) {
	out, _, code := runCLI("rules", "check")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	// Keep this count explicit: a catalog addition or removal must be reviewed,
	// not normalized away by deriving the expected value from the same load.
	if !strings.Contains(out, "rules ok: 52 compiled") {
		t.Fatalf("check output = %q", out)
	}
}

func TestRulesCheckRejectsBadRule(t *testing.T) {
	_, errb, code := runCLI("rules", "check", "--rules-dir", "testdata/rules_malformed")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "invalid severity") {
		t.Fatalf("missing load error: %q", errb)
	}
}

func TestRulesTestHelpExitsZero(t *testing.T) {
	_, _, code := runCLI("rules", "test", "--help")
	if code != 0 {
		t.Fatalf("rules test --help exit = %d, want 0", code)
	}
}

func TestRulesListRejectsStrayArg(t *testing.T) {
	_, errb, code := runCLI("rules", "list", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unexpected argument") {
		t.Fatalf("missing unexpected-argument error: %q", errb)
	}
}

func TestRulesTestRejectsStrayArg(t *testing.T) {
	_, errb, code := runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unexpected argument") {
		t.Fatalf("missing unexpected-argument error: %q", errb)
	}
}

func TestRulesTestFixture(t *testing.T) {
	out, _, code := runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d (out=%q)", code, out)
	}
	// e1 (cat .env) and e2 (ssh key) must fire; e3 (.env.example) must not.
	if !strings.Contains(out, "secrets.agent_read_env\te1") {
		t.Fatalf("e1 should fire: %q", out)
	}
	if !strings.Contains(out, "secrets.read_private_key\te2") {
		t.Fatalf("e2 should fire: %q", out)
	}
	if strings.Contains(out, "\te3") {
		t.Fatalf("e3 (.env.example) should not fire: %q", out)
	}
}

func TestRulesTestNormalizesWindowsPaths(t *testing.T) {
	eng, err := rule.NewEngine([]rule.Source{{Rules: []rule.Rule{{
		ID:       "windows-path",
		Version:  "1.0",
		Title:    "Windows path",
		Severity: model.SeverityLow,
		Expr:     `event.file_path == "C:/repo/.env"`,
	}}}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	in := strings.NewReader(`{"schema_version":"0.3.0","event_id":"e","source_agent":"claude-code","source_type":"artifact","event_type":"file.read","file_path":"C:\\repo\\.env","confidence":"high","evidence":{"artifact_type":"fixture","local_path":"fixture"}}` + "\n")
	var out bytes.Buffer
	matched, _, err := evalFixture(eng, in, &out)
	if err != nil {
		t.Fatalf("evalFixture: %v", err)
	}
	if matched != 1 || !strings.Contains(out.String(), "windows-path\te") {
		t.Fatalf("matches = %d, output = %q, want normalized Windows path match", matched, out.String())
	}
}

func TestRulesTestMissingFixtureFlag(t *testing.T) {
	_, errb, code := runCLI("rules", "test")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "rules test: --fixture is required") {
		t.Fatalf("missing flag error: %q", errb)
	}
}

func TestRulesTestNoSuchFile(t *testing.T) {
	_, _, code := runCLI("rules", "test", "--fixture", "testdata/does_not_exist.ndjson")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

func TestRulesTestBenignFixtureExitsZero(t *testing.T) {
	// A fixture with no matching events is a clean run, not a failure.
	_, _, code := runCLI("rules", "test", "--fixture", "testdata/benign_fixture.ndjson")
	if code != 0 {
		t.Fatalf("benign fixture exit = %d, want 0", code)
	}
}

func TestRulesTestRequireMatchFailsOnNoMatch(t *testing.T) {
	_, errb, code := runCLI("rules", "test", "--require-match", "--fixture", "testdata/benign_fixture.ndjson")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "no rules matched") {
		t.Fatalf("missing no-match message: %q", errb)
	}
}

func TestRulesTestExpectRule(t *testing.T) {
	_, errb, code := runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson", "--expect", "secrets.agent_read_env")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb)
	}
	_, errb, code = runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson", "--expect", "secrets.nope")
	if code != 1 {
		t.Fatalf("missing expected rule exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "expected rule(s) did not match: secrets.nope") {
		t.Fatalf("missing expect diagnostic: %q", errb)
	}
}

func TestRulesTestExpectNone(t *testing.T) {
	_, errb, code := runCLI("rules", "test", "--fixture", "testdata/benign_fixture.ndjson", "--expect-none")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb)
	}
	_, errb, code = runCLI("rules", "test", "--fixture", "testdata/secrets_fixture.ndjson", "--expect-none")
	if code != 1 {
		t.Fatalf("positive fixture with --expect-none exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "expected no matches") {
		t.Fatalf("missing expect-none diagnostic: %q", errb)
	}
}

func TestRulesTestExpectNoneRejectsConflicts(t *testing.T) {
	_, errb, code := runCLI("rules", "test", "--fixture", "testdata/benign_fixture.ndjson", "--expect-none", "--expect", "secrets.agent_read_env")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "rules test: --expect-none cannot be combined") {
		t.Fatalf("missing conflict diagnostic: %q", errb)
	}
}

func TestEvalFixtureSurfacesRuntimeEvalError(t *testing.T) {
	// A rule that indexes a short string out of range errors at eval time.
	// evalFixture must surface that as an error (which the CLI maps to exit 1)
	// rather than silently dropping it.
	eng, err := rule.NewEngine([]rule.Source{{Rules: []rule.Rule{{
		ID: "boom", Version: "test", Title: "eval boom", Severity: model.SeverityLow, Expr: `event.command[10] == "x"`,
	}}}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	in := strings.NewReader(`{"event_id":"e","event_type":"command.exec","command":"hi"}` + "\n")
	var out bytes.Buffer
	if _, _, err := evalFixture(eng, in, &out); err == nil {
		t.Fatalf("expected runtime eval error to surface")
	}
}

func TestEvalFixtureRejectsInvalidEvent(t *testing.T) {
	eng, err := rule.NewEngine([]rule.Source{{Rules: []rule.Rule{{
		ID: "valid", Version: "1.0", Title: "valid", Severity: model.SeverityLow, Expr: `true`,
	}}}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	in := strings.NewReader(`{"schema_version":"0.3.0","event_id":"e","source_agent":"claude-code","source_type":"artifact","event_type":"file.read","confidence":"high","evidence":{}}` + "\n")
	var out bytes.Buffer
	_, _, err = evalFixture(eng, in, &out)
	if err == nil || !strings.Contains(err.Error(), "fixture line 1") || !strings.Contains(err.Error(), "empty evidence.artifact_type") {
		t.Fatalf("evalFixture error = %v, want line-specific event validation", err)
	}
}
