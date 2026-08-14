package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	internalhook "github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
)

// panicWriter panics on its first Write, used to force a panic deep inside the
// hook processing path (the first diagnostic write) so the recover guard can be
// exercised end-to-end.
type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("injected panic from stderr write") }

// firstWritePanicWriter panics on its FIRST Write and writes normally after.
// It models the worst case for the no-block guarantee: the up-front passthrough
// write itself panics. The recover guard must retry the write, and that retry
// (the second Write) must land the passthrough on the buffer.
type firstWritePanicWriter struct {
	buf      bytes.Buffer
	panicked bool
}

func (w *firstWritePanicWriter) Write(p []byte) (int, error) {
	if !w.panicked {
		w.panicked = true
		panic("injected panic from initial stdout write")
	}
	return w.buf.Write(p)
}

// A panic anywhere on the hook path must NOT crash the process before the
// passthrough is written: the recover guard turns it into the same inert
// outcome as an error return — print {} on stdout and exit 0 — so the blocked
// agent is never broken. Here a garbage payload forces a diagnostic write, and
// that write panics; the passthrough must still land on stdout.
func TestHookRecoversFromPanicAndPrintsPassthrough(t *testing.T) {
	var out bytes.Buffer
	code := runHookEvent("post-tool", []string{"--agent", "claude"}, strings.NewReader("not json"), &out, panicWriter{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the processing path panics", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {} after a recovered panic", got)
	}
	// Exactly one passthrough line: the up-front write and the recover guard must
	// not both emit, or the agent would read a second stray decision line.
	if n := strings.Count(out.String(), "{}"); n != 1 {
		t.Fatalf("passthrough written %d times, want exactly 1", n)
	}
}

// The hardest case for the no-block guarantee: the INITIAL up-front stdout write
// is itself what panics. Because passthroughWritten is set only after a
// successful write, the deferred recover sees it still false and retries — and
// the retry must land the passthrough on stdout while the process exits 0. A
// regression where the flag is set before the write would leave stdout empty.
func TestHookRecoversFromInitialStdoutWritePanic(t *testing.T) {
	stdout := &firstWritePanicWriter{}
	var errb bytes.Buffer
	code := runHookEvent("post-tool", []string{"--agent", "claude"}, strings.NewReader("{}"), stdout, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the initial stdout write panics", code)
	}
	if got := strings.TrimSpace(stdout.buf.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {} after the retried write", got)
	}
	if n := strings.Count(stdout.buf.String(), "{}"); n != 1 {
		t.Fatalf("passthrough written %d times, want exactly 1", n)
	}
}

// The normal (non-panic) path must write the passthrough EXACTLY once: the
// up-front write succeeds and the writeOnce guard must keep any later call
// (there is none here, but the guard is the contract) from emitting a second {}.
func TestHookNormalPathWritesPassthroughExactlyOnce(t *testing.T) {
	var out bytes.Buffer
	code := runHookEvent("pre-tool", []string{"--agent", "claude"}, strings.NewReader(`{"session_id":"s1"}`), &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if n := strings.Count(out.String(), "{}"); n != 1 {
		t.Fatalf("passthrough written %d times, want exactly 1 on the normal path", n)
	}
}

func TestAntigravityHookWritesRequiredControlDecision(t *testing.T) {
	tests := []struct {
		event   string
		payload string
		want    string
	}{
		{"PreToolUse", `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"pwd"}}}`, "ask"},
		{"Stop", `{"conversationId":"c1","fullyIdle":true,"terminationReason":"model_stop"}`, "stop"},
	}
	for _, tc := range tests {
		t.Run(tc.event, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookEvent(tc.event, []string{"--agent", "antigravity", "--emit", "events"}, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
			}
			var response map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
				t.Fatalf("stdout = %q: %v", stdout.String(), err)
			}
			if response["decision"] != tc.want {
				t.Fatalf("response = %#v, want decision %q", response, tc.want)
			}
		})
	}
}

// The hook handler must ALWAYS print the agent's inert passthrough on stdout and
// exit 0, so it can never block or break the user's agent. For Claude the
// passthrough is the empty object {}.
func TestHookPrintsPassthroughAndExitsZero(t *testing.T) {
	payload := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	out, _, code := runCLIStdin(payload, "hook", "pre-tool", "--agent", "claude")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	got := strings.TrimSpace(out)
	if got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {}", got)
	}
}

func TestKiroSuccessfulHookWritesNoAgentContext(t *testing.T) {
	setTestHome(t, t.TempDir())
	payload := `{"session_id":"s1","tool_name":"execute_bash","tool_input":{"command":"pwd"}}`
	for _, tc := range []struct {
		name    string
		payload string
		args    []string
		errText string
	}{
		{name: "monitor", payload: payload, args: []string{"--agent", "kiro"}},
		{name: "fail open", payload: "not json", args: []string{"--agent", "kiro"}, errText: "hook payload decode"},
		{
			name:    "enforce allow",
			payload: payload,
			args: []string{
				"--agent", "kiro", "--enforce", "--output", "file",
				"--output-file", filepath.Join(t.TempDir(), "findings.ndjson"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookEvent("pre-tool", tc.args, strings.NewReader(tc.payload), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, want successful allow; stderr=%q", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want zero bytes so Kiro adds no agent context", stdout.String())
			}
			if tc.errText != "" && !strings.Contains(stderr.String(), tc.errText) {
				t.Fatalf("stderr = %q, want %q diagnostic", stderr.String(), tc.errText)
			}
		})
	}
}

func TestHookDoesNotAcceptProfileFlag(t *testing.T) {
	_, errb, code := runCLIStdin(`{}`, "hook", "pre-tool", "--agent", "claude", "--profile", "evidence")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "flag provided but not defined") || !strings.Contains(errb, "-profile") {
		t.Fatalf("stderr = %q, want unknown --profile flag", errb)
	}

	_, errb, code = runCLIStdin("", "hook", "pre-tool", "--agent", "claude", "--help")
	if code != 0 {
		t.Fatalf("help exit = %d, want 0", code)
	}
	if strings.Contains(errb, "--profile") {
		t.Fatalf("hook help still advertises --profile:\n%s", errb)
	}
}

func TestHookFullContentWritesRedactedEvent(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "records.ndjson")
	secret := "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	prompt := strings.Repeat("ordinary context ", 20) + secret
	payload, err := json.Marshal(map[string]any{
		"hookEventName": "UserPromptSubmitted",
		"prompt":        prompt,
		"cwd":           "/proj",
	})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCLIStdin(string(payload), "hook", "UserPromptSubmitted",
		"--agent", "copilot", "--emit", "events", "--content", "full",
		"--output", "file", "--output-file", outFile)
	if code != 0 || strings.TrimSpace(stdout) != "{}" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var ev model.Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.EventType != model.EventPromptUser || ev.Content == "" || strings.Contains(ev.Content, secret) || ev.ContentBytes != len(prompt) {
		t.Fatalf("hook event content = %+v", ev)
	}
}

func TestHookInstallWiresFullContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--emit", "events", "--content", "full")
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, command := range claudeInstalledCommands(t, path) {
		if !strings.Contains(command, "--content=full") {
			t.Fatalf("installed command missing full-content option: %q", command)
		}
	}
}

// A finding produced by a hook event is written to the configured sink, not to
// stdout (stdout is reserved for the passthrough the agent reads). With
// --output=file the secrets rule fires on `cat .env` and the finding lands in
// the file while stdout still carries only {}.
func TestHookWritesFindingToFileSinkNotStdout(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "findings.ndjson")
	payload := `{"session_id":"s1","cwd":"/proj","model":"gpt-5.5-codex","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	out, _, code := runCLIStdin(payload, "hook", "codex-pre-tool", "--agent", "codex", "--output", "file", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Fatalf("stdout = %q, want {} only", out)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read sink file: %v", err)
	}
	if !strings.Contains(string(data), "secrets.agent_read_env") {
		t.Fatalf("expected secrets finding in sink file, got: %s", data)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("record count = %d, want finding + enforcement decision\n%s", len(lines), data)
	}
	var f model.Finding
	if err := json.Unmarshal(lines[0], &f); err != nil {
		t.Fatalf("finding line is not JSON: %v\n%s", err, data)
	}
	if f.SourceAgent != model.AgentCodex || f.SourceType != model.SourceHook || f.Model != "gpt-5.5-codex" || f.Redacted {
		t.Fatalf("finding context wrong: %+v", f)
	}
	if len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0].ArtifactType != model.SourceHook || f.EvidenceRefs[0].LocalPath != "" {
		t.Fatalf("hook evidence ref should be thin and pathless, got: %+v", f.EvidenceRefs)
	}
	// The finding's evidence ref carries the thin hook provenance (artifact_type
	// hook, no fabricated file/line) — the honesty marker for a live signal.
	if !strings.Contains(string(data), `"artifact_type":"hook"`) {
		t.Fatalf("finding must carry hook evidence provenance, got: %s", data)
	}
	var decision model.EnforcementDecision
	if err := json.Unmarshal(lines[1], &decision); err != nil {
		t.Fatalf("enforcement line is not JSON: %v\n%s", err, data)
	}
	if decision.Decision != model.EnforcementDecisionNoOverride || decision.Mode != model.EnforcementModeMonitor || decision.Reason != model.EnforcementReasonMonitorMode {
		t.Fatalf("monitor enforcement decision = %+v", decision)
	}
	if !slices.Equal(decision.FindingIDs, []string{f.FindingID}) || !slices.Equal(decision.ActionEventIDs, f.CitedEventIDs) {
		t.Fatalf("enforcement joins = findings %v events %v; finding=%+v", decision.FindingIDs, decision.ActionEventIDs, f)
	}
}

func TestHookOutputFileExpandsRuntimeHome(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	payload := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`

	out, _, code := runCLIStdin(payload, "hook", "pre-tool", "--agent", "claude", "--output", "file", "--output-file", "$HOME/live.ndjson")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Fatalf("stdout = %q, want {} only", out)
	}
	data, err := os.ReadFile(filepath.Join(home, "live.ndjson"))
	if err != nil {
		t.Fatalf("read expanded sink file: %v", err)
	}
	if !strings.Contains(string(data), "secrets.agent_read_env") {
		t.Fatalf("expected finding in expanded sink file, got: %s", data)
	}
}

func TestHookEmitEventsWritesRecordToStderr(t *testing.T) {
	payload := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	out, errb, code := runCLIStdin(payload, "hook", "pre-tool", "--agent", "claude", "--emit", "events")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Fatalf("stdout = %q, want passthrough only", out)
	}
	types := recordTypes(t, errb)
	if countType(types, "event") != 1 {
		t.Fatalf("stderr record types = %v, want one event", types)
	}
	if countType(types, "finding") != 0 {
		t.Fatalf("--emit events should not emit findings: %v", types)
	}
}

func TestHookRecordWriteErrorStillAllows(t *testing.T) {
	payload := `{"session_id":"s1","cwd":"/proj","tool_name":"Bash","tool_input":{"command":"cat .env"}}`
	var out bytes.Buffer
	errb := failOnRecordTypeWriter{recordType: "event"}

	code := runHookEvent("pre-tool",
		[]string{"--agent", "claude", "--emit", "events", "--output", "stdout"},
		strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when record delivery fails", code)
	}
	if strings.TrimSpace(out.String()) != "{}" {
		t.Fatalf("stdout = %q, want passthrough only", out.String())
	}
	if !strings.Contains(errb.String(), "output delivery failed") {
		t.Fatalf("stderr = %q, want output delivery failure", errb.String())
	}
}

// Even when the payload is empty/garbage and processing has nothing to do, the
// handler still prints the passthrough and exits 0 — the never-block guarantee.
func TestHookTolerantOfGarbagePayload(t *testing.T) {
	out, _, code := runCLIStdin("not json at all", "hook", "post-tool", "--agent", "claude")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even on a bad payload", code)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Fatalf("stdout = %q, want {}", out)
	}
}

// A malformed callback command reports the wiring error but does not return an
// upstream blocking exit code.
func TestHookMissingAgentFailsOpen(t *testing.T) {
	_, errb, code := runCLIStdin("{}", "hook", "pre-tool")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "--agent is required") {
		t.Errorf("stderr = %q, want --agent required", errb)
	}
}

func TestHookAgentHelpParity(t *testing.T) {
	want := internalhook.SortAgentNames(internalhook.AgentNames())

	accepted := make([]string, 0, len(want))
	for _, agent := range want {
		if _, err := internalhook.ParseAgent(agent); err != nil {
			t.Fatalf("ParseAgent(%q): %v", agent, err)
		}
		accepted = append(accepted, agent)
	}
	sort.Strings(accepted)
	if !reflect.DeepEqual(accepted, want) {
		t.Fatalf("ParseAgent accepted %v, want %v", accepted, want)
	}

	var usage bytes.Buffer
	hookUsage(&usage)
	if !strings.Contains(usage.String(), "agents: "+internalhook.AgentUsage()) {
		t.Fatalf("hookUsage missing exact agent list %q:\n%s", internalhook.AgentUsage(), usage.String())
	}
	if !strings.HasSuffix(usage.String(), "\n") {
		t.Fatalf("hookUsage must end with a newline: %q", usage.String())
	}

	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	var sink bytes.Buffer
	fs.SetOutput(&sink)
	fs.String("agent", "", "source agent: "+internalhook.AgentUsage()+" (required)")
	fs.PrintDefaults()
	if !strings.Contains(sink.String(), "source agent: "+internalhook.AgentUsage()+" (required)") {
		t.Fatalf("flag help missing exact agent list %q:\n%s", internalhook.AgentUsage(), sink.String())
	}

	_, errb, code := runCLIStdin("{}", "hook", "pre-tool")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "--agent is required ("+internalhook.AgentUsage()+")") {
		t.Fatalf("required-agent error missing exact agent list %q:\n%s", internalhook.AgentUsage(), errb)
	}
}

func TestHookUnknownEventFailsOpen(t *testing.T) {
	_, errb, code := runCLIStdin("{}", "hook", "frobnicate", "--agent", "claude")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "unknown claude hook event") {
		t.Errorf("stderr = %q, want unknown claude hook event", errb)
	}
}

// `numbat hook install --agent claude --settings PATH` wires the hooks into the
// given settings file and `status` reports them; `uninstall` removes them.
func TestHookInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	out, _, code := runCLI("hook", "install", "--agent", "claude", "--settings", path)
	if code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	if !strings.Contains(out, "claude") || !strings.Contains(out, "ok") {
		t.Errorf("install report = %q", out)
	}

	out, _, code = runCLI("hook", "status", "--agent", "claude", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status after install = %q (exit %d)", out, code)
	}

	_, _, code = runCLI("hook", "uninstall", "--agent", "claude", "--settings", path)
	if code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}

	// The numbat hook commands must be gone from the file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if strings.Contains(string(data), "numbat hook ") {
		t.Errorf("numbat hooks remain after uninstall: %s", data)
	}
}

func TestHookStatusAndUninstallWithExplicitSettingsDoNotNeedHome(t *testing.T) {
	setTestHome(t, "")
	path := filepath.Join(t.TempDir(), "settings.json")

	out, errb, code := runCLI("hook", "status", "--agent", "claude", "--settings", path)
	if code != 0 || !strings.Contains(out, "not-installed") {
		t.Fatalf("status exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	out, errb, code = runCLI("hook", "uninstall", "--agent", "claude", "--settings", path)
	if code != 0 || !strings.Contains(out, "unchanged") {
		t.Fatalf("uninstall exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestHookManagedRequiresSingleSupportedAgent(t *testing.T) {
	_, errb, code := runCLI("hook", "install", "--managed")
	if code != 2 || !strings.Contains(errb, "--managed requires --agent") {
		t.Fatalf("install --managed without agent: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--managed", "--agent", "vscode")
	if code != 2 || !strings.Contains(errb, "has no numbat-managed target") {
		t.Fatalf("install --managed vscode: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--managed", "--agent", "all")
	if code != 2 || !strings.Contains(errb, "--managed requires one agent") {
		t.Fatalf("install --managed --agent all: exit=%d stderr=%q", code, errb)
	}
}

func TestHookInstallAndUninstallRequireExplicitAgent(t *testing.T) {
	for _, action := range []string{"install", "uninstall"} {
		_, errb, code := runCLI("hook", action)
		if code != 2 || !strings.Contains(errb, "--agent is required") {
			t.Errorf("hook %s: exit=%d stderr=%q", action, code, errb)
		}
	}

	agents, err := targetAgents("all")
	if err != nil || len(agents) != len(internalhook.InstallAgentNames()) {
		t.Fatalf("targetAgents(all) = %v, %v", agents, err)
	}
	if slices.Contains(agents, internalhook.AgentVSCode) {
		t.Fatalf("targetAgents(all) must not duplicate the shared Copilot/VS Code hook surface: %v", agents)
	}
	if slices.Contains(agents, internalhook.AgentOpenHands) {
		t.Fatalf("targetAgents(all) must not invent a global OpenHands project target: %v", agents)
	}
}

func TestOpenHandsRequiresExplicitRepositorySettings(t *testing.T) {
	for _, action := range []string{"install", "status", "uninstall"} {
		_, errb, code := runCLI("hook", action, "--agent", "openhands")
		if code != 2 || !strings.Contains(errb, "repository-scoped") || !strings.Contains(errb, "--settings") {
			t.Errorf("hook %s openhands: exit=%d stderr=%q", action, code, errb)
		}
	}

	setTestHome(t, t.TempDir())
	rulesDir := writeEnforceRuleFile(t, criticalEnforceRule)
	path := filepath.Join(t.TempDir(), "repo", ".openhands", "hooks.json")
	out, errb, code := runCLI("hook", "install", "--agent", "openhands", "--settings", path,
		"--rules-dir", rulesDir, "--enforce")
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("OpenHands explicit install: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	out, errb, code = runCLI("hook", "status", "--agent", "openhands", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("OpenHands explicit status: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestOpenClawDefaultInstallRefusesLegacyOnlyState(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	legacy := filepath.Join(home, ".clawdbot")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}

	out, errb, code := runCLI("hook", "install", "--agent", "openclaw")
	if code != 2 || out != "" || !strings.Contains(errb, "legacy state exists") ||
		!strings.Contains(errb, "OPENCLAW_STATE_DIR") || !strings.Contains(errb, "plugins.load.paths") {
		t.Fatalf("legacy-only install: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if _, err := os.Stat(filepath.Join(home, ".openclaw")); !os.IsNotExist(err) {
		t.Fatalf("rejected install created .openclaw: %v", err)
	}

	explicitPlugin := filepath.Join(legacy, "extensions", "numbat")
	out, errb, code = runCLI("hook", "install", "--agent", "openclaw", "--settings", explicitPlugin)
	if code != 0 || !strings.Contains(out, "installed") || errb != "" {
		t.Fatalf("explicit legacy-named package install: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	out, errb, code = runCLI("hook", "uninstall", "--agent", "openclaw", "--settings", explicitPlugin)
	if code != 0 || !strings.Contains(out, "removed") || errb != "" {
		t.Fatalf("explicit legacy-named package uninstall: exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	// Read-only and removal actions remain safe and must not create either root.
	out, errb, code = runCLI("hook", "status", "--agent", "openclaw")
	if code != 0 || !strings.Contains(out, "not-installed") || errb != "" {
		t.Fatalf("legacy-only status: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	out, errb, code = runCLI("hook", "uninstall", "--agent", "openclaw")
	if code != 0 || !strings.Contains(out, "unchanged") || errb != "" {
		t.Fatalf("legacy-only uninstall: exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	// Explicitly selecting the legacy directory makes it the active config root
	// and is therefore safe for the native plugin loader.
	t.Setenv("OPENCLAW_STATE_DIR", legacy)
	out, errb, code = runCLI("hook", "install", "--agent", "openclaw")
	if code != 0 || !strings.Contains(out, "installed") || errb != "" {
		t.Fatalf("explicit legacy state install: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if _, err := os.Stat(filepath.Join(legacy, "extensions", "numbat", "index.js")); err != nil {
		t.Fatalf("explicit legacy state plugin missing: %v", err)
	}

	// OPENCLAW_PROFILE alone is metadata, not a path selector. OpenClaw projects
	// --profile into OPENCLAW_STATE_DIR only inside its own process, so a
	// standalone Numbat invocation must continue to refuse this ambiguous root.
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_PROFILE", "work")
	out, errb, code = runCLI("hook", "install", "--agent", "openclaw")
	if code != 2 || out != "" || !strings.Contains(errb, "legacy state exists") {
		t.Fatalf("profile-only install: exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if _, err := os.Stat(filepath.Join(home, ".openclaw-work")); !os.IsNotExist(err) {
		t.Fatalf("profile-only install created inferred root: %v", err)
	}
}

func TestHookManagedJSONAgentRoundTrip(t *testing.T) {
	for _, agent := range []string{"cursor", "copilot", "gemini", "windsurf"} {
		t.Run(agent, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed.json")
			out, errb, code := runCLI("hook", "install", "--managed", "--agent", agent, "--settings", path)
			if code != 0 || !strings.Contains(out, "managed hooks") {
				t.Fatalf("install exit=%d stdout=%q stderr=%q", code, out, errb)
			}
			out, errb, code = runCLI("hook", "status", "--managed", "--agent", agent, "--settings", path)
			if code != 0 || !strings.Contains(out, "installed") {
				t.Fatalf("status exit=%d stdout=%q stderr=%q", code, out, errb)
			}
			out, errb, code = runCLI("hook", "uninstall", "--managed", "--agent", agent, "--settings", path)
			if code != 0 || !strings.Contains(out, "removed") {
				t.Fatalf("uninstall exit=%d stdout=%q stderr=%q", code, out, errb)
			}
		})
	}
}

func TestHookManagedDefaultOutputUsesRuntimeHome(t *testing.T) {
	setTestHome(t, "")
	path := filepath.Join(t.TempDir(), "managed-settings.d", "numbat.json")

	out, errb, code := runCLI("hook", "install", "--managed", "--agent", "claude", "--settings", path)
	if code != 0 {
		t.Fatalf("managed install exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, "$HOME/.numbat/findings.ndjson") {
			t.Fatalf("managed command should keep runtime HOME output path, got %q", cmd)
		}
	}
}

func TestExpandHookPathHandlesUnsetHome(t *testing.T) {
	setTestHome(t, "")
	if runtime.GOOS == "windows" {
		home := t.TempDir()
		t.Setenv("USERPROFILE", home)
		got, err := expandHookPath("$HOME/.numbat/records.ndjson")
		if err != nil || got != filepath.Join(home, ".numbat/records.ndjson") {
			t.Fatalf("expandHookPath = %q, %v; want USERPROFILE fallback", got, err)
		}
		return
	}
	got, err := expandHookPath("$HOME/.numbat/records.ndjson")
	if err == nil || got != "" || !strings.Contains(err.Error(), "HOME") {
		t.Fatalf("expandHookPath = %q, %v; want unset HOME error", got, err)
	}
}

func TestHookInstallAllDefaultsToRecordsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	out, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path, "--emit", "all")
	if code != 0 {
		t.Fatalf("install exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, filepath.Join(".numbat", "records.ndjson")) {
			t.Fatalf("--emit all default command = %q, want records.ndjson", cmd)
		}
		if strings.Contains(cmd, ".numbat/findings.ndjson") {
			t.Fatalf("--emit all command still targets findings.ndjson: %q", cmd)
		}
	}
}

func TestHookManagedClaudeRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.d", "numbat.json")
	outFile := filepath.Join(t.TempDir(), "live.ndjson")

	out, errb, code := runCLI("hook", "install", "--managed", "--agent", "claude", "--settings", path,
		"--emit", "all", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("managed install exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "managed hooks") || !strings.Contains(out, path) {
		t.Fatalf("managed install output = %q, want managed hook report with path", out)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, "--emit") || !strings.Contains(cmd, "all") {
			t.Fatalf("managed Claude command missing emit all: %q", cmd)
		}
		if !strings.Contains(cmd, outFile) {
			t.Fatalf("managed Claude command missing explicit output file: %q", cmd)
		}
	}

	out, errb, code = runCLI("hook", "status", "--managed", "--agent", "claude", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("managed status exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	out, errb, code = runCLI("hook", "uninstall", "--managed", "--agent", "claude", "--settings", path)
	if code != 0 || !strings.Contains(out, "removed numbat managed hooks") {
		t.Fatalf("managed uninstall exit=%d stdout=%q stderr=%q", code, out, errb)
	}
}

func TestHookManagedCodexRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	outFile := filepath.Join(t.TempDir(), "live.ndjson")

	out, errb, code := runCLI("hook", "install", "--managed", "--agent", "codex", "--settings", path,
		"--emit", "all", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("managed codex install exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if !strings.Contains(out, "requirements.toml") || !strings.Contains(out, path) {
		t.Fatalf("managed codex install output = %q", out)
	}
	body := testHookCommandText(readFileString(t, path))
	for _, want := range []string{"[features]", "hooks = true # numbat-managed", "[[hooks.PreToolUse]]", "--agent codex", outFile} {
		if !strings.Contains(body, want) {
			t.Fatalf("managed codex requirements missing %q:\n%s", want, body)
		}
	}

	out, errb, code = runCLI("hook", "status", "--managed", "--agent", "codex", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("managed codex status exit=%d stdout=%q stderr=%q", code, out, errb)
	}

	out, errb, code = runCLI("hook", "uninstall", "--managed", "--agent", "codex", "--settings", path)
	if code != 0 || !strings.Contains(out, "removed numbat managed hooks") {
		t.Fatalf("managed codex uninstall exit=%d stdout=%q stderr=%q", code, out, errb)
	}
	if strings.Contains(testHookCommandText(readFileString(t, path)), "--installed-by=numbat") {
		t.Fatalf("managed codex uninstall left numbat hooks:\n%s", readFileString(t, path))
	}
}

func TestHookInstallWiresEmitAndOutputFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	outFile := filepath.Join(t.TempDir(), "hook records.ndjson")

	out, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--emit", "all", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("install exit = %d, stdout=%q stderr=%q", code, out, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, "--emit") || !strings.Contains(cmd, "all") {
			t.Fatalf("installed command missing emit mode: %q", cmd)
		}
		if !strings.Contains(cmd, "--output=file") || !strings.Contains(cmd, outFile) {
			t.Fatalf("installed command missing file output: %q", cmd)
		}
	}
}

func TestHookInstallWiresCustomRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	rulesDir := filepath.Join(t.TempDir(), "custom rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}

	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--rules-dir", rulesDir, "--no-builtin-rules")
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, "--rules-dir") || !strings.Contains(cmd, rulesDir) ||
			!strings.Contains(cmd, "--no-builtin-rules") {
			t.Fatalf("installed command missing custom-rule flags: %q", cmd)
		}
	}
}

func TestHookInstallResolvesRelativeRulesDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	relative := filepath.Join("testdata", "rules_custom")
	want, err := filepath.Abs(relative)
	if err != nil {
		t.Fatal(err)
	}

	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--rules-dir", relative)
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if !strings.Contains(cmd, want) {
			t.Fatalf("installed command = %q, want absolute rules dir %q", cmd, want)
		}
	}
}

func TestInstallRuntimeArgsKeepsRuntimeRuleDirs(t *testing.T) {
	for _, dir := range []string{"$HOME/numbat-rules", "~/numbat-rules", `~\numbat-rules`} {
		args, err := installRuntimeArgs(installRuntimeConfig{ruleDirs: []string{dir}}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(args, dir) {
			t.Errorf("runtime args %q do not preserve %q", args, dir)
		}
	}
}

func TestHookInstallResolvesRelativeOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	relative := filepath.Join("logs", "numbat.ndjson")
	want, err := filepath.Abs(relative)
	if err != nil {
		t.Fatal(err)
	}
	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output-file", relative)
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, command := range claudeInstalledCommands(t, path) {
		if !strings.Contains(command, want) {
			t.Fatalf("installed command = %q, want absolute output path %q", command, want)
		}
	}
}

func TestInstallRuntimeArgsKeepsRuntimeOutputPaths(t *testing.T) {
	for _, path := range []string{"$HOME/.numbat/live.ndjson", "~/.numbat/live.ndjson", `~\.numbat\live.ndjson`} {
		args, err := installRuntimeArgs(installRuntimeConfig{file: path}, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(args, path) {
			t.Errorf("runtime args %q do not preserve %q", args, path)
		}
	}
}

func TestExpandHookPathAcceptsWindowsTildeSeparator(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	got, err := expandHookPath(`~\.numbat\live.ndjson`)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, `.numbat\live.ndjson`); got != want {
		t.Fatalf("expanded path = %q, want %q", got, want)
	}
}

func TestInstallRuntimeArgsPreservesRulesDirSpaces(t *testing.T) {
	rulesDir := filepath.Join(t.TempDir(), " rules ")
	args, err := installRuntimeArgs(installRuntimeConfig{
		ruleDirs: []string{rulesDir},
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--rules-dir" && args[i+1] == rulesDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("runtime args = %q, want exact rules dir %q", args, rulesDir)
	}
}

func TestHookInstallWiresHTTPOutputFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--emit", "events",
		"--output", "http",
		"--http-url", "https://ingest.example/numbat",
		"--http-auth", "bearer",
		"--http-batch-size", "10",
		"--http-gzip")
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		for _, want := range []string{
			"--emit", "events",
			"--output=http",
			"https://ingest.example/numbat",
			"--http-auth", "bearer",
			"--http-batch-size", "10",
			"--http-timeout", "5s",
			"--http-gzip=true",
		} {
			if !strings.Contains(cmd, want) {
				t.Fatalf("installed command missing %q: %q", want, cmd)
			}
		}
	}
}

func TestHookInstallWiresFileAndHTTPOutputFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	outFile := filepath.Join(t.TempDir(), "findings.ndjson")

	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "file",
		"--output", "http",
		"--output-file", outFile,
		"--http-url", "https://ingest.example/numbat",
		"--http-auth", "hmac-sha256")
	if code != 0 {
		t.Fatalf("install exit = %d, stderr=%q", code, errb)
	}
	for _, cmd := range claudeInstalledCommands(t, path) {
		if strings.Contains(cmd, "file,http") {
			t.Fatalf("installed command used comma output syntax: %q", cmd)
		}
		for _, want := range []string{
			"--output=file",
			"--output=http",
			"--output-file",
			outFile,
			"--http-url",
			"https://ingest.example/numbat",
			"--http-auth",
			"hmac-sha256",
		} {
			if !strings.Contains(cmd, want) {
				t.Fatalf("installed command missing %q: %q", want, cmd)
			}
		}
	}
}

func TestHookInstallOutputValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	_, errb, code := runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "http")
	if code != 2 || !strings.Contains(errb, "--output including http requires --http-url") {
		t.Fatalf("missing http-url validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "stdout", "--output-file", filepath.Join(t.TempDir(), "x.ndjson"))
	if code != 2 || !strings.Contains(errb, "--output-file is only valid") {
		t.Fatalf("missing output-file validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output-file", "")
	if code != 2 || !strings.Contains(errb, "--output-file must not be empty") {
		t.Fatalf("missing empty output-file validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "http", "--http-url", "https://user:pass@ingest.example/numbat")
	if code != 2 || !strings.Contains(errb, "must not contain embedded credentials") {
		t.Fatalf("missing credentialed-url validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "http", "--http-url", "http://ingest.example/numbat")
	if code != 2 || !strings.Contains(errb, "refusing plain http") {
		t.Fatalf("missing insecure-http validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "http", "--http-url", "https://ingest.example/numbat",
		"--http-sig-header", "X-Signature")
	if code != 2 || !strings.Contains(errb, "--http-sig-header requires --http-auth hmac-sha256") {
		t.Fatalf("missing HMAC header validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--output", "file,http")
	if code != 2 || !strings.Contains(errb, "pass one sink per flag") {
		t.Fatalf("missing comma-output validation: exit=%d stderr=%q", code, errb)
	}

	_, errb, code = runCLI("hook", "install", "--agent", "claude", "--settings", path,
		"--no-builtin-rules")
	if code != 2 || !strings.Contains(errb, "--no-builtin-rules requires at least one --rules-dir") {
		t.Fatalf("missing custom-rule validation: exit=%d stderr=%q", code, errb)
	}
}

func claudeInstalledCommands(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var parsed struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	var commands []string
	for _, groups := range parsed.Hooks {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				command := strings.Join(append([]string{ref.Command}, ref.Args...), " ")
				if strings.Contains(command, "--installed-by=numbat") {
					commands = append(commands, command)
				}
			}
		}
	}
	if len(commands) == 0 {
		t.Fatalf("no numbat commands in %s: %s", path, data)
	}
	return commands
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestHookStatusReportsMalformedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errb, code := runCLI("hook", "status", "--agent", "claude", "--settings", path)
	if code != 1 {
		t.Fatalf("status exit = %d, want 1", code)
	}
	if !strings.Contains(errb, "parse") {
		t.Fatalf("status stderr = %q, want parse error", errb)
	}
}

func TestHookStatusUsesAgentSpecificConfigParsers(t *testing.T) {
	t.Run("hermes yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("theme: dark\nhooks: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, errb, code := runCLI("hook", "status", "--agent", "hermes", "--settings", path)
		if code != 0 {
			t.Fatalf("status exit = %d, stderr=%q", code, errb)
		}
		if !strings.Contains(out, "not-installed") {
			t.Fatalf("status output = %q, want not-installed", out)
		}
	})

	t.Run("devin jsonc", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		body := []byte("// Devin permits comments\n{\"hooks\": {},}\n")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		out, errb, code := runCLI("hook", "status", "--agent", "devin", "--settings", path)
		if code != 0 {
			t.Fatalf("status exit = %d, stderr=%q", code, errb)
		}
		if !strings.Contains(out, "not-installed") {
			t.Fatalf("status output = %q, want not-installed", out)
		}
	})
}

// Cursor hooks always print the inert response and exit 0, including on
// malformed or empty stdin. Monitor mode must not alter Cursor's approval flow.
func TestCursorGatingHooksAlwaysAllow(t *testing.T) {
	gating := []string{"preToolUse", "subagentStart"}
	stdins := map[string]string{
		"realistic": `{"conversation_id":"c1","tool_name":"Shell","tool_input":{"command":"cat .env"},"cwd":"/proj"}`,
		"empty":     "",
		"malformed": "not json at all",
	}
	for _, event := range gating {
		for name, in := range stdins {
			out, _, code := runCLIStdin(in, "hook", event, "--agent", "cursor")
			if code != 0 {
				t.Errorf("%s/%s: exit = %d, want 0", event, name, code)
			}
			var resp map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
				t.Errorf("%s/%s: stdout %q is not valid JSON: %v", event, name, out, err)
				continue
			}
			if len(resp) != 0 {
				t.Errorf("%s/%s: stdout = %q, want inert {}", event, name, out)
			}
		}
	}
}

// A Cursor informational hook likewise emits the inert response.
func TestCursorInformationalHookExitsZero(t *testing.T) {
	for _, event := range []string{"postToolUse", "postToolUseFailure"} {
		payload := `{"tool_name":"Write","tool_input":{"file_path":"/p/x.go"},"tool_use_id":"tool-1"}`
		out, _, code := runCLIStdin(payload, "hook", event, "--agent", "cursor")
		if code != 0 {
			t.Errorf("%s: exit = %d, want 0", event, code)
		}
		if strings.TrimSpace(out) != "{}" {
			t.Errorf("%s: stdout = %q, want inert {}", event, out)
		}
	}
}

func TestCursorUnknownEventFailsOpen(t *testing.T) {
	_, errb, code := runCLIStdin("{}", "hook", "workspaceOpen", "--agent", "cursor")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "unknown cursor hook event") {
		t.Errorf("stderr = %q, want unknown cursor hook event", errb)
	}
}

// In monitor mode every installed Windsurf callback allows, including on empty
// or malformed input. Exit 2 is reserved for a clean opt-in enforcement match.
func TestWindsurfHooksAlwaysExitZero(t *testing.T) {
	// Per-event realistic fixtures: each carries the matching agent_action_name and
	// a nested tool_info shaped for that event, so the exit-0 guarantee is proven
	// against the actual per-event payloads the installed hooks receive — not one
	// reused body. Every installed event is covered.
	realistic := map[string]string{
		"pre_user_prompt":       `{"agent_action_name":"pre_user_prompt","trajectory_id":"t1","execution_id":"e1","tool_info":{"user_prompt":"read the env file"}}`,
		"pre_read_code":         `{"agent_action_name":"pre_read_code","trajectory_id":"t1","execution_id":"e1","tool_info":{"file_path":"/proj/main.go"}}`,
		"post_read_code":        `{"agent_action_name":"post_read_code","trajectory_id":"t1","execution_id":"e1","tool_info":{"file_path":"/proj/main.go"}}`,
		"pre_write_code":        `{"agent_action_name":"pre_write_code","trajectory_id":"t1","execution_id":"e1","tool_info":{"file_path":"/proj/y.go"}}`,
		"post_write_code":       `{"agent_action_name":"post_write_code","trajectory_id":"t1","execution_id":"e1","tool_info":{"file_path":"/proj/y.go"}}`,
		"pre_run_command":       `{"agent_action_name":"pre_run_command","trajectory_id":"t1","execution_id":"e1","tool_info":{"command_line":"cat .env","cwd":"/proj"}}`,
		"post_run_command":      `{"agent_action_name":"post_run_command","trajectory_id":"t1","execution_id":"e1","tool_info":{"command_line":"cat .env"}}`,
		"pre_mcp_tool_use":      `{"agent_action_name":"pre_mcp_tool_use","trajectory_id":"t1","execution_id":"e1","tool_info":{"mcp_server_name":"github","mcp_tool_name":"create_issue","mcp_tool_arguments":{"title":"x"}}}`,
		"post_mcp_tool_use":     `{"agent_action_name":"post_mcp_tool_use","trajectory_id":"t1","execution_id":"e1","tool_info":{"mcp_server_name":"github","mcp_tool_name":"create_issue"}}`,
		"post_cascade_response": `{"agent_action_name":"post_cascade_response","trajectory_id":"t1","execution_id":"e1","tool_info":{}}`,
	}
	if len(realistic) != len(windsurfAllEvents) {
		t.Fatalf("fixture set has %d events, want one per installed event (%d)", len(realistic), len(windsurfAllEvents))
	}
	for _, event := range windsurfAllEvents {
		body, ok := realistic[event]
		if !ok {
			t.Fatalf("%s: missing realistic fixture", event)
		}
		stdins := map[string]string{
			"realistic": body,
			"empty":     "",
			"malformed": "not json at all",
		}
		for name, in := range stdins {
			out, _, code := runCLIStdin(in, "hook", event, "--agent", "windsurf")
			if code != 0 {
				t.Errorf("%s/%s: exit = %d, want monitor-mode 0", event, name, code)
			}
			// The inert {} is emitted; it must parse as a JSON object and carry no
			// blocking directive.
			if got := strings.TrimSpace(out); got != "{}" {
				t.Errorf("%s/%s: stdout = %q, want inert {}", event, name, got)
			}
		}
	}
}

// windsurfAllEvents is the Windsurf event set numbat installs, used by
// the cmd-level no-block matrix so every installed hook is exercised with its own
// realistic payload.
var windsurfAllEvents = []string{
	"pre_user_prompt",
	"pre_read_code",
	"post_read_code",
	"pre_write_code",
	"post_write_code",
	"pre_run_command",
	"post_run_command",
	"pre_mcp_tool_use",
	"post_mcp_tool_use",
	"post_cascade_response",
}

// A panic anywhere on the Windsurf hook path must still exit 0 and land the inert
// passthrough — the same no-block guarantee proven for Claude, exercised through
// the Windsurf agent path.
func TestWindsurfHookRecoversFromPanic(t *testing.T) {
	var out bytes.Buffer
	code := runHookEvent("post_write_code", []string{"--agent", "windsurf"}, strings.NewReader("not json"), &out, panicWriter{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the processing path panics", code)
	}
	if got := strings.TrimSpace(out.String()); got != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough {} after a recovered panic", got)
	}
	if n := strings.Count(out.String(), "{}"); n != 1 {
		t.Fatalf("passthrough written %d times, want exactly 1", n)
	}
}

func TestWindsurfUnknownEventFailsOpen(t *testing.T) {
	_, errb, code := runCLIStdin("{}", "hook", "workspace_open", "--agent", "windsurf")
	if code != 0 {
		t.Fatalf("exit = %d, want fail-open 0", code)
	}
	if !strings.Contains(errb, "unknown windsurf hook event") {
		t.Errorf("stderr = %q, want unknown windsurf hook event", errb)
	}
}

// `numbat hook install --agent windsurf` wires the hooks into the given
// hooks.json and `status` reports them; `uninstall` removes them, leaving a valid
// Windsurf hooks.json (a hooks map).
func TestWindsurfHookInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")

	out, _, code := runCLI("hook", "install", "--agent", "windsurf", "--settings", path)
	if code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	if !strings.Contains(out, "windsurf") || !strings.Contains(out, "ok") {
		t.Errorf("install report = %q", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json invalid: %v", err)
	}
	if len(parsed.Hooks) == 0 {
		t.Errorf("installed hooks.json malformed: %s", data)
	}

	out, _, code = runCLI("hook", "status", "--agent", "windsurf", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status after install = %q (exit %d)", out, code)
	}

	if _, _, code = runCLI("hook", "uninstall", "--agent", "windsurf", "--settings", path); code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if strings.Contains(testHookCommandText(string(data)), "--agent windsurf") {
		t.Errorf("numbat windsurf hooks remain after uninstall: %s", data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall windsurf file dropped the hooks map: %s", data)
	}
}

// `numbat hook install --agent cursor` wires the hooks into the given hooks.json
// and `status` reports them; `uninstall` removes them. The installed file is a
// valid Cursor hooks.json (version + hooks map).
func TestCursorHookInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")

	out, _, code := runCLI("hook", "install", "--agent", "cursor", "--settings", path)
	if code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	if !strings.Contains(out, "cursor") || !strings.Contains(out, "ok") {
		t.Errorf("install report = %q", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version int                        `json:"version"`
		Hooks   map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json invalid: %v", err)
	}
	if parsed.Version != 1 || len(parsed.Hooks) == 0 {
		t.Errorf("installed hooks.json malformed: %s", data)
	}

	out, _, code = runCLI("hook", "status", "--agent", "cursor", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status after install = %q (exit %d)", out, code)
	}

	if _, _, code = runCLI("hook", "uninstall", "--agent", "cursor", "--settings", path); code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if strings.Contains(testHookCommandText(string(data)), "--agent cursor") {
		t.Errorf("numbat cursor hooks remain after uninstall: %s", data)
	}
}

// Every Copilot hook prints the inert empty object and exits 0, including on
// realistic, empty, and malformed stdin. An explicit allow decision would alter
// Copilot's normal permission flow, so monitor mode emits no directive.
// The realistic bodies carry toolArgs as a JSON-ENCODED STRING, the worst case.
func TestCopilotHooksAlwaysAllow(t *testing.T) {
	realistic := map[string]string{
		"UserPromptSubmitted": `{"hookEventName":"UserPromptSubmitted","prompt":"read the env file","cwd":"/proj"}`,
		"PreToolUse":          `{"hookEventName":"PreToolUse","toolName":"ShellCommand","toolArgs":"{\"command\":\"cat .env\"}","cwd":"/proj"}`,
		"PostToolUse":         `{"hookEventName":"PostToolUse","toolName":"Bash","toolArgs":"{\"command\":\"false\"}","exit_code":1,"cwd":"/proj"}`,
	}
	for _, event := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmitted"} {
		body := realistic[event]
		stdins := map[string]string{
			"realistic": body,
			"empty":     "",
			"malformed": "not json at all",
		}
		for name, in := range stdins {
			out, _, code := runCLIStdin(in, "hook", event, "--agent", "copilot")
			if code != 0 {
				t.Errorf("%s/%s: exit = %d, want 0 (never block)", event, name, code)
			}
			var resp map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
				t.Errorf("%s/%s: stdout %q is not valid JSON: %v", event, name, out, err)
				continue
			}
			if len(resp) != 0 {
				t.Errorf("%s/%s: stdout = %q, want inert {}", event, name, out)
			}
		}
	}
}

// A panic anywhere on the Copilot hook path must still exit 0 and land the inert
// response.
func TestCopilotHookRecoversFromPanic(t *testing.T) {
	var out bytes.Buffer
	code := runHookEvent("PostToolUse", []string{"--agent", "copilot"}, strings.NewReader("not json"), &out, panicWriter{})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 even when the processing path panics", code)
	}
	if strings.TrimSpace(out.String()) != "{}" {
		t.Fatalf("stdout = %q, want the inert passthrough after a recovered panic", out.String())
	}
}

func TestCopilotUnknownEventFailsOpen(t *testing.T) {
	// Near-misses still report a wiring error, but callback failures do not use a
	// blocking process status.
	for _, event := range []string{
		"UnknownEvent",
		"PreToolUseBroken",
		"PostToolUseV2",
		"UserPromptSubmittedV2",
		"XPreToolUse",
	} {
		_, errb, code := runCLIStdin("{}", "hook", event, "--agent", "copilot")
		if code != 0 {
			t.Fatalf("%q: exit = %d, want fail-open 0", event, code)
		}
		if !strings.Contains(errb, "unknown copilot hook event") {
			t.Errorf("%q: stderr = %q, want unknown copilot hook event", event, errb)
		}
	}
}

// `numbat hook install --agent copilot` wires the hooks into the given hooks.json
// and `status` reports them; `uninstall` removes them, leaving a valid Copilot
// hooks.json (version + hooks map, the same flat shape as Cursor).
func TestCopilotHookInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")

	out, _, code := runCLI("hook", "install", "--agent", "copilot", "--settings", path)
	if code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	if !strings.Contains(out, "copilot") || !strings.Contains(out, "ok") {
		t.Errorf("install report = %q", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version int                        `json:"version"`
		Hooks   map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks.json invalid: %v", err)
	}
	if parsed.Version != 1 || len(parsed.Hooks) == 0 {
		t.Errorf("installed hooks.json malformed: %s", data)
	}

	out, _, code = runCLI("hook", "status", "--agent", "copilot", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status after install = %q (exit %d)", out, code)
	}

	if _, _, code = runCLI("hook", "uninstall", "--agent", "copilot", "--settings", path); code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if strings.Contains(testHookCommandText(string(data)), "--agent copilot") {
		t.Errorf("numbat copilot hooks remain after uninstall: %s", data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall copilot file dropped the hooks map: %s", data)
	}
}

// Every VS Code Copilot Chat / Agent Mode hook prints the inert passthrough and
// exits 0.
func TestVSCodeHooksAlwaysAllow(t *testing.T) {
	realistic := map[string]string{
		"SessionStart":     `{"sessionId":"v1","workspaceRoots":["/proj"]}`,
		"UserPromptSubmit": `{"sessionId":"v1","prompt":"read the env file","cwd":"/proj"}`,
		"PreToolUse":       `{"sessionId":"v1","toolName":"runCommand","toolInput":{"command":"cat .env"},"cwd":"/proj"}`,
		"PostToolUse":      `{"sessionId":"v1","toolName":"runCommand","toolInput":{"command":"false"},"toolResponse":{"exitCode":1},"cwd":"/proj"}`,
		"SubagentStart":    `{"sessionId":"v1","subagent":"reviewer","cwd":"/proj"}`,
		"SubagentStop":     `{"sessionId":"v1","subagent":"reviewer","cwd":"/proj"}`,
		"Stop":             `{"sessionId":"v1","cwd":"/proj"}`,
	}
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SubagentStart", "SubagentStop", "Stop"} {
		body := realistic[event]
		stdins := map[string]string{
			"realistic": body,
			"empty":     "",
			"malformed": "not json at all",
		}
		for name, in := range stdins {
			out, _, code := runCLIStdin(in, "hook", event, "--agent", "vscode")
			if code != 0 {
				t.Errorf("%s/%s: exit = %d, want 0 (never block)", event, name, code)
			}
			if got := strings.TrimSpace(out); got != "{}" {
				t.Errorf("%s/%s: stdout = %q, want inert {}", event, name, got)
			}
		}
	}
}

// `--agent vscode` is an explicit alias for the shared Copilot CLI / VS Code
// user hook file.
func TestVSCodeHookInstallStatusUninstallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".copilot", "hooks", "numbat.json")

	out, _, code := runCLI("hook", "install", "--agent", "vscode", "--settings", path)
	if code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	if !strings.Contains(out, "vscode") || !strings.Contains(out, "ok") {
		t.Errorf("install report = %q", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed struct {
		Version int                          `json:"version"`
		Hooks   map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed hooks file invalid: %v", err)
	}
	if parsed.Version != 1 || len(parsed.Hooks) == 0 {
		t.Errorf("installed hooks file malformed: %s", data)
	}
	if !strings.Contains(testHookCommandText(string(data)), "--agent copilot") {
		t.Errorf("shared Copilot hook command missing: %s", data)
	}

	out, _, code = runCLI("hook", "status", "--agent", "vscode", "--settings", path)
	if code != 0 || !strings.Contains(out, "installed") {
		t.Fatalf("status after install = %q (exit %d)", out, code)
	}

	if _, _, code = runCLI("hook", "uninstall", "--agent", "vscode", "--settings", path); code != 0 {
		t.Fatalf("uninstall exit = %d", code)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after uninstall: %v", err)
	}
	if strings.Contains(testHookCommandText(string(data)), "--agent copilot") {
		t.Errorf("numbat vscode hooks remain after uninstall: %s", data)
	}
	if !strings.Contains(string(data), `"hooks"`) {
		t.Errorf("post-uninstall vscode file dropped the hooks map: %s", data)
	}
}

func TestHookInstallSettingsWithoutAgentErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.json")
	_, errb, code := runCLI("hook", "install", "--settings", path)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "--settings requires --agent") {
		t.Errorf("stderr = %q, want --settings requires --agent", errb)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("rejected install must not create the settings file")
	}
	_, errb, code = runCLI("hook", "install", "--agent", "all", "--settings", path)
	if code != 2 || !strings.Contains(errb, "--settings requires one agent") {
		t.Fatalf("install --agent all --settings: exit=%d stderr=%q", code, errb)
	}
	// With an explicit --agent the same override is accepted.
	if _, _, code := runCLI("hook", "install", "--agent", "cursor", "--settings", path); code != 0 {
		t.Fatalf("install --agent cursor --settings exit = %d, want 0", code)
	}
}

// Every agent numbat targets now has a hook integration. Gemini in particular is a
// supported hook backend and an install wires its settings.json rather than being
// reported unsupported.
func TestHookInstallGeminiIsSupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	out, _, code := runCLI("hook", "install", "--agent", "gemini", "--settings", path)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, "unsupported") {
		t.Errorf("gemini report = %q, want a supported install", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("gemini install must create a settings file: %v", err)
	}
}

func TestPrintHookReportAlignsAgentAndStatusColumns(t *testing.T) {
	var out bytes.Buffer
	printHookReport(&out, "status", internalhook.InstallReport{
		Agent:     internalhook.AgentAntigravity,
		Supported: true,
		Message:   "numbat hooks not installed",
	})
	if got, want := out.String(), "antigravity not-installed numbat hooks not installed\n"; got != want {
		t.Fatalf("report = %q, want %q", got, want)
	}

	out.Reset()
	printHookReport(&out, "install", internalhook.InstallReport{
		Agent:     internalhook.AgentClaude,
		Supported: true,
		Changed:   true,
		Message:   "installed",
	})
	if got, want := out.String(), "claude      ok            installed\n"; got != want {
		t.Fatalf("report = %q, want %q", got, want)
	}
}

// Sanity: the installed Claude command is a real numbat hook invocation with a
// lifecycle arg the live handler accepts.
func TestInstalledCommandsAreValidLifecycles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, _, code := runCLI("hook", "install", "--agent", "claude", "--settings", path); code != 0 {
		t.Fatalf("install exit = %d", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("installed settings is not valid JSON: %v", err)
	}
	if _, ok := parsed["hooks"]; !ok {
		t.Fatalf("installed settings missing hooks block: %s", data)
	}
}
