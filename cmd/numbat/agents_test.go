package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
)

// Every parser or hook backend must have exactly one inventory descriptor.
func TestAgentDescriptorsCoverEnum(t *testing.T) {
	supported := supportedAgentIDs(t)
	// AgentUnknown is the unclassified sentinel, not a parser source.
	if _, ok := extract.For(model.AgentUnknown); ok {
		t.Fatalf("AgentUnknown unexpectedly has a registered parser")
	}

	described := map[string]bool{}
	for _, e := range agentDescriptorEnums() {
		if described[e] {
			t.Errorf("duplicate descriptor for agent %q", e)
		}
		described[e] = true
	}

	for _, a := range supported {
		if !described[a] {
			t.Errorf("agent %q is supported by a parser or hook backend but has no descriptor row", a)
		}
	}
	for d := range described {
		if !containsString(supported, d) {
			t.Errorf("descriptor row for %q has no parser or hook backend (drifted)", d)
		}
	}
}

// supportedAgentIDs returns the sorted set that `numbat agents` must describe:
// every parser-backed source plus every hook-supported source.
func supportedAgentIDs(t *testing.T) []string {
	t.Helper()
	set := map[string]bool{}
	for _, a := range extract.RegisteredAgents() {
		set[a] = true
	}
	for _, name := range hook.AgentNames() {
		src, err := hook.ParseAgent(name)
		if err != nil {
			t.Fatalf("hook.ParseAgent(%q): %v", name, err)
		}
		set[src] = true
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// The descriptor drift check must catch additions on either side.
func TestAgentDescriptorsGuardCatchesDrift(t *testing.T) {
	supported := supportedAgentIDs(t)
	described := map[string]bool{}
	for _, e := range agentDescriptorEnums() {
		described[e] = true
	}

	mismatch := func(authority []string, desc map[string]bool) bool {
		auth := map[string]bool{}
		for _, a := range authority {
			auth[a] = true
		}
		if len(auth) != len(desc) {
			return true
		}
		for a := range auth {
			if !desc[a] {
				return true
			}
		}
		for d := range desc {
			if !auth[d] {
				return true
			}
		}
		return false
	}

	// Sanity: the real sets agree (no mismatch).
	if mismatch(supported, described) {
		t.Fatalf("real registry and descriptors disagree; the live guard should have caught this")
	}

	// A newly registered agent the descriptor table forgot → mismatch.
	forgotten := append(append([]string{}, supported...), "newagent-no-descriptor")
	if !mismatch(forgotten, described) {
		t.Errorf("guard failed to catch a supported agent with no descriptor")
	}

	// A descriptor for an agent the registry does not know → mismatch.
	extraDesc := map[string]bool{"ghost-agent": true}
	for d := range described {
		extraDesc[d] = true
	}
	if !mismatch(supported, extraDesc) {
		t.Errorf("guard failed to catch a descriptor with no parser or hook backend")
	}
}

// TestAgentsEmptyHomeExitsZero asserts the report is a clean success even when
// the machine has zero agents: exit 0 and the header still prints (zero detected
// is a valid report, not an error). The default view is an inventory of present
// agents, so an empty HOME prints no absent agent rows; --all is the coverage
// matrix.
func TestAgentsEmptyHomeExitsZero(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	// Neutralize any env overrides the test host may carry so the temp HOME is the
	// only source of truth for this run.
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	out, errb, code := runCLI("agents")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%s)", code, errb)
	}
	if !strings.Contains(out, "AGENT") || !strings.Contains(out, "CONFIG") || !strings.Contains(out, "ARTIFACTS") {
		t.Fatalf("missing table header:\n%s", out)
	}
	for _, d := range agentDescriptors {
		if strings.Contains(out, d.display) {
			t.Errorf("default empty-HOME inventory should not show absent row %q:\n%s", d.display, out)
		}
	}
	// With an empty HOME no agent is detected. tabwriter expands the column gaps to
	// spaces, so a substring like "\tyes\t" never matches the rendered table; assert
	// on the structured rows instead, which is what the column actually carries.
	for _, r := range buildAgentRows(home) {
		if r.Present {
			t.Errorf("empty HOME should have no present agents, but %q reported present", r.Agent)
		}
		if r.Detected {
			t.Errorf("empty HOME should detect nothing, but %q reported detected", r.Agent)
		}
		if r.Wired == "yes" {
			t.Errorf("empty HOME should wire nothing, but %q reported wired=yes", r.Agent)
		}
	}
}

// TestAgentsAllShowsCoverageMatrix proves --all keeps the support matrix view:
// every parser-backed or hook-backed descriptor is present even when the endpoint
// has none of them installed.
func TestAgentsAllShowsCoverageMatrix(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	out, errb, code := runCLI("agents", "--all")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%s)", code, errb)
	}
	for _, d := range agentDescriptors {
		if !strings.Contains(out, d.display) {
			t.Errorf("--all missing row for %q:\n%s", d.display, out)
		}
	}
}

func TestKiroInventoryDescribesSharedIDEAndCLIv3Coverage(t *testing.T) {
	var kiro agentDescriptor
	found := false
	for _, d := range agentDescriptors {
		if d.enum == model.AgentKiro {
			kiro, found = d, true
			break
		}
	}
	if !found {
		t.Fatal("Kiro inventory descriptor missing")
	}
	if kiro.display != "Kiro IDE / CLI v3" {
		t.Fatalf("Kiro display = %q", kiro.display)
	}
	for _, want := range []string{"KIRO_HOME", "IDE separately", "~/.kiro/hooks/numbat.json"} {
		if !strings.Contains(kiro.setupHint, want) {
			t.Errorf("Kiro setup hint %q missing %q", kiro.setupHint, want)
		}
	}

	home := t.TempDir()
	cliRoot := filepath.Join(t.TempDir(), "kiro-cli-profile")
	t.Setenv("KIRO_HOME", cliRoot)
	if got := kiro.configDir(home); got != cliRoot {
		t.Fatalf("Kiro CLI config root = %q, want %q", got, cliRoot)
	}
	if err := os.Mkdir(filepath.Join(home, ".kiro"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !kiro.configPresent(home) {
		t.Fatal("default Kiro IDE root was hidden by an absent KIRO_HOME CLI root")
	}
	if got, want := kiro.wiredPath(home), filepath.Join(cliRoot, "hooks", "numbat.json"); got != want {
		t.Fatalf("Kiro wired path = %q, want selected CLI target %q", got, want)
	}
	defaultIDEHook := filepath.Join(home, ".kiro", "hooks", "numbat.json")
	if _, err := hook.Install(hook.AgentKiro, defaultIDEHook, "/opt/numbat", "", false); err != nil {
		t.Fatal(err)
	}
	if got := kiro.wiredColumn(home); got != "yes" {
		t.Fatalf("Kiro wired column = %q, want yes for active default IDE hook with KIRO_HOME set", got)
	}
}

func TestKiroInventoryDoesNotHideUnreadableAlternateProfile(t *testing.T) {
	var kiro agentDescriptor
	found := false
	for _, d := range agentDescriptors {
		if d.enum == model.AgentKiro {
			kiro = d
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Kiro inventory descriptor missing")
	}

	home := t.TempDir()
	cliRoot := filepath.Join(t.TempDir(), "kiro-cli-profile")
	t.Setenv("KIRO_HOME", cliRoot)
	if _, err := hook.Install(hook.AgentKiro, filepath.Join(cliRoot, "hooks", "numbat.json"), "/opt/numbat", "", false); err != nil {
		t.Fatal(err)
	}
	defaultIDEHook := filepath.Join(home, ".kiro", "hooks", "numbat.json")
	if err := os.MkdirAll(filepath.Dir(defaultIDEHook), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultIDEHook, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := kiro.wiredColumn(home); !strings.HasPrefix(got, "error") {
		t.Fatalf("Kiro wired column = %q, want unreadable alternate to remain visible", got)
	}
}

func TestGrokInventoryHonorsGrokHome(t *testing.T) {
	var grok agentDescriptor
	found := false
	for _, d := range agentDescriptors {
		if d.enum == model.AgentGrok {
			grok, found = d, true
			break
		}
	}
	if !found {
		t.Fatal("Grok inventory descriptor missing")
	}

	root := filepath.Join(t.TempDir(), "grok-profile")
	t.Setenv("GROK_HOME", root)
	if got := grok.configDir("/unused"); got != root {
		t.Fatalf("Grok config root = %q, want %q", got, root)
	}
	if got, want := grok.wiredPath("/unused"), filepath.Join(root, "hooks", "numbat.json"); got != want {
		t.Fatalf("Grok wired path = %q, want %q", got, want)
	}
}

// TestAgentsDetectedAndWired exercises discovery and hook status through their
// production paths.
func TestAgentsDetectedAndWired(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	// A transcript makes Claude both detected and available for at-rest scanning.
	projDir := filepath.Join(home, ".claude", "projects", "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatalf("mkdir projects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projDir, "session.jsonl"), []byte(scanTranscript), 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}

	// Use the installer so hook status is checked against its real output.
	settings := hook.ClaudeSettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if _, err := hook.Install(hook.AgentClaude, settings, "/usr/local/bin/numbat", "", false); err != nil {
		t.Fatalf("install claude hook: %v", err)
	}

	rows := buildAgentRows(home)
	byName := map[string]agentRow{}
	for _, r := range rows {
		byName[r.Agent] = r
	}

	claude, ok := byName["Claude Code"]
	if !ok {
		t.Fatalf("no Claude Code row in %+v", rows)
	}
	if !claude.Detected {
		t.Errorf("Claude Code should be detected (config dir present)")
	}
	if !claude.Present {
		t.Errorf("Claude Code should be present")
	}
	if !strings.Contains(claude.AtRest, "found transcripts") {
		t.Errorf("Claude Code at-rest = %q, want a transcripts-found signal", claude.AtRest)
	}
	if claude.Wired != "yes" {
		t.Errorf("Claude Code wired = %q, want yes (hook installed)", claude.Wired)
	}

	out, errb, code := runCLI("agents")
	if code != 0 {
		t.Fatalf("agents exit = %d (stderr=%s)", code, errb)
	}
	if !strings.Contains(out, "Claude Code") {
		t.Errorf("default inventory missing present Claude row:\n%s", out)
	}
	if strings.Contains(out, "Codex") {
		t.Errorf("default inventory should filter absent Codex row:\n%s", out)
	}

	// Absent: Codex has neither a config dir nor any transcript under this HOME.
	codex, ok := byName["Codex"]
	if !ok {
		t.Fatalf("no Codex row in %+v", rows)
	}
	if codex.Detected {
		t.Errorf("Codex should be undetected (no config dir)")
	}
	if codex.Present {
		t.Errorf("Codex should be absent from the default inventory")
	}
	if !strings.Contains(codex.AtRest, "none found") {
		t.Errorf("Codex at-rest = %q, want a none-found signal", codex.AtRest)
	}
	if codex.Wired != "no" {
		t.Errorf("Codex wired = %q, want no (hook not installed)", codex.Wired)
	}
	if codex.SetupHint == "" {
		t.Errorf("Codex should carry a non-empty setup hint")
	}
}

// TestAgentsJSONShape asserts --format json emits a decodable array carrying the
// documented columns (including at_rest_scan_incomplete), so a wrapper can
// consume the report programmatically.
func TestAgentsJSONShape(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	out, errb, code := runCLI("agents", "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	var defaultRows []agentRow
	if err := json.Unmarshal([]byte(out), &defaultRows); err != nil {
		t.Fatalf("decode default json: %v\n%s", err, out)
	}
	if len(defaultRows) != 0 {
		t.Fatalf("default JSON rows = %d, want 0 for empty HOME: %+v", len(defaultRows), defaultRows)
	}

	out, errb, code = runCLI("agents", "--all", "--format", "json")
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	var rows []struct {
		Agent                string `json:"agent"`
		Present              bool   `json:"present"`
		Detected             bool   `json:"detected"`
		AtRest               string `json:"at_rest"`
		Hook                 string `json:"hook"`
		Wired                string `json:"wired"`
		SetupHint            string `json:"setup_hint"`
		AtRestScanIncomplete bool   `json:"at_rest_scan_incomplete"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("decode json: %v\n%s", err, out)
	}
	if len(rows) != len(agentDescriptors) {
		t.Fatalf("json rows = %d, want %d", len(rows), len(agentDescriptors))
	}
	for _, r := range rows {
		if r.Agent == "" || r.Hook == "" || r.SetupHint == "" {
			t.Errorf("row missing required field: %+v", r)
		}
		if r.Present {
			t.Errorf("empty HOME --all row should report present=false: %+v", r)
		}
		// An empty HOME completes cleanly with nothing skipped: incomplete must be
		// false everywhere, the JSON companion to a verified "none found".
		if r.AtRestScanIncomplete {
			t.Errorf("empty HOME should scan cleanly, but %q reported at_rest_scan_incomplete", r.Agent)
		}
	}
}

// TestAgentsRejectsBadFormat asserts an unknown --format value is a usage error
// (exit 2), matching timeline's contract.
func TestAgentsRejectsBadFormat(t *testing.T) {
	_, errb, code := runCLI("agents", "--format", "yaml")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "invalid --format") {
		t.Fatalf("missing invalid-format error: %q", errb)
	}
}

// TestAgentsRejectsStrayArg matches the other subcommands' usage-error contract:
// an unexpected positional argument is exit 2 with a usage error.
func TestAgentsRejectsStrayArg(t *testing.T) {
	_, errb, code := runCLI("agents", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb, "unexpected argument") {
		t.Fatalf("missing unexpected-argument error: %q", errb)
	}
}

// Detection and artifact scanning must use the same relocated agent root.
func TestAgentsEnvRootConsistency(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), "codex-data")
	setTestHome(t, home)
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CODEX_HOME", codexHome)

	sessDir := filepath.Join(codexHome, "sessions", "2026", "06")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatalf("mkdir codex sessions: %v", err)
	}
	codexTranscript := `{"type":"user","timestamp":"2026-06-05T00:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(sessDir, "rollout-2026-06-05T00-00-00-abc.jsonl"), []byte(codexTranscript), 0o644); err != nil {
		t.Fatalf("write codex transcript: %v", err)
	}

	var codex agentRow
	for _, r := range buildAgentRows(home) {
		if r.Agent == "Codex" {
			codex = r
		}
	}
	if codex.Agent == "" {
		t.Fatal("no Codex row")
	}
	if !codex.Detected {
		t.Errorf("Codex under CODEX_HOME should be detected; detection ignored the override")
	}
	if !strings.Contains(codex.AtRest, "found transcripts") {
		t.Errorf("Codex at-rest = %q, want transcripts-found under CODEX_HOME", codex.AtRest)
	}
	if codex.AtRestScanIncomplete {
		t.Errorf("scan should be complete, got incomplete: %q", codex.AtRest)
	}
}

func TestAgentsReportsPiAndRelocatedKimiCode(t *testing.T) {
	home := t.TempDir()
	kimiHome := filepath.Join(t.TempDir(), "kimi-data")
	setTestHome(t, home)
	t.Setenv("KIMI_CODE_HOME", kimiHome)
	t.Setenv("PI_CODING_AGENT_DIR", "")

	piSession := filepath.Join(home, ".pi", "agent", "sessions", "--work--", "session.jsonl")
	kimiWire := filepath.Join(kimiHome, "sessions", "wd_work_abc", "session-1", "agents", "main", "wire.jsonl")
	for _, path := range []string{piSession, kimiWire} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	rows := map[string]agentRow{}
	for _, row := range buildAgentRows(home) {
		rows[row.Agent] = row
	}
	wantLive := map[string]string{"Pi": hookModalityPlugin, "Kimi Code": hookModalityHooks}
	for _, name := range []string{"Pi", "Kimi Code"} {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("missing %s row", name)
		}
		if !row.Present || !row.Detected || !strings.Contains(row.AtRest, "found transcripts") {
			t.Errorf("%s row = %+v", name, row)
		}
		if row.Hook != wantLive[name] || row.Wired != "no" {
			t.Errorf("%s live columns = hook %q wired %q", name, row.Hook, row.Wired)
		}
	}
}

func TestAgentsReportsOpenClawStateAndConfigRoots(t *testing.T) {
	t.Run("state root owns transcripts and plugin", func(t *testing.T) {
		home := t.TempDir()
		stateDir := filepath.Join(t.TempDir(), "gateway-state")
		setTestHome(t, home)
		t.Setenv("OPENCLAW_STATE_DIR", stateDir)

		transcript := filepath.Join(stateDir, "agents", "main", "sessions", "session.jsonl")
		if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(transcript, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pluginDir := hook.OpenClawPluginPath(home)
		if _, err := hook.InstallWithOptions(hook.AgentOpenClaw, pluginDir, filepath.Join(home, "bin", "numbat"), hook.InstallOptions{Enforce: true}); err != nil {
			t.Fatal(err)
		}

		row := agentRowByName(t, buildAgentRows(home), "OpenClaw")
		assertOpenClawInventoryRow(t, row)
	})

	t.Run("config path does not relocate transcripts", func(t *testing.T) {
		home := t.TempDir()
		configRoot := filepath.Join(t.TempDir(), "gateway-config")
		setTestHome(t, home)
		t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(configRoot, "openclaw.json"))

		transcript := filepath.Join(home, ".openclaw", "agents", "main", "sessions", "session.jsonl")
		if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(transcript, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pluginDir := hook.OpenClawPluginPath(home)
		if want := filepath.Join(configRoot, "extensions", "numbat"); pluginDir != want {
			t.Fatalf("plugin path = %q, want %q", pluginDir, want)
		}
		if _, err := hook.InstallWithOptions(hook.AgentOpenClaw, pluginDir, filepath.Join(home, "bin", "numbat"), hook.InstallOptions{}); err != nil {
			t.Fatal(err)
		}

		row := agentRowByName(t, buildAgentRows(home), "OpenClaw")
		assertOpenClawInventoryRow(t, row)
	})

	t.Run("config-only root is an installation signal", func(t *testing.T) {
		home := t.TempDir()
		configRoot := filepath.Join(t.TempDir(), "gateway-config")
		setTestHome(t, home)
		t.Setenv("OPENCLAW_CONFIG_PATH", filepath.Join(configRoot, "openclaw.json"))

		if err := os.MkdirAll(configRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		row := agentRowByName(t, buildAgentRows(home), "OpenClaw")
		if !row.Present || !row.Detected || row.Wired != "no" {
			t.Fatalf("config-only OpenClaw row = %+v", row)
		}
	})

	t.Run("legacy state root is still an installation signal", func(t *testing.T) {
		home := t.TempDir()
		setTestHome(t, home)
		if err := os.MkdirAll(filepath.Join(home, ".clawdbot"), 0o700); err != nil {
			t.Fatal(err)
		}

		row := agentRowByName(t, buildAgentRows(home), "OpenClaw")
		if !row.Present || !row.Detected || row.Wired != "no" {
			t.Fatalf("legacy-only OpenClaw row = %+v", row)
		}
	})
}

func agentRowByName(t *testing.T, rows []agentRow, name string) agentRow {
	t.Helper()
	for _, row := range rows {
		if row.Agent == name {
			return row
		}
	}
	t.Fatalf("missing %s row", name)
	return agentRow{}
}

func assertOpenClawInventoryRow(t *testing.T, row agentRow) {
	t.Helper()
	if !row.Present || !row.Detected {
		t.Errorf("OpenClaw presence = %+v", row)
	}
	if !strings.Contains(row.AtRest, "found transcripts") || !strings.Contains(row.AtRest, "deferred SQLite/WAL") {
		t.Errorf("OpenClaw at-rest = %q", row.AtRest)
	}
	if row.Hook != hookModalityPlugin || row.Wired != "yes" {
		t.Errorf("OpenClaw live columns = hook %q wired %q", row.Hook, row.Wired)
	}
}

func TestAgentsHonorPiAndQwenHomeOverridesForDetection(t *testing.T) {
	home := t.TempDir()
	piHome := filepath.Join(t.TempDir(), "pi-agent")
	qwenHome := filepath.Join(t.TempDir(), "qwen-data")
	setTestHome(t, home)
	t.Setenv("PI_CODING_AGENT_DIR", piHome)
	t.Setenv("QWEN_HOME", qwenHome)
	for _, root := range []string{piHome, qwenHome} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	rows := map[string]agentRow{}
	for _, row := range buildAgentRows(home) {
		rows[row.Agent] = row
	}
	for _, name := range []string{"Pi", "Qwen Code"} {
		if row := rows[name]; !row.Present || !row.Detected {
			t.Errorf("%s override was not detected: %+v", name, row)
		}
	}
}

func TestAgentsExpandQwenHomeForDetection(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("QWEN_HOME", "~/.qwen-alt")
	if err := os.MkdirAll(filepath.Join(home, ".qwen-alt"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, row := range buildAgentRows(home) {
		if row.Agent == "Qwen Code" {
			if !row.Present || !row.Detected {
				t.Fatalf("expanded QWEN_HOME was not detected: %+v", row)
			}
			return
		}
	}
	t.Fatal("Qwen Code row missing")
}

func TestAgentsHonorClineDirForDetection(t *testing.T) {
	home := t.TempDir()
	clineHome := filepath.Join(t.TempDir(), "cline-data")
	setTestHome(t, home)
	t.Setenv("CLINE_DIR", clineHome)
	if err := os.MkdirAll(clineHome, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, row := range buildAgentRows(home) {
		if row.Agent == "Cline CLI" {
			if !row.Present || !row.Detected {
				t.Fatalf("CLINE_DIR was not detected: %+v", row)
			}
			return
		}
	}
	t.Fatal("missing Cline CLI row")
}

func TestAgentsReportsWiredGooseAndKiloUnderXDG(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "xdg")
	setTestHome(t, home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	for _, dir := range []string{filepath.Join(xdg, "goose"), filepath.Join(xdg, "kilo")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hook.InstallWithOptions(hook.AgentGoose, hook.GoosePluginPath(home), "/opt/numbat", hook.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hook.InstallWithOptions(hook.AgentKilo, hook.KiloPluginPath(home), "/opt/numbat", hook.InstallOptions{}); err != nil {
		t.Fatal(err)
	}

	rows := map[string]agentRow{}
	for _, row := range buildAgentRows(home) {
		rows[row.Agent] = row
	}
	for _, name := range []string{"Goose", "Kilo Code"} {
		row := rows[name]
		if !row.Present || !row.Detected || row.Wired != "yes" {
			t.Errorf("%s XDG row = %+v", name, row)
		}
	}
	if row := rows["OpenHands"]; row.Present || row.Detected || row.Wired != "n/a" {
		t.Errorf("project-scoped OpenHands should not invent a global signal: %+v", row)
	}
}

func TestAgentsReportsManagedOnlyHookAsWired(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	managedPath := filepath.Join(t.TempDir(), "qwen-managed.json")
	inventoryManagedHooksPath = func(agent string) (string, bool) {
		if agent == hook.AgentQwen {
			return managedPath, true
		}
		return "", false
	}
	if _, err := hook.InstallManagedWithOptions(
		hook.AgentQwen,
		managedPath,
		"/opt/numbat",
		hook.InstallOptions{},
	); err != nil {
		t.Fatal(err)
	}

	for _, row := range buildAgentRows(home) {
		if row.Agent != "Qwen Code" {
			continue
		}
		if !row.Present || row.Detected || row.Wired != "yes" {
			t.Fatalf("managed-only Qwen row = %+v", row)
		}
		return
	}
	t.Fatal("Qwen Code row missing")
}

func TestAgentsHonorAgentHomeOverrides(t *testing.T) {
	home := t.TempDir()
	claudeHome := filepath.Join(t.TempDir(), "claude-data")
	copilotHome := filepath.Join(t.TempDir(), "copilot-data")
	opencodeConfig := filepath.Join(t.TempDir(), "opencode-config")
	opencodeData := filepath.Join(t.TempDir(), "opencode-data")
	hermesHome := filepath.Join(t.TempDir(), "hermes-data")
	setTestHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("COPILOT_HOME", copilotHome)
	t.Setenv("OPENCODE_CONFIG_DIR", opencodeConfig)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", opencodeData)
	t.Setenv("HERMES_HOME", hermesHome)

	for _, dir := range []string{
		filepath.Join(claudeHome, "projects", "p1"),
		filepath.Join(copilotHome, "hooks"),
		opencodeConfig,
		hermesHome,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(claudeHome, "projects", "p1", "session.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(copilotHome, "session-state", "s1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copilotHome, "session-state", "s1", "events.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openCodeRecord := filepath.Join(opencodeData, "opencode", "storage", "message", "p1", "s1.json")
	if err := os.MkdirAll(filepath.Dir(openCodeRecord), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openCodeRecord, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := map[string]agentRow{}
	for _, row := range buildAgentRows(home) {
		rows[row.Agent] = row
	}
	for _, name := range []string{"Claude Code", "GitHub Copilot CLI", "VS Code Copilot Chat", "OpenCode", "Hermes"} {
		if !rows[name].Detected {
			t.Errorf("%s not detected under its configured home: %+v", name, rows[name])
		}
	}
	for _, name := range []string{"Claude Code", "GitHub Copilot CLI", "OpenCode"} {
		if !strings.Contains(rows[name].AtRest, "found transcripts") {
			t.Errorf("%s at-rest = %q, want relocated artifacts found", name, rows[name].AtRest)
		}
	}
}

func TestAgentsDetectsAntigravityAppAndCLIState(t *testing.T) {
	for _, rel := range []string{".gemini/antigravity", ".gemini/antigravity-cli"} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			t.Setenv("CODEX_HOME", "")
			t.Setenv("GEMINI_CLI_HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", "")
			if err := os.MkdirAll(filepath.Join(home, rel), 0o755); err != nil {
				t.Fatal(err)
			}

			var antigravity agentRow
			for _, row := range buildAgentRows(home) {
				if row.Agent == "Antigravity" {
					antigravity = row
					break
				}
			}
			if !antigravity.Detected {
				t.Fatalf("Antigravity state at %s was not detected", rel)
			}
		})
	}
}

// An unreadable subtree must qualify an otherwise empty artifact scan.
func TestAgentsSkipQualifiesNoneFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not create an unreadable directory on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions; cannot force a skip")
	}
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	// An existing .claude/projects root with an unreadable subdir and no artifact:
	// the walk completes but records a skip, so "none found" must be qualified.
	blocked := filepath.Join(home, ".claude", "projects", "blocked")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("chmod blocked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	var claude agentRow
	for _, r := range buildAgentRows(home) {
		if r.Agent == "Claude Code" {
			claude = r
		}
	}
	if claude.Agent == "" {
		t.Fatal("no Claude Code row")
	}
	if !claude.AtRestScanIncomplete {
		t.Errorf("an unreadable subtree must mark the scan incomplete; got AtRest=%q", claude.AtRest)
	}
	if !strings.Contains(claude.AtRest, "partial scan") {
		t.Errorf("at-rest = %q, want a qualified partial-scan state, not a clean none-found", claude.AtRest)
	}
}

// Malformed hook config is an unknown/error state, not a verified "not wired".
func TestAgentsMalformedConfigWiredError(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("GEMINI_CLI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	settings := hook.ClaudeSettingsPath(home)
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.WriteFile(settings, []byte("{ this is not valid json"), 0o644); err != nil {
		t.Fatalf("write malformed settings: %v", err)
	}

	var claude agentRow
	for _, r := range buildAgentRows(home) {
		if r.Agent == "Claude Code" {
			claude = r
		}
	}
	if claude.Agent == "" {
		t.Fatal("no Claude Code row")
	}
	if claude.Wired == "no" {
		t.Errorf("malformed hook config must not render wired=no (asserts an unverified absence)")
	}
	if !strings.Contains(claude.Wired, "error") {
		t.Errorf("wired = %q, want an error/unknown state for an unreadable config", claude.Wired)
	}
}

func writeMuseBundle(t *testing.T, appsDir, bundleID string) {
	t.Helper()
	dir := filepath.Join(appsDir, "Muse.app", "Contents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Binary plists store ASCII strings verbatim; this is enough for the check.
	body := append([]byte("bplist00"), []byte("\x00CFBundleIdentifier\x00"+bundleID+"\x00")...)
	if err := os.WriteFile(filepath.Join(dir, "Info.plist"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

type agentsJSONRow struct {
	Agent     string `json:"agent"`
	Supported bool   `json:"supported"`
	Present   bool   `json:"present"`
	Detected  bool   `json:"detected"`
	AtRest    string `json:"at_rest"`
	Hook      string `json:"hook"`
	Wired     string `json:"wired"`
	SetupHint string `json:"setup_hint"`
}

func agentsJSON(t *testing.T, args ...string) []agentsJSONRow {
	t.Helper()
	out, errb, code := runCLI(append([]string{"agents", "--format", "json"}, args...)...)
	if code != 0 {
		t.Fatalf("agents %v exit = %d (stderr=%s)", args, code, errb)
	}
	var rows []agentsJSONRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("decode json: %v\n%s", err, out)
	}
	return rows
}

func museDesktopRow(rows []agentsJSONRow) (agentsJSONRow, bool) {
	for _, r := range rows {
		if r.Agent == "Muse Desktop" {
			return r, true
		}
	}
	return agentsJSONRow{}, false
}

// Muse Desktop has no parser or hook, so it is listed from a presence signal
// alone and flagged unsupported. Each signal is checked independently.
func TestAgentsListsMuseDesktopWhenDetected(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, home string)
	}{
		{"application support directory", func(t *testing.T, home string) {
			mustMkdir(t, filepath.Join(home, "Library", "Application Support", "com.meta.endo"))
		}},
		{"caches directory", func(t *testing.T, home string) {
			mustMkdir(t, filepath.Join(home, "Library", "Caches", "com.meta.endo"))
		}},
		{"system Applications bundle", func(t *testing.T, home string) {
			writeMuseBundle(t, systemApplicationsDir, "com.meta.endo")
		}},
		{"user Applications bundle", func(t *testing.T, home string) {
			writeMuseBundle(t, filepath.Join(home, "Applications"), "com.meta.endo")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			tc.setup(t, home)

			for _, args := range [][]string{nil, {"--all"}} {
				row, ok := museDesktopRow(agentsJSON(t, args...))
				if !ok {
					t.Fatalf("agents %v: Muse Desktop not listed", args)
				}
				if row.Supported || !row.Present || !row.Detected {
					t.Errorf("agents %v: row flags = %+v, want unsupported but present and detected", args, row)
				}
				if row.Hook != "none" || row.Wired != "n/a" || !strings.Contains(row.AtRest, "unsupported") || !strings.Contains(row.SetupHint, "unsupported") {
					t.Errorf("agents %v: row must say unsupported with no hook or wiring: %+v", args, row)
				}
			}
			out, _, _ := runCLI("agents")
			if !strings.Contains(out, "Muse Desktop") || !strings.Contains(out, "unsupported") {
				t.Errorf("text output missing the unsupported Muse Desktop row:\n%s", out)
			}
		})
	}
}

// The bundle identifier, not the app name, is the signal, so an unrelated
// Muse.app must never be reported as Muse Desktop.
func TestAgentsDoesNotMistakeAnotherMuseAppForMuseDesktop(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	writeMuseBundle(t, systemApplicationsDir, "com.example.somethingelse")
	writeMuseBundle(t, filepath.Join(home, "Applications"), "com.example.somethingelse")

	for _, args := range [][]string{nil, {"--all"}} {
		if _, ok := museDesktopRow(agentsJSON(t, args...)); ok {
			t.Errorf("agents %v listed Muse Desktop for a bundle with a different identifier", args)
		}
	}
}

// Unsupported rows are inventory of what is present. When nothing is detected
// they must not appear even under --all, which stays the supported matrix.
func TestAgentsOmitsUnsupportedRowsWhenAbsent(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

	rows := agentsJSON(t, "--all")
	if len(rows) != len(agentDescriptors) {
		t.Fatalf("--all rows = %d, want %d supported rows only", len(rows), len(agentDescriptors))
	}
	if _, ok := museDesktopRow(rows); ok {
		t.Error("Muse Desktop listed on a machine with no Muse Desktop signal")
	}
	for _, r := range rows {
		if !r.Supported {
			t.Errorf("supported matrix row reported unsupported: %+v", r)
		}
	}
}

// A mixed machine reports both kinds of row, distinguished by the supported flag.
func TestAgentsDistinguishesSupportedFromUnsupportedRows(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	mustMkdir(t, filepath.Join(home, ".claude"))
	mustMkdir(t, filepath.Join(home, "Library", "Application Support", "com.meta.endo"))

	var sawClaude, sawMuseDesktop bool
	for _, r := range agentsJSON(t) {
		switch r.Agent {
		case "Claude Code":
			sawClaude = true
			if !r.Supported {
				t.Errorf("Claude Code must be supported: %+v", r)
			}
		case "Muse Desktop":
			sawMuseDesktop = true
			if r.Supported {
				t.Errorf("Muse Desktop must be unsupported: %+v", r)
			}
		}
	}
	if !sawClaude || !sawMuseDesktop {
		t.Fatalf("expected both rows: claude=%v muse-desktop=%v", sawClaude, sawMuseDesktop)
	}
}

// Detect-only entries must stay out of the supported descriptor table, whose
// sync test requires every row to be parser- or hook-backed.
func TestUnsupportedAgentsAreDisjointFromSupportedDescriptors(t *testing.T) {
	supported := map[string]bool{}
	for _, d := range agentDescriptors {
		supported[d.display] = true
	}
	for _, u := range unsupportedAgents {
		if supported[u.display] {
			t.Errorf("%q is listed as both supported and unsupported", u.display)
		}
		if u.detect == nil || u.atRest == "" || u.hint == "" {
			t.Errorf("%q has an incomplete unsupported descriptor: %+v", u.display, u)
		}
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
