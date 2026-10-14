package hook

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestResolveOpenClawLifecycle(t *testing.T) {
	cases := map[string]Lifecycle{
		"session_start":    LifecycleSessionStart,
		"message_received": LifecyclePromptSubmit,
		"llm_input":        LifecyclePromptSubmit,
		"before_tool_call": LifecyclePreTool,
		"after_tool_call":  LifecyclePostTool,
		"llm_output":       LifecycleAssistant,
		"message_sent":     LifecycleAssistant,
		"session_end":      LifecycleSessionEnd,
		"subagent_spawned": LifecycleSessionStart,
		"subagent_ended":   LifecycleSessionEnd,
		"SESSION_START":    LifecycleSessionStart,
		"pre-tool":         LifecyclePreTool,
	}
	for raw, want := range cases {
		got, err := ResolveLifecycle(AgentOpenClaw, raw)
		if err != nil || got != want {
			t.Errorf("ResolveLifecycle(openclaw, %q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"before_agent_run", "tool_result_persist", "message_sending", "before_tool_call_extra", ""} {
		if _, err := ResolveLifecycle(AgentOpenClaw, raw); err == nil {
			t.Errorf("ResolveLifecycle(openclaw, %q) should reject an unwired callback", raw)
		}
	}

	response, ok := DenyResponse(AgentOpenClaw, "policy denied")
	if !ok || response["block"] != true || response["blockReason"] != "policy denied" || len(response) != 2 {
		t.Fatalf("OpenClaw deny response = %#v, %v", response, ok)
	}
	if !EnforceEligible(AgentOpenClaw, "before_tool_call", LifecyclePreTool) {
		t.Fatal("OpenClaw before_tool_call should be enforceable")
	}
	if EnforceEligible(AgentOpenClaw, "after_tool_call", LifecyclePostTool) {
		t.Fatal("OpenClaw after_tool_call must not be enforceable")
	}
}

func TestMapOpenClawCorrelationAndTimestamps(t *testing.T) {
	prompt := Map(LifecyclePromptSubmit, AgentOpenClaw, model.AgentOpenClaw, "prompt", map[string]any{
		"timestamp":   int64(1_710_000_000),
		"session_key": "agent:main:session-1",
		"prompt":      "inspect the change",
	})
	if prompt.SessionID != "agent:main:session-1" || prompt.Timestamp != "2024-03-09T16:00:00Z" {
		t.Fatalf("seconds prompt correlation = %+v", prompt)
	}

	tool := Map(LifecyclePreTool, AgentOpenClaw, model.AgentOpenClaw, "tool", map[string]any{
		"timestamp":  int64(1_710_000_000_123),
		"session_id": "agent:main:session-1",
		"tool_name":  "exec",
		"tool_input": map[string]any{"command": "git status"},
	})
	if tool.SessionID != prompt.SessionID || tool.Timestamp != "2024-03-09T16:00:00.123Z" {
		t.Fatalf("millisecond tool correlation = %+v", tool)
	}

	child := Map(LifecycleSessionStart, AgentOpenClaw, model.AgentOpenClaw, "child", map[string]any{
		"session_id": "agent:main:subagent:child-1",
		"sub_agent":  "reviewer",
	})
	if child.EventType != model.EventSessionStart || child.SessionID != "agent:main:subagent:child-1" || child.SubAgent != "reviewer" {
		t.Fatalf("subagent correlation = %+v", child)
	}
}

func TestMapOpenClawConversationBoundaries(t *testing.T) {
	modelPrompt := Map(LifecyclePromptSubmit, AgentOpenClaw, model.AgentOpenClaw, "model-prompt", map[string]any{
		"timestamp":      "2026-07-23T10:00:00Z",
		"session_id":     "agent:main:session-1",
		"cwd":            "/srv/project",
		"model":          "gpt-5.6",
		"model_provider": "openai",
		"prompt":         "inspect  the\nchange",
		"boundary":       "model",
	})
	if modelPrompt.ContentPreview != "inspect the change" || modelPrompt.Model != "gpt-5.6" ||
		modelPrompt.ModelProvider != "openai" || modelPrompt.ProjectPath != "/srv/project" ||
		!containsString(modelPrompt.Tags, openClawTagModelBoundary) ||
		containsString(modelPrompt.Tags, openClawTagTransportBoundary) {
		t.Fatalf("model prompt mapping = %+v", modelPrompt)
	}

	modelOutput := Map(LifecycleAssistant, AgentOpenClaw, model.AgentOpenClaw, "model-output", map[string]any{
		"session_id":     "agent:main:session-1",
		"assistant_text": "first\nsecond " + strings.Repeat("x", previewMax),
		"boundary":       "model",
	})
	if modelOutput.EventType != model.EventMessageAssistant || modelOutput.Actor != model.ActorAssistant ||
		modelOutput.ContentPreview != "first second" ||
		!containsString(modelOutput.Tags, openClawTagModelBoundary) {
		t.Fatalf("model output mapping = %+v", modelOutput)
	}

	transportPrompt := Map(LifecyclePromptSubmit, AgentOpenClaw, model.AgentOpenClaw, "transport-prompt", map[string]any{
		"prompt": "hello", "boundary": "transport",
	})
	transportOutput := Map(LifecycleAssistant, AgentOpenClaw, model.AgentOpenClaw, "transport-output", map[string]any{
		"boundary": "transport",
	})
	if !containsString(transportPrompt.Tags, openClawTagTransportBoundary) ||
		!containsString(transportOutput.Tags, openClawTagTransportBoundary) ||
		transportOutput.ContentPreview != "" {
		t.Fatalf("transport boundary mapping = %+v / %+v", transportPrompt, transportOutput)
	}
}

func TestMapOpenClawTools(t *testing.T) {
	tests := []struct {
		name    string
		lc      Lifecycle
		payload map[string]any
		want    model.EventType
		value   string
	}{
		{
			name: "exec",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "exec", "tool_input": map[string]any{"command": "git status"},
			},
			want: model.EventCommandExec, value: "git status",
		},
		{
			name: "code mode exec stays generic",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "exec", "tool_kind": "code_mode_exec",
				"tool_input": map[string]any{"command": "await fetch('https://example.com')"},
			},
			want: model.EventToolCall,
		},
		{
			name: "code mode result stays generic and keeps error",
			lc:   LifecyclePostTool,
			payload: map[string]any{
				"tool_name": "exec", "is_error": true,
				"tool_input": map[string]any{
					"code": "throw new Error('no')", "language": "javascript",
				},
			},
			want: model.EventToolResult,
		},
		{
			name: "read",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "read", "tool_input": map[string]any{"path": "/work/a.go"},
			},
			want: model.EventFileRead, value: "/work/a.go",
		},
		{
			name: "browser navigation",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "browser", "tool_input": map[string]any{"action": "navigate", "targetUrl": "https://example.com/path"},
			},
			want: model.EventNetworkIndicator, value: "https://example.com/path",
		},
		{
			name: "browser non-egress action stays generic",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "browser", "tool_input": map[string]any{"action": "screenshot"},
			},
			want: model.EventToolCall,
		},
		{
			name: "unknown plugin tool",
			lc:   LifecyclePreTool,
			payload: map[string]any{
				"tool_name": "vendor_shellish", "tool_input": map[string]any{"command": "rm -rf /"},
			},
			want: model.EventToolCall,
		},
		{
			name: "post error and duration",
			lc:   LifecyclePostTool,
			payload: map[string]any{
				"tool_name": "exec", "tool_input": map[string]any{"command": "false"},
				"duration_ms": float64(42), "exit_code": float64(23), "is_error": true,
			},
			want: model.EventCommandResult, value: "false",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(tc.lc, AgentOpenClaw, model.AgentOpenClaw, "evt", tc.payload)
			if ev.EventType != tc.want {
				t.Fatalf("event_type = %q, want %q: %#v", ev.EventType, tc.want, ev)
			}
			got := ev.Command
			if got == "" {
				got = ev.FilePath
			}
			if got == "" {
				got = ev.URL
			}
			if got != tc.value {
				t.Errorf("mapped value = %q, want %q", got, tc.value)
			}
			if tc.name == "post error and duration" {
				if ev.DurationMs == nil || *ev.DurationMs != 42 || ev.ExitCode == nil || *ev.ExitCode != 23 ||
					!containsString(ev.Tags, model.TagToolError) {
					t.Errorf("post metadata = %#v", ev)
				}
			}
			if tc.name == "code mode result stays generic and keeps error" && !containsString(ev.Tags, model.TagToolError) {
				t.Errorf("code-mode error metadata = %#v", ev)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("invalid mapped event: %v", err)
			}
		})
	}
}

func TestMapOpenClawApplyPatchPrefersParsedPatch(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: actual.go\n@@\n-old\n+new\n*** End Patch\n"
	events := MapEvents(LifecyclePreTool, AgentOpenClaw, model.AgentOpenClaw, "patch", map[string]any{
		"tool_name":     "apply_patch",
		"tool_input":    map[string]any{"input": patch},
		"derived_paths": []any{"misleading.go"},
	})
	if len(events) != 1 || events[0].FilePath != "actual.go" || events[0].DiffSHA256 == "" || events[0].DiffBytes != len(patch) {
		t.Fatalf("parsed patch events = %#v", events)
	}

	fallback := MapEvents(LifecyclePreTool, AgentOpenClaw, model.AgentOpenClaw, "derived", map[string]any{
		"tool_name":     "apply_patch",
		"tool_input":    map[string]any{"input": "malformed patch"},
		"derived_paths": []any{"one.go", "two.go"},
	})
	if len(fallback) != 2 || fallback[0].FilePath != "one.go" || fallback[1].FilePath != "two.go" {
		t.Fatalf("derived-path fallback events = %#v", fallback)
	}
}

func TestOpenClawInstallPackageLifecycle(t *testing.T) {
	root := filepath.Join(t.TempDir(), "extensions", "numbat")
	rep, err := InstallWithOptions(AgentOpenClaw, root, "/opt/Numbat Bin/numbat", InstallOptions{
		RuntimeArgs: []string{"--emit=findings,events", "--output=file", "--output-file=/tmp/numbat.ndjson"},
		Enforce:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Installed || !rep.Changed || !Status(AgentOpenClaw, root).Installed {
		t.Fatalf("install/status = %+v / %+v", rep, Status(AgentOpenClaw, root))
	}

	manifest, err := readOpenClawManifest(openClawManifestPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !isNumbatOpenClawManifestDocument(manifest) || !manifest.Activation.OnStartup ||
		len(manifest.Activation.OnCapabilities) != 1 || manifest.Activation.OnCapabilities[0] != "hook" ||
		manifest.ConfigSchema.Type != "object" || manifest.ConfigSchema.AdditionalProperties {
		t.Fatalf("manifest = %#v", manifest)
	}
	pkg, err := readOpenClawPackage(openClawPackagePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Type != "module" || len(pkg.OpenClaw.Extensions) != 1 || pkg.OpenClaw.Extensions[0] != "./index.js" ||
		pkg.OpenClaw.Compat.PluginAPI != ">=2026.7.1" || pkg.OpenClaw.Build.OpenClawVersion != "2026.7.1" {
		t.Fatalf("package = %#v", pkg)
	}
	if !isValidNumbatOpenClawManifest(manifest) || !isValidNumbatOpenClawPackage(pkg) {
		t.Fatalf("generated documents failed strict validation: %#v / %#v", manifest, pkg)
	}

	source := readTestFile(t, openClawSourcePath(root))
	for _, want := range []string{
		openClawSourceMarker,
		`import { spawn } from "node:child_process"`,
		`api.on("before_tool_call", enforceTool, { priority: 50, timeoutMs: 10000 })`,
		`api.on("llm_input"`,
		`api.on("llm_output"`,
		`api.on("subagent_spawned"`,
		`api.on("subagent_ended"`,
		`const NUMBAT_DEADLINE_MS = 9000`,
		`const OBSERVATION_DEADLINE_MS = 30000`,
		`const MAX_STDIN_BYTES = 4 * 1024 * 1024`,
		`const MAX_STDOUT_BYTES = 1024 * 1024`,
		`Buffer.concat(stdoutChunks, stdoutBytes).toString("utf8")`,
		`const input = serialize(payload)`,
		`session_id: sessionIdentity(event, ctx)`,
		`stdio: ["pipe", "pipe", "inherit"]`,
		`"/opt/Numbat Bin/numbat"`,
		`"--enforce"`,
		`response?.block === true`,
		`exit_code: toolExitCode(event.result)`,
		`finish(undefined)`,
	} {
		if !strings.Contains(source, want) {
			t.Errorf("generated source missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"spawnSync", "exec(", "shell: true", "allowConversationAccess", "minGatewayVersion", "event.content, success",
		"event.systemPrompt", "event.historyMessages", "event.tools", "event.lastAssistant",
		"event.usage", "event.reasoning", "event.resolvedRef", "event.harnessId",
	} {
		if strings.Contains(source, unwanted) {
			t.Errorf("generated source unexpectedly contains %q", unwanted)
		}
	}

	if node, err := exec.LookPath("node"); err == nil {
		cmd := exec.Command(node, "--check", openClawSourcePath(root))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("node --check: %v\n%s", err, out)
		}
	}

	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/Numbat Bin/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("idempotent reinstall: %v", err)
	}
	if err := os.WriteFile(openClawSourcePath(root), []byte(source+"// changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if invalid := Status(AgentOpenClaw, root); invalid.Installed || !strings.Contains(invalid.Message, "invalid") {
		t.Fatalf("tampered-source status = %+v", invalid)
	}
	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/Numbat Bin/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("repair tampered source: %v", err)
	}
	manifest.Activation.OnStartup = false
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openClawManifestPath(root), manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	if invalid := Status(AgentOpenClaw, root); invalid.Installed || !strings.Contains(invalid.Message, "invalid") {
		t.Fatalf("invalid-manifest status = %+v", invalid)
	}
	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/Numbat Bin/numbat", InstallOptions{Enforce: true}); err != nil {
		t.Fatalf("repair invalid manifest: %v", err)
	}
	if err := os.Remove(openClawSourcePath(root)); err != nil {
		t.Fatal(err)
	}
	if partial := Status(AgentOpenClaw, root); partial.Installed || !strings.Contains(partial.Message, "partial") {
		t.Fatalf("partial status = %+v", partial)
	}
	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/numbat", InstallOptions{}); err != nil {
		t.Fatalf("repair partial install: %v", err)
	}
	rep, err = Uninstall(AgentOpenClaw, root)
	if err != nil || !rep.Changed || Status(AgentOpenClaw, root).Installed {
		t.Fatalf("uninstall/status = %+v, %v / %+v", rep, err, Status(AgentOpenClaw, root))
	}
}

func TestOpenClawInstallerRefusesForeignFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "numbat")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign.txt"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("non-empty foreign directory should be refused")
	}

	root = filepath.Join(t.TempDir(), "numbat")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := map[string]any{"id": "foreign", "configSchema": map[string]any{"type": "object"}}
	data, _ := json.Marshal(foreign)
	if err := os.WriteFile(openClawManifestPath(root), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallWithOptions(AgentOpenClaw, root, "/opt/numbat", InstallOptions{}); err == nil {
		t.Fatal("foreign manifest should be refused")
	}
	if rep, err := Uninstall(AgentOpenClaw, root); err != nil || rep.Changed {
		t.Fatalf("foreign uninstall = %+v, %v", rep, err)
	}
}

func TestOpenClawPluginPathHonorsStateDir(t *testing.T) {
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_HOME", "")
	t.Setenv("OPENCLAW_CONFIG_PATH", "")
	t.Setenv("OPENCLAW_PROFILE", "")
	home := t.TempDir()
	if got, want := OpenClawPluginPath(home), filepath.Join(home, ".openclaw", "extensions", "numbat"); got != want {
		t.Fatalf("default OpenClawPluginPath = %q, want %q", got, want)
	}
	root := filepath.Join(t.TempDir(), "profile-state")
	t.Setenv("OPENCLAW_STATE_DIR", root)
	if got, want := OpenClawPluginPath("/unused"), filepath.Join(root, "extensions", "numbat"); got != want {
		t.Fatalf("overridden OpenClawPluginPath = %q, want %q", got, want)
	}

	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_HOME", "~/service")
	if got, want := OpenClawPluginPath(home), filepath.Join(home, "service", ".openclaw", "extensions", "numbat"); got != want {
		t.Fatalf("OPENCLAW_HOME OpenClawPluginPath = %q, want %q", got, want)
	}

	t.Setenv("OPENCLAW_STATE_DIR", "~/state")
	if got, want := OpenClawPluginPath(home), filepath.Join(home, "service", "state", "extensions", "numbat"); got != want {
		t.Fatalf("tilde OPENCLAW_STATE_DIR OpenClawPluginPath = %q, want %q", got, want)
	}
}

func TestOpenClawPluginPathHonorsConfigRootPrecedence(t *testing.T) {
	t.Setenv("OPENCLAW_STATE_DIR", "")
	t.Setenv("OPENCLAW_HOME", "")
	t.Setenv("OPENCLAW_CONFIG_PATH", "")
	t.Setenv("OPENCLAW_PROFILE", "")
	home := t.TempDir()
	legacy := filepath.Join(home, ".clawdbot")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	wantDefault := filepath.Join(home, ".openclaw", "extensions", "numbat")
	if got := OpenClawPluginPath(home); got != wantDefault {
		t.Fatalf("legacy state must not move global plugins: got %q, want %q", got, wantDefault)
	}

	config := filepath.Join(home, "profiles", "dev", "openclaw.json")
	t.Setenv("OPENCLAW_CONFIG_PATH", config)
	wantConfig := filepath.Join(filepath.Dir(config), "extensions", "numbat")
	if got := OpenClawPluginPath(home); got != wantConfig {
		t.Fatalf("config-root OpenClawPluginPath = %q, want %q", got, wantConfig)
	}

	t.Setenv("OPENCLAW_PROFILE", "work")
	if got := OpenClawPluginPath(home); got != wantConfig {
		t.Fatalf("OPENCLAW_PROFILE alone moved config root: got %q, want %q", got, wantConfig)
	}

	t.Setenv("OPENCLAW_CONFIG_PATH", "")
	wantUnprofiled := filepath.Join(home, ".openclaw", "extensions", "numbat")
	if got := OpenClawPluginPath(home); got != wantUnprofiled {
		t.Fatalf("OPENCLAW_PROFILE alone moved default root: got %q, want %q", got, wantUnprofiled)
	}

	state := filepath.Join(home, "state")
	t.Setenv("OPENCLAW_STATE_DIR", state)
	wantState := filepath.Join(state, "extensions", "numbat")
	if got := OpenClawPluginPath(home); got != wantState {
		t.Fatalf("state-root OpenClawPluginPath = %q, want %q", got, wantState)
	}
}
