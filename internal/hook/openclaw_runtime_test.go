package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestOpenClawGeneratedPluginRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake OpenClaw child executable uses a Unix shebang")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}

	root := t.TempDir()
	capturePath := filepath.Join(root, "calls.jsonl")
	fakePath := filepath.Join(root, "fake-numbat.mjs")
	pluginPath := filepath.Join(root, "numbat-plugin.mjs")
	observePluginPath := filepath.Join(root, "numbat-observe-plugin.mjs")
	missingPluginPath := filepath.Join(root, "numbat-missing-plugin.mjs")
	harnessPath := filepath.Join(root, "harness.mjs")

	fake := fmt.Sprintf(`#!%s
import fs from "node:fs";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const payload = JSON.parse(input);
const lifecycle = process.argv[3] ?? "unknown";
fs.appendFileSync(process.env.NUMBAT_OPENCLAW_TEST_CAPTURE,
  JSON.stringify({ args: process.argv.slice(2), payload }) + "\n");

const mode = payload?.tool_input?.mode;
switch (mode) {
  case "deny":
    process.stdout.write(JSON.stringify({ block: true, blockReason: "test policy denied" }));
    break;
  case "allow":
    process.stdout.write("{}");
    break;
  case "malformed":
    process.stdout.write("{not-json");
    break;
  case "nonzero":
    process.exitCode = 7;
    break;
  case "oversized-stdout":
    process.stdout.write("x".repeat(1024 * 1024 + 65536));
    break;
  case "split-utf8-deny": {
    const response = Buffer.from(JSON.stringify({ block: true, blockReason: "blocked 🦊 policy" }), "utf8");
    const marker = response.indexOf(Buffer.from("🦊", "utf8"));
    process.stdout.write(response.subarray(0, marker + 1));
    setTimeout(() => process.stdout.end(response.subarray(marker + 1)), 20);
    break;
  }
  case "timeout":
    setTimeout(() => process.stdout.write("{}"), 1000);
    break;
  default:
    process.stdout.write("OBSERVATION_STDOUT:" + lifecycle + "\n");
    process.stderr.write("OBSERVATION_STDERR:" + lifecycle + "\n");
}
`, node)
	writeOpenClawRuntimeTestFile(t, fakePath, fake, 0o700)

	// Keep the test fast while exercising the generated wrapper's real timeout
	// branch. The authored OpenClaw host timeout remains unchanged at 10 seconds.
	enforcedSource := strings.Replace(
		openClawPluginSource(fakePath, []string{"--output=stdout"}, true),
		"const NUMBAT_DEADLINE_MS = 9000;",
		"const NUMBAT_DEADLINE_MS = 500;",
		1,
	)
	writeOpenClawRuntimeTestFile(t, pluginPath, enforcedSource, 0o600)
	writeOpenClawRuntimeTestFile(t, observePluginPath, openClawPluginSource(fakePath, nil, false), 0o600)
	missingSource := strings.Replace(
		openClawPluginSource(filepath.Join(root, "missing-numbat"), nil, true),
		"const NUMBAT_DEADLINE_MS = 9000;",
		"const NUMBAT_DEADLINE_MS = 500;",
		1,
	)
	writeOpenClawRuntimeTestFile(t, missingPluginPath, missingSource, 0o600)
	writeOpenClawRuntimeTestFile(t, harnessPath, openClawRuntimeHarness, 0o600)

	cmd := exec.Command(node, harnessPath, pluginPath, observePluginPath, missingPluginPath, capturePath)
	cmd.Env = append(os.Environ(), "NUMBAT_OPENCLAW_TEST_CAPTURE="+capturePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenClaw Node harness: %v\n%s", err, out)
	}

	resultLine := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "HARNESS_RESULT=") {
			resultLine = strings.TrimPrefix(line, "HARNESS_RESULT=")
		}
	}
	if resultLine == "" {
		t.Fatalf("OpenClaw Node harness produced no result:\n%s", out)
	}
	var result struct {
		Hooks              []string       `json:"hooks"`
		BeforeOptions      map[string]any `json:"beforeOptions"`
		Deny               map[string]any `json:"deny"`
		Allow              any            `json:"allow"`
		Malformed          any            `json:"malformed"`
		Nonzero            any            `json:"nonzero"`
		HugeStdout         any            `json:"hugeStdout"`
		SplitUTF8          map[string]any `json:"splitUtf8"`
		Timeout            any            `json:"timeout"`
		Circular           any            `json:"circular"`
		HugeInput          any            `json:"hugeInput"`
		Missing            any            `json:"missing"`
		Observe            any            `json:"observe"`
		MalformedCallbacks bool           `json:"malformedCallbacks"`
		CaptureCount       int            `json:"captureCount"`
	}
	if err := json.Unmarshal([]byte(resultLine), &result); err != nil {
		t.Fatalf("decode OpenClaw Node harness result: %v\n%s", err, out)
	}

	wantHooks := []string{
		"after_tool_call", "before_tool_call", "llm_input", "llm_output",
		"message_received", "message_sent",
		"session_end", "session_start", "subagent_ended", "subagent_spawned",
	}
	if !slices.Equal(result.Hooks, wantHooks) {
		t.Fatalf("registered hooks = %q, want %q", result.Hooks, wantHooks)
	}
	if result.BeforeOptions["priority"] != float64(50) || result.BeforeOptions["timeoutMs"] != float64(10000) {
		t.Fatalf("before_tool_call options = %#v", result.BeforeOptions)
	}
	if result.Deny["block"] != true || result.Deny["blockReason"] != "test policy denied" {
		t.Fatalf("deny decision = %#v", result.Deny)
	}
	if result.SplitUTF8["block"] != true || result.SplitUTF8["blockReason"] != "blocked 🦊 policy" {
		t.Fatalf("split UTF-8 deny decision = %#v", result.SplitUTF8)
	}
	for name, got := range map[string]any{
		"allow": result.Allow, "malformed": result.Malformed, "nonzero": result.Nonzero,
		"oversized stdout": result.HugeStdout, "timeout": result.Timeout,
		"circular input": result.Circular, "oversized input": result.HugeInput,
		"missing child": result.Missing, "observation mode": result.Observe,
	} {
		if got != nil {
			t.Errorf("%s decision = %#v, want no block", name, got)
		}
	}
	if !result.MalformedCallbacks {
		t.Error("one or more malformed callback invocations did not settle fail-open")
	}
	if result.CaptureCount != 27 {
		t.Errorf("captured child calls = %d, want 27", result.CaptureCount)
	}

	for _, lifecycle := range []string{
		"session-start", "prompt-submit", "pre-tool", "post-tool", "assistant", "session-end",
	} {
		if !strings.Contains(string(out), "OBSERVATION_STDERR:"+lifecycle) {
			t.Errorf("inherited child stderr missing for %s:\n%s", lifecycle, out)
		}
	}
	if strings.Contains(string(out), "OBSERVATION_STDOUT:") {
		t.Fatalf("observation child stdout should be ignored:\n%s", out)
	}

	records := readOpenClawRuntimeCalls(t, capturePath)
	if len(records) != 27 {
		t.Fatalf("captured records = %d, want 27: %#v", len(records), records)
	}
	deny := findOpenClawRuntimeCall(t, records, "deny")
	if deny.Payload["timestamp"] != float64(1_710_000_000_123) ||
		deny.Payload["session_id"] != "event-session-key" ||
		deny.Payload["run_id"] != "event-run" ||
		deny.Payload["agent_id"] != "main" ||
		deny.Payload["tool_name"] != "exec" ||
		deny.Payload["tool_call_id"] != "call-1" ||
		deny.Payload["cwd"] != "/srv/worktree" {
		t.Errorf("deny payload mapping = %#v", deny.Payload)
	}
	if !slices.Equal(deny.Args, []string{
		"hook", "pre-tool", "--agent", "openclaw", numbatHookMarker, "--output=stdout", "--enforce",
	}) {
		t.Errorf("deny child args = %q", deny.Args)
	}
	allow := findOpenClawRuntimeCall(t, records, "allow")
	if allow.Payload["session_id"] != "context-session-key" || allow.Payload["cwd"] != "/explicit/cwd" {
		t.Errorf("context/cwd fallback mapping = %#v", allow.Payload)
	}
	for _, mode := range []string{"circular", "oversized-input", "missing"} {
		if hasOpenClawRuntimeCall(records, mode) {
			t.Errorf("unexpected child invocation for %s input", mode)
		}
	}

	var modelInput, modelOutput, postTool, fractionalExit *openClawRuntimeCall
	for i := range records {
		call := &records[i]
		if len(call.Args) < 2 {
			continue
		}
		input, _ := call.Payload["tool_input"].(map[string]any)
		switch {
		case call.Args[1] == "prompt-submit" && call.Payload["prompt"] == "model prompt":
			modelInput = call
		case call.Args[1] == "assistant" && call.Payload["assistant_text"] != nil:
			modelOutput = call
		case call.Args[1] == "post-tool" && input["command"] == "true":
			postTool = call
		case call.Args[1] == "post-tool" && input["command"] == "fractional-exit":
			fractionalExit = call
		}
	}
	if modelInput == nil || modelOutput == nil || postTool == nil || fractionalExit == nil {
		t.Fatalf("missing mapped runtime calls: input=%v output=%v post=%v fractional=%v", modelInput, modelOutput, postTool, fractionalExit)
	}
	if got, want := openClawRuntimePayloadKeys(modelInput.Payload), []string{
		"agent_id", "boundary", "cwd", "model", "model_provider", "prompt", "run_id", "session_id", "timestamp",
	}; !slices.Equal(got, want) {
		t.Errorf("llm_input payload keys = %q, want %q", got, want)
	}
	if modelInput.Payload["session_id"] != "canonical-model-session" ||
		modelInput.Payload["run_id"] != "model-run" || modelInput.Payload["agent_id"] != "main" ||
		modelInput.Payload["cwd"] != "/srv/model-workspace" || modelInput.Payload["model"] != "gpt-5.6" ||
		modelInput.Payload["model_provider"] != "openai" || modelInput.Payload["boundary"] != "model" {
		t.Errorf("llm_input safe mapping = %#v", modelInput.Payload)
	}
	if observed, ok := modelInput.Payload["timestamp"].(string); !ok || observed == "" {
		t.Errorf("llm_input callback timestamp = %#v", modelInput.Payload["timestamp"])
	}
	if got, want := openClawRuntimePayloadKeys(modelOutput.Payload), []string{
		"agent_id", "assistant_text", "boundary", "cwd", "model", "model_provider", "run_id", "session_id", "timestamp",
	}; !slices.Equal(got, want) {
		t.Errorf("llm_output payload keys = %q, want %q", got, want)
	}
	if modelOutput.Payload["assistant_text"] != "first\nsecond" ||
		modelOutput.Payload["session_id"] != "canonical-model-session" ||
		modelOutput.Payload["boundary"] != "model" {
		t.Errorf("llm_output safe mapping = %#v", modelOutput.Payload)
	}
	if postTool.Payload["exit_code"] != float64(7) {
		t.Errorf("after_tool_call exit_code = %#v", postTool.Payload)
	}
	if response, ok := postTool.Payload["tool_response"].(map[string]any); !ok || response["result"] == nil {
		t.Errorf("after_tool_call dropped result: %#v", postTool.Payload)
	}
	if _, exists := fractionalExit.Payload["exit_code"]; exists {
		t.Errorf("fractional result exit code should be omitted: %#v", fractionalExit.Payload)
	}
	capturedJSON, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"must-not-cross-the-wrapper", "must-not-forward-output-prompt", "private/ref", "private-harness",
	} {
		if strings.Contains(string(capturedJSON), secret) {
			t.Errorf("generated wrapper leaked private field value %q", secret)
		}
	}
}

type openClawRuntimeCall struct {
	Args    []string       `json:"args"`
	Payload map[string]any `json:"payload"`
}

func readOpenClawRuntimeCalls(t *testing.T, path string) []openClawRuntimeCall {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var calls []openClawRuntimeCall
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		var call openClawRuntimeCall
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			t.Fatalf("decode captured OpenClaw call: %v", err)
		}
		calls = append(calls, call)
	}
	return calls
}

func findOpenClawRuntimeCall(t *testing.T, calls []openClawRuntimeCall, mode string) openClawRuntimeCall {
	t.Helper()
	for _, call := range calls {
		input, _ := call.Payload["tool_input"].(map[string]any)
		if input["mode"] == mode {
			return call
		}
	}
	t.Fatalf("no captured OpenClaw call for mode %q", mode)
	return openClawRuntimeCall{}
}

func hasOpenClawRuntimeCall(calls []openClawRuntimeCall, mode string) bool {
	for _, call := range calls {
		input, _ := call.Payload["tool_input"].(map[string]any)
		if input["mode"] == mode {
			return true
		}
	}
	return false
}

func openClawRuntimePayloadKeys(payload map[string]any) []string {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func writeOpenClawRuntimeTestFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

const openClawRuntimeHarness = `
import fs from "node:fs";
import { pathToFileURL } from "node:url";

async function loadPlugin(path) {
  return (await import(pathToFileURL(path).href)).default;
}

function register(plugin) {
  const hooks = new Map();
  plugin.register({
    on(name, handler, options) {
      if (hooks.has(name)) throw new Error("duplicate hook " + name);
      hooks.set(name, { handler, options });
    },
  });
  return hooks;
}

async function bounded(value, label) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve(value),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + " did not settle")), 3000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function nullable(value) {
  return value === undefined ? null : value;
}

function capturedCalls() {
  let text = "";
  try { text = fs.readFileSync(capturePath, "utf8"); } catch (_) {}
  return text.split("\n").filter(Boolean).length;
}

async function waitForCaptures(expected, label) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const count = capturedCalls();
    if (count >= expected) return count;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(label + " captured " + capturedCalls() + " child calls, want " + expected);
}

const [pluginPath, observePluginPath, missingPluginPath, capturePath] = process.argv.slice(2);
const hooks = register(await loadPlugin(pluginPath));
const expectedHooks = [
  "after_tool_call", "before_tool_call", "llm_input", "llm_output",
  "message_received", "message_sent",
  "session_end", "session_start", "subagent_ended", "subagent_spawned",
];
const hookNames = [...hooks.keys()].sort();
if (JSON.stringify(hookNames) !== JSON.stringify(expectedHooks)) {
  throw new Error("unexpected hook registration: " + JSON.stringify(hookNames));
}

const before = hooks.get("before_tool_call").handler;
const deny = await bounded(before({
  timestamp: 1710000000123,
  sessionKey: "event-session-key",
  sessionId: "ignored-event-session-id",
  runId: "event-run",
  toolName: "exec",
  toolCallId: "call-1",
  params: { mode: "deny", command: "rm -rf /", workdir: "/srv/worktree" },
}, {
  sessionKey: "ignored-context-session-key",
  runId: "ignored-context-run",
  agentId: "main",
}), "deny");
const allow = await bounded(before({
  timestamp: "2026-07-23T10:00:00Z",
  toolName: "read",
  params: { mode: "allow", path: "README.md", cwd: "/explicit/cwd", workdir: "/ignored" },
}, { sessionKey: "context-session-key", agentId: "main" }), "allow");
const malformed = await bounded(before({ toolName: "exec", params: { mode: "malformed" } }, {}), "malformed");
const nonzero = await bounded(before({ toolName: "exec", params: { mode: "nonzero" } }, {}), "nonzero");
const hugeStdout = await bounded(before({ toolName: "exec", params: { mode: "oversized-stdout" } }, {}), "huge stdout");
const splitUtf8 = await bounded(before({ toolName: "exec", params: { mode: "split-utf8-deny" } }, {}), "split UTF-8");
const timeout = await bounded(before({ toolName: "exec", params: { mode: "timeout" } }, {}), "timeout");

const circularParams = { mode: "circular" };
circularParams.self = circularParams;
const circular = await bounded(before({ toolName: "exec", params: circularParams }, {}), "circular input");
const hugeInput = await bounded(before({
  toolName: "exec", params: { mode: "oversized-input", data: "x".repeat(4 * 1024 * 1024 + 1) },
}, {}), "huge input");
let expectedCaptures = 7;
await waitForCaptures(expectedCaptures, "enforcement cases");

const privateCycle = { secret: "must-not-cross-the-wrapper" };
privateCycle.self = privateCycle;

hooks.get("session_start").handler({
  timestamp: 1710000000, sessionKey: "parent", resumedFrom: "prior",
}, { agentId: "main" });
await waitForCaptures(++expectedCaptures, "session_start");
hooks.get("message_received").handler({
  timestamp: "2026-07-23T10:00:01Z", sessionKey: "parent", content: "hello", messageId: "m1",
}, { channelId: "test", agentId: "main" });
await waitForCaptures(++expectedCaptures, "message_received");
hooks.get("after_tool_call").handler({
  timestamp: 1710000000124, sessionKey: "parent", toolName: "exec",
  params: { command: "true" }, durationMs: 12,
  result: { details: { exitCode: 7 }, content: [{ type: "text", text: "RESULT_CANARY" }] },
}, { agentId: "main" });
await waitForCaptures(++expectedCaptures, "after_tool_call");
hooks.get("after_tool_call").handler({
  timestamp: 1710000000124, sessionKey: "parent", toolName: "exec",
  params: { command: "fractional-exit" }, result: { details: { exitCode: 1.5 } },
}, { agentId: "main" });
await waitForCaptures(++expectedCaptures, "fractional after_tool_call");
hooks.get("llm_input").handler({
  runId: "model-run", sessionKey: "ignored-event-session-key", sessionId: "ephemeral-model-session",
  provider: "openai", model: "gpt-5.6", prompt: "model prompt",
  systemPrompt: privateCycle, historyMessages: [privateCycle], tools: [privateCycle],
  imagesCount: 3,
}, {
  sessionKey: "canonical-model-session", runId: "ignored-context-run", agentId: "main",
  workspaceDir: "/srv/model-workspace", modelProviderId: "ignored-provider", modelId: "ignored-model",
});
await waitForCaptures(++expectedCaptures, "llm_input");
hooks.get("llm_output").handler({
  runId: "model-run", sessionId: "ephemeral-model-session",
  provider: "openai", model: "gpt-5.6", assistantTexts: ["first", "   ", "second"],
  prompt: "must-not-forward-output-prompt", lastAssistant: privateCycle, usage: privateCycle,
  reasoningEffort: "high", resolvedRef: "private/ref", harnessId: "private-harness",
}, { sessionKey: "canonical-model-session", agentId: "main", workspaceDir: "/srv/model-workspace" });
await waitForCaptures(++expectedCaptures, "llm_output");
hooks.get("llm_output").handler({ assistantTexts: ["", "   ", 7] }, {});
hooks.get("llm_input").handler({ prompt: "x".repeat(4 * 1024 * 1024 + 1) }, {});
hooks.get("llm_output").handler({ assistantTexts: ["x".repeat(4 * 1024 * 1024 + 1)] }, {});
hooks.get("message_sent").handler({
  timestamp: 1710000000125, sessionKey: "parent", messageId: "m2", success: true,
}, { channelId: "test", agentId: "main" });
await waitForCaptures(++expectedCaptures, "message_sent");
hooks.get("session_end").handler({
  timestamp: 1710000000126, sessionKey: "parent", durationMs: 20, messageCount: 2, reason: "done",
}, { agentId: "main" });
await waitForCaptures(++expectedCaptures, "session_end");
hooks.get("subagent_spawned").handler({
  childSessionKey: "child", runId: "child-run", label: "reviewer", agentId: "reviewer",
  resolvedModel: "model", resolvedProvider: "provider",
}, { requesterSessionKey: "parent" });
await waitForCaptures(++expectedCaptures, "subagent_spawned");
hooks.get("subagent_ended").handler({
  endedAt: 1710000000127, targetSessionKey: "child", runId: "child-run",
  targetKind: "reviewer", reason: "done", outcome: "ok",
}, {});
await waitForCaptures(++expectedCaptures, "subagent_ended");

const observeHooks = register(await loadPlugin(observePluginPath));
const observe = await bounded(observeHooks.get("before_tool_call").handler({
  timestamp: 1710000000128, sessionKey: "parent", toolName: "exec",
  params: { mode: "observe", command: "pwd" },
}, { agentId: "main" }), "observation mode");
await waitForCaptures(++expectedCaptures, "observation mode");

const missingHooks = register(await loadPlugin(missingPluginPath));
const missing = await bounded(missingHooks.get("before_tool_call").handler({
  timestamp: 1710000000129, sessionKey: "parent", toolName: "exec",
  params: { mode: "missing", command: "pwd" },
}, { agentId: "main" }), "missing child");

let malformedCallbacks = true;
for (const [name, entry] of hooks) {
  const rejected = await bounded(entry.handler(null, "not-an-object"), "malformed event " + name);
  const normalized = await bounded(entry.handler({}, null), "malformed context " + name);
  if (rejected !== undefined || normalized !== undefined) malformedCallbacks = false;
  if (name !== "llm_output") {
    await waitForCaptures(++expectedCaptures, "malformed context " + name);
  }
}

if (expectedCaptures !== 27) throw new Error("runtime harness expected " + expectedCaptures + " captures");
const captureCount = await waitForCaptures(expectedCaptures, "all callbacks");

console.log("HARNESS_RESULT=" + JSON.stringify({
  hooks: hookNames,
  beforeOptions: hooks.get("before_tool_call").options,
  deny: nullable(deny),
  allow: nullable(allow),
  malformed: nullable(malformed),
  nonzero: nullable(nonzero),
  hugeStdout: nullable(hugeStdout),
  splitUtf8: nullable(splitUtf8),
  timeout: nullable(timeout),
  circular: nullable(circular),
  hugeInput: nullable(hugeInput),
  missing: nullable(missing),
  observe: nullable(observe),
  malformedCallbacks,
  captureCount,
}));
`
