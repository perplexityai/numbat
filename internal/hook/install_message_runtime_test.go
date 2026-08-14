package hook

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedMessagePluginsFinalizeParts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}

	tests := []struct {
		name        string
		source      func([]string) string
		instantiate string
	}{
		{
			name:        "opencode",
			source:      func(args []string) string { return openCodePluginSourceWithArgs("numbat", args) },
			instantiate: `const plugin = await NumbatPlugin({ directory: "/workspace" });`,
		},
		{
			name: "kilo",
			source: func(args []string) string {
				src := kiloPluginSourceWithArgs("numbat", args, false)
				src = strings.Replace(src, `import type { Plugin } from "@kilocode/plugin";`+"\n", "", 1)
				return strings.Replace(src, "const server: Plugin =", "const server =", 1)
			},
			instantiate: `const plugin = await server({ directory: "/workspace" });`,
		},
	}
	for _, tt := range tests {
		for _, includeReasoning := range []bool{false, true} {
			name := "preview"
			var args []string
			if includeReasoning {
				name = "reasoning"
				args = []string{"--include-reasoning"}
			}
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				source := tt.source(args) + messagePluginRuntimeHarness(tt.instantiate)
				path := filepath.Join(t.TempDir(), "plugin.mjs")
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command(node, path).CombinedOutput()
				if err != nil {
					t.Fatalf("Node harness: %v\n%s", err, out)
				}
				const marker = "NUMBAT_RESULT="
				line := strings.TrimSpace(string(out))
				if !strings.HasPrefix(line, marker) {
					t.Fatalf("Node harness result = %q", out)
				}
				var calls []struct {
					Lifecycle string `json:"lifecycle"`
					Payload   struct {
						Prompt       string  `json:"prompt"`
						Timestamp    float64 `json:"timestamp"`
						MessageParts []struct {
							Type string `json:"type"`
							Text string `json:"text"`
						} `json:"message_parts"`
					} `json:"payload"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &calls); err != nil {
					t.Fatal(err)
				}
				if len(calls) != 2 || calls[0].Lifecycle != "prompt-submit" || calls[0].Payload.Prompt != "keep" ||
					calls[1].Lifecycle != "assistant" || calls[1].Payload.Timestamp != 3 {
					t.Fatalf("calls = %+v", calls)
				}
				want := []string{"text:second", "text:third"}
				if includeReasoning {
					want = []string{"reasoning:first", "text:second", "text:third"}
				}
				got := make([]string, len(calls[1].Payload.MessageParts))
				for i, part := range calls[1].Payload.MessageParts {
					got[i] = part.Type + ":" + part.Text
				}
				if strings.Join(got, "|") != strings.Join(want, "|") {
					t.Fatalf("message parts = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestGeneratedPiMessagePluginRuntime(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	for _, includeReasoning := range []bool{false, true} {
		name := "preview"
		var args []string
		if includeReasoning {
			name = "reasoning"
			args = []string{"--include-reasoning"}
		}
		t.Run(name, func(t *testing.T) {
			source := piPluginSourceWithArgs("numbat", args, false)
			source = strings.Replace(source, "export default function (pi)", "function install(pi)", 1)
			path := filepath.Join(t.TempDir(), "plugin.mjs")
			if err := os.WriteFile(path, []byte(source+piMessagePluginRuntimeHarness), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(node, path).CombinedOutput()
			if err != nil {
				t.Fatalf("Node harness: %v\n%s", err, out)
			}
			const marker = "NUMBAT_RESULT="
			line := strings.TrimSpace(string(out))
			var calls []struct {
				Lifecycle string `json:"lifecycle"`
				Payload   struct {
					Model         string  `json:"model"`
					ModelProvider string  `json:"model_provider"`
					Timestamp     float64 `json:"timestamp"`
					MessageParts  []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"message_parts"`
				} `json:"payload"`
			}
			if !strings.HasPrefix(line, marker) ||
				json.Unmarshal([]byte(strings.TrimPrefix(line, marker)), &calls) != nil {
				t.Fatalf("Node harness result = %q", out)
			}
			if len(calls) != 1 || calls[0].Lifecycle != "assistant" ||
				calls[0].Payload.Model != "concrete-model" ||
				calls[0].Payload.ModelProvider != "provider" ||
				calls[0].Payload.Timestamp != 1_710_000_000_123 {
				t.Fatalf("calls = %+v", calls)
			}
			got := make([]string, len(calls[0].Payload.MessageParts))
			for i, part := range calls[0].Payload.MessageParts {
				got[i] = part.Type + ":" + part.Text
			}
			want := []string{"text:final"}
			if includeReasoning {
				want = []string{"reasoning:visible", "text:final"}
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("message parts = %v, want %v", got, want)
			}
		})
	}
}

func messagePluginRuntimeHarness(instantiate string) string {
	return `
const captured = [];
forward = (lifecycle, payload) => captured.push({ lifecycle, payload });
` + instantiate + `

await plugin["chat.message"](
  { sessionID: "s1", agent: "main", model: { modelID: "m", providerID: "p" } },
  { parts: [
    { type: "text", text: "keep" },
    { type: "text", text: "drop-ignored", ignored: true },
    { type: "text", text: "drop-synthetic", synthetic: true },
  ] },
);

const emit = (event) => plugin.event({ event });
const message = {
  id: "m1", sessionID: "s1", role: "assistant", time: { created: 1 },
  path: { cwd: "/workspace" }, agent: "main", modelID: "model", providerID: "provider",
};
await emit({ type: "message.updated", properties: { info: message } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-02", messageID: "m1", type: "text", text: "second", time: { end: 2 },
} } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-01", messageID: "m1", type: "reasoning", text: "first", time: { end: 2 },
} } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-00", messageID: "m1", type: "text", text: "removed", time: { end: 2 },
} } });
await emit({ type: "message.part.removed", properties: {
  messageID: "m1", partID: "part-00",
} });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-03", messageID: "m1", type: "text", text: "drop-ignored",
  ignored: true, time: { end: 2 },
} } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-04", messageID: "m1", type: "text", text: "partial", time: { start: 1 },
} } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-04", messageID: "m1", type: "text", text: "third", time: { start: 1, end: 2 },
} } });
await emit({ type: "message.updated", properties: { info: {
  ...message, time: { created: 1, completed: 3 },
} } });
await emit({ type: "message.updated", properties: { info: {
  ...message, time: { created: 1, completed: 3 },
} } });

const summary = { ...message, id: "summary", summary: true };
await emit({ type: "message.updated", properties: { info: summary } });
await emit({ type: "message.part.updated", properties: { part: {
  id: "part-summary", messageID: "summary", type: "text", text: "summary", time: { end: 2 },
} } });
await emit({ type: "message.updated", properties: { info: {
  ...summary, time: { created: 1, completed: 3 },
} } });

process.stdout.write("NUMBAT_RESULT=" + JSON.stringify(captured));
`
}

const piMessagePluginRuntimeHarness = `
const captured = [];
forward = (lifecycle, payload) => captured.push({ lifecycle, payload });
const handlers = new Map();
install({ on(name, handler) { handlers.set(name, handler); } });
await handlers.get("message_end")({
  message: {
    role: "assistant",
    provider: "provider",
    model: "selected-model",
    responseModel: "concrete-model",
    timestamp: 1710000000123,
    content: [
      { type: "thinking", thinking: "visible" },
      { type: "thinking", thinking: "opaque-signature", redacted: true },
      { type: "text", text: "final" },
    ],
  },
}, {
  cwd: "/workspace",
  model: { id: "context-model", provider: "context-provider" },
  sessionManager: { getSessionId() { return "s1"; } },
});
process.stdout.write("NUMBAT_RESULT=" + JSON.stringify(captured));
`
