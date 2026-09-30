package hook

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// Exercise every supported hook agent using its existing argument envelope.
func TestGenericHookInputPreviews(t *testing.T) {
	const encoded = `{"url":"https://example.com/","query":"browser docs","password":"private"}`
	const want = `{"password":"[redacted]","query":"browser docs","url":"https://example.com/"}`
	for _, form := range []struct {
		name string
		args any
	}{
		{"object", map[string]any{"url": "https://example.com/", "query": "browser docs", "password": "private"}},
		{"serialized", encoded},
	} {
		t.Run(form.name, func(t *testing.T) {
			args := form.args
			type testCase struct {
				name, agent string
				lc          Lifecycle
				payload     map[string]any
			}
			cases := []testCase{
				{"codex", AgentCodex, LifecycleCodexPreTool, map[string]any{"tool_name": "mcp__notes__save", "tool_input": args}},
				{"codex other fetch tool", AgentCodex, LifecycleCodexPreTool, map[string]any{"tool_name": "mcp__fetch__status", "tool_input": args}},
				{"codex MCP case differs", AgentCodex, LifecycleCodexPreTool, map[string]any{"tool_name": "mcp__Fetch__fetch", "tool_input": args}},
				{"claude", AgentClaude, LifecyclePreTool, map[string]any{"tool_name": "mcp__notes__save", "tool_input": args}},
				{"cursor generic", AgentCursor, LifecycleCursorPreTool, map[string]any{"tool_name": "MCP:save", "tool_input": args}},
				{"cursor direct", AgentCursor, LifecycleMCPCall, map[string]any{"tool_name": "save", "mcp_server_name": "notes", "tool_input": args}},
				{"opencode", AgentOpenCode, LifecycleOpenCodePreTool, map[string]any{"tool": "plugin", "args": args, "tool_input": map[string]any{"wrong": "field"}}},
				{"windsurf", AgentWindsurf, LifecycleMCPCall, map[string]any{"agent_action_name": "pre_mcp_tool_use", "tool_info": map[string]any{"mcp_server_name": "notes", "mcp_tool_name": "save", "mcp_tool_arguments": args}}},
				{"gemini", AgentGemini, LifecycleGeminiPreTool, map[string]any{"tool_name": "plugin", "tool_input": args, "parameters": map[string]any{"wrong": "field"}}},
				{"cline", AgentCline, LifecyclePreTool, map[string]any{"preToolUse": map[string]any{"toolName": "plugin", "parameters": args}}},
				{"copilot", AgentCopilot, LifecycleCopilotPreTool, map[string]any{"toolName": "plugin", "toolArgs": args}},
				{"vscode", AgentVSCode, LifecycleVSCodePreTool, map[string]any{"tool_name": "plugin", "tool_input": args}},
				{"antigravity", AgentAntigravity, LifecycleAntigravityPreTool, map[string]any{"toolCall": map[string]any{"name": "plugin", "args": args}}},
				{"factory", AgentFactory, LifecycleFactoryPreTool, map[string]any{"tool_name": "plugin", "tool_input": args}},
				{"grok", AgentGrok, LifecycleGrokPreTool, map[string]any{"toolName": "plugin", "toolInput": args}},
				{"devin", AgentDevin, LifecycleDevinPreTool, map[string]any{"tool_name": "plugin", "tool_input": args}},
				{"hermes", AgentHermes, LifecycleHermesPreTool, map[string]any{"tool_name": "plugin", "tool_input": args}},
				{"pi", AgentPi, LifecyclePreTool, map[string]any{"toolName": "plugin", "input": args}},
				{"kilo", AgentKilo, LifecyclePreTool, map[string]any{"tool_name": "plugin", "tool_input": args}},
			}
			for _, agent := range []string{AgentOpenClaw, AgentKimi, AgentQwen, AgentAmp, AgentAuggie, AgentKiro, AgentGoose, AgentOpenHands, AgentCrush, AgentJunie} {
				cases = append(cases, testCase{agent, agent, LifecyclePreTool, map[string]any{"tool_name": "plugin", "tool_input": args}})
			}
			covered := make(map[string]bool)
			for _, tc := range cases {
				covered[tc.agent] = true
				t.Run(tc.name, func(t *testing.T) {
					source, err := ParseAgent(tc.agent)
					if err != nil {
						t.Fatal(err)
					}
					ev := Map(tc.lc, tc.agent, source, "evt", tc.payload)
					if ev.EventType != model.EventToolCall || ev.ContentPreview != want || ev.URL != "" || hasTag(ev.Tags, model.TagNetwork) {
						t.Fatalf("event = %+v", ev)
					}
					if err := ev.Validate(); err != nil {
						t.Fatal(err)
					}
				})
			}
			for _, agent := range AgentNames() {
				if !covered[agent] {
					t.Errorf("missing generic input fixture for %s", agent)
				}
			}
		})
	}
}

func TestCodexHookCUAPreview(t *testing.T) {
	payload := map[string]any{
		"tool_name": "mcp__cua_repl__js", "tool_use_id": "cua1",
		"tool_input":    map[string]any{"code": `await tab.goto(url);`, "title": "Navigate browser test"},
		"tool_response": map[string]any{"content": "page body must not be captured"},
	}
	call := Map(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "pre", payload)
	if call.EventType != model.EventToolCall || call.URL != "" || !strings.Contains(call.ContentPreview, "await tab.goto(url)") {
		t.Fatalf("call = %+v", call)
	}
	result := Map(LifecycleCodexPostTool, AgentCodex, model.AgentCodex, "post", payload)
	if result.EventType != model.EventToolResult || result.ContentPreview != "" || result.MCPServer != "cua_repl" || result.MCPTool != "js" || result.ToolCallID != "cua1" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDirectMCPHookTransportAndTarget(t *testing.T) {
	for _, tc := range []struct {
		name, event, server, tool, endpoint, inputURL string
		want                                          model.EventType
		wantURL                                       string
	}{
		{"URL reference", "beforeMCPExecution", "notes", "save", "", "https://reference.example/", model.EventToolCall, ""},
		{"server endpoint", "beforeMCPExecution", "notes", "save", "https://mcp.example/", "https://reference.example/", model.EventNetworkIndicator, "https://mcp.example/"},
		{"fetch target", "beforeMCPExecution", "fetch", "fetch", "https://mcp.example/", "https://target.example/", model.EventNetworkIndicator, "https://target.example/"},
		{"post with endpoint", "afterMCPExecution", "fetch", "fetch", "https://mcp.example/", "https://target.example/", model.EventToolResult, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := Map(LifecycleMCPCall, AgentCursor, model.AgentCursor, "evt", map[string]any{
				"hook_event_name": tc.event, "mcp_server_name": tc.server, "tool_name": tc.tool,
				"mcp_server_url": tc.endpoint, "tool_input": map[string]any{"url": tc.inputURL, "password": "private"},
			})
			if ev.EventType != tc.want || ev.URL != tc.wantURL || ev.ToolName != tc.tool || ev.MCPServer != tc.server || ev.MCPTool != tc.tool {
				t.Fatalf("event = %+v", ev)
			}
			if strings.Contains(ev.ContentPreview, "private") || tc.want == model.EventToolResult && ev.ContentPreview != "" {
				t.Fatalf("unexpected preview: %q", ev.ContentPreview)
			}
			if err := ev.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBrowserHookActions(t *testing.T) {
	for _, tc := range []struct {
		agent, tool, action, url string
		network                  bool
	}{
		{AgentCline, "browser_action", "launch", "https://example.com/", true},
		{AgentCline, "browser_action", "launch", "", false},
		{AgentCline, "browser_action", "click", "https://reference.example/", false},
		{AgentCline, "browser_action", "type", "", false},
		{AgentCline, "browser_action", "scroll_down", "", false},
		{AgentCline, "browser_action", "close", "", false},
		{AgentOpenClaw, "browser", "navigate", "https://example.com/", true},
		{AgentOpenClaw, "browser", "open", "https://example.com/", true},
		{AgentOpenClaw, "browser", "open", "file:///tmp/page.html", false},
		{AgentOpenClaw, "browser", "screenshot", "https://reference.example/", false},
		{AgentOpenClaw, "browser", "tabs", "", false},
		{AgentOpenClaw, "browser", "upload", "", false},
		{AgentOpenClaw, "browser", "act", "", false},
		{AgentOpenClaw, "browser", "", "https://example.com/", false},
	} {
		t.Run(tc.agent+"/"+tc.action+"/"+tc.url, func(t *testing.T) {
			input := map[string]any{"action": tc.action, "url": tc.url}
			ev := Map(LifecyclePreTool, tc.agent, model.AgentUnknown, "evt", map[string]any{"tool_name": tc.tool, "tool_input": input})
			want := model.EventToolCall
			if tc.network {
				want = model.EventNetworkIndicator
			}
			if ev.EventType != want || hasTag(ev.Tags, model.TagNetwork) != tc.network || !hasTag(ev.Tags, "browser") || !strings.Contains(ev.ContentPreview, `"action":`) {
				t.Fatalf("event = %+v", ev)
			}
			if !tc.network && ev.URL != "" {
				t.Fatalf("local browser action got a network target: %+v", ev)
			}
		})
	}
}

func TestCodexCanonicalMCPFetchHook(t *testing.T) {
	payload := map[string]any{"tool_name": mcpFetchToolName, "tool_input": map[string]any{"url": "https://example.com/"}}
	call := Map(LifecycleCodexPreTool, AgentCodex, model.AgentCodex, "pre", payload)
	if call.EventType != model.EventNetworkIndicator || call.URL != "https://example.com/" || call.MCPServer != "fetch" || call.MCPTool != "fetch" {
		t.Fatalf("call = %+v", call)
	}
	result := Map(LifecycleCodexPostTool, AgentCodex, model.AgentCodex, "post", payload)
	if result.EventType != model.EventToolResult || result.URL != "" || result.MCPServer != "fetch" || result.MCPTool != "fetch" {
		t.Fatalf("result = %+v", result)
	}
}

func TestGeminiGenericPreviewUsesOnlyToolInput(t *testing.T) {
	ev := Map(LifecycleGeminiPreTool, AgentGemini, model.AgentGeminiCLI, "evt", map[string]any{
		"tool_name": "plugin", "parameters": map[string]any{"query": "wrong field"},
	})
	if ev.ContentPreview != "" {
		t.Fatalf("preview used another envelope field: %q", ev.ContentPreview)
	}
}
