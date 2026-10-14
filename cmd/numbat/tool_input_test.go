package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
)

// Exercise the complete artifact, hook, and OTLP emission paths with the same
// input. These tests use only temporary files and never install agent hooks.
func TestToolInputPreviewAcrossCaptureSurfaces(t *testing.T) {
	for _, tc := range []struct{ name, tool, server, method, input, want string }{
		{
			"CUA", "mcp__cua_repl__js", "cua_repl", "js",
			`{"code":"await tab.goto(url);","password":"private-canary","title":"Inspect browser"}`,
			`{"code":"await tab.goto(url);","password":"[redacted]","title":"Inspect browser"}`,
		},
		{
			"MCP", "mcp__database__query", "database", "query",
			`{"query":"SELECT 1","password":"private-canary"}`,
			`{"password":"[redacted]","query":"SELECT 1"}`,
		},
	} {
		for _, mode := range []string{"preview", "full"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				input, want, tool := tc.input, tc.want, tc.tool
				assertEvent := func(t *testing.T, stream, source string) {
					t.Helper()
					if strings.Contains(stream, "private-canary") {
						t.Fatal("emitted an argument credential")
					}
					count := 0
					for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
						var ev model.Event
						if err := json.Unmarshal([]byte(line), &ev); err != nil {
							t.Fatal(err)
						}
						if ev.EventType != model.EventToolCall {
							continue
						}
						count++
						if ev.ContentPreview != want || ev.SourceType != source || ev.MCPServer != tc.server || ev.MCPTool != tc.method || ev.URL != "" || ev.Content != "" {
							t.Fatalf("event = %+v", ev)
						}
						if err := ev.Validate(); err != nil {
							t.Fatal(err)
						}
					}
					if count != 1 {
						t.Fatalf("got %d tool calls: %s", count, stream)
					}
				}
				for _, agent := range []string{"claude", "codex"} {
					t.Run(agent+"/hook", func(t *testing.T) {
						var control, records bytes.Buffer
						code := runHookEvent("PreToolUse", []string{"--agent", agent, "--emit", "events", "--content", mode, "--state-db", filepath.Join(t.TempDir(), "state.db")},
							strings.NewReader(`{"session_id":"s1","tool_name":"`+tool+`","tool_use_id":"c1","tool_input":`+input+`}`), &control, &records)
						if code != 0 || strings.TrimSpace(control.String()) != "{}" {
							t.Fatalf("hook exit=%d control=%s records=%s", code, control.String(), records.String())
						}
						assertEvent(t, records.String(), model.SourceHook)
					})
					t.Run(agent+"/scan", func(t *testing.T) {
						path := filepath.Join(t.TempDir(), ".codex", "sessions", "rollout.jsonl")
						body := `{"type":"response_item","payload":{"type":"function_call","name":"` + tc.method + `","namespace":"mcp__` + tc.server + `","call_id":"c1","arguments":` + input + `}}`
						if agent == "claude" {
							path = filepath.Join(t.TempDir(), ".claude", "projects", "test", "session.jsonl")
							body = `{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"tool_use","id":"c1","name":"` + tool + `","input":` + input + `}]}}`
						}
						if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						out, diag, code := runCLI("scan", "--path", path, "--emit", "events", "--content", mode)
						if code != 0 {
							t.Fatalf("scan exit=%d: %s", code, diag)
						}
						assertEvent(t, out, model.SourceArtifact)
						out, diag, code = runCLI("timeline", "--path", path, "--format", "json", "--content", mode)
						if code != 0 || strings.Contains(out, "private-canary") {
							t.Fatalf("timeline exit=%d output=%s diag=%s", code, out, diag)
						}
						var report timelineReport
						if err := json.Unmarshal([]byte(out), &report); err != nil {
							t.Fatal(err)
						}
						var events bytes.Buffer
						for _, session := range report.Sessions {
							for _, ev := range session.Events {
								if err := json.NewEncoder(&events).Encode(ev); err != nil {
									t.Fatal(err)
								}
							}
						}
						assertEvent(t, events.String(), model.SourceArtifact)
					})
				}
				t.Run("OTLP receiver", func(t *testing.T) {
					var records, diags bytes.Buffer
					projection, err := parseContentMode(mode)
					if err != nil {
						t.Fatal(err)
					}
					em := output.New(&records, &diags, "run-test", contentEmitterOptions(projection)...)
					c, err := newCollector(collectorConfig{emit: em, runID: "run-test", sel: emitSelection{events: true}})
					if err != nil {
						t.Fatal(err)
					}
					body := buildOTLPLogs("codex", []map[string]string{{
						"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool,
						"gen_ai.tool.call.id": "c1", "gen_ai.tool.call.arguments": input,
					}})
					if rr := postLogs(t, c, body, "application/x-protobuf"); rr.Code != http.StatusOK {
						t.Fatalf("status=%d: %s", rr.Code, rr.Body.String())
					}
					assertEvent(t, records.String(), model.SourceOTel)
				})
			})
		}
	}
}
