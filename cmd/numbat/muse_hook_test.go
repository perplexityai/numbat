package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// Muse 1.4.10 native captures use path for file tools, even with extra aliases.
// See https://meta-models.github.io/muse-code-sdk/next/guides/plugins/reference/hook-events/
// for the enclosing payload. Inputs here exercise the real hook JSON decoder.
func TestMuseFileToolTargets(t *testing.T) {
	for _, tool := range []string{"write_file", "edit_file", "read_file"} {
		for _, tc := range []struct {
			name, input, path, rule string
		}{
			{"memory", `{"path":"/work/.agents/memory/topic.md"}`, "/work/.agents/memory/topic.md", "persistence.agent_memory_write"},
			{"settings", `{"path":"/home/user/.config/muse/settings.json"}`, "/home/user/.config/muse/settings.json", "tamper.agent_config_write"},
			{"project-hooks", `{"path":".muse/hooks.json"}`, ".muse/hooks.json", "tamper.agent_config_write"},
			{"relative-memory", `{"path":".agents/memory/topic.md"}`, ".agents/memory/topic.md", "persistence.agent_memory_write"},
			{"snake-alias", `{"file_path":"README.md","path":".agents/memory/topic.md"}`, ".agents/memory/topic.md", "persistence.agent_memory_write"},
			{"camel-alias", `{"filePath":"README.md","path":".agents/memory/topic.md"}`, ".agents/memory/topic.md", "persistence.agent_memory_write"},
			{"reverse-alias", `{"file_path":".agents/memory/topic.md","path":"README.md"}`, "README.md", ""},
			{"alias-only", `{"file_path":".agents/memory/topic.md"}`, "", ""},
			{"number", `{"path":42}`, "", ""},
			{"boolean", `{"path":true}`, "", ""},
			{"null", `{"path":null}`, "", ""},
			{"encoded-input", `{"path":".agents/memory/topic.md"}`, ".agents/memory/topic.md", "persistence.agent_memory_write"},
		} {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				setTestHome(t, t.TempDir())
				var input map[string]any
				if err := json.Unmarshal([]byte(tc.input), &input); err != nil {
					t.Fatal(err)
				}
				switch tool {
				case "write_file":
					input["content"] = "after"
				case "edit_file":
					input["find"], input["replace"] = "before", "after"
				}
				var wireInput any = input
				if tc.name == "encoded-input" {
					raw, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					wireInput = string(raw)
				}
				payload, err := json.Marshal(map[string]any{
					"hook_event_name": "PreToolUse", "session_id": "sess-1", "cwd": "/work",
					"tool_name": tool, "tool_input": wireInput, "tool_use_id": "call_1",
				})
				if err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(t.TempDir(), "records.ndjson")
				out, stderr, code := runCLIStdin(string(payload), "hook", "pre-tool", "--agent", "muse",
					"--enforce", "--emit", "all", "--output", "file", "--output-file", file)
				if code != 0 || strings.TrimSpace(out) != "{}" || stderr != "" {
					t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, stderr)
				}
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				events := decodeEventRecords(t, string(data))
				wantType, wantRule := model.EventFileWrite, tc.rule
				if tool == "read_file" {
					wantType, wantRule = model.EventFileRead, ""
				}
				if len(events) != 1 || events[0].EventType != wantType || events[0].FilePath != tc.path {
					t.Fatalf("events=%+v, want %s path=%q", events, wantType, tc.path)
				}
				if events[0].ContentPreview != "" || events[0].ToolInput != "" {
					t.Fatal("typed file event exposed a default input preview")
				}
				findings := decodeFindings(t, string(data))
				if wantRule == "" {
					if len(findings) != 0 {
						t.Fatalf("unexpected findings: %+v", findings)
					}
				} else if len(findings) != 1 || findings[0].RuleID != wantRule {
					t.Fatalf("findings=%+v, want %s", findings, wantRule)
				}
			})
		}
	}
}

func TestMuseFileWriteEnforcement(t *testing.T) {
	const fileRule = `id: test.muse_file_write
version: "1.0"
enabled: true
title: Protected test file
description: Test a file write decision.
severity: high
enforce: true
expr: event.event_type == "file.write" && event.file_path == "protected.txt"
`
	for _, tool := range []string{"write_file", "edit_file", "mcp__example__edit_file", "muse.edit_file"} {
		for _, tc := range []struct {
			name, event string
			enforce     bool
		}{
			{"monitor", "PreToolUse", false},
			{"enforce", "PreToolUse", true},
			{"post", "PostToolUse", true},
			{"failure", "PostToolUseFailure", true},
		} {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				setTestHome(t, t.TempDir())
				input := map[string]any{"path": "protected.txt", "file_path": "README.md"}
				if tool == "write_file" {
					input["content"] = "after"
				} else {
					input["find"], input["replace"] = "before", "after"
				}
				payload, err := json.Marshal(map[string]any{
					"hook_event_name": tc.event, "tool_name": tool, "tool_input": input,
				})
				if err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(t.TempDir(), "records.ndjson")
				args := []string{
					"hook", tc.event, "--agent", "muse",
					"--rules-dir", writeEnforceRuleFile(t, fileRule), "--no-builtin-rules",
					"--emit", "all", "--output", "file", "--output-file", file,
				}
				if tc.enforce {
					args = append(args, "--enforce")
				}
				out, stderr, code := runCLIStdin(string(payload), args...)
				nativeWrite := tool == "write_file" || tool == "edit_file"
				wantDeny := nativeWrite && tc.event == "PreToolUse" && tc.enforce
				if code != 0 || (decodeDecision(t, out) == "deny") != wantDeny || stderr != "" {
					t.Fatalf("exit=%d stdout=%q stderr=%q want deny=%v", code, out, stderr, wantDeny)
				}
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				events := decodeEventRecords(t, string(data))
				wantType := model.EventToolResult
				if tc.event == "PreToolUse" {
					wantType = model.EventToolCall
					if nativeWrite {
						wantType = model.EventFileWrite
					}
				}
				if len(events) != 1 || events[0].EventType != wantType {
					t.Fatalf("events=%+v, want %s", events, wantType)
				}
			})
		}
	}
}

func TestMuseHookDecisionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, lifecycle, payload string
		enforce, deny            bool
	}{
		{"monitor", "pre-tool", `{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}"}`, false, false},
		{"enforce", "pre-tool", `{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}"}`, true, true},
		{"post", "post-tool", `{"hook_event_name":"PostToolUse","tool_name":"bash","tool_input":"{\"command\":\"cat .env\"}","tool_response":"{\"exit_code\":0}"}`, true, false},
		{"malformed", "pre-tool", `{bad`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeEnforceRuleFile(t, criticalEnforceRule)
			args := []string{
				"hook", tc.lifecycle, "--agent", "muse", "--rules-dir", dir,
				"--no-builtin-rules", "--output", "file", "--output-file", filepath.Join(t.TempDir(), "records.ndjson"),
			}
			if tc.enforce {
				args = append(args, "--enforce")
			}
			out, stderr, code := runCLIStdin(tc.payload, args...)
			if code != 0 || (decodeDecision(t, out) == "deny") != tc.deny {
				t.Fatalf("exit=%d output=%q stderr=%q want deny=%v", code, out, stderr, tc.deny)
			}
		})
	}
}
