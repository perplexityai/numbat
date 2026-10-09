package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestContentScopeScanAndTimeline(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	message := strings.Repeat("ordinary context ", 20) + "MESSAGE_TAIL " + secret
	input := `{"password":"` + secret + `","data":"INPUT_TAIL"}`
	artifact := writeTranscript(t, `{"type":"user","sessionId":"s","cwd":"/project/`+secret+`","message":{"content":"`+message+`"}}
{"type":"assistant","sessionId":"s","message":{"content":[{"type":"text","text":"`+message+`"},{"type":"tool_use","id":"c","name":"mcp__notes__save","input":`+input+`}]}}
{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"c","content":"RESULT_TAIL"}]}}`)
	rulesDir := writeEnforceRuleFile(t, `id: test.scope
version: "1.0"
enabled: true
title: Synthetic content scope
severity: high
expr: event.content.contains("MESSAGE_TAIL") || event.tool_input.contains("INPUT_TAIL") || event.tool_result.contains("RESULT_TAIL")
`)
	for _, command := range []string{"scan", "timeline"} {
		for _, mode := range []string{"preview", "full", "raw"} {
			var defaultEvents []model.Event
			var defaultFindingIDs []string
			for _, scope := range []string{"", "all", "messages"} {
				t.Run(command+"/"+mode+"/"+scope, func(t *testing.T) {
					args := []string{command, "--path", artifact, "--content", mode}
					if command == "scan" {
						args = append(args, "--emit", "all", "--rules-dir", rulesDir, "--no-builtin-rules")
					} else {
						args = append(args, "--format", "json")
					}
					if scope != "" {
						args = append(args, "--content-scope", scope)
					}
					out, diag, code := runCLI(args...)
					if code != 0 {
						t.Fatalf("exit=%d stderr=%s", code, diag)
					}
					var events []model.Event
					if command == "scan" {
						events = decodeEventRecords(t, out)
						var findingIDs []string
						for _, finding := range decodeFindings(t, out) {
							findingIDs = append(findingIDs, finding.FindingID)
						}
						if len(findingIDs) != 4 {
							t.Fatalf("findings=%d, want 4", len(findingIDs))
						}
						if scope == "" {
							defaultFindingIDs = findingIDs
						} else if !reflect.DeepEqual(findingIDs, defaultFindingIDs) {
							t.Fatal("scope changed local findings")
						}
					} else {
						var report timelineReport
						if err := json.Unmarshal([]byte(out), &report); err != nil {
							t.Fatal(err)
						}
						if len(report.Sessions) != 1 {
							t.Fatalf("sessions=%d, want 1", len(report.Sessions))
						}
						session := report.Sessions[0]
						if strings.Contains(session.ProjectPath, secret) != (mode == "raw" && scope != "messages") {
							t.Fatal("incorrect session metadata redaction")
						}
						events = session.Events
					}
					if len(events) != 6 {
						t.Fatalf("events=%d, want 6 including session boundaries", len(events))
					}
					if scope == "" {
						defaultEvents = events
					} else if (scope == "all" || mode == "preview") && !reflect.DeepEqual(events, defaultEvents) {
						t.Fatal("default all or preview output changed")
					}
					for i, ev := range events {
						if ev.EventID != defaultEvents[i].EventID || ev.Evidence != defaultEvents[i].Evidence {
							t.Fatal("scope changed event identity or provenance")
						}
						if ev.EventType == model.EventPromptUser || ev.EventType == model.EventMessageAssistant {
							if (ev.Content != "") != (mode != "preview") ||
								(mode != "preview" && ev.ContentBytes != len(message)) ||
								strings.Contains(ev.Content, secret) != (mode == "raw") {
								t.Fatal("incorrect message projection")
							}
							continue
						}
						if ev.EventType != model.EventToolCall && ev.EventType != model.EventToolResult {
							continue
						}
						if (ev.ToolInput != "" || ev.ToolResult != "") != (mode != "preview" && scope != "messages") {
							t.Fatal("incorrect tool projection")
						}
						if ev.ToolInputBytes+ev.ToolResultBytes == 0 || ev.ToolInputTruncated || ev.ToolResultTruncated {
							t.Fatal("scope changed tool completeness metadata")
						}
					}
				})
			}
		}
	}
}

func TestContentScopeValidation(t *testing.T) {
	setTestHome(t, t.TempDir())
	for _, command := range [][]string{
		{"scan"},
		{"timeline"},
		{"collect"},
		{"hook", "PreToolUse", "--agent", "claude"},
		{"hook", "install", "--agent", "claude"},
	} {
		t.Run(strings.Join(command, "/"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "output")
			args := append([]string(nil), command...)
			args = append(args, "--content-scope", "tools")
			if command[0] == "hook" && command[1] == "install" {
				args = append(args, "--settings", path)
			} else if command[0] != "timeline" {
				args = append(args, "--output", "file", "--output-file", path)
			}
			out, diag, code := runCLIStdin(`{}`, args...)
			wantCode := 2
			if command[0] == "hook" && command[1] == "PreToolUse" {
				wantCode = 0
			}
			if code != wantCode || out != "" || !strings.Contains(diag, `invalid --content-scope "tools": want all|messages`) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, diag)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid scope touched output/config path: %v", err)
			}
		})
	}
}

func TestGeneratedIntegrationContentScope(t *testing.T) {
	setTestHome(t, t.TempDir())
	path := filepath.Join(t.TempDir(), "numbat.ts")
	_, diag, code := runCLI("hook", "install", "--agent", "pi", "--settings", path,
		"--emit", "events", "--content", "raw", "--content-scope", "messages")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, diag)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(body), `"--content-scope=messages"`) != 1 ||
		strings.Count(string(body), "...EXTRA_ARGS") != 2 {
		t.Fatal("generated integration lost scope in a callback path")
	}
}
