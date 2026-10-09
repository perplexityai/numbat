package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/output"
)

func TestMaxRecordBytesRejectsNegativeWithoutEffects(t *testing.T) {
	setTestHome(t, t.TempDir())
	for _, command := range [][]string{
		{"scan"},
		{"collect"},
		{"hook", "PreToolUse", "--agent", "claude"},
		{"hook", "install", "--agent", "claude"},
	} {
		t.Run(strings.Join(command, "/"), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "records.ndjson")
			const original = "existing records\n"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{}, command...)
			args = append(args, "--output", "file", "--output-file", path, "--max-record-bytes", "-1")
			settings := filepath.Join(dir, "settings.json")
			if len(command) > 1 && command[1] == "install" {
				args = append(args, "--settings", settings)
			}
			_, diag, code := runCLIStdin(`{}`, args...)
			want := 2
			if len(command) > 1 && command[1] == "PreToolUse" {
				want = 0
			}
			if code != want || !strings.Contains(diag, "--max-record-bytes must be non-negative") {
				t.Fatalf("exit=%d diagnostics=%s", code, diag)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != original {
				t.Fatalf("invalid cap changed file: %q, %v", got, err)
			}
			if _, err := os.Stat(settings); !os.IsNotExist(err) {
				t.Fatalf("invalid cap created settings: %v", err)
			}
		})
	}
}

func TestMaxRecordBytesScanAndShip(t *testing.T) {
	setTestHome(t, t.TempDir())
	message := strings.Repeat("message ", 1500)
	artifact := writeTranscript(t, `{"type":"user","sessionId":"s","message":{"content":"`+message+`"}}`)
	for _, mode := range []string{"full", "raw"} {
		for _, scope := range []string{"all", "messages"} {
			for _, limit := range []string{"", "0", "2048", "1073741824"} {
				t.Run(mode+"/"+scope+"/"+limit, func(t *testing.T) {
					for _, destination := range []string{"stdout", "fanout"} {
						var received syncBuf
						srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if _, err := io.Copy(&received, r.Body); err != nil {
								t.Error(err)
							}
							w.WriteHeader(http.StatusOK)
						}))
						path := filepath.Join(t.TempDir(), "records.ndjson")
						args := []string{
							"scan", "--path", artifact, "--emit", "events", "--content", mode,
							"--content-scope", scope,
						}
						if limit != "" {
							args = append(args, "--max-record-bytes", limit)
						}
						if destination == "fanout" {
							args = append(args, "--output", "file", "--output", "http", "--output-file", path, "--http-url", srv.URL)
						}
						out, diag, code := runCLI(args...)
						srv.Close()
						if code != 0 {
							t.Fatalf("exit=%d diagnostics=%s", code, diag)
						}
						records := []byte(out)
						if destination == "fanout" {
							var err error
							records, err = os.ReadFile(path)
							if err != nil {
								t.Fatal(err)
							}
							if string(records) != received.String() {
								t.Fatal("file and HTTP received different records")
							}
						}
						events := decodeEventRecords(t, string(records))
						if len(events) != 3 {
							t.Fatalf("event count=%d", len(events))
						}
						messageIndex := -1
						for i := range events {
							if events[i].ContentBytes == len(message) {
								messageIndex = i
							}
						}
						if messageIndex < 0 {
							t.Fatal("message or original byte count missing")
						}
						event := events[messageIndex]
						if limit == "2048" {
							for _, line := range bytes.Split(bytes.TrimSpace(records), []byte{'\n'}) {
								if len(line)+1 > 2048 {
									t.Fatalf("oversized %s record: %d", destination, len(line)+1)
								}
							}
							if event.Content != "" || !bytes.Contains(records, []byte(`"content_omitted":["content"]`)) {
								t.Fatal("bounded message lost omission or size metadata")
							}
							if destination == "fanout" {
								var shipped syncBuf
								receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
									if _, err := io.Copy(&shipped, r.Body); err != nil {
										t.Error(err)
									}
									w.WriteHeader(http.StatusOK)
								}))
								factory := func() (output.Sink, error) {
									return output.NewHTTPSink(output.HTTPConfig{URL: receiver.URL})
								}
								state := path + ".ship-state"
								cursor, err := drainAvailable(context.Background(), path, state, newTestShipCursor(), maxShipBatchBytes, factory, io.Discard)
								receiver.Close()
								if err != nil || cursor.checkpoint.Offset != int64(len(records)) || shipped.String() != string(records) {
									t.Fatalf("ship changed bytes/checkpoint: offset=%d err=%v", cursor.checkpoint.Offset, err)
								}
							}
						} else if event.Content != message {
							t.Fatal("disabled or large cap changed message")
						}
					}
				})
			}
		}
	}
}

func TestMaxRecordBytesHookFailureDoesNotDeny(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := writeEnforceRuleFile(t, criticalEnforceRule)
	for _, limit := range []string{"0", "1"} {
		args := enforceHookArgs(t, "hook", "pre-tool", "--agent", "claude", "--enforce", "--rules-dir", dir, "--max-record-bytes", limit)
		out, diag, code := runCLIStdin(catEnvPayload, args...)
		if code != 0 || (decodeDecision(t, out) == "deny") != (limit == "0") {
			t.Fatalf("limit=%s exit=%d stdout=%q stderr=%q", limit, code, out, diag)
		}
		if limit == "1" && !strings.Contains(diag, noDecisionMessage) {
			t.Fatalf("missing cap failure diagnostic: %s", diag)
		}
	}
}

func TestMaxRecordBytesInstalledIntegrations(t *testing.T) {
	for _, key := range []string{"XDG_CONFIG_HOME", "OPENCODE_CONFIG_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "COPILOT_HOME"} {
		t.Setenv(key, "")
	}
	for _, agent := range []string{"claude", "codex", "cursor", "windsurf", "gemini", "copilot", "opencode", "pi", "amp", "openclaw", "kilo"} {
		for _, value := range []string{"", "0", "2048", "1073741824"} {
			t.Run(agent+"/"+value, func(t *testing.T) {
				home := t.TempDir()
				setTestHome(t, home)
				args := []string{"hook", "install", "--agent", agent}
				if value != "" {
					args = append(args, "--max-record-bytes", value)
				}
				_, diag, code := runCLI(args...)
				if code != 0 {
					t.Fatalf("exit=%d diagnostics=%s", code, diag)
				}
				found := false
				match := regexp.MustCompile(`--max-record-bytes[\\'" ,:=\t\r\n]*` + value + `\b`)
				err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
					if err != nil || entry.IsDir() {
						return err
					}
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					text := testHookCommandText(string(data))
					if strings.Contains(text, "--max-record-bytes") {
						found = true
						if value != "" && !match.MatchString(text) {
							t.Errorf("wrong cap in %s: %s", path, data)
						}
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if found != (value != "") {
					t.Fatalf("flag persistence=%v for value %q", found, value)
				}
			})
		}
	}
}

func TestMaxRecordBytesHelpAndSurface(t *testing.T) {
	for _, command := range [][]string{
		{"scan"},
		{"collect"},
		{"hook", "PreToolUse", "--agent", "claude"},
		{"hook", "install", "--agent", "claude"},
	} {
		out, diag, code := runCLI(append(command, "--help")...)
		if code != 0 || !strings.Contains(out+diag, "-max-record-bytes") || !strings.Contains(out+diag, maxRecordBytesHelp) {
			t.Fatalf("%v: exit=%d output=%s%s", command, code, out, diag)
		}
	}
	for _, command := range []string{"ship", "timeline"} {
		_, diag, code := runCLI(command, "--max-record-bytes", "2048")
		if code != 2 || !strings.Contains(diag, "flag provided but not defined") {
			t.Fatalf("%s unexpectedly accepts emitter cap: exit=%d %s", command, code, diag)
		}
	}
}
