package output

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestMessageContentOnly(t *testing.T) {
	const secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	body := strings.Repeat("ordinary context ", 20) + secret
	payload := `{"password":"` + secret + `","keep":"visible"}`
	for _, eventType := range []model.EventType{
		model.EventPromptUser, model.EventMessageAssistant, model.EventMessageReasoning, model.EventCommandExec,
	} {
		ev := model.Event{
			EventType: eventType, Command: "printf " + secret,
			FilePath: "/tmp/" + secret, URL: "https://example.test/" + secret,
			ProjectPath: "/project/" + secret, MCPServer: secret, MCPTool: secret, ApprovalReason: secret,
		}
		if eventType == model.EventCommandExec {
			ev.SetToolInput(json.RawMessage(payload))
			ev.SetToolResult(json.RawMessage(payload))
		} else {
			ev.SetContent(body, true)
		}
		original := ev
		for _, mode := range []string{"preview", "full", "raw"} {
			t.Run(string(eventType)+"/"+mode, func(t *testing.T) {
				var opts []EmitterOption
				switch mode {
				case "full":
					opts = append(opts, WithFullContent())
				case "raw":
					opts = append(opts, WithRawContent())
				}
				emit := func(opts ...EmitterOption) ([]byte, model.Event) {
					t.Helper()
					var records bytes.Buffer
					if err := New(&records, io.Discard, "run-test", opts...).EmitEvent(ev); err != nil {
						t.Fatal(err)
					}
					var got model.Event
					if err := json.Unmarshal(records.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					return records.Bytes(), got
				}
				allBytes, all := emit(opts...)
				messageBytes, messages := emit(append(opts, WithMessageContentOnly())...)
				if mode == "preview" && !bytes.Equal(allBytes, messageBytes) {
					t.Fatal("scope changed preview output")
				}
				if messages.ToolInput != "" || messages.ToolResult != "" ||
					messages.ToolInputBytes != ev.ToolInputBytesForAnalysis() ||
					messages.ToolResultBytes != ev.ToolResultBytesForAnalysis() {
					t.Fatal("messages scope exposed a tool body or lost byte counts")
				}
				if mode == "preview" || eventType == model.EventCommandExec {
					if messages.Content != "" || messages.ContentBytes != 0 {
						t.Fatal("unexpected message body")
					}
				} else {
					if messages.Content == "" || messages.Content != all.Content ||
						messages.ContentBytes != len(body) || messages.ContentTruncated {
						t.Fatal("messages scope changed the conversation body")
					}
					if strings.Contains(messages.Content, secret) != (mode == "raw") {
						t.Fatal("incorrect message redaction")
					}
				}
				if eventType == model.EventCommandExec && mode != "preview" && (all.ToolInput == "" || all.ToolResult == "") {
					t.Fatal("default all scope lost tool content")
				}
				messages.Content = ""
				metadata, err := json.Marshal(messages)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(metadata, []byte(secret)) {
					t.Fatal("messages scope unredacted unrelated fields")
				}
				if !reflect.DeepEqual(ev, original) {
					t.Fatal("projection changed the analysis event")
				}
			})
		}
	}
}

func TestMessageContentScopeBeforeFanout(t *testing.T) {
	ev := model.Event{EventType: model.EventToolResult}
	ev.SetToolResult(strings.Repeat("x", 1<<20) + "PRIVATE_CANARY")
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	httpSink, err := NewHTTPSink(HTTPConfig{URL: server.URL, BatchSize: 1, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var local bytes.Buffer
	em := New(NewMultiSink(nopCloseSink{&local}, httpSink), io.Discard, "run-test",
		WithRawContent(), WithMessageContentOnly())
	if err := em.EmitEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := em.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-received:
		if !bytes.Equal(body, local.Bytes()) || len(body) > 2048 || bytes.Contains(body, []byte("PRIVATE_CANARY")) {
			t.Fatal("fanout received different or unfiltered records")
		}
		var got model.Event
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.ToolResult != "" || got.ToolResultBytes != ev.ToolResultBytesForAnalysis() || got.ToolResultTruncated {
			t.Fatal("filtered HTTP output lost tool metadata")
		}
	default:
		t.Fatal("no HTTP record delivered")
	}
}
