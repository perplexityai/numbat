package extract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// codexHistoryFile is Codex's cross-session prompt history, one JSON object
// per line — the Codex analog of Claude's history.jsonl, recording every
// user-typed prompt with its session id. Prompts also appear in the session's
// rollout; a prompt present in both is corroboration, and the history line
// survives a deleted rollout.
const codexHistoryFile = ".codex/history.jsonl"

// isCodexHistory reports whether path is the Codex prompt-history file,
// matched as a suffix (an absolute or nested path) or the whole relative path.
func isCodexHistory(path string) bool {
	slashed := filepath.ToSlash(path)
	return strings.HasSuffix(slashed, "/"+codexHistoryFile) || slashed == codexHistoryFile
}

// codexHistoryEntry is one prompt-history line.
type codexHistoryEntry struct {
	SessionID string `json:"session_id"`
	// TS is unix seconds.
	TS   int64  `json:"ts"`
	Text string `json:"text"`
}

// extractHistory parses an already-read Codex prompt-history file into
// prompt.user events. Like the Claude history parser, no session lifecycle is
// synthesized: the artifact is a cross-session index, and its session ids let
// the timeline group each prompt with its rollout when one exists.
func (e CodexExtractor) extractHistory(data []byte, sha string, src Source) (*Result, error) {
	res := &Result{}
	br := bufio.NewReader(bytes.NewReader(data))
	for line := 1; ; line++ {
		raw, tooLong, err := readLine(br)
		if tooLong {
			res.diag(src.Path, line, "line exceeds size cap; skipped")
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 {
			var entry codexHistoryEntry
			if jsonErr := json.Unmarshal(raw, &entry); jsonErr != nil {
				res.diag(src.Path, line, "malformed history line")
			} else if entry.Text != "" {
				ev := model.Event{
					SchemaVersion: model.SchemaVersion,
					CaseID:        src.CaseID,
					EventID:       historyEventID("codex-hist", src.Path, line),
					SourceAgent:   e.Agent(),
					SourceType:    model.SourceArtifact,
					Timestamp:     epochSecondsRFC3339(entry.TS),
					SessionID:     entry.SessionID,
					Actor:         model.ActorUser,
					EventType:     model.EventPromptUser,
					Confidence:    model.ConfidenceHigh,
					Evidence: model.Evidence{
						ArtifactType: "codex_history",
						LocalPath:    src.Path,
						Line:         line,
						SHA256:       sha,
					},
				}
				setMessageContent(&ev, src, entry.Text)
				res.Events = append(res.Events, ev)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return res, nil
			}
			return nil, fmt.Errorf("read %q line %d: %w", src.Path, line, err)
		}
	}
}

// epochSecondsRFC3339 renders a unix-seconds stamp as the RFC3339 form events
// carry; a non-positive value means the line carried no usable time.
func epochSecondsRFC3339(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339Nano)
}
