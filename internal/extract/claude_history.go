package extract

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
)

// claudeHistoryFile is Claude Code's cross-project prompt history, one JSON
// object per line, written for every user-typed prompt regardless of project.
// It is a second, independent record of prompts: a session's transcript under
// ~/.claude/projects may be deleted while its prompts survive here, and a
// prompt present in both artifacts is corroboration, not an error — each event
// carries its own evidence ref. The extractor selects this shape by path,
// exactly as the Gemini extractor selects logs.json by name.
const claudeHistoryFile = ".claude/history.jsonl"

// isClaudeHistory reports whether path is the Claude prompt-history file,
// matched as a suffix (an absolute or nested path) or the whole relative path.
func isClaudeHistory(path string) bool {
	slashed := filepath.ToSlash(path)
	return strings.HasSuffix(slashed, "/"+claudeHistoryFile) || slashed == claudeHistoryFile
}

// claudeHistoryEntry is one prompt-history line. The on-disk record also
// carries pastedContents (a map of pasted-attachment ids to content hashes —
// hashes only, no content); it is intentionally ignored: there is nothing
// evidentiary to lift from a bare hash.
type claudeHistoryEntry struct {
	Display   string `json:"display"`
	Project   string `json:"project"`
	SessionID string `json:"sessionId"`
	// Timestamp is unix milliseconds.
	Timestamp int64 `json:"timestamp"`
}

// extractHistory parses an already-read prompt-history file into prompt.user
// events. No session lifecycle is synthesized — this artifact is a
// cross-session index, not a session stream; the session ids on its events
// let the timeline group each prompt with its transcript when one exists.
func (e ClaudeExtractor) extractHistory(data []byte, sha string, src Source) (*Result, error) {
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
			var entry claudeHistoryEntry
			if jsonErr := json.Unmarshal(raw, &entry); jsonErr != nil {
				res.diag(src.Path, line, "malformed history line")
			} else if entry.Display != "" {
				ev := model.Event{
					SchemaVersion: model.SchemaVersion,
					CaseID:        src.CaseID,
					EventID:       historyEventID("claude-hist", src.Path, line),
					SourceAgent:   e.Agent(),
					SourceType:    model.SourceArtifact,
					Timestamp:     epochMillisRFC3339(entry.Timestamp),
					ProjectPath:   entry.Project,
					SessionID:     entry.SessionID,
					Actor:         model.ActorUser,
					EventType:     model.EventPromptUser,
					Confidence:    model.ConfidenceHigh,
					Evidence: model.Evidence{
						ArtifactType: "claude_history",
						LocalPath:    src.Path,
						Line:         line,
						SHA256:       sha,
					},
				}
				setMessageContent(&ev, src, entry.Display)
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

// historyEventID is the deterministic id for a history-line event. History
// lines carry no uuid, so the id digests path and line, mirroring the
// transcript parser's no-uuid fallback shape.
func historyEventID(prefix, path string, line int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s:%d", path, line))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

// epochMillisRFC3339 renders a unix-milliseconds stamp as the RFC3339 form
// events carry; a non-positive value means the line carried no usable time.
func epochMillisRFC3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}
