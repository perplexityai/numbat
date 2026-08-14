// Package extract turns agent-specific on-disk artifacts into the normalized
// model.Event stream that the rest of Numbat consumes.
//
// Each supported agent provides an Extractor. Extractors are pure parsers:
// they read one already-opened artifact and emit events, and do not touch the
// filesystem, walk directories, or follow references between files. Artifact
// discovery (globbing ~/.claude/projects, ~/.codex/sessions, ...) lives in the
// caller so parsers stay deterministic and unit-testable.
package extract

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

// firstURL returns the first whitespace-delimited http(s):// token in s, or ""
// when none is present. It is a deliberately conservative lift: some agents
// (e.g. Gemini's web_fetch) carry the egress target inside a free-text prompt,
// so the typed URL field is only populated when a clear URL token is found,
// never guessed from arbitrary prose.
func firstURL(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
			return strings.TrimRight(f, ".,;)]}\"'")
		}
	}
	return ""
}

// networkTargetURL returns raw iff it parses as an absolute http:// or https://
// URL with a host, else "". A network.indicator's URL must be a real egress
// target, so a fetch arg carrying file://, javascript:, data:, a relative path,
// or junk is rejected here rather than promoted into Event.URL. The returned
// value is the trimmed original, not a re-serialized form, so the surfaced URL
// matches what the agent recorded. The raw invalid value is preserved by the
// caller in ContentPreview so nothing is dropped.
func networkTargetURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return ""
	}
	if u.Hostname() == "" {
		return ""
	}
	return raw
}

// Extractor parses a single artifact into events. Implementations are
// stateless and safe to reuse across artifacts and goroutines.
type Extractor interface {
	// Agent reports the model.Agent* identifier this extractor produces.
	Agent() string

	// Extract parses the artifact bytes from r. src carries provenance (the
	// on-disk path recorded in Evidence.LocalPath, an optional case id); the
	// parser never opens or walks src.Path itself.
	//
	// Extract is tolerant: a malformed record yields a Diagnostic and is
	// skipped rather than failing the whole artifact, because forensic inputs
	// are frequently partial or truncated. A non-nil error is reserved for a
	// failure that prevents reading the artifact at all (e.g. an oversized or
	// unreadable source).
	Extract(r io.Reader, src Source) (*Result, error)
}

// SafeExtract runs ex.Extract under a panic fence: a parser that panics on
// malformed or adversarial input yields an error instead of unwinding into the
// caller. Both scan and timeline route their parse step through it so a single
// corrupt artifact can crash its own parser but never the surrounding run — and
// so the two planes share one fence and cannot drift. A recovered panic is
// returned as an ordinary error, which every caller already handles by emitting
// a diagnostic and skipping the artifact; the artifact yields no partial events
// (the named return is reset to nil on recover).
func SafeExtract(ex Extractor, r io.Reader, src Source) (res *Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			res = nil
			err = fmt.Errorf("extractor panic (%T)", p)
		}
	}()
	res, err = ex.Extract(r, src)
	if err == nil && res == nil {
		return nil, fmt.Errorf("extractor returned a nil result")
	}
	return res, err
}

// Profile selects how much an extractor emits. The default (evidence) yields
// only forensic evidence events; full additionally yields model reasoning
// (message.reasoning) and session-context fields (model/provider) that are
// monitoring join keys, not evidence.
type Profile string

const (
	ProfileEvidence Profile = "evidence"
	ProfileFull     Profile = "full"
)

// Source carries the provenance of one artifact. Keeping it separate from the
// byte reader lets callers parse embedded fixtures, network sources, or real
// files through the same Extractor without the parser knowing the difference.
type Source struct {
	// Path is the artifact's on-disk location for Evidence.LocalPath. It is
	// metadata only: the parser never opens or walks it.
	Path string
	// CaseID, when set, is stamped on every emitted event so findings from one
	// investigation share an identifier.
	CaseID string
	// Profile selects the capture depth. The zero value ("") is treated as
	// ProfileEvidence so existing callers keep evidence-only behavior.
	Profile Profile
	// CaptureContent retains bounded prompt, assistant, and reasoning bodies for
	// local rules or indicator extraction. Default output still uses previews.
	CaptureContent bool
}

func setMessageContent(ev *model.Event, src Source, raw string) {
	ev.SetContent(raw, src.CaptureContent)
}

// fullProfile reports whether the source requests the full capture profile.
func (s Source) fullProfile() bool { return s.Profile == ProfileFull }

// Result is the output of parsing one artifact.
type Result struct {
	// Events are the normalized events, in artifact order.
	Events []model.Event
	// Diagnostics record a bounded number of non-fatal parse problems (a
	// malformed line, an unrecognized record shape) so a caller can surface
	// coverage gaps without the parse aborting or flooding its output.
	Diagnostics []Diagnostic

	diagnosticCounts      map[string]int
	diagnosticsSuppressed bool
}

const (
	maxDiagnosticsPerArtifact = 20
	maxRepeatedDiagnostic     = 3
)

// diag appends a non-fatal diagnostic to the result.
func (r *Result) diag(path string, line int, msg string) {
	if r.diagnosticCounts == nil {
		r.diagnosticCounts = make(map[string]int)
	}
	key := path + "\x00" + msg
	if r.diagnosticCounts[key] >= maxRepeatedDiagnostic {
		r.suppressDiagnostic(path, line)
		return
	}
	realCount := len(r.Diagnostics)
	if r.diagnosticsSuppressed {
		realCount--
	}
	if realCount >= maxDiagnosticsPerArtifact-1 {
		r.suppressDiagnostic(path, line)
		return
	}
	r.diagnosticCounts[key]++
	diagnostic := Diagnostic{Path: path, Line: line, Msg: msg}
	if !r.diagnosticsSuppressed {
		r.Diagnostics = append(r.Diagnostics, diagnostic)
		return
	}
	last := len(r.Diagnostics) - 1
	r.Diagnostics = append(r.Diagnostics, r.Diagnostics[last])
	r.Diagnostics[last] = diagnostic
}

func (r *Result) suppressDiagnostic(path string, line int) {
	if r.diagnosticsSuppressed {
		return
	}
	r.Diagnostics = append(r.Diagnostics, Diagnostic{Path: path, Line: line, Msg: "additional diagnostics suppressed"})
	r.diagnosticsSuppressed = true
}

// Diagnostic is a non-fatal problem encountered while parsing an artifact.
type Diagnostic struct {
	// Path is the artifact the problem occurred in.
	Path string
	// Line is the 1-based line number for line-oriented artifacts, 0 if N/A.
	Line int
	// Msg is a short, human-readable description. It must not embed raw
	// artifact content, which may carry secrets.
	Msg string
}
