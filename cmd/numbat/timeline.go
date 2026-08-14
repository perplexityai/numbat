package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/perplexityai/numbat/internal/discover"
	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

// timeline output formats.
const (
	timelineFormatText = "text"
	timelineFormatJSON = "json"
)

// timelineExtractorFor resolves an agent to its extractor. It defaults to
// extract.For; tests override it to inject a panicking extractor and prove the
// SafeExtract fence keeps timeline from crashing on adversarial input.
var timelineExtractorFor = extract.For

// runTimeline implements `numbat timeline`: discover agent artifacts, parse them
// into normalized events, group those events into per-session chronological
// timelines, and render them. It is a read-only VIEW over the same extraction the
// scanner uses — no rules, no findings, no new schema. The default text format is
// a human-readable reconstruction; --format json emits the grouped structure for
// tooling.
//
// It reuses scan's discovery model: --agent limits known default roots, while
// repeatable --path reads explicit roots. It is tolerant the same way: a
// per-file failure is a stderr diagnostic, not an abort.
// The default view emits only redacted previews. JSON output can explicitly
// include bounded, redacted conversation content with --content full.
//
// Exit codes: 0 on a completed render (even with no events), 2 on a usage error,
// 1 when no artifact is found or every discovered artifact fails to parse.
func runTimeline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var paths multiFlag
	fs.Var(&paths, "path", "artifact file or directory to read (repeatable; defaults to known agent locations under $HOME plus supported agent home/data env overrides)")
	var agents multiFlag
	fs.Var(&agents, "agent", "limit automatic discovery to a parser-backed agent (repeatable; cannot be combined with --path)")
	caseID := fs.String("case-id", "", "case identifier stamped on every event")
	contentFlag := fs.String("content", "preview", contentFlagHelp())
	includeReasoning := fs.Bool("include-reasoning", false, "include source-recorded reasoning events")
	profileFlag := fs.String("profile", "", "deprecated capture profile: evidence|full (full enables --include-reasoning)")
	formatFlag := fs.String("format", timelineFormatText, "output format: text|json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat timeline [--agent NAME ... | --path FILE|DIR ...] [--case-id ID] [--include-reasoning] [--content preview|full] [--format text|json]")
		fmt.Fprintln(stderr, "\nReconstructs a per-session chronological view of agent activity (prompts, tool calls,")
		fmt.Fprintln(stderr, "commands, approvals, file edits, outcomes) from the same artifacts scan reads.")
		fmt.Fprintf(stderr, "Automatic-discovery agents: %s.\n", artifactAgentUsage())
		fmt.Fprintln(stderr, "Preserve vendor directory layouts when scanning copied or mounted artifacts.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "timeline: unexpected argument %q; pass paths with --path\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	selectedAgents, err := parseArtifactAgents(agents)
	if err != nil {
		fmt.Fprintf(stderr, "timeline: %v\n", err)
		fs.Usage()
		return 2
	}
	if len(paths) > 0 && len(selectedAgents) > 0 {
		fmt.Fprintln(stderr, "timeline: --agent cannot be combined with --path")
		fs.Usage()
		return 2
	}
	format := *formatFlag
	if format != timelineFormatText && format != timelineFormatJSON {
		fmt.Fprintf(stderr, "timeline: invalid --format %q: want text|json\n", format)
		fs.Usage()
		return 2
	}
	content, err := parseContentMode(*contentFlag)
	if err != nil {
		fmt.Fprintf(stderr, "timeline: %v\n", err)
		fs.Usage()
		return 2
	}
	reasoning, err := applyDeprecatedProfile(*profileFlag, *includeReasoning)
	if err != nil {
		fmt.Fprintf(stderr, "timeline: %v\n", err)
		fs.Usage()
		return 2
	}
	if content == contentFull && format != timelineFormatJSON {
		fmt.Fprintln(stderr, "timeline: --content full requires --format json")
		fs.Usage()
		return 2
	}
	roots := []string(paths)
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "timeline: cannot resolve home directory: %v\n", err)
			return 1
		}
		roots = discover.DefaultRootsFor(home, selectedAgents)
		if len(roots) == 0 {
			scope := ""
			if len(agents) > 0 {
				scope = fmt.Sprintf(" for --agent %s", strings.Join([]string(agents), ","))
			}
			fmt.Fprintf(stderr, "timeline: no agent artifacts found%s under %s; pass --path to read a specific file or directory\n", scope, home)
			return 1
		}
	}

	var events []model.Event
	discovered, parsed := 0, 0
	seenArtifacts := map[string]struct{}{}
	for _, root := range roots {
		arts, skips, err := discover.Walk(root)
		if err != nil {
			fmt.Fprintf(stderr, "timeline: read root %q: %v\n", root, err)
			continue
		}
		for _, sk := range skips {
			fmt.Fprintf(stderr, "timeline: skipped unreadable path %q: %v\n", sk.Path, sk.Err)
		}
		for _, a := range arts {
			key := a.DedupeKey()
			if _, seen := seenArtifacts[key]; seen {
				continue
			}
			seenArtifacts[key] = struct{}{}
			discovered++
			evs, ok := readArtifactEvents(a, *caseID, reasoning, content == contentFull, stderr)
			if !ok {
				continue
			}
			parsed++
			events = append(events, evs...)
		}
	}
	if discovered == 0 {
		fmt.Fprintln(stderr, "timeline: no agent artifacts found to read")
		return 1
	}
	if parsed == 0 {
		fmt.Fprintln(stderr, "timeline: no agent artifacts parsed")
		return 1
	}

	sessions := groupSessions(events)
	// Group first, then apply the requested shared event projection.
	for i := range sessions {
		if content == contentFull {
			sessions[i].Events = redact.EventsWithContent(sessions[i].Events)
		} else {
			sessions[i].Events = redact.Events(sessions[i].Events)
		}
		sessions[i].ProjectPath = redact.String(sessions[i].ProjectPath)
	}
	if format == timelineFormatJSON {
		return renderTimelineJSON(sessions, stdout, stderr)
	}
	if err := renderTimelineText(sessions, stdout); err != nil {
		fmt.Fprintf(stderr, "timeline: write text: %v\n", err)
		return 1
	}
	return 0
}

// readArtifactEvents parses one artifact into its events, mirroring scan's
// per-file tolerance: a missing extractor, an unreadable file, or a parse error
// is a stderr diagnostic and yields ok=false so the caller skips it without
// aborting the whole run. Per-line parse problems are diagnostics too.
func readArtifactEvents(a discover.Artifact, caseID string, includeReasoning, captureContent bool, stderr io.Writer) ([]model.Event, bool) {
	ex, ok := timelineExtractorFor(a.Agent)
	if !ok {
		fmt.Fprintf(stderr, "timeline: no extractor for agent %q (%s)\n", a.Agent, a.Path)
		return nil, false
	}
	f, err := discover.OpenArtifact(a)
	if err != nil {
		fmt.Fprintf(stderr, "timeline: open %q: %v\n", a.Path, err)
		return nil, false
	}
	defer f.Close()

	res, err := extract.SafeExtract(ex, f, extract.Source{
		Path:             a.Path,
		CaseID:           caseID,
		IncludeReasoning: includeReasoning,
		CaptureContent:   captureContent,
	})
	if err != nil {
		fmt.Fprintf(stderr, "timeline: parse %q: %v\n", a.Path, err)
		return nil, false
	}
	for _, d := range res.Diagnostics {
		fmt.Fprintf(stderr, "timeline: %s:%d: %s\n", d.Path, d.Line, d.Msg)
	}
	valid := make([]model.Event, 0, len(res.Events))
	for _, ev := range res.Events {
		ev = ev.NormalizePaths()
		if err := ev.Validate(); err != nil {
			fmt.Fprintf(stderr, "timeline: invalid %q event %s: %v\n", a.Path, ev.EventID, err)
			continue
		}
		valid = append(valid, ev)
	}
	return valid, true
}

// timelineReport is the json shape of `numbat timeline --format json`: the schema
// version (so a receiver can route deterministically, matching emitted records)
// and the grouped sessions. It is a view, not an emitted record stream, so it
// carries no record_type — it is one JSON document, not NDJSON.
type timelineReport struct {
	SchemaVersion string            `json:"schema_version"`
	Sessions      []timelineSession `json:"sessions"`
}

// renderTimelineJSON writes the grouped sessions as a single indented JSON
// document. Determinism comes entirely from groupSessions' total ordering, so the
// same artifacts always produce byte-identical output.
func renderTimelineJSON(sessions []timelineSession, stdout, stderr io.Writer) int {
	report := timelineReport{SchemaVersion: model.SchemaVersion, Sessions: sessions}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(stderr, "timeline: encode json: %v\n", err)
		return 1
	}
	return 0
}

// renderTimelineText writes a human-readable reconstruction: one block per
// session (its identity and span), then one line per event in order, each a
// labeled step anchored by its evidence ref.

func renderTimelineText(sessions []timelineSession, stdout io.Writer) error {
	w := bufio.NewWriter(stdout)
	for i, s := range sessions {
		if i > 0 {
			fmt.Fprintln(w)
		}
		id := s.SessionID
		if id == "" {
			id = "(no session id)"
		}
		fmt.Fprintf(w, "session %s [%s]\n", terminalText(id), terminalText(s.SourceAgent))
		if s.ProjectPath != "" {
			fmt.Fprintf(w, "  project: %s\n", terminalText(s.ProjectPath))
		}
		if s.Start != "" || s.End != "" {
			fmt.Fprintf(w, "  span:    %s .. %s\n", terminalText(dashIfEmpty(s.Start)), terminalText(dashIfEmpty(s.End)))
		}
		fmt.Fprintf(w, "  events:  %d\n", len(s.Events))
		fmt.Fprintln(w, "  time                          event              actor      detail  [evidence]")
		for _, ev := range s.Events {
			fmt.Fprintf(w, "  %-29s %-18s %-10s %s  [%s]\n",
				terminalText(dashIfEmpty(ev.Timestamp)), terminalText(string(ev.EventType)),
				terminalText(dashIfEmpty(ev.Actor)), timelineDetail(stepDetail(ev)), terminalText(evidenceRef(ev)))
		}
	}
	return w.Flush()
}

const timelineDetailMax = 240

func timelineDetail(s string) string {
	s = terminalText(s)
	runes := []rune(s)
	if len(runes) <= timelineDetailMax {
		return s
	}
	return string(runes[:timelineDetailMax-3]) + "..."
}

func terminalText(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsControl(r) {
			b.WriteRune(r)
			continue
		}
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// stepDetail is the salient one-line description of an event for the text view:
// the field that says what happened, chosen by event_type so a reader sees the
// command, path, url, decision, or preview that matters for that step. It returns
// "-" when the event carries no such field, so a column always renders.
func stepDetail(ev model.Event) string {
	switch ev.EventType {
	case model.EventSessionStart, model.EventSessionEnd:
		if ev.SubAgent != "" {
			return "subagent: " + ev.SubAgent
		}
	case model.EventCommandExec, model.EventCommandResult:
		if ev.Command != "" {
			return ev.Command
		}
	case model.EventFileRead, model.EventFileWrite, model.EventFileDelete:
		if ev.FilePath != "" {
			return ev.FilePath
		}
	case model.EventNetworkIndicator:
		if ev.URL != "" {
			return ev.URL
		}
	case model.EventToolCall, model.EventToolResult:
		if ev.ToolName != "" {
			return ev.ToolName
		}
	case model.EventConfigAgent:
		if ev.SubAgent != "" {
			return ev.SubAgent
		}
	}
	// Fall back to the redacted preview (prompts, assistant turns) when present.
	if ev.ContentPreview != "" {
		return ev.ContentPreview
	}
	return "-"
}

// evidenceRef formats the locator a reader follows back to the source: the
// artifact path with a line or JSON pointer when the artifact has one. Content
// stays local — this points AT it, never reproduces it.
func evidenceRef(ev model.Event) string {
	e := ev.Evidence
	switch {
	case e.Line > 0:
		return fmt.Sprintf("%s:%d", e.LocalPath, e.Line)
	case e.JSONPointer != "":
		return e.LocalPath + e.JSONPointer
	default:
		return e.LocalPath
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
