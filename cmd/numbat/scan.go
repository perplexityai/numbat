package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/discover"
	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
)

// runScan discovers artifacts, normalizes events, evaluates rules locally, and
// emits redacted NDJSON. Per-artifact failures are diagnostics and do not stop
// other inputs. Every attempted scan ends with one scan_summary record.
//
// Exit codes: 0 on a completed scan whose records were delivered (with or
// without findings); 2 on a usage error; 1 when no artifact source could be
// scanned, or when delivery failed (HTTP delivery or sink close).
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var paths multiFlag
	fs.Var(&paths, "path", "artifact file or directory to scan (repeatable; defaults to known agent locations under $HOME plus supported agent home/data env overrides)")
	var agents multiFlag
	fs.Var(&agents, "agent", "limit automatic discovery to a parser-backed agent (repeatable; cannot be combined with --path)")
	caseID := fs.String("case-id", "", "case identifier stamped on every emitted event and derived finding")
	var emitValues multiFlag
	fs.Var(&emitValues, "emit", emitFlagHelp())
	contentFlag := fs.String("content", "preview", contentFlagHelp())
	includeReasoning := fs.Bool("include-reasoning", false, "include source-recorded reasoning events")
	profileFlag := fs.String("profile", "", "deprecated capture profile: evidence|full (full enables --include-reasoning)")
	var outputValues multiFlag
	fs.Var(&outputValues, "output", outputFlagHelp(outputModeStdout))
	outputFile := fs.String("output-file", "", "destination path (required when --output includes file)")
	httpURL := fs.String("http-url", "", "ingest URL (required when --output includes http)")
	httpBatch := fs.Int("http-batch-size", 500, "records per HTTP POST")
	httpTimeout := fs.Duration("http-timeout", 30*time.Second, "HTTP request timeout")
	httpAuth := fs.String("http-auth", output.AuthNone, "HTTP delivery auth: none|bearer|hmac-sha256")
	httpSigHeader := fs.String("http-sig-header", output.DefaultHMACHeader, "header carrying the hmac-sha256 signature")
	httpTSHeader := fs.String("http-timestamp-header", output.DefaultTimestampHeader, "header carrying the signed timestamp (empty signs the bare body)")
	httpAllowInsecure := fs.Bool("http-allow-insecure", false, "allow plain http to non-loopback hosts")
	httpGzip := fs.Bool("http-gzip", false, "gzip the HTTP POST body")
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat scan [--agent NAME ... | --path FILE|DIR ...] [--case-id ID] [--emit KIND ...] [--content preview|full] [--include-reasoning] [--rules-dir DIR ...] [--no-builtin-rules] [--output SINK ...]")
		fmt.Fprintln(stderr, "\nScans supported on-disk agent artifacts and emits redacted findings, events, or indicators as NDJSON.")
		fmt.Fprintf(stderr, "Automatic-discovery agents: %s.\n", artifactAgentUsage())
		fmt.Fprintln(stderr, "Preserve vendor directory layouts when scanning copied or mounted artifacts.")
		printHTTPAuthEnvHelp(stderr, false)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "scan: unexpected argument %q; pass paths with --path\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	selectedAgents, err := parseArtifactAgents(agents)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}
	if len(paths) > 0 && len(selectedAgents) > 0 {
		fmt.Fprintln(stderr, "scan: --agent cannot be combined with --path")
		fs.Usage()
		return 2
	}

	sel, err := parseEmit(emitValues)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}
	content, err := parseContentMode(*contentFlag)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}
	reasoning, err := applyDeprecatedProfile(*profileFlag, *includeReasoning)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}
	if err := validateContentSelection(content, sel); err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}
	if rf.noBuiltin && len(rf.dirs) == 0 {
		fmt.Fprintln(stderr, "scan: --no-builtin-rules requires at least one --rules-dir")
		fs.Usage()
		return 2
	}

	// Resolve the output sink up front. A bad output/auth combination is a CLI
	// error (like --emit/--content above): it returns 2 without a scan_summary,
	// because no scan was attempted. stdout is the default sink and wraps the
	// provided writer without taking ownership of it.
	// Collect the http-only flags the operator actually passed, so buildSink can
	// reject any used when the output does not include http (a default-valued flag like
	// --http-batch-size is indistinguishable from "set" by its value alone).
	var httpFlagsSet []string
	fs.Visit(func(f *flag.Flag) {
		if httpOnlyFlags[f.Name] {
			httpFlagsSet = append(httpFlagsSet, f.Name)
		}
	})
	sinkCfg := sinkConfig{
		modes:         outputValues,
		defaultMode:   outputModeStdout,
		file:          *outputFile,
		httpURL:       *httpURL,
		httpBatch:     *httpBatch,
		httpTimeout:   *httpTimeout,
		httpAuth:      *httpAuth,
		httpSigHeader: *httpSigHeader,
		httpTSHeader:  *httpTSHeader,
		allowInsecure: *httpAllowInsecure,
		gzip:          *httpGzip,
		httpFlagsSet:  httpFlagsSet,
	}
	sink, err := buildSink(sinkCfg, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		fs.Usage()
		return 2
	}

	// Runtime failures get a summary; usage errors above do not start a scan.
	em := output.NewWithSink(sink, stderr, runID(), contentEmitterOptions(content)...)

	roots := []string(paths)
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return failScan(em, fmt.Sprintf("cannot resolve home directory: %v", err))
		}
		roots = discover.DefaultRootsFor(home, selectedAgents)
		if len(roots) == 0 {
			scope := ""
			if len(agents) > 0 {
				scope = fmt.Sprintf(" for --agent %s", strings.Join([]string(agents), ","))
			}
			return failScan(em, fmt.Sprintf("no agent artifacts found%s under %s; pass --path to scan a specific file or directory", scope, home))
		}
	}

	// Explicit rule sources are validated even when findings are not emitted.
	sources, err := loadRuleSources(rf.dirs, rf.noBuiltin)
	if err != nil {
		return failScan(em, err.Error())
	}
	// Explicit sources must compile in every emit mode; event-only defaults avoid
	// constructing an unused engine.
	var eng *rule.Engine
	if sel.findings || len(rf.dirs) > 0 || rf.noBuiltin {
		eng, err = compileEffectiveEngine(sources, rf.noBuiltin)
		if err != nil {
			return failScan(em, err.Error())
		}
	}
	captureContent := content == contentFull || sel.indicators || sel.findings && eng != nil && eng.UsesContent()

	sc := &scanner{
		emit:             em,
		caseID:           *caseID,
		sel:              sel,
		includeReasoning: reasoning,
		captureContent:   captureContent,
	}
	if sel.indicators {
		sc.indicators = output.NewIndicatorAccumulator()
	}
	sc.pipe = pipeline.New(eng, em, pipeline.Selection{
		Events:     sel.events,
		Findings:   sel.findings,
		Indicators: sel.indicators,
	}, finding.Options{}, sc.indicators)
	// One tracker spans the scan; it partitions artifact-backed windows by file.
	if sel.findings && eng != nil {
		if seqs := eng.SequenceRules(); len(seqs) > 0 {
			sc.pipe.WithSequences(sequence.NewTracker(seqs, sequence.DefaultConfig()))
		}
	}

	discovered := 0
	seenArtifacts := map[string]struct{}{}
	for _, root := range roots {
		arts, skips, err := discover.Walk(root)
		if err != nil {
			em.Diag("error", fmt.Sprintf("scan root %q: %v", root, err))
			continue
		}
		for _, sk := range skips {
			em.Diag("warn", fmt.Sprintf("skipped unreadable path %q: %v", sk.Path, sk.Err))
		}
		for _, a := range arts {
			key := a.DedupeKey()
			if _, seen := seenArtifacts[key]; seen {
				continue
			}
			seenArtifacts[key] = struct{}{}
			sc.scanArtifact(a)
			discovered++
		}
	}

	// Indicators are materialized after all artifacts contribute to the fold.
	if sel.indicators {
		for _, ind := range sc.indicators.Materialize() {
			if err := em.EmitIndicator(ind); err != nil {
				em.Diag("error", fmt.Sprintf("emit indicator %s=%s: %v", ind.Type, ind.Value, err))
			}
		}
	}

	// Emit run diagnostics before snapshotting summary counters.
	em.Diag("info", fmt.Sprintf("scan complete: %d discovered, %d parsed, %d findings", discovered, sc.parsed, em.Stats().FindingsEmitted))
	noArtifacts := discovered == 0
	if noArtifacts {
		em.Diag("error", "no agent artifacts found to scan")
	}

	st := em.Stats()
	recordDeliveryFailed := st.RecordErrors > 0

	// The terminal scan_summary is emitted last, so a receiver can bound
	// the run and decide whether to promote it. Status reflects whether the run
	// produced usable output: error if nothing was discovered or nothing parsed;
	// partial if some artifacts failed to parse or earlier record delivery failed;
	// complete only when every discovered artifact parsed and emitted cleanly
	// (per-event parse problems are diagnostics, not artifact failures).
	// ArtifactsScanned reports the successfully parsed count; it must not claim
	// files it could not read or decode.
	status := output.StatusComplete
	switch {
	case noArtifacts || sc.parsed == 0:
		status = output.StatusError
	case sc.failed > 0 || sel.indicators && sc.indicators.Truncated():
		status = output.StatusPartial
	}
	if recordDeliveryFailed && status == output.StatusComplete {
		status = output.StatusPartial
	}

	// Stamp any HTTP delivery stats observed so far and downgrade the status if a
	// batch already failed: a run with a failed POST is not a trustworthy
	// complete snapshot even if parsing succeeded. The very last batch (which
	// carries this summary) is delivered during emitter Close below; a failure
	// there is surfaced as a stderr diagnostic since the summary line is already
	// committed to the sink.
	summary := output.ScanSummary{
		Status:            status,
		ArtifactsScanned:  sc.parsed,
		EventsEmitted:     st.EventsEmitted,
		FindingsEmitted:   st.FindingsEmitted,
		IndicatorsEmitted: st.IndicatorsEmitted,
		Diagnostics:       st.Diagnostics,
	}
	applyHTTPStats(&summary, em.SinkStats())
	summaryDeliveryFailed := false
	if err := em.EmitSummary(summary); err != nil {
		em.Diag("error", fmt.Sprintf("emit scan summary: %v", err))
		summaryDeliveryFailed = true
	}

	deliveryFailed := recordDeliveryFailed || summaryDeliveryFailed || closeSink(em)
	httpFailed := summary.HTTPFailed != nil && *summary.HTTPFailed
	nothingParsed := sc.parsed == 0
	if noArtifacts || nothingParsed || httpFailed || deliveryFailed {
		return 1
	}
	return 0
}

// applyHTTPStats copies transport-side delivery counters onto the summary and
// marks HTTPFailed when any batch failed, so a receiver does not promote a run
// whose delivery was incomplete. It is a no-op for non-http sinks (HTTPTransport
// false). For an http run it always stamps the counters — even when no batch has
// flushed yet because every record fits in the final (summary-carrying) batch —
// so the absence of http_* fields unambiguously means "not an http run" rather
// than "http run with nothing delivered". The counters reflect only batches
// acknowledged before the summary batch; see ScanSummary for the full semantics.
func applyHTTPStats(s *output.ScanSummary, st output.SinkStats) {
	if !st.HTTPTransport {
		return
	}
	// Pointers so these emit as explicit (possibly zero) values for an http run;
	// a non-http run leaves them nil above so the keys are omitted entirely.
	batches := st.BatchesSucceeded
	records := st.RecordsSent
	last := st.LastStatus
	failed := st.BatchesFailed > 0
	s.HTTPBatchesSent = &batches
	s.HTTPRecordsSent = &records
	s.HTTPLastStatus = &last
	s.HTTPFailed = &failed
	if failed && s.Status == output.StatusComplete {
		s.Status = output.StatusPartial
	}
}

// closeSink closes the emitter's records sink, flushing the final batch (for
// the http sink, the POST carrying the scan_summary). A close error means that
// final delivery failed; because the summary line is already committed to the
// sink, the failure is surfaced as a stderr diagnostic so the operator sees it,
// and reported back to the caller so the run exits non-zero. Returns true on
// delivery failure. The diagnostic goes through the emitter (whose diagnostics
// writer is stderr), so a hard-down endpoint is still reported to the operator.
func closeSink(em *output.Emitter) bool {
	if err := em.Close(); err != nil {
		em.Diag("error", fmt.Sprintf("output delivery failed: %v", err))
		return true
	}
	return false
}

// failScan ends a scan that could not start (home-dir resolution, no discoverable
// roots, or rule-engine init failed) with the same terminal contract as a normal
// run: an error diagnostic, then exactly one scan_summary with status error so a
// receiver always sees a bounding record before the non-zero exit. The Stats
// snapshot is taken AFTER the diagnostic so the summary counts it.
func failScan(em *output.Emitter, msg string) int {
	em.Diag("error", msg)
	st := em.Stats()
	summary := output.ScanSummary{
		Status:            output.StatusError,
		EventsEmitted:     st.EventsEmitted,
		FindingsEmitted:   st.FindingsEmitted,
		IndicatorsEmitted: st.IndicatorsEmitted,
		Diagnostics:       st.Diagnostics,
	}
	applyHTTPStats(&summary, em.SinkStats())
	if err := em.EmitSummary(summary); err != nil {
		em.Diag("error", fmt.Sprintf("emit scan summary: %v", err))
	}
	closeSink(em)
	return 1
}

// emitSelection records which record kinds a scan should emit, parsed from the
// --emit flag. findings is the default; events and indicators are opt-in; "all"
// enables every kind.
type emitSelection struct {
	events     bool
	findings   bool
	indicators bool
}

// --emit values.
const (
	emitFindings   = "findings"
	emitEvents     = "events"
	emitIndicators = "indicators"
	emitAll        = "all"
)

func emitFlagHelp() string {
	return "record kind to emit: findings, events, indicators, or all (repeatable; default findings)"
}

// parseEmit validates the repeatable --emit flag and returns the selected record
// kinds. A bad value is an error so a typo fails loudly rather than silently
// emitting the default. The default (findings) emits finding records plus the
// terminal scan_summary; events and indicators are opt-in additional record
// types on the same stream. Whatever is selected, the stream is a record-type
// stream the consumer demultiplexes on record_type.
func parseEmit(values []string) (emitSelection, error) {
	if len(values) == 0 {
		values = []string{emitFindings}
	}
	var sel emitSelection
	seen := map[string]bool{}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return emitSelection{}, invalidEmitError(raw)
		}
		if strings.Contains(v, ",") {
			return emitSelection{}, fmt.Errorf("invalid --emit %q: pass one record kind per flag, e.g. --emit findings --emit indicators", raw)
		}
		if seen[v] {
			return emitSelection{}, fmt.Errorf("invalid --emit %q: duplicate %q", v, v)
		}
		seen[v] = true
		switch v {
		case emitFindings:
			sel.findings = true
		case emitEvents:
			sel.events = true
		case emitIndicators:
			sel.indicators = true
		case emitAll:
			sel = emitSelection{events: true, findings: true, indicators: true}
		default:
			return emitSelection{}, invalidEmitError(raw)
		}
	}
	if seen[emitAll] && len(seen) > 1 {
		return emitSelection{}, fmt.Errorf("invalid --emit %q: all cannot be combined with other record kinds", emitAll)
	}
	return sel, nil
}

func invalidEmitError(raw string) error {
	return fmt.Errorf("invalid --emit %q: want findings, events, indicators, or all", raw)
}

func (s emitSelection) canonicalModes() []string {
	if s.events && s.findings && s.indicators {
		return []string{emitAll}
	}
	var modes []string
	if s.findings {
		modes = append(modes, emitFindings)
	}
	if s.events {
		modes = append(modes, emitEvents)
	}
	if s.indicators {
		modes = append(modes, emitIndicators)
	}
	return modes
}

func (s emitSelection) defaultFindingsOnly() bool {
	return s.findings && !s.events && !s.indicators
}

// scanner holds per-run artifact-processing state.
type scanner struct {
	emit             *output.Emitter
	caseID           string
	sel              emitSelection
	includeReasoning bool
	captureContent   bool
	pipe             *pipeline.Pipeline
	indicators       *output.IndicatorAccumulator
	parsed           int
	failed           int
	// lookup is overridden only by tests.
	lookup func(agent string) (extract.Extractor, bool)
}

// scanArtifact parses one artifact. Failures are diagnosed and isolated from the
// rest of the scan; a panic fence also protects against malformed parser input.
func (s *scanner) scanArtifact(a discover.Artifact) {
	succeeded := false
	defer func() {
		if r := recover(); r != nil {
			// A failing diagnostic writer must not defeat the artifact panic fence.
			func() {
				defer func() { _ = recover() }()
				s.emit.Diag("error", fmt.Sprintf("skipped %q: recovered from panic (%T)", a.Path, r))
			}()
			if !succeeded {
				s.failed++
			}
		}
	}()

	lookup := s.lookup
	if lookup == nil {
		lookup = extract.For
	}
	ex, ok := lookup(a.Agent)
	if !ok {
		s.emit.Diag("warn", fmt.Sprintf("no extractor for agent %q (%s)", a.Agent, a.Path))
		s.failed++
		return
	}
	f, err := discover.OpenArtifact(a)
	if err != nil {
		s.emit.Diag("error", fmt.Sprintf("open %q: %v", a.Path, err))
		s.failed++
		return
	}
	defer f.Close()

	res, err := extract.SafeExtract(ex, f, extract.Source{
		Path:             a.Path,
		CaseID:           s.caseID,
		IncludeReasoning: s.includeReasoning,
		CaptureContent:   s.captureContent,
	})
	if err != nil {
		s.emit.Diag("error", fmt.Sprintf("parse %q: %v", a.Path, err))
		s.failed++
		return
	}
	for _, d := range res.Diagnostics {
		s.emit.Diag("warn", fmt.Sprintf("%s:%d: %s", d.Path, d.Line, d.Msg))
	}

	eventFailed := false
	for _, ev := range res.Events {
		if err := s.pipe.Process(ev, a.Path); err != nil {
			s.emit.Diag("error", err.Error())
			eventFailed = true
		}
	}
	if eventFailed {
		s.failed++
		return
	}
	// Count parsed only after the whole path completed cleanly: a panic in the
	// diagnostics walk or emit loop above is recovered and counted failed instead.
	succeeded = true
	s.parsed++
}

// multiFlag collects a repeatable string flag into a slice.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("value must not be empty")
	}
	*m = append(*m, v)
	return nil
}
