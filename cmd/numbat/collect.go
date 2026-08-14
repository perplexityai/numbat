package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/perplexityai/numbat/internal/finding"
	"github.com/perplexityai/numbat/internal/otel"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/pipeline"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
)

// defaultOTLPAddr is the documented OTLP/HTTP default endpoint. Agents point at
// it via OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318. numbat binds the
// loopback interface by default so live telemetry never leaves the machine.
const defaultOTLPAddr = "127.0.0.1:4318"

// otlpLogsPath is the OTLP/HTTP logs signal path. Traces (/v1/traces) and gRPC
// (:4317) are intentionally out of scope for this HTTP logs receiver.
const otlpLogsPath = "/v1/logs"

// contentTypeProtobuf is the OTLP/HTTP protobuf content type, the documented
// harness default this receiver consumes.
const contentTypeProtobuf = "application/x-protobuf"

// maxOTLPBody bounds a single OTLP POST so a malformed or hostile body cannot
// exhaust memory. 4 MiB comfortably holds a normal export batch.
const maxOTLPBody = 4 << 20

// runCollect implements `numbat collect`: a long-running, in-process OTLP/HTTP
// receiver. It listens on a loopback address (default :4318), decodes each
// incoming OTLP logs export, maps every record into a model.Event
// (source_type=otel), and runs it through the same shared pipeline scan and
// hooks use, emitting the selected record stream via the existing --output
// machinery.
// It runs until SIGINT/SIGTERM, then shuts the listener down gracefully so an
// in-flight export completes.
func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultOTLPAddr, "OTLP/HTTP listen address")
	caseID := fs.String("case-id", "", "case identifier stamped on every emitted event and derived finding")
	var emitValues multiFlag
	fs.Var(&emitValues, "emit", emitFlagHelp())
	contentFlag := fs.String("content", "preview", contentFlagHelp())
	var outputValues multiFlag
	fs.Var(&outputValues, "output", outputFlagHelp(outputModeStdout))
	outputFile := fs.String("output-file", "", "destination path (required when --output includes file)")
	httpURL := fs.String("http-url", "", "ingest URL (required when --output includes http)")
	httpBatch := fs.Int("http-batch-size", 500, "records per HTTP POST")
	httpTimeout := fs.Duration("http-timeout", 30*time.Second, "HTTP request timeout")
	httpAuth := fs.String("http-auth", output.AuthNone, "HTTP delivery auth: none|bearer|hmac-sha256")
	httpSigHeader := fs.String("http-sig-header", output.DefaultHMACHeader, "header carrying the hmac-sha256 signature")
	httpTSHeader := fs.String("http-timestamp-header", output.DefaultTimestampHeader, "header carrying the signed timestamp")
	httpAllowInsecure := fs.Bool("http-allow-insecure", false, "allow plain http to non-loopback hosts")
	httpGzip := fs.Bool("http-gzip", false, "gzip the HTTP POST body")
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat collect [--addr 127.0.0.1:4318] [--emit KIND ...] [--content preview|full] [--output SINK ...] [--case-id ID] [--rules-dir DIR ...] [--no-builtin-rules]")
		fmt.Fprintln(stderr, "\nReceives live OTLP/HTTP protobuf logs from supported AI agents and emits")
		fmt.Fprintln(stderr, "selected records through the shared detection pipeline.")
		fmt.Fprintln(stderr, "\nAt the default address, send logs to http://"+defaultOTLPAddr+otlpLogsPath+".")
		fmt.Fprintln(stderr, "Exporter setup varies by agent; see docs/cli.md#collect.")
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
		fmt.Fprintf(stderr, "collect: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	sel, err := parseEmit(emitValues)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		fs.Usage()
		return 2
	}
	content, err := parseContentMode(*contentFlag)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		fs.Usage()
		return 2
	}
	if err := validateContentSelection(content, sel); err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		fs.Usage()
		return 2
	}
	if rf.noBuiltin && len(rf.dirs) == 0 {
		fmt.Fprintln(stderr, "collect: --no-builtin-rules requires at least one --rules-dir")
		fs.Usage()
		return 2
	}

	var httpFlagsSet []string
	fs.Visit(func(f *flag.Flag) {
		if httpOnlyFlags[f.Name] {
			httpFlagsSet = append(httpFlagsSet, f.Name)
		}
	})
	sink, err := buildSink(sinkConfig{
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
		// Live telemetry accumulates over the receiver's lifetime; like the hook
		// path, findings must append to the durable file, not truncate it.
		appendFile: true,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		fs.Usage()
		return 2
	}

	rid := runID()
	em := output.NewWithSink(sink, stderr, rid, contentEmitterOptions(content)...)
	rcv, err := newCollector(collectorConfig{
		emit:      em,
		runID:     rid,
		caseID:    *caseID,
		sel:       sel,
		ruleDirs:  rf.dirs,
		noBuiltin: rf.noBuiltin,
	})
	if err != nil {
		fmt.Fprintf(stderr, "collect: %v\n", err)
		_ = em.Close()
		return 1
	}

	// SIGINT/SIGTERM trigger a graceful shutdown: stop accepting, let an in-flight
	// export finish, then drain the sink.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	code := serveCollect(ctx, *addr, rcv, stderr)
	if recordErrors := em.Stats().RecordErrors; recordErrors > 0 {
		fmt.Fprintf(stderr, "collect: output delivery failed: %d record write(s) failed\n", recordErrors)
		if code == 0 {
			code = 1
		}
	}
	if err := em.Close(); err != nil {
		fmt.Fprintf(stderr, "collect: output delivery failed: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// serveCollect binds the listener, prints the startup line, and serves OTLP/HTTP
// until ctx is cancelled (a signal) or the listener fails. On cancellation it
// shuts the server down with a bounded grace period so an in-flight export
// completes. It returns the process exit code: 0 on a clean signal-driven stop,
// 1 if the listener could not bind or serve.
func serveCollect(ctx context.Context, addr string, rcv *collector, stderr io.Writer) int {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(stderr, "collect: listen %s: %v\n", addr, err)
		return 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc(otlpLogsPath, rcv.handleLogs)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	warnIfOffLoopback(addr, stderr)

	fmt.Fprintf(stderr, "numbat collect: listening for OTLP/HTTP logs on http://%s%s (Ctrl-C to stop)\n", ln.Addr(), otlpLogsPath)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		// Graceful shutdown: stop accepting new connections and give in-flight
		// requests a bounded window to finish before forcing the listener closed.
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			_ = srv.Close()
			fmt.Fprintf(stderr, "collect: shutdown: %v\n", err)
			return 1
		}
		rcv.emit.Diag("info", fmt.Sprintf("collect stopped: %d records processed, %d skipped", rcv.processed(), rcv.skipped()))
		return 0
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "collect: serve: %v\n", err)
			return 1
		}
		return 0
	}
}

// warnIfOffLoopback prints a loud stderr warning when addr binds anything other
// than loopback. The receiver is unauthenticated by design (it trusts a local
// agent's telemetry), so exposing it on a routable interface lets any host on the
// network inject events; the default 127.0.0.1 keeps live telemetry on the
// machine. We warn rather than hard-block so an operator who deliberately fronts
// it with their own auth/proxy is not prevented from doing so.
func warnIfOffLoopback(addr string, stderr io.Writer) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	// An empty host (":4318") binds every interface; an explicit non-loopback IP
	// or hostname is off-loopback too. Only a loopback IP is safe by default.
	if host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return
		}
		if strings.EqualFold(host, "localhost") {
			return
		}
	}
	fmt.Fprintf(stderr, "numbat collect: WARNING: binding %s exposes an UNAUTHENTICATED OTLP receiver off-loopback; any host that can reach this address can inject telemetry. Bind 127.0.0.1 or front it with your own authentication.\n", addr)
}

// collectorConfig carries the resolved dependencies a collector needs.
type collectorConfig struct {
	emit      *output.Emitter
	runID     string
	caseID    string
	sel       emitSelection
	ruleDirs  multiFlag
	noBuiltin bool
}

// collector holds the per-receiver state: the shared pipeline every record flows
// through and the running counters reported at shutdown. The OTLP handler maps
// each record to a model.Event and hands it to the pipeline, exactly as the hook
// handler and scanner do, so detection is identical across sensors.
type collector struct {
	emit          *output.Emitter
	runID         string
	caseID        string
	pipe          *pipeline.Pipeline
	indicators    *output.IndicatorAccumulator
	indicatorsSel bool
	processMu     sync.Mutex
	indicatorMu   sync.Mutex
	emittedCounts map[string]int
	deliveryDown  bool

	processedN atomic.Int64
	skippedN   atomic.Int64
	decodedN   atomic.Int64
}

// newCollector builds the shared pipeline for the receiver: it compiles the rule
// engine when findings are evaluated (mirroring scan/hook), wires the indicator
// accumulator when indicators are selected, and constructs the Pipeline with the
// same Selection scan uses.
func newCollector(cfg collectorConfig) (*collector, error) {
	rid := cfg.runID
	if rid == "" {
		rid = runID()
	}
	c := &collector{emit: cfg.emit, caseID: cfg.caseID, indicatorsSel: cfg.sel.indicators, runID: rid}

	var eng *rule.Engine
	if cfg.sel.findings || len(cfg.ruleDirs) > 0 || cfg.noBuiltin {
		var err error
		eng, err = buildEngine(cfg.ruleDirs, cfg.noBuiltin)
		if err != nil {
			return nil, err
		}
	}
	if cfg.sel.indicators {
		c.indicators = output.NewIndicatorAccumulator()
		c.emittedCounts = make(map[string]int)
	}
	c.pipe = pipeline.New(eng, cfg.emit, pipeline.Selection{
		Events:     cfg.sel.events,
		Findings:   cfg.sel.findings,
		Indicators: cfg.sel.indicators,
	}, finding.Options{}, c.indicators)
	// Sequence rules correlate across the receiver's lifetime: one tracker for
	// the whole run, internally locked, so the concurrent OTLP handlers feed
	// session windows safely. Only built when findings are evaluated and the
	// load actually contains sequence rules.
	if cfg.sel.findings && eng != nil {
		if seqs := eng.SequenceRules(); len(seqs) > 0 {
			c.pipe.WithSequences(sequence.NewTracker(seqs, sequence.DefaultConfig()))
		}
	}
	return c, nil
}

// handleLogs is the OTLP/HTTP logs endpoint. It validates the method and content
// type, reads the (bounded) protobuf body, decodes it, maps each record, and
// runs the mapped events through the shared pipeline. It always answers with a
// well-formed OTLP-style status: 200 with an empty ExportLogsServiceResponse on
// success, 4xx on a client error (bad method/content-type/body). A decode
// failure is a client error (the exporter sent a malformed batch), never a
// crash.
func (c *collector) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOTLPError(w, http.StatusMethodNotAllowed, "method not allowed: use POST")
		return
	}
	if !isProtobufContentType(r.Header.Get("Content-Type")) {
		writeOTLPError(w, http.StatusUnsupportedMediaType, "unsupported content-type: want "+contentTypeProtobuf)
		return
	}
	body, status, msg := readOTLPBody(w, r)
	if status != 0 {
		writeOTLPError(w, status, msg)
		return
	}

	batchID := otlpBatchID(c.runID, body)
	results, err := otel.MapRecords(body, func(i int) string {
		c.decodedN.Add(1)
		return otlpEventID(batchID, i)
	})
	if err != nil {
		// A malformed protobuf is the exporter's mistake; report it as a 400 so a
		// misconfigured agent surfaces the problem, and never crash the receiver.
		c.emit.Diag("warn", fmt.Sprintf("collect: decode OTLP logs: %v", err))
		writeOTLPError(w, http.StatusBadRequest, "malformed OTLP logs protobuf")
		return
	}

	// Pipeline state, output ordering, and the emitter error counter are shared
	// across handlers. Serialize only processing so a sink failure is attributed
	// to the export that caused it; body reads and protobuf decoding stay parallel.
	c.processMu.Lock()
	defer c.processMu.Unlock()

	recordErrorsBefore := c.emit.Stats().RecordErrors
	rejected := int64(0)
	noAnalog := 0
	for _, res := range results {
		if res.Ignored {
			continue
		}
		if !res.Mapped {
			c.skippedN.Add(1)
			rejected++
			noAnalog++
			continue
		}
		ev := res.Event
		if ev.CaseID == "" {
			ev.CaseID = c.caseID
		}
		if err := c.pipe.Process(ev, "otel:"+res.SourceAgent); err != nil {
			c.skippedN.Add(1)
			rejected++
			c.emit.Diag("warn", "collect: "+err.Error())
			continue
		}
		c.processedN.Add(1)
	}

	if c.indicatorsSel {
		c.emitChangedIndicators()
	}
	if noAnalog > 0 {
		c.emit.Diag("info", fmt.Sprintf("collect: skipped %d record(s) with no normalized event analog", noAnalog))
	}
	sinkStats := c.emit.SinkStats()
	if sinkStats.PendingFailure != c.deliveryDown {
		if sinkStats.PendingFailure {
			c.emit.Diag("error", "collect: direct HTTP output unavailable; returning 503 until delivery recovers")
		} else {
			c.emit.Diag("info", "collect: direct HTTP output recovered")
		}
		c.deliveryDown = sinkStats.PendingFailure
	}
	if c.emit.Stats().RecordErrors > recordErrorsBefore || sinkStats.PendingFailure {
		writeOTLPError(w, http.StatusServiceUnavailable, "record delivery failed; retry the export")
		return
	}
	if rejected > 0 {
		writeOTLPPartialSuccess(w, rejected, "some log records had no normalized event analog or failed event validation")
		return
	}

	writeOTLPSuccess(w)
}

// emitChangedIndicators emits each indicator on first sight and again only
// when its cumulative observation count changes.
func (c *collector) emitChangedIndicators() {
	c.indicatorMu.Lock()
	defer c.indicatorMu.Unlock()
	for _, ind := range c.indicators.Materialize() {
		key := ind.Type + "\x00" + ind.Value
		if c.emittedCounts[key] == ind.Count {
			continue
		}
		if err := c.emit.EmitIndicator(ind); err != nil {
			c.emit.Diag("error", fmt.Sprintf("collect: emit indicator %s=%s: %v", ind.Type, ind.Value, err))
			continue
		}
		c.emittedCounts[key] = ind.Count
	}
}

func (c *collector) processed() int64 { return c.processedN.Load() }
func (c *collector) skipped() int64   { return c.skippedN.Load() }

// otlpBatchID identifies a byte-identical export within one collector run. An
// exporter retry therefore reuses event/finding ids and can be deduplicated,
// while a later run remains a distinct observation.
func otlpBatchID(run string, body []byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, run)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	return run + "-" + hex.EncodeToString(h.Sum(nil)[:12])
}

func otlpEventID(batchID string, index int) string {
	return fmt.Sprintf("otel-%s-%d", batchID, index+1)
}

// isProtobufContentType reports whether the Content-Type names OTLP protobuf,
// tolerating a charset/parameter suffix.
func isProtobufContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, contentTypeProtobuf)
}

// readOTLPBody accepts the mandatory OTLP request encodings (identity and
// gzip), bounding both the wire body and the decompressed protobuf payload.
func readOTLPBody(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOTLPBody)
	var reader io.Reader = r.Body
	var compressed io.Closer
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		if !strings.EqualFold(encoding, "gzip") {
			return nil, http.StatusUnsupportedMediaType, "unsupported content-encoding: want gzip or identity"
		}
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, http.StatusBadRequest, "invalid gzip body"
		}
		compressed = gz
		reader = gz
	}

	body, err := io.ReadAll(io.LimitReader(reader, maxOTLPBody+1))
	if compressed != nil {
		err = errors.Join(err, compressed.Close())
	}
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("body exceeds %d-byte limit", maxOTLPBody)
		}
		return nil, http.StatusBadRequest, "invalid request body"
	}
	if len(body) > maxOTLPBody {
		return nil, http.StatusRequestEntityTooLarge, fmt.Sprintf("decompressed body exceeds %d-byte limit", maxOTLPBody)
	}
	return body, 0, ""
}

// writeOTLPSuccess writes the success response: 200 with an empty (zero-field)
// ExportLogsServiceResponse protobuf, which is a zero-length body — the valid
// encoding of a message with no partial_success set. An OTLP client treats a 200
// with an empty body as full success.
func writeOTLPSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentTypeProtobuf)
	w.WriteHeader(http.StatusOK)
	// Empty ExportLogsServiceResponse == zero bytes; nothing to write.
}

// writeOTLPPartialSuccess reports a valid request whose records were only
// partly accepted. ExportLogsServiceResponse.partial_success is field 1;
// ExportLogsPartialSuccess contains rejected_log_records (field 1) and
// error_message (field 2).
func writeOTLPPartialSuccess(w http.ResponseWriter, rejected int64, msg string) {
	partial := protowire.AppendTag(nil, 1, protowire.VarintType)
	partial = protowire.AppendVarint(partial, uint64(rejected))
	partial = protowire.AppendTag(partial, 2, protowire.BytesType)
	partial = protowire.AppendString(partial, msg)
	body := protowire.AppendTag(nil, 1, protowire.BytesType)
	body = protowire.AppendBytes(body, partial)
	w.Header().Set("Content-Type", contentTypeProtobuf)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// writeOTLPError writes the google.rpc.Status protobuf body OTLP requires for
// non-2xx responses. Status.message is field 2; Status.code may be omitted.
func writeOTLPError(w http.ResponseWriter, status int, msg string) {
	body := protowire.AppendTag(nil, 2, protowire.BytesType)
	body = protowire.AppendString(body, msg)
	w.Header().Set("Content-Type", contentTypeProtobuf)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
