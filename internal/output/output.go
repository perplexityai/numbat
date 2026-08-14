// Package output emits the NDJSON record stream and diagnostics. Every record
// written to the records sink is one JSON object on its own line carrying a
// record_type discriminator (finding | event | enforcement | indicator |
// scan_summary) plus
// a run_id and schema_version envelope, so a single stream can be split by a
// downstream consumer. Diagnostics normally go to a separate writer (stderr by
// default); callers whose stderr is a control channel can route diagnostic
// records to the record sink instead.
// The emitter is safe for concurrent use.
package output

import (
	"encoding/json"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/redact"
)

// Record type discriminators stamped on every emitted line.
const (
	RecordFinding     = "finding"
	RecordEvent       = "event"
	RecordEnforcement = "enforcement"
	RecordIndicator   = "indicator"
	RecordScanSummary = "scan_summary"
	RecordDiagnostic  = "diagnostic"
)

// Diagnostic levels are the closed vocabulary published in the diagnostic JSON
// Schema. Diag normalizes any internal caller typo to info so emitted diagnostics
// remain schema-valid.
const (
	DiagnosticInfo  = "info"
	DiagnosticWarn  = "warn"
	DiagnosticError = "error"
)

// EnvDeviceID is an optional, operator-supplied stable endpoint/device identity
// stamped on emitted records as device_id. Keep the value opaque; it is for
// receiver-side joins, not display.
const EnvDeviceID = "NUMBAT_DEVICE_ID"

// Diagnostic is a non-finding operational message (info/warn/error).
type Diagnostic struct {
	SchemaVersion string   `json:"schema_version"`
	RecordType    string   `json:"record_type"`
	RunID         string   `json:"run_id"`
	Endpoint      Endpoint `json:"endpoint"`
	Timestamp     string   `json:"timestamp"`
	Level         string   `json:"level"`
	Message       string   `json:"message"`
}

// Endpoint identifies the user and host that emitted a record.
type Endpoint struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Username string `json:"username"`
	UID      string `json:"uid"`
	DeviceID string `json:"device_id,omitempty"`
}

// Indicator is one deduplicated enrichment indicator: a distinct value of a given
// type (domain, ipv4, ipv6, url, md5, sha1, sha256, email) mined from the
// observed event stream, with how often and when it was seen plus a sample event
// and session pivot. It is the enrichment-input projection an analyst runs
// through threat feeds — not a judgment of compromise. Values are redacted before
// extraction and canonical (lowercased hosts, default ports dropped);
// non-actionable noise (loopback and private IPs, *.local) is filtered out.
type Indicator struct {
	Type                  string `json:"type"`
	Value                 string `json:"value"`
	Count                 int    `json:"count"`
	FirstSeen             string `json:"first_seen,omitempty"`
	LastSeen              string `json:"last_seen,omitempty"`
	SampleSourceAgent     string `json:"source_agent,omitempty"`
	SampleEventID         string `json:"sample_event_id,omitempty"`
	SampleSessionID       string `json:"sample_session_id,omitempty"`
	SampleProjectPathHash string `json:"sample_project_path_hash,omitempty"`
}

// ScanSummary is the terminal record of a run. A receiver promotes a run to
// current state only on Status=="complete"; "partial" means records were
// emitted but a terminal error occurred, "error" means the run failed before
// producing usable output.
//
// The HTTP* fields are populated only when the http sink is used. If http_failed
// is true, at least one attempt failed; delivery may be incomplete or duplicated
// and the run must not be treated as complete.
//
// Delivery-counter semantics (important): the summary rides inside the final
// HTTP batch, so http_batches_sent and http_records_sent count only the batches
// acknowledged before this one — they cannot include the batch that carries the
// summary itself (it has not been POSTed when the line is serialized). The
// final batch's fate is reported two other ways: http_last_status carries the
// status of the most recent POST observed at serialization time, and a failure
// of the final POST is surfaced as a stderr diagnostic plus a non-zero exit by
// the caller. A receiver should therefore treat http_records_sent as "records
// acknowledged before the summary" rather than a grand total.
//
// The HTTP* fields are pointers so an http run can emit honest zero values
// (http_records_sent:0, http_last_status:0 meaning "failed before any response")
// while a stdout/file run omits the whole block: applyHTTPStats leaves them nil
// for a non-http sink, so the keys never appear and those summaries stay
// byte-identical to before sinks existed.
type ScanSummary struct {
	Status            string `json:"status"`
	ArtifactsScanned  int    `json:"artifacts_scanned"`
	EventsEmitted     int    `json:"events_emitted"`
	FindingsEmitted   int    `json:"findings_emitted"`
	IndicatorsEmitted int    `json:"indicators_emitted"`
	Diagnostics       int    `json:"diagnostics"`

	// HTTPBatchesSent is the number of batches acknowledged (2xx) before the
	// summary batch. HTTPRecordsSent is the NDJSON lines in those batches. Both
	// are nil (omitted) for non-http runs and non-nil (emitted, possibly zero)
	// for http runs.
	HTTPBatchesSent *int `json:"http_batches_sent,omitempty"`
	HTTPRecordsSent *int `json:"http_records_sent,omitempty"`
	// HTTPLastStatus is the status code of the most recent POST at serialization
	// time (0 if a POST failed before any response). HTTPFailed is true if any
	// batch failed; a true value means the run is not durably delivered. Both are
	// nil for non-http runs.
	HTTPLastStatus *int  `json:"http_last_status,omitempty"`
	HTTPFailed     *bool `json:"http_failed,omitempty"`
}

// Status values for ScanSummary.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusError    = "error"
)

// Sink is the transport a record stream is written to: an io.WriteCloser the
// emitter encodes one NDJSON line per record into. stdout and file sinks write
// synchronously; the http sink batches and POSTs. Sinks are pure transport —
// they never alter record content or reorder the stream beyond batching, so the
// terminal scan_summary stays the final record (and rides in the final batch).
type Sink interface {
	io.WriteCloser
}

// StatsReporter is implemented by sinks that carry transport-side delivery
// counters (the http sink). The scanner copies these into scan_summary without
// the output package depending on transport internals. SinkStats is defined
// alongside the http sink in httpsink.go.
type StatsReporter interface {
	Stats() SinkStats
}

// Emitter serializes records and diagnostics to their sinks.
type Emitter struct {
	runID    string
	endpoint Endpoint
	// fullContent is fixed by a constructor option before concurrent use.
	fullContent bool

	mu                sync.Mutex
	sink              Sink
	diags             *json.Encoder
	diagnosticsInSink bool
	eventsEmitted     int
	findingsEmitted   int
	indicatorsEmitted int
	diagnostics       int
	recordErrors      int
}

// EmitterOption configures an Emitter before it is used.
type EmitterOption func(*Emitter)

// WithFullContent includes redacted, bounded conversation content in event
// records. The default projection emits only content_preview.
func WithFullContent() EmitterOption {
	return func(e *Emitter) { e.fullContent = true }
}

// Stats is a point-in-time snapshot of emitter counters.
type Stats struct {
	EventsEmitted     int
	FindingsEmitted   int
	IndicatorsEmitted int
	Diagnostics       int
	RecordErrors      int
}

// New constructs an Emitter writing records to records and diagnostics to
// diags. runID is stamped on every emitted line for correlation. If records is
// already a Sink it is used directly; otherwise it is wrapped in a no-op-close
// adapter so a bare io.Writer (stdout, a test buffer) keeps working unchanged.
func New(records, diags io.Writer, runID string, opts ...EmitterOption) *Emitter {
	sink, ok := records.(Sink)
	if !ok {
		sink = nopCloseSink{records}
	}
	return NewWithSink(sink, diags, runID, opts...)
}

// NewWithSink constructs an Emitter writing records to an explicit Sink. The
// sink is closed by Emitter.Close (which must be called last, after the
// terminal scan_summary, so a batching sink flushes its final batch).
func NewWithSink(sink Sink, diags io.Writer, runID string, opts ...EmitterOption) *Emitter {
	e := &Emitter{
		runID:    runID,
		endpoint: defaultEndpoint(),
		sink:     sink,
		diags:    json.NewEncoder(diags),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// NewWithSinkAndDiagnostics constructs an Emitter that writes diagnostics as
// records on sink. It is for runtimes where stderr belongs to the invoking host
// rather than the operator.
func NewWithSinkAndDiagnostics(sink Sink, runID string, opts ...EmitterOption) *Emitter {
	e := &Emitter{
		runID:             runID,
		endpoint:          defaultEndpoint(),
		sink:              sink,
		diagnosticsInSink: true,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// nopCloseSink adapts a bare io.Writer to a Sink whose Close is a no-op, so the
// default stdout path and existing tests stay byte-identical.
type nopCloseSink struct{ io.Writer }

func (nopCloseSink) Close() error { return nil }

// emitLocked marshals payload, injects the record_type/run_id envelope, and
// writes the resulting object as one NDJSON line. The caller holds e.mu.
func (e *Emitter) emitLocked(recordType string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	fields["record_type"], _ = json.Marshal(recordType)
	fields["run_id"], _ = json.Marshal(e.runID)
	if raw, ok := fields["schema_version"]; !ok || string(raw) == `""` || string(raw) == "null" {
		fields["schema_version"], _ = json.Marshal(model.SchemaVersion)
	}
	fields["endpoint"], _ = json.Marshal(e.endpoint)
	line, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	n, err := e.sink.Write(line)
	if err != nil {
		return err
	}
	if n != len(line) {
		return io.ErrShortWrite
	}
	return nil
}

// EmitFinding writes one finding as an NDJSON line (record_type=finding).
func (e *Emitter) EmitFinding(f model.Finding) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.emitLocked(RecordFinding, f); err != nil {
		e.recordErrors++
		return err
	}
	e.findingsEmitted++
	return nil
}

// EmitEvent writes one normalized event as an NDJSON line (record_type=event).
// The event is redacted on the way out (redact.Event), masking secret-like
// values while preserving useful evidence context.
// Rules have already evaluated the unredacted event upstream, so this affects
// output only, never detection.
func (e *Emitter) EmitEvent(ev model.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var projected model.Event
	if e.fullContent {
		projected = redact.EventWithContent(ev)
	} else {
		projected = redact.Event(ev)
	}
	if err := e.emitLocked(RecordEvent, projected); err != nil {
		e.recordErrors++
		return err
	}
	e.eventsEmitted++
	return nil
}

// EmitEnforcement writes one computed decision for a matched pre-action hook.
// Unlike a finding, this record states whether Numbat selected its deny
// contract or left the host's permission flow unchanged.
func (e *Emitter) EmitEnforcement(decision model.EnforcementDecision) error {
	if err := decision.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.emitLocked(RecordEnforcement, decision); err != nil {
		e.recordErrors++
		return err
	}
	return nil
}

// EmitIndicator writes one indicator as an NDJSON line (record_type=indicator).
func (e *Emitter) EmitIndicator(ind Indicator) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.emitLocked(RecordIndicator, ind); err != nil {
		e.recordErrors++
		return err
	}
	e.indicatorsEmitted++
	return nil
}

// EmitSummary writes the terminal scan_summary record. It is called once, last,
// after every other record has been emitted.
func (e *Emitter) EmitSummary(s ScanSummary) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.emitLocked(RecordScanSummary, s); err != nil {
		e.recordErrors++
		return err
	}
	return nil
}

// Diag writes a diagnostic line at the given level.
func (e *Emitter) Diag(level, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	diagnostic := Diagnostic{
		SchemaVersion: model.SchemaVersion,
		RecordType:    RecordDiagnostic,
		RunID:         e.runID,
		Endpoint:      e.endpoint,
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:         normalizeDiagnosticLevel(level),
		Message:       msg,
	}
	if e.diagnosticsInSink {
		if err := e.emitLocked(RecordDiagnostic, diagnostic); err != nil {
			e.recordErrors++
		}
	} else {
		_ = e.diags.Encode(diagnostic)
	}
	e.diagnostics++
}

func normalizeDiagnosticLevel(level string) string {
	switch level {
	case DiagnosticInfo, DiagnosticWarn, DiagnosticError:
		return level
	default:
		return DiagnosticInfo
	}
}

// Stats returns a consistent snapshot of the emitter counters. It takes the
// lock so it is safe to call while other goroutines are emitting.
func (e *Emitter) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{
		EventsEmitted:     e.eventsEmitted,
		FindingsEmitted:   e.findingsEmitted,
		IndicatorsEmitted: e.indicatorsEmitted,
		Diagnostics:       e.diagnostics,
		RecordErrors:      e.recordErrors,
	}
}

// SinkStats returns the transport-side delivery counters if the records sink
// reports them (the http sink), or a zero value otherwise. It is read after the
// summary batch is queued but reflects only batches the sink has flushed; the
// final batch is delivered during Close.
func (e *Emitter) SinkStats() SinkStats {
	if r, ok := e.sink.(StatsReporter); ok {
		return r.Stats()
	}
	return SinkStats{}
}

func defaultEndpoint() Endpoint {
	endpoint := Endpoint{
		Hostname: hostName(),
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		DeviceID: deviceID(),
	}
	if current, err := user.Current(); err == nil {
		endpoint.Username = strings.TrimSpace(current.Username)
		endpoint.UID = strings.TrimSpace(current.Uid)
	}
	return endpoint
}

func hostName() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return ""
	}
	return strings.TrimSpace(name)
}

func deviceID() string {
	return strings.TrimSpace(os.Getenv(EnvDeviceID))
}

// Close closes the records sink, flushing any buffered batch (the http sink's
// final POST, including the terminal scan_summary). It must be called once,
// after EmitSummary. A separate diagnostics writer, when configured, is left
// open; its caller retains ownership.
func (e *Emitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sink.Close()
}
