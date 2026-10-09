package output

// HTTPSink is an optional output target that batches NDJSON record lines in
// memory and POSTs them to a generic HTTPS endpoint. It is transport-agnostic:
// no vendor schema, headers, or signing scheme is assumed. Operators point it
// at whatever receiver they run (a self-hosted relay, a log collector that
// accepts custom JSON, a small forwarder to object storage).
//
// It satisfies io.WriteCloser so it drops in where Emitter expects a records
// writer: output.New(httpSink, os.Stderr, runID). Each Encode from the emitter
// is one complete NDJSON line; lines buffer until BatchSize is reached, then
// flush as a single application/x-ndjson POST. Close flushes the remainder.

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Auth modes for the http sink. Secrets for bearer/hmac come from the
// environment only (see cmd/numbat), never from a flag, and are never logged.
const (
	AuthNone   = "none"
	AuthBearer = "bearer"
	AuthHMAC   = "hmac-sha256"
)

const (
	defaultBatchSize      = 500
	defaultTimeout        = 30 * time.Second
	defaultMaxBufferBytes = 16 << 20
	defaultRetryInterval  = 30 * time.Second
	contentTypeNDJSON     = "application/x-ndjson"
	maxResponseRequestID  = 128
	maxResponseBodyDrain  = 64 << 10

	// DefaultHMACHeader and DefaultTimestampHeader are numbat's default HMAC
	// header names, exported so the CLI can use them as flag defaults. They are
	// numbat-specific names; see applyAuth.
	DefaultHMACHeader      = "X-Numbat-Signature"
	DefaultTimestampHeader = "X-Numbat-Timestamp"
)

// HTTPAuth describes how an HTTPSink authenticates each request. Secrets are
// supplied by the caller (read from the environment); this package never reads
// them and never logs them.
type HTTPAuth struct {
	// Mode is one of AuthNone, AuthBearer, or AuthHMAC.
	Mode string
	// Token is the bearer token (Mode == AuthBearer).
	Token string
	// HMACKey is the shared secret bytes (Mode == AuthHMAC).
	HMACKey []byte
	// HMACHeader carries the hex signature. Defaults to DefaultHMACHeader when
	// empty (an unnamed header is never sent).
	HMACHeader string
	// TimestampHeader, if non-empty, receives the unix-seconds timestamp that is
	// also prefixed onto the signed payload as "<ts>.<body>". Empty means sign
	// the bare body and send no timestamp; it is NOT defaulted, so a caller can
	// deliberately choose bare-body signing.
	TimestampHeader string
}

// HTTPConfig configures an HTTPSink. The zero value is invalid; URL is
// required. Unset BatchSize/Timeout fall back to sane defaults.
type HTTPConfig struct {
	URL       string
	Auth      HTTPAuth
	Timeout   time.Duration
	BatchSize int
	// MaxBufferBytes bounds the in-memory NDJSON batch buffer. The sink normally
	// flushes by BatchSize, but this cap also protects long-running receivers when
	// a destination fails and records continue to arrive. Zero uses a safe default.
	MaxBufferBytes int
	UserAgent      string
	// AllowInsecure permits plain http:// to non-loopback hosts. Off by
	// default; loopback is always allowed so local testing needs no flag.
	AllowInsecure bool
	// Gzip compresses the POST body; Content-Encoding: gzip is set and the
	// Content-Type stays application/x-ndjson. When Mode is AuthHMAC the
	// signature is computed over the compressed (on-the-wire) bytes, so a
	// receiver verifies the HMAC against the raw body, then decompresses.
	Gzip bool
	// HTTPClient is used for the POST; tests inject a stub. Defaults to a
	// client with Timeout.
	HTTPClient *http.Client
}

// SinkStats reports best-effort delivery counters. RecordsSent counts NDJSON
// lines acknowledged in 2xx batches. LastStatus is the most recent HTTP status
// (0 = the last batch failed before any response was received). HTTPTransport is
// true whenever these stats come from the http sink. PendingFailure means the
// buffer is waiting for a retry after a failed POST.
type SinkStats struct {
	HTTPTransport    bool
	PendingFailure   bool
	BatchesAttempted int
	BatchesSucceeded int
	BatchesFailed    int
	RecordsSent      int
	RecordsDropped   int
	BytesDropped     int
	LastStatus       int
}

// HTTPSink batches NDJSON lines and delivers them over HTTP.
type HTTPSink struct {
	cfg    HTTPConfig
	client *http.Client

	mu             sync.Mutex
	buf            bytes.Buffer
	inBatch        int
	err            error
	pendingFailure bool
	retryAfter     time.Time
	now            func() time.Time
	retryInterval  time.Duration
	closed         bool
	stats          SinkStats
}

type httpStatusError struct {
	statusCode int
	requestID  string
}

func (e *httpStatusError) Error() string {
	if e.requestID != "" {
		return fmt.Sprintf("http sink: server returned %d %s (request-id %q)", e.statusCode, http.StatusText(e.statusCode), e.requestID)
	}
	return fmt.Sprintf("http sink: server returned %d %s", e.statusCode, http.StatusText(e.statusCode))
}

// HTTPStatusCode returns the response status carried by an HTTP sink error.
func HTTPStatusCode(err error) (int, bool) {
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) {
		return 0, false
	}
	return statusErr.statusCode, true
}

// NewHTTPSink validates cfg and constructs the sink.
func NewHTTPSink(cfg HTTPConfig) (*HTTPSink, error) {
	if err := validateHTTPConfig(&cfg); err != nil {
		return nil, err
	}
	client := http.Client{Timeout: cfg.Timeout}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	client.Timeout = cfg.Timeout
	// Never follow redirects: a 307/308 would otherwise replay the NDJSON body
	// and its bearer/HMAC headers to a different origin.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPSink{
		cfg:           cfg,
		client:        &client,
		now:           time.Now,
		retryInterval: defaultRetryInterval,
	}, nil
}

func validateHTTPConfig(cfg *HTTPConfig) error {
	if cfg.URL == "" {
		return errors.New("http sink: url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		// Do not wrap err: Go's url.Parse error text frequently quotes the raw
		// input, which may carry userinfo credentials. Return a scrubbed message.
		return errors.New("http sink: invalid url")
	}
	switch u.Scheme {
	case "https", "http":
	default:
		return fmt.Errorf("http sink: url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return errors.New("http sink: url must include a host")
	}
	if u.Scheme == "http" && !cfg.AllowInsecure && !isLoopbackHost(u.Hostname()) {
		return errors.New("http sink: refusing plain http to non-loopback host; use https or set --http-allow-insecure for testing")
	}
	// Reject embedded credentials. Go turns https://user:pass@host into an HTTP
	// Basic Authorization header, which would make --http-url a second
	// secret-bearing flag — exactly the env-only-secrets policy this sink
	// enforces. The error is scrubbed so the secret never echoes to a log.
	if u.User != nil {
		return errors.New("http sink: url must not contain embedded credentials; pass auth via --http-auth with env secrets")
	}
	switch cfg.Auth.Mode {
	case "", AuthNone:
		cfg.Auth.Mode = AuthNone
	case AuthBearer:
		if cfg.Auth.Token == "" {
			return errors.New("http sink: bearer auth requires a token")
		}
		if !validHTTPHeaderValue(cfg.Auth.Token) {
			return errors.New("http sink: bearer token contains an invalid control character")
		}
	case AuthHMAC:
		if len(cfg.Auth.HMACKey) == 0 {
			return errors.New("http sink: hmac-sha256 auth requires a key")
		}
		// An empty signature header would set a header with no name; default it.
		// TimestampHeader is intentionally not defaulted: an empty value is a
		// valid choice meaning "sign the bare body, send no timestamp" (the stock
		// bare-body verifier default). The CLI supplies its own non-empty default.
		if cfg.Auth.HMACHeader == "" {
			cfg.Auth.HMACHeader = DefaultHMACHeader
		}
		if !validHTTPHeaderName(cfg.Auth.HMACHeader) {
			return fmt.Errorf("http sink: invalid signature header name %q", cfg.Auth.HMACHeader)
		}
		if cfg.Auth.TimestampHeader != "" {
			if !validHTTPHeaderName(cfg.Auth.TimestampHeader) {
				return fmt.Errorf("http sink: invalid timestamp header name %q", cfg.Auth.TimestampHeader)
			}
			if strings.EqualFold(cfg.Auth.HMACHeader, cfg.Auth.TimestampHeader) {
				return errors.New("http sink: signature and timestamp headers must be different")
			}
		}
	default:
		return fmt.Errorf("http sink: unknown auth mode %q", cfg.Auth.Mode)
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxBufferBytes <= 0 {
		cfg.MaxBufferBytes = defaultMaxBufferBytes
	}
	return nil
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHTTPHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// responseRequestID returns a correlation id from a non-2xx response if the
// receiver set one, so an operator can match the failure to receiver-side logs
// without numbat reflecting any attacker-influenced body content.
func responseRequestID(h http.Header) string {
	for _, k := range []string{"X-Request-Id", "X-Request-ID", "Request-Id"} {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			runes := []rune(v)
			if len(runes) > maxResponseRequestID {
				v = string(runes[:maxResponseRequestID]) + "..."
			}
			return v
		}
	}
	return ""
}

// Write appends NDJSON bytes (one complete line per emitter Encode) and
// flushes when the batch is full. It reports all bytes accepted so the
// json.Encoder never sees a short write.
func (h *HTTPSink) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0, errors.New("http sink: write after close")
	}
	h.retryIfDueLocked()
	if err := h.ensureRoomLocked(len(p)); err != nil {
		if h.err == nil {
			h.err = err
		}
		h.stats.RecordsDropped += bytes.Count(p, []byte{'\n'})
		h.stats.BytesDropped += len(p)
		return 0, err
	}
	// Always buffer, even once a batch has failed and h.err is latched: the
	// records written after a failure (notably the terminal scan_summary) must
	// stay queued so Close can make a final best-effort delivery attempt that gives
	// the receiver a bounding record. The buffer is still bounded; after a delivery
	// failure the oldest whole records are dropped when needed so long-running
	// collect processes cannot grow memory without limit.
	//
	// Once bytes are accepted into the buffer they are not reported as a
	// per-record write error, even when a flush fails or the sink is already
	// latched: the record is queued for the final Close delivery, so surfacing a
	// failure here would make the emitter undercount *_emitted and log spurious
	// per-record "emit ..." diagnostics for records that may still be delivered.
	// The delivery failure stays latched in h.err and is reported authoritatively
	// by Stats() (http_failed) and Close() (non-zero exit).
	n, _ := h.buf.Write(p)
	h.inBatch += bytes.Count(p, []byte{'\n'})
	if !h.pendingFailure && h.inBatch >= h.cfg.BatchSize {
		_ = h.attemptFlushLocked()
	}
	return n, nil
}

// Close flushes any buffered lines. It is idempotent.
//
// If a mid-stream batch already failed (h.err is latched), Close still makes one
// best-effort attempt to deliver whatever is buffered — which includes the
// terminal scan_summary appended after the failure. That gives the receiver a
// bounding record (carrying status=partial / http_failed) instead of a silently
// truncated stream. The original latched error is returned regardless of whether
// that final POST succeeds, so the caller still exits non-zero.
func (h *HTTPSink) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.buf.Len() > 0 {
		_ = h.attemptFlushLocked()
	}
	if h.err == nil {
		return nil
	}
	if h.stats.RecordsDropped > 0 || h.stats.BytesDropped > 0 {
		return errors.Join(h.err, fmt.Errorf("http sink: dropped %d buffered records (%d bytes) after delivery failure; buffer limit %d bytes", h.stats.RecordsDropped, h.stats.BytesDropped, h.cfg.MaxBufferBytes))
	}
	return h.err
}

// Stats returns a snapshot of delivery counters.
func (h *HTTPSink) Stats() SinkStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.stats
	s.HTTPTransport = true
	s.PendingFailure = h.pendingFailure
	return s
}

// ensureRoomLocked makes space for the next record without letting the in-memory
// buffer grow past MaxBufferBytes. Before any delivery failure, it flushes the
// current batch early to free space. After a failure, it cannot rely on delivery,
// so it drops the oldest complete NDJSON records and keeps the newest tail (where
// a terminal scan_summary is written) for the final Close retry.
func (h *HTTPSink) ensureRoomLocked(n int) error {
	if n > h.cfg.MaxBufferBytes {
		return fmt.Errorf("http sink: record exceeds %d-byte buffer limit", h.cfg.MaxBufferBytes)
	}
	if h.buf.Len()+n <= h.cfg.MaxBufferBytes {
		return nil
	}
	if !h.pendingFailure && h.buf.Len() > 0 {
		_ = h.attemptFlushLocked()
		if h.buf.Len()+n <= h.cfg.MaxBufferBytes {
			return nil
		}
	}
	h.dropOldestLocked(h.buf.Len() + n - h.cfg.MaxBufferBytes)
	return nil
}

func (h *HTTPSink) retryIfDueLocked() {
	if !h.pendingFailure || h.buf.Len() == 0 || h.now().Before(h.retryAfter) {
		return
	}
	_ = h.attemptFlushLocked()
}

func (h *HTTPSink) attemptFlushLocked() error {
	err := h.flushLocked()
	if err != nil {
		if h.err == nil {
			h.err = err
		}
		h.pendingFailure = true
		h.retryAfter = h.now().Add(h.retryInterval)
		return err
	}
	h.pendingFailure = false
	h.retryAfter = time.Time{}
	return nil
}

// dropOldestLocked removes at least need bytes, rounded up to the next newline so
// the buffer remains a valid NDJSON suffix.
func (h *HTTPSink) dropOldestLocked(need int) {
	b := h.buf.Bytes()
	if need > len(b) {
		need = len(b)
	}
	cut := len(b)
	if need > 0 && b[need-1] == '\n' {
		cut = need
	} else if i := bytes.IndexByte(b[need:], '\n'); i >= 0 {
		cut = need + i + 1
	}
	dropped := bytes.Clone(b[:cut])
	kept := bytes.Clone(b[cut:])
	h.buf.Reset()
	_, _ = h.buf.Write(kept)
	droppedRecords := bytes.Count(dropped, []byte{'\n'})
	h.inBatch -= droppedRecords
	if h.inBatch < 0 {
		h.inBatch = 0
	}
	h.stats.RecordsDropped += droppedRecords
	h.stats.BytesDropped += len(dropped)
}

// flushLocked POSTs the buffered batch. The buffer is cleared ONLY on a 2xx
// response: if the POST fails, the bytes stay buffered so a later flush (notably
// the final flush in Close, which carries the terminal scan_summary) can retry
// delivering them. This is what lets a mid-stream failure still get a bounding
// summary to the receiver rather than dropping the batch on the floor.
func (h *HTTPSink) flushLocked() error {
	lines := h.inBatch
	body := bytes.Clone(h.buf.Bytes())

	wireBody := body
	if h.cfg.Gzip {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		if _, werr := zw.Write(body); werr != nil {
			return fmt.Errorf("http sink: gzip: %w", werr)
		}
		if cerr := zw.Close(); cerr != nil {
			return fmt.Errorf("http sink: gzip close: %w", cerr)
		}
		wireBody = gz.Bytes()
	}

	req, err := http.NewRequest(http.MethodPost, h.cfg.URL, bytes.NewReader(wireBody))
	if err != nil {
		return errors.New("http sink: build request failed")
	}
	req.Header.Set("Content-Type", contentTypeNDJSON)
	if h.cfg.Gzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if h.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", h.cfg.UserAgent)
	}
	if err := applyAuth(req, h.cfg.Auth, wireBody); err != nil {
		return err
	}

	h.stats.BatchesAttempted++
	resp, err := h.client.Do(req)
	if err != nil {
		h.stats.BatchesFailed++
		h.stats.LastStatus = 0
		return fmt.Errorf("http sink: post failed: %v", requestErrorCause(err))
	}
	defer resp.Body.Close()
	h.stats.LastStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.stats.BatchesFailed++
		// Discard the body rather than echo it: a hostile or buggy receiver could
		// otherwise reflect arbitrary content into numbat's stderr diagnostics.
		// Surface only the status and, when present, a request-id header an
		// operator can correlate against receiver logs.
		drainResponseBody(resp.Body)
		return &httpStatusError{
			statusCode: resp.StatusCode,
			requestID:  responseRequestID(resp.Header),
		}
	}
	drainResponseBody(resp.Body)
	h.stats.BatchesSucceeded++
	h.stats.RecordsSent += lines
	// Delivered: only now drop the bytes so a failed POST above leaves them
	// buffered for a retry by the next flush.
	h.buf.Reset()
	h.inBatch = 0
	return nil
}

func requestErrorCause(err error) error {
	for range 8 {
		var urlErr *url.Error
		if !errors.As(err, &urlErr) || urlErr.Err == nil {
			break
		}
		err = urlErr.Err
	}
	return err
}

func drainResponseBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxResponseBodyDrain))
}

// applyAuth sets the auth headers for one request. For AuthHMAC the signature
// is HMAC-SHA256 over the raw (on-the-wire) body, hex-encoded and sent as
// "sha256=<hex>"; when a timestamp header is configured the signed payload is
// prefixed "<unix-seconds>.<body>".
//
// This is a conventional HMAC signing algorithm, but numbat ships its own default
// header names (X-Numbat-Signature / X-Numbat-Timestamp). Point a receiver at the
// same header names, or override them with --http-sig-header /
// --http-timestamp-header to match whatever verifier you run.
func applyAuth(req *http.Request, a HTTPAuth, body []byte) error {
	switch a.Mode {
	case AuthNone:
		return nil
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+a.Token)
		return nil
	case AuthHMAC:
		signedPayload := body
		if a.TimestampHeader != "" {
			ts := strconv.FormatInt(time.Now().Unix(), 10)
			req.Header.Set(a.TimestampHeader, ts)
			signedPayload = append([]byte(ts+"."), body...)
		}
		mac := hmac.New(sha256.New, a.HMACKey)
		mac.Write(signedPayload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set(a.HMACHeader, "sha256="+sig)
		return nil
	default:
		// Unreachable: validateHTTPConfig normalizes "" to AuthNone and rejects
		// any other unknown mode before a sink is built. Kept as a defensive
		// guard so a future caller bypassing validation fails closed.
		return fmt.Errorf("http sink: unknown auth mode %q", a.Mode)
	}
}
