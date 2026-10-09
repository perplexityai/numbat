package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/spool"
	"github.com/perplexityai/numbat/internal/version"
)

// --output sink names.
const (
	outputModeStdout = "stdout"
	outputModeFile   = "file"
	outputModeSpool  = "spool"
	outputModeHTTP   = "http"
)

func outputFlagHelp(defaultMode string) string {
	return fmt.Sprintf("where to write records: stdout, file, spool, or http (repeatable, default %s, stdout cannot be combined)", defaultMode)
}

// Environment variables carrying HTTP auth secrets. Secrets are never accepted
// as flags and never logged: the flag selects the auth mode, the secret value
// comes from the environment.
const (
	envHTTPToken   = "NUMBAT_HTTP_TOKEN"
	envHTTPHMACKey = "NUMBAT_HTTP_HMAC_KEY"
)

func printHTTPAuthEnvHelp(w io.Writer, liveIntegration bool) {
	if liveIntegration {
		fmt.Fprintln(w, "\nLive integrations read HTTP record-delivery auth secrets from their runtime")
		fmt.Fprintln(w, "environment, never from flags:")
	} else {
		fmt.Fprintln(w, "\nHTTP record-delivery auth secrets come from the environment, never flags:")
	}
	fmt.Fprintf(w, "  bearer: %s\n  hmac-sha256: %s\n", envHTTPToken, envHTTPHMACKey)
}

// sinkConfig is the parsed --output* flag set, validated by buildSink.
type sinkConfig struct {
	modes         []string
	defaultMode   string
	file          string
	spool         string
	httpURL       string
	httpBatch     int
	httpMaxBuffer int
	httpTimeout   time.Duration
	httpAuth      string
	httpSigHeader string
	httpTSHeader  string
	allowInsecure bool
	gzip          bool
	// httpFlagsSet lists the names of http-only flags the operator actually
	// passed (collected via flag.Visit, so a flag left at its default is not
	// counted). buildSink rejects any of them when the output does not include
	// http, since a flag with a non-empty default (e.g. --http-batch-size)
	// cannot be distinguished from "set" by its value alone.
	httpFlagsSet []string
	// appendFile selects an append (not truncate) file sink and creates the
	// parent directory. Live hook and collector paths set it so records
	// accumulate; scan leaves it false for a fresh output file per run.
	appendFile bool
}

// httpOnlyFlags are the flags that only have meaning when the output includes
// http. Passing any of them in a non-http mode is a mistake buildSink rejects
// rather than silently ignores. --http-url is handled separately (it is the
// http-mode requirement) so its cross-mode message stays specific.
var httpOnlyFlags = map[string]bool{
	"http-auth":             true,
	"http-batch-size":       true,
	"http-timeout":          true,
	"http-gzip":             true,
	"http-sig-header":       true,
	"http-timestamp-header": true,
	"http-allow-insecure":   true,
}

// buildSink validates the output flag combination and constructs the records
// sink. stdout (the default) wraps the provided writer without taking ownership
// of it. File, spool, and HTTP sinks require their respective flags. File and
// spool are mutually exclusive so one run has one durable local record stream.
// Cross-mode flags are rejected so a mistaken invocation fails loudly.
// HTTP auth secrets are read from the environment here, never from a flag.
func buildSink(cfg sinkConfig, stdout io.Writer) (output.Sink, error) {
	sel, err := parseOutputSinks(cfg.modes, cfg.defaultMode)
	if err != nil {
		return nil, err
	}

	if !sel.http {
		for _, name := range cfg.httpFlagsSet {
			if httpOnlyFlags[name] {
				return nil, fmt.Errorf("--%s is only valid when --output includes http", name)
			}
		}
	}
	if !sel.file && cfg.file != "" {
		return nil, fmt.Errorf("--output-file is only valid when --output includes file")
	}
	if !sel.spool && cfg.spool != "" {
		return nil, fmt.Errorf("--spool-file is only valid when --output includes spool")
	}
	if !sel.http && cfg.httpURL != "" {
		return nil, fmt.Errorf("--http-url is only valid when --output includes http")
	}

	if sel.stdout {
		if cfg.file != "" {
			return nil, fmt.Errorf("--output-file is only valid when --output includes file")
		}
		if cfg.httpURL != "" {
			return nil, fmt.Errorf("--http-url is only valid when --output includes http")
		}
		if cfg.spool != "" {
			return nil, fmt.Errorf("--spool-file is only valid when --output includes spool")
		}
		return stdoutSink{stdout}, nil
	}

	if sel.file && strings.TrimSpace(cfg.file) == "" {
		return nil, fmt.Errorf("--output including file requires --output-file PATH")
	}
	if sel.spool && strings.TrimSpace(cfg.spool) == "" {
		return nil, fmt.Errorf("--output including spool requires --spool-file PATH")
	}
	if sel.http {
		if err := validateHTTPAuthFlags(cfg.httpAuth, cfg.httpFlagsSet); err != nil {
			return nil, err
		}
	}

	// Validate and construct the side-effect-free HTTP sink before opening a
	// file sink. A bad URL or missing auth secret must not truncate an existing
	// output file when both destinations were requested.
	var httpSink output.Sink
	if sel.http {
		if cfg.httpURL == "" {
			return nil, fmt.Errorf("--output including http requires --http-url URL")
		}
		// Reject non-positive batch/timeout here rather than silently coercing to
		// a default: an operator who passes --http-batch-size 0 has made a
		// mistake, and quietly using 500 would hide it.
		if cfg.httpBatch <= 0 {
			return nil, fmt.Errorf("--http-batch-size must be a positive integer, got %d", cfg.httpBatch)
		}
		if cfg.httpTimeout <= 0 {
			return nil, fmt.Errorf("--http-timeout must be a positive duration, got %s", cfg.httpTimeout)
		}
		auth, err := httpAuthFromEnv(cfg.httpAuth)
		if err != nil {
			return nil, err
		}
		auth.HMACHeader = cfg.httpSigHeader
		auth.TimestampHeader = cfg.httpTSHeader
		httpSink, err = output.NewHTTPSink(output.HTTPConfig{
			URL:            cfg.httpURL,
			Auth:           auth,
			Timeout:        cfg.httpTimeout,
			BatchSize:      cfg.httpBatch,
			MaxBufferBytes: cfg.httpMaxBuffer,
			UserAgent:      model.ToolName + "/" + version.String(),
			AllowInsecure:  cfg.allowInsecure,
			Gzip:           cfg.gzip,
		})
		if err != nil {
			return nil, err
		}
	}

	var sinks []output.Sink
	if sel.file {
		if cfg.appendFile {
			s, err := output.NewFileSinkAppend(cfg.file)
			if err != nil {
				return nil, err
			}
			sinks = append(sinks, s)
		} else {
			s, err := output.NewFileSink(cfg.file)
			if err != nil {
				return nil, err
			}
			sinks = append(sinks, s)
		}
	}
	if sel.spool {
		sinks = append(sinks, spoolSink{store: spool.New(cfg.spool)})
	}
	if httpSink != nil {
		sinks = append(sinks, httpSink)
	}
	return output.NewMultiSink(sinks...), nil
}

func validateHTTPAuthFlags(auth string, flags []string) error {
	if auth == output.AuthHMAC {
		return nil
	}
	for _, name := range flags {
		if name == "http-sig-header" || name == "http-timestamp-header" {
			return fmt.Errorf("--%s requires --http-auth hmac-sha256", name)
		}
	}
	return nil
}

type outputSinks struct {
	stdout bool
	file   bool
	spool  bool
	http   bool
}

func (s outputSinks) canonicalModes() []string {
	if s.stdout {
		return []string{outputModeStdout}
	}
	var modes []string
	if s.file {
		modes = append(modes, outputModeFile)
	}
	if s.spool {
		modes = append(modes, outputModeSpool)
	}
	if s.http {
		modes = append(modes, outputModeHTTP)
	}
	return modes
}

func parseOutputSinks(values []string, defaultMode string) (outputSinks, error) {
	if defaultMode == "" {
		defaultMode = outputModeStdout
	}
	if len(values) == 0 {
		values = []string{defaultMode}
	}
	var sinks outputSinks
	seen := map[string]bool{}
	for _, raw := range values {
		mode := strings.TrimSpace(raw)
		if mode == "" {
			return outputSinks{}, invalidOutputError(raw)
		}
		if strings.Contains(mode, ",") {
			return outputSinks{}, fmt.Errorf("invalid --output %q: pass one sink per flag, e.g. --output file --output http", raw)
		}
		switch mode {
		case outputModeStdout:
			sinks.stdout = true
		case outputModeFile:
			sinks.file = true
		case outputModeSpool:
			sinks.spool = true
		case outputModeHTTP:
			sinks.http = true
		default:
			return outputSinks{}, invalidOutputError(raw)
		}
		if seen[mode] {
			return outputSinks{}, fmt.Errorf("invalid --output %q: duplicate %q", mode, mode)
		}
		seen[mode] = true
	}
	if len(seen) == 0 {
		return outputSinks{}, invalidOutputError("")
	}
	if sinks.stdout && len(seen) > 1 {
		return outputSinks{}, fmt.Errorf("invalid --output %q: stdout cannot be combined with file, spool, or http", strings.Join(values, " "))
	}
	if sinks.file && sinks.spool {
		return outputSinks{}, fmt.Errorf("invalid --output %q: file and spool cannot be combined", strings.Join(values, " "))
	}
	return sinks, nil
}

func invalidOutputError(raw string) error {
	return fmt.Errorf("invalid --output %q: want stdout, file, spool, or http", raw)
}

// httpAuthFromEnv maps the --http-auth mode onto an output.HTTPAuth, reading the
// secret from the environment for bearer/hmac. A selected mode with a missing
// secret is an error so a misconfigured run fails before sending anything.
func httpAuthFromEnv(mode string) (output.HTTPAuth, error) {
	switch mode {
	case "", output.AuthNone:
		return output.HTTPAuth{Mode: output.AuthNone}, nil
	case output.AuthBearer:
		tok := os.Getenv(envHTTPToken)
		if tok == "" {
			return output.HTTPAuth{}, fmt.Errorf("--http-auth=bearer requires %s in the environment", envHTTPToken)
		}
		return output.HTTPAuth{Mode: output.AuthBearer, Token: tok}, nil
	case output.AuthHMAC:
		key := os.Getenv(envHTTPHMACKey)
		if key == "" {
			return output.HTTPAuth{}, fmt.Errorf("--http-auth=hmac-sha256 requires %s in the environment", envHTTPHMACKey)
		}
		return output.HTTPAuth{Mode: output.AuthHMAC, HMACKey: []byte(key)}, nil
	default:
		return output.HTTPAuth{}, fmt.Errorf("invalid --http-auth %q: want none|bearer|hmac-sha256", mode)
	}
}

// stdoutSink adapts the process stdout writer to a Sink whose Close is a no-op,
// so the default path never closes os.Stdout.
type stdoutSink struct{ io.Writer }

func (stdoutSink) Close() error { return nil }

// spoolSink accepts exactly one complete, supported NDJSON record per Write.
// Put returns only after bbolt commits the whole value, so no repair path is
// needed after an interrupted hook process.
type spoolSink struct{ store spool.Store }

func (sink spoolSink) Write(p []byte) (int, error) {
	if len(p) == 0 || len(p) > maxShipRecordBytes || p[len(p)-1] != '\n' || bytes.Count(p, []byte("\n")) != 1 {
		return 0, fmt.Errorf("spool sink: record must be one complete NDJSON line of at most %d bytes", maxShipRecordBytes)
	}
	if !isShippableRecord(p[:len(p)-1]) {
		return 0, fmt.Errorf("spool sink: record must be a JSON object")
	}
	if err := sink.store.Put(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (spoolSink) Close() error { return nil }
