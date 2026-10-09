// Package casebundle builds and verifies case.numbat bundles: portable,
// self-describing directories that carry one case's findings, their enforcement
// decisions, the events those findings cite, and a manifest of sha256 digests.
//
// A bundle is plain NDJSON plus one JSON manifest, with no database.
// Records are copied from the operator's captured record streams byte-for-byte
// (the original emitted lines are the evidence; re-marshaling would alter
// them), deduplicated by their deterministic ids, and sorted into a reproducible
// record order. The manifest still records the build time.
//
// Safe by default: a bundle contains findings, cited events, and digests —
// never copies of raw evidence files. Copying cited files (which can hold
// .env contents, keys, or transcripts) is a per-build opt-in, raw or redacted.
//
// The manifest's digests prove integrity: that the bundle is self-consistent
// and unmodified since it was written. They do not prove authenticity or
// origin: there is no signing, and anyone can rebuild a manifest. Wording in
// the CLI and docs keeps that distinction explicit.
package casebundle

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
	"github.com/perplexityai/numbat/internal/redact"
	"github.com/perplexityai/numbat/internal/version"
)

// maxRecordLine bounds one NDJSON input line, matching the fixture reader's
// cap so a corrupt stream cannot exhaust memory.
const (
	maxRecordLine                 = 64 * 1024 * 1024
	maxEvidenceLine               = 16 * 1024 * 1024
	maxJSONEvidenceBytes          = 64 * 1024 * 1024
	maxResultWarnings             = 100
	maxGeneralResultWarnings      = 80
	maxMalformedWarningsPerSource = 3
)

// EvidenceMode selects whether cited evidence files are copied into the
// bundle. The default is None: refs and digests travel, file contents do not.
type EvidenceMode int

const (
	EvidenceNone EvidenceMode = iota
	// EvidenceRaw copies each cited file verbatim into evidence/.
	EvidenceRaw
	// EvidenceRedacted applies best-effort masking while keeping supported
	// structured evidence parseable.
	EvidenceRedacted
)

func (m EvidenceMode) String() string {
	switch m {
	case EvidenceNone:
		return "none"
	case EvidenceRaw:
		return "raw"
	case EvidenceRedacted:
		return "redacted"
	default:
		return ""
	}
}

// Options configures one bundle build.
type Options struct {
	// CaseID selects the findings to bundle (their case_id field).
	CaseID string
	// Out is the bundle directory to create. It must not already exist —
	// Build never overwrites.
	Out string
	// Sources are NDJSON record-stream files previously captured from scan,
	// collect, or hook with an output file.
	Sources []string
	// Evidence selects evidence-file copying; default None.
	Evidence EvidenceMode
	// Now stamps the manifest's created_at. A zero value uses time.Now();
	// tests inject it for deterministic output.
	Now time.Time
}

// Result reports what one build wrote.
type Result struct {
	Findings      int
	Enforcements  int
	Events        int
	EvidenceFiles int
	// Warnings are non-fatal problems: unparseable input lines, cited
	// events that are absent, or evidence files that are missing or changed.
	Warnings []string
}

func (r *Result) warn(msg string) {
	r.appendWarning(msg, maxGeneralResultWarnings, "additional warnings suppressed")
}

func (r *Result) warnEvidence(msg string) {
	r.appendWarning(msg, maxResultWarnings, "additional evidence warnings suppressed")
}

func (r *Result) appendWarning(msg string, limit int, suppressed string) {
	if len(r.Warnings) < limit-1 {
		r.Warnings = append(r.Warnings, msg)
		return
	}
	if len(r.Warnings) == limit-1 {
		r.Warnings = append(r.Warnings, suppressed)
	}
}

// Manifest is the bundle's integrity index, written as manifest.json. Its
// digests prove self-consistency only — see the package comment.
type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	CaseID        string         `json:"case_id"`
	CreatedAt     string         `json:"created_at"`
	Tool          string         `json:"tool"`
	ToolVersion   string         `json:"tool_version"`
	EvidenceMode  string         `json:"evidence_mode"`
	Files         []ManifestFile `json:"files"`
}

// ManifestFile is one bundle file's integrity record.
type ManifestFile struct {
	// Path is bundle-relative, slash-separated.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	// Records is the NDJSON line count, for the record files.
	Records int `json:"records,omitempty"`
	// SourcePath is the local path an evidence copy was taken from.
	SourcePath string `json:"source_path,omitempty"`
	// SourceSHA256 hashes the source bytes before any redaction.
	SourceSHA256 string `json:"source_sha256,omitempty"`
}

// manifestName is the one non-record file every bundle carries.
const manifestName = "manifest.json"

// record is a kept input line with its sort key. Raw is the original emitted
// bytes, preserved verbatim.
type record struct {
	timestamp string
	id        string
	raw       []byte
}

// probe is the minimal parse of one stream line: enough to route by record
// type, filter by case, and key deduplication — the line itself stays raw.
type probe struct {
	RecordType    string           `json:"record_type"`
	SchemaVersion string           `json:"schema_version"`
	CaseID        string           `json:"case_id"`
	FindingID     string           `json:"finding_id"`
	DecisionID    string           `json:"decision_id"`
	EventID       string           `json:"event_id"`
	Timestamp     string           `json:"timestamp"`
	EvidenceRefs  []model.Evidence `json:"evidence_refs"`
	CitedEventIDs []string         `json:"cited_event_ids"`
	Evidence      model.Evidence   `json:"evidence"`
}

// findingCitation keeps the first emitted finding bytes and the identity of
// the events and artifacts that finding cites.
type findingCitation struct {
	first         record
	evidenceRefs  []model.Evidence
	citedEventIDs []string
	semantic      []byte
}

// Build assembles a bundle from the source streams. It reads the sources
// twice — findings first, then the events those findings cite — so memory
// holds only kept records, never the whole stream. The output directory is
// created only after the first pass proves the case has findings; a case id
// matching nothing is an error, not an empty bundle.
func Build(opts Options) (Result, error) {
	var res Result
	if strings.TrimSpace(opts.CaseID) == "" {
		return res, fmt.Errorf("casebundle: empty case id")
	}
	if len(opts.Sources) == 0 {
		return res, fmt.Errorf("casebundle: no source record streams")
	}
	if strings.TrimSpace(opts.Out) == "" {
		return res, fmt.Errorf("casebundle: empty output path")
	}
	switch opts.Evidence {
	case EvidenceNone, EvidenceRaw, EvidenceRedacted:
	default:
		return res, fmt.Errorf("casebundle: invalid evidence mode %d", opts.Evidence)
	}
	if err := ensureBundleDestinationAbsent(opts.Out); err != nil {
		return res, err
	}

	findings, refs, citedEventIDs, err := collectFindings(opts, &res)
	if err != nil {
		return res, err
	}
	if len(findings) == 0 {
		return res, fmt.Errorf("casebundle: no findings with case_id %q in the sources", opts.CaseID)
	}
	events, err := collectCitedEvents(opts, citedEventIDs, &res)
	if err != nil {
		return res, err
	}
	enforcements, err := collectEnforcements(opts, &res)
	if err != nil {
		return res, err
	}

	evidenceFiles := 0
	if err := publishBundle(opts.Out, func(stage string) error {
		stagedOpts := opts
		stagedOpts.Out = stage
		var files []ManifestFile
		recordFiles := []struct {
			name string
			recs []record
		}{
			{"findings.ndjson", findings},
			{"events.ndjson", events},
		}
		if len(enforcements) > 0 {
			recordFiles = append(recordFiles, struct {
				name string
				recs []record
			}{"enforcements.ndjson", enforcements})
		}
		for _, f := range recordFiles {
			mf, err := writeRecords(stage, f.name, f.recs)
			if err != nil {
				return err
			}
			files = append(files, mf)
		}

		if opts.Evidence != EvidenceNone {
			evFiles, err := copyEvidence(stagedOpts, refs, &res)
			if err != nil {
				return err
			}
			files = append(files, evFiles...)
			evidenceFiles = len(evFiles)
		}
		return writeManifest(stagedOpts, files)
	}); err != nil {
		return res, err
	}
	res.Findings = len(findings)
	res.Enforcements = len(enforcements)
	res.Events = len(events)
	res.EvidenceFiles = evidenceFiles
	return res, nil
}

// collectEnforcements keeps case-scoped decisions byte-for-byte. Decision ids
// are unique per hook callback; conflicting duplicates are rejected rather
// than arbitrarily choosing one policy result.
func collectEnforcements(opts Options, res *Result) ([]record, error) {
	byID := make(map[string]record)
	semanticByID := make(map[string][]byte)
	conflictingID := ""
	var semanticErr error
	err := eachLine(opts.Sources, res, false, func(p probe, raw []byte) {
		if semanticErr != nil || p.RecordType != output.RecordEnforcement || p.CaseID != opts.CaseID {
			return
		}
		if p.SchemaVersion != model.SchemaVersion {
			res.warn(fmt.Sprintf("enforcement decision %q uses unsupported schema_version %q; skipped", p.DecisionID, p.SchemaVersion))
			return
		}
		if p.DecisionID == "" {
			res.warn("matching enforcement record with empty decision_id skipped")
			return
		}
		semantic, err := canonicalRecord(raw, "run_id", "timestamp")
		if err != nil {
			semanticErr = fmt.Errorf("casebundle: parse enforcement decision %q: %w", p.DecisionID, err)
			return
		}
		if previous, ok := semanticByID[p.DecisionID]; ok {
			if conflictingID == "" && !bytes.Equal(previous, semantic) {
				conflictingID = p.DecisionID
			}
			return
		}
		semanticByID[p.DecisionID] = semantic
		byID[p.DecisionID] = record{timestamp: p.Timestamp, id: p.DecisionID, raw: append([]byte(nil), raw...)}
	})
	if err != nil {
		return nil, err
	}
	if semanticErr != nil {
		return nil, semanticErr
	}
	if conflictingID != "" {
		return nil, fmt.Errorf("casebundle: duplicate enforcement decision %q has conflicting content", conflictingID)
	}
	decisions := make([]record, 0, len(byID))
	for _, decision := range byID {
		decisions = append(decisions, decision)
	}
	sortRecords(decisions)
	return decisions, nil
}

func ensureBundleDestinationAbsent(out string) error {
	_, err := os.Lstat(out)
	switch {
	case err == nil:
		return fmt.Errorf("casebundle: %q already exists; refusing to overwrite", out)
	case os.IsNotExist(err):
		return nil
	default:
		return fmt.Errorf("casebundle: inspect %q: %w", out, err)
	}
}

// publishBundle builds in a sibling staging directory and renames it into place
// only after every file and the manifest have been written successfully.
func publishBundle(out string, build func(stage string) error) error {
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("casebundle: create parent for %q: %w", out, err)
	}
	stage, err := os.MkdirTemp(parent, ".numbat-case-*.tmp")
	if err != nil {
		return fmt.Errorf("casebundle: create staging directory: %w", err)
	}
	defer func() {
		if stage != "" {
			_ = os.RemoveAll(stage)
		}
	}()

	if err := build(stage); err != nil {
		return err
	}
	if err := renameNoReplace(stage, out); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("casebundle: %q already exists; refusing to overwrite", out)
		}
		return fmt.Errorf("casebundle: publish %q: %w", out, err)
	}
	stage = ""
	return nil
}

// collectFindings keeps the first line for each finding_id and rejects duplicate
// ids whose semantic content differs. Run id and detection time are envelope
// fields.
func collectFindings(opts Options, res *Result) ([]record, map[model.Evidence]struct{}, map[string]struct{}, error) {
	byID := map[string]*findingCitation{}
	conflictingID := ""
	var semanticErr error
	err := eachLine(opts.Sources, res, true, func(p probe, raw []byte) {
		if semanticErr != nil {
			return
		}
		if p.RecordType != output.RecordFinding || p.CaseID != opts.CaseID {
			return
		}
		if p.SchemaVersion != model.SchemaVersion {
			res.warn(fmt.Sprintf("finding %q uses unsupported schema_version %q; skipped", p.FindingID, p.SchemaVersion))
			return
		}
		if p.FindingID == "" {
			res.warn("matching finding with empty finding_id skipped")
			return
		}
		semantic, err := canonicalRecord(raw, "run_id", "detected_at")
		if err != nil {
			semanticErr = fmt.Errorf("casebundle: parse finding %q: %w", p.FindingID, err)
			return
		}
		fc := byID[p.FindingID]
		if fc == nil {
			fc = &findingCitation{
				first:         record{timestamp: p.Timestamp, id: p.FindingID, raw: append([]byte(nil), raw...)},
				evidenceRefs:  append([]model.Evidence(nil), p.EvidenceRefs...),
				citedEventIDs: append([]string(nil), p.CitedEventIDs...),
				semantic:      semantic,
			}
			byID[p.FindingID] = fc
			return
		}
		if conflictingID == "" && !bytes.Equal(fc.semantic, semantic) {
			conflictingID = p.FindingID
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if semanticErr != nil {
		return nil, nil, nil, semanticErr
	}
	if conflictingID != "" {
		return nil, nil, nil, fmt.Errorf("casebundle: duplicate finding %q has conflicting content", conflictingID)
	}

	findings := make([]record, 0, len(byID))
	refs := map[model.Evidence]struct{}{}
	citedEventIDs := map[string]struct{}{}
	for _, fc := range byID {
		findings = append(findings, fc.first)
		for _, ref := range fc.evidenceRefs {
			refs[ref] = struct{}{}
		}
		for _, id := range fc.citedEventIDs {
			if id != "" {
				citedEventIDs[id] = struct{}{}
			}
		}
		if len(fc.citedEventIDs) == 0 {
			res.warn(fmt.Sprintf("finding %q has no cited_event_ids; its events cannot be resolved", fc.first.id))
		}
	}
	sortRecords(findings)
	return findings, refs, citedEventIDs, nil
}

// collectCitedEvents keeps cited events, rejects conflicting duplicate ids, and
// reports citations absent from the input streams.
func collectCitedEvents(opts Options, citedEventIDs map[string]struct{}, res *Result) ([]record, error) {
	var (
		events      []record
		seen        = map[string][]byte{}
		conflictID  string
		semanticErr error
	)
	err := eachLine(opts.Sources, res, false, func(p probe, raw []byte) {
		if semanticErr != nil {
			return
		}
		if p.RecordType != output.RecordEvent {
			return
		}
		if _, cited := citedEventIDs[p.EventID]; !cited {
			return
		}
		if p.SchemaVersion != model.SchemaVersion {
			res.warn(fmt.Sprintf("cited event %q uses unsupported schema_version %q; skipped", p.EventID, p.SchemaVersion))
			return
		}
		if p.CaseID != "" && p.CaseID != opts.CaseID {
			res.warn(fmt.Sprintf("cited event %q belongs to case_id %q; skipped", p.EventID, p.CaseID))
			return
		}
		if p.EventID == "" {
			res.warn("cited event with empty event_id skipped")
			return
		}
		semantic, err := canonicalRecord(raw, "run_id")
		if err != nil {
			semanticErr = fmt.Errorf("casebundle: parse event %q: %w", p.EventID, err)
			return
		}
		if previous, dup := seen[p.EventID]; dup {
			if conflictID == "" && !bytes.Equal(previous, semantic) {
				conflictID = p.EventID
			}
			return
		}
		seen[p.EventID] = semantic
		events = append(events, record{timestamp: p.Timestamp, id: p.EventID, raw: append([]byte(nil), raw...)})
	})
	if err != nil {
		return nil, err
	}
	if semanticErr != nil {
		return nil, semanticErr
	}
	if conflictID != "" {
		return nil, fmt.Errorf("casebundle: duplicate event %q has conflicting content", conflictID)
	}
	if missing := len(citedEventIDs) - len(seen); missing > 0 {
		res.warn(fmt.Sprintf("%d cited event(s) were not found in the source streams; events.ndjson is incomplete", missing))
	}
	sortRecords(events)
	return events, nil
}

func canonicalRecord(raw []byte, ignore ...string) ([]byte, error) {
	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return nil, err
	}
	for _, field := range ignore {
		delete(fields, field)
	}
	return json.Marshal(fields)
}

func isThinLiveEvidence(ev model.Evidence) bool {
	if ev.ArtifactType != model.SourceHook && ev.ArtifactType != model.SourceOTel {
		return false
	}
	return ev.Line == 0 && ev.RowID == 0 && ev.JSONPointer == "" && ev.SHA256 == ""
}

// eachLine streams every source line through fn. raw is the scanner's buffer,
// valid only during the call — fn copies the lines it keeps. A line that does
// not parse as a record is a warning, not an error — a forensic read keeps
// going — but an unreadable source file fails the build: silently bundling
// from half the inputs would misrepresent the case.
func eachLine(sources []string, res *Result, warnMalformed bool, fn func(p probe, raw []byte)) error {
	for _, src := range sources {
		f, err := openRegularFile(src)
		if err != nil {
			return fmt.Errorf("casebundle: %w", err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), maxRecordLine)
		line := 0
		malformed := 0
		for sc.Scan() {
			line++
			raw := sc.Bytes()
			if len(raw) == 0 {
				continue
			}
			var p probe
			if err := json.Unmarshal(raw, &p); err != nil {
				if warnMalformed {
					malformed++
					if malformed <= maxMalformedWarningsPerSource {
						res.warn(fmt.Sprintf("%s:%d: not a record: %v", src, line, err))
					}
				}
				continue
			}
			fn(p, raw)
		}
		scanErr := sc.Err()
		if closeErr := f.Close(); scanErr == nil {
			scanErr = closeErr
		}
		if scanErr != nil {
			return fmt.Errorf("casebundle: read %q: %w", src, scanErr)
		}
		if suppressed := malformed - maxMalformedWarningsPerSource; suppressed > 0 {
			res.warn(fmt.Sprintf("%s: %d additional malformed records suppressed", src, suppressed))
		}
	}
	return nil
}

// sortRecords fixes the bundle order: timestamp ascending, then id — a total
// order over deduplicated records, so identical inputs yield identical files.
func sortRecords(recs []record) {
	sort.Slice(recs, func(i, j int) bool {
		if cmp := model.CompareTimestamps(recs[i].timestamp, recs[j].timestamp); cmp != 0 {
			return cmp < 0
		}
		return recs[i].id < recs[j].id
	})
}

// writeRecords writes one NDJSON bundle file and returns its manifest entry.
func writeRecords(dir, name string, recs []record) (ManifestFile, error) {
	h := sha256.New()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("casebundle: %w", err)
	}
	w := io.MultiWriter(f, h)
	var writeErr error
	for _, r := range recs {
		if _, writeErr = w.Write(r.raw); writeErr == nil {
			_, writeErr = w.Write([]byte{'\n'})
		}
		if writeErr != nil {
			break
		}
	}
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return ManifestFile{}, fmt.Errorf("casebundle: write %s: %w", name, writeErr)
	}
	return ManifestFile{
		Path:    name,
		SHA256:  hex.EncodeToString(h.Sum(nil)),
		Records: len(recs),
	}, nil
}

// copyEvidence copies each cited artifact into evidence/, raw or redacted.
// Paths are deduplicated and processed in sorted order. A missing or
// unreadable cited file is a warning — the refs in the findings still locate
// it on the source machine. A source digest that does not equal every recorded
// digest on citing refs warns that the artifact changed after the finding was
// made. If different findings recorded conflicting digests, any source value
// necessarily drifts from at least one of them and therefore warns.
func copyEvidence(opts Options, refs map[model.Evidence]struct{}, res *Result) ([]ManifestFile, error) {
	byPath := map[string]map[string]struct{}{} // local path -> distinct non-empty recorded sha256s
	for ref := range refs {
		if ref.LocalPath == "" || isThinLiveEvidence(ref) {
			continue
		}
		if byPath[ref.LocalPath] == nil {
			byPath[ref.LocalPath] = make(map[string]struct{})
		}
		if ref.SHA256 != "" {
			byPath[ref.LocalPath][ref.SHA256] = struct{}{}
		}
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, nil
	}

	evDir := filepath.Join(opts.Out, "evidence")
	if err := os.Mkdir(evDir, 0o700); err != nil {
		return nil, fmt.Errorf("casebundle: %w", err)
	}
	var files []ManifestFile
	for _, src := range paths {
		mf, sourceSHA256, err := copyOneEvidence(evDir, src, opts.Evidence)
		if err != nil {
			res.warnEvidence(fmt.Sprintf("evidence %q: %v", src, err))
			continue
		}
		recorded := sortedDigests(byPath[src])
		if digestDiffers(recorded, sourceSHA256) {
			res.warnEvidence(evidenceDriftWarning(src, recorded, sourceSHA256))
		}
		files = append(files, mf)
	}
	if len(files) == 0 {
		if err := os.Remove(evDir); err != nil {
			return nil, fmt.Errorf("casebundle: remove empty evidence directory: %w", err)
		}
	}
	return files, nil
}

func sortedDigests(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	digests := make([]string, 0, len(set))
	for digest := range set {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return digests
}

func digestDiffers(recorded []string, copied string) bool {
	for _, digest := range recorded {
		// Warn if the source bytes drift from ANY recorded digest. A mixed set
		// therefore always warns, even if one digest matches.
		if digest != copied {
			return true
		}
	}
	return false
}

func evidenceDriftWarning(src string, recorded []string, current string) string {
	if len(recorded) == 1 {
		return fmt.Sprintf("evidence %q: content changed since the finding (recorded sha256 %s, source at copy time %s)", src, recorded[0], current)
	}
	return fmt.Sprintf("evidence %q: content changed since the finding (recorded sha256s [%s], source at copy time %s)", src, strings.Join(recorded, ", "), current)
}

// copyOneEvidence writes one evidence copy and returns its manifest entry.
// The bundle name prefixes the basename with a digest of the source path, so
// two cited files sharing a basename never collide. The basename is reduced to
// a portable ASCII segment so odd local filenames do not leak control
// characters into the bundle.
func copyOneEvidence(evDir, src string, mode EvidenceMode) (ManifestFile, string, error) {
	in, err := openRegularFile(src)
	if err != nil {
		return ManifestFile{}, "", err
	}

	name := evidenceCopyName(src)
	out, err := os.OpenFile(filepath.Join(evDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = in.Close()
		return ManifestFile{}, "", err
	}

	outputHash := sha256.New()
	sourceHash := sha256.New()
	w := io.MultiWriter(out, outputHash)
	copyErr := errors.Join(copyContent(w, io.TeeReader(in, sourceHash), mode, src), in.Close(), out.Close())
	if copyErr != nil {
		// Never leave a partial copy behind a clean manifest.
		_ = os.Remove(filepath.Join(evDir, name))
		return ManifestFile{}, "", copyErr
	}
	outputSHA256 := hex.EncodeToString(outputHash.Sum(nil))
	sourceSHA256 := hex.EncodeToString(sourceHash.Sum(nil))
	return ManifestFile{
		Path:         "evidence/" + name,
		SHA256:       outputSHA256,
		SourcePath:   src,
		SourceSHA256: sourceSHA256,
	}, sourceSHA256, nil
}

func evidenceCopyName(src string) string {
	pathSum := sha256.Sum256([]byte(src))
	base := sanitizeEvidenceBase(filepath.Base(src))
	return hex.EncodeToString(pathSum[:12]) + "-" + base
}

const maxEvidenceBaseLen = 180

func sanitizeEvidenceBase(base string) string {
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return "evidence"
	}
	var b strings.Builder
	b.Grow(len(base))
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= maxEvidenceBaseLen {
			break
		}
	}
	cleaned := strings.Trim(b.String(), "._-")
	if cleaned == "" {
		return "evidence"
	}
	return cleaned
}

// copyContent streams raw evidence verbatim. Redacted JSON is parsed before it
// is rewritten so masking cannot corrupt its syntax; supported text remains
// line-oriented and preserves line endings.
func copyContent(w io.Writer, in io.Reader, mode EvidenceMode, src string) error {
	if mode == EvidenceRaw {
		_, err := io.Copy(w, in)
		return err
	}
	lower := strings.ToLower(filepath.Base(src))
	base, compressed := trimCompressionSuffix(lower)
	switch {
	case compressed:
		return fmt.Errorf("redacted evidence does not support compressed input; decompress the source first or include it raw")
	case isJSONLinesName(base):
		return copyRedactedJSONLines(w, in)
	case strings.HasSuffix(base, ".json"):
		return copyRedactedJSON(w, in)
	default:
		return copyRedactedText(w, in)
	}
}

func trimCompressionSuffix(name string) (string, bool) {
	for _, suffix := range []string{".zst", ".gz", ".bz2", ".xz", ".zip"} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix), true
		}
	}
	return name, false
}

func isJSONLinesName(name string) bool {
	return strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".ndjson") ||
		strings.Contains(name, ".jsonl.") || strings.Contains(name, ".ndjson.")
}

func copyRedactedJSONLines(w io.Writer, in io.Reader) error {
	r := bufio.NewReaderSize(in, 64*1024)
	lineNumber := 0
	for {
		line, err := readEvidenceLine(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		lineNumber++
		body, eol := splitLineEnding(line)
		if strings.TrimSpace(body) == "" {
			if _, err := io.WriteString(w, body+eol); err != nil {
				return err
			}
			continue
		}
		redacted, err := redact.JSON([]byte(body))
		if err != nil {
			return fmt.Errorf("line %d: cannot safely redact JSON: %w", lineNumber, err)
		}
		if _, err := w.Write(redacted); err != nil {
			return err
		}
		if _, err := io.WriteString(w, eol); err != nil {
			return err
		}
	}
}

func copyRedactedJSON(w io.Writer, in io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(in, maxJSONEvidenceBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxJSONEvidenceBytes {
		return fmt.Errorf("JSON evidence exceeds %d bytes", maxJSONEvidenceBytes)
	}
	redacted, err := redact.JSON(raw)
	if err != nil {
		return fmt.Errorf("cannot safely redact JSON: %w", err)
	}
	if _, err := w.Write(redacted); err != nil {
		return err
	}
	switch {
	case bytes.HasSuffix(raw, []byte("\r\n")):
		_, err = io.WriteString(w, "\r\n")
	case bytes.HasSuffix(raw, []byte("\n")):
		_, err = io.WriteString(w, "\n")
	}
	return err
}

func copyRedactedText(w io.Writer, in io.Reader) error {
	r := bufio.NewReaderSize(in, 64*1024)
	sample, err := r.Peek(512)
	if err != nil && err != io.EOF {
		return err
	}
	if contentType := http.DetectContentType(sample); !strings.HasPrefix(contentType, "text/") {
		return fmt.Errorf("redacted evidence only supports UTF-8 plain text or JSON (detected %s)", contentType)
	}
	for {
		line, err := readEvidenceLine(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		body, eol := splitLineEnding(line)
		if !utf8.ValidString(body) || strings.IndexByte(body, 0) >= 0 {
			return fmt.Errorf("redacted evidence only supports UTF-8 plain text or JSON")
		}
		if _, err := io.WriteString(w, redact.String(body)+eol); err != nil {
			return err
		}
	}
}

func readEvidenceLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > maxEvidenceLine+len("\r\n") {
			return "", fmt.Errorf("line exceeds %d bytes", maxEvidenceLine)
		}
		switch err {
		case nil:
			return string(line), nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			if len(line) == 0 {
				return "", io.EOF
			}
			return string(line), nil
		default:
			return "", err
		}
	}
}

func splitLineEnding(line string) (body, eol string) {
	if !strings.HasSuffix(line, "\n") {
		return line, ""
	}
	body = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(body, "\r") {
		return strings.TrimSuffix(body, "\r"), "\r\n"
	}
	return body, "\n"
}

// writeManifest writes manifest.json last, once every listed file is on disk.
func writeManifest(opts Options, files []ManifestFile) error {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m := Manifest{
		SchemaVersion: model.SchemaVersion,
		CaseID:        opts.CaseID,
		CreatedAt:     now.UTC().Format(time.RFC3339Nano),
		Tool:          model.ToolName,
		ToolVersion:   version.String(),
		EvidenceMode:  opts.Evidence.String(),
		Files:         files,
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("casebundle: marshal manifest: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(opts.Out, manifestName), b, 0o600); err != nil {
		return fmt.Errorf("casebundle: %w", err)
	}
	return nil
}
