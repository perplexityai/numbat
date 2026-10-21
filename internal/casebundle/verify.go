package casebundle

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/output"
)

const (
	maxManifestBytes = 4 * 1024 * 1024
	maxManifestFiles = 10_000
	maxBundleEntries = maxManifestFiles + 1_024
)

// VerifyResult reports one bundle integrity check. OK is true only when every
// manifest entry matched and the bundle holds nothing the manifest does not
// list — a self-consistency verdict, not an authenticity one.
type VerifyResult struct {
	CaseID string
	Files  int
	// Problems lists every failed check: a missing or unlisted file, a digest
	// or record-count mismatch, a non-regular file inside the bundle.
	Problems []string
}

// OK reports whether the bundle verified cleanly.
func (r VerifyResult) OK() bool { return len(r.Problems) == 0 }

// Verify checks a bundle directory against its manifest: every listed file
// must exist with the recorded sha256 (and record count, for the NDJSON
// files), and no file may exist that the manifest does not list. An unlisted
// file is a problem, not a curiosity — additions are exactly what an
// integrity check is for. A bundle that cannot be read at all (no directory,
// no parseable manifest) is an error rather than a result.
func Verify(dir string) (VerifyResult, error) {
	var res VerifyResult
	m, err := readManifest(dir)
	if err != nil {
		return res, err
	}
	res.CaseID = m.CaseID
	res.Files = len(m.Files)

	listed := map[string]struct{}{manifestName: {}}
	res.Problems = append(res.Problems, validateManifest(m)...)
	files := m.Files
	if len(files) > maxManifestFiles {
		files = files[:maxManifestFiles]
	}
	seen := make(map[string]struct{}, len(files))
	for _, mf := range files {
		if _, duplicate := seen[mf.Path]; duplicate {
			continue
		}
		seen[mf.Path] = struct{}{}
		if problems := validateManifestFile(mf); len(problems) != 0 {
			res.Problems = append(res.Problems, problems...)
			continue
		}
		listed[mf.Path] = struct{}{}
		for parent := path.Dir(mf.Path); parent != "."; parent = path.Dir(parent) {
			listed[parent] = struct{}{}
		}
		res.Problems = append(res.Problems, checkFile(dir, m.CaseID, mf)...)
	}
	res.Problems = append(res.Problems, findUnlisted(dir, listed)...)
	sort.Strings(res.Problems)
	return res, nil
}

func readManifest(dir string) (Manifest, error) {
	var m Manifest
	root, err := os.Lstat(dir)
	if err != nil {
		return m, fmt.Errorf("casebundle: inspect bundle: %w", err)
	}
	if root.Mode()&os.ModeSymlink != 0 || !root.IsDir() {
		return m, fmt.Errorf("casebundle: bundle path is not a plain directory")
	}

	manifestPath := filepath.Join(dir, manifestName)
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return m, fmt.Errorf("casebundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return m, fmt.Errorf("casebundle: %s is not a regular file", manifestName)
	}
	f, err := openRegularFile(manifestPath)
	if err != nil {
		return m, fmt.Errorf("casebundle: open %s: %w", manifestName, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return m, fmt.Errorf("casebundle: read %s: %w", manifestName, readErr)
	}
	if closeErr != nil {
		return m, fmt.Errorf("casebundle: close %s: %w", manifestName, closeErr)
	}
	if len(raw) > maxManifestBytes {
		return m, fmt.Errorf("casebundle: %s exceeds %d bytes", manifestName, maxManifestBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("casebundle: parse %s: %w", manifestName, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("trailing JSON value")
		}
		return m, fmt.Errorf("casebundle: parse %s: %w", manifestName, err)
	}
	return m, nil
}

func validateManifest(m Manifest) []string {
	var problems []string
	if m.SchemaVersion != model.SchemaVersion {
		problems = append(problems, fmt.Sprintf("manifest: unsupported schema_version %q", m.SchemaVersion))
	}
	if strings.TrimSpace(m.CaseID) == "" {
		problems = append(problems, "manifest: empty case_id")
	}
	if m.Tool != model.ToolName {
		problems = append(problems, fmt.Sprintf("manifest: unexpected tool %q", m.Tool))
	}
	if strings.TrimSpace(m.ToolVersion) == "" {
		problems = append(problems, "manifest: empty tool_version")
	}
	switch m.EvidenceMode {
	case "", "none", "raw", "redacted":
	default:
		problems = append(problems, fmt.Sprintf("manifest: invalid evidence_mode %q", m.EvidenceMode))
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		problems = append(problems, fmt.Sprintf("manifest: invalid created_at %q", m.CreatedAt))
	}
	if len(m.Files) > maxManifestFiles {
		problems = append(problems, fmt.Sprintf("manifest: %d files exceeds limit %d", len(m.Files), maxManifestFiles))
	}

	files := m.Files
	if len(files) > maxManifestFiles {
		files = files[:maxManifestFiles]
	}
	present := make(map[string]bool, 2)
	seen := make(map[string]struct{}, len(files))
	for _, mf := range files {
		if mf.Path == "findings.ndjson" || mf.Path == "events.ndjson" {
			present[mf.Path] = true
		}
		if isEvidenceFile(mf.Path) {
			switch m.EvidenceMode {
			case "none":
				problems = append(problems, fmt.Sprintf("manifest: evidence_mode none cannot list %q", mf.Path))
			case "raw", "redacted":
				if mf.SourcePath == "" {
					problems = append(problems, fmt.Sprintf("%s: empty source_path", mf.Path))
				}
				if mf.SourceSHA256 == "" {
					problems = append(problems, fmt.Sprintf("%s: empty source_sha256", mf.Path))
				}
				if m.EvidenceMode == "raw" && isLowerHex64(mf.SourceSHA256) && mf.SourceSHA256 != mf.SHA256 {
					problems = append(problems, fmt.Sprintf("%s: raw evidence source_sha256 does not match sha256", mf.Path))
				}
			}
		}
		if _, ok := seen[mf.Path]; ok {
			problems = append(problems, fmt.Sprintf("manifest: duplicate path %q", mf.Path))
		}
		seen[mf.Path] = struct{}{}
	}
	for _, required := range []string{"findings.ndjson", "events.ndjson"} {
		if !present[required] {
			problems = append(problems, fmt.Sprintf("manifest: missing required entry %q", required))
		}
	}
	return problems
}

func validateManifestFile(mf ManifestFile) []string {
	label := mf.Path
	if label == "" {
		label = "<empty>"
	}
	var problems []string
	if err := validateRelativePath(mf.Path); err != nil {
		problems = append(problems, fmt.Sprintf("%s: rejected: %v", label, err))
		return problems
	}
	isEvidence := isEvidenceFile(mf.Path)
	if !isRecordFile(mf.Path) && !isEvidence {
		problems = append(problems, fmt.Sprintf("%s: unexpected bundle path", mf.Path))
	}
	if !isLowerHex64(mf.SHA256) {
		problems = append(problems, fmt.Sprintf("%s: invalid sha256", mf.Path))
	}
	if mf.Records < 0 {
		problems = append(problems, fmt.Sprintf("%s: negative record count", mf.Path))
	}
	if mf.Path == "findings.ndjson" && mf.Records == 0 {
		problems = append(problems, "findings.ndjson: record count must be positive")
	}
	if isEvidence && mf.Records != 0 {
		problems = append(problems, fmt.Sprintf("%s: evidence file cannot have a record count", mf.Path))
	}
	if isEvidence && mf.SourceSHA256 != "" && !isLowerHex64(mf.SourceSHA256) {
		problems = append(problems, fmt.Sprintf("%s: invalid source_sha256", mf.Path))
	}
	if isRecordFile(mf.Path) && (mf.SourcePath != "" || mf.SourceSHA256 != "") {
		problems = append(problems, fmt.Sprintf("%s: record file cannot have source metadata", mf.Path))
	}
	return problems
}

func isEvidenceFile(name string) bool {
	rel := strings.TrimPrefix(name, "evidence/")
	return rel != name && rel != "" && !strings.Contains(rel, "/")
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}

// checkFile verifies one manifest entry: present, digest match, and — for
// record files — the NDJSON line count the manifest recorded.
//
// Before opening anything it validates mf.Path (validateBundlePath): a manifest
// is attacker-controlled, so an entry like "../../etc/passwd", an absolute path,
// or a symlink escaping the bundle would otherwise make verify open and hash a
// file outside dir, and pass if the attacker knew that file's digest. Validation
// rejects closed: a rejected entry records a problem and is skipped, so verify can
// never pass on a manifest that points outside the bundle. (The fail-open
// constraint governs the hook, not case verify.)
func checkFile(dir, caseID string, mf ManifestFile) []string {
	joined, err := validateBundlePath(dir, mf.Path)
	if err != nil {
		return []string{fmt.Sprintf("%s: rejected: %v", mf.Path, err)}
	}
	var problems []string
	f, err := openRegularFile(joined)
	if err != nil {
		return []string{fmt.Sprintf("%s: missing: %v", mf.Path, err)}
	}
	defer f.Close()

	h := sha256.New()
	records := 0
	if mf.Records > 0 || isRecordFile(mf.Path) {
		sc := bufio.NewScanner(io.TeeReader(f, h))
		sc.Buffer(make([]byte, 0, 64*1024), maxRecordLine)
		line := 0
		semanticProblem := ""
		for sc.Scan() {
			line++
			if len(sc.Bytes()) == 0 {
				if semanticProblem == "" {
					semanticProblem = fmt.Sprintf("%s:%d: blank NDJSON line", mf.Path, line)
				}
				continue
			}
			records++
			if semanticProblem == "" {
				semanticProblem = validateRecordLine(mf.Path, caseID, line, sc.Bytes())
			}
		}
		if err := sc.Err(); err != nil {
			return []string{fmt.Sprintf("%s: read: %v", mf.Path, err)}
		}
		if records != mf.Records {
			problems = append(problems, fmt.Sprintf("%s: %d records, manifest says %d", mf.Path, records, mf.Records))
		}
		if semanticProblem != "" {
			problems = append(problems, semanticProblem)
		}
	} else if _, err := io.Copy(h, f); err != nil {
		return []string{fmt.Sprintf("%s: read: %v", mf.Path, err)}
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != mf.SHA256 {
		problems = append(problems, fmt.Sprintf("%s: sha256 %s, manifest says %s", mf.Path, sum, mf.SHA256))
	}
	return problems
}

func validateRecordLine(file, caseID string, line int, raw []byte) string {
	var p probe
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Sprintf("%s:%d: invalid JSON: %v", file, line, err)
	}
	if p.SchemaVersion != model.SchemaVersion {
		return fmt.Sprintf("%s:%d: invalid schema_version %q", file, line, p.SchemaVersion)
	}
	if file == "findings.ndjson" {
		if p.RecordType != output.RecordFinding || p.FindingID == "" || p.CaseID != caseID {
			return fmt.Sprintf("%s:%d: invalid finding identity", file, line)
		}
		return ""
	}
	if file == "enforcements.ndjson" {
		if p.RecordType != output.RecordEnforcement || p.DecisionID == "" || p.CaseID != caseID {
			return fmt.Sprintf("%s:%d: invalid enforcement identity", file, line)
		}
		return ""
	}
	if file == "assessments.ndjson" {
		if p.RecordType != output.RecordAssessment || p.AssessmentID == "" || p.CaseID != caseID {
			return fmt.Sprintf("%s:%d: invalid assessment identity", file, line)
		}
		return ""
	}
	if p.RecordType != output.RecordEvent || p.EventID == "" || p.CaseID != "" && p.CaseID != caseID {
		return fmt.Sprintf("%s:%d: invalid event identity", file, line)
	}
	return ""
}

// validateBundlePath confirms a manifest entry's path is a safe, bundle-relative
// reference and returns the OS path to open. Every check rejects rather than
// normalizes-and-trusts: a manifest is attacker-controlled, so traversal is a
// problem to report, not a shape to silently repair.
//
//   - The slash path must be non-empty, not absolute (path.IsAbs), carry no ".."
//     segment, and already be in clean form (path.Clean(p) == p) — so "./foo",
//     "a//b", or a trailing slash are rejected as malformed rather than accepted.
//   - The OS-joined path must not be absolute (filepath.IsAbs catches a Windows
//     volume/drive or UNC path that path.IsAbs misses) and must stay lexically
//     within dir (withinDir: equal to cleanDir, or under cleanDir + separator —
//     when dir is the filesystem root cleanDir already ends in the separator), so
//     a value that escapes the bundle is rejected before any filesystem access.
//   - os.Lstat, rather than os.Stat, must show a regular file: a symlink or
//     special file is rejected here before os.Open,
//     moving the symlink guard ahead of the open instead of relying on the
//     post-open findUnlisted walk.
func validateBundlePath(dir, raw string) (string, error) {
	if err := validateRelativePath(raw); err != nil {
		return "", err
	}
	cleanDir := filepath.Clean(dir)
	root, err := os.Lstat(cleanDir)
	if err != nil {
		return "", fmt.Errorf("bundle directory: %v", err)
	}
	if root.Mode()&os.ModeSymlink != 0 || !root.IsDir() {
		return "", fmt.Errorf("bundle path is not a plain directory")
	}
	joined := filepath.Join(cleanDir, filepath.FromSlash(raw))
	if !withinDir(cleanDir, joined) {
		return "", fmt.Errorf("escapes bundle directory")
	}

	current := cleanDir
	segments := strings.Split(raw, "/")
	for i, segment := range segments {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("missing: %v", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink not allowed")
		}
		if i < len(segments)-1 && !info.IsDir() {
			return "", fmt.Errorf("parent component is not a directory")
		}
		if i == len(segments)-1 && !info.Mode().IsRegular() {
			return "", fmt.Errorf("not a regular file")
		}
	}
	return joined, nil
}

func validateRelativePath(raw string) error {
	if raw == "" {
		return fmt.Errorf("empty path")
	}
	// path.IsAbs catches a slash-absolute path; filepath.IsAbs additionally catches
	// a Windows volume/drive or UNC path (e.g. `C:\x`, `\\host\share`).
	if path.IsAbs(raw) || filepath.IsAbs(raw) {
		return fmt.Errorf("absolute path not allowed")
	}
	if strings.Contains(raw, `\`) || strings.ContainsRune(raw, 0) {
		return fmt.Errorf("non-portable path separator or NUL")
	}
	if path.Clean(raw) != raw {
		return fmt.Errorf("not in clean relative form")
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return fmt.Errorf("path traversal segment %q", seg)
		}
	}
	return nil
}

// withinDir reports whether joined stays lexically inside cleanDir (already in
// filepath.Clean form): it must equal cleanDir or sit under it past a separator.
// The separator is only appended when cleanDir does not already end in one, so a
// filesystem-root cleanDir ("/") does not become "//" and wrongly reject a
// legitimate in-bundle entry.
func withinDir(cleanDir, joined string) bool {
	if joined == cleanDir {
		return true
	}
	prefix := cleanDir
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	return strings.HasPrefix(joined, prefix)
}

// isRecordFile reports whether a bundle path is an NDJSON record file, whose
// manifest entry carries a line count (omitted when zero).
func isRecordFile(path string) bool {
	return path == "findings.ndjson" || path == "events.ndjson" ||
		path == "enforcements.ndjson" || path == "assessments.ndjson"
}

// findUnlisted walks the bundle for anything the manifest does not vouch for.
// Non-regular files (symlinks, devices) are flagged outright: a bundle is
// plain files only, and a symlink could point integrity checks at content
// outside the bundle.
func findUnlisted(dir string, listed map[string]struct{}) []string {
	var problems []string
	entries := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: walk: %v", path, err))
			return nil
		}
		if path == dir {
			return nil
		}
		entries++
		if entries > maxBundleEntries {
			problems = append(problems, fmt.Sprintf("bundle tree exceeds %d entries", maxBundleEntries))
			return fs.SkipAll
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, relErr))
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if _, ok := listed[rel]; !ok {
				problems = append(problems, fmt.Sprintf("%s: directory not implied by manifest", rel))
			}
			return nil
		}
		if !d.Type().IsRegular() {
			if d.Type()&os.ModeSymlink != 0 {
				problems = append(problems, fmt.Sprintf("%s: symlink not allowed", rel))
			} else {
				problems = append(problems, fmt.Sprintf("%s: not a regular file", rel))
			}
			return nil
		}
		if _, ok := listed[rel]; !ok {
			problems = append(problems, fmt.Sprintf("%s: not listed in manifest", rel))
		}
		return nil
	})
	sort.Strings(problems)
	return problems
}
