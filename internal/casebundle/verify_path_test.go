package casebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeManifestBundle writes a bundle dir holding only a manifest.json listing
// the given files, plus a real, listed events.ndjson the test can point a
// symlink at. It returns the bundle dir.
func writeManifestBundle(t *testing.T, files []ManifestFile) string {
	t.Helper()
	dir := t.TempDir()
	m := Manifest{
		SchemaVersion: "0.3.0",
		CaseID:        "case-1",
		CreatedAt:     "2026-06-10T12:00:00Z",
		Tool:          "numbat",
		ToolVersion:   "test",
		Files:         files,
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestVerifyRejectsTraversalManifest plants an out-of-bundle secret target and a
// manifest entry that points at it via "../...". Verify must reject the entry as
// a problem (never pass) and must not open/hash the target, even though the
// manifest carries the target's true digest, which would otherwise "pass".
func TestVerifyRejectsTraversalManifest(t *testing.T) {
	parent := t.TempDir()
	secret := filepath.Join(parent, "secret.txt")
	secretBody := []byte("TOP SECRET out-of-bundle content")
	if err := os.WriteFile(secret, secretBody, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(parent, "case.numbat")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	// The manifest lists the secret by a traversal path, with its true digest, so
	// only the path check (not a digest mismatch) can stop it.
	m := Manifest{SchemaVersion: "0.3.0", CaseID: "c", Tool: "numbat", Files: []ManifestFile{
		{Path: "../secret.txt", SHA256: sha256Hex(secretBody)},
	}}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(bundle, manifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Verify(bundle)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if v.OK() {
		t.Fatal("traversal manifest verified clean; out-of-bundle file was trusted")
	}
	joined := strings.Join(v.Problems, "\n")
	if !strings.Contains(joined, "rejected") || !strings.Contains(joined, "traversal") {
		t.Fatalf("problems = %v, want a traversal rejection", v.Problems)
	}
}

// TestVerifyRejectsAbsolutePathManifest rejects an absolute manifest path.
func TestVerifyRejectsAbsolutePathManifest(t *testing.T) {
	abs := "/etc/passwd"
	dir := writeManifestBundle(t, []ManifestFile{{Path: abs, SHA256: "deadbeef"}})
	v, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("absolute-path manifest verified clean")
	}
	if !strings.Contains(strings.Join(v.Problems, "\n"), "absolute") {
		t.Fatalf("problems = %v, want an absolute-path rejection", v.Problems)
	}
}

// TestVerifyRejectsUncleanPath rejects an entry that is not in clean relative
// form ("./foo"), which would normalize-and-trust under a laxer check.
func TestVerifyRejectsUncleanPath(t *testing.T) {
	dir := writeManifestBundle(t, []ManifestFile{{Path: "./events.ndjson", SHA256: "deadbeef"}})
	v, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("unclean-path manifest verified clean")
	}
	if !strings.Contains(strings.Join(v.Problems, "\n"), "clean") {
		t.Fatalf("problems = %v, want a clean-form rejection", v.Problems)
	}
}

// TestVerifyRejectsSymlinkEscapingBundle plants a symlink inside the bundle that
// points outside it, lists it in the manifest with the target's digest, and
// confirms verify rejects it via the pre-open Lstat guard — not the post-open
// findUnlisted walk.
func TestVerifyRejectsSymlinkEscapingBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "outside.txt")
	body := []byte("outside the bundle")
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(parent, "case.numbat")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(bundle, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bundle, "evidence", "evil")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	m := Manifest{SchemaVersion: "0.3.0", CaseID: "c", Tool: "numbat", Files: []ManifestFile{
		{Path: "evidence/evil", SHA256: sha256Hex(body)},
	}}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(bundle, manifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Verify(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("symlink-escaping manifest verified clean")
	}
	if !strings.Contains(strings.Join(v.Problems, "\n"), "symlink") {
		t.Fatalf("problems = %v, want a symlink rejection", v.Problems)
	}
}

// TestVerifyRejectsSymlinkPointingInside confirms a symlink is rejected even when
// its target is inside the bundle: a bundle is plain files only, and the Lstat
// guard rejects the link before following it.
func TestVerifyRejectsSymlinkPointingInside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "evidence", "real")
	body := []byte(`{"record_type":"finding"}` + "\n")
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "evidence", "alias")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	m := Manifest{SchemaVersion: "0.3.0", CaseID: "c", Tool: "numbat", Files: []ManifestFile{
		{Path: "evidence/alias", SHA256: sha256Hex(body)},
	}}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, manifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() {
		t.Fatal("inside-pointing symlink verified clean")
	}
	if !strings.Contains(strings.Join(v.Problems, "\n"), "symlink") {
		t.Fatalf("problems = %v, want a symlink rejection", v.Problems)
	}
}

func TestVerifyRejectsSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("outside\n")
	if err := os.WriteFile(filepath.Join(outside, "copy"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(parent, "case.numbat")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(bundle, "evidence")); err != nil {
		t.Fatal(err)
	}
	m := Manifest{
		SchemaVersion: "0.3.0",
		CaseID:        "case-1",
		CreatedAt:     "2026-06-10T12:00:00Z",
		Tool:          "numbat",
		ToolVersion:   "test",
		Files:         []ManifestFile{{Path: "evidence/copy", SHA256: sha256Hex(body)}},
	}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(bundle, manifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Verify(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if v.OK() || !strings.Contains(strings.Join(v.Problems, "\n"), "symlink") {
		t.Fatalf("problems = %v, want parent-symlink rejection", v.Problems)
	}
}

func TestVerifyRejectsInvalidManifestStructure(t *testing.T) {
	dir := writeManifestBundle(t, nil)
	v, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(v.Problems, "\n")
	for _, want := range []string{"missing required entry \"findings.ndjson\"", "missing required entry \"events.ndjson\""} {
		if !strings.Contains(joined, want) {
			t.Fatalf("problems = %v, want %q", v.Problems, want)
		}
	}
}

func TestValidateManifestEvidenceMetadata(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	base := func(mode string, evidence ManifestFile) Manifest {
		files := []ManifestFile{{Path: "findings.ndjson"}, {Path: "events.ndjson"}}
		if evidence.Path != "" {
			files = append(files, evidence)
		}
		return Manifest{
			SchemaVersion: "0.3.0", CaseID: "case-1", CreatedAt: "2026-06-10T12:00:00Z",
			Tool: "numbat", ToolVersion: "test", EvidenceMode: mode, Files: files,
		}
	}
	tests := []struct {
		name string
		m    Manifest
		want string
	}{
		{"invalid mode", base("masked", ManifestFile{}), `invalid evidence_mode "masked"`},
		{"none with evidence", base("none", ManifestFile{Path: "evidence/x", SHA256: digestA}), "evidence_mode none"},
		{"raw missing source hash", base("raw", ManifestFile{Path: "evidence/x", SHA256: digestA, SourcePath: "/tmp/x"}), "empty source_sha256"},
		{"raw transformed", base("raw", ManifestFile{Path: "evidence/x", SHA256: digestA, SourcePath: "/tmp/x", SourceSHA256: digestB}), "does not match sha256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(validateManifest(tc.m), "\n"); !strings.Contains(got, tc.want) {
				t.Fatalf("problems = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerifyRejectsUnknownManifestField(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":"0.3.0","case_id":"c","created_at":"2026-06-10T12:00:00Z","tool":"numbat","tool_version":"test","files":[],"surprise":true}`
	if err := os.WriteFile(filepath.Join(dir, manifestName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Verify error = %v, want unknown-field rejection", err)
	}
}

// TestValidateBundlePathAcceptsPlainFile confirms the validator does not
// over-reject: a normal listed regular file inside the bundle passes.
func TestValidateBundlePathAcceptsPlainFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "events.ndjson"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := validateBundlePath(dir, "events.ndjson")
	if err != nil {
		t.Fatalf("validateBundlePath rejected a plain file: %v", err)
	}
	if got != filepath.Join(dir, "events.ndjson") {
		t.Fatalf("joined path = %q", got)
	}
}

// TestWithinDirRootAccepts proves the boundary decision treats a bundle at the
// filesystem root correctly: when cleanDir already ends in the separator ("/"),
// a plain in-bundle entry like "/events.ndjson" is accepted rather than rejected
// by a "//" prefix. It also guards the ordinary in/out cases.
func TestWithinDirRootAccepts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix root separator semantics")
	}
	cases := []struct {
		cleanDir string
		joined   string
		want     bool
	}{
		{"/", "/events.ndjson", true},
		{"/x/case", "/x/case/f", true},
		{"/x/case", "/x/case", true},
		{"/x/case", "/x/case-evil/f", false},
		{"/x/case", "/x/other/f", false},
	}
	for _, c := range cases {
		if got := withinDir(c.cleanDir, c.joined); got != c.want {
			t.Errorf("withinDir(%q, %q) = %v, want %v", c.cleanDir, c.joined, got, c.want)
		}
	}
}
