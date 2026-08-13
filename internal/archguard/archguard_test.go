// Package archguard enforces release architecture and dependency constraints.
// Its tests cover internal package boundaries, cmd entrypoint boundaries,
// direct dependencies, cgo, and bundled third-party licenses.
package archguard

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/perplexityai/numbat"

const bboltPath = "go.etcd.io/bbolt"

// internalPrefix is the import-path prefix for the module's own internal
// packages, e.g. "github.com/perplexityai/numbat/internal/".
const internalPrefix = modulePath + "/internal/"

// Plane membership. Names are the package's path under internal/ (e.g. "model"
// or a nested package such as "rule/foo").
var (
	corePkgs       = []string{"applypatch", "model", "redact", "rule", "sequence", "finding", "pipeline", "output", "winfile"}
	forensicsPkgs  = []string{"extract", "discover", "casebundle"}
	monitoringPkgs = []string{"hook", "otel", "state"}
)

// nonPlane lists internal packages that intentionally belong to no plane:
// version is a pure constant, and archguard is this test package itself. Every
// other internal package MUST classify into exactly one plane; the no-orphan
// check in TestPackageImportSeam fails if a new unclassified package appears.
var nonPlane = map[string]bool{"version": true, "archguard": true}

// bboltAllowed lists the only internal packages permitted to import bbolt.
var bboltAllowed = map[string]bool{"state": true, "sequence": true}

// ---------------------------------------------------------------------------
// A2a — package-level guard (go list)
// ---------------------------------------------------------------------------

func TestPackageImportSeam(t *testing.T) {
	imports := internalImports(t)

	core := set(corePkgs)
	forensics := set(forensicsPkgs)
	monitoring := set(monitoringPkgs)

	// No-orphan check: every internal package must classify into exactly one
	// plane, or be an explicitly intentional non-plane package. This converts
	// "unclassified = silently unguarded" into "unclassified = test failure":
	// a new internal package forces the contributor to place it in a plane (or
	// the nonPlane allowlist) before the guard will pass.
	for _, pkg := range sortedKeys(imports) {
		planes := 0
		if core[pkg] {
			planes++
		}
		if forensics[pkg] {
			planes++
		}
		if monitoring[pkg] {
			planes++
		}
		if planes != 1 && !nonPlane[pkg] {
			t.Errorf("internal package %q is unclassified (%d planes); classify it into core/forensics/monitoring or add it to nonPlane", pkg, planes)
		}
	}

	// nonPlane purity: a package that belongs to no plane (version, archguard)
	// must be pure support — it must not reach into any internal package or
	// bbolt, or it becomes a hidden routing tunnel that bypasses the plane
	// seam. internalImports reads .Imports (production graph, no _test.go), so
	// archguard's own test-only internal refs are excluded and it shows empty;
	// any entry here for a nonPlane package is therefore a real violation.
	for _, pkg := range sortedKeys(imports) {
		if !nonPlane[pkg] {
			continue
		}
		for _, imp := range imports[pkg] {
			t.Errorf("nonPlane package %q must be pure support but imports %q (internal/bbolt deps would make it a cross-plane tunnel)", pkg, imp)
		}
	}

	// inPlane reports plane membership by leaf prefix: an import of a plane's
	// sub-package (e.g. "hook/foo") counts as importing that plane, matching the
	// file-level guard's leafMatches. Keeps A2a and A2b consistent and prevents a
	// future nested plane package from slipping past an exact-match check.
	inPlane := func(plane map[string]bool, imp string) bool {
		for p := range plane {
			if leafMatches(imp, p) {
				return true
			}
		}
		return false
	}

	for _, pkg := range sortedKeys(imports) {
		for _, imp := range imports[pkg] {
			// The hard rule: core MUST NOT import any plane package.
			if core[pkg] && (inPlane(forensics, imp) || inPlane(monitoring, imp)) {
				t.Errorf("core package %q imports plane package %q (core must not depend on a plane)", pkg, imp)
			}
			// Forensics MUST NOT import monitoring (or bbolt).
			if forensics[pkg] && (inPlane(monitoring, imp) || imp == bboltPath) {
				t.Errorf("forensics package %q imports %q (forensics must stay independent of the monitoring plane)", pkg, imp)
			}
			// Monitoring MUST NOT import forensics.
			if monitoring[pkg] && inPlane(forensics, imp) {
				t.Errorf("monitoring package %q imports %q (monitoring must stay independent of the forensics plane)", pkg, imp)
			}
			// bbolt allowlist: only {state, sequence} may touch it.
			if imp == bboltPath && !bboltAllowed[pkg] {
				t.Errorf("package %q imports %s but is not on the bbolt allowlist {state, sequence}", pkg, bboltPath)
			}
		}
	}
}

// internalImports returns, for every internal package keyed by its path under
// internal/ (e.g. "model" or "rule/foo" — nested packages do NOT collapse
// to their parent), the keys of its internal imports plus the bbolt path when
// present. Stdlib and other third-party imports are dropped — only the
// boundaries the guard governs are kept.
//
// This reads `go list`'s .Imports — the production import graph that links into
// the shipped binary. It intentionally does NOT consult .TestImports: test code
// may legitimately cross planes (a plane's tests can use sibling packages), so
// the seam is enforced on the shipped graph, not on test scaffolding.
func internalImports(t *testing.T) map[string][]string {
	t.Helper()
	type pkgList struct {
		ImportPath string
		Imports    []string
	}
	cmd := exec.Command("go", "list", "-json", modulePath+"/internal/...")
	cmd.Dir = moduleRoot(t)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -json failed: %v\n%s", err, stderr(err))
	}
	res := map[string][]string{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	for dec.More() {
		var p pkgList
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list json: %v", err)
		}
		leaf := strings.TrimPrefix(p.ImportPath, internalPrefix)
		var keep []string
		for _, imp := range p.Imports {
			switch {
			case strings.HasPrefix(imp, internalPrefix):
				keep = append(keep, strings.TrimPrefix(imp, internalPrefix))
			case imp == bboltPath:
				keep = append(keep, bboltPath)
			}
		}
		res[leaf] = keep
	}
	if len(res) == 0 {
		t.Fatal("go list returned no internal packages")
	}
	return res
}

// ---------------------------------------------------------------------------
// A2b — cmd/numbat file-level guard (AST)
// ---------------------------------------------------------------------------

// forbidMonitoring / forbidForensics are the plane packages a given entrypoint
// class must not import. scan/timeline/case are the forensics-side entrypoints:
// they must not touch the monitoring plane (hook/otel/state) or bbolt.
// hook/collect are the monitoring-side entrypoints: they must not touch the
// forensics plane (extract/discover/casebundle).
var (
	forbidMonitoring = []string{"hook", "otel", "state", bboltPath}
	forbidForensics  = []string{"extract", "discover", "casebundle"}
)

// classifyCmdFile assigns a non-test cmd/numbat source file to exactly one of
// four classes and returns the plane packages it may not import. Unlike a
// fall-through switch, classification is CLOSED: ok=false means the file matches
// no class, which the seam test treats as a failure rather than a silent skip.
// A future scan_helpers.go / collect_extra.go therefore cannot import the wrong
// plane unchecked — it must first be named into a class here.
//
//   - ir     forensics entrypoints — forbid the monitoring plane + bbolt
//   - mon    monitoring entrypoints — forbid the forensics plane
//   - common plane-neutral wiring — no plane restriction
//   - bridge agents.go, the report-only cross-plane bridge — exempt
func classifyCmdFile(name string) (forbidden []string, ok bool) {
	switch {
	case name == "scan.go" || strings.HasPrefix(name, "scan_") ||
		name == "timeline.go" || strings.HasPrefix(name, "timeline_") ||
		name == "case.go" || strings.HasPrefix(name, "case_"):
		return forbidMonitoring, true
	case name == "hook.go" || strings.HasPrefix(name, "hook_") ||
		name == "collect.go" || strings.HasPrefix(name, "collect_") ||
		name == "ship.go" || strings.HasPrefix(name, "ship_"):
		return forbidForensics, true
	case name == "content.go" || name == "main.go" || name == "rules.go" || name == "rules_companion.go" ||
		name == "run_id.go" || name == "sink.go" || name == "version.go":
		return nil, true
	case name == "agents.go":
		return nil, true
	default:
		return nil, false
	}
}

func TestCmdNumbatFileSeam(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "cmd", "numbat")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cmd/numbat: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		forbidden, ok := classifyCmdFile(name)
		if !ok {
			t.Errorf("cmd/numbat/%s is unclassified; add it to the ir/mon/common/bridge classification in classifyCmdFile", name)
			continue
		}
		for _, imp := range fileImports(t, fset, filepath.Join(dir, name)) {
			leaf, isInternal := internalLeaf(imp)
			for _, bad := range forbidden {
				if (isInternal && leafMatches(leaf, bad)) || imp == bad {
					t.Errorf("cmd/numbat/%s imports %q, which crosses its plane seam (forbidden: %s)", name, imp, strings.Join(forbidden, ", "))
				}
			}
		}
	}
}

// fileImports returns the unquoted import paths of a single Go source file.
// It uses strconv.Unquote so both interpreted ("...") and raw (`...`) string
// import literals collapse to the bare path; a raw-string import must not be
// able to slip a forbidden plane leaf past the seam guard.
func fileImports(t *testing.T, fset *token.FileSet, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var imps []string
	for _, spec := range f.Imports {
		imp, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %q in %s: %v", spec.Path.Value, path, err)
		}
		imps = append(imps, imp)
	}
	return imps
}

// internalLeaf reports whether an import path is one of the module's internal
// packages and returns its leaf name.
func internalLeaf(imp string) (string, bool) {
	if !strings.HasPrefix(imp, internalPrefix) {
		return "", false
	}
	return strings.TrimPrefix(imp, internalPrefix), true
}

// leafMatches reports whether an internal-package leaf belongs to the plane
// named by plane. A plane is identified by its leaf (e.g. "hook"), so an import
// of a sub-package ("hook/foo") must match too — otherwise a forbidden plane
// could be reached by importing one of its children. Exact match alone would
// miss that; the prefix check closes it.
func leafMatches(leaf, plane string) bool {
	return leaf == plane || strings.HasPrefix(leaf, plane+"/")
}

// ---------------------------------------------------------------------------
// A3 — dependency + cgo allowlist guard
// ---------------------------------------------------------------------------

// allowedDirectDeps is the complete set of direct (non-indirect) module
// requires numbat is allowed to carry. The "no cgo / SQLite / new heavy deps"
// constraint is a shipping contract, not a style note; without this guard a
// contributor could add a heavy direct dep and CI would stay green. Indirect
// deps are deliberately not policed — they flow transitively from these.
var allowedDirectDeps = map[string]bool{
	"github.com/google/cel-go":      true,
	"github.com/klauspost/compress": true,
	"go.etcd.io/bbolt":              true,
	"go.yaml.in/yaml/v3":            true,
	"golang.org/x/sys":              true,
	"google.golang.org/protobuf":    true,
	"mvdan.cc/sh/v3":                true,
}

func TestDependencyAllowlist(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()

	// Direct deps: `go list -m` resolves replace directives and multiple
	// require blocks that naive go.mod parsing would miss. The main module is
	// the only non-indirect entry that is not a real dependency, so drop it.
	out := goList(t, root, "-m", "-f", "{{if not .Indirect}}{{.Path}}{{end}}", "all")
	for _, path := range strings.Fields(out) {
		if path == modulePath {
			continue
		}
		if !allowedDirectDeps[path] {
			t.Errorf("disallowed direct dependency %q; the allowed set is exactly {cel-go, klauspost/compress, bbolt, x/sys, protobuf, yaml.v3, mvdan/sh}", path)
		}
		// Belt-and-suspenders on the heaviest likely violation: SQLite pulls in
		// cgo and a C toolchain, which the no-cgo contract forbids outright.
		if strings.Contains(path, "sqlite") {
			t.Errorf("direct dependency %q is a SQLite driver; numbat is cgo-free and stores state in bbolt", path)
		}
	}

	// No replace directives: the direct-dep check above keys on .Path, so an
	// allowed module path could be redirected via `replace` to a local fork —
	// swapping what actually ships (possibly to unreviewed or cgo code) without
	// tripping the allowlist. A cgo-free single-binary project pinning an exact
	// dep set has no legitimate need for replaces, so forbid them outright. This
	// also covers a replace pointed at an indirect dep.
	rawMods := goList(t, root, "-m", "-json", "all")
	type modList struct {
		Path    string
		Replace *struct{ Path string }
	}
	dec := json.NewDecoder(strings.NewReader(rawMods))
	for dec.More() {
		var m modList
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode go list -m json: %v", err)
		}
		if m.Replace != nil {
			t.Errorf("module %q has a replace directive (=> %q); replaces are forbidden — they can redirect an allowed dependency to unreviewed/cgo code", m.Path, m.Replace.Path)
		}
	}

	// cgo: AST-scan every .go file in the module's own tree (cmd/ + internal/,
	// production AND _test.go) for a literal `import "C"`. This is env-independent
	// — unlike `go list ... .CgoFiles`, which under CGO_ENABLED=0 drops a pure-cgo
	// package from the list entirely and reports 0 CgoFiles for a mixed one, and
	// never sees cgo in a _test.go file at all. A direct import-"C" walk closes
	// all three gaps. (Dependency source is not scanned; the replace-ban above
	// keeps allowed deps from being redirected to cgo forks.)
	scanned := 0
	for _, sub := range []string{"cmd", "internal"} {
		dir := filepath.Join(root, sub)
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			scanned++
			for _, imp := range fileImports(t, fset, path) {
				if imp == "C" {
					rel, relErr := filepath.Rel(root, path)
					if relErr != nil {
						rel = path
					}
					t.Errorf("file %s imports \"C\"; numbat is cgo-free and must build with CGO_ENABLED=0", rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s for cgo scan: %v", sub, err)
		}
	}
	if scanned == 0 {
		t.Fatal("cgo scan walked no Go files; the walk root is wrong")
	}
}

func TestThirdPartyLicensesCoverProductionModules(t *testing.T) {
	root := moduleRoot(t)
	notices, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_LICENSES.txt"))
	if err != nil {
		t.Fatalf("read third-party licenses: %v", err)
	}
	text := string(notices)
	if !strings.Contains(text, "Go standard library release toolchain:") {
		t.Error("third-party license bundle omits the Go standard library")
	}

	type listedPackage struct {
		Standard bool
		Module   *struct {
			Path    string
			Version string
			Main    bool
		}
	}
	dec := json.NewDecoder(strings.NewReader(goList(t, root, "-deps", "-json", "./cmd/numbat")))
	seen := make(map[string]bool)
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("decode production package graph: %v", err)
		}
		if pkg.Standard || pkg.Module == nil || pkg.Module.Main {
			continue
		}
		label := strings.TrimSpace(pkg.Module.Path + " " + pkg.Module.Version)
		if seen[label] {
			continue
		}
		seen[label] = true
		if !strings.Contains(text, label+" (") {
			t.Errorf("third-party license bundle omits production module %s", label)
		}
	}
	if len(seen) == 0 {
		t.Fatal("production dependency graph was empty")
	}
}

// goList runs `go list` in dir and returns stdout, failing the test on error.
func goList(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s failed: %v\n%s", strings.Join(args, " "), err, stderr(err))
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func moduleRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", modulePath)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("resolve module root: %v\n%s", err, stderr(err))
	}
	return strings.TrimSpace(string(raw))
}

func stderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return string(ee.Stderr)
	}
	return ""
}

func set(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
