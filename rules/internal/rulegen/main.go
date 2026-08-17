// Command rulegen generates checked CEL expressions for Numbat's built-in
// rules. It is invoked by go generate from the rules package.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/perplexityai/numbat/internal/rule"
)

func main() {
	rulesDir := flag.String("rules", ".", "directory containing source rule YAML")
	outDir := flag.String("out", "checked", "directory for generated checked expressions")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected argument %q", flag.Arg(0))
	}

	sources, err := rule.LoadSourcesFS(os.DirFS(*rulesDir), ".")
	if err != nil {
		fatalf("load rules: %v", err)
	}
	checked, err := rule.BuildCheckedExpressions(sources)
	if err != nil {
		fatalf("check rules: %v", err)
	}
	if err := writeCatalog(*outDir, checked); err != nil {
		fatalf("write checked expressions: %v", err)
	}
	fmt.Printf("generated %d checked expressions in %s\n", len(checked), *outDir)
}

func writeCatalog(dir string, checked rule.CheckedExpressions) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	desired := make(map[string][]byte, len(checked))
	var names []string
	for digest, data := range checked {
		name := hex.EncodeToString(digest[:]) + ".pb"
		desired[name] = data
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := filepath.Join(dir, name)
		current, err := os.ReadFile(target)
		if err == nil && bytes.Equal(current, desired[name]) {
			continue
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(target, desired[name], 0o644); err != nil {
			return err
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pb") {
			continue
		}
		if _, ok := desired[entry.Name()]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rulegen: "+format+"\n", args...)
	os.Exit(1)
}
