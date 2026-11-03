package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/perplexityai/numbat/internal/casebundle"
)

// integrityNote is printed by both case subcommands so nobody mistakes the
// manifest digests for a signature: they prove the bundle is self-consistent,
// not who made it or that it was never rebuilt.
const integrityNote = "integrity: manifest digests prove bundle self-consistency only, not authenticity (the bundle is unsigned)"

// runCase dispatches the `case` subcommand group: build a portable
// case.numbat evidence bundle from captured record streams, or verify one.
func runCase(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		caseUsage(stderr)
		return 2
	}
	switch args[0] {
	case "build":
		return runCaseBuild(args[1:], stdout, stderr)
	case "verify":
		return runCaseVerify(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		caseUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown case subcommand %q\n", args[0])
		caseUsage(stderr)
		return 2
	}
}

func caseUsage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  numbat case build <case-id> --from FILE [--from FILE ...] [-o|--out DIR] [--include-raw-evidence|--include-redacted-evidence]
  numbat case verify <DIR>

build assembles a portable case.numbat bundle from previously captured NDJSON
record streams (for example scan/collect/hook with an output file): the case's
findings, hook enforcement decisions, the events named by their cited_event_ids,
and a manifest of sha256 digests.
By default no evidence file contents are copied; only references and digests
travel. --include-raw-evidence copies the cited files verbatim, and
--include-redacted-evidence copies plain-text or valid, uncompressed JSON evidence
with best-effort secret masking; review it before sharing.

verify checks a bundle against its manifest: every listed file must match its
digest and record count, and the bundle may contain nothing unlisted.

`+integrityNote)
}

type caseBuildOptions struct {
	out             string
	from            multiFlag
	includeRaw      bool
	includeRedacted bool
}

func newCaseBuildFlagSet(output io.Writer, opts *caseBuildOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("case build", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&opts.out, "o", opts.out, "bundle directory to create (must not exist)")
	fs.StringVar(&opts.out, "out", opts.out, "bundle directory to create (must not exist)")
	fs.Var(&opts.from, "from", "captured NDJSON record-stream file to read (repeatable; required)")
	fs.BoolVar(&opts.includeRaw, "include-raw-evidence", false, "copy cited evidence files verbatim into the bundle (opt-in: may include secrets/transcripts)")
	fs.BoolVar(&opts.includeRedacted, "include-redacted-evidence", false, "copy cited plain-text or uncompressed JSON evidence with best-effort secret masking (review before sharing)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(output, "usage: numbat case build <case-id> --from FILE [--from FILE ...] [-o|--out DIR] [--include-raw-evidence|--include-redacted-evidence]")
		fs.PrintDefaults()
	}
	return fs
}

// runCaseBuild implements `numbat case build <case-id>`. The case id is the
// first argument (mirroring `hook <event>`); flags follow.
func runCaseBuild(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpArg(args[0]) {
		opts := caseBuildOptions{out: "case.numbat"}
		newCaseBuildFlagSet(stdout, &opts).Usage()
		return 0
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "case build: the case id comes first: numbat case build <case-id> --from FILE ...")
		return 2
	}
	caseID := args[0]

	opts := caseBuildOptions{out: "case.numbat"}
	fs := newCaseBuildFlagSet(stderr, &opts)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "case build: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if len(opts.from) == 0 {
		fmt.Fprintln(stderr, "case build: at least one --from record-stream file is required")
		return 2
	}
	if opts.includeRaw && opts.includeRedacted {
		fmt.Fprintln(stderr, "case build: --include-raw-evidence and --include-redacted-evidence are mutually exclusive")
		return 2
	}
	mode := casebundle.EvidenceNone
	switch {
	case opts.includeRaw:
		mode = casebundle.EvidenceRaw
	case opts.includeRedacted:
		mode = casebundle.EvidenceRedacted
	}

	res, err := casebundle.Build(casebundle.Options{
		CaseID:   caseID,
		Out:      opts.out,
		Sources:  opts.from,
		Evidence: mode,
	})
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "case build: warning: %s\n", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "case build: %v\n", err)
		return 1
	}
	summary := fmt.Sprintf("case bundle written: %s (%d findings", opts.out, res.Findings)
	if res.Enforcements > 0 {
		summary += fmt.Sprintf(", %d enforcement decisions", res.Enforcements)
	}
	if res.Assessments > 0 {
		summary += fmt.Sprintf(", %d assessments", res.Assessments)
	}
	summary += fmt.Sprintf(", %d events", res.Events)
	if mode != casebundle.EvidenceNone {
		summary += fmt.Sprintf(", %d evidence files", res.EvidenceFiles)
	}
	fmt.Fprintln(stdout, summary+")")
	fmt.Fprintln(stdout, integrityNote)
	return 0
}

// runCaseVerify implements `numbat case verify <dir>`. The verdict and any
// problems go to stdout — they are the command's output; exit 1 means the
// bundle failed verification, exit 2 a usage error.
func runCaseVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpArg(args[0]) {
		fmt.Fprintln(stdout, "usage: numbat case verify <DIR>")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Checks a case.numbat bundle against its manifest digests.")
		fmt.Fprintln(stdout, integrityNote)
		return 0
	}
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: numbat case verify <DIR>")
		return 2
	}
	res, err := casebundle.Verify(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "case verify: %v\n", err)
		return 1
	}
	if !res.OK() {
		for _, p := range res.Problems {
			fmt.Fprintln(stdout, "problem: "+p)
		}
		fmt.Fprintf(stdout, "bundle FAILED verification: %d problem(s)\n", len(res.Problems))
		return 1
	}
	fmt.Fprintf(stdout, "bundle verified: case %s, %d files match the manifest\n", res.CaseID, res.Files)
	fmt.Fprintln(stdout, integrityNote)
	return 0
}
