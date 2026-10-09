// Command numbat provides endpoint visibility into AI agent activity, with
// local detection, optional pre-action blocking, and forensic reconstruction.
//
// Numbat reconstructs and inspects what an endpoint AI agent did on a machine by
// parsing on-disk artifacts from the registered agent parsers, normalizing them
// into a single event model, evaluating deterministic CEL rules on-device, and
// emitting normalized NDJSON records — events, findings, hook enforcement
// decisions, indicators, and, for scans, a terminating scan_summary — never raw
// transcripts.
//
// Subcommands:
//
//	numbat scan [--agent NAME ... | --path FILE|DIR ...]      scan agent artifacts; emit selected NDJSON records
//	numbat timeline [--agent NAME ... | --path FILE|DIR ...]  reconstruct a per-session chronological view
//	numbat collect [--addr 127.0.0.1:4318]   receive OTLP/HTTP protobuf logs; emit records
//	numbat ship (--spool-file S | --input-file F) --http-url U  send local records to an HTTP endpoint
//	numbat hook (install|uninstall|status)   manage live agent integrations
//	numbat agents                            report detected and supported local agents
//	numbat rules check                       validate and compile rules; run companion tests
//	numbat rules list                        list effective compiled rule ids
//	numbat rules test --fixture FILE         evaluate rules against fixture events
//	numbat case build|verify                 bundle findings, enforcement decisions, and cited events
//	numbat version                           print version and schema version
//
// scan, collect, hook callbacks and installation, and the rule-loading
// subcommands accept --rules-dir DIR (repeatable) to add operator rules or
// replace embedded rules by id, and --no-builtin-rules to load only those rules.
//
// scan emits the selected NDJSON records (`--emit findings|events|indicators`,
// repeatable, or `--emit all`; default findings) to the configured sink and
// operational diagnostics to stderr.
// timeline is a read-only view over the same extraction, rendering what an agent
// did per session as text (default) or json. Subcommand implementations live in
// sibling files in this package.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code. It is split
// from main so tests can drive the CLI with explicit args and writers.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "help":
		if len(args) == 1 {
			usage(stdout)
			return 0
		}
		return runHelp(args[1:], stdin, stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "timeline":
		return runTimeline(args[1:], stdout, stderr)
	case "hook":
		return runHook(args[1:], stdin, stdout, stderr)
	case "agents":
		return runAgents(args[1:], stdout, stderr)
	case "collect":
		return runCollect(args[1:], stdout, stderr)
	case "ship":
		return runShip(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "case":
		return runCase(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		if args[0] == "version" && len(args) == 2 && isHelpArg(args[1]) {
			versionUsage(stdout)
			return 0
		}
		if len(args) != 1 {
			fmt.Fprintf(stderr, "version: unexpected argument %q\n", args[1])
			return 2
		}
		fmt.Fprintln(stdout, versionString())
		return 0
	case "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q\n", args[0])
		usage(stderr)
		return 2
	}
}

// runHelp implements `numbat help <subcommand>` as a thin alias over each
// command's own --help path, so the displayed flags stay owned by that command.
func runHelp(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	switch args[0] {
	case "scan":
		if len(args) != 1 {
			return helpUnexpectedArg(args, stderr)
		}
		return runScan([]string{"--help"}, stdout, stdout)
	case "timeline":
		if len(args) != 1 {
			return helpUnexpectedArg(args, stderr)
		}
		return runTimeline([]string{"--help"}, stdout, stdout)
	case "hook":
		if len(args) == 1 {
			return runHook([]string{"--help"}, stdin, stdout, stdout)
		}
		if len(args) > 2 {
			return helpUnexpectedArg(args, stderr)
		}
		switch args[1] {
		case "install", "uninstall", "status":
			return runHook([]string{args[1], "--help"}, stdin, stdout, stdout)
		default:
			return unknownHelpTopic(args, stderr)
		}
	case "agents":
		if len(args) != 1 {
			return helpUnexpectedArg(args, stderr)
		}
		return runAgents([]string{"--help"}, stdout, stdout)
	case "collect":
		if len(args) != 1 {
			return helpUnexpectedArg(args, stderr)
		}
		return runCollect([]string{"--help"}, stdout, stdout)
	case "ship":
		if len(args) != 1 {
			return helpUnexpectedArg(args, stderr)
		}
		return runShip([]string{"--help"}, stdout, stdout)
	case "rules":
		if len(args) == 1 {
			return runRules([]string{"--help"}, stdout, stdout)
		}
		if len(args) > 2 {
			return helpUnexpectedArg(args, stderr)
		}
		switch args[1] {
		case "check", "list", "test":
			return runRules([]string{args[1], "--help"}, stdout, stdout)
		default:
			return unknownHelpTopic(args, stderr)
		}
	case "case":
		if len(args) == 1 {
			return runCase([]string{"--help"}, stdout, stdout)
		}
		if len(args) > 2 {
			return helpUnexpectedArg(args, stderr)
		}
		switch args[1] {
		case "build", "verify":
			return runCase([]string{args[1], "--help"}, stdout, stdout)
		default:
			return unknownHelpTopic(args, stderr)
		}
	case "version":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "help version: unexpected argument %q\n", args[1])
			return 2
		}
		versionUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown help topic %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func helpUnexpectedArg(args []string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "help %s: unexpected argument %q\n", strings.Join(args[:len(args)-1], " "), args[len(args)-1])
	return 2
}

func unknownHelpTopic(args []string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "unknown help topic %q\n", strings.Join(args, " "))
	return 2
}

func isHelpArg(s string) bool {
	return s == "-h" || s == "--help" || s == "help"
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `numbat — observe, detect, block, and reconstruct AI agent activity on the endpoint

usage:
  numbat scan [--agent NAME ... | --path FILE|DIR ...]      scan agent artifacts; emit records (NDJSON)
  numbat timeline [--agent NAME ... | --path FILE|DIR ...]  reconstruct a per-session chronological view (text|json)
  numbat collect [--addr 127.0.0.1:4318]   receive OTLP/HTTP protobuf logs; emit records
  numbat ship (--spool-file S | --input-file F) --http-url U  send local records to an HTTP endpoint
  numbat hook EVENT --agent NAME           live integration callback (normally not run by hand)
  numbat hook install --agent NAME|all     install numbat's live integrations
  numbat hook uninstall --agent NAME|all   remove numbat-owned live integrations
  numbat hook status [--agent NAME|all]    inspect numbat-owned integration configuration
  numbat agents [--all]                    report detected agents; --all includes absent agents
  numbat rules check                       validate and compile rules; run companion tests
  numbat rules list                        list effective compiled rule ids
  numbat rules test --fixture FILE         evaluate rules against fixture events (NDJSON)
  numbat case build <case-id> --from FILE  bundle findings, enforcement decisions, and cited events
  numbat case verify DIR                   check a bundle against its manifest digests
  numbat version                           print version and schema version

Use --rules-dir DIR (repeatable) with scan, collect, hook EVENT, hook install,
or rules check/list/test to add operator rules or replace embedded rules by id.
Add --no-builtin-rules to omit the built-ins.
Run "numbat help <command> [subcommand]" for detailed flags.`)
}
