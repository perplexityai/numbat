package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/perplexityai/numbat/internal/decision"
	"github.com/perplexityai/numbat/internal/evaluator"
)

// runDecisions owns offline preparation, not inference or host control.
func runDecisions(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		decisionsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "check":
		return runDecisionCheck(args[1:], stdout, stderr)
	case "digest":
		return runDecisionDigest(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		decisionsUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown decisions subcommand %q\n", args[0])
		decisionsUsage(stderr)
		return 2
	}
}

func decisionsUsage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  numbat decisions check --config FILE [--decision-user-config]
  numbat decisions digest --policy FILE

Validate enabled configuration and explain its enforcement prerequisites, or
print a policy's canonical SHA-256. Neither command reads credentials, accesses
state, contacts a provider, or establishes that an agent host will enforce.
Disabled bindings and unreferenced providers are not activated or verified.`)
}

func runDecisionCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decisions check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "protected decision configuration to validate")
	user := fs.Bool("decision-user-config", false, "allow current-user-owned configuration; not an agent security boundary")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat decisions check --config FILE [--decision-user-config]")
		fmt.Fprintln(stderr, "\nValidate enabled bindings, policies and any supplied pins without reading credentials,\naccessing state or contacting a provider. Disabled configuration is not verified.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *config == "" {
		fmt.Fprintln(stderr, "decisions check requires --config FILE and no positional arguments")
		return 2
	}
	c, err := evaluator.LoadConfig(*config, *user)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printDecisionConfiguration(stdout, c)
	return 0
}

func runDecisionDigest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decisions digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("policy", "", "decision policy to validate and hash")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat decisions digest --policy FILE")
		fmt.Fprintln(stderr, "\nPrint the canonical policy SHA-256 for an optional policy_sha256 pin, not a hash of the source file.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *path == "" {
		fmt.Fprintln(stderr, "decisions digest requires --policy FILE and no positional arguments")
		return 2
	}
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintf(stderr, "decision policy unavailable: %v\n", err)
		return 1
	}
	defer f.Close()
	c, err := decision.LoadPolicy(f)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, c.Digest())
	return 0
}

func printDecisionConfiguration(w io.Writer, c *evaluator.Config) {
	fmt.Fprintf(w, "decision configuration parsed; enabled=%t\n", c.Enabled)
	if c.Enabled {
		fmt.Fprintf(w, "enabled bindings validated; content=%s; budget_ms=%d\n", c.Content, c.BudgetMS)
	} else {
		fmt.Fprintln(w, "configuration disabled: activation fields and referenced files not validated")
	}
	active := 0
	for i, b := range c.Bindings {
		if c.Enabled && b.Enabled {
			fmt.Fprintf(w, "bindings[%d]: policy=%q view=%s mode=%s provider=%q\n",
				i, b.Compiled.Policy().ID, b.View, b.Mode, b.Provider)
			if b.SendContent {
				active++
				fmt.Fprintln(w, "  inference: configured for selected pre-action calls")
			} else {
				fmt.Fprintln(w, "  inference: disabled (send_content not authorized)")
			}
			fmt.Fprintf(w, "  request cap: %d bytes including policy and provider envelope\n", b.MaxRequestBytes)
		} else {
			fmt.Fprintf(w, "bindings[%d]: inactive; policy and provider not validated\n", i)
		}
		if blockers := c.EnforcementBlockers(b); len(blockers) != 0 {
			fmt.Fprintf(w, "  enforcement configuration blockers: %s\n", strings.Join(blockers, "; "))
		} else {
			fmt.Fprintln(w, "  enforcement configuration prerequisites satisfied; runtime eligibility not checked")
		}
		if c.Enabled && b.Enabled && b.View == decision.Session {
			fmt.Fprintf(w, "  retained session cap: %d encoded bytes\n", min(c.State.MaxBytes, 1<<20))
			fmt.Fprintf(w, "  complete-prefix ceiling: %d calls including the pending call; bytes, expiry or gaps can stop enforcement earlier\n",
				min(c.State.MaxCalls, b.MaxHistoryCalls+1))
			fmt.Fprintln(w, "  exceeding the ceiling leaves this session monitor-only; a fresh session is needed")
		}
	}
	fmt.Fprintf(w, "inference-enabled bindings: %d\n", active)
	if c.Enabled && c.Content == "redacted" {
		fmt.Fprintln(w, "redacted evidence can be incomplete and therefore ineligible for enforcement; raw egress requires separate approval")
	}
	fmt.Fprintln(w, "not checked: disabled bindings, unreferenced providers, credentials, provider availability, state, loaded hooks or host behavior")
	fmt.Fprintln(w, "runtime enforcement also requires hook --enforce, supported final arguments, fresh complete evidence, a qualifying response and successful output")
}
