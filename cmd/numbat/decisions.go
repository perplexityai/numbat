package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/perplexityai/numbat/internal/evaluator"
)

func runDecisions(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelpArg(args[0]) {
		decisionsUsage(stdout)
		return 0
	}
	if len(args) == 0 || args[0] != "check" {
		decisionsUsage(stderr)
		return 2
	}
	fs := flag.NewFlagSet("decisions check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "inference configuration to validate without reading credentials or making requests")
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() { decisionsUsage(stderr); fs.PrintDefaults() }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *config == "" {
		decisionsUsage(stderr)
		return 2
	}
	c, err := evaluator.LoadConfig(*config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	eng, err := buildEngine(rf.dirs, rf.noBuiltin)
	if err == nil {
		err = c.ConfigureRules(eng.DecisionRules())
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%d decision rules; model=%q content=%s budget_ms=%d\n",
		len(c.Rules), c.Provider.Model, c.Content, c.BudgetMS)
	for _, r := range c.Rules {
		fmt.Fprintf(stdout, "rule=%q view=%s mode=%s match=%g deny=%g\n",
			r.Rule.ID, r.View, r.Mode, r.MatchThreshold, r.DenyThreshold)
	}
	fmt.Fprintf(stdout, "request cap=%d bytes; retained session cap=%d bytes, %d calls\n",
		c.MaxRequestBytes, min(c.State.MaxBytes, 1<<20), c.State.MaxCalls)
	fmt.Fprintln(stdout, "Not checked: credentials, provider, state or host delivery. Blocking also requires --enforce and eligible evidence.")
	return 0
}

func decisionsUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: numbat decisions check --config FILE [--rules-dir DIR ...] [--no-builtin-rules]")
}
