package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/internal/sequence"
	"github.com/perplexityai/numbat/rules"
)

var (
	// Embedded sources and their engine are immutable, so repeated commands in
	// one process can share the expensive CEL compilation safely.
	loadBuiltinRuleSources = sync.OnceValues(func() ([]rule.Source, error) {
		return rule.LoadSourcesFS(rules.FS, rules.Dir)
	})
	loadBuiltinCheckedExpressions = sync.OnceValues(func() (rule.CheckedExpressions, error) {
		return rule.LoadCheckedExpressionsFS(rules.CheckedFS, rules.CheckedDir)
	})
	loadBuiltinRuleEngine = sync.OnceValues(func() (*rule.Engine, error) {
		sources, err := loadBuiltinRuleSources()
		if err != nil {
			return nil, err
		}
		return compileBuiltinEngine(sources)
	})
)

// runRules dispatches the `rules` subcommand group.
func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		rulesUsage(stderr)
		return 2
	}
	switch args[0] {
	case "check":
		return runRulesCheck(args[1:], stdout, stderr)
	case "list":
		return runRulesList(args[1:], stdout, stderr)
	case "test":
		return runRulesTest(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		rulesUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown rules subcommand %q\n", args[0])
		rulesUsage(stderr)
		return 2
	}
}

func rulesUsage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  numbat rules check [--rules-dir DIR ...] [--no-builtin-rules]
  numbat rules list [--rules-dir DIR ...] [--no-builtin-rules]
  numbat rules test --fixture FILE [--require-match] [--expect RULE_ID ...] [--expect-none] [--rules-dir DIR ...] [--no-builtin-rules]

check strictly loads and compiles rule files and runs companion tests without scanning artifacts.
list prints compiled rule IDs, one per line.
test evaluates NDJSON events from --fixture and prints rule_id<TAB>event_id for each match.`)
}

// ruleFlags holds the rule-source flags shared by every rule-evaluating
// command so each path loads rules with identical semantics.
type ruleFlags struct {
	dirs      multiFlag
	noBuiltin bool
}

// register wires the rule-source flags onto a flag set.
func (rf *ruleFlags) register(fs *flag.FlagSet) {
	fs.Var(&rf.dirs, "rules-dir", "directory of operator YAML rules to add or replace by id (repeatable)")
	fs.BoolVar(&rf.noBuiltin, "no-builtin-rules", false, "skip embedded built-in rules and load only --rules-dir rules")
}

// loadRuleSources resolves the effective rule catalog. Explicit operator rules
// add to the embedded built-ins and replace a built-in with the same stable id;
// this lets an operator change any field without copying the entire catalog.
// Duplicate ids within or across operator directories remain an error because
// there is no unambiguous precedence between two operator definitions.
//
// It validates rule sources independently of whether findings are emitted: a
// missing, non-directory, or empty/no-YAML --rules-dir is an error, as is
// --no-builtin-rules with no --rules-dir (nothing to run). Each dir must yield
// at least one rule source so a typo'd or empty directory fails loudly rather
// than silently contributing no rules. NewEngine still rejects any duplicates
// left in the effective catalog as a defense-in-depth invariant.
func loadRuleSources(rulesDirs []string, noBuiltin bool) ([]rule.Source, error) {
	if noBuiltin && len(rulesDirs) == 0 {
		return nil, fmt.Errorf("--no-builtin-rules requires at least one --rules-dir")
	}
	var builtins []rule.Source
	if !noBuiltin {
		var err error
		builtins, err = loadBuiltinRuleSources()
		if err != nil {
			return nil, err
		}
	}
	var operatorSources []rule.Source
	for _, dir := range rulesDirs {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("rules dir %q: %w", dir, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("rules dir %q: not a directory", dir)
		}
		userSources, err := rule.LoadSourcesFS(os.DirFS(dir), ".")
		if err != nil {
			return nil, err
		}
		if len(userSources) == 0 {
			return nil, fmt.Errorf("rules dir %q: no YAML rule files found", dir)
		}
		// Qualify each source's loader-relative path with its dir so duplicate-id
		// diagnostics stay unambiguous across multiple --rules-dir values.
		for i := range userSources {
			userSources[i].Path = filepath.Join(dir, userSources[i].Path)
		}
		operatorSources = append(operatorSources, userSources...)
	}
	return overlayRuleSources(builtins, operatorSources)
}

// overlayRuleSources applies the one intentional precedence boundary in rule
// loading: an explicit operator definition replaces an embedded definition
// with the same id. It preserves the built-in's catalog position so output
// ordering does not change merely because an embedded definition was replaced.
func overlayRuleSources(builtins, operators []rule.Source) ([]rule.Source, error) {
	builtinIndex, err := uniqueRuleSourceIndex(builtins, "built-in")
	if err != nil {
		return nil, err
	}
	if _, err := uniqueRuleSourceIndex(operators, "operator"); err != nil {
		return nil, err
	}

	effective := append([]rule.Source(nil), builtins...)
	for _, source := range operators {
		id := source.Rules[0].ID
		if i, ok := builtinIndex[id]; ok {
			effective[i] = source
			continue
		}
		effective = append(effective, source)
	}
	return effective, nil
}

func uniqueRuleSourceIndex(sources []rule.Source, layer string) (map[string]int, error) {
	index := make(map[string]int, len(sources))
	labels := make(map[string]string, len(sources))
	for i, source := range sources {
		// LoadSourcesFS guarantees one rule per source. Keep an explicit error
		// here so a future loader cannot turn a malformed source into a panic.
		if len(source.Rules) != 1 {
			return nil, fmt.Errorf("%s rule source %s contains %d rules; want exactly one", layer, ruleSourceLabel(source), len(source.Rules))
		}
		id := source.Rules[0].ID
		if prev, ok := labels[id]; ok {
			return nil, fmt.Errorf("duplicate %s rule id %q: defined in %s and %s", layer, id, prev, ruleSourceLabel(source))
		}
		index[id] = i
		labels[id] = ruleSourceLabel(source)
	}
	return index, nil
}

func ruleSourceLabel(source rule.Source) string {
	if source.Path != "" {
		return fmt.Sprintf("%q", source.Path)
	}
	if source.Name != "" {
		return fmt.Sprintf("%q", source.Name)
	}
	return "(unnamed source)"
}

// compileEngine compiles rule sources into an engine and guards that it holds at least
// one rule, so a set of dirs that exist but contribute only disabled rules
// cannot yield a silent zero-rule run. Shared by buildEngine and scan so the
// zero-rule contract is identical on every command.
func compileEngine(sources []rule.Source) (*rule.Engine, error) {
	return validateCompiledEngine(rule.NewEngine(sources))
}

func compileBuiltinEngine(sources []rule.Source) (*rule.Engine, error) {
	checked, err := loadBuiltinCheckedExpressions()
	if err != nil {
		// Generated data is an optimization, never a correctness dependency.
		return compileEngine(sources)
	}
	return validateCompiledEngine(rule.NewEngineWithCheckedExpressions(sources, checked))
}

func compileEffectiveEngine(sources []rule.Source, noBuiltin bool) (*rule.Engine, error) {
	if noBuiltin {
		return compileEngine(sources)
	}
	return compileBuiltinEngine(sources)
}

func validateCompiledEngine(eng *rule.Engine, err error) (*rule.Engine, error) {
	if err != nil {
		return nil, err
	}
	if eng.Len() == 0 {
		return nil, fmt.Errorf("no rules to run: every loaded rule source is empty or all rules are disabled")
	}
	return eng, nil
}

// buildEngine loads the rule files (see loadRuleSources) and compiles them.
func buildEngine(rulesDirs []string, noBuiltin bool) (*rule.Engine, error) {
	if len(rulesDirs) == 0 && !noBuiltin {
		return loadBuiltinRuleEngine()
	}
	sources, err := loadRuleSources(rulesDirs, noBuiltin)
	if err != nil {
		return nil, err
	}
	return compileEffectiveEngine(sources, noBuiltin)
}

func runRulesCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat rules check [--rules-dir DIR ...] [--no-builtin-rules]")
		fmt.Fprintln(stderr, "\nStrictly load, compile, and test rule files without scanning artifacts.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "rules check: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	eng, err := buildEngine(rf.dirs, rf.noBuiltin)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	tests, err := runCompanionRuleTests(rf.dirs, eng)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	if tests > 0 {
		fmt.Fprintf(stdout, "rules ok: %d compiled, %d tests passed\n", eng.Len(), tests)
		return 0
	}
	fmt.Fprintf(stdout, "rules ok: %d compiled\n", eng.Len())
	return 0
}

// runRulesList prints the ids of all compiled rules, one per line.
func runRulesList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat rules list [--rules-dir DIR ...] [--no-builtin-rules]")
		fmt.Fprintln(stderr, "\nPrint compiled rule IDs, one per line.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "rules list: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	eng, err := buildEngine(rf.dirs, rf.noBuiltin)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	for _, id := range eng.RuleIDs() {
		fmt.Fprintln(stdout, id)
	}
	return 0
}

// runRulesTest evaluates the compiled rules against a fixture of NDJSON
// events (one model.Event per line) and prints each match as "rule_id\tevent_id".
// It is the deterministic, offline check that rules fire as intended.
func runRulesTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixture := fs.String("fixture", "", "path to an NDJSON file of events to evaluate (required)")
	requireMatch := fs.Bool("require-match", false, "exit non-zero if no rule matches (for positive fixtures)")
	expectNone := fs.Bool("expect-none", false, "exit non-zero if any rule matches (for negative fixtures)")
	var expect multiFlag
	fs.Var(&expect, "expect", "rule ID expected to match at least once (repeatable)")
	var rf ruleFlags
	rf.register(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat rules test --fixture FILE [--require-match] [--expect RULE_ID ...] [--expect-none] [--rules-dir DIR ...] [--no-builtin-rules]")
		fmt.Fprintln(stderr, "\nEvaluate fixture events and print rule_id<TAB>event_id for each match.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// rules test takes its input via --fixture; it has no positional operands, so
	// a stray argument is a mistake (mirrors scan's NArg rejection) rather than a
	// silently dropped path.
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "rules test: unexpected argument %q; pass the events file with --fixture\n", fs.Arg(0))
		return 2
	}
	if *fixture == "" {
		fmt.Fprintln(stderr, "rules test: --fixture is required")
		return 2
	}
	if *expectNone && (*requireMatch || len(expect) > 0) {
		fmt.Fprintln(stderr, "rules test: --expect-none cannot be combined with --require-match or --expect")
		return 2
	}
	f, err := os.Open(*fixture)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	defer f.Close()

	eng, err := buildEngine(rf.dirs, rf.noBuiltin)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}

	matched, matchedRules, evalErr := evalFixture(eng, f, stdout)
	if evalErr != nil {
		fmt.Fprintln(stderr, evalErr.Error())
		return 1
	}
	if matched == 0 && *requireMatch {
		fmt.Fprintln(stderr, "no rules matched")
		return 1
	}
	if *expectNone && matched > 0 {
		fmt.Fprintf(stderr, "expected no matches, got %d\n", matched)
		return 1
	}
	if missing := missingExpectedRules(expect, matchedRules); len(missing) > 0 {
		fmt.Fprintf(stderr, "expected rule(s) did not match: %s\n", strings.Join(missing, ", "))
		return 1
	}
	return 0
}

// evalFixture reads NDJSON events from r, evaluates eng against each, and
// writes "rule_id\tevent_id" lines to out. It returns the number of matches.
// Sequence rules run too: the fixture stream is fed through a window tracker
// in line order, and a completed chain prints the same rule_id\tevent_id
// shape, citing the event that completed the chain — so a positive sequence
// fixture is checked exactly like a single-event one.
func evalFixture(eng *rule.Engine, r io.Reader, out io.Writer) (int, map[string]int, error) {
	var tracker *sequence.Tracker
	if seqs := eng.SequenceRules(); len(seqs) > 0 {
		tracker = sequence.NewTracker(seqs, sequence.DefaultConfig())
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	matched := 0
	matchedRules := map[string]int{}
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return matched, matchedRules, fmt.Errorf("fixture line %d: %w", line, err)
		}
		ev = ev.NormalizePaths()
		if err := ev.Validate(); err != nil {
			return matched, matchedRules, fmt.Errorf("fixture line %d: %w", line, err)
		}
		matches, err := eng.Eval(ev)
		if err != nil {
			return matched, matchedRules, fmt.Errorf("fixture line %d: %w", line, err)
		}
		for _, m := range matches {
			matched++
			matchedRules[m.Rule.ID]++
			if _, err := fmt.Fprintf(out, "%s\t%s\n", m.Rule.ID, ev.EventID); err != nil {
				return matched, matchedRules, fmt.Errorf("write match: %w", err)
			}
		}
		if tracker != nil {
			observation, err := tracker.Observe(ev)
			if err != nil {
				return matched, matchedRules, fmt.Errorf("fixture line %d: %w", line, err)
			}
			for _, c := range observation.Findings {
				matched++
				matchedRules[c.Rule.ID]++
				if _, err := fmt.Fprintf(out, "%s\t%s\n", c.Rule.ID, ev.EventID); err != nil {
					return matched, matchedRules, fmt.Errorf("write match: %w", err)
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return matched, matchedRules, fmt.Errorf("scan fixture: %w", err)
	}
	return matched, matchedRules, nil
}

func missingExpectedRules(expect []string, matchedRules map[string]int) []string {
	if len(expect) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var missing []string
	for _, id := range expect {
		if _, done := seen[id]; done {
			continue
		}
		seen[id] = struct{}{}
		if matchedRules[id] == 0 {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	return missing
}
