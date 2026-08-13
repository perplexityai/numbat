package rule

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"github.com/perplexityai/numbat/internal/model"
)

// Engine holds a compiled set of rules and evaluates events against them.
// It is safe for concurrent Eval calls after construction; rules are never
// mutated post-compile.
//
// Sequence rules compile here too — every step expr goes through the same
// strict compile path as a single-event expr — but the Engine itself stays
// stateless: Eval skips them, and a caller that wants correlation feeds the
// compiled SequenceRules into a window tracker (internal/sequence) that owns
// the partitioned state.
type Engine struct {
	env               *cel.Env
	rules             []compiledRule
	usesShellCommands bool
	usesContent       bool
}

// compiledRule is one compiled rule of either shape: program is set for a
// single-event rule, seq for a sequence rule. Exactly one side is populated;
// validateRule guarantees the source rule declares exactly one.
type compiledRule struct {
	rule    Rule
	program compiledExpression
	seq     *SequenceRule
}

type compiledExpression struct {
	program           cel.Program
	usesShellCommands bool
	usesContent       bool
}

const contentRuleCostLimit uint64 = 10_000_000

// SequenceRule is a compiled sequence rule ready for per-step evaluation. It
// distills the validated spec (window, cap) next to the compiled step
// programs so a tracker never re-parses YAML fields on the hot path.
type SequenceRule struct {
	rule              Rule
	steps             []compiledExpression
	within            time.Duration // 0 = no wall-clock window
	withinEvents      int           // 0 = no event-count window
	maxMatches        int           // resolved, >= 1
	usesShellCommands bool
	usesContent       bool
	adapter           types.Adapter
}

// Rule returns the source rule (id, severity, tags, ...).
func (s *SequenceRule) Rule() Rule { return cloneRule(s.rule) }

// StepCount returns the chain length.
func (s *SequenceRule) StepCount() int { return len(s.steps) }

// Within returns the wall-clock window, 0 when none is set.
func (s *SequenceRule) Within() time.Duration { return s.within }

// WithinEvents returns the event-count window, 0 when none is set.
func (s *SequenceRule) WithinEvents() int { return s.withinEvents }

// MaxMatches returns the per-(rule, session) finding cap, always >= 1.
func (s *SequenceRule) MaxMatches() int { return s.maxMatches }

// EvalStep evaluates one step predicate against a prebuilt activation. An eval
// error reports false: an erroring predicate must never fabricate a link in a
// chain, so the failure surfaces as a diagnostic and, at worst, a documented
// false negative.
func (s *SequenceRule) EvalStep(i int, activation map[string]any) (bool, error) {
	if i < 0 || i >= len(s.steps) {
		return false, fmt.Errorf("rule %q: step index %d out of range", s.rule.ID, i)
	}
	out, _, err := s.steps[i].program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("rule %q step %d: evaluation failed", s.rule.ID, i+1)
	}
	return asBool(out), nil
}

// StepUsesShellCommands reports whether step i depends on the derived command
// projection.
func (s *SequenceRule) StepUsesShellCommands(i int) bool {
	if i < 0 || i >= len(s.steps) {
		return false
	}
	return s.steps[i].usesShellCommands
}

// newEnv builds the CEL environment shared by every rule. `event` uses emitted
// JSON field names; shellCommandsVariable is an activation-only helper.
func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeOf(ShellCommand{}),
			reflect.TypeOf(ShellArgument{}),
			reflect.TypeOf(ShellAssignment{}),
			reflect.TypeOf(ShellWrapper{}),
			reflect.TypeOf(ShellRedirect{}),
			ext.ParseStructTags(true),
		),
		ext.Lists(),
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(shellCommandsVariable, cel.ListType(cel.ObjectType("rule.ShellCommand"))),
	)
}

// NewEngine compiles the supplied rule sources into a ready-to-eval Engine.
// Disabled rules are validated and compiled but excluded from evaluation.
// Invalid metadata, expressions, or duplicate IDs fail the whole load.
func NewEngine(sources []Source) (*Engine, error) {
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}

	var (
		compiled          []compiledRule
		seen              = map[string]string{}
		expressions       = map[string]compiledExpression{}
		errs              []error
		usesShellCommands bool
		usesContent       bool
	)
	for _, source := range sources {
		for i := range source.Rules {
			r := cloneRule(source.Rules[i])
			if err := validateRule(r); err != nil {
				errs = append(errs, err)
				continue
			}
			// The engine accepts only an already-resolved catalog. Source-layer
			// precedence, if any, belongs to the caller; duplicate ids here are
			// always ambiguous and remain a hard error.
			if prev, dup := seen[r.ID]; dup {
				errs = append(errs, fmt.Errorf("duplicate rule id %q: defined in source %s and source %s", r.ID, prev, sourceLabel(source)))
				continue
			}
			seen[r.ID] = sourceLabel(source)

			c, err := compileRule(env, expressions, r)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %q: %w", r.ID, err))
				continue
			}
			if !r.IsEnabled() {
				continue
			}
			compiled = append(compiled, c)
			if c.program.usesShellCommands {
				usesShellCommands = true
			}
			if c.program.usesContent || c.seq != nil && c.seq.usesContent {
				usesContent = true
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Engine{env: env, rules: compiled, usesShellCommands: usesShellCommands, usesContent: usesContent}, nil
}

// sourceLabel renders a stable, unambiguous source label for diagnostics. The
// loader-set Path is preferred because file paths are what users edit;
// Name is a fallback for in-memory tests.
func sourceLabel(p Source) string {
	name := p.Name
	if name == "" {
		name = "(unnamed)"
	}
	if p.Path == "" {
		return fmt.Sprintf("%q", name)
	}
	return fmt.Sprintf("%q [%s]", name, p.Path)
}

// validateRule checks the shape shared by both rule kinds and the
// exactly-one-of {expr, sequence} branch. Sequence-specific structure is
// validated by SequenceSpec.validate; step compilation happens in compileRule.
func validateRule(r Rule) error {
	if err := validateCleanRequired("id", r.ID); err != nil {
		if strings.TrimSpace(r.ID) == "" {
			return errors.New("rule with empty id")
		}
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if !validRuleID(r.ID) {
		return fmt.Errorf("rule %q: invalid id: use dot-separated lowercase letters, digits, underscore, or dash; segments must start and end with a letter or digit", r.ID)
	}
	if err := validateCleanRequired("version", r.Version); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	if err := validateCleanRequired("title", r.Title); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	for _, tag := range r.Tags {
		if err := validateCleanRequired("tags", tag); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	if r.DenyMessage != "" {
		if err := validateCleanRequired("deny_message", r.DenyMessage); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if len(r.DenyMessage) > maxDenyMessageBytes {
			return fmt.Errorf("rule %q: deny_message exceeds %d bytes", r.ID, maxDenyMessageBytes)
		}
		for _, ch := range r.DenyMessage {
			if unicode.IsControl(ch) || unicode.Is(unicode.Zl, ch) || unicode.Is(unicode.Zp, ch) {
				return fmt.Errorf("rule %q: deny_message must be one line without control characters", r.ID)
			}
		}
	}
	if !model.IsValidSeverity(r.Severity) {
		return fmt.Errorf("rule %q: invalid severity %q", r.ID, r.Severity)
	}
	switch {
	case strings.TrimSpace(r.Expr) == "" && r.Sequence == nil:
		return fmt.Errorf("rule %q: empty expr (set expr or sequence)", r.ID)
	case strings.TrimSpace(r.Expr) != "" && r.Sequence != nil:
		return fmt.Errorf("rule %q: expr and sequence are mutually exclusive", r.ID)
	case r.Sequence != nil:
		if err := r.Sequence.validate(); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

func validateCleanRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("missing %s", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not have leading or trailing whitespace", field)
	}
	return nil
}

func validRuleID(id string) bool {
	for _, segment := range strings.Split(id, ".") {
		if segment == "" || !isRuleIDAlnum(segment[0]) || !isRuleIDAlnum(segment[len(segment)-1]) {
			return false
		}
		for i := 1; i < len(segment)-1; i++ {
			c := segment[i]
			if isRuleIDAlnum(c) || c == '_' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isRuleIDAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// compileRule compiles either rule shape against the shared env: the single
// expr, or every sequence step through the identical strict path (boolean
// type, known event fields). A sequence rule also distills its validated
// window into the SequenceRule a tracker consumes.
func compileRule(env *cel.Env, expressions map[string]compiledExpression, r Rule) (compiledRule, error) {
	if r.Sequence == nil {
		prg, err := compileCachedExpr(env, expressions, r.Expr)
		if err != nil {
			return compiledRule{}, err
		}
		return compiledRule{rule: r, program: prg}, nil
	}
	steps := make([]compiledExpression, len(r.Sequence.Steps))
	usesShellCommands := false
	usesContent := false
	for i, st := range r.Sequence.Steps {
		prg, err := compileCachedExpr(env, expressions, st.Expr)
		if err != nil {
			return compiledRule{}, fmt.Errorf("step %d: %w", i+1, err)
		}
		steps[i] = prg
		usesShellCommands = usesShellCommands || prg.usesShellCommands
		usesContent = usesContent || prg.usesContent
	}
	within, err := r.Sequence.withinDuration()
	if err != nil {
		// Unreachable after validateRule; kept so compileRule is safe alone.
		return compiledRule{}, err
	}
	return compiledRule{rule: r, seq: &SequenceRule{
		rule:              r,
		steps:             steps,
		within:            within,
		withinEvents:      r.Sequence.WithinEvents,
		maxMatches:        r.Sequence.resolvedMaxMatches(),
		usesShellCommands: usesShellCommands,
		usesContent:       usesContent,
		adapter:           env.CELTypeAdapter(),
	}}, nil
}

func compileCachedExpr(env *cel.Env, expressions map[string]compiledExpression, expr string) (compiledExpression, error) {
	if compiled, ok := expressions[expr]; ok {
		return compiled, nil
	}
	compiled, err := compileExpr(env, expr)
	if err == nil {
		expressions[expr] = compiled
	}
	return compiled, err
}

// compileExpr parses, type-checks, and programs a CEL boolean expression.
func compileExpr(env *cel.Env, expr string) (compiledExpression, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return compiledExpression{}, fmt.Errorf("compile expr: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return compiledExpression{}, fmt.Errorf("expr must be boolean, got %s", ast.OutputType())
	}
	if err := checkEventFields(ast); err != nil {
		return compiledExpression{}, err
	}
	usesContent := astReferencesEventField(ast, "content") ||
		astReferencesEventField(ast, "content_bytes") ||
		astReferencesEventField(ast, "content_truncated")
	programOptions := []cel.ProgramOption{cel.EvalOptions(cel.OptOptimize)}
	if usesContent {
		programOptions = append(programOptions, cel.CostLimit(contentRuleCostLimit))
	}
	prg, err := env.Program(ast, programOptions...)
	if err != nil {
		return compiledExpression{}, fmt.Errorf("program expr: %w", err)
	}
	return compiledExpression{
		program:           prg,
		usesShellCommands: astReferencesGlobal(ast, shellCommandsVariable),
		usesContent:       usesContent,
	}, nil
}

func astReferencesEventField(ast *cel.Ast, field string) bool {
	found := false
	walkEventFields(ast.NativeRep(), ast.NativeRep().Expr(), false, func(name string, literal bool) {
		if literal && name == field {
			found = true
		}
	})
	return found
}

func astReferencesGlobal(ast *cel.Ast, name string) bool {
	native := ast.NativeRep()
	return exprReferencesGlobal(native, native.Expr(), name, false)
}

func exprReferencesGlobal(ast *celast.AST, expr celast.Expr, name string, shadowed bool) bool {
	switch expr.Kind() {
	case celast.IdentKind:
		if shadowed || expr.AsIdent() != name {
			return false
		}
		ref, ok := ast.ReferenceMap()[expr.ID()]
		return ok && ref.Name == name
	case celast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		if exprReferencesGlobal(ast, comprehension.IterRange(), name, shadowed) ||
			exprReferencesGlobal(ast, comprehension.AccuInit(), name, shadowed) {
			return true
		}
		loopShadowed := shadowed ||
			comprehension.IterVar() == name ||
			comprehension.HasIterVar2() && comprehension.IterVar2() == name ||
			comprehension.AccuVar() == name
		if exprReferencesGlobal(ast, comprehension.LoopCondition(), name, loopShadowed) ||
			exprReferencesGlobal(ast, comprehension.LoopStep(), name, loopShadowed) {
			return true
		}
		return exprReferencesGlobal(ast, comprehension.Result(), name, shadowed || comprehension.AccuVar() == name)
	default:
		for _, child := range celast.NavigateExpr(ast, expr).Children() {
			if exprReferencesGlobal(ast, child, name, shadowed) {
				return true
			}
		}
		return false
	}
}

// checkEventFields rejects an expression that selects an unknown field off the
// `event` variable (e.g. event.file_pathh). Because `event` is a dyn map, such
// typos type-check fine and only fail per-event at runtime; catching them here
// keeps the strict-load guarantee that a broken rule never silently degrades
// coverage.
func checkEventFields(ast *cel.Ast) error {
	if exprUsesGlobalAsValue(ast.NativeRep(), ast.NativeRep().Expr(), "event", false) {
		return errors.New("event must be accessed directly by a literal field name")
	}
	var bad []error
	walkEventFields(ast.NativeRep(), ast.NativeRep().Expr(), false, func(field string, literal bool) {
		if !literal {
			bad = append(bad, errors.New("event field index must be a string literal"))
		} else if !model.IsCELField(field) {
			bad = append(bad, fmt.Errorf("unknown event field %q", field))
		}
	})
	return errors.Join(bad...)
}

func walkEventFields(ast *celast.AST, expr celast.Expr, shadowed bool, visit func(string, bool)) {
	switch expr.Kind() {
	case celast.SelectKind:
		operand := expr.AsSelect().Operand()
		if isGlobalIdent(ast, operand, "event", shadowed) {
			visit(expr.AsSelect().FieldName(), true)
			return
		}
		walkEventFields(ast, operand, shadowed, visit)
	case celast.CallKind:
		call := expr.AsCall()
		if call.FunctionName() == operators.Index || call.FunctionName() == operators.OptIndex {
			args := call.Args()
			var target, key celast.Expr
			if call.IsMemberFunction() {
				if len(args) != 1 {
					return
				}
				target, key = call.Target(), args[0]
			} else {
				if len(args) != 2 {
					return
				}
				target, key = args[0], args[1]
			}
			if isGlobalIdent(ast, target, "event", shadowed) {
				if key.Kind() != celast.LiteralKind {
					visit("", false)
				} else if field, ok := key.AsLiteral().Value().(string); ok {
					visit(field, true)
				} else {
					visit("", false)
				}
			} else {
				walkEventFields(ast, target, shadowed, visit)
			}
			walkEventFields(ast, key, shadowed, visit)
			return
		}
		if call.IsMemberFunction() {
			walkEventFields(ast, call.Target(), shadowed, visit)
		}
		for _, arg := range call.Args() {
			walkEventFields(ast, arg, shadowed, visit)
		}
	case celast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		walkEventFields(ast, comprehension.IterRange(), shadowed, visit)
		walkEventFields(ast, comprehension.AccuInit(), shadowed, visit)
		loopShadowed := shadowed ||
			comprehension.IterVar() == "event" ||
			comprehension.HasIterVar2() && comprehension.IterVar2() == "event" ||
			comprehension.AccuVar() == "event"
		walkEventFields(ast, comprehension.LoopCondition(), loopShadowed, visit)
		walkEventFields(ast, comprehension.LoopStep(), loopShadowed, visit)
		walkEventFields(ast, comprehension.Result(), shadowed || comprehension.AccuVar() == "event", visit)
	default:
		for _, child := range celast.NavigateExpr(ast, expr).Children() {
			walkEventFields(ast, child, shadowed, visit)
		}
	}
}

func exprUsesGlobalAsValue(ast *celast.AST, expr celast.Expr, name string, shadowed bool) bool {
	switch expr.Kind() {
	case celast.IdentKind:
		if shadowed || expr.AsIdent() != name {
			return false
		}
		ref, ok := ast.ReferenceMap()[expr.ID()]
		return ok && ref.Name == name
	case celast.SelectKind:
		operand := expr.AsSelect().Operand()
		if !isGlobalIdent(ast, operand, name, shadowed) &&
			exprUsesGlobalAsValue(ast, operand, name, shadowed) {
			return true
		}
		return false
	case celast.CallKind:
		call := expr.AsCall()
		if call.FunctionName() == operators.Index || call.FunctionName() == operators.OptIndex {
			args := call.Args()
			var target, key celast.Expr
			if call.IsMemberFunction() {
				if len(args) != 1 {
					return false
				}
				target, key = call.Target(), args[0]
			} else {
				if len(args) != 2 {
					return false
				}
				target, key = args[0], args[1]
			}
			if !isGlobalIdent(ast, target, name, shadowed) &&
				exprUsesGlobalAsValue(ast, target, name, shadowed) {
				return true
			}
			return exprUsesGlobalAsValue(ast, key, name, shadowed)
		}
		if call.IsMemberFunction() && exprUsesGlobalAsValue(ast, call.Target(), name, shadowed) {
			return true
		}
		for _, arg := range call.Args() {
			if exprUsesGlobalAsValue(ast, arg, name, shadowed) {
				return true
			}
		}
		return false
	case celast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		if exprUsesGlobalAsValue(ast, comprehension.IterRange(), name, shadowed) ||
			exprUsesGlobalAsValue(ast, comprehension.AccuInit(), name, shadowed) {
			return true
		}
		loopShadowed := shadowed ||
			comprehension.IterVar() == name ||
			comprehension.HasIterVar2() && comprehension.IterVar2() == name ||
			comprehension.AccuVar() == name
		if exprUsesGlobalAsValue(ast, comprehension.LoopCondition(), name, loopShadowed) ||
			exprUsesGlobalAsValue(ast, comprehension.LoopStep(), name, loopShadowed) {
			return true
		}
		return exprUsesGlobalAsValue(ast, comprehension.Result(), name, shadowed || comprehension.AccuVar() == name)
	default:
		for _, child := range celast.NavigateExpr(ast, expr).Children() {
			if exprUsesGlobalAsValue(ast, child, name, shadowed) {
				return true
			}
		}
		return false
	}
}

func isGlobalIdent(ast *celast.AST, expr celast.Expr, name string, shadowed bool) bool {
	if shadowed || expr.Kind() != celast.IdentKind || expr.AsIdent() != name {
		return false
	}
	ref, ok := ast.ReferenceMap()[expr.ID()]
	return ok && ref.Name == name
}

// Len reports the number of compiled (enabled, valid) rules of both shapes.
func (e *Engine) Len() int { return len(e.rules) }

// UsesContent reports whether an enabled rule evaluates the bounded message
// body instead of only its preview.
func (e *Engine) UsesContent() bool { return e != nil && e.usesContent }

// HasEnforceEligibleRules reports whether the compiled catalog contains at
// least one enabled rule that may block in live hook enforce mode. Disabled
// rules are absent from e.rules, so they cannot make an otherwise inert policy
// appear enforceable.
func (e *Engine) HasEnforceEligibleRules() bool {
	for _, c := range e.rules {
		if c.rule.IsEnforceEligible() {
			return true
		}
	}
	return false
}

// SequenceRules returns the compiled sequence rules in load order, for a
// window tracker to evaluate. Empty when the load contains none.
func (e *Engine) SequenceRules() []*SequenceRule {
	var seqs []*SequenceRule
	for _, c := range e.rules {
		if c.seq != nil {
			seqs = append(seqs, c.seq)
		}
	}
	return seqs
}

// RuleIDs returns the ids of compiled rules in load order.
func (e *Engine) RuleIDs() []string {
	ids := make([]string, len(e.rules))
	for i, c := range e.rules {
		ids[i] = c.rule.ID
	}
	return ids
}

// Eval runs every compiled single-event rule against one event and returns
// the matches in rule load order. Sequence rules are skipped — they match
// chains, not events, and are evaluated by the window tracker that holds
// their partitioned state. An evaluation error for one rule does not stop
// the others; it is returned alongside any matches so callers can surface it
// as a diagnostic without losing detections.
func (e *Engine) Eval(ev model.Event) ([]Match, error) {
	activations := prepareActivations(e.env.CELTypeAdapter(), ev, e.usesShellCommands)
	var (
		matches []Match
		errs    = []error{activations.err}
	)
	for _, c := range e.rules {
		if c.seq != nil {
			continue
		}
		if activations.err != nil && c.program.usesShellCommands && !activations.shellUsable {
			continue
		}
		out, _, err := c.program.program.Eval(activations.detection)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %q: evaluation failed", c.rule.ID))
			continue
		}
		if asBool(out) {
			enforcementMatch := c.rule.IsEnforceEligible()
			if enforcementMatch && c.program.usesShellCommands && !activations.shellEnforcementSafe {
				enforcementMatch = false
			}
			matches = append(matches, Match{
				Rule:             cloneRule(c.rule),
				Event:            ev,
				EnforcementMatch: enforcementMatch,
			})
		}
	}
	return matches, errors.Join(errs...)
}

// asBool reports whether a CEL result is a true boolean. Any non-bool result
// (which compile-time type checking already forbids) is treated as no match.
func asBool(v ref.Val) bool {
	b, ok := v.(types.Bool)
	return ok && bool(b)
}
