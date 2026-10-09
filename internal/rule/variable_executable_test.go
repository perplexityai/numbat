package rule_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
)

const (
	forkByNameExpr = `shell_commands.exists(command,
		command.name == "gh" && command.argv.size() > 2 &&
		command.argv[1] == "repo" && command.argv[2] == "fork")`
	quotedForkExpr = `shell_commands.exists(command,
		command.name == "gh" && command.arguments[0].quote == "double")`
	dynamicExecutable = "dynamic command executable"
	nestedScript      = "bash -c 'GH=/usr/bin/gh; $GH repo fork" +
		" example/project'"
	resolvedFork       = "GH=/usr/bin/gh; $GH repo fork example/project"
	quotedResolvedFork = `GH=/usr/bin/gh; "$GH" repo fork example/project`
	singleMatch        = 1
)

// ruleEngine builds an engine holding one enforced rule with expr.
func ruleEngine(t *testing.T, expr string) *rule.Engine {
	t.Helper()

	var enforced rule.Rule

	enforced.ID = "t.fork"
	enforced.Version = "1"
	enforced.Title = "fork"
	enforced.Severity = model.SeverityHigh
	enforced.Enforce = new(true)
	enforced.Expr = expr

	var source rule.Source

	source.Name = "test"
	source.Rules = []rule.Rule{enforced}

	engine, err := rule.NewEngine([]rule.Source{source})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	return engine
}

// commandEvent wraps command as a command.exec event with no tool hint.
func commandEvent(command string) model.Event {
	return toolEvent("", command)
}

// toolEvent wraps command as a command.exec event from the named tool.
func toolEvent(tool, command string) model.Event {
	var event model.Event

	event.EventType = model.EventCommandExec
	event.ToolName = tool
	event.Command = command

	return event
}

// evalFork evaluates one command against the name-based fork rule and
// returns the matches and the analysis diagnostic.
func evalFork(t *testing.T, command string) ([]rule.Match, error) {
	t.Helper()

	matches, err := ruleEngine(t, forkByNameExpr).Eval(commandEvent(command))
	if err != nil {
		return matches, fmt.Errorf("eval %q: %w", command, err)
	}

	return matches, nil
}

// resolvedMatch evaluates a command that must analyze without a diagnostic
// and match the fork rule exactly once.
func resolvedMatch(t *testing.T, command string) rule.Match {
	t.Helper()

	matches, err := evalFork(t, command)
	if err != nil {
		t.Fatalf("diagnostic %v, want none", err)
	}

	if len(matches) != singleMatch {
		t.Fatalf("%q: matches = %+v, want one", command, matches)
	}

	return matches[0]
}

// requireDynamic evaluates a command whose first word must stay a run-time
// executable: the dynamic diagnostic and no match.
func requireDynamic(t *testing.T, command string) {
	t.Helper()
	requireDynamicFrom(t, "", command)
}

// requireDynamicFrom evaluates a command from the named tool that must keep
// the dynamic diagnostic and produce no match.
func requireDynamicFrom(t *testing.T, tool, command string) {
	t.Helper()

	matches, err := ruleEngine(t, forkByNameExpr).Eval(toolEvent(tool, command))
	if err == nil || !strings.Contains(err.Error(), dynamicExecutable) {
		t.Fatalf("%q: diagnostic %v, want %q", command, err, dynamicExecutable)
	}

	if len(matches) != 0 {
		t.Fatalf("%q: matches = %+v, want none", command, matches)
	}
}

// resolvedForms assign the variable once at the top level before its use.
func resolvedForms() []string {
	return []string{
		resolvedFork,
		"GH=/usr/bin/gh\n$GH repo fork example/project",
		quotedResolvedFork,
		"GH=/usr/bin/gh; ${GH} repo fork example/project",
		"GH='gh'; $GH repo fork example/project",
		"GH=/usr/bin/gh; $GH repo fork example/project; $GH pr view 1",
		"GH=gh; echo ${GH:=echo}; $GH repo fork example/project",
		"S=sudo; $S gh repo fork example/project",
		"GH=/usr/bin/gh;$GH repo fork example/project",
		"GH=/usr/bin/gh; f() { $GH repo fork example/project; }; f",
		"GH=/usr/bin/gh; ( $GH repo fork example/project )",
		"GH=/usr/bin/gh; time $GH repo fork example/project",
		"bash <<'EOF'\nGH=/usr/bin/gh; $GH repo fork example/project\nEOF",
	}
}

// inertNeighbors put a statement that reads no variable between the
// assignment and its use.
func inertNeighbors() []string {
	return []string{
		"GH=/usr/bin/gh; printf '%s\\n' start; $GH repo fork example/project",
		"GH=/usr/bin/gh; command -v gh; $GH repo fork example/project",
		"GH=/usr/bin/gh; sh -c 'X=1'; $GH repo fork example/project",
		"GH=/usr/bin/gh; export PATH=/x; $GH repo fork example/project",
		"GH=/usr/bin/gh; set -euo pipefail; $GH repo fork example/project",
		"GH=/usr/bin/gh; printf '%s\\n' \"$x\"; $GH repo fork example/project",
		"GH=/usr/bin/gh; set -- \"$@\"; $GH repo fork example/project",
		"GH=/usr/bin/gh; [[ -f x ]]; $GH repo fork example/project",
		"GH=/usr/bin/gh; echo \"${a[@]}\"; $GH repo fork example/project",
		"GH=/usr/bin/gh; printf -- '%s\\n' \"$x\"; $GH repo fork example/p",
		"GH=/usr/bin/gh; printf '%s\\n' '--- reviews ---'; $GH repo fork x/y",
		"GH=/usr/bin/gh; [ -f \"$x\" ]; $GH repo fork example/project",
		"GH=/usr/bin/gh; [ \"$x\" = \"$y\" ]; $GH repo fork example/project",
		"GH=/usr/bin/gh; [ \"$x\" ]; $GH repo fork example/project",
		"GH=/usr/bin/gh; true & wait; $GH repo fork example/project",
		"GH=/usr/bin/gh; [[ -v GH ]]; $GH repo fork example/project",
		"GH=/usr/bin/gh; [ -v GH ]; $GH repo fork example/project",
		`GH=/usr/bin/gh; [ "$n" -gt 0 ]; $GH repo fork example/project`,
		`GH=/usr/bin/gh; [ -n "$x" -a -f y ]; $GH repo fork example/project`,
		"GH=/usr/bin/gh; command true; $GH repo fork example/project",
	}
}

// unresolvedAssignments are inputs whose assignment is not one plain
// top-level statement before the use, or whose value is not one static word.
func unresolvedAssignments() []string {
	return []string{
		"$GH repo fork example/project",
		"GH=gh; GH=echo; $GH repo fork example/project",
		"GH=gh; if true; then GH=echo; fi; $GH repo fork example/project",
		"cd repo; $GH repo fork example/project; GH=gh",
		"GH=gh && $GH repo fork example/project",
		`GH="gh --verbose"; $GH repo fork example/project`,
		"GH=gh true; $GH repo fork example/project",
		"GH=gh & $GH repo fork example/project",
		"GH=gh; for GH in echo; do :; done; $GH repo fork example/project",
		"GH+=gh; $GH repo fork example/project",
		"GH[1]=gh; $GH repo fork example/project",
		`GH=""; $GH repo fork example/project`,
		"GH=$(which gh); $GH repo fork example/project",
		"f() { GH=gh; }; f; $GH repo fork example/project",
		"_=echo; true gh; $_ repo fork example/project",
		"BASH_REMATCH=echo; [[ gh =~ gh ]]; $BASH_REMATCH repo fork example/p",
		"argv=echo; set -- gh; $argv repo fork example/project",
		`GH=$'g\x68'; $GH repo fork example/project`,
		"UID=gh; $UID repo fork example/project",
		`GH=gh; $"$GH" repo fork example/project`,
		`GH=$"gh"; $GH repo fork example/project`,
		"GH=g\\h; $GH repo fork example/project",
		"GH=~/gh; $GH repo fork example/project",
		"GH=gh &| $GH repo fork example/project",
		"ERRNO=gh; cd /nonexistent; $ERRNO repo fork example/project",
		"GH='+(gh)'; $GH repo fork example/project",
		"GH==gh; $GH repo fork example/project",
		`sudo -u $'r\x6fot' bash -c 'GH=/usr/bin/gh; $GH repo fork example/p'`,
		"GH='(gh)'; $GH repo fork example/project",
	}
}

// builtinWrites are inputs that write the variable through a bash builtin, a
// wrapper, or a program the input does not name statically.
func builtinWrites() []string {
	return []string{
		"GH=gh; unset GH; $GH repo fork example/project",
		"GH=gh; eval x; $GH repo fork example/project",
		"GH=gh; printf -v GH echo; $GH repo fork example/project",
		"GH=gh; command unset GH; $GH repo fork example/project",
		"GH=gh; wait -p GH; $GH repo fork example/project",
		"GH=gh; wait -fp GH; $GH repo fork example/project",
		"GH=gh; coproc GH { sleep 1; }; $GH repo fork example/project",
		"GH=gh; E=eval; $E 'GH=echo'; $GH repo fork example/project",
		"GH=gh; $RUN x; $GH repo fork example/project",
		"GH=gh; trap 'GH=echo' ERR; false; $GH repo fork example/project",
		"GH=gh; command -p unset GH; $GH repo fork example/project",
		"GH=gh; U=unset; command $U GH; $GH repo fork example/project",
		"GH=echo; F=-v; printf $F GH gh; $GH repo fork example/project",
		"GH=echo; X=printf; command $X -v GH gh; $GH repo fork example/p",
		"GH=echo; alias u=unset; u GH; $GH repo fork example/project",
		"GH=gh; enable -n unset; $GH repo fork example/project",
		"GH=gh; builtin unset GH; $GH repo fork example/project",
		"GH=echo; set -o keyword; : GH=gh; $GH repo fork example/project",
		"GH=echo; set -o posix; set -k; : GH=gh; $GH repo fork example/project",
		"GH=gh; shopt -so keyword; : GH=echo; $GH repo fork example/project",
		"GH=gh; shopt -s -o keyword; : GH=echo; $GH repo fork example/project",
		"GH=gh; U=unset; command -p $U GH; $GH repo fork example/project",
	}
}

// expansionWrites are inputs whose builtin, option, or test word reaches
// the shell only after quote removal, brace expansion, or globbing.
func expansionWrites() []string {
	return []string{
		"GH=echo; e\\val 'GH=gh'; $GH repo fork example/project",
		"GH=echo; printf \\-v GH gh; $GH repo fork example/project",
		`GH=echo; $'e\x76al' 'GH=gh'; $GH repo fork example/project`,
		`GH=echo; printf $'\x2dv' GH gh; $GH repo fork example/project`,
		`GH=gh; [ $'\x2dv' a[GH=7] ]; $GH repo fork example/project`,
		"GH=echo; eva{l,l} 'GH=gh'; $GH repo fork example/project",
		"GH=gh; u{nset,nset} GH; $GH repo fork example/project",
		"GH=echo; ev?l 'GH=gh'; $GH repo fork example/project",
		"GH=echo; printf -[v] GH gh; $GH repo fork example/project",
		`GH=gh; [""u]nset GH; $GH repo fork example/project`,
		`GH=echo; printf [""-]v GH gh; $GH repo fork example/project`,
	}
}

// interpreterWrites are inputs whose nested script reaches the inner shell
// changed, or runs under an interpreter option that turns argument words
// into assignments.
func interpreterWrites() []string {
	return []string{
		"GH=gh; bash -c \"GH=echo; $GH repo fork example/project\"",
		`bash -c $'GH=echo; : x\x3bGH=gh; $GH repo fork example/project'`,
		`eval 'GH=echo;' $'$GH repo\x20fork example/project'`,
		"sh -k <<'EOF'\nGH=echo; : GH=gh; $GH repo fork example/project\nEOF",
		`bash <<< $'GH=gh; : x\x3bGH=echo; $GH repo fork example/project'`,
		"sudo sh -k <<'EOF'\nGH=gh; : GH=echo; $GH repo fork example/p\nEOF",
		"sudo bash -k -c 'GH=echo; : GH=gh; $GH repo fork example/project'",
		"sh -o keyword <<'EOF'\nGH=echo; : GH=gh; $GH repo fork example/p\nEOF",
		"BASH_ENV=/tmp/e bash -c 'GH=/usr/bin/gh; $GH repo fork example/p'",
		"env BASH_ENV=/tmp/e bash -c 'GH=/usr/bin/gh; $GH repo fork example/p'",
		"IFS=x; eval 'GH=ghxfoo; $GH repo fork example/project'",
		"export BASH_ENV=/tmp/e; bash -c 'GH=echo; $GH repo fork example/project'",
		"set -o posix; set -k; eval 'GH=echo; : GH=gh; $GH repo fork example/p'",
		"eval 'GH=/usr/bin/gh;' '$GH repo fork example/project'",
		"export SHELLOPTS=keyword:posix; bash -c 'GH=echo; : GH=gh; $GH repo fork x/y'",
	}
}

// zshWrites are inputs that write the variable through a zsh builtin, option
// form, or precommand modifier.
func zshWrites() []string {
	return []string{
		"GH=gh; set -A GH echo; $GH repo fork example/project",
		"GH=gh; print -v GH echo; $GH repo fork example/project",
		"GH=echo; print -rv GH gh; $GH repo fork example/project",
		"GH=echo; set +A GH gh; $GH repo fork example/project",
		"GH=echo; set -o errexit -A GH gh; $GH repo fork example/project",
		"GH=echo; print -f '%s' -v GH gh; $GH repo fork example/project",
		"GH=echo; noglob print -v GH gh; $GH repo fork example/project",
		"GH=echo; nocorrect print -v GH gh; $GH repo fork example/project",
		"GH=echo; - print -v GH gh; $GH repo fork example/project",
		"GH=echo; emulate sh -c 'GH=gh'; $GH repo fork example/project",
		"GH=echo; zformat -f GH %s s:gh; $GH repo fork example/project",
		"GH=echo; zstyle -s :x y GH; $GH repo fork example/project",
		"GH=gh; typeset -F x; x=GH=7; $GH repo fork example/project",
		"GH=gh; x=GH; echo ${(P)x}; $GH repo fork example/project",
		"GH=gh; ${GH:s/g/z/} repo fork example/project",
		"GH=gh; : *(e:'GH=echo':); $GH repo fork example/project",
	}
}

// arithmeticWrites are inputs that write the variable through an arithmetic
// context or a computed subscript or slice.
func arithmeticWrites() []string {
	return []string{
		"GH=/usr/bin/gh; n=$((1 <= 2)); $GH repo fork example/project",
		"GH=gh; ((GH = 0)); $GH repo fork example/project",
		"GH=gh; n=$((GH++)); $GH repo fork example/project",
		"GH=gh; x=GH=7; : $((x)); $GH repo fork example/project",
		"GH=gh; x[GH=7]=1; $GH repo fork example/project",
		"GH=gh; echo ${a[GH=7]}; $GH repo fork example/project",
		"GH=gh; echo ${x:GH=7}; $GH repo fork example/project",
		"GH=gh; x=([GH=7]=1); $GH repo fork example/project",
		"GH=gh; x=a[GH=7]; echo ${!x}; $GH repo fork example/project",
		`GH=gh; p='$((GH=7))'; echo "${p@P}"; $GH repo fork example/project`,
		"GH=gh; for ((GH=0; GH<1; GH++)); do :; done; $GH repo fork x/y",
		"GH=gh; select GH in a; do :; done; $GH repo fork example/project",
		"GH=gh; i=GH=7; echo ${a[i]}; $GH repo fork example/project",
	}
}

// testCommandWrites are inputs that write the variable through a `test`,
// `[`, or `[[` word that names or evaluates an array subscript.
func testCommandWrites() []string {
	return []string{
		"GH=gh; [[ GH=7 -eq 7 ]]; $GH repo fork example/project",
		"GH=gh; [[ -v a[GH=7] ]]; $GH repo fork example/project",
		"GH=gh; i=GH=7; [[ -v a[$i] ]]; $GH repo fork example/project",
		"GH=gh; [ -v a[GH=7] ]; $GH repo fork example/project",
		"GH=gh; [ ! -v a[GH=7] ]; $GH repo fork example/project",
		"GH=gh; O=-v; [ $O a[GH=7] ]; $GH repo fork example/project",
		"GH=gh; O=-v; A=a[GH=7]; [ $O $A ]; $GH repo fork example/project",
		"GH=gh; command test -v a[GH=7]; $GH repo fork example/project",
		"GH=gh; a=x; [ -v 'a[GH=7]' ]; $GH repo fork example/project",
		"GH=gh; x='-v a[GH=7]'; [ $x ]; $GH repo fork example/project",
		"GH=gh; x='!'; [ $x -v a[GH=7] ]; $GH repo fork example/project",
		`GH=gh; x='-v a[GH=7]'; [ ""$x ]; $GH repo fork example/project`,
		`GH=gh; x='!'; [ "$x" -v a[GH=7] ]; $GH repo fork example/project`,
		`GH=gh; [ \! -v a[GH=7] ]; $GH repo fork example/project`,
		`GH=gh; set -- -v 'a[GH=7]'; [ "$@" ]; $GH repo fork example/project`,
		"GH=gh; [ {-v,a[GH=7]} ]; $GH repo fork example/project",
		"GH=gh; [ * ]; $GH repo fork example/project",
		`GH=gh; arr=(-v 'a[GH=7]'); [ "${arr[@]}" ]; $GH repo fork example/p`,
	}
}

// declarationWrites are inputs that write the variable through a
// declaration, a descriptor variable, or a name the shell reads specially.
func declarationWrites() []string {
	return []string{
		"GH=gh; declare -n REF=GH; REF=echo; $GH repo fork example/project",
		"GH=gh; nameref REF=GH; REF=echo; $GH repo fork example/project",
		"GH=gh; declare -i x; x=GH=7; $GH repo fork example/project",
		"GH=echo; O=-n; declare $O REF=GH; REF=gh; $GH repo fork example/p",
		`GH=gh; export "GH=echo"; $GH repo fork example/project`,
		"IFS=h; GH=gh; $GH repo fork example/project",
		"GH=gh; PS4='$((GH=7))'; set -x; :; $GH repo fork example/project",
		"GH=gh; true {GH}>/dev/null; $GH repo fork example/project",
		"GH=gh; declare -F; $GH repo fork example/project",
	}
}

// operatorExpansions use the variable through an expansion that changes or
// extends its value.
func operatorExpansions() []string {
	return []string{
		"GH=gh; ${GH:+echo} repo fork example/project",
		"GH=gh; ${#GH} repo fork example/project",
		"GH=gh; ${!GH} repo fork example/project",
		"GH=gh; ${GH:0:1} repo fork example/project",
		"GH=gh; ${GH/gh/echo} repo fork example/project",
		"GH=gh; ${GH[1]} repo fork example/project",
		`GH=gh; "${GH}x" repo fork example/project`,
		"GH=gh; ${GH}x repo fork example/project",
		"GH=gh; ${(U)GH} repo fork example/project",
		"GH=gh; ${+GH} repo fork example/project",
		"GH=gh; ${!GH*} repo fork example/project",
	}
}

// forEachCommand runs check on every command as a parallel subtest.
func forEachCommand(
	t *testing.T,
	commands []string,
	check func(*testing.T, string),
) {
	t.Helper()

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			check(t, command)
		})
	}
}

// requireEnforceable evaluates a command that must resolve to one
// enforceable match.
func requireEnforceable(t *testing.T, command string) {
	t.Helper()

	if match := resolvedMatch(t, command); !match.EnforcementMatch {
		t.Fatalf("%q: match %+v, want enforceable", command, match)
	}
}

// requireDetectionOnly evaluates a command that must resolve to one match
// that enforcement does not act on.
func requireDetectionOnly(t *testing.T, command string) {
	t.Helper()

	if match := resolvedMatch(t, command); match.EnforcementMatch {
		t.Fatalf("%q: match %+v, want detection only", command, match)
	}
}

func TestSameInputAssignmentResolvesVariableExecutable(t *testing.T) {
	t.Parallel()

	forEachCommand(
		t,
		slices.Concat(resolvedForms(), inertNeighbors()),
		requireEnforceable,
	)
}

func TestUnresolvableVariableExecutableStaysDynamic(t *testing.T) {
	t.Parallel()

	forEachCommand(t, slices.Concat(
		unresolvedAssignments(),
		builtinWrites(),
		expansionWrites(),
		interpreterWrites(),
		zshWrites(),
		arithmeticWrites(),
		testCommandWrites(),
		declarationWrites(),
		operatorExpansions(),
	), requireDynamic)
}

func TestResolvedInterpreterParsesInlineScript(t *testing.T) {
	t.Parallel()

	forEachCommand(t, []string{
		"SH=/bin/sh; $SH -c 'gh repo fork example/project'",
		nestedScript,
		"sudo bash -c 'GH=/usr/bin/gh; $GH repo fork example/project'",
	}, requireDetectionOnly)
}

func TestVariableOptionWordEndsResolution(t *testing.T) {
	t.Parallel()

	forEachCommand(t, []string{
		"GH=/usr/bin/gh; wait $!; $GH repo fork example/project",
		"GH=/usr/bin/gh; set \"$@\"; $GH repo fork example/project",
	}, requireDynamic)
}

func TestPowerShellScriptDoesNotResolve(t *testing.T) {
	t.Parallel()
	requireDynamicFrom(t, "pwsh", nestedScript)
	requireDynamicFrom(
		t,
		"cmd",
		`bash -c "GH=/usr/bin/gh; $GH repo fork example/project"`,
	)
	requireDynamic(
		t,
		`pwsh -c 'bash -c '"'"'GH=gh; $GH repo fork example/project'"'"''`,
	)
}

func TestWrapperOperandStaysUnresolved(t *testing.T) {
	t.Parallel()

	command := "GH=/usr/bin/gh; sudo $GH repo fork example/project"

	matches, err := evalFork(t, command)
	if err != nil || len(matches) != 0 {
		t.Fatalf("%q: matches = %+v, %v, want none", command, matches, err)
	}
}

func TestResolvedQuotedWordKeepsQuote(t *testing.T) {
	t.Parallel()

	for command, want := range map[string]int{
		quotedResolvedFork:      singleMatch,
		`GH=/usr/bin/gh; "$GH"`: singleMatch,
		resolvedFork:            0,
	} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()

			engine := ruleEngine(t, quotedForkExpr)

			matches, evalErr := engine.Eval(commandEvent(command))
			if evalErr != nil || len(matches) != want {
				t.Fatalf(
					"%q: matches = %+v, %v, want %d",
					command,
					matches,
					evalErr,
					want,
				)
			}
		})
	}
}
