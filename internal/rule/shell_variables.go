package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type resolvedExecutable struct {
	value string
	end   syntax.Pos
}

type resolvedExecutables map[string]resolvedExecutable

func (r resolvedExecutables) lookup(name string, at syntax.Pos) (string, bool) {
	assignment, found := r[name]
	if !found || assignment.end.After(at) {
		return "", false
	}
	return assignment.value, true
}

var (
	variableWritingBuiltins = stringSet(
		"eval", "source", ".", "read", "unset", "declare", "local", "typeset",
		"export", "readonly", "mapfile", "readarray", "let", "getopts", "trap",
		"alias", "enable", "emulate", "integer", "float", "vared", "zparseopts",
		"zformat", "zstyle", "zregexparse", "getln", "sysread", "strftime",
		"zstat", "pcre_match", "zpty", "zgetattr", "ztie", "sysopen", "zselect",
		"zcurses", "private",
	)
	builtinWrappers   = stringSet("command", "builtin", "noglob", "nocorrect", "-")
	shellManagedNames = stringSet(
		"_", "argv", "reply", "REPLY", "MATCH", "match", "MBEGIN", "MEND",
		"mbegin", "mend", "PWD", "OLDPWD", "DIRSTACK", "RANDOM", "SRANDOM",
		"SECONDS", "LINENO", "EPOCHSECONDS", "EPOCHREALTIME", "BASHPID",
		"HISTCMD", "SHLVL", "FUNCNAME", "funcstack", "PIPESTATUS", "pipestatus",
		"OPTARG", "OPTIND", "MAPFILE", "COPROC", "UID", "EUID", "PPID", "GROUPS",
		"SHELLOPTS", "BASHOPTS", "status", "zsh_eval_context", "TTY", "USERNAME",
		"EGID", "GID", "ARGC", "signals", "functrace", "funcfiletrace",
		"funcsourcetrace", "TTYIDLE", "zsh_scheduled_events", "ERRNO",
	)
	shellManagedPrefixes = []string{"BASH_", "ZSH_", "COMP_", "READLINE_"}
	// IFS changes how every later word splits, PS4 runs on every traced
	// command, and the others configure a child shell before it reads its
	// script.
	unsafeWrites = stringSet("IFS", "PS4", "SHELLOPTS", "BASH_ENV", "ENV", "ZDOTDIR", "HOME")
)

// resolveTopLevelAssignments returns nil, not an empty map, when the input
// writes variables in any way the scan cannot follow: a wrong resolution would
// report a command the shell never runs, or hide one it does.
func resolveTopLevelAssignments(file *syntax.File) resolvedExecutables {
	counts := make(map[string]int)
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if n.Name != nil {
				counts[n.Name.Value]++
			}
		case *syntax.WordIter:
			if n.Name != nil {
				counts[n.Name.Value]++
			}
		}
		return true
	})
	for name := range unsafeWrites {
		if counts[name] != 0 {
			return nil
		}
	}

	resolved := make(resolvedExecutables)
	for _, stmt := range file.Stmts {
		name, value, ok := topLevelStaticAssignment(stmt)
		if ok && counts[name] == 1 && !shellManaged(name) {
			resolved[name] = resolvedExecutable{value: value, end: stmt.End()}
		}
	}
	if writesOpaquely(file, resolved) {
		return nil
	}
	return resolved
}

func topLevelStaticAssignment(stmt *syntax.Stmt) (name, value string, ok bool) {
	call, isCall := stmt.Cmd.(*syntax.CallExpr)
	if !isCall || stmt.Background || stmt.Disown || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Value == nil || assign.Append || assign.Index != nil {
		return "", "", false
	}
	value, static := staticText(assign.Value)
	// `~`, `=`, and `(...)` expand in assignment values (zsh `=cmd`, glob qualifiers).
	if !static || value == "" || strings.ContainsAny(value, " \t\n*?[~()=") {
		return "", "", false
	}
	return assign.Name.Value, value, true
}

func shellManaged(name string) bool {
	if shellManagedNames[name] {
		return true
	}
	for _, prefix := range shellManagedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// Arithmetic evaluates variable contents recursively, so any arithmetic
// context can assign any variable; zsh glob qualifiers such as (e:code:) run
// code.
func writesOpaquely(file *syntax.File, resolved resolvedExecutables) bool {
	opaque := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if opaque {
			return false
		}
		switch n := node.(type) {
		case *syntax.CoprocClause, *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.CStyleLoop, *syntax.LetClause, *syntax.ExtGlob:
			opaque = true
		case *syntax.DeclClause:
			opaque = declarationRebinds(n)
		case *syntax.Redirect:
			opaque = n.N != nil && strings.HasPrefix(n.N.Value, "{") // {name}>file stores the descriptor in name
		case *syntax.CallExpr:
			opaque = callWritesVariables(n.Args, resolved)
		case *syntax.BinaryTest:
			opaque = isArithmeticTest(n.Op)
		case *syntax.UnaryTest:
			opaque = n.Op == syntax.TsVarSet && namesArrayElement(n.X)
		case *syntax.Assign:
			opaque = computedIndex(n.Index)
		case *syntax.ArrayElem:
			opaque = computedIndex(n.Index)
		case *syntax.ParamExp:
			opaque = paramEvaluates(n)
		}
		return !opaque
	})
	return opaque
}

func isArithmeticTest(op syntax.BinTestOperator) bool {
	switch op {
	case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
		return true
	}
	return false
}

func namesArrayElement(expr syntax.TestExpr) bool {
	word, ok := expr.(*syntax.Word)
	if !ok {
		return false
	}
	value, static := staticText(word)
	return !static || strings.Contains(value, "[")
}

func paramEvaluates(param *syntax.ParamExp) bool {
	if param.Flags != nil || param.Excl || (param.Exp != nil && param.Exp.Op == syntax.OtherParamOps) {
		return true
	}
	if computedIndex(param.Index) {
		return true
	}
	if param.Slice == nil {
		return false
	}
	return !isPlainIndex(param.Slice.Offset) || (param.Slice.Length != nil && !isPlainIndex(param.Slice.Length))
}

func computedIndex(index syntax.ArithmExpr) bool {
	return index != nil && !isPlainIndex(index)
}

// The shell does not evaluate @, *, or a literal number as a subscript.
func isPlainIndex(index syntax.ArithmExpr) bool {
	word, ok := index.(*syntax.Word)
	if !ok {
		return false
	}
	value, static := staticWord(word)
	if !static || value == "" {
		return false
	}
	if value == "@" || value == "*" {
		return true
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// A nameref, an attribute among n, i, E, and F, or an operand the Assign
// count does not see, such as `export "GH=echo"`, can change what a later
// assignment does.
func declarationRebinds(decl *syntax.DeclClause) bool {
	if decl.Variant != nil && decl.Variant.Value == "nameref" {
		return true
	}
	for _, arg := range decl.Args {
		if !arg.Naked || arg.Value == nil {
			continue
		}
		option, ok := staticText(arg.Value)
		if !ok || !strings.HasPrefix(option, "-") || strings.ContainsAny(option, "niEF") {
			return true
		}
	}
	return false
}

// A first word that is neither static nor resolved counts as a writer.
func callWritesVariables(args []*syntax.Word, resolved resolvedExecutables) bool {
	if len(args) == 0 {
		return false
	}
	name, ok := staticText(args[0])
	if !ok {
		if param, _ := variableReference(args[0]); param != nil {
			name, ok = resolved.lookup(param.Param.Value, args[0].Pos())
		}
	}
	if !ok {
		return true
	}
	program := commandProgram(name)
	rest := args[1:]
	if builtinWrappers[program] {
		if inner, unwrapped := commandAfterCommandBuiltin(args); unwrapped {
			return callWritesVariables(inner, resolved)
		}
		// Only `command -v name` and `command -V name` are inert; a wrapper that
		// does not unwrap for any other reason may still run a builtin.
		if len(rest) == 0 {
			return true
		}
		option, static := staticText(rest[0])
		return !static || (option != "-v" && option != "-V")
	}
	switch program {
	case "printf", "print":
		return mayCarryOption(rest, "v")
	case "set":
		return namesKeyword(rest) || mayCarryOption(rest, "Ak")
	case "shopt":
		return namesKeyword(rest)
	case "wait":
		return mayCarryOption(rest, "p")
	case "test", "[":
		return testWrites(rest)
	}
	return variableWritingBuiltins[program]
}

// mayCarryOption reports whether the option words of a call can pass one of
// the letters.
func mayCarryOption(args []*syntax.Word, letters string) bool {
	afterOption := false
	for _, arg := range args {
		value, ok := staticText(arg)
		if !ok {
			return true
		}
		isOption := strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+")
		if value == "--" || (!afterOption && !isOption) {
			return false
		}
		if isOption && strings.ContainsAny(value, letters) {
			return true
		}
		afterOption = isOption
	}
	return false
}

func namesKeyword(words []*syntax.Word) bool {
	for _, word := range words {
		if value, ok := staticText(word); ok && value == "keyword" {
			return true
		}
	}
	return false
}

// testWrites reports whether a test or [ call can apply -v to an array element,
// whose subscript bash evaluates as arithmetic. A three-word test with a
// readable middle word other than -v is a binary test: in bash and zsh, test
// and [ evaluate nothing for those, and the numeric operators take integer
// literals only, unlike [[.
func testWrites(args []*syntax.Word) bool {
	words := make([]*syntax.Word, 0, len(args))
	for _, word := range args {
		if wordSplits(word) {
			return true
		}
		if value, ok := staticText(word); ok && (value == "]" || value == "!") {
			continue
		}
		words = append(words, word)
	}
	if len(words) == 3 {
		if value, ok := staticText(words[1]); ok && value != "-v" {
			return false
		}
	}
	elements, hasV := 0, false
	for _, word := range words {
		value, ok := staticText(word)
		switch {
		case !ok || strings.Contains(value, "["):
			elements++
		case value == "-v":
			hasV = true
		}
	}
	return elements >= 2 || (elements > 0 && hasV)
}

// Double quotes do not join $@ or ${name[@]}.
func wordSplits(word *syntax.Word) bool {
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(p.Value, "*?{") {
				return true
			}
		case *syntax.SglQuoted, *syntax.DblQuoted:
		default:
			return true
		}
	}
	list := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if list {
			return false
		}
		param, ok := node.(*syntax.ParamExp)
		if !ok {
			return true
		}
		if param.Param != nil && param.Param.Value == "@" {
			list = true
		} else if index, isWord := param.Index.(*syntax.Word); isWord {
			value, static := staticWord(index)
			list = static && value == "@"
		}
		return !list
	})
	return list
}

// args is the call after wrapper unwrapping, a non-empty suffix of call.Args
// when the call has no assignments. An environment word can configure the
// interpreter before it reads the script, a redirect or script word the outer
// shell rewrites is not the text the inner shell sees (the option scan rejects
// such a script word), and keyword mode (-k, -o keyword) turns assignment
// words after a command into assignments.
func resolvableScript(call *syntax.CallExpr, args []*syntax.Word, redirects []*syntax.Redirect) bool {
	if len(call.Assigns) > 0 {
		return false
	}
	for _, word := range call.Args[:len(call.Args)-len(args)] {
		if value, ok := staticText(word); !ok || strings.Contains(value, "=") {
			return false
		}
	}
	for _, redirect := range redirects {
		if redirect.Word == nil {
			continue
		}
		if _, ok := staticText(redirect.Word); !ok {
			return false
		}
	}
	return !mayCarryOption(args[1:], "k") && !namesKeyword(args[1:])
}

// staticText returns the text of a word the shell looks up as written. Beyond
// posixPartsExpand, an unquoted backslash rewrites the word, and the bare test
// command `[` is the one bracket the shell reads as written.
func staticText(word *syntax.Word) (string, bool) {
	value, ok := staticWord(word)
	if !ok {
		return "", false
	}
	if value == "[" && len(word.Parts) == 1 {
		return value, true
	}
	if posixPartsExpand(word.Parts, true) {
		return "", false
	}
	for _, part := range word.Parts {
		if lit, isLit := part.(*syntax.Lit); isLit && strings.Contains(lit.Value, `\`) {
			return "", false
		}
	}
	return value, true
}

// Indirection and zsh flags need no check here: paramEvaluates makes the
// input opaque.
func variableReference(word *syntax.Word) (*syntax.ParamExp, *syntax.DblQuoted) {
	if len(word.Parts) != 1 {
		return nil, nil
	}
	part := word.Parts[0]
	quoted, isQuoted := part.(*syntax.DblQuoted)
	if isQuoted {
		if quoted.Dollar || len(quoted.Parts) != 1 {
			return nil, nil
		}
		part = quoted.Parts[0]
	}
	param, ok := part.(*syntax.ParamExp)
	if !ok || param.Param == nil || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.Exp != nil ||
		param.NestedParam != nil || len(param.Modifiers) != 0 {
		return nil, nil
	}
	return param, quoted
}

// The literal keeps the span and the double quotes of the reference, so
// positions and quote fields still describe the input as written.
func resolvedCall(call *syntax.CallExpr, resolved resolvedExecutables) *syntax.CallExpr {
	if len(call.Args) == 0 {
		return call
	}
	param, quoted := variableReference(call.Args[0])
	if param == nil {
		return call
	}
	executable, ok := resolved.lookup(param.Param.Value, call.Args[0].Pos())
	if !ok {
		return call
	}
	var part syntax.WordPart = &syntax.Lit{ValuePos: param.Pos(), ValueEnd: param.End(), Value: executable}
	if quoted != nil {
		part = &syntax.DblQuoted{Left: quoted.Left, Right: quoted.Right, Parts: []syntax.WordPart{part}}
	}
	args := make([]*syntax.Word, len(call.Args))
	copy(args, call.Args)
	args[0] = &syntax.Word{Parts: []syntax.WordPart{part}}
	out := *call
	out.Args = args
	return &out
}
