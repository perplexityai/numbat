package rule

import (
	"errors"
	"strconv"

	"mvdan.cc/sh/v3/syntax"
)

// ShellCommand is a statically identified command invocation available only
// while evaluating CEL rules. It is not part of the emitted event schema.
type ShellCommand struct {
	Executable        string            `cel:"executable"`
	Name              string            `cel:"name"`
	Argv              []string          `cel:"argv"`
	Arguments         []ShellArgument   `cel:"arguments"`
	Assignments       []ShellAssignment `cel:"assignments"`
	Redirects         []ShellRedirect   `cel:"redirects"`
	Dialect           string            `cel:"dialect"`
	Wrappers          []ShellWrapper    `cel:"wrappers"`
	StatementID       int64             `cel:"statement_id"`
	PipelineID        int64             `cel:"pipeline_id"`
	ParentStatementID int64             `cel:"parent_statement_id"`
	Preview           string            `cel:"preview"`
	FunctionCall      bool              `cel:"function_call"`
	Recursive         bool              `cel:"recursive"`

	enforcementUnsafe bool
}

// ShellArgument preserves the source semantics of one argv element. Value is
// the same normalized value exposed through ShellCommand.Argv; Source retains
// the token spelling so rules can distinguish executable expansion from inert
// quoted text.
type ShellArgument struct {
	Value       string  `cel:"value"`
	Source      string  `cel:"source"`
	Quote       string  `cel:"quote"`
	Expands     bool    `cel:"expands"`
	Subcommands []int64 `cel:"subcommands"`
}

// ShellAssignment records a shell assignment applied to a command or current
// shell. Value preserves source-level dynamic references without evaluating them.
type ShellAssignment struct {
	Name   string `cel:"name"`
	Value  string `cel:"value"`
	Append bool   `cel:"append"`

	// Kept out of CEL; it only prevents decisions from inferred runtime values.
	runtimeDependent bool
}

// ShellWrapper records a transparent launcher around a ShellCommand.
// Argv includes the wrapper executable and options, but excludes the child
// command or inline script.
type ShellWrapper struct {
	Executable string   `cel:"executable"`
	Name       string   `cel:"name"`
	Argv       []string `cel:"argv"`
}

// ShellRedirect is one syntactic redirection attached to a ShellCommand.
// FD is -1 when the operator addresses both standard output and error.
type ShellRedirect struct {
	FD            int64   `cel:"fd"`
	Op            string  `cel:"op"`
	Target        string  `cel:"target"`
	TargetSource  string  `cel:"target_source"`
	TargetQuote   string  `cel:"target_quote"`
	TargetExpands bool    `cel:"target_expands"`
	Subcommands   []int64 `cel:"subcommands"`
}

const (
	previewNormal    = "normal"
	previewRequested = "preview"
	previewUncertain = "uncertain"

	redirectRead      = "read"
	redirectWrite     = "write"
	redirectAppend    = "append"
	redirectReadWrite = "read_write"
	redirectHereDoc   = "here_doc"
	redirectDuplicate = "duplicate"
	redirectClose     = "close"
)

type posixCommandContext struct {
	statementID       int64
	pipelineID        int64
	parentStatementID int64
	statementIDs      map[*syntax.Stmt]int64
}

func projectPOSIXCommand(source string, args []*syntax.Word, assignments []*syntax.Assign, redirects []*syntax.Redirect, wrappers []ShellWrapper, ctx posixCommandContext) (ShellCommand, bool, error) {
	command := ShellCommand{
		Dialect:           dialectPOSIX.String(),
		Wrappers:          cloneWrappers(wrappers),
		StatementID:       ctx.statementID,
		PipelineID:        ctx.pipelineID,
		ParentStatementID: ctx.parentStatementID,
		Preview:           previewNormal,
	}
	if len(args) > 0 {
		executable, ok := staticWord(args[0])
		if !ok {
			return ShellCommand{}, false, errors.New("shell command analysis: dynamic command executable")
		}
		if executable == "" {
			return ShellCommand{}, false, errors.New("shell command analysis: empty command executable")
		}
		command.Executable = executable
		command.Name = commandProgram(executable)
		command.Argv = make([]string, len(args))
		command.Arguments = make([]ShellArgument, len(args))
		for i, arg := range args {
			projected, err := projectPOSIXArgument(source, arg, ctx.statementIDs)
			if err != nil {
				return ShellCommand{}, false, err
			}
			command.Arguments[i] = projected
			command.Argv[i] = projected.Value
		}
	}
	var err error
	command.Assignments, err = projectPOSIXAssignments(source, assignments)
	if err != nil {
		return ShellCommand{}, false, err
	}
	if len(redirects) > 0 {
		command.Redirects = make([]ShellRedirect, 0, len(redirects))
		for _, redirect := range redirects {
			projected, err := projectPOSIXRedirect(source, redirect, ctx.statementIDs)
			if err != nil {
				return command, false, err
			}
			command.Redirects = append(command.Redirects, projected)
		}
	}
	return command, len(args) > 0 || len(assignments) > 0 || len(redirects) > 0, nil
}

func projectPOSIXDeclaration(source string, declaration *syntax.DeclClause, redirects []*syntax.Redirect, wrappers []ShellWrapper, ctx posixCommandContext) (ShellCommand, bool, error) {
	if declaration == nil || declaration.Variant == nil {
		return ShellCommand{}, false, errors.New("shell command analysis: malformed declaration")
	}
	command := ShellCommand{
		Executable:        declaration.Variant.Value,
		Name:              commandProgram(declaration.Variant.Value),
		Argv:              make([]string, 1, len(declaration.Args)+1),
		Arguments:         make([]ShellArgument, 1, len(declaration.Args)+1),
		Dialect:           dialectPOSIX.String(),
		Wrappers:          cloneWrappers(wrappers),
		StatementID:       ctx.statementID,
		PipelineID:        ctx.pipelineID,
		ParentStatementID: ctx.parentStatementID,
		Preview:           previewNormal,
	}
	command.Argv[0] = declaration.Variant.Value
	command.Arguments[0] = ShellArgument{
		Value:  declaration.Variant.Value,
		Source: declaration.Variant.Value,
		Quote:  quoteNone,
	}
	for _, arg := range declaration.Args {
		value, err := sourceSpan(source, arg.Pos(), arg.End())
		if err != nil {
			return ShellCommand{}, false, err
		}
		command.Argv = append(command.Argv, value)
		command.Arguments = append(command.Arguments, ShellArgument{
			Value:  value,
			Source: value,
			Quote:  quoteNone,
		})
	}
	var err error
	command.Assignments, err = projectPOSIXAssignments(source, declaration.Args)
	if err != nil {
		return ShellCommand{}, false, err
	}
	if len(redirects) > 0 {
		command.Redirects = make([]ShellRedirect, 0, len(redirects))
		for _, redirect := range redirects {
			projected, err := projectPOSIXRedirect(source, redirect, ctx.statementIDs)
			if err != nil {
				return ShellCommand{}, false, err
			}
			command.Redirects = append(command.Redirects, projected)
		}
	}
	return command, true, nil
}

func projectPOSIXAssignments(source string, assignments []*syntax.Assign) ([]ShellAssignment, error) {
	projected := make([]ShellAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		if assignment == nil || assignment.Name == nil || assignment.Naked {
			continue
		}
		value := ""
		runtimeDependent := false
		switch {
		case assignment.Value != nil:
			var err error
			value, err = shellWordValue(source, assignment.Value)
			if err != nil {
				return nil, err
			}
			spelling, err := sourceSpan(source, assignment.Value.Pos(), assignment.Value.End())
			if err != nil {
				return nil, err
			}
			runtimeDependent = posixWordExpands(assignment.Value, spelling)
		case assignment.Array != nil:
			var err error
			value, err = sourceSpan(source, assignment.Array.Pos(), assignment.Array.End())
			if err != nil {
				return nil, err
			}
			// Array elements are not individually projected, so their runtime
			// value cannot support an enforcement decision.
			runtimeDependent = true
		}
		projected = append(projected, ShellAssignment{
			Name:             assignment.Name.Value,
			Value:            value,
			Append:           assignment.Append,
			runtimeDependent: runtimeDependent,
		})
	}
	return projected, nil
}

func projectPOSIXRedirect(source string, redirect *syntax.Redirect, statementIDs map[*syntax.Stmt]int64) (ShellRedirect, error) {
	fd := defaultRedirectFD(redirect.Op)
	if redirect.N != nil {
		value := redirect.N.Value
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return ShellRedirect{}, errors.New("shell command analysis: dynamic redirect descriptor")
		}
		fd = parsed
	}
	target, err := projectPOSIXArgument(source, redirect.Word, statementIDs)
	if err != nil {
		return ShellRedirect{}, err
	}
	op := redirectOp(redirect.Op, target.Value)
	if op == "" {
		return ShellRedirect{}, errors.New("shell command analysis: unsupported redirect")
	}
	return ShellRedirect{
		FD:            fd,
		Op:            op,
		Target:        target.Value,
		TargetSource:  target.Source,
		TargetQuote:   target.Quote,
		TargetExpands: target.Expands,
		Subcommands:   target.Subcommands,
	}, nil
}

func defaultRedirectFD(op syntax.RedirOperator) int64 {
	switch op {
	case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return 0
	case syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return -1
	default:
		return 1
	}
}

func redirectOp(op syntax.RedirOperator, target string) string {
	switch op {
	case syntax.RdrIn:
		return redirectRead
	case syntax.RdrOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob:
		return redirectWrite
	case syntax.AppOut, syntax.AppClob, syntax.AppAll, syntax.AppAllClob:
		return redirectAppend
	case syntax.RdrInOut:
		return redirectReadWrite
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return redirectHereDoc
	case syntax.DplIn, syntax.DplOut:
		if target == "-" {
			return redirectClose
		}
		return redirectDuplicate
	default:
		return ""
	}
}

func shellWordValue(source string, word *syntax.Word) (string, error) {
	if word == nil {
		return "", errors.New("shell command analysis: redirect without target")
	}
	if value, ok := staticWord(word); ok {
		return value, nil
	}
	value, err := sourceSpan(source, word.Pos(), word.End())
	if err != nil {
		return "", err
	}
	return trimOuterQuotes(value), nil
}

func trimOuterQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	first, last := value[0], value[len(value)-1]
	if first == last && (first == '\'' || first == '"') {
		return value[1 : len(value)-1]
	}
	return value
}

func wrapperProjection(source string, outer, inner []*syntax.Word) (ShellWrapper, error) {
	n := len(outer) - len(inner)
	if n <= 0 {
		return ShellWrapper{}, errors.New("shell command analysis: invalid wrapper projection")
	}
	argv := make([]string, n)
	for i, word := range outer[:n] {
		value, err := shellWordValue(source, word)
		if err != nil {
			return ShellWrapper{}, err
		}
		argv[i] = value
	}
	executable, ok := staticWord(outer[0])
	if !ok {
		return ShellWrapper{}, errors.New("shell command analysis: dynamic wrapper executable")
	}
	return ShellWrapper{Executable: executable, Name: commandProgram(executable), Argv: argv}, nil
}

func projectInterpreterWrapper(source string, args []*syntax.Word) (ShellWrapper, error) {
	if len(args) == 0 {
		return ShellWrapper{}, errors.New("shell command analysis: empty interpreter projection")
	}
	executable, ok := staticWord(args[0])
	if !ok {
		return ShellWrapper{}, errors.New("shell command analysis: dynamic interpreter executable")
	}
	argv := make([]string, len(args))
	for i, word := range args {
		value, err := shellWordValue(source, word)
		if err != nil {
			return ShellWrapper{}, err
		}
		argv[i] = value
	}
	return ShellWrapper{Executable: executable, Name: commandProgram(executable), Argv: argv}, nil
}

func cloneWrappers(in []ShellWrapper) []ShellWrapper {
	if len(in) == 0 {
		return nil
	}
	out := make([]ShellWrapper, len(in))
	for i, wrapper := range in {
		out[i] = ShellWrapper{
			Executable: wrapper.Executable,
			Name:       wrapper.Name,
			Argv:       append([]string(nil), wrapper.Argv...),
		}
	}
	return out
}

func (d commandDialect) String() string {
	switch d {
	case dialectPOSIX:
		return "posix"
	case dialectPowerShell:
		return "powershell"
	case dialectCMD:
		return "cmd"
	default:
		return ""
	}
}
