package rule

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"mvdan.cc/sh/v3/syntax"

	"github.com/perplexityai/numbat/internal/model"
)

const (
	shellCommandsVariable          = "shell_commands"
	shellCommandCandidatesVariable = "__numbat_shell_command_candidates"
	maxShellCommandBytes           = 256 << 10
	maxShellCommands               = 64
	maxShellListItems              = 512
	maxCommandExpansionDepth       = 4
)

type commandDialect uint8

const (
	dialectAuto commandDialect = iota
	dialectPOSIX
	dialectPowerShell
	dialectCMD
)

type sequenceActivations struct {
	detection            map[string]any
	shellUsable          bool
	shellEnforcementSafe bool
	err                  error
}

// prepareActivations adds the rule-only shell command projection when a
// compiled expression references it. Detection sees every statically proven
// command. The projection is never emitted.
func prepareActivations(adapter types.Adapter, ev model.Event, needShellCommands bool) sequenceActivations {
	detection := ev.CELActivation()
	detection["event"] = adapter.NativeToValue(detection["event"])
	if !needShellCommands {
		return sequenceActivations{
			detection:            detection,
			shellUsable:          true,
			shellEnforcementSafe: true,
		}
	}
	analysis := analyzeEventShellCommandsDetailed(ev)
	detection[shellCommandsVariable] = shellCommandList(adapter, analysis.commands)
	detection[shellCommandCandidatesVariable] = shellCommandCandidateList(adapter, analysis.enforcementCandidates)
	return sequenceActivations{
		detection:            detection,
		shellUsable:          analysis.usable,
		shellEnforcementSafe: analysis.enforcementSafe,
		err:                  analysis.err,
	}
}

// commandSafeForEnforcement rejects a command whose runtime meaning can differ
// from the parsed argv used by a rule.
func commandSafeForEnforcement(command ShellCommand) bool {
	if command.Preview != previewNormal || command.FunctionCall || command.enforcementUnsafe {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands {
			return false
		}
	}
	for _, assignment := range command.Assignments {
		if assignment.runtimeDependent {
			return false
		}
	}
	for _, redirect := range command.Redirects {
		if redirect.TargetExpands {
			return false
		}
	}
	return true
}

func shellCommandList(adapter types.Adapter, commands []ShellCommand) ref.Val {
	values := make([]ref.Val, len(commands))
	for i := range commands {
		values[i] = adapter.NativeToValue(commands[i])
	}
	return types.NewRefValList(adapter, values)
}

func shellCommandCandidateList(adapter types.Adapter, candidates [][]ShellCommand) ref.Val {
	values := make([]ref.Val, len(candidates))
	for i, commands := range candidates {
		values[i] = shellCommandList(adapter, commands)
	}
	return types.NewRefValList(adapter, values)
}

type SequenceActivations struct {
	prepared sequenceActivations
}

// PrepareSequenceActivations builds the command view shared by every sequence
// step for an event.
func PrepareSequenceActivations(ev model.Event, rules []*SequenceRule) (SequenceActivations, error) {
	var adapter types.Adapter = types.DefaultTypeAdapter
	if len(rules) > 0 {
		adapter = rules[0].adapter
	}
	for _, r := range rules {
		if r.usesShellCommands {
			prepared := prepareActivations(adapter, ev, true)
			return SequenceActivations{prepared: prepared}, prepared.err
		}
	}
	prepared := prepareActivations(adapter, ev, false)
	return SequenceActivations{prepared: prepared}, prepared.err
}

type fatalShellAnalysisError struct {
	err error
}

func (e *fatalShellAnalysisError) Error() string { return e.err.Error() }
func (e *fatalShellAnalysisError) Unwrap() error { return e.err }

func hasFatalShellAnalysisError(err error) bool {
	var fatal *fatalShellAnalysisError
	return errors.As(err, &fatal)
}

type shellAnalyzer struct {
	commands                  []ShellCommand
	issues                    []error
	issueIndex                map[string]int
	powerShellFunctions       map[string]string
	activePowerShellFunctions map[string]bool
	powerShellWhatIf          powerShellWhatIfState
	enforcementUnsafe         bool
	statementCounter          int64
	pipelineCounter           int64
	unsafePipelines           map[int64]bool
	unsafeStatements          map[int64]bool
	statementParents          map[int64]int64
	halt                      bool
	resolved                  resolvedExecutables
}

type shellAnalysis struct {
	commands              []ShellCommand
	enforcementCandidates [][]ShellCommand
	usable                bool
	enforcementSafe       bool
	err                   error
}

func analyzeShellCommands(source string) ([]ShellCommand, bool, error) {
	return analyzeShellCommandsAs(source, dialectAuto)
}

func analyzeEventShellCommands(ev model.Event) ([]ShellCommand, bool, error) {
	analysis := analyzeEventShellCommandsDetailed(ev)
	return analysis.commands, analysis.usable, analysis.err
}

func analyzeEventShellCommandsDetailed(ev model.Event) shellAnalysis {
	return analyzeShellCommandsDetailed(ev.Command, commandDialectHint(ev))
}

func analyzeShellCommandsAs(source string, dialect commandDialect) ([]ShellCommand, bool, error) {
	analysis := analyzeShellCommandsDetailed(source, dialect)
	return analysis.commands, analysis.usable, analysis.err
}

func analyzeShellCommandsDetailed(source string, dialect commandDialect) shellAnalysis {
	if strings.TrimSpace(source) == "" {
		return shellAnalysis{usable: true, enforcementSafe: true}
	}
	a := shellAnalyzer{
		unsafePipelines:  make(map[int64]bool),
		unsafeStatements: make(map[int64]bool),
		statementParents: make(map[int64]int64),
	}
	a.parseDialectUnderRedirects(source, dialect, 0, nil, 0, nil, true)
	err := errors.Join(a.issues...)
	enforcementSafe := !a.enforcementUnsafe && len(a.commands) > 0
	if enforcementSafe {
		for i := range a.commands {
			if !commandSafeForEnforcement(a.commands[i]) {
				enforcementSafe = false
				break
			}
		}
	}
	var candidates [][]ShellCommand
	if !a.halt {
		candidates = posixEnforcementCandidates(a.commands, a.unsafePipelines, a.unsafeStatements, a.statementParents)
	}
	return shellAnalysis{
		commands:              a.commands,
		enforcementCandidates: candidates,
		usable:                err == nil || len(a.commands) > 0,
		enforcementSafe:       enforcementSafe,
		err:                   err,
	}
}

func commandDialectHint(ev model.Event) commandDialect {
	switch commandProgram(strings.TrimSpace(ev.ToolName)) {
	case "bash", "sh", "zsh", "dash", "ksh", "mksh":
		return dialectPOSIX
	case "powershell", "pwsh":
		return dialectPowerShell
	case "cmd":
		return dialectCMD
	case "exec_command":
		if ev.SourceAgent == model.AgentCodex && runtime.GOOS != "windows" {
			return dialectPOSIX
		}
	}
	return dialectAuto
}

func (a *shellAnalyzer) parseDialect(source string, dialect commandDialect, depth int, wrappers []ShellWrapper) {
	a.parseDialectUnderRedirects(source, dialect, depth, wrappers, 0, nil, false)
}

// resolvable is true for the original input and for a nested script whose
// interpreter call passed resolvableScript; text that another shell expanded
// first never resolves.
func (a *shellAnalyzer) parseDialectUnderRedirects(source string, dialect commandDialect, depth int, wrappers []ShellWrapper, parent int64, inheritedRedirects []*syntax.Redirect, resolvable bool) {
	if a.halt {
		return
	}
	switch {
	case len(source) > maxShellCommandBytes:
		a.reportFatal(fmt.Errorf("shell command analysis: input exceeds %d bytes", maxShellCommandBytes))
		return
	case depth > maxCommandExpansionDepth:
		a.report(fmt.Errorf("shell command analysis: expansion nesting exceeds %d", maxCommandExpansionDepth))
		return
	}

	if dialect == dialectAuto {
		dialect = explicitSyntaxDialect(source)
		if dialect == dialectAuto {
			dialect = inferCommandDialect(source)
		}
	}
	switch dialect {
	case dialectPowerShell:
		if !powerShellEnforcementShapeSafe(source) {
			a.enforcementUnsafe = true
		}
		a.parsePowerShell(source, depth, wrappers)
		return
	case dialectCMD:
		if !cmdEnforcementShapeSafe(source) {
			a.enforcementUnsafe = true
		}
		a.parseCMD(source, depth, wrappers)
		return
	case dialectPOSIX:
	default:
		a.reportFatal(errors.New("shell command analysis: unsupported command dialect"))
		return
	}

	file, err := parseShell(source)
	if err != nil {
		a.reportFatal(errors.New("shell command analysis: unsupported or malformed syntax"))
		return
	}
	if !posixEnforcementShapeSafe(file) {
		a.enforcementUnsafe = true
	}

	saved := a.resolved
	a.resolved = nil
	if resolvable {
		a.resolved = resolveTopLevelAssignments(file)
	}
	a.walk(source, file, depth, make(map[string]*syntax.Stmt), make(map[string]bool), wrappers, parent, inheritedRedirects)
	a.resolved = saved
}

func (a *shellAnalyzer) walk(source string, root syntax.Node, depth int, functions map[string]*syntax.Stmt, activeFunctions map[string]bool, wrappers []ShellWrapper, parent int64, inheritedRedirects []*syntax.Redirect) {
	relations := a.buildPOSIXRelations(root, inheritedRedirects)
	for statement, id := range relations.statements {
		if relations.parents[statement] == 0 {
			relations.parents[statement] = parent
		}
		a.statementParents[id] = relations.parents[statement]
	}
	syntax.Walk(root, func(node syntax.Node) bool {
		if a.halt {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if node.Name != nil {
				functions[node.Name.Value] = node.Body
			}
			for _, name := range node.Names {
				functions[name.Value] = node.Body
			}
			return false
		case *syntax.Stmt:
			ctx := relations.context(node)
			statementStart := len(a.commands)
			for _, redirect := range node.Redirs {
				if redirect.Hdoc != nil {
					a.markPipelineUnsafe(ctx)
				}
			}
			if declaration, ok := node.Cmd.(*syntax.DeclClause); ok {
				if ctx.pipelineID != 0 {
					a.markStatementsUnsafe(node, ctx.statementIDs)
					a.markPipelineUnsafe(ctx)
				}
				command, add, err := projectPOSIXDeclaration(source, declaration, node.Redirs, wrappers, ctx)
				if err != nil {
					a.report(err)
					return true
				}
				if add {
					return a.add(command)
				}
				return true
			}
			call, ok := node.Cmd.(*syntax.CallExpr)
			if !ok {
				if len(node.Redirs) > 0 {
					redirectCommand, add, err := projectPOSIXCommand(source, nil, nil, node.Redirs, wrappers, ctx)
					if err != nil {
						a.report(err)
						if ctx.pipelineID != 0 {
							a.markStatementsUnsafe(node, ctx.statementIDs)
						}
						a.markPipelineUnsafe(ctx)
						return true
					}
					if node.Cmd == nil && add {
						return a.add(redirectCommand)
					}
				}
				if node.Cmd != nil {
					if ctx.pipelineID != 0 {
						a.markStatementsUnsafe(node, ctx.statementIDs)
					}
					a.markPipelineUnsafe(ctx)
				}
				return true
			}

			call = resolvedCall(call, a.resolved)
			command, add, err := projectPOSIXCommand(source, call.Args, call.Assigns, node.Redirs, wrappers, ctx)
			if err != nil {
				a.report(err)
				if ctx.pipelineID != 0 {
					a.unsafeStatements[ctx.statementID] = true
				}
				a.markPipelineUnsafe(ctx)
				if command.Executable == "" {
					return true
				}
			}
			if name, ok := commandName(call.Args); ok && functions[name] != nil {
				command.FunctionCall = true
				command.Recursive = activeFunctions[name]
			}
			invocation := inspectShellInvocation(call.Args)
			command.enforcementUnsafe = invocation.noExec || invocation.inputEnforcementUnsafe
			if add && !a.add(command) {
				return false
			}

			args := call.Args
			commandWrappers := cloneWrappers(wrappers)
			allowShellBuiltins := !command.FunctionCall
			wrapperSafe := true
			for !command.FunctionCall {
				wrapperName, _ := commandName(args)
				inner, enforcementSafe := unwrapCommand(args)
				if inner == nil {
					break
				}
				if !enforcementSafe {
					wrapperSafe = false
				}
				wrapperProgram := commandProgram(wrapperName)
				if !allowShellBuiltins && (wrapperProgram == "command" || wrapperProgram == "exec") {
					wrapperSafe = false
				}
				// Basename projection aids detection but cannot prove that a
				// path-qualified program implements the wrapper's semantics.
				if wrapperName != commandProgram(wrapperName) {
					wrapperSafe = false
				}
				wrapper, err := wrapperProjection(source, args, inner)
				if err != nil {
					a.report(err)
					break
				}
				if wrapperProgram == "command" {
					childName, _ := commandName(inner)
					switch commandProgram(childName) {
					case "command", "exec":
						wrapperSafe = false
					}
				}
				commandWrappers = append(commandWrappers, wrapper)
				args = inner
				allowShellBuiltins = allowShellBuiltins && wrapperProgram == "command"
				innerCommand, add, err := projectPOSIXCommand(source, args, call.Assigns, node.Redirs, commandWrappers, ctx)
				if err != nil {
					a.report(err)
					invocation = inspectShellInvocation(args)
					break
				}
				invocation = inspectShellInvocation(args)
				innerCommand.enforcementUnsafe = !wrapperSafe || invocation.noExec || invocation.inputEnforcementUnsafe
				if add && !a.add(innerCommand) {
					return false
				}
			}

			redirects := append(relations.inheritedRedirects[node], node.Redirs...)
			resolvable := a.resolved != nil && resolvableScript(call, args, redirects)
			if !command.FunctionCall {
				if script, dialect, wrapper, ok, err := wrapperScript(source, args); err != nil {
					a.report(err)
				} else if ok {
					innerWrappers := append(cloneWrappers(commandWrappers), wrapper)
					a.parseDialectUnderRedirects(script, dialect, depth+1, innerWrappers, ctx.statementID, redirects, resolvable)
					a.markCommandsUnsafe(statementStart)
				}
				if scripts := interpreterHeredocs(invocation.inputFDs, redirects); len(scripts) > 0 {
					wrapper, err := projectInterpreterWrapper(source, args)
					if err != nil {
						a.report(err)
					} else {
						innerWrappers := append(cloneWrappers(commandWrappers), wrapper)
						a.markCommandsUnsafe(statementStart)
						for _, script := range scripts {
							innerStart := len(a.commands)
							a.parseDialectUnderRedirects(script, dialectPOSIX, depth+1, innerWrappers, ctx.statementID, nil, resolvable)
							if ctx.pipelineID != 0 || !wrapperSafe || invocation.inputEnforcementUnsafe {
								a.markCommandsUnsafe(innerStart)
							}
						}
					}
				}
			}
			if allowShellBuiltins {
				if script, ok := evalScript(source, args); ok {
					a.parseDialectUnderRedirects(script, dialectPOSIX, depth+1, commandWrappers, ctx.statementID, redirects, false)
					a.markCommandsUnsafe(statementStart)
				}
			}
			if command.FunctionCall {
				if name, ok := commandName(call.Args); ok {
					if body := functions[name]; body != nil && depth < maxCommandExpansionDepth && !activeFunctions[name] {
						activeFunctions[name] = true
						a.walk(source, body, depth+1, functions, activeFunctions, commandWrappers, ctx.statementID, redirects)
						delete(activeFunctions, name)
					}
				}
			}
		}
		return true
	})
}

func (a *shellAnalyzer) add(command ShellCommand) bool {
	if len(a.commands) == maxShellCommands {
		a.report(fmt.Errorf("shell command analysis: command count exceeds %d", maxShellCommands))
		a.halt = true
		return false
	}
	if limitShellCommandLists(&command) {
		command.Preview = previewUncertain
		a.report(fmt.Errorf("shell command analysis: command projection list exceeds %d items", maxShellListItems))
	}
	a.commands = append(a.commands, command)
	return true
}

func limitShellCommandLists(command *ShellCommand) bool {
	limited := limitSlice(&command.Argv)
	if limitSlice(&command.Arguments) {
		limited = true
	}
	for i := range command.Arguments {
		limited = limitSlice(&command.Arguments[i].Subcommands) || limited
	}
	if limitSlice(&command.Assignments) {
		limited = true
	}
	if limitSlice(&command.Redirects) {
		limited = true
	}
	for i := range command.Redirects {
		limited = limitSlice(&command.Redirects[i].Subcommands) || limited
	}
	for i := range command.Wrappers {
		limited = limitSlice(&command.Wrappers[i].Argv) || limited
	}
	return limited
}

func limitSlice[T any](values *[]T) bool {
	if len(*values) <= maxShellListItems {
		return false
	}
	*values = (*values)[:maxShellListItems:maxShellListItems]
	return true
}

func (a *shellAnalyzer) report(err error) {
	a.addIssue(err, false)
}

func (a *shellAnalyzer) reportFatal(err error) {
	a.addIssue(err, true)
}

func (a *shellAnalyzer) addIssue(err error, fatal bool) {
	if err == nil {
		return
	}
	a.enforcementUnsafe = true
	if a.issueIndex == nil {
		a.issueIndex = make(map[string]int)
	}
	key := err.Error()
	if index, ok := a.issueIndex[key]; ok {
		if fatal && !hasFatalShellAnalysisError(a.issues[index]) {
			a.issues[index] = &fatalShellAnalysisError{err: err}
		}
		return
	}
	if fatal {
		err = &fatalShellAnalysisError{err: err}
	}
	a.issueIndex[key] = len(a.issues)
	a.issues = append(a.issues, err)
}

func (a *shellAnalyzer) nextStatement() int64 {
	a.statementCounter++
	return a.statementCounter
}

func (a *shellAnalyzer) nextPipeline() int64 {
	a.pipelineCounter++
	return a.pipelineCounter
}

func parseShell(source string) (*syntax.File, error) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err == nil {
		return file, nil
	}
	return syntax.NewParser(syntax.Variant(syntax.LangZsh)).Parse(strings.NewReader(source), "")
}

func sourceSpan(source string, start, end syntax.Pos) (string, error) {
	startOffset, endOffset := start.Offset(), end.Offset()
	if startOffset > endOffset || endOffset > uint(len(source)) {
		return "", errors.New("shell command analysis: invalid parser span")
	}
	return strings.TrimSpace(source[startOffset:endOffset]), nil
}

type commandWrapperSpec struct {
	valueOptions               map[string]bool
	optionalValueOptions       map[string]bool
	flagOptions                map[string]bool
	stopOptions                map[string]bool
	detectionOnlyOptions       map[string]bool
	assignments                bool
	assignmentsAfterTerminator bool
	optionsAfterAssignments    bool
}

var (
	sudoWrapper = commandWrapperSpec{
		valueOptions:            stringSet("-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u", "--chdir", "--close-from", "--group", "--host", "--prompt", "--role", "--type", "--user"),
		optionalValueOptions:    stringSet("--preserve-env"),
		flagOptions:             stringSet("-B", "-b", "-E", "-H", "-n", "-P", "--background", "--bell", "--set-home", "--non-interactive"),
		stopOptions:             stringSet("-e", "-K", "-L", "-l", "-U", "-V", "-v", "--edit", "--help", "--list", "--other-user", "--remove-timestamp", "--validate", "--version"),
		detectionOnlyOptions:    stringSet("-A", "-i", "-k", "-N", "-S", "-s", "--askpass", "--login", "--no-update", "--reset-timestamp", "--shell", "--stdin"),
		assignments:             true,
		optionsAfterAssignments: true,
	}
	doasWrapper = commandWrapperSpec{
		valueOptions: stringSet("-a", "-u"),
		flagOptions:  stringSet("-n"),
		stopOptions:  stringSet("-C", "-L", "-s"),
	}
	envWrapper = commandWrapperSpec{
		valueOptions:               stringSet("-C", "-u", "--chdir", "--unset"),
		flagOptions:                stringSet("-", "-0", "-i", "--ignore-environment", "--null"),
		stopOptions:                stringSet("-S", "--help", "--split-string", "--version"),
		assignments:                true,
		assignmentsAfterTerminator: true,
	}
	execWrapper = commandWrapperSpec{
		valueOptions: stringSet("-a"),
		flagOptions:  stringSet("-c", "-l"),
	}
)

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func unwrapCommand(args []*syntax.Word) ([]*syntax.Word, bool) {
	name, ok := commandName(args)
	if !ok {
		return nil, false
	}
	switch commandProgram(name) {
	case "sudo":
		return commandAfterWrapper(args, sudoWrapper)
	case "doas":
		return commandAfterWrapper(args, doasWrapper)
	case "env":
		return commandAfterWrapper(args, envWrapper)
	case "exec":
		return commandAfterWrapper(args, execWrapper)
	case "command":
		inner, ok := commandAfterCommandBuiltin(args)
		if !ok {
			return nil, false
		}
		return inner, true
	case "nohup":
		if len(args) > 1 {
			value, static := staticWord(args[1])
			if static && value == "--" {
				args = args[1:]
			}
		}
		if len(args) > 1 {
			value, static := staticWord(args[1])
			if !static || strings.HasPrefix(value, "-") {
				return nil, false
			}
			return args[1:], true
		}
	}
	return nil, false
}

func commandAfterWrapper(args []*syntax.Word, spec commandWrapperSpec) ([]*syntax.Word, bool) {
	enforcementSafe := true
	for i := 1; i < len(args); i++ {
		value, ok := staticWord(args[i])
		if !ok {
			return nil, false
		}
		if value == "--" {
			i++
			if spec.assignmentsAfterTerminator {
				for i < len(args) {
					value, ok = staticWord(args[i])
					if !ok {
						return nil, false
					}
					if !isAssignment(value) {
						break
					}
					i++
				}
			}
			if i < len(args) {
				return args[i:], enforcementSafe
			}
			return nil, false
		}
		if spec.assignments && isAssignment(value) {
			if spec.optionsAfterAssignments {
				continue
			}
			for i++; i < len(args); i++ {
				value, ok = staticWord(args[i])
				if !ok {
					return nil, false
				}
				if !isAssignment(value) {
					return args[i:], enforcementSafe
				}
			}
			return nil, false
		}
		if value == "-" {
			if spec.flagOptions[value] {
				continue
			}
			return args[i:], enforcementSafe
		}
		if !strings.HasPrefix(value, "-") {
			return args[i:], enforcementSafe
		}

		if strings.HasPrefix(value, "--") {
			option, attached := splitLongOption(value)
			switch {
			case spec.stopOptions[option]:
				return nil, false
			case spec.valueOptions[option]:
				enforcementSafe = false
				if attached {
					continue
				}
				i++
				if i >= len(args) {
					return nil, false
				}
			case spec.optionalValueOptions[option]:
				if attached {
					enforcementSafe = false
				}
			case spec.flagOptions[option]:
				if attached {
					return nil, false
				}
			case spec.detectionOnlyOptions[option]:
				if attached {
					return nil, false
				}
				enforcementSafe = false
			default:
				return nil, false
			}
			continue
		}
		consumeNext, safe, ok := consumeShortOptions(value, spec)
		if !ok {
			return nil, false
		}
		enforcementSafe = enforcementSafe && safe
		if consumeNext {
			i++
			if i >= len(args) {
				return nil, false
			}
		}
	}
	return nil, false
}

func splitLongOption(value string) (string, bool) {
	if i := strings.IndexByte(value, '='); i >= 0 {
		return value[:i], true
	}
	return value, false
}

func consumeShortOptions(value string, spec commandWrapperSpec) (bool, bool, bool) {
	if len(value) < 2 || value[0] != '-' {
		return false, false, false
	}
	enforcementSafe := true
	for i := 1; i < len(value); i++ {
		option := "-" + value[i:i+1]
		switch {
		case spec.stopOptions[option]:
			return false, false, false
		case spec.valueOptions[option]:
			return i+1 == len(value), false, true
		case spec.flagOptions[option]:
			continue
		case spec.detectionOnlyOptions[option]:
			enforcementSafe = false
		default:
			return false, false, false
		}
	}
	return false, enforcementSafe, true
}

func commandAfterCommandBuiltin(args []*syntax.Word) ([]*syntax.Word, bool) {
	for i := 1; i < len(args); i++ {
		value, ok := staticWord(args[i])
		if !ok {
			return nil, false
		}
		switch value {
		case "--":
			if i+1 < len(args) {
				return args[i+1:], true
			}
			return nil, false
		case "-p":
			continue
		case "-v", "-V":
			return nil, false
		default:
			if strings.HasPrefix(value, "-") {
				return nil, false
			}
			return args[i:], true
		}
	}
	return nil, false
}

func isAssignment(value string) bool {
	i := strings.IndexByte(value, '=')
	if i <= 0 {
		return false
	}
	for j, r := range value[:i] {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		if r != '_' && !letter && (j == 0 || !digit) {
			return false
		}
	}
	return true
}

func wrapperScript(source string, args []*syntax.Word) (string, commandDialect, ShellWrapper, bool, error) {
	if len(args) == 0 {
		return "", dialectAuto, ShellWrapper{}, false, nil
	}
	name, ok := staticWord(args[0])
	if !ok {
		return "", dialectAuto, ShellWrapper{}, false, errors.New("shell command analysis: dynamic interpreter invocation")
	}
	switch commandProgram(name) {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh":
		for i := 1; i+1 < len(args); i++ {
			flag, ok := staticWord(args[i])
			if !ok {
				return "", dialectAuto, ShellWrapper{}, false, errors.New("shell command analysis: dynamic interpreter option")
			}
			if flag == "--" || len(flag) < 2 || flag[0] != '-' && flag[0] != '+' {
				return "", dialectAuto, ShellWrapper{}, false, nil
			}
			if flag == "-o" || flag == "+o" || flag == "-O" || flag == "+O" || flag == "--rcfile" || flag == "--init-file" {
				i++
				continue
			}
			if !isShellCommandFlag(flag) {
				continue
			}
			script, ok := scriptWord(source, args[i+1])
			if !ok {
				return "", dialectAuto, ShellWrapper{}, false, errors.New("shell command analysis: dynamic inline shell command")
			}
			wrapper, err := projectInterpreterWrapper(source, args[:i+1])
			return script, dialectPOSIX, wrapper, err == nil, err
		}
	case "pwsh", "powershell":
		script, prefix, ok, err := powerShellWrapperScript(source, args)
		if err != nil || !ok {
			return "", dialectAuto, ShellWrapper{}, false, err
		}
		wrapper, err := projectInterpreterWrapper(source, args[:prefix])
		return script, dialectPowerShell, wrapper, err == nil, err
	case "cmd":
		script, prefix, ok, err := cmdWrapperScript(source, args)
		if err != nil || !ok {
			return "", dialectAuto, ShellWrapper{}, false, err
		}
		wrapper, err := projectInterpreterWrapper(source, args[:prefix])
		return script, dialectCMD, wrapper, err == nil, err
	}
	return "", dialectAuto, ShellWrapper{}, false, nil
}

func (a *shellAnalyzer) expandProjectedInterpreter(command ShellCommand, depth int) {
	script, dialect, prefix, ok, err := projectedInterpreterScript(command)
	if err != nil {
		a.report(err)
		return
	}
	if !ok {
		return
	}
	a.enforcementUnsafe = true
	wrapper := ShellWrapper{
		Executable: command.Executable,
		Name:       command.Name,
		Argv:       append([]string(nil), command.Argv[:prefix]...),
	}
	wrappers := append(cloneWrappers(command.Wrappers), wrapper)
	a.parseDialect(script, dialect, depth+1, wrappers)
}

func projectedInterpreterScript(command ShellCommand) (string, commandDialect, int, bool, error) {
	args := command.Arguments
	if len(args) == 0 {
		return "", dialectAuto, 0, false, nil
	}
	switch command.Name {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh":
		for i := 1; i+1 < len(args); i++ {
			flag := args[i]
			if flag.Expands {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic interpreter option")
			}
			if flag.Value == "--" || len(flag.Value) < 2 || flag.Value[0] != '-' && flag.Value[0] != '+' {
				return "", dialectAuto, 0, false, nil
			}
			if flag.Value == "-o" || flag.Value == "+o" || flag.Value == "-O" || flag.Value == "+O" || flag.Value == "--rcfile" || flag.Value == "--init-file" {
				i++
				continue
			}
			if !isShellCommandFlag(flag.Value) {
				continue
			}
			script, ok := joinProjectedScript(args[i+1:])
			if !ok {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic inline shell command")
			}
			return script, dialectPOSIX, i + 1, true, nil
		}
	case "pwsh", "powershell":
		return projectedPowerShellScript(args)
	case "cmd":
		return projectedCMDScript(args)
	}
	return "", dialectAuto, 0, false, nil
}

func projectedPowerShellScript(args []ShellArgument) (string, commandDialect, int, bool, error) {
	for i := 1; i < len(args); i++ {
		if args[i].Expands {
			return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic PowerShell option")
		}
		flag := args[i].Value
		lower := strings.ToLower(flag)
		if name, _, found := strings.Cut(lower, ":"); found {
			lower = name
		}
		switch lower {
		case "-c", "-command":
			if i+1 >= len(args) {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: PowerShell command option without value")
			}
			script, ok := joinProjectedScript(args[i+1:])
			if !ok || script == "-" {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic PowerShell command input")
			}
			return script, dialectPowerShell, i + 1, true, nil
		case "-commandwithargs", "-cwa":
			if i+1 >= len(args) {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: PowerShell command option without value")
			}
			script, ok := joinProjectedScript(args[i+1 : i+2])
			if !ok || script == "-" {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic PowerShell command input")
			}
			return script, dialectPowerShell, i + 1, true, nil
		case "-e", "-ec", "-enc", "-encodedcommand":
			if i+1 >= len(args) || args[i+1].Expands {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: invalid PowerShell encoded command")
			}
			script, ok := decodePowerShellCommand(args[i+1].Value)
			if !ok {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: invalid PowerShell encoded command")
			}
			return script, dialectPowerShell, i + 1, true, nil
		case "-f", "-file", "-filewithargs", "-help", "-?", "-h":
			return "", dialectAuto, 0, false, nil
		case "-configurationfile", "-configurationname", "-config", "-custompipename",
			"-encodedarguments", "-executionpolicy", "-ex", "-ep",
			"-inputformat", "-outputformat", "-settingsfile", "-windowstyle",
			"-workingdirectory", "-psconsolefile", "-version":
			if !strings.Contains(flag, ":") {
				i++
				if i >= len(args) {
					return "", dialectAuto, 0, false, errors.New("shell command analysis: PowerShell option without value")
				}
			}
		case "-interactive", "-login", "-mta", "-noexit", "-nologo", "-noninteractive",
			"-noni", "-noprofile", "-nop", "-noprofileloadtime", "-sta":
		default:
			if !strings.HasPrefix(flag, "-") {
				return "", dialectAuto, 0, false, nil
			}
			return "", dialectAuto, 0, false, errors.New("shell command analysis: unsupported PowerShell option")
		}
	}
	return "", dialectAuto, 0, false, nil
}

func projectedCMDScript(args []ShellArgument) (string, commandDialect, int, bool, error) {
	for i := 1; i < len(args); i++ {
		if args[i].Expands {
			return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic cmd option")
		}
		flag := strings.ToLower(args[i].Value)
		switch {
		case flag == "/c" || flag == "/k":
			if i+1 >= len(args) {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: cmd command option without value")
			}
			script, ok := joinProjectedScript(args[i+1:])
			if !ok {
				return "", dialectAuto, 0, false, errors.New("shell command analysis: dynamic cmd command input")
			}
			return script, dialectCMD, i + 1, true, nil
		case flag == "/a" || flag == "/d" || flag == "/q" || flag == "/s" || flag == "/u" ||
			strings.HasPrefix(flag, "/t:") || strings.HasPrefix(flag, "/e:") ||
			strings.HasPrefix(flag, "/f:") || strings.HasPrefix(flag, "/v:"):
		default:
			if !strings.HasPrefix(flag, "/") {
				return "", dialectAuto, 0, false, nil
			}
			return "", dialectAuto, 0, false, errors.New("shell command analysis: unsupported cmd option")
		}
	}
	return "", dialectAuto, 0, false, nil
}

func joinProjectedScript(args []ShellArgument) (string, bool) {
	values := make([]string, len(args))
	for i := range args {
		if args[i].Expands {
			return "", false
		}
		values[i] = args[i].Value
	}
	return strings.Join(values, " "), true
}

func interpreterHeredocs(fds []int64, redirects []*syntax.Redirect) []string {
	var scripts []string
	var seen *syntax.Redirect
	for _, fd := range fds {
		if script, redirect, ok := heredocForFD(redirects, fd); ok && redirect != seen {
			scripts = append(scripts, script)
			seen = redirect
		}
	}
	return scripts
}

func heredocForFD(redirects []*syntax.Redirect, fd int64) (string, *syntax.Redirect, bool) {
	for i := len(redirects) - 1; i >= 0; i-- {
		redirect := redirects[i]
		redirectFD, valid := posixRedirectFD(redirect)
		if !valid {
			continue
		}
		if redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut {
			target, static := staticWord(redirect.Word)
			if !static {
				return "", nil, false
			}
			if target == "-" {
				if redirectFD == fd {
					return "", nil, false
				}
				continue
			}
			moved := strings.HasSuffix(target, "-")
			sourceFD, valid := parseShellFD(strings.TrimSuffix(target, "-"))
			if !valid {
				return "", nil, false
			}
			if moved && sourceFD == fd && redirectFD != fd {
				return "", nil, false
			}
			if redirectFD == fd {
				fd = sourceFD
			}
			continue
		}
		if redirectFD != fd {
			continue
		}
		if (redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) && redirect.Hdoc != nil {
			script, ok := staticWord(redirect.Hdoc)
			return script, redirect, ok
		}
		if redirect.Op == syntax.WordHdoc {
			script, ok := staticWord(redirect.Word)
			return script, redirect, ok
		}
		return "", nil, false
	}
	return "", nil, false
}

type shellInvocation struct {
	inputFDs               []int64
	inputEnforcementUnsafe bool
	noExec                 bool
}

func inspectShellInvocation(args []*syntax.Word) shellInvocation {
	name, ok := commandName(args)
	if !ok {
		return shellInvocation{}
	}
	program := commandProgram(name)
	if !isShellInterpreter(program) {
		return shellInvocation{}
	}
	var (
		noExec, terminalNoExec        bool
		interactive, stdin            bool
		startupFD                     int64
		startupFound, startupDisabled bool
		inputFD                       int64
		inputFound                    = true
		inputEnforcementUnsafe        bool
		bashShortOption               bool
		shOptionLetters               bool
	)
	for i := 1; i < len(args); i++ {
		flag, static := staticWord(args[i])
		if !static {
			inputFound = false
			break
		}
		if flag == "--" || flag == "-" || program == "zsh" && (flag == "+" || flag == "+-" || !shOptionLetters && (flag == "-b" || flag == "+b")) {
			if !stdin && i+1 < len(args) {
				script, static := staticWord(args[i+1])
				inputFD, inputFound = shellInputPathFD(script)
				if !static {
					inputFound = false
				}
			}
			break
		}
		if len(flag) < 2 || flag[0] != '-' && flag[0] != '+' {
			if !stdin {
				inputFD, inputFound = shellInputPathFD(flag)
			}
			break
		}
		if program == "bash" && strings.HasPrefix(flag, "--") && bashShortOption {
			terminalNoExec = true
			inputFound = false
			break
		}
		if flag == "--help" || flag == "--version" || program == "bash" && (flag == "--dump-strings" || flag == "--dump-po-strings") {
			terminalNoExec = true
			continue
		}
		if program == "bash" && flag == "--pretty-print" {
			terminalNoExec = true
			continue
		}
		if program == "zsh" && strings.HasPrefix(flag, "+-") && applyZshOption(flag[2:], false, &noExec, &stdin, &shOptionLetters) {
			continue
		}
		longOption := strings.TrimPrefix(flag, "--")
		if program == "zsh" {
			longOption = normalizedZshOption(longOption)
			if applyZshOption(longOption, true, &noExec, &stdin, &shOptionLetters) {
				continue
			}
		}
		if longOption == "noexec" {
			noExec = true
			continue
		}
		if program == "zsh" && len(flag) > 2 && (flag[:2] == "-o" || flag[:2] == "+o") {
			applyZshOption(flag[2:], flag[0] == '-', &noExec, &stdin, &shOptionLetters)
			continue
		}
		if program == "bash" && !strings.HasPrefix(flag, "--") {
			bashShortOption = true
		}
		if flag == "-o" || flag == "+o" {
			i++
			if i >= len(args) {
				inputFound = false
				break
			}
			option, static := staticWord(args[i])
			if !static {
				inputFound = false
				break
			}
			known := option == "noexec"
			if program == "zsh" {
				known = applyZshOption(option, flag[0] == '-', &noExec, &stdin, &shOptionLetters)
			} else if known {
				noExec = flag[0] == '-'
			}
			if !known {
				inputEnforcementUnsafe = true
			}
			continue
		}
		if flag == "-O" || flag == "+O" {
			i++
			if i >= len(args) {
				inputFound = false
				break
			}
			if _, static := staticWord(args[i]); !static {
				inputFound = false
				break
			}
			inputEnforcementUnsafe = true
			continue
		}
		if program == "bash" && flag == "--norc" {
			startupDisabled = true
			startupFound = false
			continue
		}
		if flag == "--rcfile" || flag == "--init-file" {
			i++
			if program == "bash" && !startupDisabled && i < len(args) {
				startupPath, static := staticWord(args[i])
				startupFD, startupFound = shellInputPathFD(startupPath)
				if !static {
					startupFound = false
				}
			}
			continue
		}
		if strings.HasPrefix(flag, "--") {
			if program == "bash" {
				switch flag {
				case "--debugger", "--login", "--noediting", "--noprofile", "--posix", "--restricted", "--verbose":
					continue
				}
			}
			inputFound = false
			break
		}
		if !validInterpreterOptionLetters(program, flag) {
			inputFound = false
			break
		}
		if strings.ContainsRune(flag[1:], 'i') {
			interactive = flag[0] == '-'
		}
		if strings.ContainsRune(flag[1:], 'n') {
			noExec = flag[0] == '-'
		}
		if program == "bash" && strings.ContainsRune(flag[1:], 'D') {
			terminalNoExec = true
		}
		if flag[0] == '-' && strings.ContainsRune(flag[1:], 'c') {
			inputFound = false
			break
		}
		if strings.ContainsRune(flag[1:], 's') {
			stdin = flag[0] == '-'
		}
	}
	result := shellInvocation{
		inputEnforcementUnsafe: inputEnforcementUnsafe,
		noExec:                 noExec || terminalNoExec,
	}
	if result.noExec {
		return result
	}
	if program == "bash" && interactive && startupFound {
		result.inputFDs = append(result.inputFDs, startupFD)
	}
	if inputFound && (len(result.inputFDs) == 0 || result.inputFDs[0] != inputFD) {
		result.inputFDs = append(result.inputFDs, inputFD)
	}
	return result
}

func validInterpreterOptionLetters(program, flag string) bool {
	allowed := "abefhkmnptuvxCcis"
	switch program {
	case "bash":
		allowed = "abefhkmnptuvxBCEHPTcdilrsD"
	case "zsh":
		allowed = "bcdfiklmnoprsuvxX"
	}
	for _, option := range flag[1:] {
		if !strings.ContainsRune(allowed, option) {
			return false
		}
	}
	return true
}

func normalizedZshOption(option string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(option))
}

func applyZshOption(option string, enabled bool, noExec, stdin, shOptionLetters *bool) bool {
	switch normalizedZshOption(option) {
	case "noexec":
		*noExec = enabled
	case "exec":
		*noExec = !enabled
	case "stdin", "shinstdin":
		*stdin = enabled
	case "nostdin", "noshinstdin":
		*stdin = !enabled
	case "shoptionletters":
		*shOptionLetters = enabled
	case "noshoptionletters":
		*shOptionLetters = !enabled
	default:
		return false
	}
	return true
}

func shellInputPathFD(sourcePath string) (int64, bool) {
	sourcePath = path.Clean(sourcePath)
	if sourcePath == "/dev/stdin" {
		return 0, true
	}
	for _, prefix := range []string{"/dev/fd/", "/proc/self/fd/"} {
		if strings.HasPrefix(sourcePath, prefix) {
			return parseShellFD(strings.TrimPrefix(sourcePath, prefix))
		}
	}
	return 0, false
}

func parseShellFD(value string) (int64, bool) {
	fd, err := strconv.ParseUint(value, 10, 63)
	return int64(fd), err == nil
}

func posixRedirectFD(redirect *syntax.Redirect) (int64, bool) {
	if redirect.N == nil {
		return defaultRedirectFD(redirect.Op), true
	}
	return parseShellFD(redirect.N.Value)
}

func evalScript(source string, args []*syntax.Word) (string, bool) {
	name, ok := commandName(args)
	if !ok || commandProgram(name) != "eval" || len(args) < 2 {
		return "", false
	}
	return joinScriptWords(source, args[1:])
}

func commandName(args []*syntax.Word) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	return staticWord(args[0])
}

func isShellCommandFlag(flag string) bool {
	if len(flag) < 2 || flag[0] != '-' || strings.HasPrefix(flag, "--") {
		return false
	}
	return strings.ContainsRune(flag[1:], 'c')
}

func isShellInterpreter(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh":
		return true
	default:
		return false
	}
}

func staticWord(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, nested := range part.Parts {
				lit, ok := nested.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func scriptWord(source string, word *syntax.Word) (string, bool) {
	if len(word.Parts) == 1 {
		switch part := word.Parts[0].(type) {
		case *syntax.SglQuoted:
			return part.Value, true
		case *syntax.DblQuoted:
			start := part.Left.Offset() + 1
			end := part.Right.Offset()
			if start <= end && end <= uint(len(source)) {
				return source[start:end], true
			}
			return "", false
		}
	}
	return staticWord(word)
}

func joinScriptWords(source string, words []*syntax.Word) (string, bool) {
	values := make([]string, len(words))
	for i, word := range words {
		value, ok := scriptWord(source, word)
		if !ok {
			return "", false
		}
		values[i] = value
	}
	return strings.Join(values, " "), true
}

func commandBase(command string) string {
	if i := strings.LastIndexAny(command, `/\`); i >= 0 {
		command = command[i+1:]
	}
	return strings.ToLower(command)
}

func commandProgram(command string) string {
	name := commandBase(command)
	for _, suffix := range []string{".exe", ".cmd", ".bat", ".com"} {
		if strings.HasSuffix(name, suffix) && len(name) > len(suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}
