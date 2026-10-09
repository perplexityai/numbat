package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func posixEnforcementCandidates(commands []ShellCommand, unsafePipelines, unsafeStatements map[int64]bool, parents map[int64]int64) [][]ShellCommand {
	type candidateKey struct {
		pipeline bool
		id       int64
	}
	groups := make(map[candidateKey][]ShellCommand)
	unsafeGroups := make(map[candidateKey]bool)
	for _, command := range commands {
		if command.PipelineID != 0 && !commandSafeForEnforcement(command) {
			unsafePipelines[command.PipelineID] = true
		}
	}
	for _, command := range commands {
		if unsafePipelines[command.PipelineID] {
			unsafeStatements[command.StatementID] = true
		}
	}
	order := make([]candidateKey, 0, len(commands))
	for _, command := range commands {
		if command.Dialect != dialectPOSIX.String() || command.StatementID == 0 || unsafeStatements[command.StatementID] {
			continue
		}
		unsafeParent := false
		for parent := command.ParentStatementID; parent != 0; parent = parents[parent] {
			if unsafeStatements[parent] {
				unsafeParent = true
				break
			}
		}
		if unsafeParent {
			continue
		}
		key := candidateKey{id: command.StatementID}
		if command.PipelineID != 0 {
			key = candidateKey{pipeline: true, id: command.PipelineID}
		}
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		if commandSafeForEnforcement(command) {
			groups[key] = append(groups[key], command)
		} else {
			unsafeGroups[key] = true
		}
	}
	candidates := make([][]ShellCommand, 0, len(order))
	for _, key := range order {
		if !unsafeGroups[key] {
			candidates = append(candidates, groups[key])
		}
	}
	return candidates
}

func (a *shellAnalyzer) markCommandsUnsafe(start int) {
	for i := start; i < len(a.commands); i++ {
		a.commands[i].enforcementUnsafe = true
	}
}

func (a *shellAnalyzer) markStatementsUnsafe(root syntax.Node, statements map[*syntax.Stmt]int64) {
	syntax.Walk(root, func(node syntax.Node) bool {
		if statement, ok := node.(*syntax.Stmt); ok {
			a.unsafeStatements[statements[statement]] = true
		}
		return true
	})
}

func (a *shellAnalyzer) markPipelineUnsafe(ctx posixCommandContext) {
	if ctx.pipelineID == 0 {
		return
	}
	a.unsafePipelines[ctx.pipelineID] = true
}

func posixEnforcementShapeSafe(file *syntax.File) bool {
	return file != nil && len(file.Stmts) == 1 && posixStatementEnforcementSafe(file.Stmts[0])
}

func posixStatementEnforcementSafe(stmt *syntax.Stmt) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return false
		}
	}
	switch command := stmt.Cmd.(type) {
	case nil:
		return len(stmt.Redirs) > 0
	case *syntax.CallExpr:
		return true
	case *syntax.BinaryCmd:
		if command.Op != syntax.Pipe && command.Op != syntax.PipeAll {
			return false
		}
		return posixStatementEnforcementSafe(command.X) &&
			posixStatementEnforcementSafe(command.Y)
	default:
		return false
	}
}

func powerShellEnforcementShapeSafe(source string) bool {
	var singleQuoted, doubleQuoted bool
	for i := 0; i < len(source); i++ {
		switch {
		case singleQuoted:
			if source[i] == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					i++
				} else {
					singleQuoted = false
				}
			}
		case doubleQuoted:
			switch source[i] {
			case '`':
				return false
			case '"':
				doubleQuoted = false
			}
		default:
			switch source[i] {
			case '\'':
				singleQuoted = true
			case '"':
				doubleQuoted = true
			case '&':
				if !cmdRedirectAmpersand(source, i) {
					return false
				}
			case '`', ';', ',', '\n', '\r', '|', '(', ')', '{', '}', '[', ']':
				return false
			}
		}
	}
	return !singleQuoted && !doubleQuoted
}

func cmdEnforcementShapeSafe(source string) bool {
	source = trimCMDEchoPrefix(source)
	var quoted bool
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '^':
			return false
		case '"':
			quoted = !quoted
		case '&':
			if !quoted && !cmdRedirectAmpersand(source, i) {
				return false
			}
		case '|', '(', ')', '\n', '\r':
			if !quoted {
				return false
			}
		}
	}
	if quoted {
		return false
	}
	words := cmdWords(source)
	if len(words) == 0 {
		return false
	}
	switch commandProgram(strings.ToLower(words[0].text)) {
	case "call", "else", "endlocal", "exit", "for", "goto", "if", "set",
		"setlocal", "start":
		return false
	default:
		return true
	}
}
