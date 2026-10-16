package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func posixEnforcementShapeSafe(file *syntax.File) bool {
	return file != nil && len(file.Stmts) > 0 && posixStatementsEnforcementSafe(file.Stmts)
}

func posixStatementsEnforcementSafe(stmts []*syntax.Stmt) bool {
	for _, stmt := range stmts {
		if !posixStatementEnforcementSafe(stmt) {
			return false
		}
	}
	return true
}

func posixStatementEnforcementSafe(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return false
		}
	}
	switch stmt.Cmd.(type) {
	case nil:
		return len(stmt.Redirs) > 0
	case *syntax.CallExpr:
		return true
	}
	if len(stmt.Redirs) > 0 {
		return false
	}
	switch command := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		return posixStatementEnforcementSafe(command.X) &&
			posixStatementEnforcementSafe(command.Y)
	case *syntax.Block:
		return posixStatementsEnforcementSafe(command.Stmts)
	case *syntax.Subshell:
		return posixStatementsEnforcementSafe(command.Stmts)
	case *syntax.IfClause:
		return posixIfEnforcementSafe(command)
	case *syntax.WhileClause:
		return posixStatementsEnforcementSafe(command.Cond) &&
			posixStatementsEnforcementSafe(command.Do)
	case *syntax.ForClause:
		loop, ok := command.Loop.(*syntax.WordIter)
		if !ok || !posixWordsLiteral(loop.Items) {
			return false
		}
		return posixStatementsEnforcementSafe(command.Do)
	case *syntax.CaseClause:
		if !posixWordsLiteral([]*syntax.Word{command.Word}) {
			return false
		}
		for _, item := range command.Items {
			if !posixWordsStatic(item.Patterns) ||
				!posixStatementsEnforcementSafe(item.Stmts) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func posixWordsStatic(words []*syntax.Word) bool {
	for _, word := range words {
		if word == nil {
			return false
		}
		if _, ok := staticWord(word); !ok {
			return false
		}
	}
	return true
}

func posixWordsLiteral(words []*syntax.Word) bool {
	if !posixWordsStatic(words) {
		return false
	}
	for _, word := range words {
		if posixPartsExpand(word.Parts, true) {
			return false
		}
		if lit, ok := word.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(lit.Value, "~") {
			return false
		}
	}
	return true
}

func posixIfEnforcementSafe(clause *syntax.IfClause) bool {
	for ; clause != nil; clause = clause.Else {
		if !posixStatementsEnforcementSafe(clause.Cond) ||
			!posixStatementsEnforcementSafe(clause.Then) {
			return false
		}
	}
	return true
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
