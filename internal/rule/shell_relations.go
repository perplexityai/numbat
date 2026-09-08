package rule

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	quoteNone   = "none"
	quoteSingle = "single"
	quoteDouble = "double"
	quoteMixed  = "mixed"
)

type posixRelations struct {
	statements         map[*syntax.Stmt]int64
	pipelines          map[*syntax.Stmt]int64
	parents            map[*syntax.Stmt]int64
	inheritedRedirects map[*syntax.Stmt][]*syntax.Redirect
}

func (a *shellAnalyzer) buildPOSIXRelations(root syntax.Node, inheritedRedirects []*syntax.Redirect) posixRelations {
	relations := posixRelations{
		statements:         make(map[*syntax.Stmt]int64),
		pipelines:          make(map[*syntax.Stmt]int64),
		parents:            make(map[*syntax.Stmt]int64),
		inheritedRedirects: make(map[*syntax.Stmt][]*syntax.Redirect),
	}
	syntax.Walk(root, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
			return true
		}
		var statements []*syntax.Stmt
		collectPipelineStatements(binary.X, &statements)
		collectPipelineStatements(binary.Y, &statements)
		var pipelineID int64
		for _, stmt := range statements {
			if existing := relations.pipelines[stmt]; existing != 0 {
				pipelineID = existing
				break
			}
		}
		if pipelineID == 0 {
			pipelineID = a.nextPipeline()
		}
		for _, stmt := range statements {
			relations.pipelines[stmt] = pipelineID
		}
		return true
	})

	var stack []syntax.Node
	syntax.Walk(root, func(node syntax.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if stmt, ok := node.(*syntax.Stmt); ok {
			relations.statements[stmt] = a.nextStatement()
			relations.parents[stmt] = enclosingSubcommandStatement(stack, relations.statements)
			redirects := append([]*syntax.Redirect(nil), inheritedRedirects...)
			relations.inheritedRedirects[stmt] = append(redirects, enclosingRedirects(stack)...)
		}
		stack = append(stack, node)
		return true
	})
	return relations
}

func enclosingRedirects(stack []syntax.Node) []*syntax.Redirect {
	var redirects []*syntax.Redirect
	for _, node := range stack {
		switch node := node.(type) {
		case *syntax.ProcSubst:
			if node.Op == syntax.CmdOut {
				redirects = redirectsExceptFD(redirects, 0)
			}
		case *syntax.Stmt:
			switch node.Cmd.(type) {
			case *syntax.Block, *syntax.Subshell, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
				redirects = append(redirects, node.Redirs...)
			}
		}
	}
	return redirects
}

func redirectsExceptFD(redirects []*syntax.Redirect, excluded int64) []*syntax.Redirect {
	kept := make([]*syntax.Redirect, 0, len(redirects))
	for _, redirect := range redirects {
		fd, ok := posixRedirectFD(redirect)
		if !ok {
			continue
		}
		if fd != excluded && fd != -1 {
			kept = append(kept, redirect)
		}
	}
	return kept
}

func (r posixRelations) context(stmt *syntax.Stmt) posixCommandContext {
	return posixCommandContext{
		statementID:       r.statements[stmt],
		pipelineID:        r.pipelines[stmt],
		parentStatementID: r.parents[stmt],
		statementIDs:      r.statements,
	}
}

func collectPipelineStatements(stmt *syntax.Stmt, out *[]*syntax.Stmt) {
	if stmt == nil {
		return
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok &&
		(binary.Op == syntax.Pipe || binary.Op == syntax.PipeAll) {
		collectPipelineStatements(binary.X, out)
		collectPipelineStatements(binary.Y, out)
		return
	}
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.Stmt:
			*out = append(*out, node)
		}
		return true
	})
}

func enclosingSubcommandStatement(stack []syntax.Node, statements map[*syntax.Stmt]int64) int64 {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i].(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
		default:
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if stmt, ok := stack[j].(*syntax.Stmt); ok {
				return statements[stmt]
			}
		}
	}
	return 0
}

func projectPOSIXArgument(source string, word *syntax.Word, statements map[*syntax.Stmt]int64) (ShellArgument, error) {
	value, err := shellWordValue(source, word)
	if err != nil {
		return ShellArgument{}, err
	}
	spelling, err := sourceSpan(source, word.Pos(), word.End())
	if err != nil {
		return ShellArgument{}, err
	}
	return ShellArgument{
		Value:       value,
		Source:      spelling,
		Quote:       posixWordQuote(word),
		Expands:     posixWordExpands(word, spelling),
		Subcommands: wordSubcommands(word, statements),
	}, nil
}

func posixWordQuote(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return quoteNone
	}
	if len(word.Parts) == 1 {
		switch word.Parts[0].(type) {
		case *syntax.SglQuoted:
			return quoteSingle
		case *syntax.DblQuoted:
			return quoteDouble
		default:
			return quoteNone
		}
	}
	return quoteMixed
}

func posixWordExpands(word *syntax.Word, source string) bool {
	if posixPartsExpand(word.Parts, true) {
		return true
	}
	return posixWordQuote(word) != quoteSingle && strings.HasPrefix(source, "~")
}

func posixPartsExpand(parts []syntax.WordPart, unquoted bool) bool {
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst,
			*syntax.ExtGlob, *syntax.BraceExp:
			return true
		case *syntax.Lit:
			if unquoted && strings.ContainsAny(part.Value, "*?[{") {
				return true
			}
		case *syntax.SglQuoted:
			if part.Dollar {
				return true
			}
		case *syntax.DblQuoted:
			if part.Dollar {
				return true
			}
			if posixPartsExpand(part.Parts, false) {
				return true
			}
		}
	}
	return false
}

func wordSubcommands(word *syntax.Word, statements map[*syntax.Stmt]int64) []int64 {
	if word == nil || len(statements) == 0 {
		return nil
	}
	var (
		stack []syntax.Node
		ids   []int64
		seen  = make(map[int64]struct{})
	)
	syntax.Walk(word, func(node syntax.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if stmt, ok := node.(*syntax.Stmt); ok && stackContainsCommandSubstitution(stack) {
			if id := statements[stmt]; id != 0 {
				if _, exists := seen[id]; !exists {
					seen[id] = struct{}{}
					ids = append(ids, id)
				}
			}
		}
		stack = append(stack, node)
		return true
	})
	return ids
}

func stackContainsCommandSubstitution(stack []syntax.Node) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i].(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			return true
		}
	}
	return false
}
