package rule

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"

	"mvdan.cc/sh/v3/syntax"
)

const maxCommandDelimiterDepth = 64

type powerShellWhatIfState uint8

const (
	powerShellWhatIfUnseen powerShellWhatIfState = iota
	powerShellWhatIfFalse
	powerShellWhatIfTrue
	powerShellWhatIfUncertain
)

func powerShellWrapperScript(source string, args []*syntax.Word) (string, int, bool, error) {
	for i := 1; i < len(args); i++ {
		flag, ok := staticWord(args[i])
		if !ok {
			return "", 0, false, errors.New("shell command analysis: dynamic PowerShell option")
		}
		lower := strings.ToLower(flag)
		if name, _, found := strings.Cut(lower, ":"); found {
			lower = name
		}
		switch lower {
		case "-c", "-command":
			if i+1 >= len(args) {
				return "", 0, false, errors.New("shell command analysis: PowerShell command option without value")
			}
			script, ok := joinScriptWords(source, args[i+1:])
			if !ok || script == "-" {
				return "", 0, false, errors.New("shell command analysis: dynamic PowerShell command input")
			}
			return script, i + 1, true, nil
		case "-commandwithargs", "-cwa":
			if i+1 >= len(args) {
				return "", 0, false, errors.New("shell command analysis: PowerShell command option without value")
			}
			script, ok := scriptWord(source, args[i+1])
			if !ok || script == "-" {
				return "", 0, false, errors.New("shell command analysis: dynamic PowerShell command input")
			}
			return script, i + 1, true, nil
		case "-e", "-ec", "-enc", "-encodedcommand":
			if i+1 >= len(args) {
				return "", 0, false, errors.New("shell command analysis: PowerShell encoded command without value")
			}
			encoded, ok := staticWord(args[i+1])
			if !ok {
				return "", 0, false, errors.New("shell command analysis: dynamic PowerShell encoded command")
			}
			script, ok := decodePowerShellCommand(encoded)
			if !ok {
				return "", 0, false, errors.New("shell command analysis: invalid PowerShell encoded command")
			}
			return script, i + 1, true, nil
		case "-f", "-file", "-filewithargs":
			if i+1 < len(args) {
				value, static := staticWord(args[i+1])
				if !static || value == "-" {
					return "", 0, false, errors.New("shell command analysis: dynamic PowerShell file input")
				}
			}
			return "", 0, false, nil
		case "-configurationfile", "-configurationname", "-config", "-custompipename",
			"-encodedarguments", "-executionpolicy", "-ex", "-ep",
			"-inputformat", "-outputformat", "-settingsfile", "-windowstyle",
			"-workingdirectory", "-psconsolefile", "-version":
			if strings.Contains(flag, ":") {
				continue
			}
			i++
			if i >= len(args) {
				return "", 0, false, errors.New("shell command analysis: PowerShell option without value")
			}
		case "-help", "-?", "-h":
			return "", 0, false, nil
		case "-interactive", "-login", "-mta", "-noexit", "-nologo", "-noninteractive",
			"-noni", "-noprofile", "-nop", "-noprofileloadtime", "-sta":
			continue
		default:
			if !strings.HasPrefix(flag, "-") {
				return "", 0, false, nil
			}
			return "", 0, false, errors.New("shell command analysis: unsupported PowerShell option")
		}
	}
	return "", 0, false, nil
}

func decodePowerShellCommand(encoded string) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data)%2 != 0 || len(data) > maxShellCommandBytes*2 {
		return "", false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	for i, unit := range units {
		switch {
		case unit >= 0xD800 && unit <= 0xDBFF:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", false
			}
		case unit >= 0xDC00 && unit <= 0xDFFF:
			if i == 0 || units[i-1] < 0xD800 || units[i-1] > 0xDBFF {
				return "", false
			}
		}
	}
	decoded := strings.TrimPrefix(string(utf16.Decode(units)), "\ufeff")
	if len(decoded) > maxShellCommandBytes {
		return "", false
	}
	return decoded, true
}

func inferCommandDialect(source string) commandDialect {
	lower := strings.ToLower(strings.TrimSpace(source))
	for _, prefix := range []string{
		"if (", "elseif (", "foreach (", "for (", "while (", "switch (",
		"try {", "catch {", "finally {", "& {", ". {", "@(",
		"register-scheduledtask ", "set-content ", "add-content ", "clear-content ",
		"out-file ", "copy-item ", "move-item ", "remove-item ", "new-item ",
		"add-localgroupmember ", "add-adgroupmember ",
	} {
		if strings.HasPrefix(lower, prefix) {
			return dialectPowerShell
		}
	}
	if strings.HasPrefix(lower, "$") && powerShellAssignment(lower) >= 0 {
		return dialectPowerShell
	}
	if looksLikeCMDEnvironmentRead(lower) {
		return dialectCMD
	}
	for _, prefix := range []string{
		"if exist ", "if not exist ", "if defined ", "if errorlevel ",
		"schtasks ", "schtasks.exe ", "reg add ", "reg.exe add ",
		"net localgroup ", "net.exe localgroup ", "net1 localgroup ",
		"call ", "rd ", "rmdir /s ", "rmdir /q ",
	} {
		if strings.HasPrefix(lower, prefix) {
			return dialectCMD
		}
	}
	if strings.HasPrefix(lower, "for %") || strings.HasPrefix(lower, "for /") {
		return dialectCMD
	}
	token, _ := firstCommandToken(lower)
	token = strings.Trim(token, `&"'`)
	if looksPowerShellCmdlet(token) {
		return dialectPowerShell
	}
	return dialectPOSIX
}

func looksPowerShellCmdlet(token string) bool {
	verb, noun, ok := strings.Cut(commandProgram(token), "-")
	if !ok || verb == "" || noun == "" {
		return false
	}
	switch verb {
	case "add", "clear", "copy", "disable", "enable", "export", "format",
		"get", "import", "invoke", "move", "new", "out", "read", "register",
		"remove", "rename", "reset", "restart", "resume", "select", "set",
		"start", "stop", "suspend", "test", "unregister", "update", "write":
		return true
	default:
		return false
	}
}

func explicitSyntaxDialect(source string) commandDialect {
	lower := strings.ToLower(strings.TrimSpace(source))
	for _, prefix := range []string{"try {", "catch {", "finally {"} {
		if strings.HasPrefix(lower, prefix) {
			return dialectPowerShell
		}
	}
	if strings.HasPrefix(lower, "$") && strings.Contains(lower, "|") {
		return dialectPowerShell
	}
	return dialectAuto
}

func (a *shellAnalyzer) parsePowerShell(source string, depth int, wrappers []ShellWrapper) {
	var (
		segment      strings.Builder
		delimiters   []byte
		singleQuoted bool
		doubleQuoted bool
		lineComment  bool
		blockComment bool
		escaped      bool
		stopParsing  bool
		suppressAt   int
		functionName string
		functionBody int
		pipelineID   int64
	)

	flush := func(relationID int64) string {
		value := strings.TrimSpace(segment.String())
		segment.Reset()
		if suppressAt == 0 && value != "" {
			a.addPowerShellSegment(value, depth, wrappers, a.nextStatement(), relationID)
		}
		return value
	}

	for i := 0; i < len(source) && !a.halt; i++ {
		c := source[i]
		if stopParsing {
			if c == '\n' || c == '\r' || c == '|' {
				stopParsing = false
				if c == '|' && (i+1 >= len(source) || source[i+1] != '|') {
					if pipelineID == 0 {
						pipelineID = a.nextPipeline()
					}
					flush(pipelineID)
				} else {
					flush(pipelineID)
					pipelineID = 0
				}
				if c == '\r' && i+1 < len(source) && source[i+1] == '\n' {
					i++
				} else if c == '|' && i+1 < len(source) && source[i+1] == '|' {
					i++
				}
			} else {
				segment.WriteByte(c)
			}
			continue
		}
		if lineComment {
			if c == '\n' || c == '\r' {
				lineComment = false
				flush(pipelineID)
				pipelineID = 0
			}
			continue
		}
		if blockComment {
			if c == '#' && i+1 < len(source) && source[i+1] == '>' {
				blockComment = false
				i++
			}
			continue
		}
		if escaped {
			segment.WriteByte(c)
			escaped = false
			continue
		}
		if singleQuoted {
			segment.WriteByte(c)
			if c == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					segment.WriteByte(source[i+1])
					i++
				} else {
					singleQuoted = false
				}
			}
			continue
		}
		if doubleQuoted {
			segment.WriteByte(c)
			switch c {
			case '`':
				escaped = true
			case '"':
				doubleQuoted = false
			case '$':
				if i+1 < len(source) && source[i+1] == '(' {
					end, ok := powerShellSubexpressionEnd(source, i+2)
					if !ok {
						a.reportFatal(errors.New("shell command analysis: unsupported or malformed PowerShell syntax"))
						return
					}
					segment.WriteString(source[i+1 : end+1])
					if suppressAt == 0 {
						a.parseDialect(source[i+2:end], dialectPowerShell, depth+1, wrappers)
					}
					i = end
				}
			}
			continue
		}

		switch c {
		case '-':
			if i+2 < len(source) && source[i:i+3] == "--%" &&
				powerShellTokenBoundary(segment.String()) &&
				(i+3 == len(source) || powerShellBoundaryByte(source[i+3])) {
				segment.WriteString("--%")
				stopParsing = true
				i += 2
			} else {
				segment.WriteByte(c)
			}
		case '`':
			segment.WriteByte(c)
			escaped = true
		case '\'':
			segment.WriteByte(c)
			singleQuoted = true
		case '"':
			segment.WriteByte(c)
			doubleQuoted = true
		case '#':
			if powerShellTokenBoundary(segment.String()) {
				lineComment = true
			} else {
				segment.WriteByte(c)
			}
		case '<':
			if i+1 < len(source) && source[i+1] == '#' && powerShellTokenBoundary(segment.String()) {
				blockComment = true
				i++
			} else {
				segment.WriteByte(c)
			}
		case '@':
			if i+1 < len(source) && (source[i+1] == '\'' || source[i+1] == '"') {
				end, bodyStart, bodyEnd, ok := powerShellHereString(source, i, source[i+1])
				if !ok {
					a.reportFatal(errors.New("shell command analysis: unsupported or malformed PowerShell syntax"))
					return
				}
				segment.WriteString(source[i:end])
				if source[i+1] == '"' && suppressAt == 0 {
					a.parsePowerShellSubexpressions(source[bodyStart:bodyEnd], depth+1, wrappers)
				}
				i = end - 1
			} else {
				segment.WriteByte(c)
			}
		case '{', '(', '[':
			prefix := flush(pipelineID)
			delimiters = append(delimiters, c)
			if len(delimiters) > maxCommandDelimiterDepth {
				a.reportFatal(errors.New("shell command analysis: PowerShell nesting limit exceeded"))
				return
			}
			if c == '{' && suppressAt == 0 {
				if name, ok := powerShellFunctionName(prefix); ok {
					suppressAt = braceDepth(delimiters)
					functionName = name
					functionBody = i + 1
				} else if powerShellNonExecutingBlock(prefix, source, i) {
					suppressAt = braceDepth(delimiters)
				}
			}
		case '}', ')', ']':
			flush(pipelineID)
			if len(delimiters) == 0 || !matchingDelimiter(delimiters[len(delimiters)-1], c) {
				a.reportFatal(errors.New("shell command analysis: unsupported or malformed PowerShell syntax"))
				return
			}
			if c == '}' && suppressAt > 0 && braceDepth(delimiters) == suppressAt {
				if functionName != "" {
					if a.powerShellFunctions == nil {
						a.powerShellFunctions = make(map[string]string)
					}
					a.powerShellFunctions[functionName] = source[functionBody:i]
					functionName = ""
					functionBody = 0
				}
				suppressAt = 0
			}
			delimiters = delimiters[:len(delimiters)-1]
		case ';', '\n', '\r', '|':
			if c == '|' && (i+1 >= len(source) || source[i+1] != '|') {
				if pipelineID == 0 {
					pipelineID = a.nextPipeline()
				}
				flush(pipelineID)
			} else {
				flush(pipelineID)
				pipelineID = 0
			}
			if (c == '|' || c == '\r') && i+1 < len(source) && source[i+1] == c {
				i++
			}
		case '&':
			if i+1 < len(source) && source[i+1] == '&' {
				flush(pipelineID)
				pipelineID = 0
				i++
			} else {
				segment.WriteByte(c)
			}
		default:
			segment.WriteByte(c)
		}
	}
	if a.halt {
		return
	}
	if singleQuoted || doubleQuoted || blockComment || escaped || len(delimiters) != 0 {
		a.reportFatal(errors.New("shell command analysis: unsupported or malformed PowerShell syntax"))
		return
	}
	flush(pipelineID)
}

func (a *shellAnalyzer) addPowerShellSegment(segment string, depth int, wrappers []ShellWrapper, statementID, pipelineID int64) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return
	}
	lower := strings.ToLower(segment)
	callOperator := false
	if strings.HasPrefix(segment, "&") {
		segment = strings.TrimSpace(segment[1:])
		if segment == "" {
			return
		}
		callOperator = true
		if strings.HasPrefix(segment, "$") || strings.HasPrefix(segment, "@") ||
			strings.HasPrefix(segment, "(") || strings.HasPrefix(segment, "[") {
			a.report(errors.New("shell command analysis: dynamic PowerShell invocation"))
			return
		}
		lower = strings.ToLower(segment)
	}
	if strings.HasPrefix(segment, ". ") {
		return
	}
	if strings.HasPrefix(segment, "$") {
		if i := powerShellAssignment(segment); i >= 0 {
			a.observePowerShellWhatIfAssignment(segment[:i], segment[i+1:])
			a.addPowerShellSegment(segment[i+1:], depth, wrappers, statementID, pipelineID)
		}
		return
	}
	for _, prefix := range []string{"return ", "exit "} {
		if strings.HasPrefix(lower, prefix) {
			a.addPowerShellSegment(segment[len(prefix):], depth, wrappers, statementID, pipelineID)
			return
		}
	}

	token, _ := firstCommandToken(segment)
	switch strings.ToLower(token) {
	case "", "%", "?", "if", "elseif", "else", "while", "for", "foreach", "switch",
		"try", "catch", "finally", "do", "until", "trap", "begin", "process", "end",
		"clean", "param", "dynamicparam", "function", "filter", "class", "enum",
		"configuration", "data", "throw":
		return
	}
	if token[0] == '$' || token[0] == '@' || !callOperator && (token[0] == '\'' || token[0] == '"') ||
		token[0] == '[' || token[0] >= '0' && token[0] <= '9' {
		return
	}
	key := powerShellFunctionKey(token)
	body, functionCall := a.powerShellFunctions[key]
	command, ok, err := projectPowerShellCommand(segment, wrappers, statementID, pipelineID, a.powerShellWhatIf)
	if err != nil {
		a.report(err)
		return
	}
	if !ok {
		a.report(errors.New("shell command analysis: unsupported or malformed PowerShell command"))
		return
	}
	// The call operator admits a quoted token so "& 'C:\path with space.exe'"
	// projects, but an empty quoted target carries no executable, assignment,
	// or redirect. Such a command names nothing a rule can match, so drop it
	// and mark the analysis uncertain rather than seating a phantom entry that
	// still consumes one of the maxShellCommands slots.
	if command.Executable == "" && len(command.Assignments) == 0 && len(command.Redirects) == 0 {
		a.report(errors.New("shell command analysis: unsupported or malformed PowerShell command"))
		return
	}
	if recognizedPowerShellAlias(command.Executable) {
		command.enforcementUnsafe = true
	}
	if functionCall {
		command.FunctionCall = true
		command.Recursive = a.activePowerShellFunctions[key]
		if command.Preview != previewNormal {
			command.Preview = previewUncertain
			a.report(errors.New("shell command analysis: PowerShell function preview semantics are uncertain"))
		}
	} else if command.Preview == previewUncertain {
		a.report(errors.New("shell command analysis: PowerShell preview state is uncertain"))
	}
	invokeExpression := !functionCall && isPowerShellInvokeExpression(token)
	var invokeScript string
	if invokeExpression {
		var static bool
		invokeScript, static = staticPowerShellInvokeExpression(command)
		command.enforcementUnsafe = !static
	}
	if !a.add(command) {
		return
	}
	if invokeExpression {
		a.enforcementUnsafe = true
		if command.enforcementUnsafe {
			a.report(errors.New("shell command analysis: dynamic PowerShell invocation"))
			return
		}
		a.parseDialect(invokeScript, dialectPowerShell, depth+1, wrappers)
		return
	}
	a.expandProjectedInterpreter(command, depth)
	if !functionCall {
		return
	}
	if a.activePowerShellFunctions == nil {
		a.activePowerShellFunctions = make(map[string]bool)
	}
	if a.activePowerShellFunctions[key] {
		a.report(errors.New("shell command analysis: recursive PowerShell function"))
		return
	}
	a.activePowerShellFunctions[key] = true
	a.parseDialect(body, dialectPowerShell, depth+1, wrappers)
	delete(a.activePowerShellFunctions, key)
}

func (a *shellAnalyzer) parsePowerShellSubexpressions(source string, depth int, wrappers []ShellWrapper) {
	for i := 0; i+1 < len(source) && !a.halt; i++ {
		if source[i] != '$' || source[i+1] != '(' {
			continue
		}
		end, ok := powerShellSubexpressionEnd(source, i+2)
		if !ok {
			a.reportFatal(errors.New("shell command analysis: unsupported or malformed PowerShell syntax"))
			return
		}
		a.parseDialect(source[i+2:end], dialectPowerShell, depth, wrappers)
		i = end
	}
}

func powerShellSubexpressionEnd(source string, start int) (int, bool) {
	depth := 1
	var singleQuoted, doubleQuoted, escaped bool
	for i := start; i < len(source); i++ {
		c := source[i]
		if escaped {
			escaped = false
			continue
		}
		if singleQuoted {
			if c == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					i++
				} else {
					singleQuoted = false
				}
			}
			continue
		}
		if doubleQuoted {
			switch c {
			case '`':
				escaped = true
			case '"':
				doubleQuoted = false
			}
			continue
		}
		switch c {
		case '`':
			escaped = true
		case '\'':
			singleQuoted = true
		case '"':
			doubleQuoted = true
		case '(':
			depth++
			if depth > maxCommandDelimiterDepth {
				return 0, false
			}
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func powerShellHereString(source string, start int, quote byte) (end, bodyStart, bodyEnd int, ok bool) {
	if start+2 >= len(source) {
		return 0, 0, 0, false
	}
	switch source[start+2] {
	case '\n':
		bodyStart = start + 3
	case '\r':
		if start+3 >= len(source) || source[start+3] != '\n' {
			return 0, 0, 0, false
		}
		bodyStart = start + 4
	default:
		return 0, 0, 0, false
	}
	terminator := string([]byte{quote, '@'})
	for pos := bodyStart; pos <= len(source); {
		next := strings.IndexByte(source[pos:], '\n')
		lineStop := len(source)
		if next >= 0 {
			lineStop = pos + next
		}
		line := strings.TrimSuffix(source[pos:lineStop], "\r")
		if line == terminator {
			return lineStop, bodyStart, pos, true
		}
		if next < 0 {
			break
		}
		pos = lineStop + 1
	}
	return 0, 0, 0, false
}

func powerShellTokenBoundary(segment string) bool {
	return segment == "" || powerShellBoundaryByte(segment[len(segment)-1])
}

func powerShellBoundaryByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ';', '|', '&', ',', '(', ')', '{', '}', '[', ']', '=':
		return true
	default:
		return false
	}
}

func powerShellFunctionName(prefix string) (string, bool) {
	token, rest := firstCommandToken(prefix)
	switch strings.ToLower(token) {
	case "function", "filter":
		name, _ := firstCommandToken(rest)
		if key := powerShellFunctionKey(name); key != "" {
			return key, true
		}
	}
	return "", false
}

func powerShellFunctionKey(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" || strings.ContainsAny(name, `$@'"(){}[]`) {
		return ""
	}
	return strings.ToLower(name)
}

func powerShellNonExecutingBlock(prefix, source string, open int) bool {
	token, _ := firstCommandToken(prefix)
	switch strings.ToLower(commandProgram(token)) {
	case "function", "filter", "class", "enum", "configuration":
		return true
	case "&", ".", "if", "elseif", "else", "while", "for", "foreach", "switch",
		"try", "catch", "finally", "do", "until", "trap", "begin", "process", "end", "clean",
		"foreach-object", "where-object", "invoke-command", "start-job", "start-threadjob",
		"measure-command":
		return false
	}
	if assignment := powerShellAssignment(prefix); assignment >= 0 &&
		strings.TrimSpace(prefix[assignment+1:]) == "" {
		return true
	}
	if strings.TrimSpace(prefix) != "" {
		return true
	}
	for i := open - 1; i >= 0; i-- {
		switch source[i] {
		case ' ', '\t', '\n', '\r':
			continue
		case ')':
			return false
		default:
			return true
		}
	}
	return true
}

func braceDepth(delimiters []byte) int {
	depth := 0
	for _, delimiter := range delimiters {
		if delimiter == '{' {
			depth++
		}
	}
	return depth
}

func matchingDelimiter(open, close byte) bool {
	return open == '{' && close == '}' || open == '(' && close == ')' || open == '[' && close == ']'
}

func powerShellAssignment(segment string) int {
	var singleQuoted, doubleQuoted, escaped bool
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if escaped {
			escaped = false
			continue
		}
		if singleQuoted {
			if c == '\'' {
				singleQuoted = false
			}
			continue
		}
		if doubleQuoted {
			switch c {
			case '`':
				escaped = true
			case '"':
				doubleQuoted = false
			}
			continue
		}
		switch c {
		case '\'':
			singleQuoted = true
		case '"':
			doubleQuoted = true
		case '=':
			if i+1 >= len(segment) || segment[i+1] != '=' {
				return i
			}
		}
	}
	return -1
}

func (a *shellAnalyzer) observePowerShellWhatIfAssignment(name, value string) {
	next, ok := powerShellWhatIfAssignment(name, value)
	if !ok || a.powerShellWhatIf == powerShellWhatIfUncertain {
		return
	}
	previous := a.powerShellWhatIf
	switch previous {
	case powerShellWhatIfUnseen, powerShellWhatIfFalse:
		a.powerShellWhatIf = next
	case powerShellWhatIfTrue:
		if next != powerShellWhatIfTrue {
			a.powerShellWhatIf = powerShellWhatIfUncertain
		}
	}
	if a.powerShellWhatIf == powerShellWhatIfUncertain && previous != powerShellWhatIfUncertain {
		a.report(errors.New("shell command analysis: PowerShell WhatIf preference scope is uncertain"))
	}
}

func powerShellWhatIfAssignment(name, value string) (powerShellWhatIfState, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.HasPrefix(name, "${") && strings.HasSuffix(name, "}"):
		name = name[2 : len(name)-1]
	case strings.HasPrefix(name, "$"):
		name = name[1:]
	default:
		return powerShellWhatIfUnseen, false
	}
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		switch name[:i] {
		case "global", "local", "private", "script", "variable":
		default:
			return powerShellWhatIfUnseen, false
		}
		name = name[i+1:]
	}
	if name != "whatifpreference" {
		return powerShellWhatIfUnseen, false
	}

	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "$true":
		return powerShellWhatIfTrue, true
	case "$false", "$null":
		return powerShellWhatIfFalse, true
	}
	if literal, ok := staticPowerShellString(value); ok {
		if literal == "" {
			return powerShellWhatIfFalse, true
		}
		return powerShellWhatIfTrue, true
	}
	return powerShellWhatIfUncertain, true
}

func isPowerShellInvokeExpression(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "invoke-expression", "iex", "microsoft.powershell.utility\\invoke-expression":
		return true
	default:
		return false
	}
}

func staticPowerShellInvokeExpression(command ShellCommand) (string, bool) {
	arguments := command.Arguments
	if len(arguments) < 2 {
		return "", false
	}
	parameter := arguments[1]
	if parameter.Quote == quoteNone &&
		parameter.Source == parameter.Value &&
		strings.EqualFold(parameter.Source, "-command") {
		if len(arguments) != 3 {
			return "", false
		}
		return staticPowerShellString(arguments[2].Source)
	}
	if strings.HasPrefix(strings.ToLower(parameter.Source), "-command:") {
		if len(arguments) != 2 {
			return "", false
		}
		source := parameter.Source
		if len(source) < len("-command:") {
			return "", false
		}
		return staticPowerShellString(source[len("-command:"):])
	}
	if len(arguments) != 2 {
		return "", false
	}
	return staticPowerShellString(arguments[1].Source)
}

func firstCommandToken(segment string) (string, string) {
	segment = strings.TrimSpace(segment)
	for i, r := range segment {
		if r == ' ' || r == '\t' {
			return segment[:i], strings.TrimSpace(segment[i:])
		}
	}
	return segment, ""
}

func projectPowerShellCommand(
	segment string,
	wrappers []ShellWrapper,
	statementID, pipelineID int64,
	whatIf powerShellWhatIfState,
) (ShellCommand, bool, error) {
	arguments, ok := powerShellArguments(segment)
	if !ok || len(arguments) == 0 {
		return ShellCommand{}, false, nil
	}
	arguments, redirects, err := projectPowerShellRedirects(arguments)
	if err != nil {
		return ShellCommand{}, false, err
	}
	if len(arguments) == 0 {
		return ShellCommand{
			Redirects:   redirects,
			Dialect:     dialectPowerShell.String(),
			Wrappers:    cloneWrappers(wrappers),
			StatementID: statementID,
			PipelineID:  pipelineID,
			Preview:     previewNormal,
		}, true, nil
	}
	argv := argumentValues(arguments)
	preview := previewNormal
	recognizedCmdlet := recognizedPowerShellPreviewCmdlet(argv[0])
	recognizedAlias := recognizedPowerShellPreviewAlias(argv[0])
	if recognizedCmdlet || recognizedAlias {
		var explicit bool
		preview, explicit = powerShellPreview(arguments)
		if !explicit {
			switch whatIf {
			case powerShellWhatIfTrue:
				preview = previewRequested
			case powerShellWhatIfUncertain:
				preview = previewUncertain
			}
		}
		if recognizedAlias && preview != previewNormal {
			preview = previewUncertain
		}
	}
	return ShellCommand{
		Executable:  argv[0],
		Name:        commandProgram(argv[0]),
		Argv:        argv,
		Arguments:   arguments,
		Redirects:   redirects,
		Dialect:     dialectPowerShell.String(),
		Wrappers:    cloneWrappers(wrappers),
		StatementID: statementID,
		PipelineID:  pipelineID,
		Preview:     preview,
	}, true, nil
}

// Only cmdlets known to support -WhatIf are trusted as non-executing previews.
func recognizedPowerShellPreviewCmdlet(executable string) bool {
	switch strings.ToLower(strings.TrimSpace(executable)) {
	case "add-adgroupmember", "add-content", "add-localgroupmember",
		"clear-content", "clear-disk", "copy-item", "format-volume",
		"move-item", "new-item", "out-file", "remove-item", "set-acl",
		"set-content", "stop-process",
		"activedirectory\\add-adgroupmember",
		"microsoft.powershell.localaccounts\\add-localgroupmember",
		"microsoft.powershell.management\\add-content",
		"microsoft.powershell.management\\clear-content",
		"microsoft.powershell.management\\copy-item",
		"microsoft.powershell.management\\move-item",
		"microsoft.powershell.management\\new-item",
		"microsoft.powershell.management\\remove-item",
		"microsoft.powershell.management\\set-content",
		"microsoft.powershell.management\\stop-process",
		"microsoft.powershell.security\\set-acl",
		"microsoft.powershell.utility\\out-file",
		"storage\\clear-disk",
		"storage\\format-volume":
		return true
	default:
		return false
	}
}

// Documented aliases are mutable session state. Their preview syntax is enough
// to fail open, but not enough to claim that a known cmdlet was resolved.
func recognizedPowerShellPreviewAlias(executable string) bool {
	switch strings.ToLower(strings.TrimSpace(executable)) {
	case "ac", "clc", "copy", "cp", "cpi", "mi", "move", "mv", "ni",
		"del", "erase", "rd", "ri", "rm", "rmdir", "sc", "spps", "kill":
		return true
	default:
		return false
	}
}

func recognizedPowerShellAlias(executable string) bool {
	switch strings.ToLower(strings.TrimSpace(executable)) {
	case "ac", "cat", "clc", "copy", "cp", "cpi", "curl", "gc", "irm",
		"iwr", "mi", "move", "mv", "ni", "type", "wget",
		"del", "erase", "rd", "ri", "rm", "rmdir", "sc", "spps", "kill":
		return true
	default:
		return false
	}
}

func projectPowerShellRedirects(arguments []ShellArgument) ([]ShellArgument, []ShellRedirect, error) {
	out := make([]ShellArgument, 0, len(arguments))
	var redirects []ShellRedirect
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		fd, op, target, matched := windowsRedirectToken(argument.Value, true)
		if !matched {
			out = append(out, argument)
			continue
		}
		targetArgument := ShellArgument{
			Value:   target,
			Source:  target,
			Quote:   argument.Quote,
			Expands: argument.Expands,
		}
		if target == "" {
			i++
			if i >= len(arguments) {
				return nil, nil, errors.New("shell command analysis: PowerShell redirect without target")
			}
			targetArgument = arguments[i]
		}
		redirect, err := windowsRedirect(fd, op, targetArgument)
		if err != nil {
			return nil, nil, err
		}
		redirects = append(redirects, redirect)
	}
	return out, redirects, nil
}

func windowsRedirectToken(token string, allowAll bool) (int64, string, string, bool) {
	if token == "" {
		return 0, "", "", false
	}
	fd, i := int64(1), 0
	switch {
	case allowAll && token[0] == '*':
		fd, i = -1, 1
	case token[0] >= '0' && token[0] <= '9':
		fd, i = int64(token[0]-'0'), 1
	}
	if i >= len(token) || token[i] != '>' {
		return 0, "", "", false
	}
	i++
	op := redirectWrite
	if i < len(token) && token[i] == '>' {
		op = redirectAppend
		i++
	}
	return fd, op, token[i:], true
}

func windowsRedirect(fd int64, op string, target ShellArgument) (ShellRedirect, error) {
	if strings.HasPrefix(target.Value, "&") {
		value := strings.TrimPrefix(target.Value, "&")
		if value == "-" {
			return ShellRedirect{FD: fd, Op: redirectClose, Target: "-", TargetSource: target.Source, TargetQuote: target.Quote}, nil
		}
		if len(value) != 1 || value[0] < '0' || value[0] > '9' {
			return ShellRedirect{}, errors.New("shell command analysis: dynamic redirect descriptor")
		}
		return ShellRedirect{FD: fd, Op: redirectDuplicate, Target: value, TargetSource: target.Source, TargetQuote: target.Quote}, nil
	}
	if target.Value == "" {
		return ShellRedirect{}, errors.New("shell command analysis: redirect without target")
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

func powerShellArguments(source string) ([]ShellArgument, bool) {
	var (
		arguments    []ShellArgument
		word         strings.Builder
		singleQuoted bool
		doubleQuoted bool
		escaped      bool
		started      bool
		start        int
		sawSingle    bool
		sawDouble    bool
		sawBare      bool
		expands      bool
	)
	flush := func(end int) {
		if !started {
			return
		}
		quote := quoteMixed
		switch {
		case sawSingle && !sawDouble && !sawBare:
			quote = quoteSingle
		case sawDouble && !sawSingle && !sawBare:
			quote = quoteDouble
		case sawBare && !sawSingle && !sawDouble:
			quote = quoteNone
		}
		arguments = append(arguments, ShellArgument{
			Value:   word.String(),
			Source:  source[start:end],
			Quote:   quote,
			Expands: expands,
		})
		word.Reset()
		started = false
		sawSingle = false
		sawDouble = false
		sawBare = false
		expands = false
	}
	for i := 0; i < len(source); i++ {
		c := source[i]
		if !started && c != ' ' && c != '\t' {
			start = i
		}
		if escaped {
			word.WriteByte(c)
			started = true
			escaped = false
			continue
		}
		if singleQuoted {
			sawSingle = true
			if c == '\'' {
				if i+1 < len(source) && source[i+1] == '\'' {
					word.WriteByte('\'')
					i++
				} else {
					singleQuoted = false
				}
			} else {
				word.WriteByte(c)
			}
			started = true
			continue
		}
		if doubleQuoted {
			sawDouble = true
			switch c {
			case '`':
				escaped = true
			case '"':
				doubleQuoted = false
			case '$':
				expands = true
				word.WriteByte(c)
			default:
				word.WriteByte(c)
			}
			started = true
			continue
		}
		switch c {
		case ' ', '\t':
			flush(i)
		case '\'':
			singleQuoted = true
			sawSingle = true
			started = true
		case '"':
			doubleQuoted = true
			sawDouble = true
			started = true
		case '`':
			escaped = true
			sawBare = true
			started = true
		case '$':
			if !powerShellStaticDollarLiteral(source, i) {
				expands = true
			}
			sawBare = true
			word.WriteByte(c)
			started = true
		case '@':
			if !started {
				expands = true
			}
			sawBare = true
			word.WriteByte(c)
			started = true
		default:
			sawBare = true
			word.WriteByte(c)
			started = true
		}
	}
	if singleQuoted || doubleQuoted || escaped {
		return nil, false
	}
	flush(len(source))
	return arguments, true
}

func powerShellStaticDollarLiteral(source string, offset int) bool {
	lower := strings.ToLower(source[offset:])
	for _, literal := range []string{"$true", "$false", "$null"} {
		if !strings.HasPrefix(lower, literal) {
			continue
		}
		end := offset + len(literal)
		if end == len(source) {
			return true
		}
		switch source[end] {
		case ' ', '\t', '\r', '\n':
			return true
		default:
			return false
		}
	}
	return false
}

func argumentValues(arguments []ShellArgument) []string {
	values := make([]string, len(arguments))
	for i := range arguments {
		values[i] = arguments[i].Value
	}
	return values
}

func powerShellPreview(arguments []ShellArgument) (string, bool) {
	state := previewNormal
	explicit := false
	for i := 1; i < len(arguments); i++ {
		argument := arguments[i]
		value := strings.ToLower(argument.Value)
		name, setting, hasSetting := strings.Cut(value, ":")
		isWhatIf := name == "-wi" ||
			len(name) >= len("-wh") && strings.HasPrefix("-whatif", name)
		if argument.Quote != quoteNone || argument.Source != argument.Value {
			if isWhatIf {
				return previewUncertain, true
			}
			continue
		}
		if value == "--" || value == "--%" {
			break
		}
		if len(value) > 1 && value[0] == '@' && value[1] != '{' && value[1] != '(' {
			state = previewUncertain
			continue
		}
		if !isWhatIf {
			continue
		}
		explicit = true
		if !hasSetting {
			state = previewRequested
			continue
		}
		switch setting {
		case "$true":
			state = previewRequested
		case "$false":
			if state != previewRequested {
				state = previewNormal
			}
		default:
			return previewUncertain, true
		}
	}
	return state, explicit
}

func staticPowerShellString(source string) (string, bool) {
	source = strings.TrimSpace(source)
	if len(source) < 2 {
		return "", false
	}
	quote := source[0]
	if (quote != '\'' && quote != '"') || source[len(source)-1] != quote {
		return "", false
	}
	body := source[1 : len(source)-1]
	if quote == '"' && (strings.Contains(body, "$") || strings.Contains(body, "`")) {
		return "", false
	}
	if quote == '\'' {
		body = strings.ReplaceAll(body, "''", "'")
	}
	return body, true
}
