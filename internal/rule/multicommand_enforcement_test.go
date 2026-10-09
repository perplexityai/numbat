package rule

import (
	"runtime"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func compoundRuleEngine(t *testing.T, expr string) *Engine {
	t.Helper()
	return mustEngine(t, Rule{
		ID:       "t.multicommand",
		Title:    "multi-command enforcement",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     expr,
	})
}

func TestMultiCommandEnforcementRegression(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{name: "simple", command: `cat .env`},
		{name: "pipeline", command: `cat .env | grep x`},
		{name: "semicolon", command: `echo hi; cat .env`},
		{name: "and", command: `false && cat .env`},
		{name: "or", command: `true || cat .env`},
		{name: "conditional branch", command: `if false; then cat .env; fi`},
		{name: "loop body", command: `while false; do cat .env; done`},
		{name: "subshell", command: `(cat .env)`},
		{name: "group", command: `{ cat .env; }`},
		{name: "background", command: `cat .env &`},
		{name: "negation", command: `! cat .env`},
		{name: "heredoc", command: "cat .env <<'EOF'\nbody\nEOF"},
		{name: "command substitution", command: `echo "$(cat .env)"`},
		{name: "standalone command substitution", command: `$(cat .env)`, wantErr: true},
		{name: "redirect substitution", command: `{ true; } > "$(cat .env)"`},
		{name: "named descriptor redirect substitution", command: `true "$(cat .env)" {fd}>out`, wantErr: true},
		{name: "commandless descriptor redirect substitution", command: `> "$(cat .env)" {fd}>out`, wantErr: true},
		{name: "assignment descriptor redirect substitution", command: `X=1 >"$(cat .env)" {fd}>out`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: test.command})
			if err != nil && !test.wantErr {
				t.Fatal(err)
			}
			if err == nil && test.wantErr {
				t.Fatal("Eval returned no dynamic executable diagnostic")
			}
			if len(matches) != 1 || !matches[0].EnforcementMatch {
				t.Fatalf("Eval(%q) did not return one enforceable match", test.command)
			}
		})
	}
}

func TestMultiCommandEnforcementUsesPOSIXParserForExecCommand(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	commands := []string{
		"if (true)\nthen\ncat .env\nfi",
	}
	if runtime.GOOS != "windows" {
		commands = append(commands, "get-process; cat .env")
	}
	for _, command := range commands {
		matches, err := eng.Eval(model.Event{
			SourceAgent: model.AgentCodex,
			EventType:   model.EventCommandExec,
			ToolName:    "exec_command",
			Command:     command,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || !matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) returned %+v, want one enforceable POSIX candidate match", command, matches)
		}
	}
}

func TestMultiCommandEnforcementCandidateEvaluation(t *testing.T) {
	tests := []struct {
		name, expr, command             string
		wantErr, wantMatch, wantEnforce bool
	}{
		{name: "candidate confirms complete-list match", expr: `shell_commands.exists(command, command.name == "cat")`, command: `cat .env; true`, wantMatch: true, wantEnforce: true},
		{name: "candidate cannot create size match", expr: `shell_commands.size() == 1 && shell_commands[0].name == "cat"`, command: `cat .env; true`},
		{name: "candidate cannot create pipeline-size match", expr: `shell_commands.size() == 2 && shell_commands.exists(command, command.name == "cat") && shell_commands.exists(command, command.name == "grep")`, command: `true; cat .env | grep x`},
		{name: "candidate cannot create all match", expr: `event.event_type == "command.exec" && shell_commands.all(command, command.name == "cat")`, command: `cat one; true`},
		{name: "full-list error prevents candidate evaluation", expr: `shell_commands.filter(command, command.name == "cat").size() == 1 && shell_commands[0].argv[1] == ".env"`, command: `true; cat .env`, wantErr: true},
		{name: "raw predicate", expr: `event.command.contains("RAW_BLOCK") || shell_commands.exists(command, command.name == "never-match")`, command: `echo RAW_BLOCK "$x"; true`, wantMatch: true, wantEnforce: true},
		{name: "nested raw predicate", expr: `(event.command.contains("RAW_BLOCK") || shell_commands.exists(command, command.name == "never-match")) == true`, command: `echo RAW_BLOCK "$x"; true`, wantMatch: true, wantEnforce: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eng := compoundRuleEngine(t, test.expr)
			matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: test.command})
			if (err != nil) != test.wantErr {
				t.Fatalf("Eval error = %v, want error %t", err, test.wantErr)
			}
			matched := len(matches) == 1
			if matched != test.wantMatch {
				t.Fatalf("Eval returned %+v, want match %t", matches, test.wantMatch)
			}
			enforced := matched && matches[0].EnforcementMatch
			if enforced != test.wantEnforce {
				t.Fatalf("Eval returned %+v, want enforcement %t", matches, test.wantEnforce)
			}
		})
	}
}

func TestMultiCommandEnforcementPreservesPipelineSafety(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	for _, command := range []string{
		`echo ready; cat .env | "$sink"`,
		`echo "$(cat .env)" | grep x; true`,
		`${dyn} "$(cat .env)" | true; true`,
		`echo ready; (( $(cat .env) )) | "$sink"`,
		`echo ready; { true; } > "$(cat .env)" | true; true`,
		"sh <<'EOF' | \"$sink\"\ncat .env\nEOF",
		"echo \"$(sh <<'EOF'\ncat .env\nEOF\n)\" | \"$sink\"",
		"sudo -u root sh <<'EOF'\ncat .env\nEOF",
		`X=$(> "$(cat .env)" {fd}>out) | true`,
		`echo "$("$dyn" "$(cat .env)")" | true`,
		`f(){ cat .env; }; f | "$sink"`,
		`f(){ cat .env; }; f |& "$sink"`,
		`f(){ cat .env; }; f | echo "$value"`,
		`f(){ cat .env; }; f |& echo "$value"`,
		`declare X=1 >"$(cat .env)" {fd}>out | true`,
		`{ cat .env; } > "$target"`,
		`(cat .env) > "$target"`,
		`{ cat .env; } {fd}>out`,
		`(cat .env) {fd}>out`,
	} {
		matches, _ := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: command})
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) returned %+v, want detection-only pipeline match", command, matches)
		}
	}
}

func TestMultiCommandEnforcementDoesNotUseRecoveredCommand(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	for _, command := range []string{
		`cat .env |`,
		`{ cat .env`,
		`cat .env; )`,
		"cat .env\n)",
	} {
		matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: command})
		if err == nil {
			t.Fatalf("Eval(%q) returned no malformed syntax error", command)
		}
		for _, match := range matches {
			if match.EnforcementMatch {
				t.Fatalf("Eval(%q) returned %+v, want no recovered command enforcement", command, matches)
			}
		}
	}
}

func TestMultiCommandEnforcementDoesNotDetachUnsafeCommands(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.argv.exists(arg, arg == "BLOCK"))`)
	for _, command := range []string{
		`eval BLOCK | true; true`,
		`bash -c true BLOCK; true`,
		`declare BLOCK | true; true`,
		`BLOCK(){ :; }; false && BLOCK`,
	} {
		matches, _ := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: command})
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) returned %+v, want detection-only unsafe match", command, matches)
		}
	}
}

func TestMultiCommandEnforcementDoesNotTreatFunctionCallsAsExecutables(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	for _, command := range []string{
		`cat(){ :; }; false && cat .env`,
		`cat(){ :; }; unset -f cat; cat .env`,
	} {
		matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: command})
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) returned %+v, want detection-only function match", command, matches)
		}
	}
}

func TestMultiCommandEnforcementKeepsFunctionBodiesDetectionOnly(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	for _, command := range []string{
		`f(){ cat .env; }; f`,
		`f(){ cat .env; }; unset -f f; f`,
		`if true; then f(){ :; }; else f(){ cat .env; }; fi; f`,
	} {
		matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: "bash", Command: command})
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) returned %+v, want detection-only function-body match", command, matches)
		}
	}
}

func TestMultiCommandEnforcementKeepsInterpreterScriptsDetectionOnly(t *testing.T) {
	eng := compoundRuleEngine(t, `shell_commands.exists(command,
		command.name == "cat" && command.argv.exists(arg, arg == ".env"))`)
	for _, test := range []struct {
		name, tool, command string
	}{
		{"heredoc", "bash", "sh <<'EOF'\ncat .env\nEOF"},
		{"wrapped heredoc", "bash", "env sh <<'EOF'\ncat .env\nEOF"},
		{"invalid attached option", "bash", "zsh -odefinitely_invalid <<'EOF'\ncat .env\nEOF"},
		{"missing startup file", "bash", "bash --rcfile <<'EOF'\ncat .env\nEOF"},
		{"inline script", "bash", `sh -c 'cat .env'`},
		{"powershell inline script", "PowerShell", `Write-Output ready; sh -c 'cat .env'`},
		{"cmd inline script", "cmd", `echo ready & sh -c "cat .env"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: test.tool, Command: test.command})
			if err != nil || len(matches) != 1 || matches[0].EnforcementMatch {
				t.Fatalf("Eval(%q) = (%+v, %v), want one detection-only match", test.command, matches, err)
			}
		})
	}
}
