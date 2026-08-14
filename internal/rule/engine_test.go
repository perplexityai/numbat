package rule

import (
	"strings"
	"sync"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func boolPtr(b bool) *bool { return &b }

func mustEngine(t *testing.T, rules ...Rule) *Engine {
	t.Helper()
	fillTestRuleDefaults(rules)
	eng, err := NewEngine([]Source{{Name: "test", Rules: rules}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func fillTestRuleDefaults(rules []Rule) {
	for i := range rules {
		if rules[i].Version == "" {
			rules[i].Version = "test"
		}
		if rules[i].Title == "" {
			rules[i].Title = rules[i].ID
		}
	}
}

func TestEngineMatch(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.read_env",
		Title:    "read env",
		Severity: model.SeverityHigh,
		Expr:     `event.event_type == "file.read" && event.file_path.endsWith("/.env")`,
	})
	ev := model.Event{EventID: "e1", EventType: model.EventFileRead, FilePath: "/x/.env"}
	matches, err := eng.Eval(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Rule.ID != "t.read_env" {
		t.Fatalf("matches = %+v", matches)
	}
}

func TestEngineNoMatch(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.read_env",
		Severity: model.SeverityHigh,
		Expr:     `event.file_path.endsWith("/.env")`,
	})
	ev := model.Event{EventID: "e1", EventType: model.EventFileRead, FilePath: "/x/main.go"}
	matches, err := eng.Eval(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %+v", matches)
	}
}

func TestEngineContentSeesBeyondPreview(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.content",
		Severity: model.SeverityHigh,
		Expr:     `event.event_type == "prompt.user" && event.content.contains("needle-after-preview")`,
	})
	if !eng.UsesContent() {
		t.Fatal("UsesContent = false, want true")
	}
	var ev model.Event
	ev.EventType = model.EventPromptUser
	ev.SetContent(strings.Repeat("padding ", 40)+"needle-after-preview", true)
	if strings.Contains(ev.ContentPreview, "needle-after-preview") {
		t.Fatal("test needle unexpectedly fits in preview")
	}
	matches, err := eng.Eval(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one content match", matches)
	}
}

func TestEngineContentCostLimit(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.content_cost",
		Severity: model.SeverityHigh,
		Expr:     `event.content.matches("` + strings.Repeat("x", 500) + `")`,
	})
	var ev model.Event
	ev.SetContent(strings.Repeat("y", model.ContentMaxBytes), true)
	matches, err := eng.Eval(ev)
	if err == nil || !strings.Contains(err.Error(), "evaluation failed") {
		t.Fatalf("Eval error = %v, want bounded content evaluation failure", err)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %+v, want none", matches)
	}
}

func TestEngineShellCommandsUsesExecutableStatements(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.scheduler",
		Severity: model.SeverityHigh,
		Expr:     `shell_commands.exists(command, command.executable == "crontab")`,
	})
	tests := []struct {
		name    string
		command string
		match   bool
	}{
		{"direct", "crontab /tmp/job", true},
		{"later statement", "echo ready; crontab /tmp/job", true},
		{"command substitution", "echo $(crontab /tmp/job)", true},
		{"quoted prose", `echo "example: crontab /tmp/job"`, false},
		{"heredoc prose", "cat <<'EOF'\ncrontab /tmp/job\nEOF\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, Command: tc.command})
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got := len(matches) == 1; got != tc.match {
				t.Fatalf("matched = %v, want %v (%+v)", got, tc.match, matches)
			}
		})
	}
}

func TestEngineShellAnalysisErrorKeepsProvenCommands(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "raw", Severity: model.SeverityLow, Expr: `event.event_type == "command.exec"`},
		Rule{ID: "shell", Severity: model.SeverityLow, Expr: `shell_commands.size() == 0 || shell_commands.exists(command, command.executable == "danger")`},
	)
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   `danger; sh -c 'echo "unterminated'`,
	})
	if err == nil || !strings.Contains(err.Error(), "shell command analysis") {
		t.Fatalf("Eval error = %v, want content-free shell analysis error", err)
	}
	if len(matches) != 2 || matches[0].Rule.ID != "raw" || matches[1].Rule.ID != "shell" {
		t.Fatalf("proven commands and raw rules should still match despite partial analysis: %+v", matches)
	}
}

func TestEngineCompleteShellAnalysisFailureSkipsOnlyTypedRules(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "raw", Severity: model.SeverityLow, Expr: `event.event_type == "command.exec"`},
		Rule{ID: "shell", Severity: model.SeverityLow, Expr: `shell_commands.size() == 0`},
	)
	const command = `"$private_action"`
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   command,
	})
	if err == nil || !strings.Contains(err.Error(), "shell command analysis") {
		t.Fatalf("Eval error = %v, want shell analysis diagnostic", err)
	}
	if strings.Contains(err.Error(), "private_action") || strings.Contains(err.Error(), command) {
		t.Fatalf("diagnostic leaked command content: %v", err)
	}
	if len(matches) != 1 || matches[0].Rule.ID != "raw" {
		t.Fatalf("matches = %+v, want only raw-independent rule", matches)
	}
}

func TestShellCommandsReferenceDetectionHonorsComprehensionScope(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{`shell_commands.size() > 0`, true},
		{`shell_commands.exists(command, command.executable == "x")`, true},
		{`[1].exists(shell_commands, shell_commands == 1)`, false},
		{`[shell_commands].exists(shell_commands, shell_commands.size() > 0)`, true},
		{`[1].exists(shell_commands, shell_commands == 1) || shell_commands.size() > 0`, true},
		{`[1].exists(x, [2].exists(shell_commands, shell_commands == x))`, false},
		{`[1].exists(shell_commands, [shell_commands].exists(x, x == 1))`, false},
	}
	for _, tc := range tests {
		eng := mustEngine(t, Rule{ID: "scope", Severity: model.SeverityLow, Expr: tc.expr})
		if eng.usesShellCommands != tc.want {
			t.Errorf("%s: usesShellCommands = %v, want %v", tc.expr, eng.usesShellCommands, tc.want)
		}
	}
}

func TestShadowedShellCommandsDoesNotAnalyzeCommand(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "shadow",
		Severity: model.SeverityLow,
		Expr:     `[1].exists(shell_commands, shell_commands == 1)`,
	})
	matches, err := eng.Eval(model.Event{Command: `echo "unterminated`})
	if err != nil {
		t.Fatalf("shadow-only expression triggered command analysis: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want shadow-only expression to evaluate normally", matches)
	}
}

func TestShellCommandsSchemaIsTypeChecked(t *testing.T) {
	valid := `shell_commands.exists(command,
	  command.name == "docker" &&
	  command.assignments.exists(assignment,
	    assignment.name == "DOCKER_HOST" && !assignment.append
	  ) &&
	  command.wrappers.all(wrapper, wrapper.name != "")
	)`
	if _, err := NewEngine([]Source{{Rules: []Rule{{
		ID: "valid", Version: "test", Title: "valid", Severity: model.SeverityLow, Expr: valid,
	}}}}); err != nil {
		t.Fatalf("valid shell command schema: %v", err)
	}
	tests := []string{
		`shell_commands.exists(command, command.unknown == "")`,
		`shell_commands.exists(command, command.argv == "not a list")`,
		`shell_commands.exists(command, command.assignments.exists(assignment, assignment.value == 1))`,
	}
	for _, expr := range tests {
		if _, err := NewEngine([]Source{{Rules: []Rule{{
			ID: "invalid", Version: "test", Title: "invalid", Severity: model.SeverityLow, Expr: expr,
		}}}}); err == nil {
			t.Errorf("invalid shell command expression compiled: %s", expr)
		}
	}
}

// TestEngineExitCodeNullContract proves the documented CEL contract for the
// optional exit_code: because celView always includes the key (nil when unset),
// has(event.exit_code) cannot distinguish absent from set, so rules use
// `event.exit_code != null`. This evaluates real rules through the engine — the
// only place the contract is observable — rather than inspecting the raw map.
func TestEngineExitCodeNullContract(t *testing.T) {
	notNull := mustEngine(t, Rule{ID: "r.has_exit", Severity: model.SeverityLow, Expr: `event.exit_code != null`})
	isZero := mustEngine(t, Rule{ID: "r.exit_zero", Severity: model.SeverityLow, Expr: `event.exit_code == 0`})

	matches := func(eng *Engine, ev model.Event) bool {
		t.Helper()
		ms, err := eng.Eval(ev)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		return len(ms) == 1
	}

	intp := func(i int) *int { return &i }
	set := model.Event{EventID: "e1", EventType: model.EventCommandResult, ExitCode: intp(2)}
	zero := model.Event{EventID: "e2", EventType: model.EventCommandResult, ExitCode: intp(0)}
	absent := model.Event{EventID: "e3", EventType: model.EventCommandResult}

	if !matches(notNull, set) {
		t.Errorf("exit_code != null should be TRUE for a set code (2)")
	}
	if !matches(notNull, zero) {
		t.Errorf("exit_code != null should be TRUE for a real exit 0")
	}
	if matches(notNull, absent) {
		t.Errorf("exit_code != null should be FALSE when no code was recorded")
	}

	if !matches(isZero, zero) {
		t.Errorf("exit_code == 0 should match a real exit 0")
	}
	if matches(isZero, absent) {
		t.Errorf("exit_code == 0 should NOT match an absent code")
	}
	if matches(isZero, set) {
		t.Errorf("exit_code == 0 should NOT match a non-zero code")
	}
}

func TestEngineDisabledRuleSkipped(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.disabled",
		Severity: model.SeverityHigh,
		Expr:     `true`,
		Enabled:  boolPtr(false),
	})
	if eng.Len() != 0 {
		t.Fatalf("disabled rule was compiled: len=%d", eng.Len())
	}
}

func TestEngineHasEnforceEligibleRulesCountsOnlyEnabledRules(t *testing.T) {
	disabled := mustEngine(t, Rule{
		ID:       "t.disabled_enforce",
		Severity: model.SeverityHigh,
		Expr:     `true`,
		Enabled:  boolPtr(false),
		Enforce:  boolPtr(true),
	})
	if disabled.HasEnforceEligibleRules() {
		t.Fatal("disabled enforce rule made the compiled catalog enforceable")
	}

	enabled := mustEngine(t,
		Rule{ID: "t.monitor", Severity: model.SeverityLow, Expr: `true`},
		Rule{ID: "t.enforce", Severity: model.SeverityInfo, Expr: `true`, Enforce: boolPtr(true)},
	)
	if !enabled.HasEnforceEligibleRules() {
		t.Fatal("enabled enforce rule was not recognized")
	}

	sequence := mustEngine(t, Rule{
		ID:       "t.enforce_sequence",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Sequence: &SequenceSpec{
			WithinEvents: 2,
			Steps: []SequenceStep{
				{Expr: `true`},
				{Expr: `true`},
			},
		},
	})
	if !sequence.HasEnforceEligibleRules() {
		t.Fatal("enabled enforce sequence rule was not recognized")
	}
}

func TestEngineSeparatesPowerShellPreviewDetectionFromEnforcement(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.stop_process",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr: `event.event_type == "command.exec" &&
			shell_commands.exists(command, command.name in ["stop-process", "ri"])`,
	})
	tests := []struct {
		name        string
		command     string
		enforcement bool
		wantErr     bool
	}{
		{"WhatIf", `Stop-Process -Name * -Force -WhatIf`, false, false},
		{"WhatIf alias", `Stop-Process -Name * -Force -wi`, false, false},
		{"WhatIf abbreviation", `Stop-Process -Name * -Force -Wh`, false, false},
		{"explicit true", `Stop-Process -Name * -Force -WhatIf:$true`, false, false},
		{"explicit false", `Stop-Process -Name * -Force -WhatIf:$false`, true, false},
		{"invalid bare false", `Stop-Process -Name * -Force -WhatIf:false`, false, true},
		{"invalid quoted false", `Stop-Process -Name * -Force -WhatIf:"False"`, false, true},
		{"escaped false is literal", "Stop-Process -Name * -Force -WhatIf:`$false", false, true},
		{"module qualified", `Microsoft.PowerShell.Management\Stop-Process -Name * -Force -WhatIf`, false, false},
		{"splat is uncertain", `$p=@{WhatIf=$true}; Stop-Process -Name * -Force @p`, false, true},
		{"inline WhatIf preference", `$WhatIfPreference=$true; Stop-Process -Name * -Force`, false, false},
		{"quoted inline WhatIf preference", `$WhatIfPreference="True"; Stop-Process -Name * -Force`, false, false},
		{"nonempty false string is truthy", `$WhatIfPreference="False"; Stop-Process -Name * -Force`, false, false},
		{"empty string preference is false", `$WhatIfPreference=""; Stop-Process -Name * -Force`, false, false},
		{"scoped inline WhatIf preference", `$script:WhatIfPreference=$true; Stop-Process -Name * -Force`, false, false},
		{"environment lookalike", `$env:WhatIfPreference=$true; Stop-Process -Name * -Force`, false, false},
		{"explicit false overrides preference", `$WhatIfPreference=$true; Stop-Process -Name * -Force -WhatIf:$false`, false, false},
		{"dynamic inline WhatIf preference", `$WhatIfPreference=$mode; Stop-Process -Name * -Force`, false, true},
		{"same-script function shadow without preview", `function Stop-Process { Write-Output invoked }; Stop-Process -Name * -Force`, false, false},
		{"same-script function shadow", `function Stop-Process { Write-Output invoked }; Stop-Process -Name * -Force -WhatIf`, false, true},
		{"documented alias preview", `ri C:\ -Recurse -Force -WhatIf`, false, true},
		{"preview plus benign", `Stop-Process -Name * -Force -WhatIf; Write-Output done`, false, false},
		{"preview plus real", `Stop-Process -Name * -Force -WhatIf; Stop-Process -Name * -Force`, false, false},
		{"dynamic setting", `Stop-Process -Name * -Force -WhatIf:$mode`, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := eng.Eval(model.Event{
				EventType: model.EventCommandExec,
				ToolName:  "PowerShell",
				Command:   tt.command,
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Eval error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(matches) != 1 {
				t.Fatalf("matches = %+v, want one detection match", matches)
			}
			if matches[0].EnforcementMatch != tt.enforcement {
				t.Fatalf("EnforcementMatch = %v, want %v", matches[0].EnforcementMatch, tt.enforcement)
			}
		})
	}
}

func TestEngineDoesNotEnforceRuntimeDependentCommands(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.runtime_dependent",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr: `shell_commands.exists(command,
			command.name in ["wipefs", "stop-process", "del"]
		)`,
	})

	staticMatches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   `wipefs -a /dev/sda`,
	})
	if err != nil || len(staticMatches) != 1 || !staticMatches[0].EnforcementMatch {
		t.Fatalf("static command = (%+v, %v), want enforceable match", staticMatches, err)
	}

	tests := []struct {
		name    string
		tool    string
		command string
		wantErr bool
	}{
		{"argument", "bash", `wipefs -a /dev/sda "$mode"`, false},
		{"assignment", "bash", `MODE=$mode wipefs -a /dev/sda`, false},
		{"redirect", "bash", `wipefs -a /dev/sda > "$output"`, false},
		{"PowerShell argument", "PowerShell", `Stop-Process -Name $target -Force`, false},
		{"cmd argument", "cmd.exe", `del %TARGET%`, false},
		{"cmd for variable", "cmd.exe", `for %A in (target) do del %A`, true},
		{"POSIX function shadow", "bash", `wipefs(){ echo safe; }; wipefs -a /dev/sda`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := eng.Eval(model.Event{
				EventType: model.EventCommandExec,
				ToolName:  tt.tool,
				Command:   tt.command,
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Eval error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(matches) != 1 {
				t.Fatalf("matches = %+v, want one detection match", matches)
			}
			if matches[0].EnforcementMatch {
				t.Fatal("runtime-dependent command authorized enforcement")
			}
		})
	}

	staticBody, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		ToolName:  "bash",
		Command:   `run(){ wipefs -a /dev/sda; }; run`,
	})
	if err != nil || len(staticBody) != 1 || staticBody[0].EnforcementMatch {
		t.Fatalf("static function body = (%+v, %v), want detection-only match", staticBody, err)
	}
}

func TestEngineTreatsInvokeExpressionAsDetectionOnly(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.invoke_expression",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr: `shell_commands.exists(command,
			command.name == "invoke-expression"
		)`,
	})

	valid, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		ToolName:  "PowerShell",
		Command:   `Invoke-Expression 'Write-Output ok'`,
	})
	if err != nil || len(valid) != 1 || valid[0].EnforcementMatch {
		t.Fatalf("valid invocation = (%+v, %v), want detection-only match", valid, err)
	}

	for _, command := range []string{
		`Invoke-Expression 'Write-Output ok' unexpected`,
		`Invoke-Expression '-Command' 'Write-Output ok'`,
	} {
		matches, err := eng.Eval(model.Event{
			EventType: model.EventCommandExec,
			ToolName:  "PowerShell",
			Command:   command,
		})
		if err == nil {
			t.Fatalf("Eval(%q) error = nil, want invocation diagnostic", command)
		}
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Fatalf("Eval(%q) = %+v, want detection-only match", command, matches)
		}
	}
}

func TestEngineDoesNotInferPowerShellPreviewForNativeCommandsOrAmbientState(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.command",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     `shell_commands.exists(command, true)`,
	})
	for _, command := range []string{
		`docker run --privileged alpine -WhatIf`,
		`Invoke-Evil -WhatIf`,
		`Stop-Process.exe -Name target -WhatIf`,
		`Stop-Process.ps1 -Name target -WhatIf`,
		`C:\Tools\Stop-Process.exe -Name target -WhatIf`,
	} {
		matches, err := eng.Eval(model.Event{
			EventType: model.EventCommandExec,
			ToolName:  "PowerShell",
			Command:   command,
		})
		if err != nil {
			t.Errorf("Eval(%q): %v", command, err)
			continue
		}
		if len(matches) != 1 || !matches[0].EnforcementMatch {
			t.Errorf("Eval(%q) = %+v, want enforceable command", command, matches)
		}
	}
	for _, command := range []string{
		`$WhatIfPreference=$true; docker run --privileged alpine`,
		`$WhatIfPreference=$true; Invoke-WebRequest https://example.invalid`,
	} {
		matches, err := eng.Eval(model.Event{
			EventType: model.EventCommandExec,
			ToolName:  "PowerShell",
			Command:   command,
		})
		if err != nil {
			t.Errorf("Eval(%q): %v", command, err)
			continue
		}
		if len(matches) != 1 || matches[0].EnforcementMatch {
			t.Errorf("Eval(%q) = %+v, want detection-only command", command, matches)
		}
	}
}

func TestEngineDoesNotEnforcePartialShellAnalysis(t *testing.T) {
	enforce := true
	eng := mustEngine(t, Rule{
		ID:       "t.remove",
		Title:    "remove",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  &enforce,
		Expr: `event.event_type == "command.exec" &&
			shell_commands.exists(command, command.name == "rm")`,
	})
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   `rm -rf /; "$action"`,
	})
	if err == nil {
		t.Fatal("Eval succeeded, want dynamic-command diagnostic")
	}
	if len(matches) != 1 || matches[0].EnforcementMatch {
		t.Fatalf("partial static match = %+v, want detection-only rm witness", matches)
	}

	eng = mustEngine(t, Rule{
		ID:       "t.stop",
		Title:    "stop",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  &enforce,
		Expr:     `shell_commands.exists(command, command.name == "stop-process")`,
	})
	matches, err = eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		ToolName:  "PowerShell",
		Command:   `Stop-Process -Name * -Force; "unterminated`,
	})
	if err == nil {
		t.Fatal("Eval succeeded, want malformed-syntax diagnostic")
	}
	if len(matches) != 1 || matches[0].EnforcementMatch {
		t.Fatalf("malformed static match = %+v, want detection-only", matches)
	}
}

func TestEngineLimitsEnforcementToStaticShellSubset(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.static_subset",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr: `shell_commands.exists(command,
			command.name in ["wipefs", "stop-process", "del"]
		)`,
	})

	allowed := []model.Event{
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `printf x | wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo MODE=test wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo MODE=test -- wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -B wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --preserve-env wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -- wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env - MODE=test wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env MODE=test wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env -- MODE=test wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `exec wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `nohup wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `Stop-Process -Name target -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `Stop-Process -Name target -Force 2>&1`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `del C:\target 2>&1`},
	}
	for _, event := range allowed {
		matches, err := eng.Eval(event)
		if err != nil || len(matches) != 1 || !matches[0].EnforcementMatch {
			t.Errorf("Eval(%q) = (%+v, %v), want enforceable match", event.Command, matches, err)
		}
	}

	detectionOnly := []model.Event{
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `false && wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `true || wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `if false; then wipefs -a /dev/sda; fi`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `for x in one; do wipefs -a /dev/sda; done`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `run(){ wipefs -a /dev/sda; }; run`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `eval 'wipefs -a /dev/sda'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `command eval 'wipefs -a /dev/sda'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `command exec wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `command command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `./env wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `/usr/bin/sudo wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `./command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `ENV wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env exec wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `exec command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `nohup command wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sh -c 'wipefs -a /dev/sda'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `BASH_ENV=/tmp/functions bash -c 'wipefs -a /dev/sda'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo bash -c 'wipefs -a /dev/sda'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo MODE=test -u root wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --preserve-env=PATH=unexpected wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -C 2 wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --user= wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -u root -u daemon wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo MODE=test -k wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --reset-timestamp wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -N wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -s wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -i wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `doas -a passwd wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env -u PATH wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `exec -a wipe wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `pwsh -Command 'Stop-Process -Name target -Force'`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `echo "$(wipefs -a /dev/sda)"`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `wipefs -a /dev/sda --no-*`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `wipefs -a /dev/sda --{no-act,other}`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `echo ready; wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `"$next"; wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `! wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `wipefs -a /dev/sda &`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `Write-Output ready; Stop-Process -Name target -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `if ($false) { Stop-Process -Name target -Force }`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `Write-Output target | Stop-Process -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `Stop-Process -Name target,other -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `& 'Stop-Process' -Name target -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `& $next; Stop-Process -Name target -Force`},
		{EventType: model.EventCommandExec, ToolName: "PowerShell", Command: `del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `echo ready & del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `cmd.exe /c "del C:\target"`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `@if exist marker del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `cmd.exe /c "@if exist marker del C:\target"`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `if exist marker del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `for %A in (target) do del %A`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `call del C:\target`},
		{EventType: model.EventCommandExec, ToolName: "cmd.exe", Command: `%NEXT% & del C:\target`},
	}
	for _, event := range detectionOnly {
		matches, err := eng.Eval(event)
		if len(matches) != 1 {
			t.Errorf("Eval(%q) = (%+v, %v), want one detection match", event.Command, matches, err)
			continue
		}
		if matches[0].EnforcementMatch {
			t.Errorf("Eval(%q) authorized enforcement", event.Command)
		}
	}

	for _, event := range []model.Event{
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -- MODE=test wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --other-user root wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo -U root wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --bell=unexpected wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `sudo --non-interactive=unexpected wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env MODE=test -- wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env MODE=test -i wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env --ignore-environment=unexpected wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `doas -L wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `doas -Ln wipefs -a /dev/sda`},
		{EventType: model.EventCommandExec, ToolName: "bash", Command: `env eval 'wipefs -a /dev/sda'`},
	} {
		matches, err := eng.Eval(event)
		if err != nil || len(matches) != 0 {
			t.Errorf("Eval(%q) = (%+v, %v), want no projected wipefs", event.Command, matches, err)
		}
	}
}

func TestEngineIgnoresCMDEchoSuppressedComments(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.cmd_comment",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     `shell_commands.exists(command, command.name == "del")`,
	})
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		ToolName:  "cmd.exe",
		Command:   `@rem del C:\target`,
	})
	if err != nil || len(matches) != 0 {
		t.Fatalf("Eval = (%+v, %v), want no match", matches, err)
	}
}

func TestEngineDoesNotEnforceTruncatedCommand(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.wipefs",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr: `shell_commands.exists(command,
			command.name == "wipefs" &&
			command.argv.exists(arg, arg == "-a") &&
			command.argv.exists(arg, arg == "/dev/sda") &&
			!command.argv.exists(arg, arg == "--no-act")
		)`,
	})
	matches, err := eng.Eval(model.Event{
		EventType: model.EventCommandExec,
		Command:   "wipefs -a /dev/sda " + strings.Repeat("value ", maxShellListItems) + "--no-act",
	})
	if err == nil || !strings.Contains(err.Error(), "projection list") {
		t.Fatalf("Eval error = %v, want projection-list diagnostic", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one detection match", matches)
	}
	if matches[0].EnforcementMatch {
		t.Fatal("truncated command authorized enforcement")
	}
}

func TestEngineAllowsRawCommandEnforcement(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.raw",
		Title:    "raw",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     `event.command.contains("danger")`,
	})
	matches, err := eng.Eval(model.Event{Command: "danger"})
	if err != nil || len(matches) != 1 || !matches[0].EnforcementMatch {
		t.Fatalf("raw command match = (%+v, %v), want enforceable match", matches, err)
	}

	mustEngine(t, Rule{
		ID:       "t.raw_sequence",
		Title:    "raw sequence",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Sequence: &SequenceSpec{
			WithinEvents: 2,
			Steps: []SequenceStep{
				{Expr: `true`},
				{Expr: `event["command"].contains("danger")`},
			},
		},
	})
}

func TestEngineAllowsGeneralShellEnforcementExpressions(t *testing.T) {
	base := Rule{
		ID:       "t.general",
		Title:    "general",
		Version:  "1",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
	}
	for _, expr := range []string{
		`shell_commands.all(command, command.name == "wipefs")`,
		`shell_commands.size() == 1`,
		`!shell_commands.exists(command, command.name == "safe")`,
		`shell_commands.exists(command, command.name == "wipefs") == true`,
		`shell_commands.exists(outer,
			!shell_commands.exists(inner, inner.statement_id != outer.statement_id)
		)`,
	} {
		r := base
		r.Expr = expr
		eng := mustEngine(t, r)
		matches, err := eng.Eval(model.Event{
			EventType: model.EventCommandExec,
			ToolName:  "bash",
			Command:   `wipefs -a /dev/sda`,
		})
		if err != nil || len(matches) != 1 || !matches[0].EnforcementMatch {
			t.Errorf("Eval with %q = (%+v, %v), want enforceable match", expr, matches, err)
		}
	}
}

func TestNewEngineRejectsEventAliases(t *testing.T) {
	for _, expr := range []string{
		`[event].exists(e, e.command.contains("danger"))`,
		`{"copy": event}.copy.command.contains("danger")`,
		`size(event) > 0`,
	} {
		if _, err := NewEngine([]Source{{Name: "test", Rules: []Rule{{
			ID:       "t.alias",
			Title:    "alias",
			Version:  "1",
			Severity: model.SeverityLow,
			Expr:     expr,
		}}}}); err == nil || !strings.Contains(err.Error(), "event must be accessed directly") {
			t.Fatalf("event alias %q error = %v, want direct-access requirement", expr, err)
		}
	}
	if _, err := NewEngine([]Source{{Name: "test", Rules: []Rule{{
		ID:       "t.shadow",
		Title:    "shadow",
		Version:  "1",
		Severity: model.SeverityLow,
		Expr:     `[1].exists(event, event == 1) && event.event_type == "command.exec"`,
	}}}}); err != nil {
		t.Fatalf("shadowed local named event rejected: %v", err)
	}
	enforce := true
	if _, err := NewEngine([]Source{{Name: "test", Rules: []Rule{{
		ID:       "t.shadow_fields",
		Title:    "shadow fields",
		Version:  "1",
		Severity: model.SeverityLow,
		Enforce:  &enforce,
		Expr:     `[{"command": "safe", "local_field": "x"}].exists(event, event.command == "safe" && event.local_field == "x") && event.event_type == "command.exec"`,
	}}}}); err != nil {
		t.Fatalf("fields on shadowed local named event rejected: %v", err)
	}
}

func TestEvalErrorDoesNotLeakEventCommand(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.runtime_error",
		Title:    "runtime error",
		Version:  "1",
		Severity: model.SeverityLow,
		Expr:     `"value".matches(event.command)`,
	})
	command := "[private-command-fragment"
	_, err := eng.Eval(model.Event{EventType: model.EventCommandExec, Command: command})
	if err == nil {
		t.Fatal("Eval succeeded, want invalid-pattern error")
	}
	if strings.Contains(err.Error(), command) || strings.Contains(err.Error(), "private-command-fragment") {
		t.Fatalf("evaluation diagnostic leaked command content: %v", err)
	}
	if !strings.Contains(err.Error(), "evaluation failed") {
		t.Fatalf("evaluation error = %v, want sanitized diagnostic", err)
	}
}

func TestEngineOwnsAndReturnsRuleMetadataCopies(t *testing.T) {
	enforce := true
	source := Rule{
		ID:       "t.copy",
		Title:    "copy",
		Version:  "1",
		Severity: model.SeverityLow,
		Expr:     `true`,
		Tags:     []string{"original"},
		Enforce:  &enforce,
	}
	eng, err := NewEngine([]Source{{Name: "test", Rules: []Rule{source}}})
	if err != nil {
		t.Fatal(err)
	}
	source.Tags[0] = "mutated"
	*source.Enforce = false

	first, err := eng.Eval(model.Event{})
	if err != nil || len(first) != 1 {
		t.Fatalf("first Eval = %+v, %v", first, err)
	}
	if first[0].Rule.Tags[0] != "original" || !first[0].Rule.IsEnforceEligible() {
		t.Fatalf("engine retained caller aliases: %+v", first[0].Rule)
	}
	first[0].Rule.Tags[0] = "returned mutation"
	*first[0].Rule.Enforce = false

	second, err := eng.Eval(model.Event{})
	if err != nil || len(second) != 1 {
		t.Fatalf("second Eval = %+v, %v", second, err)
	}
	if second[0].Rule.Tags[0] != "original" || !second[0].Rule.IsEnforceEligible() {
		t.Fatalf("Eval returned aliased metadata: %+v", second[0].Rule)
	}
}

func TestNewEngineRejectsBadSeverity(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "x", Version: "test", Title: "x", Severity: "nope", Expr: "true"}}}})
	if err == nil || !strings.Contains(err.Error(), "invalid severity") {
		t.Fatalf("want invalid severity error, got %v", err)
	}
}

func TestNewEngineAllowsEnforceAtEverySeverity(t *testing.T) {
	for _, severity := range []string{
		model.SeverityInfo,
		model.SeverityLow,
		model.SeverityMedium,
		model.SeverityHigh,
		model.SeverityCritical,
	} {
		t.Run(severity, func(t *testing.T) {
			eng := mustEngine(t, Rule{
				ID:       "x",
				Severity: severity,
				Enforce:  boolPtr(true),
				Expr:     "true",
			})
			matches, err := eng.Eval(model.Event{})
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 || !matches[0].Rule.IsEnforceEligible() {
				t.Fatalf("enforce rule at severity %q is not eligible: %+v", severity, matches)
			}
		})
	}
}

func TestNewEngineRejectsMissingVersion(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "x", Title: "x", Severity: model.SeverityLow, Expr: "true"}}}})
	if err == nil || !strings.Contains(err.Error(), "missing version") {
		t.Fatalf("want missing version error, got %v", err)
	}
}

func TestNewEngineRejectsMissingTitle(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "x", Version: "test", Severity: model.SeverityLow, Expr: "true"}}}})
	if err == nil || !strings.Contains(err.Error(), "missing title") {
		t.Fatalf("want missing title error, got %v", err)
	}
}

func TestNewEngineRejectsSloppyMetadata(t *testing.T) {
	base := Rule{ID: "x", Version: "test", Title: "Title", Severity: model.SeverityLow, Expr: "true"}
	cases := []struct {
		name string
		mut  func(*Rule)
		want string
	}{
		{"id whitespace", func(r *Rule) { r.ID = " x" }, "id"},
		{"id bad chars", func(r *Rule) { r.ID = "x y" }, "id"},
		{"id empty segment", func(r *Rule) { r.ID = "x..y" }, "id"},
		{"id segment starts with separator", func(r *Rule) { r.ID = "x.-y" }, "id"},
		{"id segment ends with separator", func(r *Rule) { r.ID = "x.y_" }, "id"},
		{"version whitespace", func(r *Rule) { r.Version = " test " }, "version"},
		{"title whitespace", func(r *Rule) { r.Title = " Title " }, "title"},
		{"deny message whitespace", func(r *Rule) { r.DenyMessage = " denied " }, "deny_message"},
		{"deny message newline", func(r *Rule) { r.DenyMessage = "denied\ntry later" }, "one line"},
		{"deny message control", func(r *Rule) { r.DenyMessage = "denied\x1b" }, "control characters"},
		{"deny message line separator", func(r *Rule) { r.DenyMessage = "denied\u2028try later" }, "one line"},
		{"deny message too long", func(r *Rule) { r.DenyMessage = strings.Repeat("x", maxDenyMessageBytes+1) }, "exceeds 512 bytes"},
		{"empty tag", func(r *Rule) { r.Tags = []string{"ok", ""} }, "tags"},
		{"tag whitespace", func(r *Rule) { r.Tags = []string{" ok"} }, "tags"},
		{"whitespace expr", func(r *Rule) { r.Expr = " \t\n" }, "empty expr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mut(&r)
			_, err := NewEngine([]Source{{Rules: []Rule{r}}})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestNewEngineAcceptsMaximumDenyMessage(t *testing.T) {
	r := Rule{
		ID:          "x",
		Version:     "test",
		Title:       "Title",
		Severity:    model.SeverityLow,
		Expr:        "true",
		DenyMessage: strings.Repeat("x", maxDenyMessageBytes),
	}
	if _, err := NewEngine([]Source{{Rules: []Rule{r}}}); err != nil {
		t.Fatalf("maximum-size deny_message rejected: %v", err)
	}
}

func TestNewEngineRejectsNonBoolExpr(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "x", Version: "test", Title: "x", Severity: model.SeverityLow, Expr: `event.command`}}}})
	if err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("want boolean error, got %v", err)
	}
}

func TestNewEngineRejectsUncompilableExpr(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "x", Version: "test", Title: "x", Severity: model.SeverityLow, Expr: `event.nope(`}}}})
	if err == nil {
		t.Fatalf("want compile error for malformed expr")
	}
}

func TestNewEngineRejectsDuplicateID(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{
		{ID: "dup", Version: "test", Title: "dup", Severity: model.SeverityLow, Expr: "true"},
		{ID: "dup", Version: "test", Title: "dup", Severity: model.SeverityLow, Expr: "true"},
	}}})
	if err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("want duplicate id error, got %v", err)
	}
}

func TestNewEngineDuplicateIDNamesBothSources(t *testing.T) {
	_, err := NewEngine([]Source{
		{Name: "builtin", Rules: []Rule{{ID: "dup", Version: "test", Title: "dup", Severity: model.SeverityLow, Expr: "true"}}},
		{Name: "operator", Rules: []Rule{{ID: "dup", Version: "test", Title: "dup", Severity: model.SeverityLow, Expr: "true"}}},
	})
	if err == nil {
		t.Fatal("want duplicate id error across sources")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"dup"`) || !strings.Contains(msg, `"builtin"`) || !strings.Contains(msg, `"operator"`) {
		t.Fatalf("error should name the id and both sources, got %v", err)
	}
}

func TestNewEngineRejectsEmptyID(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{ID: "", Version: "test", Title: "x", Severity: model.SeverityLow, Expr: "true"}}}})
	if err == nil || !strings.Contains(err.Error(), "empty id") {
		t.Fatalf("want empty id error, got %v", err)
	}
}

func TestNewEngineRejectsUnknownEventField(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{
		ID: "x", Version: "test", Severity: model.SeverityLow,
		Title: "x",
		Expr:  `event.file_pathh == "x"`,
	}}}})
	if err == nil || !strings.Contains(err.Error(), "unknown event field") {
		t.Fatalf("want unknown event field error, got %v", err)
	}
}

func TestNewEngineRejectsUnknownEventFieldIndex(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{
		ID: "x", Version: "test", Severity: model.SeverityLow,
		Title: "x",
		Expr:  `event["file_pathh"] == "x"`,
	}}}})
	if err == nil || !strings.Contains(err.Error(), `unknown event field "file_pathh"`) {
		t.Fatalf("want unknown event field error, got %v", err)
	}
}

func TestNewEngineRejectsDynamicEventFieldIndex(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{
		ID: "x", Version: "test", Severity: model.SeverityLow,
		Title: "x",
		Expr:  `event[event.command] == "x"`,
	}}}})
	if err == nil || !strings.Contains(err.Error(), "event field index must be a string literal") {
		t.Fatalf("want non-literal field index error, got %v", err)
	}
}

func TestNewEngineRejectsInvalidConstantRegex(t *testing.T) {
	_, err := NewEngine([]Source{{Rules: []Rule{{
		ID: "x", Version: "test", Severity: model.SeverityLow,
		Title: "x",
		Expr:  `event.command.matches("[")`,
	}}}})
	if err == nil || !strings.Contains(err.Error(), "program expr") {
		t.Fatalf("want invalid constant regex error, got %v", err)
	}
}

func TestRuleEnabledDefaultsTrueWhenOmitted(t *testing.T) {
	// Enabled is nil (field omitted) — the rule must still compile.
	eng := mustEngine(t, Rule{ID: "e", Severity: model.SeverityLow, Expr: "true"})
	if eng.Len() != 1 {
		t.Fatalf("omitted enabled should default to true, len=%d", eng.Len())
	}
}

func TestDisabledRuleIsStillValidated(t *testing.T) {
	r := Rule{
		ID:       "t.disabled_invalid",
		Version:  "test",
		Title:    "Disabled invalid",
		Severity: model.SeverityLow,
		Expr:     `event.not_a_field == "x"`,
	}
	r.Enabled = boolPtr(false)
	_, err := NewEngine([]Source{{Name: "test", Rules: []Rule{r}}})
	if err == nil || !strings.Contains(err.Error(), `unknown event field "not_a_field"`) {
		t.Fatalf("NewEngine() error = %v, want disabled-rule validation error", err)
	}
}

func TestDisabledRuleIDStillParticipatesInDuplicateCheck(t *testing.T) {
	disabled := false
	_, err := NewEngine([]Source{
		{Name: "disabled", Rules: []Rule{{ID: "dup.rule", Title: "disabled", Severity: model.SeverityLow, Version: "1", Expr: "true", Enabled: &disabled}}},
		{Name: "enabled", Rules: []Rule{{ID: "dup.rule", Title: "enabled", Severity: model.SeverityLow, Version: "1", Expr: "true"}}},
	})
	if err == nil || !strings.Contains(err.Error(), `duplicate rule id "dup.rule"`) {
		t.Fatalf("NewEngine error = %v, want duplicate-id error", err)
	}
}

func TestEvalErrorDoesNotStopOtherRules(t *testing.T) {
	// A rule that calls a method on a field that is a string works fine;
	// to force a runtime eval error we index a string like a list.
	eng := mustEngine(t,
		Rule{ID: "ok", Severity: model.SeverityLow, Expr: `event.event_type == "file.read"`},
		Rule{ID: "boom", Severity: model.SeverityLow, Expr: `event.command[10] == "x"`},
	)
	ev := model.Event{EventID: "e1", EventType: model.EventFileRead, Command: "short"}
	matches, err := eng.Eval(ev)
	if err == nil {
		t.Fatalf("expected eval error from 'boom' rule")
	}
	if len(matches) != 1 || matches[0].Rule.ID != "ok" {
		t.Fatalf("ok rule should still match despite boom error: %+v", matches)
	}
}

func TestRuleIDsOrder(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "a", Severity: model.SeverityLow, Expr: "true"},
		Rule{ID: "b", Severity: model.SeverityLow, Expr: "true"},
	)
	ids := eng.RuleIDs()
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("RuleIDs = %v", ids)
	}
}

func TestEvalConcurrent(t *testing.T) {
	eng := mustEngine(t,
		Rule{ID: "a", Severity: model.SeverityLow, Expr: `event.event_type == "file.read"`},
		Rule{ID: "b", Severity: model.SeverityLow, Expr: `event.command.contains("rm")`},
	)
	ev := model.Event{EventID: "e1", EventType: model.EventFileRead, Command: "rm -rf /"}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ms, err := eng.Eval(ev)
				if err != nil || len(ms) != 2 {
					t.Errorf("eval = %d matches, err=%v", len(ms), err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
