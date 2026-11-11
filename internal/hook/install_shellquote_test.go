package hook

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A binary path with a space AND a single quote — the worst realistic case
// (macOS "Application Support" plus a quoted directory). An unquoted
// interpolation of this into the hook command would split it across multiple
// argv words, the command would fail to launch, and an agent that gates on a
// non-zero hook exit (Windsurf, Cursor/Claude gating) would BLOCK the user. Every
// installer must shell-quote the binary so it round-trips as a single argument.
const trickyBinary = "/Users/x/Library/Application Support/My Tools/it's numbat"

// shellArgv parses cmd the way the agent's shell would (POSIX `sh`) and returns
// the resulting argv, so a test can prove the wired command tokenizes to the
// intended words rather than splitting on an unquoted space or quote. printf
// emits each positional arg NUL-separated, so a space inside an argument is never
// mistaken for a separator.
func shellArgv(t *testing.T, cmd string) []string {
	t.Helper()
	// Seed the command text as arguments to printf so sh tokenizes it exactly as it
	// would when running the hook, emitting each resulting word NUL-separated.
	out, err := exec.Command("sh", "-c", `printf '%s\0' `+cmd).Output()
	if err != nil {
		t.Fatalf("sh parse of %q failed: %v", cmd, err)
	}
	parts := strings.Split(string(out), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// assertBinaryIsSingleArg parses the installed command through a real shell and
// asserts the tricky binary path survives as exactly one argument, immediately
// followed by `hook`, and that the numbat marker is still present as its own word
// (so isNumbatHookCommand still matches after quoting).
func assertBinaryIsSingleArg(t *testing.T, cmd string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell tokenization does not apply to Windows hook commands")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available; skipping shell round-trip")
	}
	argv := shellArgv(t, cmd)
	if len(argv) < 2 {
		t.Fatalf("command parsed to %d args, want at least the binary + hook: %q -> %v", len(argv), cmd, argv)
	}
	if argv[0] != trickyBinary {
		t.Errorf("binary argv[0] = %q, want the unsplit path %q (command: %q)", argv[0], trickyBinary, cmd)
	}
	if argv[1] != "hook" {
		t.Errorf("argv[1] = %q, want \"hook\" (command: %q)", argv[1], cmd)
	}
	if !isNumbatHookCommand(cmd) {
		t.Errorf("isNumbatHookCommand failed on quoted command: %q", cmd)
	}
}

// TestCommandBuildersShellQuoteBinary verifies per-agent command builders quote
// the binary path so a space/quote in it cannot split the command — the
// cross-installer passthrough-safety fix. It checks the builders directly (no
// install) so the assertion is precise, and also asserts the output file is
// quoted with the same helper.
func TestCommandBuildersShellQuoteBinary(t *testing.T) {
	const outFile = "/home/u/My Findings/it's out.ndjson"
	cases := []struct {
		name   string
		cmd    string
		hasOut bool
	}{
		{"claude", claudeCommandWithArgs(trickyBinary, "pre-tool", nil, false), false},
		{"cursor", cursorCommandWithArgs(trickyBinary, "beforeShellExecution", nil, false), false},
		{"windsurf", windsurfCommandWithArgs(trickyBinary, "pre_run_command", nil, false), false},
		{"copilot", copilotCommandWithArgs(trickyBinary, "copilot-pre-tool", nil, false), false},
		{"codex", codexCommandWithArgs(trickyBinary, "codex-pre-tool", nil, false), false},
		{"kimi", kimiCommandWithArgs(trickyBinary, "pre-tool", nil, false), false},
		{"qwen", qwenCommandWithArgs(trickyBinary, "pre-tool", nil, false), false},
		{"kiro", buildHookCommand(runtime.GOOS, trickyBinary, "pre-tool", AgentKiro, nil, false), false},
		{"claude+out", claudeCommandWithArgs(trickyBinary, "pre-tool", outputFileArgs(outFile), true), true},
		{"cursor+out", cursorCommandWithArgs(trickyBinary, "beforeShellExecution", outputFileArgs(outFile), false), true},
		{"windsurf+out", windsurfCommandWithArgs(trickyBinary, "pre_run_command", outputFileArgs(outFile), false), true},
		{"copilot+out", copilotCommandWithArgs(trickyBinary, "copilot-pre-tool", outputFileArgs(outFile), false), true},
		{"codex+out", codexCommandWithArgs(trickyBinary, "codex-pre-tool", outputFileArgs(outFile), true), true},
		{"kimi+out", kimiCommandWithArgs(trickyBinary, "pre-tool", outputFileArgs(outFile), true), true},
		{"qwen+out", qwenCommandWithArgs(trickyBinary, "pre-tool", outputFileArgs(outFile), true), true},
		{"kiro+out", buildHookCommand(runtime.GOOS, trickyBinary, "pre-tool", AgentKiro, outputFileArgs(outFile), true), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertBinaryIsSingleArg(t, c.cmd)
			if c.hasOut {
				argv := shellArgv(t, c.cmd)
				foundOut := false
				for _, a := range argv {
					if a == outFile {
						foundOut = true
					}
				}
				if !foundOut {
					t.Errorf("output file %q did not survive as a single argument: %v", outFile, argv)
				}
			}
		})
	}
}

func TestWindowsCommandBuilderEncodesExactArguments(t *testing.T) {
	binary := `C:\Program Files\Numbat's\numbat.exe`
	output := `C:\Users\dev\Numbat & Logs\live.ndjson`
	url := `https://ingest.example/numbat?node=%COMPUTERNAME%&mode=full`
	cmd := buildHookCommand("windows", binary, "codex-pre-tool", AgentCodex,
		[]string{"--output-file", output, "--http-url", url}, true)
	wantPrefix := systemPowerShellPath() +
		" -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(cmd, wantPrefix) {
		t.Fatalf("Windows command did not use absolute encoded PowerShell: %q", cmd)
	}
	if strings.HasPrefix(strings.ToLower(cmd), "powershell.exe ") {
		t.Fatalf("Windows command relies on executable search order: %q", cmd)
	}
	if strings.Contains(cmd, output) || strings.Contains(cmd, "%COMPUTERNAME%") {
		t.Fatalf("Windows-sensitive arguments leaked into the outer shell command: %q", cmd)
	}
	script := decodedHookCommand(cmd)
	for _, want := range []string{
		powerShellQuote(binary), powerShellQuote("hook"), powerShellQuote("codex-pre-tool"),
		powerShellQuote(AgentCodex), powerShellQuote(numbatHookMarker),
		powerShellQuote(enforceFlag), powerShellQuote(output), powerShellQuote(url),
		"exit $LASTEXITCODE",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("decoded PowerShell missing %q: %s", want, script)
		}
	}
	if !isNumbatHookCommand(cmd) {
		t.Fatal("encoded Windows command was not recognized as numbat-owned")
	}
	config := `{"hooks":{"PreToolUse":[{"hooks":[{"command":` + fmt.Sprintf("%q", cmd) + `}]}]}}`
	if !isNumbatHookCommand(config) {
		t.Fatal("encoded command was not recognized inside serialized config")
	}
	foreign := encodedPowerShellCommand(`C:\Tools\foreign.exe`, []string{"audit"})
	foreignFirst := fmt.Sprintf(`{"foreign":%q,"numbat":%q}`, foreign, cmd)
	if !isNumbatHookCommand(foreignFirst) {
		t.Fatal("numbat marker after a foreign encoded command was not recognized")
	}
}

func TestWindowsCodexCommandIsUnquotedSystemPowerShell(t *testing.T) {
	binary := `C:\Program Files\Numbat's\numbat.exe`
	cmd := buildHookCommand("windows", binary, "codex-pre-tool", AgentCodex, nil, false)

	// The system PowerShell must be an unquoted forward-slash path: PowerShell
	// parses a quoted executable at the head of the command as a string
	// expression, so Codex's session shell never runs the hook.
	const wantPrefix = `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand `
	if !strings.HasPrefix(cmd, wantPrefix) {
		t.Fatalf("Windows user hook command did not start with unquoted system PowerShell: %q", cmd)
	}
	if strings.HasPrefix(cmd, `"`) {
		t.Error("Windows user hook command quoted the PowerShell executable: " + cmd)
	}
	if strings.HasPrefix(strings.ToLower(cmd), "powershell.exe ") {
		t.Error("Windows user hook command relies on executable search order: " + cmd)
	}

	// The encoded payload is unchanged: call-operator invocation, quoted binary
	// and args, LASTEXITCODE propagation.
	script := decodedHookCommand(cmd)
	for _, want := range []string{
		"& ", powerShellQuote(binary), powerShellQuote("hook"), powerShellQuote("codex-pre-tool"),
		powerShellQuote(AgentCodex), powerShellQuote(numbatHookMarker), "exit $LASTEXITCODE",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("decoded PowerShell missing %q: %s", want, script)
		}
	}
	if !isNumbatHookCommand(cmd) {
		t.Error("encoded Windows user command was not recognized as numbat-owned")
	}
}

func TestWindowsCodexManagedHookBlockEmbedsTheBuiltCommand(t *testing.T) {
	body := renderCodexRequirementsHookBlock(numbatBinary, nil, false)
	// Managed Codex generation shares codexCommandWithArgs → buildHookCommand,
	// so on Windows its command is the unquoted system PowerShell asserted
	// above. Pin the wiring on every platform.
	for _, ev := range codexHookEvents {
		want := `command = ` + tomlString(codexCommandWithArgs(numbatBinary, ev.lifecycle, nil, false)) + "\n"
		if !strings.Contains(body, want) {
			t.Errorf("managed hook block does not embed the builder command for %q:\n%s", ev.settingsKey, body)
		}
	}
	if !strings.Contains(body, codexNumbatHookBlockStart) || !strings.Contains(body, codexNumbatHookBlockEnd) {
		t.Error("managed hook block lost its numbat markers: " + body)
	}
}

func TestClaudeInstallUsesShellFreeExecForm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if _, err := InstallWithOptions(AgentClaude, path, trickyBinary, InstallOptions{
		RuntimeArgs: []string{"--output-file", "/tmp/a path/it's-live.ndjson"},
		Enforce:     true,
	}); err != nil {
		t.Fatal(err)
	}
	for event, groups := range readHooks(t, path) {
		for _, group := range groups {
			for _, ref := range group.Hooks {
				if !isNumbatHookRef(ref) {
					continue
				}
				if ref.Command != trickyBinary || len(ref.Args) == 0 {
					t.Fatalf("Claude hook is not exec form: %+v", ref)
				}
				if got, want := slicesContain(ref.Args, enforceFlag), event == "PreToolUse"; got != want {
					t.Fatalf("Claude event %s enforce flag = %v, want %v: %v", event, got, want, ref.Args)
				}
				if !slicesContain(ref.Args, "/tmp/a path/it's-live.ndjson") {
					t.Fatalf("Claude exec args lost install options: %v", ref.Args)
				}
			}
		}
	}
}

// rawEntryCommand pulls the "command" string from a flat hook entry (Cursor and
// Windsurf share the {command,...} entry shape) for shell-safety checks.
func rawEntryCommand(raw json.RawMessage) string {
	var m struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(raw, &m)
	return m.Command
}

// TestInstallShellQuotesBinaryEndToEnd installs each agent with the tricky binary
// path and asserts every installed command round-trips through a shell with the
// binary intact. This exercises the full install path (marshal + read-back), not
// just the builder, so a regression anywhere in the wiring is caught. Detection
// must also survive: status reports installed despite the spaces and quote.
func TestInstallShellQuotesBinaryEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available; skipping shell round-trip")
	}

	t.Run("claude", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		if _, err := Install(AgentClaude, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		sf, err := readSettings(path)
		if err != nil {
			t.Fatalf("readSettings: %v", err)
		}
		n := 0
		for _, groups := range sf.hooks {
			for _, g := range groups {
				for _, h := range g.Hooks {
					if isNumbatHookRef(h) {
						n++
						if h.Command != trickyBinary {
							t.Errorf("Claude exec-form command = %q, want %q", h.Command, trickyBinary)
						}
						if len(h.Args) < 2 || h.Args[0] != "hook" || !slicesContain(h.Args, numbatHookMarker) {
							t.Errorf("Claude exec-form args malformed: %v", h.Args)
						}
					}
				}
			}
		}
		if n == 0 {
			t.Fatal("no numbat commands found to check")
		}
		if rep := Status(AgentClaude, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})

	t.Run("cursor", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if _, err := Install(AgentCursor, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		assertEveryFlatCommand(t, readCursorHooks(t, path))
		if rep := Status(AgentCursor, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})

	t.Run("windsurf", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if _, err := Install(AgentWindsurf, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		assertEveryFlatCommand(t, readWindsurfHooks(t, path))
		if rep := Status(AgentWindsurf, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})

	t.Run("copilot", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if _, err := Install(AgentCopilot, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		assertEveryFlatCommand(t, readCopilotHooks(t, path))
		if rep := Status(AgentCopilot, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})

	t.Run("vscode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks", "numbat.json")
		if _, err := Install(AgentVSCode, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		assertEveryFlatCommand(t, readCopilotHooks(t, path))
		if rep := Status(AgentVSCode, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})

	// Codex reuses the Claude nested matcher/hooks schema, so its commands live in
	// hookGroup entries (not the Cursor/Windsurf flat map): walk the groups the same
	// way the Claude subtest does.
	t.Run("codex", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hooks.json")
		if _, err := Install(AgentCodex, path, trickyBinary, "", false); err != nil {
			t.Fatalf("install: %v", err)
		}
		n := 0
		for _, groups := range readCodexHooks(t, path) {
			for _, g := range groups {
				for _, h := range g.Hooks {
					if isNumbatHookRef(h) {
						n++
						assertBinaryIsSingleArg(t, h.Command)
					}
				}
			}
		}
		if n == 0 {
			t.Fatal("no numbat commands found to check")
		}
		if rep := Status(AgentCodex, path); !rep.Installed {
			t.Error("status after tricky-binary install = not-installed, want installed")
		}
	})
}

// assertEveryFlatCommand shell-checks the command on each numbat entry in a
// flat-map hooks block (Cursor/Windsurf share the shape).
func assertEveryFlatCommand(t *testing.T, hooks map[string][]json.RawMessage) {
	t.Helper()
	n := 0
	for _, entries := range hooks {
		for _, raw := range entries {
			cmd := rawEntryCommand(raw)
			if cmd != "" && isNumbatHookCommand(cmd) {
				n++
				assertBinaryIsSingleArg(t, cmd)
			}
		}
	}
	if n == 0 {
		t.Fatal("no numbat commands found to check")
	}
}
