package rule

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/perplexityai/numbat/internal/model"
)

func TestCanonicalCommandRootProvenance(t *testing.T) {
	env, err := newEnv()
	if err != nil {
		t.Fatal(err)
	}
	adapter := env.CELTypeAdapter()
	for _, tc := range []struct {
		name, dialect, value, source, want string
		expands                            bool
	}{
		{"absolute literal", "posix", "/home/dev/x/../.ssh/authorized_keys", "'/home/dev/x/../.ssh/authorized_keys'", "/home/dev/.ssh/authorized_keys", false},
		{"absolute expanding", "posix", "/home/$OTHER/../dev/.ssh/authorized_keys", `"/home/$OTHER/../dev/.ssh/authorized_keys"`, "/home/$OTHER/../dev/.ssh/authorized_keys", true},
		{"literal HOME", "posix", "$HOME/x/../.ssh/authorized_keys", "'$HOME/x/../.ssh/authorized_keys'", "./$HOME/x/../.ssh/authorized_keys", false},
		{"active HOME", "posix", "$HOME/x/../.ssh/authorized_keys", `"$HOME/x/../.ssh/authorized_keys"`, "$HOME/.ssh/authorized_keys", true},
		{"active braced HOME", "posix", "${HOME}/x/../.ssh/authorized_keys", `${HOME}/x/../.ssh/authorized_keys`, "${HOME}/.ssh/authorized_keys", true},
		{"HOME parent retained", "posix", "$HOME/../$HOME/.ssh/authorized_keys", "$HOME/../$HOME/.ssh/authorized_keys", "$HOME/../$HOME/.ssh/authorized_keys", true},
		{"HOME other expansion", "posix", "$HOME/$OTHER/../.ssh/authorized_keys", "$HOME/$OTHER/../.ssh/authorized_keys", "$HOME/$OTHER/../.ssh/authorized_keys", true},
		{"active tilde", "posix", "~/x/../.ssh/authorized_keys", "~/x/../.ssh/authorized_keys", "~/.ssh/authorized_keys", true},
		{"tilde parent retained", "posix", "~/../~/.ssh/authorized_keys", "~/../~/.ssh/authorized_keys", "~/../~/.ssh/authorized_keys", true},
		{"quoted tilde despite expansion", "posix", "~/$OTHER/../.ssh/authorized_keys", `"~/$OTHER/../.ssh/authorized_keys"`, "./~/$OTHER/../.ssh/authorized_keys", true},
		{"relative root manufacture", "posix", "x/../~/.ssh/authorized_keys", "x/../~/.ssh/authorized_keys", "./x/../~/.ssh/authorized_keys", false},
		{"POSIX drive recreation", "posix", "C:/../C:/Users/dev/.ssh/authorized_keys", "'C:/../C:/Users/dev/.ssh/authorized_keys'", "./C:/../C:/Users/dev/.ssh/authorized_keys", false},
		{"PowerShell provider tilde", "powershell", "~/x/../.ssh/authorized_keys", "'~/x/../.ssh/authorized_keys'", "~/.ssh/authorized_keys", false},
		{"PowerShell active variable", "powershell", `$env:USERPROFILE\x\..\.ssh\authorized_keys`, `"$env:USERPROFILE\x\..\.ssh\authorized_keys"`, "$env:USERPROFILE/.ssh/authorized_keys", true},
		{"PowerShell escaped variable", "powershell", `$env:USERPROFILE\x\..\.ssh\authorized_keys`, "\"`$env:USERPROFILE\\x\\..\\.ssh\\authorized_keys\"", "./$env:USERPROFILE/x/../.ssh/authorized_keys", false},
		{"CMD active variable", "cmd", `%USERPROFILE%\x\..\.ssh\authorized_keys`, `"%USERPROFILE%\x\..\.ssh\authorized_keys"`, "%USERPROFILE%/.ssh/authorized_keys", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argument := adapter.NativeToValue(ShellArgument{Value: tc.value, Source: tc.source, Expands: tc.expands})
			redirect := adapter.NativeToValue(ShellRedirect{Target: tc.value, TargetSource: tc.source, TargetExpands: tc.expands})
			command := adapter.NativeToValue(ShellCommand{Dialect: tc.dialect, Executable: "Set-Content"})
			for kind, got := range map[string]ref.Val{
				"argument": canonicalPathArgumentBinding(argument, command),
				"redirect": canonicalPathRedirectBinding(redirect, command),
			} {
				if got != types.String(tc.want) {
					t.Errorf("%s = %v, want %q", kind, got, tc.want)
				}
			}
		})
	}
	for _, executable := range []string{"tee", "unknown", "cp", `C:\tools\Set-Content`, `Microsoft.PowerShell.Management\Out-File`, `Microsoft.PowerShell.Utility\Set-Content`} {
		arg := adapter.NativeToValue(ShellArgument{Value: "~/x/../.ssh/authorized_keys", Source: "'~/x/../.ssh/authorized_keys'"})
		command := adapter.NativeToValue(ShellCommand{Dialect: "powershell", Executable: executable})
		if got := canonicalPathArgumentBinding(arg, command); got != types.String("./~/x/../.ssh/authorized_keys") {
			t.Errorf("%s tilde = %v, want unresolved relative path", executable, got)
		}
	}
	for _, executable := range []string{"Set-Content", "Out-File", `Microsoft.PowerShell.Management\Set-Content`, `Microsoft.PowerShell.Utility\Out-File`} {
		if !powerShellFileCmdlet(executable) {
			t.Errorf("%s: want recognized file cmdlet", executable)
		}
	}
	for _, binding := range []func(ref.Val, ref.Val) ref.Val{canonicalPathArgumentBinding, canonicalPathRedirectBinding} {
		if got := binding(types.String("not an operand"), adapter.NativeToValue(ShellCommand{Dialect: "posix"})); !types.IsError(got) {
			t.Errorf("non-object input = %v, want error", got)
		}
		if got := binding(types.String("not an operand"), types.Int(1)); !types.IsError(got) {
			t.Errorf("non-object command = %v, want error", got)
		}
	}
}

func TestCanonicalPathSourceDialect(t *testing.T) {
	for _, tc := range []struct {
		dialect, path, want string
	}{
		{"posix", `\etc\sudoers`, `./\etc\sudoers`},
		{"posix", `/etc/./sudoers`, `/etc/sudoers`},
		{"posix", `/etc/sudoers `, `/etc/sudoers `},
		{"posix", `'/etc/sudoers'`, `./'/etc/sudoers'`},
		{"posix", `//etc/sudoers`, `/etc/sudoers`},
		{"posix", `C:/../etc/sudoers`, `./C:/../etc/sudoers`},
		{"posix", `\\?\C:\etc\sudoers`, `./\\?\C:\etc\sudoers`},
		{"posix", `/proc/self/root/etc/sudoers`, `/etc/sudoers`},
		{"posix", "", ""},
		{"powershell", `C:\..\ProgramData\ssh\administrators_authorized_keys`, `C:/ProgramData/ssh/administrators_authorized_keys`},
		{"cmd", `\\?\C:\Users\dev\.ssh\authorized_keys`, `C:/Users/dev/.ssh/authorized_keys`},
		{"powershell", `\\server\share\..\keys`, `//server/share/keys`},
		{"cmd", `\\server\share\..\keys`, `//server/share/keys`},
		{"posix", `x/../~/.ssh/authorized_keys`, `./x/../~/.ssh/authorized_keys`},
		{"posix", `$HOME/x/../.ssh/authorized_keys`, `./$HOME/x/../.ssh/authorized_keys`},
		{"posix", `/home/$OTHER/../dev/.ssh/authorized_keys`, `/home/$OTHER/../dev/.ssh/authorized_keys`},
		{"", `\etc\sudoers`, `\etc\sudoers`},
		{"unknown", `/etc/./sudoers`, `/etc/./sudoers`},
		{"POSIX", `C:/../etc/sudoers`, `C:/../etc/sudoers`},
	} {
		t.Run(tc.dialect+"/"+tc.path, func(t *testing.T) {
			got := canonicalPathDialectBinding(types.String(tc.path), types.String(tc.dialect))
			if got != types.String(tc.want) {
				t.Fatalf("canonical_path(%q, %q) = %v, want %q", tc.path, tc.dialect, got, tc.want)
			}
		})
	}
	if got := canonicalPathDialectBinding(types.Int(1), types.String("posix")); !types.IsError(got) {
		t.Fatalf("non-string path = %v, want error", got)
	}
	if got := canonicalPathDialectBinding(types.String("/etc/sudoers"), types.Int(1)); !types.IsError(got) {
		t.Fatalf("non-string dialect = %v, want error", got)
	}
}

func TestCanonicalPathCollapsesTraversalForFileEvents(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.protect_rule_file",
		Severity: model.SeverityHigh,
		Expr:     `event.event_type in ["file.write", "file.delete"] && canonical_path(event.file_path) == "/etc/numbat/rules/protect_numbat.yaml"`,
	})
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"plain", "/etc/numbat/rules/protect_numbat.yaml", true},
		{"dot_segment", "/etc/numbat/./rules/protect_numbat.yaml", true},
		{"shallow_traversal", "/etc/numbat/rules/x/../protect_numbat.yaml", true},
		{"deep_traversal_depth4", "/etc/numbat/rules/d0/d1/d2/d3/../../../../protect_numbat.yaml", true},
		{"proc_root_prefix", "/proc/self/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_task_root_pid", "/proc/4321/task/8765/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_task_root_self", "/proc/self/task/8765/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_task_root_dot_segment", "/proc/4321/task/./8765/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_task_root_parent_traversal", "/proc/4321/task/8765/root/../etc/numbat/rules/protect_numbat.yaml", true},
		{"nested_proc_root_prefix", "/proc/self/root/proc/thread-self/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"nested_proc_task_root_prefix", "/proc/4321/task/8765/root/proc/self/task/8765/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_root_pid_traversal", "/proc/4321/root/etc/numbat/rules/d0/d1/../../protect_numbat.yaml", true},
		{"proc_root_parent_traversal", "/proc/self/root/../etc/numbat/rules/protect_numbat.yaml", true},
		{"proc_root_dot_prefix", "/proc/./self/root/etc/numbat/rules/protect_numbat.yaml", true},
		{"duplicate_slash", "/etc/numbat//rules/protect_numbat.yaml", true},
		{"three_leading_slashes", "///etc/numbat/rules/protect_numbat.yaml", true},
		{"windows_separators", `\etc\numbat\rules\protect_numbat.yaml`, true},
		{"UNC_path_does_not_become_local", `\\etc\numbat\rules\protect_numbat.yaml`, false},
		{"zero_is_not_a_pid", "/proc/0/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"zero_padded_pid", "/proc/04321/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"task_zero_tid", "/proc/4321/task/0/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"task_zero_padded_tid", "/proc/4321/task/08765/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"task_non_numeric_tid", "/proc/4321/task/current/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"task_self_is_not_a_tid", "/proc/4321/task/self/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"thread_self_has_no_task_segment", "/proc/thread-self/task/8765/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"missing_task_tid", "/proc/4321/task/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"task_root_name_boundary", "/proc/4321/task/8765/rooted/etc/numbat/rules/protect_numbat.yaml", false},
		{"different_proc_entry", "/proc/not-a-pid/root/etc/numbat/rules/protect_numbat.yaml", false},
		{"similar_proc_entry", "/proc/self/rooted/etc/numbat/rules/protect_numbat.yaml", false},
		{"relative_path_stays_relative", "etc/numbat/rules/protect_numbat.yaml", false},
		{"leading_parent_stays_relative", "../etc/numbat/rules/protect_numbat.yaml", false},
		{"unprotected_sibling", "/etc/numbat/rules.example/protect_numbat.yaml", false},
		{"escapes_out", "/etc/numbat/rules/../ordinary.txt", false},
		{"whitespace_is_path_content", " /etc/numbat/rules/protect_numbat.yaml ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{EventID: "e", EventType: model.EventFileWrite, FilePath: tc.path}
			matches, err := eng.Eval(ev)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			got := len(matches) == 1
			if got != tc.want {
				t.Fatalf("path %q: matched=%v want=%v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCanonicalPathKeepsMissingPathEmpty(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.empty_path",
		Severity: model.SeverityLow,
		Expr:     `canonical_path(event.file_path) == ""`,
	})
	matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
}

func TestCanonicalPathPreservesWindowsDriveRoot(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.windows_drive_root",
		Severity: model.SeverityHigh,
		Expr:     `canonical_path(event.file_path) == "C:/ProgramData/ssh/administrators_authorized_keys"`,
	})
	for _, filePath := range []string{
		`C:\..\ProgramData\ssh\administrators_authorized_keys`,
		`\\?\C:\ProgramData\ssh\administrators_authorized_keys`,
	} {
		ev := model.Event{
			EventID:   "e",
			EventType: model.EventFileWrite,
			FilePath:  filePath,
		}
		matches, err := eng.Eval(ev)
		if err != nil {
			t.Fatalf("Eval(%q): %v", filePath, err)
		}
		if len(matches) != 1 {
			t.Fatalf("Eval(%q) matches = %d, want 1", filePath, len(matches))
		}
	}
}

func TestCanonicalPathPreservesUNCRoot(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.unc_root",
		Severity: model.SeverityLow,
		Expr:     `canonical_path(event.file_path) == "//server/share/keys/authorized_keys"`,
	})
	for _, filePath := range []string{
		`\\server\share\keys\old\..\authorized_keys`,
		`\\?\UNC\server\share\keys\authorized_keys`,
		`//server/share/../../keys/authorized_keys`,
	} {
		matches, err := eng.Eval(model.Event{EventType: model.EventFileWrite, FilePath: filePath})
		if err != nil {
			t.Fatalf("Eval(%q): %v", filePath, err)
		}
		if len(matches) != 1 {
			t.Fatalf("Eval(%q) matches = %d, want 1", filePath, len(matches))
		}
	}
}

func TestCanonicalPathRejectsNonStringEventField(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.non_string_path",
		Severity: model.SeverityLow,
		Expr:     `canonical_path(event.exit_code) == ""`,
	})
	exitCode := 1
	matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ExitCode: &exitCode})
	if err == nil {
		t.Fatal("Eval error = nil, want type error")
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %d, want 0", len(matches))
	}
}

func TestCanonicalPathCollapsesTraversalForShellArgv(t *testing.T) {
	eng := mustEngine(t, Rule{
		ID:       "t.protect_rule_rm",
		Severity: model.SeverityHigh,
		Enforce:  boolPtr(true),
		Expr:     `event.event_type == "command.exec" && shell_commands.exists(command, command.name in ["rm", "unlink"] && command.argv.exists(a, canonical_path(a) == "/usr/local/bin/numbat"))`,
	})
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"plain", "rm -f /usr/local/bin/numbat", true},
		{"deep_traversal_depth5", "rm -f /usr/local/bin/d0/d1/d2/d3/d4/../../../../../numbat", true},
		{"proc_root", "rm -f /proc/thread-self/root/usr/local/bin/numbat", true},
		{"proc_task_root", "rm -f /proc/4321/task/8765/root/usr/local/bin/numbat", true},
		{"benign_other", "rm -f /tmp/numbat", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{EventID: "e", EventType: model.EventCommandExec, Command: tc.command}
			matches, err := eng.Eval(ev)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			got := len(matches) == 1 && matches[0].EnforcementMatch
			if got != tc.want {
				t.Fatalf("command %q: matched=%v want=%v", tc.command, got, tc.want)
			}
		})
	}
}
