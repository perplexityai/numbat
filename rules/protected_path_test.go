package rules_test

import (
	"fmt"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	"github.com/perplexityai/numbat/rules"
)

func TestProtectedPathSourceSemantics(t *testing.T) {
	type testCase struct {
		name, tool, command, want string
		detectionOnly             bool
	}
	const sudoers = "privilege.sudoers_tamper"
	const keys = "persistence.ssh_authorized_keys_command"
	cases := []testCase{
		{"literal HOME redirect", "bash", `printf key > '$HOME/x/../.ssh/authorized_keys'`, "", false},
		{"literal tilde redirect", "bash", `printf key > '~/x/../.ssh/authorized_keys'`, "", false},
		{"literal braced HOME redirect", "bash", `printf key > '${HOME}/x/../.ssh/authorized_keys'`, "", false},
		{"double quoted tilde", "bash", `printf key > "~/x/../.ssh/authorized_keys"`, "", false},
		{"escaped HOME", "bash", `printf key > \$HOME/x/../.ssh/authorized_keys`, "", false},
		{"escaped tilde", "bash", `printf key > \~/x/../.ssh/authorized_keys`, "", false},
		{"mixed quoted HOME", "bash", `printf key > '$HOME'/x/../.ssh/authorized_keys`, "", false},
		{"literal prefix unrelated expansion", "bash", `printf key > '$HOME/'"$PART"'/../.ssh/authorized_keys'`, "", false},
		{"quoted tilde unrelated expansion", "bash", `printf key > "~/$PART/../.ssh/authorized_keys"`, "", false},
		{"relative tilde manufacture", "bash", `printf key > 'x/../~/.ssh/authorized_keys'`, "", false},
		{"relative HOME manufacture", "bash", `printf key > x/../$HOME/.ssh/authorized_keys`, "", false},
		{"relative drive manufacture", "bash", `printf key > 'x/../C:/Users/dev/.ssh/authorized_keys'`, "", false},
		{"relative direct drive", "bash", `printf key > 'C:/Users/dev/.ssh/authorized_keys'`, "", false},
		{"relative drive recreation", "bash", `printf key > 'C:/../C:/Users/dev/.ssh/authorized_keys'`, "", false},
		{"tilde root recreation", "bash", `printf key > ~/../~/.ssh/authorized_keys`, "", false},
		{"HOME root recreation", "bash", `printf key > $HOME/../$HOME/.ssh/authorized_keys`, "", false},
		{"absolute unknown expansion", "bash", `printf key > "/home/$OTHER/../dev/.ssh/authorized_keys"`, "", false},
		{"absolute literal dollar directory", "bash", `printf key > '/home/$OTHER/../dev/.ssh/authorized_keys'`, keys, false},
		{"HOME suffix unknown expansion", "bash", `printf key > "$HOME/$OTHER/../.ssh/authorized_keys"`, "", false},
		{"active HOME redirect", "bash", `printf key > "$HOME/x/../.ssh/authorized_keys"`, keys, true},
		{"active braced HOME redirect", "bash", `printf key > "${HOME}/x/../.ssh/authorized_keys"`, keys, true},
		{"active tilde redirect", "bash", `printf key > ~/x/../.ssh/authorized_keys`, keys, true},
		{"literal tee operand", "bash", `tee '$HOME/x/../.ssh/authorized_keys'`, "", false},
		{"active tee operand", "bash", `tee "$HOME/x/../.ssh/authorized_keys"`, keys, true},
		{"absolute tee operand", "bash", `tee /home/dev/x/../.ssh/authorized_keys`, keys, false},
		{"literal copy last operand", "bash", `cp /tmp/key '~/x/../.ssh/authorized_keys'`, "", false},
		{"active copy last operand", "bash", `cp /tmp/key ~/x/../.ssh/authorized_keys`, keys, true},
		{"absolute copy last operand", "bash", `cp /tmp/key /home/dev/x/../.ssh/authorized_keys`, keys, false},
		{"PowerShell literal variable", "powershell", `Set-Content '$env:USERPROFILE\x\..\.ssh\authorized_keys' key`, "", false},
		{"PowerShell expanding variable", "powershell", `Set-Content "$env:USERPROFILE\x\..\.ssh\authorized_keys" key`, keys, true},
		{"PowerShell provider tilde", "powershell", `Set-Content '~/x/../.ssh/authorized_keys' key`, keys, false},
		{"PowerShell native tilde", "powershell", `tee '~/x/../.ssh/authorized_keys'`, "", false},
		{"PowerShell unknown tilde", "powershell", `unknown '~/x/../.ssh/authorized_keys'`, "", false},
		{"PowerShell redirect tilde", "powershell", `Write-Output key > '~/x/../.ssh/authorized_keys'`, keys, false},
		{"PowerShell copy provider tilde", "powershell", `Copy-Item /tmp/key '~/x/../.ssh/authorized_keys'`, keys, false},
		{"PowerShell named provider tilde", "powershell", `Copy-Item /tmp/key -Destination '~/x/../.ssh/authorized_keys' -Force`, keys, false},
		{"PowerShell literal named destination", "powershell", `Copy-Item /tmp/key -Destination '$env:USERPROFILE\x\..\.ssh\authorized_keys' -Force`, "", false},
		{"PowerShell expanding named destination", "powershell", `Copy-Item /tmp/key -Destination "$env:USERPROFILE\x\..\.ssh\authorized_keys" -Force`, keys, true},
		{"PowerShell absolute named destination", "powershell", `Copy-Item /tmp/key -Destination 'C:\Users\dev\x\..\.ssh\authorized_keys' -Force`, keys, false},
		{"PowerShell absolute unknown expansion", "powershell", `Set-Content "C:\Users\$OTHER\..\dev\.ssh\authorized_keys" key`, "", false},
		{"CMD expanding home", "cmd", `echo key > "%USERPROFILE%\x\..\.ssh\authorized_keys"`, keys, true},
		{"visudo clustered version", "bash", "visudo -qV -f/etc/sudoers", "", false},
		{"visudo clustered help", "bash", "visudo -qh -f/etc/sudoers", "", false},
		{"visudo attached edit", "bash", "visudo -qf/etc/sudoers", sudoers, false},
		{"visudo hV in file value", "bash", "visudo -f/etc/sudoers.d/hV", sudoers, false},
		{"visudo consumes version-looking file", "bash", "visudo -f -V -f/etc/sudoers", sudoers, false},
		{"visudo last fixture wins", "bash", "visudo -f/etc/sudoers -f /tmp/fixture", "", false},
		{"visudo ignores positional with file option", "bash", "visudo -f/tmp/fixture /etc/sudoers", "", false},
		{"visudo marker precedes option-looking file", "bash", "visudo -- -f/etc/sudoers", "", false},
		{"visudo marker precedes protected file", "bash", "visudo -- /etc/sudoers", sudoers, false},
		{"visudo marker precedes ignored positional", "bash", "visudo -f/etc/sudoers -- -V", sudoers, false},
		{"visudo unknown option", "bash", "visudo --unknown -f/etc/sudoers", "", false},
		{"visudo missing value", "bash", "visudo -f/etc/sudoers -f", "", false},
		{"visudo conditional edit is detection only", "bash", "echo ready && visudo -f/etc/sudoers", sudoers, true},
		{"PowerShell drive target", "powershell", `Set-Content 'C:\Users\dev\.ssh\authorized_keys' key`, keys, false},
		{"PowerShell drive traversal", "pwsh", `Set-Content 'C:\..\ProgramData\ssh\administrators_authorized_keys' key`, keys, false},
		{"PowerShell preview remains detection only", "powershell", `Set-Content 'C:\Users\dev\.ssh\authorized_keys' key -WhatIf`, keys, true},
		{"PowerShell UNC stays remote", "powershell", `Set-Content '\\server\share\Users\dev\.ssh\authorized_keys' key`, "", false},
		{"CMD drive redirect", "cmd", `echo key > C:\Users\dev\.ssh\authorized_keys`, keys, false},
		{"CMD UNC redirect stays remote", "cmd", `echo key > \\server\share\Users\dev\.ssh\authorized_keys`, "", false},
	}
	for _, tool := range []string{"bash", "sh", "zsh", ""} {
		for _, tc := range []testCase{
			{"literal backslash redirect", "", `printf fixture > '\etc\sudoers'`, "", false},
			{"literal backslash operand", "", `rm '\etc\sudoers'`, "", false},
			{"literal backslash SSH redirect", "", `printf fixture > '\home\dev\.ssh\authorized_keys'`, "", false},
			{"literal trailing space", "", `printf fixture > '/etc/sudoers '`, "", false},
			{"literal quote characters", "", `printf fixture > "'/etc/sudoers'"`, "", false},
			{"POSIX drive-looking relative path", "", `printf fixture > 'C:/../etc/sudoers'`, "", false},
			{"POSIX duplicate root slashes", "", `printf policy > //etc/sudoers`, sudoers, false},
			{"POSIX protected redirect", "", `printf policy > /etc/./sudoers`, sudoers, false},
			{"POSIX SSH redirect", "", `printf key > /home/dev/.ssh/./authorized_keys`, keys, false},
			{"POSIX proc alias", "", `rm /proc/self/root/etc/sudoers`, sudoers, false},
			{"POSIX conditional redirect", "", `echo ready && printf policy > /etc/sudoers`, sudoers, true},
		} {
			tc.name = tool + "/" + tc.name
			tc.tool = tool
			cases = append(cases, tc)
		}
	}

	for _, enforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("enforce=%v", enforce), func(t *testing.T) {
			sources, err := rule.LoadSourcesFS(rules.FS, rules.Dir)
			if err != nil {
				t.Fatal(err)
			}
			var selected []rule.Source
			for _, source := range sources {
				for _, r := range source.Rules {
					if r.ID == sudoers || r.ID == keys {
						r.Enforce = &enforce
						selected = append(selected, rule.Source{Name: source.Name, Rules: []rule.Rule{r}})
					}
				}
			}
			checked, err := rule.LoadCheckedExpressionsFS(rules.CheckedFS, rules.CheckedDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, generated := range []bool{false, true} {
				t.Run(fmt.Sprintf("generated=%v", generated), func(t *testing.T) {
					var eng *rule.Engine
					if generated {
						eng, err = rule.NewEngineWithCheckedExpressions(selected, checked)
					} else {
						eng, err = rule.NewEngine(selected)
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, tc := range cases {
						t.Run(tc.name, func(t *testing.T) {
							matches, err := eng.Eval(model.Event{EventType: model.EventCommandExec, ToolName: tc.tool, Command: tc.command})
							if err != nil {
								t.Fatal(err)
							}
							if tc.want == "" {
								if len(matches) != 0 {
									t.Fatalf("expected no match, got %+v", matches)
								}
							} else if len(matches) != 1 || matches[0].Rule.ID != tc.want ||
								matches[0].EnforcementMatch != (enforce && !tc.detectionOnly) {
								t.Fatalf("matches = %+v, want %s (enforcement %v)", matches, tc.want, enforce && !tc.detectionOnly)
							}
						})
					}
				})
			}
		})
	}
}
