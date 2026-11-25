package rules_test

import (
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

// TestMCPServerConfigWrite pins the detection boundary for a write to an MCP
// server registry. The structured branch is authoritative; the shell branch
// covers a redirect and the mutating commands whose operand is unambiguously a
// target. Operand roles that need source/target analysis, such as cp and sed,
// are deliberately left out to keep the rule precise.
func TestMCPServerConfigWrite(t *testing.T) {
	eng := builtinEngine(t)
	for _, tc := range []struct {
		name string
		ev   model.Event
		want bool
	}{
		{
			"claude desktop config on macOS",
			model.Event{EventType: model.EventFileWrite, FilePath: "/Users/dev/Library/Application Support/Claude/claude_desktop_config.json"},
			true,
		},
		{
			"claude desktop config on Windows",
			model.Event{EventType: model.EventFileWrite, FilePath: "C:/Users/dev/AppData/Roaming/Claude/claude_desktop_config.json"},
			true,
		},
		{
			"project scoped registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/.mcp.json"},
			true,
		},
		{
			"cursor project registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/.cursor/mcp.json"},
			true,
		},
		{
			"vscode workspace registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/.vscode/mcp.json"},
			true,
		},
		{
			"kiro workspace registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/.kiro/settings/mcp.json"},
			true,
		},
		{
			"windsurf registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/home/dev/.codeium/windsurf/mcp_config.json"},
			true,
		},
		{
			"registry deleted",
			model.Event{EventType: model.EventFileDelete, FilePath: "/repo/.mcp.json"},
			true,
		},
		{
			"shell redirect appends a server",
			cmd(`echo '{"mcpServers":{"x":{}}}' >> .mcp.json`),
			true,
		},
		{
			"shell redirect writes the claude desktop config",
			cmd(`printf '{}' > "$HOME/Library/Application Support/Claude/claude_desktop_config.json"`),
			true,
		},
		{
			"PowerShell Set-Content writes the registry",
			cmd(`Set-Content -Path "$env:APPDATA\Claude\claude_desktop_config.json" -Value "{}"`),
			true,
		},
		{
			"registry removed by rm",
			cmd("rm .mcp.json"),
			true,
		},
		{
			"ordinary source write",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/src/index.ts"},
			false,
		},
		{
			"package manifest write",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/package.json"},
			false,
		},
		{
			"cursor settings are not the registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/.cursor/settings.json"},
			false,
		},
		{
			"backup copy of the registry",
			model.Event{EventType: model.EventFileWrite, FilePath: "/repo/mcp.json.bak"},
			false,
		},
		{
			"registry read is not a write",
			model.Event{EventType: model.EventFileRead, FilePath: "/repo/.mcp.json"},
			false,
		},
		{
			"reading the registry with cat",
			cmd("cat .mcp.json"),
			false,
		},
		{
			"copying the registry out is not a write",
			cmd("cp .mcp.json /tmp/backup.json"),
			false,
		},
		{
			"unrelated shell command",
			cmd("git status --short"),
			false,
		},
		{
			"redirect to an ordinary build artifact",
			cmd("go build -o app ./cmd/app > build.log"),
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, tc.ev), "mcp.server_config_write")
			if got != tc.want {
				t.Fatalf("mcp.server_config_write match = %t, want %t", got, tc.want)
			}
		})
	}
}
