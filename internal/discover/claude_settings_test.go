package discover

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

func TestClassifyClaudeSettings(t *testing.T) {
	clearDefaultRootEnv(t)
	configDir := t.TempDir()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/home/dev/.claude/settings.json", true},
		{"/home/dev/.claude/settings.local.json", true},
		{"/repo/.claude/settings.local.json", true},
		{"/repo/sub/.claude/settings.json", true},
		{".claude/settings.local.json", true},
		{"/repo/settings.local.json", false},
		{"/repo/.claude/other.json", false},
		{"/repo/.cursor/settings.json", false},
		{filepath.Join(configDir, "settings.json"), false},
	} {
		a, ok := classify(tc.path)
		if ok != tc.want {
			t.Errorf("classify(%q) = %t, want %t", tc.path, ok, tc.want)
		}
		if ok && a.Agent != model.AgentClaudeCode {
			t.Errorf("classify(%q) agent = %q, want claude-code", tc.path, a.Agent)
		}
	}
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	if _, ok := classify(filepath.Join(configDir, "settings.local.json")); !ok {
		t.Error("settings under CLAUDE_CONFIG_DIR were not classified")
	}
	if _, ok := classify(filepath.Join(configDir, "nested", "settings.json")); ok {
		t.Error("nested settings under CLAUDE_CONFIG_DIR were classified")
	}
}

func TestDefaultRootsIncludeUserClaudeSettings(t *testing.T) {
	home := t.TempDir()
	clearDefaultRootEnv(t)
	settings := filepath.Join(home, ".claude", "settings.json")
	local := filepath.Join(home, ".claude", "settings.local.json")
	mkfile(t, settings, "{}")
	mkfile(t, local, "{}")
	got := DefaultRootsFor(home, []string{model.AgentClaudeCode})
	if !slices.Equal(got, []string{settings, local}) {
		t.Fatalf("Claude roots = %v, want [%q %q]", got, settings, local)
	}
	if got := DefaultRootsFor(home, []string{model.AgentCodex}); len(got) != 0 {
		t.Fatalf("Codex roots = %v, want none", got)
	}
}

func TestClaudeProjectSettingsProbesToRepositoryRoot(t *testing.T) {
	home := t.TempDir()
	outer := filepath.Join(home, "work")
	repo := filepath.Join(outer, "repo")
	sub := filepath.Join(repo, "pkg", "app")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	repoLocal := filepath.Join(repo, ".claude", "settings.local.json")
	repoShared := filepath.Join(repo, ".claude", "settings.json")
	subLocal := filepath.Join(sub, ".claude", "settings.local.json")
	mkfile(t, repoLocal, "{}")
	mkfile(t, repoShared, "{}")
	mkfile(t, subLocal, "{}")
	// Above the repository root and in home are out of project scope.
	mkfile(t, filepath.Join(outer, ".claude", "settings.local.json"), "{}")
	mkfile(t, filepath.Join(home, ".claude", "settings.json"), "{}")
	// A directory with the settings name is not a regular file.
	other := filepath.Join(home, "other")
	if err := os.MkdirAll(filepath.Join(other, ".claude", "settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	projects := []string{sub, repo, "relative/project", "", filepath.Join(home, "missing"), other}
	got := ClaudeProjectSettings(home, projects)
	want := []string{subLocal, repoShared, repoLocal}
	if !slices.Equal(got, want) {
		t.Fatalf("project settings = %v, want %v", got, want)
	}
	if got := ClaudeProjectSettings(home, nil); len(got) != 0 {
		t.Fatalf("no projects = %v, want none", got)
	}
}

func TestClaudeProjectSettingsWithoutRepositoryStopsAtHome(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "notes", "draft")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(home, "notes", ".claude", "settings.local.json")
	mkfile(t, parent, "{}")
	mkfile(t, filepath.Join(home, ".claude", "settings.local.json"), "{}")
	got := ClaudeProjectSettings(home, []string{project})
	if !slices.Equal(got, []string{parent}) {
		t.Fatalf("project settings = %v, want [%q]", got, parent)
	}
}

func TestWalkFindsProjectSettings(t *testing.T) {
	clearDefaultRootEnv(t)
	root := t.TempDir()
	local := filepath.Join(root, "svc", ".claude", "settings.local.json")
	mkfile(t, local, `{"permissions":{"allow":["Bash(ls)"]}}`)
	mkfile(t, filepath.Join(root, "svc", "settings.json"), "{}")
	arts, skips, err := Walk(root)
	if err != nil || len(skips) != 0 {
		t.Fatalf("walk: arts=%v skips=%v err=%v", arts, skips, err)
	}
	if len(arts) != 1 || arts[0].Path != local || arts[0].Agent != model.AgentClaudeCode {
		t.Fatalf("artifacts = %+v, want only %q", arts, local)
	}
}
