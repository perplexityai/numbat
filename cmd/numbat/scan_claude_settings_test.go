package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const settingsSecret = "hunter2hunter2"

// settingsWithSecret mirrors a "don't ask again" approval: the full command,
// including a literal password, persisted as an allow rule. The variable form
// beside it must not produce a finding.
const settingsWithSecret = `{
  "permissions": {
    "allow": [
      "Bash(npm run test *)",
      "Bash(PGPASSWORD=` + settingsSecret + ` psql -h db.internal -U app)",
      "Bash(PGPASSWORD=$DB_PASS psql -h db.internal -U app)"
    ]
  }
}
`

func TestScanClaudeSettingsFindsPersistedCredentialWithoutEmittingIt(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, "repo", ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(settingsWithSecret), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, emit := range [][]string{nil, {"--emit", "findings", "--emit", "events"}, {"--emit", "indicators"}} {
		args := append([]string{"scan", "--path", root}, emit...)
		out, errb, code := runCLI(args...)
		if code != 0 {
			t.Fatalf("%v: exit = %d (stderr=%s)", emit, code, errb)
		}
		if strings.Contains(out, settingsSecret) || strings.Contains(errb, settingsSecret) {
			t.Fatalf("%v: scan output leaked the persisted credential:\n%s\n%s", emit, out, errb)
		}
		if emit != nil && emit[1] == "indicators" {
			continue
		}
		findings := decodeFindings(t, out)
		if len(findings) != 1 {
			t.Fatalf("%v: findings = %d, want 1:\n%s", emit, len(findings), out)
		}
		f := findings[0]
		if f.RuleID != "secrets.persisted_permission_credential" {
			t.Fatalf("%v: rule = %q", emit, f.RuleID)
		}
		if len(f.EvidenceRefs) != 1 || f.EvidenceRefs[0].LocalPath != settings ||
			f.EvidenceRefs[0].JSONPointer != "/permissions/allow/1" || f.EvidenceRefs[0].SHA256 == "" {
			t.Fatalf("%v: evidence = %+v", emit, f.EvidenceRefs)
		}
	}
}

func TestScanDefaultDiscoveryFindsProjectSettingsFromTranscripts(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")

	project := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(project, ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(settingsWithSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	transcriptDir := filepath.Join(home, ".claude", "projects", "repo")
	if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cwd := strings.ReplaceAll(filepath.ToSlash(project), `"`, `\"`)
	transcript := `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-06-02T10:00:00Z","cwd":"` + cwd + `","message":{"role":"user","content":"hello"}}` + "\n"
	if err := os.WriteFile(filepath.Join(transcriptDir, "session.jsonl"), []byte(transcript), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errb, code := runCLI("scan", "--agent", "claude")
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%s)", code, errb)
	}
	findings := decodeFindings(t, out)
	if len(findings) != 1 || findings[0].RuleID != "secrets.persisted_permission_credential" {
		t.Fatalf("findings = %+v", findings)
	}
	if !strings.Contains(errb, "2 discovered, 2 parsed") {
		t.Fatalf("summary did not count the transcript and settings file: %s", errb)
	}
	if strings.Contains(out, settingsSecret) {
		t.Fatalf("scan output leaked the persisted credential:\n%s", out)
	}

	// The same home scanned through --path does not probe transcript projects.
	out, errb, code = runCLI("scan", "--path", filepath.Join(home, ".claude"))
	if code != 0 {
		t.Fatalf("--path exit = %d (stderr=%s)", code, errb)
	}
	if got := len(decodeFindings(t, out)); got != 0 {
		t.Fatalf("--path findings = %d, want 0:\n%s", got, out)
	}
}
