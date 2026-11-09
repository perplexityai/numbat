package rules_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
)

const persistedPermissionRule = "secrets.persisted_permission_credential"

// settingsAllow builds the event the Claude settings parser emits for one
// permissions.allow entry: the raw JSON string is the tool input.
func settingsAllow(t *testing.T, ruleText string) model.Event {
	t.Helper()
	raw, err := json.Marshal(ruleText)
	if err != nil {
		t.Fatal(err)
	}
	ev := model.Event{
		EventType:        model.EventPermissionApproved,
		SourceType:       model.SourceArtifact,
		SourceAgent:      model.AgentClaudeCode,
		ToolName:         "Bash",
		Decision:         model.DecisionAllowed,
		ApprovalDecision: model.DecisionAllowed,
	}
	ev.SetToolInput(json.RawMessage(raw))
	return ev
}

func TestSecretsPersistedPermissionCredential(t *testing.T) {
	eng := builtinEngine(t)
	// Token-shaped fixtures are assembled at runtime so the source tree never
	// carries a string that secret scanners would treat as a live credential.
	ghToken := "ghp_" + strings.Repeat("A1b2", 9)
	slackToken := "xoxb-" + strings.Repeat("1234", 4) + "-abcdEFGH"
	anthropicKey := "sk-ant-" + "api03-" + strings.Repeat("x", 24)
	for _, tc := range []struct {
		name string
		rule string
		want bool
	}{
		{"pgpassword assignment", "Bash(PGPASSWORD=hunter2hunter2 psql -h db -U app)", true},
		{"quoted mysql password env", "Bash(MYSQL_PWD='s3cr3tPassw0rd' mysql -u root)", true},
		{"double-quoted api key env", `Bash(OPENAI_API_KEY="abcd1234efgh5678" python run.py)`, true},
		{"token flag", "Bash(vault login --token=hvs.CAESIabcdefgh12345678)", true},
		{"spaced password flag", "Bash(redis-cli --password Sup3rS3cretValue ping)", true},
		{"bearer header", `Bash(curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc" https://api.example.com)`, true},
		{"custom token header", `Bash(curl -H 'X-Eppo-Token: 0123456789abcdef' https://eppo.example)`, true},
		{"url userinfo", "Bash(psql postgres://app:Pa55word@db.internal:5432/app)", true},
		{"github token", "Bash(git clone https://" + ghToken + "@github.com/org/repo)", true},
		{"slack token", "Bash(curl -d token=" + slackToken + " https://slack.com/api/auth.test)", true},
		{"anthropic key", "Bash(curl -H x-api-key:" + anthropicKey + " https://api.anthropic.com)", true},
		{"aws access key", "Bash(AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls)", true},
		{"sshpass literal", "Bash(sshpass -p hunter2 ssh admin@host)", true},
		{"mysql attached password", "Bash(mysql -u root -pS3cret db)", true},
		{"query token", "WebFetch(https://api.example.com/v1?token=abcdef0123456789)", true},

		{"variable assignment", "Bash(PGPASSWORD=$DB_PASS psql -h db)", false},
		{"braced variable", "Bash(PGPASSWORD=${DB_PASS} psql -h db)", false},
		{"command substitution", `Bash(GITHUB_TOKEN="$(gh auth token)" gh api user)`, false},
		{"wildcard value", "Bash(PGPASSWORD=* psql:*)", false},
		{"variable bearer", `Bash(curl -H "Authorization: Bearer $TOKEN" https://api.example.com)`, false},
		{"variable userinfo", "Bash(psql postgres://app:${PGPASS}@db/app)", false},
		{"sshpass from env", "Bash(sshpass -e ssh admin@host)", false},
		{"mysql prompts", "Bash(mysql -u root -p db)", false},
		{"short placeholder", "Bash(TOKEN=abc make test)", false},
		{"token count flag", "Bash(llm --max-tokens=1000000 prompt)", false},
		{"token file flag", "Bash(gh auth login --with-token)", false},
		{"ordinary rule", "Bash(npm run test *)", false},
		{"ssh url without password", "Bash(git clone ssh://git@github.com/org/repo)", false},
		{"web fetch domain", "WebFetch(domain:docs.anthropic.com)", false},
		{"read deny style path", "Read(./.env)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, settingsAllow(t, tc.rule)), persistedPermissionRule)
			if got != tc.want {
				t.Fatalf("%s match = %t, want %t for %q", persistedPermissionRule, got, tc.want, tc.rule)
			}
		})
	}
}

// The rule describes persisted configuration, so a live approval or a command
// carrying the same text must not fire it.
func TestSecretsPersistedPermissionCredentialScope(t *testing.T) {
	eng := builtinEngine(t)
	live := settingsAllow(t, "Bash(PGPASSWORD=hunter2hunter2 psql)")
	live.SourceType = model.SourceHook
	if contains(match(t, eng, live), persistedPermissionRule) {
		t.Fatal("hook approval matched the persisted-rule detector")
	}
	requested := settingsAllow(t, "Bash(PGPASSWORD=hunter2hunter2 psql)")
	requested.EventType = model.EventPermissionRequested
	if contains(match(t, eng, requested), persistedPermissionRule) {
		t.Fatal("permission request matched the persisted-rule detector")
	}
}
