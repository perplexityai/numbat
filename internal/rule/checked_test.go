package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/google/cel-go/cel"
	"github.com/perplexityai/numbat/internal/model"
	"google.golang.org/protobuf/proto"
)

func TestCheckedExpressionsPreserveEvaluation(t *testing.T) {
	enforce := true
	sources := []Source{{Name: "test", Rules: []Rule{{
		ID:       "test.command",
		Version:  "1.0",
		Title:    "test",
		Severity: model.SeverityLow,
		Expr:     `event.event_type == "command.exec" && shell_commands.exists(command, command.name == "echo")`,
		Enforce:  &enforce,
	}}}}
	checked, err := BuildCheckedExpressions(sources)
	if err != nil {
		t.Fatal(err)
	}
	fromSource, err := NewEngine(sources)
	if err != nil {
		t.Fatal(err)
	}
	fromChecked, err := NewEngineWithCheckedExpressions(sources, checked)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []model.Event{
		{EventType: model.EventCommandExec, Command: "echo ready"},
		{EventType: model.EventCommandExec, Command: "go test ./..."},
		{EventType: model.EventFileRead, FilePath: "README.md"},
	} {
		want, wantErr := fromSource.Eval(event)
		got, gotErr := fromChecked.Eval(event)
		if gotErr != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("checked evaluation = (%#v, %v), source = (%#v, %v)", got, gotErr, want, wantErr)
		}
	}
}

func TestCheckedExpressionASTLoadsGeneratedExpression(t *testing.T) {
	const expression = `event.event_type == "command.exec"`
	sources := []Source{{Name: "test", Rules: []Rule{{
		ID:       "test.command",
		Version:  "1.0",
		Title:    "test",
		Severity: model.SeverityLow,
		Expr:     expression,
	}}}}
	checked, err := BuildCheckedExpressions(sources)
	if err != nil {
		t.Fatal(err)
	}
	ast, ok := checkedExpressionAST(expression, checked)
	if !ok {
		t.Fatal("generated checked expression did not load")
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		t.Fatalf("checked expression output type = %s, want bool", ast.OutputType())
	}
}

func TestCheckedExpressionsFallBackToSource(t *testing.T) {
	const expression = `event.event_type == "command.exec"`
	sources := []Source{{Name: "test", Rules: []Rule{{
		ID:       "test.command",
		Version:  "1.0",
		Title:    "test",
		Severity: model.SeverityLow,
		Expr:     expression,
	}}}}
	digest := sha256.Sum256([]byte(expression))
	location := checkedExpressionLocationPrefix + hex.EncodeToString(digest[:])

	otherSources := []Source{{Name: "other", Rules: []Rule{{
		ID:       "test.other",
		Version:  "1.0",
		Title:    "other",
		Severity: model.SeverityLow,
		Expr:     `event.event_type == "file.read"`,
	}}}}
	other, err := BuildCheckedExpressions(otherSources)
	if err != nil {
		t.Fatal(err)
	}
	var otherData []byte
	for _, data := range other {
		otherData = data
	}
	defaultEnv, err := cel.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	foreignEnv, err := cel.NewEnv(cel.Function(
		"foreign",
		cel.Overload("foreign_bool", nil, cel.BoolType),
	))
	if err != nil {
		t.Fatal(err)
	}

	for name, checked := range map[string]CheckedExpressions{
		"missing":              {},
		"corrupt":              {digest: []byte("not protobuf")},
		"wrong source":         {digest: otherData},
		"invalid result type":  {digest: marshalCheckedExpr(t, defaultEnv, `"not bool"`, location)},
		"unavailable overload": {digest: marshalCheckedExpr(t, foreignEnv, `foreign()`, location)},
	} {
		t.Run(name, func(t *testing.T) {
			engine, err := NewEngineWithCheckedExpressions(sources, checked)
			if err != nil {
				t.Fatal(err)
			}
			matches, err := engine.Eval(model.Event{EventType: model.EventCommandExec})
			if err != nil || len(matches) != 1 {
				t.Fatalf("fallback evaluation = (%d matches, %v), want one match", len(matches), err)
			}
		})
	}
}

func marshalCheckedExpr(t *testing.T, env *cel.Env, expression, location string) []byte {
	t.Helper()
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	checked, err := cel.AstToCheckedExpr(ast)
	if err != nil {
		t.Fatal(err)
	}
	checked.SourceInfo.Location = location
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadCheckedExpressionsFS(t *testing.T) {
	sources := []Source{{Name: "test", Rules: []Rule{{
		ID:       "test.rule",
		Version:  "1.0",
		Title:    "test",
		Severity: model.SeverityLow,
		Expr:     "true",
	}}}}
	checked, err := BuildCheckedExpressions(sources)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{}
	for digest, data := range checked {
		files["checked/"+hex.EncodeToString(digest[:])+".pb"] = &fstest.MapFile{Data: data}
	}
	loaded, err := LoadCheckedExpressionsFS(files, "checked")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(checked) {
		t.Fatalf("loaded %d expressions, want %d", len(loaded), len(checked))
	}
}

func TestLoadCheckedExpressionsFSRejectsBadFilename(t *testing.T) {
	files := fstest.MapFS{"checked/not-a-digest.pb": &fstest.MapFile{Data: []byte("x")}}
	if _, err := LoadCheckedExpressionsFS(files, "checked"); err == nil {
		t.Fatal("bad checked-expression filename was accepted")
	}
}
