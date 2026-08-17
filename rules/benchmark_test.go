package rules_test

import (
	"strings"
	"testing"

	"github.com/perplexityai/numbat/internal/model"
	"github.com/perplexityai/numbat/internal/rule"
	builtinrules "github.com/perplexityai/numbat/rules"
)

func BenchmarkBuiltinEngineCommandEval(b *testing.B) {
	engine := builtinEngine(b)
	cases := []struct {
		name  string
		event model.Event
	}{
		{"tool_result", model.Event{EventType: model.EventToolResult}},
		{"file_read", model.Event{EventType: model.EventFileRead, FilePath: "/repo/README.md"}},
		{"short_command", model.Event{EventType: model.EventCommandExec, Command: "go test ./..."}},
		{"64_segments", model.Event{EventType: model.EventCommandExec, Command: strings.Repeat("echo ready;", 63) + "crontab /tmp/job"}},
		{"long_docker_argv", model.Event{EventType: model.EventCommandExec, Command: "docker run " + strings.Repeat("--env K=V ", 128) + "ubuntu:24.04"}},
	}
	for _, test := range cases {
		if _, err := engine.Eval(test.event); err != nil {
			b.Fatalf("%s warmup: %v", test.name, err)
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := engine.Eval(test.event); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBuiltinEngineCompile(b *testing.B) {
	sources, err := rule.LoadSourcesFS(builtinrules.FS, builtinrules.Dir)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := rule.NewEngine(sources); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuiltinSourceLoad(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := rule.LoadSourcesFS(builtinrules.FS, builtinrules.Dir); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuiltinCheckedExpressionLoad(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := rule.LoadCheckedExpressionsFS(builtinrules.CheckedFS, builtinrules.CheckedDir); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuiltinEngineChecked(b *testing.B) {
	sources, err := rule.LoadSourcesFS(builtinrules.FS, builtinrules.Dir)
	if err != nil {
		b.Fatal(err)
	}
	checked, err := rule.LoadCheckedExpressionsFS(builtinrules.CheckedFS, builtinrules.CheckedDir)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := rule.NewEngineWithCheckedExpressions(sources, checked); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRuleEnvironment(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := rule.NewEngine(nil); err != nil {
			b.Fatal(err)
		}
	}
}
