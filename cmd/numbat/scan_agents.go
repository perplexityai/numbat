package main

import (
	"fmt"
	"strings"

	"github.com/perplexityai/numbat/internal/model"
)

var artifactAgentByCLI = map[string]string{
	"claude":   model.AgentClaudeCode,
	"codex":    model.AgentCodex,
	"copilot":  model.AgentCopilot,
	"cowork":   model.AgentCowork,
	"cursor":   model.AgentCursor,
	"gemini":   model.AgentGeminiCLI,
	"kimi":     model.AgentKimiCode,
	"muse":     model.AgentMuseCode,
	"openclaw": model.AgentOpenClaw,
	"opencode": model.AgentOpenCode,
	"pi":       model.AgentPi,
	"windsurf": model.AgentWindsurf,
}

var artifactAgentNames = []string{
	"claude", "codex", "copilot", "cowork", "cursor", "gemini",
	"kimi", "muse", "openclaw", "opencode", "pi", "windsurf",
}

func artifactAgentUsage() string {
	return strings.Join(artifactAgentNames, "|")
}

func parseArtifactAgents(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, name := range values {
		sourceAgent, ok := artifactAgentByCLI[name]
		if !ok {
			return nil, fmt.Errorf("invalid --agent %q: want %s", name, artifactAgentUsage())
		}
		if _, ok := seen[sourceAgent]; ok {
			continue
		}
		seen[sourceAgent] = struct{}{}
		out = append(out, sourceAgent)
	}
	return out, nil
}
