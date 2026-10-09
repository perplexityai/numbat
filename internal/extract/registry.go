package extract

import (
	"sort"

	"github.com/perplexityai/numbat/internal/model"
)

// registry is the shared dispatch and enumeration source for at-rest parsers.
var registry = map[string]Extractor{
	model.AgentClaudeCode: ClaudeExtractor{},
	model.AgentCowork:     CoworkExtractor{},
	model.AgentGeminiCLI:  GeminiExtractor{},
	model.AgentCodex:      CodexExtractor{},
	model.AgentCursor:     CursorExtractor{},
	model.AgentWindsurf:   WindsurfExtractor{},
	model.AgentCopilot:    CopilotExtractor{},
	model.AgentOpenCode:   OpenCodeExtractor{},
	model.AgentOpenClaw:   OpenClawExtractor{},
	model.AgentPi:         PiExtractor{},
	model.AgentKimiCode:   KimiCodeExtractor{},
	model.AgentMuseCode:   MuseCodeExtractor{},
}

// For returns the parser registered for an agent identifier.
func For(agent string) (Extractor, bool) {
	e, ok := registry[agent]
	return e, ok
}

// RegisteredAgents returns the sorted identifiers accepted by For.
func RegisteredAgents() []string {
	out := make([]string, 0, len(registry))
	for a := range registry {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
