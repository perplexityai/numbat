package main

import (
	"fmt"

	"github.com/perplexityai/numbat/internal/output"
)

type contentMode uint8

const (
	contentPreview contentMode = iota
	contentFull
	contentRaw
)

func parseContentMode(value string) (contentMode, error) {
	switch value {
	case "preview":
		return contentPreview, nil
	case "full":
		return contentFull, nil
	case "raw":
		return contentRaw, nil
	default:
		return contentPreview, fmt.Errorf("invalid --content %q: want preview|full|raw", value)
	}
}

func applyDeprecatedProfile(value string, includeReasoning bool) (bool, error) {
	switch value {
	case "", "evidence":
		return includeReasoning, nil
	case "full":
		return true, nil
	default:
		return false, fmt.Errorf("invalid --profile %q: want evidence|full", value)
	}
}

func validateContentSelection(mode contentMode, sel emitSelection) error {
	if mode != contentPreview && !sel.events {
		name := "full"
		if mode == contentRaw {
			name = "raw"
		}
		return fmt.Errorf("--content %s requires --emit events or --emit all", name)
	}
	return nil
}

func contentFlagHelp() string {
	return "message and tool content in event output: preview|full|raw (full redacts, raw does not; messages: 1 MiB; tool payloads: 16 MiB)"
}

func contentEmitterOptions(mode contentMode) []output.EmitterOption {
	if mode == contentRaw {
		return []output.EmitterOption{output.WithRawContent()}
	}
	if mode == contentFull {
		return []output.EmitterOption{output.WithFullContent()}
	}
	return nil
}
