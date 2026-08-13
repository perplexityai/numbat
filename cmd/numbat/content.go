package main

import (
	"fmt"

	"github.com/perplexityai/numbat/internal/output"
)

type contentMode uint8

const (
	contentPreview contentMode = iota
	contentFull
)

func parseContentMode(value string) (contentMode, error) {
	switch value {
	case "preview":
		return contentPreview, nil
	case "full":
		return contentFull, nil
	default:
		return contentPreview, fmt.Errorf("invalid --content %q: want preview|full", value)
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
	if mode == contentFull && !sel.events {
		return fmt.Errorf("--content full requires --emit events or --emit all")
	}
	return nil
}

func contentFlagHelp() string {
	return "conversation content in event output: preview|full (full is redacted and bounded to 1 MiB)"
}

func contentEmitterOptions(mode contentMode) []output.EmitterOption {
	if mode == contentFull {
		return []output.EmitterOption{output.WithFullContent()}
	}
	return nil
}
