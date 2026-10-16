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

type contentScope uint8

const (
	contentScopeAll contentScope = iota
	contentScopeMessages
)

func parseContentScope(value string) (contentScope, error) {
	switch value {
	case "all":
		return contentScopeAll, nil
	case "messages":
		return contentScopeMessages, nil
	default:
		return contentScopeAll, fmt.Errorf("invalid --content-scope %q: want all|messages", value)
	}
}

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
	return "message and tool content in event output: preview|full|raw (full redacts; raw preserves selected content; messages: 1 MiB; tool payloads: 16 MiB)"
}

func contentScopeFlagHelp() string {
	return "scope of full/raw content: all|messages (messages keeps tool previews and metadata; does not affect local detection)"
}

const maxRecordBytesHelp = "maximum bytes per output record including newline (0 disables; oversized content bodies are omitted)"

func contentEmitterOptions(mode contentMode, scope contentScope, maxRecordBytes int) []output.EmitterOption {
	var opts []output.EmitterOption
	switch mode {
	case contentRaw:
		opts = append(opts, output.WithRawContent())
	case contentFull:
		opts = append(opts, output.WithFullContent())
	}
	if scope == contentScopeMessages {
		opts = append(opts, output.WithMessageContentOnly())
	}
	if maxRecordBytes != 0 {
		opts = append(opts, output.WithMaxRecordBytes(maxRecordBytes))
	}
	return opts
}
