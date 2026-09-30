package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var structuredSecretKey = regexp.MustCompile(secretKeyTerm)

var tokenMetricKeys = map[string]struct{}{
	"audio_tokens":                {},
	"cache_creation_input_tokens": {},
	"cache_read_input_tokens":     {},
	"cache_write_input_tokens":    {},
	"cached_input_tokens":         {},
	"cached_tokens":               {},
	"completion_tokens":           {},
	"completion_tokens_details":   {},
	"context_window_tokens":       {},
	"ephemeral_1h_input_tokens":   {},
	"ephemeral_5m_input_tokens":   {},
	"input_token_count":           {},
	"input_tokens":                {},
	"input_tokens_details":        {},
	"last_token_usage":            {},
	"max_output_tokens":           {},
	"max_tokens":                  {},
	"output_token_count":          {},
	"output_tokens":               {},
	"output_tokens_details":       {},
	"prompt_tokens":               {},
	"prompt_tokens_details":       {},
	"reasoning_output_tokens":     {},
	"reasoning_tokens":            {},
	"time_to_first_token_ms":      {},
	"token_count":                 {},
	"token_usage":                 {},
	"total_token_usage":           {},
	"total_tokens":                {},
}

// JSON redacts one JSON value without producing invalid JSON.
func JSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	redacted, err := redactJSONValue(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(redacted)
}

func redactJSONValue(value any) (any, error) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if String(key) != key {
				return nil, fmt.Errorf("JSON object key contains credential material")
			}
			credential := false
			switch strings.ToLower(key) {
			case "authorization", "proxy-authorization", "cookie", "set-cookie", "auth", "credentials", "pwd":
				credential = true
			}
			if credential || structuredSecretKey.MatchString(key) && !isTokenMetric(key, child) {
				value[key] = Mask
				continue
			}
			redacted, err := redactJSONValue(child)
			if err != nil {
				return nil, err
			}
			value[key] = redacted
		}
		return value, nil
	case []any:
		for i := range value {
			redacted, err := redactJSONValue(value[i])
			if err != nil {
				return nil, err
			}
			value[i] = redacted
		}
		return value, nil
	case string:
		return String(value), nil
	default:
		return value, nil
	}
}

func isTokenMetric(key string, value any) bool {
	key = strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	if _, ok := tokenMetricKeys[key]; !ok {
		return false
	}
	return isNumericJSONValue(value)
}

func isNumericJSONValue(value any) bool {
	switch value := value.(type) {
	case json.Number:
		return true
	case map[string]any:
		for _, child := range value {
			if !isNumericJSONValue(child) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
