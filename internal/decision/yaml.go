package decision

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DecodeYAML decodes one bounded decision policy or configuration document.
// Unknown fields and duplicate keys are rejected. Errors expose line/category,
// not supplied values that may contain sensitive operator data.
func DecodeYAML(data []byte, out any) error {
	if len(data) > 512<<10 {
		return errors.New("YAML document exceeds 524288 bytes")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return yamlError(err)
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("requires one YAML document")
	}
	return nil
}

func yamlError(err error) error {
	message, format, kind := err.Error(), "yaml: line %d:", "invalid field or syntax"
	var fields *yaml.TypeError
	if errors.As(err, &fields) && len(fields.Errors) != 0 {
		message, format = fields.Errors[0], "line %d:"
	}
	switch {
	case strings.Contains(message, "already defined"):
		kind = "duplicate key"
	case strings.Contains(message, "not found in type"):
		kind = "unknown field"
	case strings.Contains(message, "cannot unmarshal"):
		kind = "invalid field type"
	}
	var line int
	if _, err := fmt.Sscanf(message, format, &line); err == nil && line > 0 {
		return fmt.Errorf("YAML line %d: %s; use the documented fields and types", line, kind)
	}
	return fmt.Errorf("invalid YAML: %s; use the documented fields and types", kind)
}
