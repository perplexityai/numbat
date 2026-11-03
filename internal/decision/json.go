package decision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ValidJSON accepts one JSON value with unique object keys and bounded nesting.
// Last-wins duplicate decoding is not an unambiguous basis for a decision.
func ValidJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if checkJSONValue(d, 0) != nil {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func checkJSONValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("decision JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, nested := t.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := t.(string)
			if !ok || seen[key] {
				return errors.New("ambiguous decision JSON key")
			}
			seen[key] = true
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid decision JSON delimiter")
	}
	_, err = d.Token()
	return err
}
