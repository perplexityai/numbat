package evaluator

import (
	"fmt"
	"strings"
	"testing"
)

func TestResponseRejectsCaseVariantAliases(t *testing.T) {
	const good = `{"id":"response","provider":"fixture","model":"test","answers":{"policy":{"type":"choice","choice":"blocked","probabilities":{"blocked":0.999,"unknown":0.001}}}}`
	if !exactResponseFields([]byte(good)) {
		t.Fatal("valid response rejected")
	}
	for _, field := range []string{"id", "provider", "model", "answers", "type", "choice", "probabilities"} {
		for _, upper := range []string{strings.ToUpper(field[:1]) + field[1:], strings.ToUpper(field)} {
			for _, encoded := range []string{upper, fmt.Sprintf(`\u%04x%s`, upper[0], upper[1:])} {
				raw := strings.Replace(good, `"`+field+`":`, `"`+encoded+`":null,"`+field+`":`, 1)
				if exactResponseFields([]byte(raw)) {
					t.Fatalf("accepted %s alias: %s", field, raw)
				}
				raw = strings.Replace(good, `"`+field+`":`, `"`+field+`":null,"`+encoded+`":`, 1)
				if exactResponseFields([]byte(raw)) {
					t.Fatalf("accepted reverse %s alias", field)
				}
			}
		}
	}
	escaped := strings.Replace(good, `"choice":"blocked"`, `"choice":"blocked","\u0043hoice":"unknown"`, 1)
	if exactResponseFields([]byte(escaped)) {
		t.Fatal("accepted escaped Choice alias")
	}
}
