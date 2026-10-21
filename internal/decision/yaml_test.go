package decision

import (
	"strings"
	"testing"
)

func TestPolicyYAMLErrorsAreSpecificAndSafe(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"unknown", "id: local.test\nunknown: DO_NOT_ECHO\n", "unknown field"},
		{"type", "id: local.test\nenforce: DO_NOT_ECHO\n", "invalid field type"},
		{"duplicate", "id: local.test\nid: DO_NOT_ECHO\n", "duplicate key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPolicy(strings.NewReader(tc.body))
			if err == nil || !strings.Contains(err.Error(), "line 2") ||
				!strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "DO_NOT_ECHO") {
				t.Fatalf("unsafe or unactionable policy diagnostic: %v", err)
			}
		})
	}
}
