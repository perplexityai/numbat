package rule

import (
	"strings"
	"testing"

	"github.com/google/cel-go/common/types"
)

// Option/value and positional precedence follow sudo's visudo.c:
// https://github.com/sudo-project/sudo/blob/cb6ea72cb0205c782be91d26c71178988c1231af/plugins/sudoers/visudo.c#L113-L234
// Its getopt implementation disables permutation for POSIXLY_CORRECT:
// https://github.com/sudo-project/sudo/blob/cb6ea72cb0205c782be91d26c71178988c1231af/lib/util/getopt_long.c#L372-L388
func TestVisudoEditPath(t *testing.T) {
	for _, tc := range []struct {
		argv, want string
	}{
		{"", ""},
		{"visudo", "/etc/sudoers"},
		{"visudo -IOPqs", "/etc/sudoers"},
		{"visudo --no-includes --owner --perms --quiet --strict", "/etc/sudoers"},
		{"visudo -f /etc/sudoers", "/etc/sudoers"},
		{"visudo -qf/etc/sudoers", "/etc/sudoers"},
		{"visudo --file=/etc/sudoers", "/etc/sudoers"},
		{"visudo --file /etc/sudoers", "/etc/sudoers"},
		{"visudo -f=/etc/sudoers", "=/etc/sudoers"},
		{"visudo /etc/sudoers", "/etc/sudoers"},
		{"visudo -f /etc/sudoers /tmp/fixture", "/etc/sudoers"},
		{"visudo -f /tmp/fixture /etc/sudoers", "/tmp/fixture"},
		{"visudo -f /etc/sudoers -f /tmp/fixture", "/tmp/fixture"},
		{"visudo -f /tmp/fixture -f/etc/sudoers", "/etc/sudoers"},
		{"visudo -f/etc/sudoers -qV", ""},
		{"visudo -qh -f/etc/sudoers", ""},
		{"visudo -qVf/etc/sudoers", ""},
		{"visudo -qcf/etc/sudoers", ""},
		{"visudo --check --file=/etc/sudoers", ""},
		{"visudo --help", ""},
		{"visudo --version", ""},
		{"visudo -x /tmp/export -f/etc/sudoers", ""},
		{"visudo -qx/tmp/export -f/etc/sudoers", ""},
		{"visudo --export=/tmp/export -f/etc/sudoers", ""},
		{"visudo --export /tmp/export -f/etc/sudoers", ""},
		{"visudo -f /etc/sudoers.d/hV", "/etc/sudoers.d/hV"},
		{"visudo -f/etc/sudoers.d/hV", "/etc/sudoers.d/hV"},
		{"visudo -f -V", "-V"},
		{"visudo -f -h -f/etc/sudoers", "/etc/sudoers"},
		{"visudo -f -V --file=/etc/sudoers", "/etc/sudoers"},
		{"visudo -f -c -f/etc/sudoers", "/etc/sudoers"},
		{"visudo -f -f -h", ""},
		{"visudo -- /etc/sudoers", "/etc/sudoers"},
		{"visudo --", "/etc/sudoers"},
		{"visudo -- -f/etc/sudoers", "-f/etc/sudoers"},
		{"visudo -f/etc/sudoers -- -V", "/etc/sudoers"},
		{"visudo -f -- -f/etc/sudoers", "/etc/sudoers"},
		{"visudo --file=-- -f/etc/sudoers", "/etc/sudoers"},
		{"visudo -- -V -f/etc/sudoers", ""},
		{"visudo /etc/sudoers /tmp/fixture", ""},
		{"visudo -f/etc/sudoers /tmp/one /tmp/two", ""},
		{"visudo /etc/sudoers -q", ""},
		{"visudo /tmp/fixture -f/etc/sudoers", ""},
		{"visudo --unknown -f/etc/sudoers", ""},
		{"visudo -Z -f/etc/sudoers", ""},
		{"visudo -qZf/etc/sudoers", ""},
		{"visudo --quiet=yes -f/etc/sudoers", ""},
		{"visudo --fi=/etc/sudoers", ""},
		{"visudo -f", ""},
		{"visudo -qf", ""},
		{"visudo --file", ""},
		{"visudo --file=", ""},
		{"visudo -x", ""},
		{"visudo --export", ""},
	} {
		t.Run(tc.argv, func(t *testing.T) {
			if got := visudoEditPath(strings.Fields(tc.argv)); got != tc.want {
				t.Fatalf("visudoEditPath(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

func TestVisudoEditPathPreservesFileValue(t *testing.T) {
	for _, file := range []string{"", "/etc/sudoers ", "'/etc/sudoers'"} {
		if got := visudoEditPath([]string{"visudo", "-f", file}); got != file {
			t.Errorf("file value %q became %q", file, got)
		}
	}
	if got := visudoEditPathBinding(types.String("visudo")); !types.IsError(got) {
		t.Fatalf("non-list binding = %v, want error", got)
	}
}
