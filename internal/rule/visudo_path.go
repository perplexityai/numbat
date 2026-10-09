package rule

import (
	"reflect"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func visudoEditPathBinding(arg ref.Val) ref.Val {
	value, err := arg.ConvertToNative(reflect.TypeFor[[]string]())
	if err != nil {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(visudoEditPath(value.([]string)))
}

// visudoEditPath recognizes options before at most one positional file. It
// deliberately avoids platform-dependent getopt permutation after an operand.
// An empty result means no statically supported edit target, not the default.
func visudoEditPath(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	file := "/etc/sudoers"
	explicitFile := false
	options := true
	operands := 0
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			operands++
			if operands > 1 {
				return ""
			}
			options = false
			if !explicitFile {
				file = arg
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached := strings.Cut(arg, "=")
			switch name {
			case "--check", "--help", "--version", "--export":
				return ""
			case "--no-includes", "--owner", "--perms", "--quiet", "--strict":
				if attached {
					return ""
				}
			case "--file":
				if !attached {
					i++
					if i == len(argv) {
						return ""
					}
					value = argv[i]
				}
				if value == "" {
					return ""
				}
				file, explicitFile = value, true
			default:
				return ""
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'I', 'O', 'P', 'q', 's':
			case 'c', 'h', 'V', 'x':
				return ""
			case 'f':
				value := arg[j+1:]
				if value == "" {
					i++
					if i == len(argv) {
						return ""
					}
					value = argv[i]
				}
				if value == "" {
					return ""
				}
				file, explicitFile = value, true
				j = len(arg) // The rest of this option word is the file value.
			default:
				return ""
			}
		}
	}
	return file
}
