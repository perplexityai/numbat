package rule

import (
	"path"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

var procRootPrefix = regexp.MustCompile(`^/proc/(?:self|thread-self|[1-9][0-9]*)(?:/task/[1-9][0-9]*)?/root(?:/|$)`)

func canonicalPathFunction() cel.EnvOption {
	return cel.Function("canonical_path",
		cel.Overload("canonical_path_string",
			[]*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(canonicalPathBinding),
		),
	)
}

func canonicalPathBinding(arg ref.Val) ref.Val {
	value, ok := arg.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(canonicalPath(string(value)))
}

func canonicalPath(value string) string {
	if value == "" || !strings.Contains(value, "/") {
		return value
	}
	if strings.HasPrefix(value, "/") {
		if strings.ContainsAny(value, "$`") {
			return value
		}
		for {
			for {
				loc := procRootPrefix.FindStringIndex(value)
				if loc == nil {
					break
				}
				value = "/" + value[loc[1]:]
			}
			cleaned := path.Clean(value)
			if cleaned == value {
				return value
			}
			value = cleaned
		}
	}
	root, rest, _ := strings.Cut(value, "/")
	if strings.ContainsAny(rest, "$`") {
		return value
	}
	if strings.HasSuffix(root, "=") {
		return root + canonicalPath("/"+rest)
	}
	rest = strings.TrimLeft(rest, "/")
	if rest == "" {
		return root
	}
	return root + "/" + path.Clean(rest)
}
