package rule

import (
	"path"
	"regexp"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/perplexityai/numbat/internal/model"
)

var procRootPath = regexp.MustCompile(`^/proc/(?:(?:self|[1-9][0-9]*)/task/[1-9][0-9]*|self|thread-self|[1-9][0-9]*)/root(?:/+|$)`)

func canonicalPathBinding(arg ref.Val) ref.Val {
	value, ok := arg.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(canonicalPath(string(value)))
}

func canonicalPath(value string) string {
	value = model.NormalizeEventPath(value)
	if value == "" {
		return ""
	}
	if len(value) >= 7 && value[:4] == "//?/" && isWindowsDrivePath(value[4:]) {
		value = value[4:]
	} else if len(value) >= 8 && strings.EqualFold(value[:8], "//?/UNC/") {
		value = "//" + value[8:]
	}
	if len(value) > 2 && strings.HasPrefix(value, "//") && value[2] != '/' {
		return canonicalUNCPath(value)
	}
	volume := ""
	if isWindowsDrivePath(value) {
		volume = value[:2]
		value = value[2:]
	}
	for {
		if volume == "" {
			prefix := procRootPath.FindStringIndex(value)
			if prefix != nil {
				if prefix[1] == len(value) {
					return "/"
				}
				value = value[prefix[1]-1:]
				continue
			}
		}
		clean := path.Clean(value)
		if clean == value {
			return volume + clean
		}
		value = clean
	}
}

func isWindowsDrivePath(value string) bool {
	return len(value) >= 3 &&
		((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
		value[1] == ':' && value[2] == '/'
}

func canonicalUNCPath(value string) string {
	parts := strings.SplitN(strings.TrimPrefix(value, "//"), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return value
	}
	root := "//" + parts[0] + "/" + parts[1]
	if len(parts) == 2 {
		return root
	}
	rest := path.Clean("/" + parts[2])
	if rest == "/" {
		return root
	}
	return root + rest
}
