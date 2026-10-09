package rule

import (
	"path"
	"reflect"
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

func canonicalPathDialectBinding(arg, dialect ref.Val) ref.Val {
	value, ok := arg.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	style, ok := dialect.(types.String)
	if !ok {
		return types.MaybeNoSuchOverloadErr(dialect)
	}
	// Strings alone cannot distinguish literal metacharacters from expansion.
	spelling := string(value)
	if style == types.String(dialectPowerShell.String()) || style == types.String(dialectCMD.String()) {
		spelling = strings.TrimPrefix(model.NormalizeEventPath(spelling), "//?/")
	}
	expands := strings.ContainsAny(spelling, "$`%*?[]{}")
	return types.String(canonicalCommandPath(string(value), "", expands, string(style), false))
}

func canonicalPathArgumentBinding(arg, command ref.Val) ref.Val {
	context, err := command.ConvertToNative(reflect.TypeFor[ShellCommand]())
	if err != nil {
		return types.MaybeNoSuchOverloadErr(command)
	}
	value, err := arg.ConvertToNative(reflect.TypeFor[ShellArgument]())
	if err != nil {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	operand := value.(ShellArgument)
	cmd := context.(ShellCommand)
	return types.String(canonicalCommandPath(operand.Value, operand.Source, operand.Expands, cmd.Dialect, powerShellFileCmdlet(cmd.Executable)))
}

func canonicalPathRedirectBinding(arg, command ref.Val) ref.Val {
	context, err := command.ConvertToNative(reflect.TypeFor[ShellCommand]())
	if err != nil {
		return types.MaybeNoSuchOverloadErr(command)
	}
	value, err := arg.ConvertToNative(reflect.TypeFor[ShellRedirect]())
	if err != nil {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	operand := value.(ShellRedirect)
	cmd := context.(ShellCommand)
	return types.String(canonicalCommandPath(operand.Target, operand.TargetSource, operand.TargetExpands, cmd.Dialect, true))
}

// Only explicit file cmdlets establish provider semantics; aliases and native
// executables may interpret a literal tilde differently.
func powerShellFileCmdlet(executable string) bool {
	name := strings.ToLower(executable)
	if module, cmdlet, qualified := strings.Cut(name, `\`); qualified {
		wantModule := "microsoft.powershell.management"
		if cmdlet == "out-file" {
			wantModule = "microsoft.powershell.utility"
		}
		if module != wantModule {
			return false
		}
		name = cmdlet
	}
	switch name {
	case "add-content", "clear-content", "copy-item", "move-item", "new-item",
		"out-file", "remove-item", "set-content":
		return true
	default:
		return false
	}
}

func canonicalCommandPath(value, source string, expands bool, dialect string, providerPath bool) string {
	windows := dialect == dialectPowerShell.String() || dialect == dialectCMD.String()
	if !windows && dialect != dialectPOSIX.String() {
		return value
	}
	if windows {
		value = model.NormalizeEventPath(value)
	}
	if value == "" {
		return ""
	}
	root, suffix, separated := strings.Cut(value, "/")
	if separated && activeCommandHomeRoot(root, source, expands, dialect, providerPath) {
		// A home root is opaque: ../ must not erase it or reveal a later root.
		// Other expansions can contain separators, so do not cancel them either.
		if strings.ContainsAny(suffix, "$`%*?[]{}") {
			return value
		}
		return root + "/" + path.Clean(suffix)
	}
	if strings.HasPrefix(value, "/") || windows && isWindowsDrivePath(value) {
		if expands {
			return value
		}
		return canonicalPathLexical(value, windows)
	}
	// Keep relative provenance even if the spelling resembles a home or drive.
	// Do not let cleaning x/.. manufacture a new root.
	if strings.HasPrefix(value, "./") {
		return value
	}
	return "./" + value
}

func activeCommandHomeRoot(root, source string, expands bool, dialect string, providerPath bool) bool {
	if source == "" {
		return false
	}
	switch dialect {
	case dialectPOSIX.String():
		if root == "~" {
			return expands && strings.HasPrefix(source, "~/")
		}
		if root != "$HOME" && root != "${HOME}" {
			return false
		}
	case dialectPowerShell.String():
		if root == "~" {
			return providerPath
		}
		root = strings.ToLower(root)
		source = strings.ToLower(model.NormalizeEventPath(source))
		if root != "$home" && root != "${home}" && root != "$env:userprofile" && root != "$env:programdata" {
			return false
		}
	case dialectCMD.String():
		root = strings.ToLower(root)
		source = strings.ToLower(model.NormalizeEventPath(source))
		if root != "%userprofile%" && root != "%programdata%" {
			return false
		}
	default:
		return false
	}
	return expands && strings.HasPrefix(strings.TrimPrefix(source, `"`), root+"/")
}

func canonicalPath(value string) string {
	return canonicalPathLexical(model.NormalizeEventPath(value), true)
}

func canonicalPathLexical(value string, windowsRoots bool) string {
	if value == "" {
		return ""
	}
	volume := ""
	if windowsRoots {
		if len(value) >= 7 && value[:4] == "//?/" && isWindowsDrivePath(value[4:]) {
			value = value[4:]
		} else if len(value) >= 8 && strings.EqualFold(value[:8], "//?/UNC/") {
			value = "//" + value[8:]
		}
		if len(value) > 2 && strings.HasPrefix(value, "//") && value[2] != '/' {
			return canonicalUNCPath(value)
		}
		if isWindowsDrivePath(value) {
			volume = value[:2]
			value = value[2:]
		}
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
