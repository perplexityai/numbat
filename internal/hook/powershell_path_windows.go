//go:build windows

package hook

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

func systemPowerShellPath() string {
	systemDir, err := windows.GetSystemDirectory()
	if err != nil || systemDir == "" {
		// Keep executable lookup out of the working directory even if the API
		// unexpectedly fails. Standard supported installations use this path.
		systemDir = `C:\Windows\System32`
	}
	// Forward slashes are accepted by both PowerShell and cmd.exe, and an
	// unquoted executable at the head of the command stays a command in
	// PowerShell instead of being parsed as a string expression.
	return filepath.ToSlash(filepath.Join(systemDir, "WindowsPowerShell", "v1.0", "powershell.exe"))
}
