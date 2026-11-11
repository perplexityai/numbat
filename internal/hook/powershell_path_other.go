//go:build !windows

package hook

// systemPowerShellPath supplies a stable value for cross-platform command
// rendering tests. Native Windows builds resolve the actual system directory.
func systemPowerShellPath() string {
	return `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`
}
