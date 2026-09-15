package hook

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf16"
)

const maxHookConfigFileSize = 16 << 20

// Explicit agent-side deadlines keep a stuck callback from inheriting long
// vendor defaults.
const (
	fastHookTimeoutSeconds   = 10
	promptHookTimeoutSeconds = 30
	stopHookTimeoutSeconds   = 45
)

// Installers preserve unrelated config, keep one pristine backup, and replace
// user-level settings atomically. Unix writes use mode 0600; Windows uses the
// destination directory's inherited ACL.

// claudeHookEvent is a Claude Code settings hook event name paired with the
// numbat lifecycle argument its command invokes and an optional tool matcher.
type claudeHookEvent struct {
	// settingsKey is the key under "hooks" in Claude's settings.json.
	settingsKey string
	// lifecycle is the positional argument passed to `numbat hook <lifecycle>`.
	lifecycle string
	// matcher restricts which tools fire the hook; empty means all.
	matcher string
	// timeout is the hook's timeout in seconds; 0 omits it.
	timeout int
}

// claudeHookEvents is the Claude Code hook set numbat installs. It covers
// lifecycle boundaries, prompts, tool success/failure, permission gates, and
// subagent spans that map cleanly to the normalized event vocabulary.
var claudeHookEvents = []claudeHookEvent{
	{settingsKey: "SessionStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{settingsKey: "UserPromptSubmit", lifecycle: "prompt-submit", timeout: promptHookTimeoutSeconds},
	{settingsKey: "PreToolUse", lifecycle: "pre-tool", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUse", lifecycle: "post-tool", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PostToolUseFailure", lifecycle: "post-tool", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PermissionRequest", lifecycle: "permission-request", timeout: fastHookTimeoutSeconds},
	{settingsKey: "PermissionDenied", lifecycle: "permission-denied", timeout: fastHookTimeoutSeconds},
	{settingsKey: "Stop", lifecycle: "stop", timeout: stopHookTimeoutSeconds},
	{settingsKey: "SessionEnd", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStart", lifecycle: "session-start", timeout: fastHookTimeoutSeconds},
	{settingsKey: "SubagentStop", lifecycle: "session-end", timeout: fastHookTimeoutSeconds},
}

// hookRef is one command-hook entry in a Claude settings hook group.
type hookRef struct {
	Type    string
	Command string
	Args    []string
	Timeout int
	fields  map[string]json.RawMessage
}

// hookGroup is a matcher plus the command hooks that fire for it.
type hookGroup struct {
	Matcher string
	Hooks   []hookRef
	fields  map[string]json.RawMessage
}

func (h *hookRef) UnmarshalJSON(data []byte) error {
	var wire struct {
		Type    string   `json:"type"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
		Timeout int      `json:"timeout"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &h.fields); err != nil {
		return err
	}
	h.Type, h.Command, h.Args, h.Timeout = wire.Type, wire.Command, wire.Args, wire.Timeout
	return nil
}

func (h hookRef) MarshalJSON() ([]byte, error) {
	out := cloneRawFields(h.fields)
	if h.Type != "" {
		if err := setJSONField(out, "type", h.Type); err != nil {
			return nil, err
		}
	}
	if h.Command != "" {
		if err := setJSONField(out, "command", h.Command); err != nil {
			return nil, err
		}
	}
	if h.Args != nil {
		if err := setJSONField(out, "args", h.Args); err != nil {
			return nil, err
		}
	}
	if h.Timeout != 0 {
		if err := setJSONField(out, "timeout", h.Timeout); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

func (g *hookGroup) UnmarshalJSON(data []byte) error {
	var wire struct {
		Matcher string    `json:"matcher"`
		Hooks   []hookRef `json:"hooks"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &g.fields); err != nil {
		return err
	}
	g.Matcher, g.Hooks = wire.Matcher, wire.Hooks
	return nil
}

func (g hookGroup) MarshalJSON() ([]byte, error) {
	out := cloneRawFields(g.fields)
	if g.Matcher != "" {
		if err := setJSONField(out, "matcher", g.Matcher); err != nil {
			return nil, err
		}
	}
	if err := setJSONField(out, "hooks", g.Hooks); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func cloneRawFields(fields map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(fields)+4)
	for key, value := range fields {
		out[key] = value
	}
	return out
}

func setJSONField(fields map[string]json.RawMessage, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal hook field %s: %w", key, err)
	}
	fields[key] = data
	return nil
}

// settingsFile holds a Claude settings.json with its "hooks" block split out for
// editing. Unrelated top-level keys are preserved verbatim in values so a
// round-trip never drops a user's configuration.
type settingsFile struct {
	values map[string]json.RawMessage
	hooks  map[string][]hookGroup
}

// numbatHookMarker identifies owned entries independently of the binary name.
// The live handler accepts it as inert provenance.
const numbatHookMarker = "--installed-by=numbat"

// InstallReport is the per-agent outcome of an install/uninstall/status call.
type InstallReport struct {
	Agent        string
	Supported    bool
	Installed    bool
	SettingsPath string
	BackupPath   string
	Changed      bool
	Message      string
}

// AgentSupportsHooks reports whether an agent has a lifecycle-hook backend numbat
// can wire into. The closed set mirrors AgentNames; each agent's config shape
// lives in its install_*.go file.
func AgentSupportsHooks(agent string) bool {
	switch agent {
	case AgentClaude, AgentCursor, AgentWindsurf, AgentCopilot, AgentCodex,
		AgentVSCode, AgentGemini, AgentOpenCode, AgentOpenClaw, AgentAntigravity, AgentFactory, AgentGrok,
		AgentDevin, AgentHermes, AgentPi, AgentKimi, AgentQwen, AgentCline, AgentAmp, AgentAuggie, AgentKiro,
		AgentGoose, AgentKilo, AgentOpenHands, AgentCrush, AgentJunie:
		return true
	default:
		return false
	}
}

// AgentSupportsEnforcement reports whether the agent has a documented,
// synchronous pre-tool blocking contract that numbat implements.
func AgentSupportsEnforcement(agent string) bool {
	switch agent {
	case AgentClaude, AgentCodex, AgentCursor, AgentCopilot, AgentVSCode, AgentGemini,
		AgentWindsurf, AgentAntigravity, AgentFactory, AgentGrok, AgentDevin, AgentHermes,
		AgentOpenClaw, AgentPi, AgentKimi, AgentQwen, AgentCline, AgentAmp, AgentAuggie, AgentKiro, AgentGoose, AgentKilo, AgentOpenHands, AgentCrush, AgentJunie:
		return true
	default:
		return false
	}
}

// EnforceAgentUsage is the stable CLI list of enforce-capable install targets.
func EnforceAgentUsage() string {
	return "claude|codex|cursor|copilot|vscode|gemini|windsurf|antigravity|factory|grok|devin|hermes|openclaw|pi|kimi|qwen|cline|amp|auggie|kiro|goose|kilo|openhands|crush|junie"
}

// InstallAgentNames returns the distinct hook configurations targeted by
// --agent all. vscode is an explicit alias for copilot because both products
// load the same ~/.copilot/hooks files; installing both would be redundant.
// OpenHands is project-scoped and therefore requires an explicit --settings
// path rather than participating in a user-home-wide install.
func InstallAgentNames() []string {
	out := make([]string, 0, len(agentList)-2)
	for _, agent := range agentList {
		if agent != AgentVSCode && agent != AgentOpenHands {
			out = append(out, agent)
		}
	}
	return out
}

// AgentSupportsManagedHooks reports whether numbat can write an upstream
// admin-managed hook layer for agent. Managed hook formats are not universal:
// Claude uses managed settings JSON, while Codex uses requirements TOML.
func AgentSupportsManagedHooks(agent string) bool {
	switch agent {
	case AgentClaude, AgentCodex, AgentCursor, AgentCopilot, AgentGemini, AgentWindsurf, AgentQwen, AgentAuggie:
		return true
	default:
		return false
	}
}

// ManagedAgentUsage is the stable CLI list of first-class managed targets.
func ManagedAgentUsage() string {
	return "claude|codex|cursor|copilot|gemini|windsurf|qwen|auggie"
}

// ManagedHooksPath returns the default admin-managed hook config path for agent.
// Claude uses a managed-settings.d drop-in so numbat does not rewrite a shared
// base policy file; Codex uses the system requirements.toml source documented for
// managed hooks.
func ManagedHooksPath(agent string) (string, bool) {
	if agent == AgentQwen {
		if path := os.Getenv("QWEN_CODE_SYSTEM_SETTINGS_PATH"); path != "" {
			return path, true
		}
	}
	return managedHooksPath(agent, runtime.GOOS, os.Getenv("ProgramFiles"), os.Getenv("ProgramData"))
}

func managedHooksPath(agent, goos, programFiles, programData string) (string, bool) {
	switch agent {
	case AgentClaude:
		switch goos {
		case "darwin":
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "ClaudeCode", "managed-settings.d", "numbat.json"), true
		case "windows":
			root := programFiles
			if root == "" {
				root = `C:\Program Files`
			}
			return filepath.Join(root, "ClaudeCode", "managed-settings.d", "numbat.json"), true
		default:
			return filepath.Join(string(filepath.Separator), "etc", "claude-code", "managed-settings.d", "numbat.json"), true
		}
	case AgentCodex:
		if goos == "windows" {
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "OpenAI", "Codex", "requirements.toml"), true
		}
		return filepath.Join(string(filepath.Separator), "etc", "codex", "requirements.toml"), true
	case AgentCursor:
		switch goos {
		case "darwin":
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "Cursor", "hooks.json"), true
		case "windows":
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "Cursor", "hooks.json"), true
		default:
			return filepath.Join(string(filepath.Separator), "etc", "cursor", "hooks.json"), true
		}
	case AgentCopilot:
		if goos == "windows" {
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "GitHub", "Copilot", "policy.d", "numbat.json"), true
		}
		return filepath.Join(string(filepath.Separator), "etc", "github-copilot", "policy.d", "numbat.json"), true
	case AgentGemini:
		switch goos {
		case "darwin":
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "GeminiCli", "settings.json"), true
		case "windows":
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "gemini-cli", "settings.json"), true
		default:
			return filepath.Join(string(filepath.Separator), "etc", "gemini-cli", "settings.json"), true
		}
	case AgentWindsurf:
		switch goos {
		case "darwin":
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "Windsurf", "hooks.json"), true
		case "windows":
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "Windsurf", "hooks.json"), true
		default:
			return filepath.Join(string(filepath.Separator), "etc", "windsurf", "hooks.json"), true
		}
	case AgentQwen:
		switch goos {
		case "darwin":
			return filepath.Join(string(filepath.Separator), "Library", "Application Support", "QwenCode", "settings.json"), true
		case "windows":
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "qwen-code", "settings.json"), true
		default:
			return filepath.Join(string(filepath.Separator), "etc", "qwen-code", "settings.json"), true
		}
	case AgentAuggie:
		if goos == "windows" {
			root := programData
			if root == "" {
				root = `C:\ProgramData`
			}
			return filepath.Join(root, "Augment", "settings.json"), true
		}
		return filepath.Join(string(filepath.Separator), "etc", "augment", "settings.json"), true
	default:
		return "", false
	}
}

// claudeCommandWithArgs builds one absolute, self-contained hook command from
// validated install-time runtime options.
func claudeCommandWithArgs(binary, lifecycle string, runtimeArgs []string, enforce bool) string {
	return buildHookCommand(runtime.GOOS, binary, lifecycle, AgentClaude, runtimeArgs, enforce)
}

// enforceFlag opts an installed hook into blocking explicitly enforceable matches.
const enforceFlag = "--enforce"

// shellQuote produces one POSIX shell argument, including embedded quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func appendShellArgs(cmd string, args []string) string {
	for _, arg := range args {
		cmd += " " + shellQuote(arg)
	}
	return cmd
}

func hookInvocationArgs(lifecycle, agent string, runtimeArgs []string, enforce bool) []string {
	args := []string{"hook", lifecycle, "--agent", agent, numbatHookMarker}
	if enforce {
		args = append(args, enforceFlag)
	}
	return append(args, runtimeArgs...)
}

// buildHookCommand renders a command string for hook schemas that cannot carry
// an argument array. Windows uses EncodedCommand so cmd.exe, PowerShell, and Git
// Bash cannot reinterpret paths, URLs, or output arguments.
func buildHookCommand(goos, binary, lifecycle, agent string, runtimeArgs []string, enforce bool) string {
	args := hookInvocationArgs(lifecycle, agent, runtimeArgs, enforce)
	if goos == "windows" {
		return encodedPowerShellCommand(binary, args)
	}
	cmd := fmt.Sprintf("%s hook %s --agent %s %s", shellQuote(binary), lifecycle, agent, numbatHookMarker)
	if enforce {
		cmd += " " + enforceFlag
	}
	return appendShellArgs(cmd, runtimeArgs)
}

func encodedPowerShellCommand(binary string, args []string) string {
	var script strings.Builder
	script.WriteString("$global:LASTEXITCODE = 1; & ")
	script.WriteString(powerShellQuote(binary))
	for _, arg := range args {
		script.WriteByte(' ')
		script.WriteString(powerShellQuote(arg))
	}
	script.WriteString("; exit $LASTEXITCODE")
	return windowsCommandQuote(systemPowerShellPath()) +
		" -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodePowerShell(script.String())
}

func powerShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func windowsCommandQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		data[i*2] = byte(unit)
		data[i*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// decodedHookCommand returns the PowerShell source from a command generated by
// buildHookCommand. Other command strings are returned unchanged.
func decodedHookCommand(cmd string) string {
	scripts := decodedHookCommands(cmd)
	if len(scripts) > 0 {
		return scripts[0]
	}
	return cmd
}

func decodedHookCommands(cmd string) []string {
	const flag = "-encodedcommand"
	lower := strings.ToLower(cmd)
	var scripts []string
	for offset := 0; offset < len(cmd); {
		i := strings.Index(lower[offset:], flag)
		if i < 0 {
			break
		}
		start := offset + i + len(flag)
		for start < len(cmd) && (cmd[start] == ' ' || cmd[start] == '\t') {
			start++
		}
		end := start
		for end < len(cmd) && isBase64Byte(cmd[end]) {
			end++
		}
		if end > start {
			data, err := base64.StdEncoding.DecodeString(cmd[start:end])
			if err == nil && len(data)%2 == 0 {
				units := make([]uint16, len(data)/2)
				for i := range units {
					units[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
				}
				scripts = append(scripts, string(utf16.Decode(units)))
			}
		}
		offset = start
		if end > start {
			offset = end
		}
	}
	return scripts
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' ||
		b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
}

func outputFileArgs(outputFile string) []string {
	if outputFile == "" {
		return nil
	}
	return []string{"--output=file", "--output-file", outputFile}
}

// isNumbatHookCommand reports whether a hook command was installed by numbat,
// detected by the marker numbat owns and always emits — never by the binary's
// name, so a renamed binary is still recognized.
func isNumbatHookCommand(cmd string) bool {
	if strings.Contains(cmd, numbatHookMarker) {
		return true
	}
	for _, script := range decodedHookCommands(cmd) {
		if strings.Contains(script, numbatHookMarker) {
			return true
		}
	}
	return false
}

func isNumbatHookRef(ref hookRef) bool {
	if isNumbatHookCommand(ref.Command) {
		return true
	}
	return slicesContain(ref.Args, numbatHookMarker)
}

func slicesContain(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// readSettings loads a Claude settings.json, splitting the "hooks" block out for
// editing. A missing file is not an error: it yields an empty settings value so
// install can create it.
func readSettings(path string) (settingsFile, error) {
	sf := settingsFile{
		values: map[string]json.RawMessage{},
		hooks:  map[string][]hookGroup{},
	}
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return settingsFile{}, err
	}
	if len(data) == 0 {
		return sf, nil
	}
	if err := json.Unmarshal(data, &sf.values); err != nil {
		return settingsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if raw, ok := sf.values["hooks"]; ok {
		if err := json.Unmarshal(raw, &sf.hooks); err != nil {
			return settingsFile{}, fmt.Errorf("parse hooks in %s: %w", path, err)
		}
	}
	if sf.hooks == nil {
		sf.hooks = map[string][]hookGroup{}
	}
	return sf, nil
}

// marshal renders the settings back to indented JSON, folding the edited hooks
// block back in and preserving every other top-level key.
func (sf settingsFile) marshal() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(sf.values)+1)
	for k, v := range sf.values {
		if k != "hooks" {
			out[k] = v
		}
	}
	if len(sf.hooks) > 0 {
		data, err := json.Marshal(sf.hooks)
		if err != nil {
			return nil, err
		}
		out["hooks"] = data
	}
	return json.MarshalIndent(out, "", "  ")
}

// marshalAlwaysHooks is marshal for an agent whose schema requires the hooks key
// to always be present (Codex's {hooks:{...}}). Unlike marshal, which omits an
// empty hooks block (matching Claude's settings.json, where an empty hooks key is
// not required), this emits the hooks map even when empty: after an uninstall
// that removed the last entry the file must still carry a (possibly empty) hooks
// map rather than collapsing to an object with no hooks key — the same lesson the
// Cursor/Windsurf installers encode in their own marshal.
func (sf settingsFile) marshalAlwaysHooks() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(sf.values)+1)
	for k, v := range sf.values {
		if k != "hooks" {
			out[k] = v
		}
	}
	hooks := sf.hooks
	if hooks == nil {
		hooks = map[string][]hookGroup{}
	}
	data, err := json.Marshal(hooks)
	if err != nil {
		return nil, err
	}
	out["hooks"] = data
	return json.MarshalIndent(out, "", "  ")
}

// hasNumbatHooks reports whether any numbat-installed hook is present.
func (sf settingsFile) hasNumbatHooks() bool {
	for _, groups := range sf.hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isNumbatHookRef(h) {
					return true
				}
			}
		}
	}
	return false
}

// applyNumbatHooksWithArgs sets numbat's hook entries for each lifecycle event,
// replacing any prior numbat entry so a re-install is idempotent. Non-numbat
// hooks in the same event are left untouched.
func (sf settingsFile) applyNumbatHooksWithArgs(binary string, runtimeArgs []string, enforce bool) {
	for _, ev := range claudeHookEvents {
		groups := stripNumbatGroups(sf.hooks[ev.settingsKey])
		groups = append(groups, hookGroup{
			Matcher: ev.matcher,
			Hooks: []hookRef{{
				Type:    "command",
				Command: binary,
				Args:    hookInvocationArgs(ev.lifecycle, AgentClaude, runtimeArgs, enforce && ev.settingsKey == "PreToolUse"),
				Timeout: ev.timeout,
			}},
		})
		sf.hooks[ev.settingsKey] = groups
	}
}

// removeNumbatHooks strips every numbat-installed hook, dropping now-empty
// groups and now-empty event keys, and reports whether anything changed.
func (sf settingsFile) removeNumbatHooks() bool {
	changed := false
	for key, groups := range sf.hooks {
		kept := make([]hookGroup, 0, len(groups))
		for _, g := range groups {
			filtered := g.Hooks[:0:0]
			for _, h := range g.Hooks {
				if isNumbatHookRef(h) {
					changed = true
					continue
				}
				filtered = append(filtered, h)
			}
			if len(filtered) == 0 {
				continue
			}
			g.Hooks = filtered
			kept = append(kept, g)
		}
		if len(kept) == 0 {
			delete(sf.hooks, key)
		} else {
			sf.hooks[key] = kept
		}
	}
	return changed
}

// stripNumbatGroups drops groups that consist solely of numbat hooks and removes
// numbat hooks from mixed groups, so applyNumbatHooks never leaves a stale
// duplicate behind.
func stripNumbatGroups(groups []hookGroup) []hookGroup {
	out := make([]hookGroup, 0, len(groups))
	for _, g := range groups {
		filtered := g.Hooks[:0:0]
		for _, h := range g.Hooks {
			if isNumbatHookRef(h) {
				continue
			}
			filtered = append(filtered, h)
		}
		if len(filtered) == 0 {
			continue
		}
		g.Hooks = filtered
		out = append(out, g)
	}
	return out
}

func hasNumbatGroup(groups []hookGroup) bool {
	for _, group := range groups {
		for _, ref := range group.Hooks {
			if isNumbatHookRef(ref) {
				return true
			}
		}
	}
	return false
}

// ClaudeSettingsPath returns the user-level Claude settings.json path under
// home. It is the install target unless a caller overrides it.
func ClaudeSettingsPath(home string) string {
	root := os.Getenv("CLAUDE_CONFIG_DIR")
	if root == "" {
		root = filepath.Join(home, ".claude")
	}
	return filepath.Join(root, "settings.json")
}

// DefaultFindingsPath returns the default durable findings destination wired
// into installed hooks: a single NDJSON file under numbat's own state directory
// (~/.numbat), mirroring the .numbat-bak naming the installer already uses. The
// live handler appends findings here so a hook-detected finding survives instead
// of being dropped to stderr.
func DefaultFindingsPath(home string) string {
	return filepath.Join(home, ".numbat", "findings.ndjson")
}

// DefaultRecordsPath is used when installed hooks emit events or indicators in
// addition to findings.
func DefaultRecordsPath(home string) string {
	return filepath.Join(home, ".numbat", "records.ndjson")
}

// DefaultFindingsSpoolPath is the transactional queue used by hook installs
// that select spool output and emit only findings.
func DefaultFindingsSpoolPath(home string) string {
	return filepath.Join(home, ".numbat", "findings.spool")
}

// DefaultRecordsSpoolPath is used when a spool hook also emits events or
// indicators.
func DefaultRecordsSpoolPath(home string) string {
	return filepath.Join(home, ".numbat", "records.spool")
}

// InstallOptions are the runtime flags baked into commands written by Install.
// RuntimeArgs are appended to every installed `numbat hook <event>` invocation
// after the agent marker. Claude receives an argument array; string-only hook
// schemas receive a quoted POSIX command or an encoded PowerShell invocation;
// OpenCode receives JSON-encoded plugin arguments. Enforce controls whether
// --enforce is threaded into agents that support blocking.
type InstallOptions struct {
	RuntimeArgs []string
	Enforce     bool
}

func installMessage(enforce bool) string {
	if enforce {
		return "installed numbat hooks (enforce mode: blocks matches from rules marked enforce=true)"
	}
	return "installed numbat hooks"
}

func samePlatformPath(a, b string) bool {
	return samePlatformPathForOS(a, b, runtime.GOOS)
}

func samePlatformPathForOS(a, b, goos string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Install wires numbat's hook entries into the agent's settings at path, using
// binary as the absolute numbat command. outputFile, when non-empty, is wired as
// the durable findings destination (--output=file) so findings are not lost to
// stderr at runtime; pass "" to leave output unset. It is idempotent and backs
// the pristine file up before the first write. An unsupported agent returns a
// report with Supported=false and makes no change.
func Install(agent, path, binary, outputFile string, enforce bool) (InstallReport, error) {
	return InstallWithOptions(agent, path, binary, InstallOptions{
		RuntimeArgs: outputFileArgs(outputFile),
		Enforce:     enforce,
	})
}

// InstallWithOptions lets the CLI bake validated runtime flags (for example
// --emit, output sinks, or --output-file) into the installed hook command.
func InstallWithOptions(agent, path, binary string, opts InstallOptions) (InstallReport, error) {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsHooks(agent)}
	if !rep.Supported {
		rep.Message = unsupportedMessage(agent)
		return rep, nil
	}
	if opts.Enforce && !AgentSupportsEnforcement(agent) {
		return rep, fmt.Errorf("--enforce is supported for %s; %s is observe-only", EnforceAgentUsage(), agent)
	}
	if agent == AgentCursor {
		return installCursorWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentWindsurf {
		return installWindsurfWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentCopilot {
		return installCopilotWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentVSCode {
		return installVSCodeWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentCodex {
		return installCodexWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentGemini {
		return installGeminiWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentOpenCode {
		return installOpenCodeWithArgs(path, binary, opts.RuntimeArgs)
	}
	if agent == AgentOpenClaw {
		return installOpenClawWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentAntigravity {
		return installAntigravityWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentFactory {
		return installFactoryWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentGrok {
		return installGrokWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentDevin {
		return installDevinWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentHermes {
		return installHermesWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentPi {
		return installPiWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentKimi {
		return installKimiWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentQwen {
		return installQwenWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentCline {
		return installClineWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentAmp {
		return installAmpWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentAuggie {
		return installAuggieWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentKiro {
		return installKiroWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentGoose {
		return installGooseWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentKilo {
		return installKiloWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentOpenHands {
		return installOpenHandsWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentCrush {
		return installCrushWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	if agent == AgentJunie {
		return installJunieWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	sf.applyNumbatHooksWithArgs(binary, opts.RuntimeArgs, opts.Enforce)
	if err := writeSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Installed = true
	rep.Changed = true
	if opts.Enforce {
		rep.Message = "installed numbat hooks (enforce mode: blocks matches from rules marked enforce=true)"
	} else {
		rep.Message = "installed numbat hooks"
	}
	return rep, nil
}

// InstallManagedWithOptions wires numbat into an agent's admin-managed hook
// layer. Only agents with a documented managed hook format are supported.
func InstallManagedWithOptions(agent, path, binary string, opts InstallOptions) (InstallReport, error) {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsManagedHooks(agent)}
	if !rep.Supported {
		rep.Message = fmt.Sprintf("managed hooks are supported for %s; %s has no numbat-managed target", ManagedAgentUsage(), agent)
		return rep, nil
	}
	if opts.Enforce && !AgentSupportsEnforcement(agent) {
		return rep, fmt.Errorf("--enforce is supported for %s; %s is observe-only", EnforceAgentUsage(), agent)
	}
	switch agent {
	case AgentClaude:
		return installClaudeManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentCodex:
		return installCodexRequirementsWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentCursor:
		return installCursorManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentCopilot:
		return installCopilotManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentGemini:
		return installGeminiManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentWindsurf:
		return installWindsurfManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentQwen:
		return installQwenManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	case AgentAuggie:
		return installAuggieManagedWithArgs(path, binary, opts.RuntimeArgs, opts.Enforce)
	default:
		return rep, nil
	}
}

// Uninstall removes only numbat's hook entries from the agent's settings,
// leaving every other key and hook intact. A missing file or absent numbat
// entries is a no-op (Changed=false).
func Uninstall(agent, path string) (InstallReport, error) {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsHooks(agent)}
	if !rep.Supported {
		rep.Message = unsupportedMessage(agent)
		return rep, nil
	}
	if agent == AgentCursor {
		return uninstallCursor(path)
	}
	if agent == AgentWindsurf {
		return uninstallWindsurf(path)
	}
	if agent == AgentCopilot {
		return uninstallCopilot(path)
	}
	if agent == AgentVSCode {
		return uninstallVSCode(path)
	}
	if agent == AgentCodex {
		return uninstallCodex(path)
	}
	if agent == AgentGemini {
		return uninstallGemini(path)
	}
	if agent == AgentOpenCode {
		return uninstallOpenCode(path)
	}
	if agent == AgentOpenClaw {
		return uninstallOpenClaw(path)
	}
	if agent == AgentAntigravity {
		return uninstallAntigravity(path)
	}
	if agent == AgentFactory {
		return uninstallFactory(path)
	}
	if agent == AgentGrok {
		return uninstallGrok(path)
	}
	if agent == AgentDevin {
		return uninstallDevin(path)
	}
	if agent == AgentHermes {
		return uninstallHermes(path)
	}
	if agent == AgentPi {
		return uninstallPi(path)
	}
	if agent == AgentKimi {
		return uninstallKimi(path)
	}
	if agent == AgentQwen {
		return uninstallQwen(path)
	}
	if agent == AgentCline {
		return uninstallCline(path)
	}
	if agent == AgentAmp {
		return uninstallAmp(path)
	}
	if agent == AgentAuggie {
		return uninstallAuggie(path)
	}
	if agent == AgentKiro {
		return uninstallKiro(path)
	}
	if agent == AgentGoose {
		return uninstallGoose(path)
	}
	if agent == AgentKilo {
		return uninstallKilo(path)
	}
	if agent == AgentOpenHands {
		return uninstallOpenHands(path)
	}
	if agent == AgentCrush {
		return uninstallCrush(path)
	}
	if agent == AgentJunie {
		return uninstallJunie(path)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		rep.Message = "no settings file; nothing to remove"
		return rep, nil
	}
	sf, err := readSettings(path)
	if err != nil {
		return rep, err
	}
	if !sf.removeNumbatHooks() {
		rep.Message = "no numbat hooks present"
		return rep, nil
	}
	backup, err := backupIfExists(path)
	if err != nil {
		return rep, err
	}
	rep.BackupPath = backup
	if err := writeSettings(path, sf); err != nil {
		return rep, err
	}
	rep.Changed = true
	rep.Message = "removed numbat hooks"
	return rep, nil
}

// UninstallManaged removes numbat entries from an agent's admin-managed hook
// layer without touching unrelated policy.
func UninstallManaged(agent, path string) (InstallReport, error) {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsManagedHooks(agent)}
	if !rep.Supported {
		rep.Message = fmt.Sprintf("managed hooks are supported for %s; %s has no numbat-managed target", ManagedAgentUsage(), agent)
		return rep, nil
	}
	switch agent {
	case AgentClaude:
		return uninstallClaudeManaged(path)
	case AgentCodex:
		return uninstallCodexRequirements(path)
	case AgentCursor:
		return uninstallCursorManaged(path)
	case AgentCopilot:
		return uninstallCopilotManaged(path)
	case AgentGemini:
		return uninstallGeminiManaged(path)
	case AgentWindsurf:
		return uninstallWindsurfManaged(path)
	case AgentQwen:
		return uninstallQwenManaged(path)
	case AgentAuggie:
		return uninstallAuggieManaged(path)
	default:
		return rep, nil
	}
}

// Status reports whether numbat hooks are present in the agent's settings,
// without modifying anything.
func Status(agent, path string) InstallReport {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsHooks(agent)}
	if !rep.Supported {
		rep.Message = unsupportedMessage(agent)
		return rep
	}
	if agent == AgentCursor {
		return statusCursor(path)
	}
	if agent == AgentWindsurf {
		return statusWindsurf(path)
	}
	if agent == AgentCopilot {
		return statusCopilot(path)
	}
	if agent == AgentVSCode {
		return statusVSCode(path)
	}
	if agent == AgentCodex {
		return statusCodex(path)
	}
	if agent == AgentGemini {
		return statusGemini(path)
	}
	if agent == AgentOpenCode {
		return statusOpenCode(path)
	}
	if agent == AgentOpenClaw {
		return statusOpenClaw(path)
	}
	if agent == AgentAntigravity {
		return statusAntigravity(path)
	}
	if agent == AgentFactory {
		return statusFactory(path)
	}
	if agent == AgentGrok {
		return statusGrok(path)
	}
	if agent == AgentDevin {
		return statusDevin(path)
	}
	if agent == AgentHermes {
		return statusHermes(path)
	}
	if agent == AgentPi {
		return statusPi(path)
	}
	if agent == AgentKimi {
		return statusKimi(path)
	}
	if agent == AgentQwen {
		return statusQwen(path)
	}
	if agent == AgentCline {
		return statusCline(path)
	}
	if agent == AgentAmp {
		return statusAmp(path)
	}
	if agent == AgentAuggie {
		return statusAuggie(path)
	}
	if agent == AgentKiro {
		return statusKiro(path)
	}
	if agent == AgentGoose {
		return statusGoose(path)
	}
	if agent == AgentKilo {
		return statusKilo(path)
	}
	if agent == AgentOpenHands {
		return statusOpenHands(path)
	}
	if agent == AgentCrush {
		return statusCrush(path)
	}
	if agent == AgentJunie {
		return statusJunie(path)
	}
	sf, err := readSettings(path)
	if err != nil {
		rep.Message = err.Error()
		return rep
	}
	rep.Installed = sf.hasNumbatHooks()
	if rep.Installed {
		rep.Message = "numbat hooks installed"
	} else {
		rep.Message = "numbat hooks not installed"
	}
	return rep
}

// StatusErr distinguishes a verified absence from unreadable or malformed
// config. Missing files and unsupported agents are not errors.
func StatusErr(agent, path string) (InstallReport, error) {
	rep := Status(agent, path)
	if !rep.Supported {
		return rep, nil
	}
	if err := configReadable(agent, path); err != nil {
		return rep, err
	}
	return rep, nil
}

// StatusManagedErr reports whether numbat entries are present in an
// admin-managed hook layer.
func StatusManagedErr(agent, path string) (InstallReport, error) {
	rep := InstallReport{Agent: agent, SettingsPath: path, Supported: AgentSupportsManagedHooks(agent)}
	if !rep.Supported {
		rep.Message = fmt.Sprintf("managed hooks are supported for %s; %s has no numbat-managed target", ManagedAgentUsage(), agent)
		return rep, nil
	}
	switch agent {
	case AgentClaude:
		return statusClaudeManagedErr(path)
	case AgentCodex:
		return statusCodexRequirements(path)
	case AgentCursor, AgentCopilot, AgentGemini, AgentWindsurf, AgentQwen, AgentAuggie:
		rep = Status(agent, path)
		if err := configReadable(agent, path); err != nil {
			return rep, err
		}
		if rep.Installed {
			rep.Message = "numbat managed hooks installed"
		} else {
			rep.Message = "numbat managed hooks not installed"
		}
		return rep, nil
	default:
		return rep, nil
	}
}

// configReadable parses each agent's config format. Missing files are valid.
func configReadable(agent, path string) error {
	switch agent {
	case AgentClaude, AgentCodex:
		_, err := readSettings(path)
		return err
	case AgentFactory:
		return configReadableFactory(path)
	case AgentCursor, AgentCopilot:
		_, err := readCursorSettings(path)
		return err
	case AgentVSCode:
		_, err := readCursorSettings(path)
		return err
	case AgentWindsurf:
		_, err := readWindsurfSettings(path)
		return err
	case AgentGemini:
		_, err := readGeminiSettings(path)
		return err
	case AgentOpenCode:
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s: plugin path is a directory", path)
		}
		_, err = readHookConfigFile(path)
		return err
	case AgentOpenClaw:
		return configReadableOpenClaw(path)
	case AgentAntigravity:
		_, err := readAntigravityFile(path)
		return err
	case AgentGrok:
		_, err := readGrokFile(path)
		return err
	case AgentDevin:
		_, err := readDevinFile(path)
		return err
	case AgentHermes:
		_, err := readHermesFile(path)
		return err
	case AgentPi, AgentAmp:
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s: plugin path is a directory", path)
		}
		_, err = readHookConfigFile(path)
		return err
	case AgentKimi:
		body, err := readOptionalText(path)
		if err != nil {
			return err
		}
		_, err = kimiConfigWithoutNumbat(body)
		return err
	case AgentQwen:
		_, err := readGeminiSettings(path)
		return err
	case AgentCline:
		return configReadableCline(path)
	case AgentAuggie:
		return configReadableAuggie(path)
	case AgentKiro:
		_, err := readKiroHookFile(path)
		return err
	case AgentGoose:
		return configReadableGoose(path)
	case AgentKilo:
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s: Kilo plugin path is a directory", path)
		}
		_, err = readHookConfigFile(path)
		return err
	case AgentOpenHands:
		if err := validateOpenHandsPath(path); err != nil {
			return err
		}
		_, err := readSettings(path)
		return err
	case AgentCrush:
		_, err := readCrushFile(path)
		return err
	case AgentJunie:
		_, err := readSettings(path)
		return err
	default:
		return nil
	}
}

func unsupportedMessage(agent string) string {
	return fmt.Sprintf("unknown agent %q", agent)
}

// writeSettings writes user config atomically (0600 on Unix; inherited ACL on
// Windows).
func writeSettings(path string, sf settingsFile) error {
	data, err := sf.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func writeManagedSettings(path string, sf settingsFile) error {
	data, err := sf.marshal()
	if err != nil {
		return err
	}
	return writeManagedFileAtomic(path, data)
}

// writeFileAtomic writes user config through a same-directory temp file.
func writeFileAtomic(path string, data []byte) error {
	return writeFileAtomicMode(path, data, 0o600, 0o700)
}

// writeManagedFileAtomic writes admin-managed config in a form readable by the
// user-level agent process but still owned/deployed by the administrator.
func writeManagedFileAtomic(path string, data []byte) error {
	return writeFileAtomicMode(path, data, 0o644, 0o755)
}

func writeHookConfig(path string, data []byte, managed bool) error {
	if managed {
		return writeManagedFileAtomic(path, data)
	}
	return writeFileAtomic(path, data)
}

func writeFileAtomicMode(path string, data []byte, fileMode, dirMode os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".numbat-settings-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, fileMode); err != nil {
		return err
	}
	return replaceFile(tmpName, path)
}

// backupSuffix is the fixed sibling suffix for the pristine pre-numbat backup.
const backupSuffix = ".numbat-bak"

// backupIfExists preserves the first pre-numbat version in a fixed sibling file.
// O_EXCL prevents concurrent installers from replacing that pristine backup.
func backupIfExists(path string) (string, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	backup := path + backupSuffix
	if info, statErr := os.Lstat(backup); statErr == nil {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("existing hook backup %s is not a regular file", backup)
		}
		return backup, nil
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect hook backup %s: %w", backup, statErr)
	}
	// If numbat created the target from scratch, a later reinstall must not
	// manufacture a "pristine" backup from the already-modified file.
	if isNumbatHookCommand(string(data)) {
		return "", nil
	}
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(backup)
		if statErr != nil {
			return "", fmt.Errorf("inspect existing hook backup %s: %w", backup, statErr)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("existing hook backup %s is not a regular file", backup)
		}
		return backup, nil
	}
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(backup)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(backup)
		return "", err
	}
	return backup, nil
}

func readHookConfigFile(path string) ([]byte, error) {
	f, err := openHookConfig(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxHookConfigFileSize+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > maxHookConfigFileSize {
		return nil, fmt.Errorf("read %s: hook config exceeds %d bytes", path, maxHookConfigFileSize)
	}
	return data, nil
}

// textHookFileOwnership distinguishes a missing generated file from a readable
// foreign file and from a file that could not be inspected. Callers that remove
// owned files must not collapse the last case into "not owned": doing so can
// turn permission, symlink, or non-regular-file failures into a false success.
func textHookFileOwnership(path string, markers ...string) (exists, owned bool, err error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}
	for _, marker := range markers {
		if !strings.Contains(string(data), marker) {
			return true, false, nil
		}
	}
	return true, true, nil
}

// LifecycleArgs returns the lifecycle argument names numbat wires for Claude,
// sorted, for diagnostics and tests.
func LifecycleArgs() []string {
	out := make([]string, 0, len(claudeHookEvents))
	for _, ev := range claudeHookEvents {
		out = append(out, ev.lifecycle)
	}
	sort.Strings(out)
	return out
}
