package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/output"
)

// runHookAdmin handles `numbat hook install|uninstall|status [--agent ...]`. It
// wires numbat's live hook handler into each requested agent's hook integration
// (settings/command hooks, standalone hook files, or generated plugins and
// extensions). Every action is idempotent; shared settings are backed up before
// writing and standalone targets use explicit ownership markers.
func runHookAdmin(action string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	agentUsage := "all|" + hook.AgentUsage()
	agentHelp := "agent to target: " + agentUsage + " (required; use all explicitly)"
	if action == "status" {
		agentHelp = "agent to inspect: " + agentUsage + " (default: all)"
	}
	agentFlag := fs.String("agent", "", agentHelp)
	settingsPath := fs.String("settings", "", "override the install-target path for one agent")
	managedTarget := fs.Bool("managed", false, "target the agent's admin-managed hook config ("+hook.ManagedAgentUsage()+"; requires --agent)")
	// --enforce opts this install into numbat's enforcement path: the installed
	// hook command carries the runtime enforce signal, so a positive
	// explicitly enforceable rule match emits a block. Off by default; without
	// it numbat stays strictly detection-only and passthrough-safe. Meaningful only
	// for install; ignored by uninstall/status (which key on the numbat marker).
	var (
		enforce           bool
		emitValues        multiFlag
		contentValue      = "preview"
		includeReasoning  bool
		outputValues      multiFlag
		outputFileValue   string
		httpURL           string
		httpBatch         = 500
		httpTimeout       = defaultHookHTTPTimeout
		httpAuth          = output.AuthNone
		httpSigHeader     = output.DefaultHMACHeader
		httpTSHeader      = output.DefaultTimestampHeader
		httpAllowInsecure bool
		httpGzip          bool
		ruleDirs          multiFlag
		noBuiltinRules    bool
	)
	if action == "install" {
		fs.BoolVar(&enforce, "enforce", false, "install in enforce mode for agents with blocking support: deny supported pre-action requests when a rule marked enforce=true matches; requires an enabled enforce=true rule in the effective catalog (default: monitor only)")
		fs.Var(&emitValues, "emit", "records emitted by live integrations: findings, events, indicators, or all (repeatable; default findings; enforce mode requires findings)")
		fs.StringVar(&contentValue, "content", "preview", contentFlagHelp())
		fs.BoolVar(&includeReasoning, "include-reasoning", false, "include source-recorded reasoning events when an integration exposes them")
		fs.Var(&outputValues, "output", outputFlagHelp(outputModeFile)+"; stdout mode writes records to hook stderr and is unavailable in enforce mode")
		fs.StringVar(&outputFileValue, "output-file", "", "destination path when --output includes file (default findings.ndjson, or records.ndjson when --emit includes events/indicators)")
		fs.StringVar(&httpURL, "http-url", "", "ingest URL (required when --output includes http)")
		fs.IntVar(&httpBatch, "http-batch-size", 500, "records per HTTP POST")
		fs.DurationVar(&httpTimeout, "http-timeout", defaultHookHTTPTimeout, "HTTP request timeout")
		fs.StringVar(&httpAuth, "http-auth", output.AuthNone, "HTTP delivery auth: none|bearer|hmac-sha256")
		fs.StringVar(&httpSigHeader, "http-sig-header", output.DefaultHMACHeader, "header carrying the hmac-sha256 signature")
		fs.StringVar(&httpTSHeader, "http-timestamp-header", output.DefaultTimestampHeader, "header carrying the signed timestamp")
		fs.BoolVar(&httpAllowInsecure, "http-allow-insecure", false, "allow plain http to non-loopback hosts")
		fs.BoolVar(&httpGzip, "http-gzip", false, "gzip the HTTP POST body")
		fs.Var(&ruleDirs, "rules-dir", "directory of operator YAML rules to add or replace by id in installed live integrations (repeatable)")
		fs.BoolVar(&noBuiltinRules, "no-builtin-rules", false, "install live integrations with only --rules-dir rules")
	}
	fs.Usage = func() {
		agentArg := "--agent NAME|all"
		if action == "status" {
			agentArg = "[" + agentArg + "]"
		}
		fmt.Fprintf(stderr, "usage: numbat hook %s %s [--settings PATH] [--managed]", action, agentArg)
		if action == "install" {
			fmt.Fprint(stderr, " [--emit KIND ...] [--content preview|full] [--include-reasoning] [--output SINK ...] [--rules-dir DIR ...] [--no-builtin-rules] [--enforce]")
		}
		fmt.Fprintln(stderr)
		switch action {
		case "install":
			fmt.Fprintln(stderr, "\nInstalls numbat's live integrations in monitor-only mode by default.")
			fmt.Fprintln(stderr, "Trust, enablement, and restart requirements vary by agent; see")
			fmt.Fprintln(stderr, "docs/deployment.md#hook-trust-and-activation.")
			printHTTPAuthEnvHelp(stderr, true)
		case "uninstall":
			fmt.Fprintln(stderr, "\nRemoves only numbat-owned integration configuration.")
		case "status":
			fmt.Fprintln(stderr, "\nInspects numbat-owned integration configuration; it does not verify agent trust,")
			fmt.Fprintln(stderr, "activation, execution, or record delivery.")
		}
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "hook %s: unexpected argument %q\n", action, fs.Arg(0))
		return 2
	}

	if *settingsPath != "" && *agentFlag == "" {
		fmt.Fprintf(stderr, "hook %s: --settings requires --agent (it names one file, but multiple agents use incompatible hook schemas)\n", action)
		return 2
	}
	if *managedTarget && *agentFlag == "" {
		fmt.Fprintf(stderr, "hook %s: --managed requires --agent (managed paths are agent-specific)\n", action)
		return 2
	}
	if *agentFlag == "" && action != "status" {
		fmt.Fprintf(stderr, "hook %s: --agent is required (name one agent, or use --agent all explicitly)\n", action)
		return 2
	}

	agents, err := targetAgents(*agentFlag)
	if err != nil {
		fmt.Fprintf(stderr, "hook %s: %v\n", action, err)
		return 2
	}
	if *settingsPath != "" && len(agents) != 1 {
		fmt.Fprintf(stderr, "hook %s: --settings requires one agent; --agent all is not valid\n", action)
		return 2
	}
	if containsHookAgent(agents, hook.AgentOpenHands) && *settingsPath == "" {
		fmt.Fprintf(stderr, "hook %s: openhands is repository-scoped and requires --settings /path/to/repo/.openhands/hooks.json\n", action)
		return 2
	}
	if *managedTarget && len(agents) != 1 {
		fmt.Fprintf(stderr, "hook %s: --managed requires one agent; --agent all is not valid\n", action)
		return 2
	}
	if enforce && len(agents) != 1 {
		fmt.Fprintln(stderr, "hook install: --enforce requires one agent; --agent all is not valid")
		return 2
	}
	if enforce && !hook.AgentSupportsEnforcement(agents[0]) {
		fmt.Fprintf(stderr, "hook install: --enforce is supported for %s; %s is observe-only\n", hook.EnforceAgentUsage(), agents[0])
		return 2
	}
	if *managedTarget {
		for _, agent := range agents {
			if !hook.AgentSupportsManagedHooks(agent) {
				fmt.Fprintf(stderr, "hook %s: --managed supports %s; %s has no numbat-managed target\n", action, hook.ManagedAgentUsage(), agent)
				return 2
			}
		}
	}

	var binary string
	if action == "install" {
		binary, err = numbatBinaryPath()
		if err != nil {
			fmt.Fprintf(stderr, "hook %s: %v\n", action, err)
			return 1
		}
	}
	var home string
	if !*managedTarget && (action == "install" || *settingsPath == "") {
		home, err = os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "hook %s: %v\n", action, err)
			return 1
		}
	}
	if action == "install" && *settingsPath == "" && containsHookAgent(agents, hook.AgentOpenClaw) {
		if current, legacy, conflict := openClawLegacyStateConflict(home); conflict {
			fmt.Fprintf(stderr, "hook install: openclaw: legacy state exists at %s, but the native global plugin loader targets %s; refusing to create the new root because it can change future state selection (migrate the Gateway, set OPENCLAW_STATE_DIR explicitly, or use --settings with a matching plugins.load.paths entry)\n", legacy, current)
			return 2
		}
	}
	var installOpts hook.InstallOptions
	if action == "install" {
		content, parseErr := parseContentMode(contentValue)
		if parseErr != nil {
			fmt.Fprintf(stderr, "hook install: %v\n", parseErr)
			return 2
		}
		args, err := installRuntimeArgs(installRuntimeConfig{
			emit:             emitValues,
			content:          content,
			includeReasoning: includeReasoning,
			modes:            outputValues,
			file:             outputFileValue,
			httpURL:          httpURL,
			httpBatch:        httpBatch,
			httpTimeout:      httpTimeout,
			httpAuth:         httpAuth,
			httpSigHeader:    httpSigHeader,
			httpTSHeader:     httpTSHeader,
			allowInsecure:    httpAllowInsecure,
			gzip:             httpGzip,
			ruleDirs:         ruleDirs,
			noBuiltin:        noBuiltinRules,
			enforce:          enforce,
			managed:          *managedTarget,
			visitFlags:       fs,
		}, home)
		if err != nil {
			fmt.Fprintf(stderr, "hook install: %v\n", err)
			return 2
		}
		installOpts = hook.InstallOptions{RuntimeArgs: args, Enforce: enforce}
	}

	exit := 0
	for _, agent := range agents {
		path := *settingsPath
		if path == "" {
			if *managedTarget {
				var ok bool
				path, ok = hook.ManagedHooksPath(agent)
				if !ok {
					fmt.Fprintf(stderr, "hook %s: --managed supports %s; %s has no numbat-managed target\n", action, hook.ManagedAgentUsage(), agent)
					exit = 2
					continue
				}
			} else {
				path = settingsPathFor(agent, home)
			}
		}
		rep, err := runHookAction(action, agent, path, binary, installOpts, *managedTarget)
		if err != nil {
			fmt.Fprintf(stderr, "hook %s: %s: %v\n", action, agent, err)
			exit = 1
			continue
		}
		printHookReport(stdout, action, rep)
	}
	return exit
}

// openClawLegacyStateConflict detects the one default-install case where
// writing the native package can change subsequent OpenClaw state discovery.
// Session discovery retains the historical .clawdbot fallback, but the global
// plugin loader always targets the active config root and defaults to
// .openclaw. An explicit state/config path is an operator choice and therefore
// bypasses this ambiguity check. OPENCLAW_PROFILE alone is not a path selector
// in OpenClaw and deliberately does not bypass the check.
func openClawLegacyStateConflict(home string) (current, legacy string, conflict bool) {
	if strings.TrimSpace(os.Getenv("OPENCLAW_STATE_DIR")) != "" ||
		strings.TrimSpace(os.Getenv("OPENCLAW_CONFIG_PATH")) != "" {
		return "", "", false
	}
	plugin := hook.OpenClawPluginPath(home)
	current = filepath.Dir(filepath.Dir(plugin))
	legacy = filepath.Join(filepath.Dir(current), ".clawdbot")
	if _, err := os.Stat(current); err == nil || !errors.Is(err, os.ErrNotExist) {
		return current, legacy, false
	}
	info, err := os.Stat(legacy)
	return current, legacy, err == nil && info.IsDir()
}

// runHookAction dispatches one agent through the requested install action.
// installOpts are meaningful only for install; uninstall/status ignore them.
func runHookAction(action, agent, path, binary string, installOpts hook.InstallOptions, managed bool) (hook.InstallReport, error) {
	switch action {
	case "install":
		if managed {
			return hook.InstallManagedWithOptions(agent, path, binary, installOpts)
		}
		return hook.InstallWithOptions(agent, path, binary, installOpts)
	case "uninstall":
		if managed {
			return hook.UninstallManaged(agent, path)
		}
		return hook.Uninstall(agent, path)
	case "status":
		if managed {
			return hook.StatusManagedErr(agent, path)
		}
		return hook.StatusErr(agent, path)
	default:
		return hook.InstallReport{}, fmt.Errorf("unknown action %q", action)
	}
}

type installRuntimeConfig struct {
	emit             []string
	content          contentMode
	includeReasoning bool
	modes            []string
	file             string
	httpURL          string
	httpBatch        int
	httpTimeout      time.Duration
	httpAuth         string
	httpSigHeader    string
	httpTSHeader     string
	allowInsecure    bool
	gzip             bool
	ruleDirs         []string
	noBuiltin        bool
	enforce          bool
	managed          bool
	visitFlags       *flag.FlagSet
}

func installRuntimeArgs(cfg installRuntimeConfig, home string) ([]string, error) {
	emitSel, err := parseEmit(cfg.emit)
	if err != nil {
		return nil, err
	}
	if err := validateContentSelection(cfg.content, emitSel); err != nil {
		return nil, err
	}
	sinks, err := parseOutputSinks(cfg.modes, outputModeFile)
	if err != nil {
		return nil, err
	}
	if err := validateEnforceIO(cfg.enforce, emitSel, sinks); err != nil {
		return nil, err
	}

	set := map[string]bool{}
	if cfg.visitFlags != nil {
		cfg.visitFlags.Visit(func(f *flag.Flag) {
			set[f.Name] = true
		})
	}
	args := []string{}
	if cfg.noBuiltin && len(cfg.ruleDirs) == 0 {
		return nil, fmt.Errorf("--no-builtin-rules requires at least one --rules-dir")
	}
	resolvedRuleDirs := make([]string, 0, len(cfg.ruleDirs))
	for _, raw := range cfg.ruleDirs {
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("--rules-dir must not be empty")
		}
		dir := raw
		// Hook commands run from the agent's working directory, which may differ
		// from the installer's. Resolve relative rule directories now so installed
		// hooks keep loading the intended files.
		if !filepath.IsAbs(dir) && !runtimeExpandedPath(dir) {
			dir, err = filepath.Abs(dir)
			if err != nil {
				return nil, fmt.Errorf("resolve --rules-dir %q: %w", raw, err)
			}
		}
		resolvedRuleDirs = append(resolvedRuleDirs, dir)
		args = append(args, "--rules-dir", dir)
	}
	if cfg.enforce {
		if err := validateInstallEnforcementPolicy(resolvedRuleDirs, cfg.noBuiltin); err != nil {
			return nil, err
		}
	}
	if cfg.noBuiltin {
		args = append(args, "--no-builtin-rules")
	}
	if !emitSel.defaultFindingsOnly() {
		for _, mode := range emitSel.canonicalModes() {
			args = append(args, "--emit", mode)
		}
	}
	if cfg.content == contentFull {
		args = append(args, "--content=full")
	}
	if cfg.includeReasoning {
		args = append(args, "--include-reasoning")
	}
	if !sinks.http {
		for _, name := range httpOnlyInstallFlagNames() {
			if set[name] {
				return nil, fmt.Errorf("--%s is only valid when --output includes http", name)
			}
		}
	}
	if !sinks.file && cfg.file != "" {
		return nil, fmt.Errorf("--output-file is only valid when --output includes file")
	}
	if !sinks.http && cfg.httpURL != "" {
		return nil, fmt.Errorf("--http-url is only valid when --output includes http")
	}

	if sinks.stdout {
		if cfg.file != "" {
			return nil, fmt.Errorf("--output-file is only valid when --output includes file")
		}
		if cfg.httpURL != "" {
			return nil, fmt.Errorf("--http-url is only valid when --output includes http")
		}
		return append(args, "--output=stdout"), nil
	}

	for _, mode := range sinks.canonicalModes() {
		args = append(args, "--output="+mode)
	}
	if sinks.file {
		if set["output-file"] && strings.TrimSpace(cfg.file) == "" {
			return nil, fmt.Errorf("--output-file must not be empty")
		}
		file := cfg.file
		if file == "" {
			findingsOnly := emitSel.defaultFindingsOnly()
			if cfg.managed && findingsOnly {
				file = "$HOME/.numbat/findings.ndjson"
			} else if cfg.managed {
				file = "$HOME/.numbat/records.ndjson"
			} else if findingsOnly {
				file = hook.DefaultFindingsPath(home)
			} else {
				file = hook.DefaultRecordsPath(home)
			}
		} else if !filepath.IsAbs(file) && !runtimeExpandedPath(file) {
			file, err = filepath.Abs(file)
			if err != nil {
				return nil, fmt.Errorf("resolve --output-file %q: %w", cfg.file, err)
			}
		}
		args = append(args, "--output-file", file)
	}
	if sinks.http {
		if cfg.httpURL == "" {
			return nil, fmt.Errorf("--output including http requires --http-url URL")
		}
		var authFlags []string
		for _, name := range []string{"http-sig-header", "http-timestamp-header"} {
			if set[name] {
				authFlags = append(authFlags, name)
			}
		}
		if err := validateHTTPAuthFlags(cfg.httpAuth, authFlags); err != nil {
			return nil, err
		}
		if cfg.httpBatch <= 0 {
			return nil, fmt.Errorf("--http-batch-size must be a positive integer, got %d", cfg.httpBatch)
		}
		if cfg.httpTimeout <= 0 {
			return nil, fmt.Errorf("--http-timeout must be a positive duration, got %s", cfg.httpTimeout)
		}
		switch cfg.httpAuth {
		case "", output.AuthNone, output.AuthBearer, output.AuthHMAC:
		default:
			return nil, fmt.Errorf("invalid --http-auth %q: want none|bearer|hmac-sha256", cfg.httpAuth)
		}
		validationAuth := output.HTTPAuth{
			Mode:            cfg.httpAuth,
			HMACHeader:      cfg.httpSigHeader,
			TimestampHeader: cfg.httpTSHeader,
		}
		switch cfg.httpAuth {
		case "", output.AuthNone:
			validationAuth.Mode = output.AuthNone
		case output.AuthBearer:
			validationAuth.Token = "install-time-validation"
		case output.AuthHMAC:
			validationAuth.HMACKey = []byte("install-time-validation")
		}
		if _, err := output.NewHTTPSink(output.HTTPConfig{
			URL:           cfg.httpURL,
			Auth:          validationAuth,
			Timeout:       cfg.httpTimeout,
			BatchSize:     cfg.httpBatch,
			AllowInsecure: cfg.allowInsecure,
		}); err != nil {
			return nil, err
		}
		args = append(args, "--http-url", cfg.httpURL)
		if set["http-auth"] {
			args = append(args, "--http-auth", cfg.httpAuth)
		}
		if set["http-batch-size"] {
			args = append(args, "--http-batch-size", strconv.Itoa(cfg.httpBatch))
		}
		args = append(args, "--http-timeout", cfg.httpTimeout.String())
		if set["http-gzip"] {
			args = append(args, "--http-gzip="+strconv.FormatBool(cfg.gzip))
		}
		if set["http-sig-header"] {
			args = append(args, "--http-sig-header", cfg.httpSigHeader)
		}
		if set["http-timestamp-header"] {
			args = append(args, "--http-timestamp-header", cfg.httpTSHeader)
		}
		if set["http-allow-insecure"] {
			args = append(args, "--http-allow-insecure="+strconv.FormatBool(cfg.allowInsecure))
		}
	}
	return args, nil
}

// validateInstallEnforcementPolicy prevents an enforce-mode hook from being
// installed with no policy capable of blocking. Validation happens before any
// agent configuration is changed and uses the same effective-catalog overlay
// and compile path as the live hook. Deferred paths are rejected because their
// contents cannot be verified in the installer's environment.
func validateInstallEnforcementPolicy(ruleDirs []string, noBuiltin bool) error {
	for _, dir := range ruleDirs {
		if runtimeExpandedPath(dir) {
			return fmt.Errorf("--enforce requires a concrete --rules-dir path that can be validated at install time; got %q", dir)
		}
	}
	eng, err := buildEngine(ruleDirs, noBuiltin)
	if err != nil {
		return fmt.Errorf("validate --enforce rule catalog: %w", err)
	}
	if !eng.HasEnforceEligibleRules() {
		return fmt.Errorf("--enforce requires at least one enabled rule with enforce: true in the effective catalog (supply one with --rules-dir)")
	}
	return nil
}

func runtimeExpandedPath(path string) bool {
	return strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) || strings.Contains(path, "$")
}

func httpOnlyInstallFlagNames() []string {
	return []string{
		"http-allow-insecure",
		"http-auth",
		"http-batch-size",
		"http-gzip",
		"http-sig-header",
		"http-timeout",
		"http-timestamp-header",
	}
}

// targetAgents resolves one agent or the explicit all selector. The caller
// rejects an empty selector for mutating actions; status uses it as all.
func targetAgents(agentFlag string) ([]string, error) {
	if agentFlag == "" || agentFlag == "all" {
		return hook.InstallAgentNames(), nil
	}
	if _, err := hook.ParseAgent(agentFlag); err != nil {
		return nil, err
	}
	return []string{agentFlag}, nil
}

func containsHookAgent(agents []string, want string) bool {
	for _, agent := range agents {
		if agent == want {
			return true
		}
	}
	return false
}

// settingsPathFor returns the per-agent install-target path under home: a settings
// file for the settings-hook agents, or the plugin file for OpenCode (which has no
// settings.json). Codex's path honors the CODEX_HOME override inside CodexSettingsPath;
// Gemini's honors GEMINI_CLI_HOME inside GeminiSettingsPath.
func settingsPathFor(agent, home string) string {
	switch agent {
	case hook.AgentClaude:
		return hook.ClaudeSettingsPath(home)
	case hook.AgentCursor:
		return hook.CursorSettingsPath(home)
	case hook.AgentWindsurf:
		return hook.WindsurfSettingsPath(home)
	case hook.AgentCopilot:
		return hook.CopilotSettingsPath(home)
	case hook.AgentVSCode:
		return hook.VSCodeHooksPath(home)
	case hook.AgentCodex:
		return hook.CodexSettingsPath(home)
	case hook.AgentGemini:
		return hook.GeminiSettingsPath(home)
	case hook.AgentOpenCode:
		// OpenCode uses a plugin file and honors its config-root overrides.
		return hook.OpenCodePluginPath(home)
	case hook.AgentOpenClaw:
		// OpenClaw loads native plugins from its active config root.
		return hook.OpenClawPluginPath(home)
	case hook.AgentAntigravity:
		// Project hooks (<cwd>/.agents/hooks.json) remain available via --settings.
		return hook.AntigravityHooksPath(home)
	case hook.AgentFactory:
		// Project hooks remain reachable through --settings.
		return hook.FactorySettingsPath(home)
	case hook.AgentGrok:
		// Project hooks (<cwd>/.grok/hooks/numbat.json) remain available via --settings.
		return hook.GrokHooksPath(home)
	case hook.AgentDevin:
		// Project .devin/hooks.v1.json files remain reachable through --settings.
		return hook.DevinUserConfigPath(home)
	case hook.AgentHermes:
		// Hermes supports only the active profile's platform-specific config.
		return hook.HermesUserConfigPath(home)
	case hook.AgentPi:
		return hook.PiExtensionPath(home)
	case hook.AgentKimi:
		return hook.KimiConfigPath(home)
	case hook.AgentQwen:
		return hook.QwenSettingsPath(home)
	case hook.AgentCline:
		return hook.ClineHooksPath(home)
	case hook.AgentAmp:
		return hook.AmpPluginPath(home)
	case hook.AgentAuggie:
		return hook.AuggieSettingsPath(home)
	case hook.AgentKiro:
		return hook.KiroHooksPath(home)
	case hook.AgentGoose:
		return hook.GoosePluginPath(home)
	case hook.AgentKilo:
		return hook.KiloPluginPath(home)
	case hook.AgentCrush:
		return hook.CrushConfigPath(home)
	case hook.AgentJunie:
		return hook.JunieConfigPath(home)
	default:
		return ""
	}
}

// numbatBinaryPath returns the absolute path to the running numbat binary, used
// as the hook command so it fires regardless of the agent's PATH or working
// directory.
func numbatBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve numbat binary path: %w", err)
	}
	return exe, nil
}

// printHookReport renders a single agent's outcome as a one-line human summary.
func printHookReport(stdout io.Writer, action string, rep hook.InstallReport) {
	var state string
	switch {
	case !rep.Supported:
		state = "unsupported"
	case action == "status":
		if rep.Installed {
			state = "installed"
		} else {
			state = "not-installed"
		}
	case rep.Changed:
		state = "ok"
	default:
		state = "unchanged"
	}
	line := fmt.Sprintf("%-11s %-13s %s", rep.Agent, state, rep.Message)
	if rep.SettingsPath != "" && rep.Supported {
		line += fmt.Sprintf(" (%s)", rep.SettingsPath)
	}
	if rep.BackupPath != "" {
		line += fmt.Sprintf(" [backup: %s]", rep.BackupPath)
	}
	fmt.Fprintln(stdout, line)
}
