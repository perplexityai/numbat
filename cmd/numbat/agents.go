package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/perplexityai/numbat/internal/discover"
	"github.com/perplexityai/numbat/internal/extract"
	"github.com/perplexityai/numbat/internal/hook"
	"github.com/perplexityai/numbat/internal/model"
)

// agents.go implements `numbat agents`, a read-only inventory report for local
// endpoint AI agents. It checks known config dirs, bounded transcript roots, and
// hook status; it never executes agent binaries or writes config.
//
// agentDescriptors is the report's source of truth. A sync test compares it with
// the parser registry and hook agent list so new support cannot ship without an
// inventory row.

// hook modality strings reported in the "live" column. They are display labels,
// not behavior switches: the actual wiring is read from hook.Status.
const (
	hookModalityHooks    = "hooks"
	hookModalityPlugin   = "plugin"
	hookModalityForensic = "none"
)

// Output format names for --format, mirroring `numbat timeline` so the two
// commands share one convention (text default, json for machine consumers).
const (
	agentsFormatText = "text"
	agentsFormatJSON = "json"
)

var inventoryManagedHooksPath = hook.ManagedHooksPath

// agentDescriptor is the per-agent capability metadata behind the report.
type agentDescriptor struct {
	// enum is the model.Agent* identifier the sync test enumerates.
	enum    string
	display string
	// configDirRel is the home-relative config dir used as the detection signal.
	configDirRel string
	// configDirAlternates are additional product roots that identify the same
	// agent family (for example Antigravity app and CLI state).
	configDirAlternates []string
	// configDirEnv is an optional root override such as CODEX_HOME or XDG_CONFIG_HOME.
	configDirEnv string
	// configRoot resolves platform-specific config locations.
	configRoot func(home string) string
	// configRootAlternates are additional platform-specific roots whose presence
	// identifies the same agent without changing the primary config target.
	configRootAlternates []func(home string) string
	// rootsRel are the bounded home-relative transcript roots numbat parses.
	rootsRel []string
	// roots resolves platform-specific roots that cannot be represented by one
	// home-relative path list.
	roots        func(home string) []string
	hookModality string
	// wiredPath resolves the hook config/plugin path inspected by hook.Status.
	wiredPath func(home string) string
	// wiredPathAlternates are independently active paths for a shared product
	// row. For example, Kiro IDE keeps its default root when KIRO_HOME moves the
	// CLI root.
	wiredPathAlternates []func(home string) string
	// hookAgent is empty for forensic-only agents.
	hookAgent string
	// deferredStore names a known secondary store numbat does not parse yet.
	deferredStore string
	setupHint     string
}

// agentDescriptors is one row per local agent numbat can parse at rest or wire
// through a live hook/plugin surface.
//
// Detection roots and config dirs mirror internal/discover's constants and the
// internal/hook installers' paths; they are restated here (not imported) because
// discover keeps them unexported and the command needs per-agent roots, where
// discover.DefaultRoots returns only the combined set. The sync test guards the
// enum coverage; the per-agent path strings are covered by the temp-HOME tests.
var agentDescriptors = []agentDescriptor{
	{
		enum:         model.AgentClaudeCode,
		display:      "Claude Code",
		configDirRel: ".claude",
		configDirEnv: "CLAUDE_CONFIG_DIR",
		rootsRel:     []string{".claude/projects", ".claude/history.jsonl"},
		hookModality: hookModalityHooks,
		wiredPath:    hook.ClaudeSettingsPath,
		hookAgent:    hook.AgentClaude,
		setupHint:    "install: numbat hook install --agent claude",
	},
	{
		enum:         model.AgentCowork,
		display:      "Claude Cowork",
		configDirRel: "Library/Application Support/Claude/local-agent-mode-sessions",
		roots:        discover.CoworkRootCandidates,
		hookModality: hookModalityForensic,
		setupHint:    "scan only",
	},
	{
		enum:         model.AgentCodex,
		display:      "Codex",
		configDirRel: ".codex",
		configDirEnv: "CODEX_HOME",
		rootsRel:     []string{".codex/sessions", ".codex/archived_sessions", ".codex/history.jsonl"},
		hookModality: hookModalityHooks,
		wiredPath:    hook.CodexSettingsPath,
		hookAgent:    hook.AgentCodex,
		setupHint:    "install: numbat hook install --agent codex",
	},
	{
		enum:         model.AgentGeminiCLI,
		display:      "Gemini CLI",
		configDirRel: ".gemini",
		configDirEnv: "GEMINI_CLI_HOME",
		rootsRel:     []string{".gemini/tmp"},
		hookModality: hookModalityHooks,
		wiredPath:    hook.GeminiSettingsPath,
		hookAgent:    hook.AgentGemini,
		setupHint:    "install: numbat hook install --agent gemini",
	},
	{
		enum:          model.AgentCursor,
		display:       "Cursor",
		configDirRel:  ".cursor",
		rootsRel:      []string{".cursor/projects"},
		hookModality:  hookModalityHooks,
		wiredPath:     hook.CursorSettingsPath,
		hookAgent:     hook.AgentCursor,
		deferredStore: "SQLite",
		setupHint:     "install: numbat hook install --agent cursor",
	},
	{
		enum:         model.AgentWindsurf,
		display:      "Windsurf / Devin Desktop",
		configDirRel: ".windsurf",
		rootsRel:     []string{".windsurf/transcripts"},
		hookModality: hookModalityHooks,
		wiredPath:    hook.WindsurfSettingsPath,
		hookAgent:    hook.AgentWindsurf,
		setupHint:    "install shared Cascade hooks: numbat hook install --agent windsurf",
	},
	{
		enum:          model.AgentCopilot,
		display:       "GitHub Copilot CLI",
		configDirRel:  ".copilot",
		configDirEnv:  "COPILOT_HOME",
		rootsRel:      []string{".copilot/session-state"},
		hookModality:  hookModalityHooks,
		wiredPath:     hook.CopilotSettingsPath,
		hookAgent:     hook.AgentCopilot,
		deferredStore: "SQLite",
		setupHint:     "install: numbat hook install --agent copilot",
	},
	{
		enum:         model.AgentVSCode,
		display:      "VS Code Copilot Chat",
		configDirRel: ".copilot/hooks",
		configDirEnv: "COPILOT_HOME",
		hookModality: hookModalityHooks,
		wiredPath:    hook.VSCodeHooksPath,
		hookAgent:    hook.AgentVSCode,
		setupHint:    "install: numbat hook install --agent vscode",
	},
	{
		enum:          model.AgentOpenCode,
		display:       "OpenCode",
		configDirRel:  ".config/opencode",
		configDirEnv:  "OPENCODE_CONFIG_DIR",
		rootsRel:      []string{".local/share/opencode/storage", ".local/share/opencode/project"},
		hookModality:  hookModalityPlugin,
		wiredPath:     hook.OpenCodePluginPath,
		hookAgent:     hook.AgentOpenCode,
		deferredStore: "SQLite",
		setupHint:     "install: numbat hook install --agent opencode",
	},
	{
		enum:         model.AgentOpenClaw,
		display:      "OpenClaw",
		configDirRel: ".openclaw",
		configRoot:   func(home string) string { return filepath.Dir(filepath.Dir(hook.OpenClawPluginPath(home))) },
		configRootAlternates: []func(home string) string{
			func(home string) string { return filepath.Dir(discover.OpenClawRootCandidates(home)[0]) },
		},
		roots:         discover.OpenClawRootCandidates,
		hookModality:  hookModalityPlugin,
		wiredPath:     hook.OpenClawPluginPath,
		hookAgent:     hook.AgentOpenClaw,
		deferredStore: "SQLite/WAL sessions in the OpenClaw 2026.7.2 beta/development line",
		setupHint:     "install package: numbat hook install --agent openclaw; then pin/allow it, restart, and verify the Gateway",
	},
	{
		enum:         model.AgentPi,
		display:      "Pi",
		configDirRel: ".pi/agent",
		configDirEnv: "PI_CODING_AGENT_DIR",
		roots:        discover.PiRootCandidates,
		hookModality: hookModalityPlugin,
		wiredPath:    hook.PiExtensionPath,
		hookAgent:    hook.AgentPi,
		setupHint:    "install: numbat hook install --agent pi",
	},
	{
		enum:         model.AgentKimiCode,
		display:      "Kimi Code",
		configDirRel: ".kimi-code",
		configDirEnv: "KIMI_CODE_HOME",
		rootsRel:     []string{".kimi-code/sessions"},
		hookModality: hookModalityHooks,
		wiredPath:    hook.KimiConfigPath,
		hookAgent:    hook.AgentKimi,
		setupHint:    "install: numbat hook install --agent kimi",
	},
	{
		enum:          model.AgentQwenCode,
		display:       "Qwen Code",
		configDirRel:  ".qwen",
		configRoot:    func(home string) string { return filepath.Dir(hook.QwenSettingsPath(home)) },
		hookModality:  hookModalityHooks,
		wiredPath:     hook.QwenSettingsPath,
		hookAgent:     hook.AgentQwen,
		deferredStore: "conversation/checkpoint storage",
		setupHint:     "install: numbat hook install --agent qwen (Qwen Code 0.12.0+)",
	},
	{
		enum:          model.AgentCline,
		display:       "Cline CLI",
		configDirRel:  ".cline",
		configRoot:    hook.ClineRootPath,
		hookModality:  hookModalityHooks,
		wiredPath:     hook.ClineHooksPath,
		hookAgent:     hook.AgentCline,
		setupHint:     "install: numbat hook install --agent cline; restart Cline",
		deferredStore: "SQLite sessions",
	},
	{
		enum:          model.AgentAmp,
		display:       "Amp",
		configDirRel:  ".config/amp",
		hookModality:  hookModalityPlugin,
		wiredPath:     hook.AmpPluginPath,
		hookAgent:     hook.AgentAmp,
		deferredStore: "thread/history storage",
		setupHint:     "install: numbat hook install --agent amp; reload Amp plugins",
	},
	{
		enum:          model.AgentAuggie,
		display:       "Auggie",
		configDirRel:  ".augment",
		hookModality:  hookModalityHooks,
		wiredPath:     hook.AuggieSettingsPath,
		hookAgent:     hook.AgentAuggie,
		deferredStore: "session/task storage",
		setupHint:     "install: numbat hook install --agent auggie",
	},
	{
		enum:                model.AgentKiro,
		display:             "Kiro IDE / CLI v3",
		configDirRel:        ".kiro",
		configDirAlternates: []string{".kiro"}, // IDE keeps using the default root when KIRO_HOME moves the CLI root.
		configDirEnv:        "KIRO_HOME",
		hookModality:        hookModalityHooks,
		wiredPath:           hook.KiroHooksPath,
		wiredPathAlternates: []func(string) string{
			func(home string) string { return filepath.Join(home, ".kiro", "hooks", "numbat.json") },
		},
		hookAgent:     hook.AgentKiro,
		deferredStore: "SQLite sessions",
		setupHint:     "install: numbat hook install --agent kiro; with KIRO_HOME, wire IDE separately at ~/.kiro/hooks/numbat.json",
	},
	{
		enum:          model.AgentGoose,
		display:       "Goose",
		configDirRel:  ".config/goose",
		configDirEnv:  "XDG_CONFIG_HOME",
		hookModality:  hookModalityHooks,
		wiredPath:     hook.GoosePluginPath,
		hookAgent:     hook.AgentGoose,
		deferredStore: "SQLite sessions",
		setupHint:     "install: numbat hook install --agent goose",
	},
	{
		enum:          model.AgentKilo,
		display:       "Kilo Code",
		configDirRel:  ".config/kilo",
		configDirEnv:  "XDG_CONFIG_HOME",
		hookModality:  hookModalityPlugin,
		wiredPath:     hook.KiloPluginPath,
		hookAgent:     hook.AgentKilo,
		deferredStore: "SQLite/session storage",
		setupHint:     "install: numbat hook install --agent kilo",
	},
	{
		enum:          model.AgentOpenHands,
		display:       "OpenHands",
		hookModality:  hookModalityHooks,
		hookAgent:     hook.AgentOpenHands,
		deferredStore: "conversation/event storage",
		setupHint:     "project install: numbat hook install --agent openhands --settings /repo/.openhands/hooks.json",
	},
	{
		enum:          model.AgentCrush,
		display:       "Crush",
		configDirRel:  ".config/crush",
		configRoot:    func(home string) string { return filepath.Dir(hook.CrushConfigPath(home)) },
		hookModality:  hookModalityHooks,
		wiredPath:     hook.CrushConfigPath,
		hookAgent:     hook.AgentCrush,
		deferredStore: "project-local .crush/crush.db (SQLite/WAL)",
		setupHint:     "install: numbat hook install --agent crush; restart Crush",
	},
	{
		enum:          model.AgentJunie,
		display:       "Junie CLI (EAP)",
		configDirRel:  ".junie",
		hookModality:  hookModalityHooks,
		wiredPath:     hook.JunieConfigPath,
		hookAgent:     hook.AgentJunie,
		deferredStore: "local session state (schema/path not published)",
		setupHint:     "install: numbat hook install --agent junie; restart Junie EAP",
	},
	{
		enum:                model.AgentAntigravity,
		display:             "Antigravity",
		configDirRel:        ".gemini/antigravity-cli",
		configDirAlternates: []string{".gemini/antigravity"},
		hookModality:        hookModalityHooks,
		wiredPath:           hook.AntigravityHooksPath,
		hookAgent:           hook.AgentAntigravity,
		deferredStore:       "JSONL transcript format",
		setupHint:           "install: numbat hook install --agent antigravity",
	},
	{
		enum:          model.AgentFactory,
		display:       "Factory Droid",
		configDirRel:  ".factory",
		hookModality:  hookModalityHooks,
		wiredPath:     hook.FactorySettingsPath,
		hookAgent:     hook.AgentFactory,
		deferredStore: "JSONL transcript format",
		setupHint:     "install: numbat hook install --agent factory",
	},
	{
		enum:          model.AgentGrok,
		display:       "Grok Build",
		configDirRel:  ".grok",
		configDirEnv:  "GROK_HOME",
		hookModality:  hookModalityHooks,
		wiredPath:     hook.GrokHooksPath,
		hookAgent:     hook.AgentGrok,
		deferredStore: "sessions record format",
		setupHint:     "install: numbat hook install --agent grok",
	},
	{
		enum:         model.AgentDevinCLI,
		display:      "Devin CLI",
		configDirRel: ".config/devin",
		configRoot:   func(home string) string { return filepath.Dir(hook.DevinUserConfigPath(home)) },
		hookModality: hookModalityHooks,
		wiredPath:    hook.DevinUserConfigPath,
		hookAgent:    hook.AgentDevin,
		setupHint:    "install: numbat hook install --agent devin",
	},
	{
		enum:          model.AgentHermesCLI,
		display:       "Hermes",
		configDirRel:  ".hermes",
		configRoot:    func(home string) string { return filepath.Dir(hook.HermesUserConfigPath(home)) },
		hookModality:  hookModalityHooks,
		wiredPath:     hook.HermesUserConfigPath,
		hookAgent:     hook.AgentHermes,
		deferredStore: "state.db (SQLite/WAL)",
		setupHint:     "install: numbat hook install --agent hermes",
	},
	{
		enum:          model.AgentMuseCode,
		display:       "Muse Code",
		configDirRel:  ".config/muse",
		configRoot:    func(home string) string { return filepath.Dir(hook.MuseUserSettingsPath(home)) },
		hookModality:  hookModalityHooks,
		wiredPath:     hook.MuseUserSettingsPath,
		hookAgent:     hook.AgentMuse,
		deferredStore: "session logs (unpublished record format)",
		setupHint:     "install: numbat hook install --agent muse",
	},
}

// agentRow is the computed report for one agent: every column the table/JSON
// renders. It is built from a descriptor plus the read-only on-disk signals.
type agentRow struct {
	Agent string `json:"agent"`
	// Present is true when numbat found any local signal for the agent: its
	// config directory, a parsed or incomplete at-rest scan, or a wired/unreadable
	// hook config. The default text/JSON report includes only present rows; --all
	// keeps the full coverage matrix.
	Present   bool   `json:"present"`
	Detected  bool   `json:"detected"`
	AtRest    string `json:"at_rest"`
	Hook      string `json:"hook"`
	Wired     string `json:"wired"`
	SetupHint string `json:"setup_hint"`
	// AtRestScanIncomplete is true when the at-rest scan of the agent's known
	// roots did not complete cleanly — a hard read error, or one or more subtrees
	// skipped (unreadable dir, special file). It is the machine-readable companion
	// to the qualified at-rest string, so a JSON consumer can tell a verified
	// "none found" from one numbat could not fully verify.
	AtRestScanIncomplete bool `json:"at_rest_scan_incomplete"`
}

// runAgents implements `numbat agents`: REPORT-ONLY agent discovery. It prints a
// clean aligned text table (or --format json) of local agent inventory; --all
// includes absent rows to show numbat's full local parser/hook coverage. It
// installs/wires nothing and never executes an agent binary.
//
// Exit codes: 0 on a completed report (even when zero agents are detected — that
// is a valid success, not an error), 2 on a usage error, 1 only when the home
// directory cannot be resolved at all (no machine to scan).
func runAgents(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agents", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formatFlag := fs.String("format", agentsFormatText, "output format: text|json")
	allFlag := fs.Bool("all", false, "show all supported local agents, including absent ones")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: numbat agents [--all] [--format text|json]")
		fmt.Fprintln(stderr, "\nReport-only: scans this machine's known agent config dirs and at-rest roots.")
		fmt.Fprintln(stderr, "By default it reports supported agents with local signals; --all prints")
		fmt.Fprintln(stderr, "the full parser/live coverage matrix (config, artifacts, live mode, wired,")
		fmt.Fprintln(stderr, "next step). WIRED means numbat-owned configuration is present.")
		fmt.Fprintln(stderr, "It does not verify runtime activation.")
		fmt.Fprintln(stderr, "It installs nothing, writes nothing, and never executes an agent binary.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "agents: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}
	if *formatFlag != agentsFormatText && *formatFlag != agentsFormatJSON {
		fmt.Fprintf(stderr, "agents: invalid --format %q: want text|json\n", *formatFlag)
		return 2
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(stderr, "agents: cannot resolve home directory: %v\n", err)
		return 1
	}

	rows := buildAgentRows(home)
	if !*allFlag {
		rows = presentAgentRows(rows)
	}
	if *formatFlag == agentsFormatJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "agents: encode json: %v\n", err)
			return 1
		}
		return 0
	}
	writeAgentsTable(stdout, rows)
	return 0
}

// buildAgentRows computes the report for every descriptor, in table order. One
// agent's scan error never aborts the others: detect/at-rest/wired are each
// resolved independently and a failure degrades that one cell to "—" or "no".
func buildAgentRows(home string) []agentRow {
	rows := make([]agentRow, 0, len(agentDescriptors))
	for _, d := range agentDescriptors {
		rows = append(rows, d.row(home))
	}
	return rows
}

// row computes the report row for one descriptor from read-only on-disk signals.
func (d agentDescriptor) row(home string) agentRow {
	detected := d.configPresent(home)
	found, skipped, scanErr := d.artifactFound(home)
	atRest, incomplete := d.atRestColumn(found, skipped, scanErr)
	wired := d.wiredColumn(home)
	return agentRow{
		Agent:                d.display,
		Present:              detected || found || incomplete || wired == "yes" || strings.HasPrefix(wired, "error"),
		Detected:             detected,
		AtRest:               atRest,
		Hook:                 d.hookModality,
		Wired:                wired,
		SetupHint:            d.setupHint,
		AtRestScanIncomplete: incomplete,
	}
}

func (d agentDescriptor) configPresent(home string) bool {
	if (d.configDirRel != "" || d.configRoot != nil) && dirPresent(d.configDir(home)) {
		return true
	}
	for _, root := range d.configRootAlternates {
		if dirPresent(root(home)) {
			return true
		}
	}
	for _, rel := range d.configDirAlternates {
		if dirPresent(filepath.Join(home, rel)) {
			return true
		}
	}
	if d.roots != nil {
		for _, root := range d.roots(home) {
			if dirPresent(root) {
				return true
			}
		}
	}
	return false
}

// presentAgentRows filters the coverage matrix down to agents with a local
// signal. This is the default CLI posture: an endpoint inventory should answer
// "what is actually here?" while --all remains available for support coverage.
func presentAgentRows(rows []agentRow) []agentRow {
	out := make([]agentRow, 0, len(rows))
	for _, r := range rows {
		if r.Present {
			out = append(out, r)
		}
	}
	return out
}

// configDir resolves the directory whose presence signals an installed agent,
// using the same home/config override as that agent's hook installer.
func (d agentDescriptor) configDir(home string) string {
	if d.configRoot != nil {
		return d.configRoot(home)
	}
	switch d.configDirEnv {
	case "PI_CODING_AGENT_DIR":
		if v := os.Getenv(d.configDirEnv); v != "" {
			return v
		}
	case "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GROK_HOME",
		"HERMES_HOME", "KIMI_CODE_HOME", "KIRO_HOME", "QWEN_HOME":
		if v := os.Getenv(d.configDirEnv); v != "" {
			rootName := d.configDirRel
			if i := strings.Index(rootName, "/"); i >= 0 {
				rootName = rootName[:i]
			}
			if rest := strings.TrimPrefix(d.configDirRel, rootName+"/"); rest != d.configDirRel {
				return filepath.Join(v, rest)
			}
			return v
		}
	case "GEMINI_CLI_HOME":
		if v := os.Getenv(d.configDirEnv); v != "" {
			return filepath.Join(v, d.configDirRel)
		}
	case "XDG_CONFIG_HOME":
		if v := os.Getenv(d.configDirEnv); v != "" {
			if rest := strings.TrimPrefix(d.configDirRel, ".config/"); rest != d.configDirRel {
				return filepath.Join(v, rest)
			}
			return v
		}
	case "OPENCODE_CONFIG_DIR":
		if v := os.Getenv(d.configDirEnv); v != "" {
			return v
		}
		if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
			return filepath.Join(v, "opencode")
		}
	}
	return filepath.Join(home, d.configDirRel)
}

// atRestRoots uses the same effective agent/data home as discovery so inventory
// cannot report an installed override while scanning only the default tree.
func (d agentDescriptor) atRestRoots(home string) []string {
	if d.roots != nil {
		return d.roots(home)
	}
	roots := make([]string, 0, len(d.rootsRel))
	for _, rel := range d.rootsRel {
		roots = append(roots, d.resolveRoot(home, rel))
	}
	return roots
}

// resolveRoot resolves one home-relative at-rest root to an absolute path under
// the agent's effective root, applying the env override that governs that tree.
func (d agentDescriptor) resolveRoot(home, rel string) string {
	switch d.configDirEnv {
	case "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "KIMI_CODE_HOME":
		if v := os.Getenv(d.configDirEnv); v != "" {
			// These variables replace the leading agent root.
			if rest := strings.TrimPrefix(rel, d.configDirRel+"/"); rest != rel {
				return filepath.Join(v, rest)
			}
			return filepath.Join(v, rel)
		}
	case "GEMINI_CLI_HOME":
		if v := os.Getenv(d.configDirEnv); v != "" {
			return filepath.Join(v, rel)
		}
	case "OPENCODE_CONFIG_DIR":
		// OPENCODE_CONFIG_DIR does not move data; XDG_DATA_HOME does.
		if v := os.Getenv("XDG_DATA_HOME"); v != "" {
			if rest := strings.TrimPrefix(rel, ".local/share/"); rest != rel {
				return filepath.Join(v, rest)
			}
		}
	}
	return filepath.Join(home, rel)
}

// atRestColumn summarizes parser coverage and qualifies incomplete scans rather
// than reporting a confident absence.
func (d agentDescriptor) atRestColumn(found bool, skipped int, scanErr bool) (string, bool) {
	if !d.hasParser() {
		if d.deferredStore != "" {
			return fmt.Sprintf("n/a (hook-only; deferred %s)", d.deferredStore), false
		}
		return "n/a (hook-only)", false
	}
	incomplete := scanErr || skipped > 0
	var b strings.Builder
	switch {
	case found:
		b.WriteString("found transcripts")
	case scanErr:
		b.WriteString("scan error")
	case skipped > 0:
		fmt.Fprintf(&b, "none found (partial scan: %d skipped)", skipped)
	default:
		b.WriteString("none found")
	}
	if d.deferredStore != "" {
		fmt.Fprintf(&b, "; deferred %s", d.deferredStore)
	}
	return b.String(), incomplete
}

// hasParser reports whether the extractor registry covers this agent.
func (d agentDescriptor) hasParser() bool {
	_, ok := extract.For(d.enum)
	return ok
}

// artifactFound checks the agent's override-aware roots with the same classifier
// scan and timeline use. Read failures and skipped entries mark it incomplete.
func (d agentDescriptor) artifactFound(home string) (found bool, skipped int, scanErr bool) {
	for _, root := range d.atRestRoots(home) {
		if _, statErr := os.Stat(root); statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			scanErr = true
			continue
		}
		arts, skips, walkErr := discover.Walk(root)
		if walkErr != nil {
			scanErr = true
			continue
		}
		skipped += len(skips)
		for _, a := range arts {
			if a.Agent == d.enum {
				return true, skipped, scanErr
			}
		}
	}
	return false, skipped, scanErr
}

// wiredColumn reuses the hook installer's status check. Unreadable or malformed
// config is an error, not a verified absence.
func (d agentDescriptor) wiredColumn(home string) string {
	if d.wiredPath == nil || d.hookAgent == "" {
		return "n/a"
	}
	type statusTarget struct {
		path    string
		managed bool
	}
	targets := []statusTarget{{path: d.wiredPath(home)}}
	for _, alternate := range d.wiredPathAlternates {
		targets = append(targets, statusTarget{path: alternate(home)})
	}
	if path, ok := inventoryManagedHooksPath(d.hookAgent); ok {
		targets = append(targets, statusTarget{path: path, managed: true})
	}
	seen := make(map[string]struct{}, len(targets))
	supported := false
	readError := false
	installed := false
	for _, target := range targets {
		key := fmt.Sprintf("%t:%s", target.managed, filepath.Clean(target.path))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		var (
			rep hook.InstallReport
			err error
		)
		if target.managed {
			rep, err = hook.StatusManagedErr(d.hookAgent, target.path)
		} else {
			rep, err = hook.StatusErr(d.hookAgent, target.path)
		}
		if !rep.Supported {
			continue
		}
		supported = true
		if err != nil {
			readError = true
			continue
		}
		if rep.Installed {
			installed = true
		}
	}
	if !supported {
		return "n/a"
	}
	if readError {
		return "error (cannot read config)"
	}
	if installed {
		return "yes"
	}
	return "no"
}

// dirPresent reports whether path exists and is a directory. It is the read-only
// detection primitive: a stat, never an execution. A symlink to a directory
// counts (os.Stat follows it), matching how a relocated config dir is still a
// real install.
func dirPresent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// writeAgentsTable renders the rows as a clean aligned text table via tabwriter,
// matching the repo's text-output style. CONFIG is yes/no for a local config
// signal; ARTIFACTS reports the at-rest parser result, LIVE reports hook/plugin
// modality, and WIRED says whether numbat is already installed there.
func writeAgentsTable(w io.Writer, rows []agentRow) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "AGENT\tCONFIG\tARTIFACTS\tLIVE\tWIRED\tNEXT")
	for _, r := range rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Agent, yesNo(r.Detected), r.AtRest, r.Hook, r.Wired, r.SetupHint)
	}
	_ = tw.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// agentDescriptorEnums returns the set of enum ids the descriptor table covers,
// sorted, for the sync test and diagnostics.
func agentDescriptorEnums() []string {
	out := make([]string, 0, len(agentDescriptors))
	for _, d := range agentDescriptors {
		out = append(out, d.enum)
	}
	sort.Strings(out)
	return out
}
