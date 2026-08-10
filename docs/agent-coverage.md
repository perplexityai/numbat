# Agent coverage

numbat observes local desktop, CLI, IDE, and gateway agents through three
inputs:

- on-disk session artifacts for forensic reconstruction;
- synchronous lifecycle hooks or generated agent plugins and extensions; and
- OTLP/HTTP logs.

All inputs produce the same normalized events and use the same CEL rules. This
page lists the surfaces numbat actually supports. A product name does not imply
coverage of every desktop, CLI, IDE, ACP, gateway, or hosted mode; host limits
are stated in the relevant row.

## Platform conventions

Release binaries target macOS, Linux, and native Windows. `~` means the current
user's home (`%USERPROFILE%` on Windows). WSL has a separate Linux home; pass an
explicit mounted `--path` to inspect native Windows files from WSL.

Home-relative stores use the same layout on all three platforms unless a row
shows an OS-specific path. Agent-root overrides honored by the relevant
discoverer or installer include `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`GEMINI_CLI_HOME`, `COPILOT_HOME`, `OPENCODE_CONFIG_DIR`, `GROK_HOME`,
`HERMES_HOME`, `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR`,
`PI_CODING_AGENT_DIR`, `PI_CODING_AGENT_SESSION_DIR`, `KIMI_CODE_HOME`,
`QWEN_HOME`, `CLINE_DIR`, `KIRO_HOME`, and the relevant XDG variables.
`OPENCLAW_CONFIG_PATH` selects OpenClaw's live plugin config root but does not
move its at-rest state. `OPENCLAW_PROFILE` alone does not select a path;
OpenClaw's `--profile` flag projects concrete state/config variables only for
that OpenClaw process. `CLINE_HOOKS_DIR` selects an additional runtime hook
directory.
Crush treats `CRUSH_GLOBAL_CONFIG` as a directory and reads
`$CRUSH_GLOBAL_CONFIG/crush.json`.

## Matrix

This matrix defines the supported capture surfaces. A concrete
path or mechanism means numbat implements it. **Deferred** means the upstream
surface is known but is not parsed yet; **none** means no usable upstream
surface is currently published. The enforcement column names only a synchronous
pre-action gate—monitoring can still be supported when enforcement is not.

Notes call out only material version, host, trust, or fidelity limits.
Installation steps are in [live-capture.md](live-capture.md); scope, trust, and
fleet rollout are in [deployment.md](deployment.md).
Parser-backed at-rest paths are also the default roots used by `scan` and
`timeline`; use repeatable `--agent` to select agents without entering paths.

| Agent | At-rest artifacts | Live capture | Enforcement | Notes |
|---|---|---|---|---|
| Claude Code | `$CLAUDE_CONFIG_DIR/{projects,history.jsonl}` or `~/.claude/...` | the same root's `settings.json`; OTLP logs | yes — `PreToolUse` | CLI, Desktop Code, and IDE sessions share the local settings file. Subagent transcripts are discovered recursively. |
| Claude Cowork | macOS: `~/Library/Application Support/Claude/local-agent-mode-sessions/**/audit.jsonl` | none | no | Native Windows and Linux stores are not defaulted without current fixtures. Acquired copies must retain the `local-agent-mode-sessions/.../audit.jsonl` path shape. |
| Codex | `$CODEX_HOME/{sessions,archived_sessions,history.jsonl}` or `~/.codex/...`; rollout files may be `.jsonl` or `.jsonl.zst` | `$CODEX_HOME/hooks.json` or `~/.codex/hooks.json`; OTLP logs | yes — `PreToolUse` | App, CLI, and IDE sessions share the root. The canonical code-mode form for one static shell call becomes `command.exec`; other JavaScript remains `tool.call`. Hooks cover most local function tools; hosted tools do not enter the local hook path. Non-managed hook definitions require review in `/hooks` or Settings > Hooks. |
| Gemini CLI | `$GEMINI_CLI_HOME/.gemini/tmp` or `~/.gemini/tmp`; current `chats/**/*.jsonl` journals plus legacy `logs.json` and checkpoints | the same root's `settings.json`; OTLP logs | yes — `BeforeTool` | Current journals include nested subagent sessions. Rewinds do not erase earlier actions from the forensic timeline. |
| Cursor | `~/.cursor/projects/<hash>/agent-transcripts/**/*.jsonl` | `~/.cursor/hooks.json` | yes — `preToolUse` / `beforeReadFile` | `state.vscdb` is deferred. numbat uses Cursor's native `permission:"deny"` response. The default user hook covers local Agent sessions; Cloud and Tab limits are below. |
| Windsurf / Cascade / Devin Desktop | `~/.windsurf/transcripts/*.jsonl` | `~/.codeium/windsurf/hooks.json` | yes — pre-action events | numbat uses exit code 2 for `pre_read_code`, `pre_write_code`, `pre_run_command`, and `pre_mcp_tool_use`. The payload does not reliably distinguish Windsurf from Devin Desktop. |
| GitHub Copilot CLI | `$COPILOT_HOME/session-state/*/events.jsonl` or `~/.copilot/session-state/*/events.jsonl` | `$COPILOT_HOME/hooks/numbat.json` or `~/.copilot/hooks/numbat.json` | yes — `preToolUse` | The shared hook file uses Copilot's native lower-camel schema. Copilot's trace/metric OTLP output is not consumed. |
| VS Code Copilot Chat / Agent Mode | none | shared Copilot hook file | yes — `PreToolUse` | VS Code loads Copilot CLI hook files and converts lower-camel events. numbat recognizes the VS Code payload and emits `source_agent:"vscode"`. Hooks are currently a VS Code preview feature. |
| OpenCode | Earlier JSON message/part stores under `$XDG_DATA_HOME/opencode/storage` or `~/.local/share/opencode/storage`; older `project/*/storage` is also read | plugin under the OpenCode config root; optional OTLP plugin | no | Live plugin capture works on native Windows. The current `opencode.db` forensic store is deferred pending a native fixture and parser. |
| OpenClaw | Stable v2026.7.1: primary JSONL plus plain retained `.jsonl.{reset,deleted}.<timestamp>` archives under `<state-root>/agents/<id>/sessions`, including embedded `agent/sessions` and `agent/codex-home/sessions`; native AgentMessage and embedded-Codex flavors are parsed, while standalone `event_msg`/unknown flavors are diagnostic-only | native plugin at `<config-root>/extensions/numbat/` | yes — `before_tool_call` | Requires OpenClaw v2026.7.1+. Eight message, session, subagent, and tool callbacks load without conversation access; `llm_input` and `llm_output` add model/harness-boundary coverage when explicitly trusted. The v2026.7.2 beta/development database and compressed archives are deferred. Root selection and host limits are below. |
| Pi | `${PI_CODING_AGENT_SESSION_DIR}/**/*.jsonl` or `${PI_CODING_AGENT_DIR:-~/.pi/agent}/sessions/**/*.jsonl` | `${PI_CODING_AGENT_DIR:-~/.pi/agent}/extensions/numbat.ts` | yes — `tool_call` | Versioned session records are parsed in physical artifact order, retaining every branch. The generated extension observes prompts, tools, turns, and session boundaries; only the synchronous pre-execution `tool_call` can block. |
| Kimi Code | `$KIMI_CODE_HOME/sessions/*/*/agents/*/wire.jsonl` or `~/.kimi-code/sessions/.../wire.jsonl` | `${KIMI_CODE_HOME:-~/.kimi-code}/config.toml` | yes — `PreToolUse` | Current flat wire journals cover main and sub-agents. The installer appends a marked `[[hooks]]` block using only Kimi's documented fields and leaves existing keys, comments, and ordering intact. Legacy `kimi-cli` records are not mixed into this parser. |
| Qwen Code | deferred conversation/checkpoint storage | `${QWEN_HOME:-~/.qwen}/settings.json`; OTLP logs | yes — `PreToolUse` | Hooks require Qwen Code 0.17.0+. Hook input/output follows Qwen's command-hook contract. Exit code 2 carries an intentional deny; hook errors and timeouts remain upstream fail-open. The automatic installer accepts strict JSON and refuses JSON comments or trailing commas rather than rewriting them. Current conversation storage is not parsed without a stable fixture. |
| Cline CLI | deferred SQLite sessions | `${CLINE_DIR:-~/.cline}/hooks/{TaskStart,...,SessionShutdown}`, or `CLINE_HOOKS_DIR` | yes — `PreToolUse` | The current CLI/SDK auto-discovers the global directory and accepts an additional runtime directory through `CLINE_HOOKS_DIR` / `--hooks-dir`; no hook-enable setting is required. numbat installs all current action/lifecycle files except bookkeeping-only `PreCompact`: task start/resume/complete/cancel/error, session shutdown, prompt, and pre/post tool. Project `.cline/hooks` and legacy `.clinerules/hooks` directories can be targeted with `--settings`. The legacy editor directory remains available through `--settings ~/Documents/Cline/Hooks`; its Unix files require the Hooks-tab toggle. |
| Amp | deferred thread/history storage | `~/.config/amp/plugins/numbat.ts` | yes — `tool.call` | The generated TypeScript plugin uses Amp's stable plugin API. Monitor mode forwards asynchronously; enforce mode waits only at `tool.call` and returns Amp's native `reject-and-continue` response. Reload plugins in Amp after installation. |
| Auggie | deferred session/task storage | `~/.augment/settings.json` plus generated scripts under `~/.augment/hooks/` | yes — `PreToolUse` | Auggie requires a script path rather than an inline command, so numbat owns explicit `.sh`/`.ps1` wrappers. Unknown strict-JSON keys are preserved; automatic install refuses comments and trailing commas instead of rewriting ambiguous input. Project paths remain available through `--settings`. |
| Kiro IDE / CLI v3 | deferred local session state | default `~/.kiro/hooks/numbat.json`; CLI-only `${KIRO_HOME}/hooks/numbat.json` override | yes — `PreToolUse` | The default global `v1` file covers Kiro IDE 1.0.182+ and Kiro CLI 2.13.0+ with its opt-in v3 engine (`kiro-cli --v3`). When `KIRO_HOME` is set, install the default IDE file separately with `--settings ~/.kiro/hooks/numbat.json` if both hosts need coverage. Kiro 2.x hook blocks embedded in custom agents are not rewritten. |
| Goose | deferred SQLite sessions | `~/.agents/plugins/numbat/{plugin.json,hooks/hooks.json}` | yes — `PreToolUse` | Goose discovers the user-level Open Plugins package automatically. numbat covers session, prompt, tool success/failure, stop, and session-end events; exit code 2 is the clean blocking signal. A plugin listed in Goose `disabledPlugins` will not load. |
| Kilo Code | deferred SQLite/session storage | `${XDG_CONFIG_HOME:-~/.config}/kilo/plugin/numbat.ts` | yes — `tool.execute.before` | The generated module uses Kilo's current global plugin directory and module descriptor. It works in the CLI and VS Code extension, blocks by throwing only after a clean numbat deny, and otherwise fails open. `KILO_PURE=1` disables external plugins. |
| OpenHands | deferred conversation/event storage | repository `.openhands/hooks.json` (explicit `--settings` required) | yes — `PreToolUse` | Repository hooks work across OpenHands Cloud, CLI, and local GUI. There is no documented user-global file, so numbat does not include OpenHands in `--agent all`; install with `--agent openhands --settings /repo/.openhands/hooks.json`. |
| Crush | deferred project-local `.crush/crush.db` (SQLite/WAL; `options.data_directory` can move it) | `$CRUSH_GLOBAL_CONFIG/crush.json` or `${XDG_CONFIG_HOME:-~/.config}/crush/crush.json`; project config via explicit `--settings` | yes — `PreToolUse` | Crush currently exposes only this preliminary action hook and only for top-level agent tool calls. numbat leaves the matcher empty to cover every tool, sets a 10-second timeout, uses exit code 2 to deny, and otherwise fails open. Restart Crush after an external config edit. |
| Junie CLI (Early Access) | deferred local session state (record schema and path are not published) | `~/.junie/config.json`; explicit `JUNIE_CONFIG_LOCATION` / `--config-location` file via numbat's `--settings` | yes — `PreToolUse` | numbat installs session start/end, prompt, pre-tool, and stop callbacks. Prompt callbacks are interactive-only; the other installed events run in interactive and batch hosts. No hooks run in ACP/server. Junie's hook payload has no session id or cwd, so cross-event sequence correlation is unavailable. Restart Junie after installation. |
| Antigravity | deferred `~/.gemini/{antigravity,antigravity-cli}/brain/<conversation>/.../transcript.jsonl` | `~/.gemini/config/hooks.json` | yes — `PreToolUse` | Desktop and CLI publish the transcript locations, but not a stable record schema. Monitor mode returns `ask`; enforce mode uses the documented hard deny. |
| Factory Droid | deferred `~/.factory/projects/**/*.jsonl` | `~/.factory/hooks.json`; project `.factory/hooks.json` via `--settings` | yes — `PreToolUse` | Root `hooks.json` is canonical. The installer preserves compatible `settings.json` events and migrates the older `.factory/hooks/hooks.json` source without dropping foreign hooks. It refuses an effective `hooksDisabled:true`. The transcript path is exposed by hooks, but its durable record format is not versioned. |
| Grok Build | `${GROK_HOME:-~/.grok}/sessions/` (deferred record shape) | `${GROK_HOME:-~/.grok}/hooks/numbat.json` | yes — `PreToolUse` | Sessions persist automatically across TUI, headless, and ACP hosts, but the record schema is not published. Project hooks require `/hooks-trust`. |
| Devin CLI | none | Unix: `${XDG_CONFIG_HOME:-~/.config}/devin/config.json`; Windows: `%APPDATA%\devin\config.json`; project: `.devin/hooks.v1.json` | yes — `PreToolUse` | Hook events emit `source_agent:"devin-cli"`. |
| Hermes | `$HERMES_HOME/state.db`; otherwise Unix `~/.hermes/state.db`, Windows `%LOCALAPPDATA%\hermes\state.db` (SQLite/WAL; deferred) | shell hooks in the active profile's `config.yaml` (CLI and Gateway) | yes — `pre_tool_call` | numbat observes session, prompt/assistant, tool, approval, subagent, and finalization events. Hermes requires first-use consent per event/command pair. There is no documented project hook config. |

## Permission and decision telemetry

The enforcement column above says whether numbat can return a synchronous deny;
it does not imply that the host reports its own permission decision. Explicit
permission inputs are normalized to `permission.requested`,
`permission.approved`, or `permission.denied`:

| Agent | Input | Host signal | Per-action join |
|---|---|---|---|
| Claude Code | `PermissionRequest`, `PermissionDenied`; OTLP `claude_code.tool_decision` | request, classifier denial, or OTLP decision | denial `tool_use_id`; OTLP `tool_use_id` |
| Codex | `PermissionRequest`; OTLP `codex.tool_decision` | request; OTLP decision | hook id not established; OTLP `call_id` |
| Kimi Code | `PermissionRequest`, `PermissionResult` | request and result | `tool_call_id` |
| Qwen Code | `PermissionRequest`, `PermissionDenied` | request or classifier denial | denial `tool_use_id` |
| Copilot CLI / VS Code | `PermissionRequest` | request only | not established |
| Grok Build | `PermissionDenied` | denial only | not established |
| Devin CLI | `PermissionRequest` | request only | not established |
| Hermes | `pre_approval_request`, `post_approval_response` | request and final choice | session only |
| OpenCode | OTLP `tool_decision` | decision | `call_id` |

Other OTLP records carrying `approval.required`, `approval.decision`, or
`permission.decision` are also mapped; `gen_ai.tool.call.id` is retained when
present. A join key links records but does not prove that the host honored a
numbat response.

## Material exceptions and limits

These boundaries affect installation or interpretation and do not fit in one
matrix cell.

| Agent | Qualification |
|---|---|
| Codex | `PreToolUse` and `PostToolUse` cover most local function tools, which numbat classifies into shell, file, network, MCP, or generic tool events. Hosted tools bypass the local hook path, and upstream hooks are not a complete policy boundary. |
| Cursor | `Read` and `ReadFile` actions use `beforeReadFile`; generic pre/success/failure callbacks exclude those names so the overlapping callbacks do not double-report one action. Other tools use the generic stream. Enforcement applies to `preToolUse` and `beforeReadFile`; `subagentStart` is monitoring-only because current Cursor builds invoke it but ignore its deny response. For local sessions, all matching Enterprise, Team, trusted Project, and User hooks run. Cloud agents load repository Project hooks and, on Enterprise plans, Team and Enterprise hooks; they do not load `~/.cursor/hooks.json`, may perform initial read-only exploratory turns before hooks begin, and do not emit `sessionStart` or `sessionEnd`. Cursor Tab uses separate `beforeTabFileRead` / `afterTabFileEdit` events that numbat does not install. |
| OpenCode | Live plugin capture is supported and monitor-only. The parser covers earlier JSON storage, while the current `opencode.db` store remains deferred. |
| OpenClaw | Coverage is limited to actions crossing the typed Gateway pipeline or native Codex relay; generic ACP/ACPX and text-only backends need the underlying agent's own integration. Stable v2026.7.1 AgentMessage and embedded-Codex JSONL are parsed; unknown flavors produce diagnostics. Code Mode records with explicit `code` or `language` remain generic rather than being mislabeled as shell. Gateway mirrors and embedded rollouts can overlap and are not deduplicated. The v2026.7.2 beta/development database and compressed archives remain deferred. Root, profile, and production-policy steps live in [deployment.md](deployment.md#openclaw-production-policy). |
| Cline | The current CLI/SDK auto-discovers its global hook directory. Project and legacy editor directories require `--settings`; the legacy editor also requires its Hooks-tab toggle. Bookkeeping-only `PreCompact` is intentionally omitted. |
| Kiro | The default global `v1` file covers IDE 1.0.182+ and CLI 2.13.0+ v3. `KIRO_HOME` relocates only the CLI target; wire `~/.kiro/hooks/numbat.json` separately for the IDE when both roots are active. The combined `agents` row reports `WIRED=yes` when either root is wired and both are readable; an unreadable root reports an error. Verify each required root with matching `hook status` arguments. numbat does not rewrite v2 blocks embedded in individual custom agents. |
| OpenHands | Hooks are repository-scoped, so OpenHands requires an explicit `.openhands/hooks.json` path and is excluded from `--agent all`. |
| Crush | The preliminary hook observes only top-level agent tool calls. numbat covers every tool with the documented fail-open, exit-code-2 contract. |

### Event-selection exceptions

OpenClaw, Hermes, and Junie need event-selection detail because superficially
similar upstream callbacks do not always represent the same lifecycle boundary:

| Agent | Installed coverage | Intentional exclusions and limits |
|---|---|---|
| OpenClaw | Eight typed session, message, tool, and subagent callbacks. `llm_input` and `llm_output` are added only with `plugins.entries.numbat.hooks.allowConversationAccess:true`. | Inbound messages can contain content; outbound delivery is content-free. Model callbacks forward only the current input or nonempty assistant text, can repeat on retries, and omit system prompt, history, reasoning, tools, usage, and raw message objects. WhatsApp inbound callbacks require a separate channel opt-in. Only `before_tool_call` can block. |
| Hermes | Session start/finalize, LLM prompt/assistant, pre/post tool, approval, and subagent events in the active profile; CLI and Gateway use the same shell hooks. | `on_session_end` fires after each turn, so `on_session_finalize` is the true `session.end`. `on_session_reset` is followed by a new start, and transform/policy callbacks add no distinct normalized action. The canonical `state.db` remains deferred. |
| Junie CLI (Early Access) | `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `Stop`, and `SessionEnd` from user or explicitly supplied config. | `PermissionRequest` is omitted because an empty successful monitor callback would auto-approve the action. `StopFailure` is provider-health telemetry, and there is no post-tool event. Payloads have no session id or cwd, so sequence correlation is unavailable. Prompt hooks are TUI-only; ACP and server hosts run no hooks. |

## Enforcement

See [enforcement.md](enforcement.md) for the authoritative decision flow,
control-response/operator-record boundary, and fail-open semantics. This
section records host coverage and transport exceptions.

Live capture is monitor-only by default. `hook install --enforce` is available
for rows marked **yes** in the matrix. The shipped catalog remains monitor-only;
blocking also requires an operator rule or same-id replacement with `enforce: true`.

Structured-response agents exit 0 with their native deny JSON. Windsurf, Kimi
Code, Qwen Code, Auggie, Kiro, Goose, OpenHands, Crush, and Junie exit 2 and
write the reason to stderr, as their hook contracts require. Copilot CLI itself
denies when a command `preToolUse` hook fails to launch, crashes, or exits
non-zero; its hook timeouts allow. Post-action hooks never block. Cursor
`subagentStart` remains a monitoring event because Cursor currently ignores its
deny response.

OpenClaw enforcement evaluates the parameters presented to numbat's
`before_tool_call` callback; later rewrites by other plugins are not reevaluated.
The wrapper returns no deny on child failure or its nine-second deadline, while
OpenClaw itself fails closed on an escaped handler error or host timeout. The
generated host timeout is ten seconds; full semantics are in
[enforcement.md](enforcement.md#coverage-limits).

OpenCode remains monitor-only. OTLP and at-rest inputs cannot block because
they are not synchronous control paths.

## Managed hooks

Claude Code, Codex, Cursor, Copilot CLI, Gemini CLI, Windsurf, Qwen Code, and
Auggie expose documented machine policy files and support `hook install
--managed`. Scope definitions, paths, and precedence are in
[deployment.md](deployment.md#choose-an-install-scope).

OpenCode is an explicit installer gap rather than an absent vendor mechanism.
Upstream now defines highest-priority machine-managed `opencode.json[c]`
directories (and macOS managed preferences), but does not document those
directories as local source-plugin directories. numbat's integration is a
generated local TypeScript plugin, so it does not claim a first-class OpenCode
`--managed` target until that loading path is verified. OpenClaw likewise
documents per-state-directory plugin roots, not an administrator-managed plugin
path; deploy its package and activation policy per Gateway service user. Other
agents use user/project configuration or a vendor management plane; numbat does
not invent a system path where the vendor has not defined one.

## Known collection gaps

Live support does not imply that numbat also parses every durable store an
agent owns. A path alone is not enough: numbat waits for a stable record shape
or representative fixture so it does not invent actions, exit codes, or errors.

| Gap | Affected supported surfaces | What unblocks it |
|---|---|---|
| SQLite/WAL acquisition and record validation | OpenCode `opencode.db`, the OpenClaw v2026.7.2 beta/development line's `openclaw-agent.sqlite` session/transcript tables, Hermes `state.db`, Cursor `state.vscdb`, Copilot `session-store.db`, and the current Cline, Goose, Kilo, Crush, and Kiro stores | Native fixture sets plus safe snapshot/WAL handling |
| OpenClaw replacement/alternate transcript sources | Development-line compressed archives; stable standalone `event_msg`-only or unknown JSONL flavors; custom `session.store` indexes and arbitrary `sessionFile` paths outside recognized roots | Version-pinned fixtures and schemas, plus bounded index traversal or a future explicit parser hint for acquired files; current behavior rejects compressed files and emits diagnostics for unparsed JSONL flavors |
| Unpublished or unstable durable record shape | Factory JSONL, Antigravity transcripts, Grok sessions, and Qwen, Amp, Auggie, OpenHands, and Junie session state | A versioned schema or representative fixtures with stable semantics |
| Agent-specific telemetry transports | OTLP traces, metrics, and gRPC | A normalized event contract and fixtures; current `collect` support is OTLP/HTTP logs only |

Old Hermes JSONL transcripts are legacy fallback data, not its current primary
store. Kiro 2.x per-custom-agent hook blocks are also intentionally not rewritten
by the global v3 installer. A shared directory lineage is not sufficient proof
that Kilo, Roo, and Cline task records have identical current semantics.

## Evaluated but unsupported

The following agents currently lack a hook or durable-record surface that meets
numbat's support contract.

| Agent / host | Why it is not supported now | Revisit when |
|---|---|---|
| Zed native agent and generic ACP host coverage, including AionUi | Zed's `create_worktree` Task hook is post-creation bootstrap only. The host exposes no synchronous prompt/tool/result/session hook; interactive ACP logs are not an automatic security callback. A supported external agent may still load its own native numbat integration, but that is agent coverage rather than a host-wide Zed/AionUi sensor. | A documented host action hook, or a separately designed ACP proxy with framing, capability, cancellation, terminal, and update-passthrough tests |
| Aider | The relocatable `.aider.chat.history.md` is a human-readable transcript, not a versioned action record: it lacks stable tool, timestamp, and session fields. Aider publishes no action-hook API. | A stable structured record or installable lifecycle/action hook is published |
| Trae Agent | JSON trajectories contain useful actions, but their destination is working-directory or caller selected and numbat has no versioned native fixture/discovery contract. No action hook is published. | Native fixtures establish stable record semantics and bounded discovery, or upstream adds hooks |
| Continue CLI | The CLI can resume sessions, but public docs do not specify a durable record schema. The source contains a hook runner, yet its general lifecycle `fire*` functions are not wired into CLI execution or publicly documented; the wired `git-ai` checkpoint is fail-open and file-edit-only. | A stable session schema or the general hook surface is documented and wired |
| Codebuff | Local chats exist under `~/.config/manicode/projects/.../chats`, but their record schema is not published. Progress callbacks are an application SDK surface, not a user-configurable CLI hook. | A versioned record fixture or user-installable CLI lifecycle hook is published |

Installers also omit compaction, notification, todo, and similar bookkeeping
callbacks when they do not represent a normalized agent action or lifecycle
boundary.

## Primary references

- Claude Code hooks: <https://code.claude.com/docs/en/hooks>
- Codex hooks: <https://learn.chatgpt.com/docs/hooks>
- Gemini CLI hooks: <https://geminicli.com/docs/hooks/>
- Cursor hooks: <https://cursor.com/docs/hooks>
- Cursor `subagentStart` deny bug (confirmed 20 July 2026): <https://forum.cursor.com/t/subagentstart-hook-deny-is-not-enforced/166143/7>
- Windsurf hooks: <https://docs.windsurf.com/windsurf/cascade/hooks>
- Copilot CLI hooks: <https://docs.github.com/en/copilot/reference/hooks-reference>
- VS Code hooks: <https://code.visualstudio.com/docs/agent-customization/hooks>
- OpenCode plugins: <https://opencode.ai/docs/plugins/>
- OpenCode managed settings: <https://opencode.ai/docs/config/#managed-settings>
- OpenClaw plugin hooks: <https://docs.openclaw.ai/plugins/hooks>
- OpenClaw plugin policy and runtime verification: <https://docs.openclaw.ai/plugins>
- OpenClaw plugin management: <https://docs.openclaw.ai/cli/plugins>
- OpenClaw paths and state overrides: <https://docs.openclaw.ai/help/environment>
- OpenClaw stable v2026.7.1 session format: <https://github.com/openclaw/openclaw/blob/v2026.7.1/docs/concepts/session.md>
- OpenClaw ACP/external-agent boundary: <https://docs.openclaw.ai/tools/acp-agents>
- OpenClaw WhatsApp hook privacy: <https://docs.openclaw.ai/channels/whatsapp#plugin-hooks-and-privacy>
- Antigravity hooks: <https://antigravity.google/docs/hooks>
- Factory hooks: <https://docs.factory.ai/reference/hooks-reference>
- Grok hooks: <https://docs.x.ai/build/features/hooks>
- Grok sessions: <https://docs.x.ai/build/features/sessions>
- Devin hooks: <https://docs.devin.ai/cli/extensibility/hooks/overview>
- Hermes hooks: <https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks/>
- Hermes native Windows paths: <https://hermes-agent.nousresearch.com/docs/user-guide/windows-native>
- Pi session format: <https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/session-format.md>
- Pi extensions: <https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md>
- Kimi Code sessions: <https://www.kimi.com/code/docs/en/kimi-code-cli/guides/sessions.html>
- Kimi Code hooks: <https://www.kimi.com/code/docs/en/kimi-code-cli/customization/hooks.html>
- Qwen Code hooks: <https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/>
- Qwen Code telemetry: <https://qwenlm.github.io/qwen-code-docs/en/developers/development/telemetry/>
- Cline hooks: <https://docs.cline.bot/customization/hooks>
- Cline CLI: <https://docs.cline.bot/cli/cli-reference>
- Amp plugin API: <https://ampcode.com/manual/plugin-api>
- Auggie hooks: <https://docs.augmentcode.com/cli/hooks>
- Kiro hooks: <https://kiro.dev/docs/hooks/>
- Kiro global hooks release: <https://kiro.dev/changelog/cli/2-13/>
- Kiro IDE global hooks release: <https://kiro.dev/changelog/ide/1-0-182/>
- Goose Open Plugins hooks: <https://goose-docs.ai/docs/guides/context-engineering/hooks/>
- Kilo Code plugins: <https://kilo.ai/docs/automate/extending/plugins>
- OpenHands hooks: <https://docs.openhands.dev/openhands/usage/customization/hooks>
- Crush hooks: <https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md>
- Junie CLI hooks: <https://junie.jetbrains.com/docs/junie-cli-hooks.html>
- Junie CLI config precedence: <https://junie.jetbrains.com/docs/junie-cli-configuration.html>
- Zed external agents: <https://zed.dev/docs/ai/external-agents>
- Zed parallel-agent worktree hook: <https://zed.dev/docs/ai/parallel-agents>
- AionUi external-agent ACP setup: <https://github.com/iOfficeAI/AionUi/wiki/ACP-Setup>
- Continue CLI hook integration functions: <https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/fireHook.ts>
- Continue CLI tool execution path: <https://github.com/continuedev/continue/blob/main/extensions/cli/src/tools/index.tsx>
- Aider history configuration: <https://aider.chat/docs/config/aider_conf.html>
- Trae Agent trajectory recording: <https://github.com/bytedance/trae-agent/blob/main/docs/TRAJECTORY_RECORDING.md>
- Codebuff local chat storage: <https://www.codebuff.com/docs/advanced/troubleshooting>
- Codebuff SDK event callback: <https://github.com/CodebuffAI/codebuff#sdk-run-agents-in-production>
