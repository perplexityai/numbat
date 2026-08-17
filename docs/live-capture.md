# Live capture

Use hooks or OTLP/HTTP to observe actions as they happen. Both sensors feed the
same pipeline `scan` uses:

- **Hooks** — `numbat hook` handles a lifecycle-hook payload on stdin, so an
  action can be detected as it happens and, in enforce mode, eligible actions
  can be blocked before they run. Covered below.
- **OTLP/HTTP** — `numbat collect` runs an in-process receiver for agents that
  report over OpenTelemetry. The per-agent OTLP setup lives in
  [cli.md](cli.md#collect).

For the per-agent support matrix, deferred surfaces, and hook-contract notes,
see [agent-coverage.md](agent-coverage.md).

## Hook callbacks

`hook` reads one lifecycle payload from stdin. The
[coverage matrix](agent-coverage.md#matrix) lists supported hook and plugin
targets, default paths, enforcement capability, and host limits.
`numbat agents --all` reports the supported local-agent inventory.

Default installation targets the current user's effective agent path and honors
the documented agent-root environment overrides. On native Windows, `~` means
`%USERPROFILE%`; fleet hooks should point to an absolute `.exe` path. OpenHands
is repository-only and therefore requires explicit `--settings`. OpenClaw must
be installed as the serving Gateway user and activated through Gateway policy;
see [OpenClaw production policy](deployment.md#openclaw-production-policy).

OpenCode is monitor-only. Other hook targets, including OpenClaw, support
enforce mode when their upstream contract lets a pre-action hook block
synchronously. See
[agent-coverage.md](agent-coverage.md#enforcement).

## Install, inspect, and remove hooks

`hook install` wires numbat into an agent's hook integration (a settings hook,
standalone hook file, or generated JS/TS plugin/extension). Installation is
idempotent and `uninstall` removes only numbat-owned entries or files. Installers
that edit a shared settings file preserve unrelated hooks and keys and keep one
pristine backup of the original. Backup behavior for owned standalone artifacts
is installer-specific; OpenClaw's generated multi-file package replaces each
owned file atomically without a separate backup.

Common local installs:

```
numbat hook install --agent claude
numbat hook install --agent codex
numbat hook install --agent cursor
numbat hook install --agent windsurf
numbat hook status --agent codex
numbat hook uninstall --agent claude
```

Every other target in the coverage matrix uses the same command shape. Use
`numbat hook install --help` for the accepted agent names.

Install and uninstall require an explicit agent. Use `--agent all` only when you
intentionally want every supported effective user path. Supported agent-root
environment overrides apply, but secondary profiles are not added. Status
defaults to all agents.
Copilot CLI and VS Code share one hook file, so `--agent all` installs that
sensor once under the `copilot` target. OpenHands is excluded from `--agent all`
because its only documented configuration is repository-scoped.

OpenClaw installation writes only numbat's package; it does not run OpenClaw or
edit Gateway policy. `hook status` validates the owned files, not activation.
Use the [production policy checklist](deployment.md#openclaw-production-policy)
to enable, pin, verify, or decommission the package.

Choose a scope or explicit target:

| Goal | How |
|---|---|
| Default user-level install | `numbat hook install --agent codex` |
| Install every supported default path | `numbat hook install --agent all` |
| Explicit path (project, alternate home, or staging) | `numbat hook install --agent codex --settings /path/to/.codex/hooks.json` |
| Explicit OpenClaw package directory | `numbat hook install --agent openclaw --settings /gateway-state/extensions/numbat` |
| OpenClaw workspace development package | `numbat hook install --agent openclaw --settings /repo/.openclaw/extensions/numbat` |
| Managed/system path | `numbat hook install --agent codex --managed` |

`--settings PATH` selects one agent-specific file or directory and therefore
must be combined with `--agent`; numbat rejects `--settings` without `--agent`,
since agents use incompatible hook schemas. Some installers create owned
companion artifacts beside that target. Use it only for a location the upstream
agent actually reads, such as a documented project hook file or an alternate
agent home. `--settings` does not itself make a path
project-scoped, trusted, or active. Scope selection and vendor trust gates are
explained in [deployment.md](deployment.md#choose-an-install-scope).

`--managed` targets an upstream-defined machine policy file for Claude Code,
Codex, Cursor, Copilot CLI, Gemini CLI, Windsurf, Qwen Code, or Auggie. For a
single-file target, stage that schema with both `--managed --settings PATH`.
Auggie's explicit target is its final runtime path because adjacent generated
scripts are referenced absolutely. Staged files also retain the generator's
OS-specific command and absolute numbat binary path; use the deployment guide's
staging constraints. Exact paths and precedence are in
[deployment.md](deployment.md).

Default installs write the user-level config each agent reads. For admin-owned
rollouts, managed paths, output durability, and drift expectations, see
[deployment.md](deployment.md).

### Output and timeouts

Installed hooks default to `--emit findings --output=file`, writing findings
and applicable enforcement decisions to `$HOME/.numbat/findings.ndjson`. When
events or indicators are selected, the default becomes
`$HOME/.numbat/records.ndjson`. Change it with
`--output-file PATH`; repeat `--emit findings|events|indicators`, or use
`--emit all`. `--emit events` alone is collection-only and skips the local
rule engine; `--emit all` includes findings and runs it. Event records use
bounded previews by default; add
`--content full` to retain bounded, redacted conversation text when the agent
exposes it. Add `--include-reasoning` for source-exposed Pi, OpenCode, and
Kilo reasoning; hidden model chain-of-thought is not reconstructed. Repeat
`--output file --output http --http-url URL` to keep the file and also attempt
direct HTTP delivery. Direct HTTP alone is not durable: it has bounded in-memory
buffering, but no disk spool. numbat does not rotate output files itself; for
long-running all-event streams, let your log forwarder or OS retention policy
manage the file. Hook HTTP requests use a five-second timeout by default; change
it with `--http-timeout`. Agents normally wait for the callback process to exit,
so direct HTTP adds request latency on the hook path. HTTP auth secrets are never
written into hook settings;
when `--http-auth` is `bearer` or `hmac-sha256`, the installed hook reads
`NUMBAT_HTTP_TOKEN` or `NUMBAT_HTTP_HMAC_KEY` from the agent's runtime
environment. The live hook handler always reserves stdout for the agent's
allow/deny response (zero bytes on successful Kiro hooks), so `--output=stdout`
writes records to stderr in hook mode
and is mainly for manual monitor-mode testing. Enforce mode requires findings
and an out-of-band `file` and/or `http` sink; it rejects stdout output so
finding details cannot enter the immediate agent control response. The deployer
is responsible for restricting the agent's filesystem or network access to that
sink when stronger isolation is required.

For hook formats with a native timeout field, numbat writes an explicit finite
deadline on every installed command. Most fast lifecycle and tool callbacks use
10 seconds, prompt callbacks use 30 seconds, and stop callbacks use 45 seconds.
Gemini's millisecond-based hooks use five seconds; Junie's `UserPromptSubmit`
uses 10 seconds and `SessionEnd` uses two seconds.
This bounds a stuck callback instead of inheriting Claude Code or Codex's
ten-minute default. It is a process deadline imposed by the agent, distinct from
`--http-timeout`, which bounds one HTTP request inside numbat. Prefer file output
plus a forwarder when delivery may take longer than the hook's deadline.

Examples:

```
numbat hook install --agent codex --emit all --output-file ~/.numbat/codex.ndjson
numbat hook install --agent claude --output file --output http --http-url https://ingest.example/numbat
```

PowerShell uses the same flags:

```powershell
.\numbat.exe hook install --agent claude --emit all
.\numbat.exe hook install --agent codex --emit all
```

After installation, complete any vendor trust, consent, reload, version, or
feature-gate step before testing. The centralized
[trust and activation table](deployment.md#hook-trust-and-activation) explains
which scopes need action and how to validate them; `hook status` alone proves
only that numbat-owned configuration is present and readable.

For remote, cloud, or SSH sessions, install numbat where the agent process runs
or route supported telemetry to `collect`. Use the same agent-root environment
variables for install, status, and runtime. numbat accepts only strict JSON when
editing Auggie and Qwen settings; it refuses comments or trailing commas rather
than silently erasing them. Agent-specific event omissions and fidelity limits
are documented in
[agent-coverage.md](agent-coverage.md#material-exceptions-and-limits).

## Monitor and enforce

In default **monitor** mode, numbat never denies and preserves the host's normal
permission flow. `--enforce` allows a block only for an enforce-capable
pre-action callback and a matching rule with `enforce: true`. numbat has no
operator-configurable `allow` rule effect.
The shipped catalog is monitor-only; select blocking policy through operator
rules or same-id replacements.

See [enforcement.md](enforcement.md) for the control flow, clean-decision gate,
control-response/operator-record split, deny-message behavior, and rollout
checklist. See
[agent-coverage.md](agent-coverage.md#enforcement) for supported hosts, native
deny transports, and upstream coverage gaps.

Findings and enforcement decisions are deliberately separate records. A finding
means a rule matched. When findings are selected, a matched, enforce-capable
pre-action callback also records whether numbat computed `deny` or
`no_override`, with joins through `finding_ids` and `action_event_ids`. It is
written before the control response and does not prove response delivery or
host behavior.

On Windows, pre-tool checks classify native PowerShell commands and normalize
reported paths before CEL evaluation. Installed string commands use encoded
PowerShell so paths and output arguments are not reinterpreted by a shell.

Hook payloads are limited to 4 MiB. An oversized or malformed payload produces
no numbat deny response and is reported as a diagnostic.

## What hooks emit

Hooks emit the same normalized event vocabulary as scans: prompts, assistant
messages, tool calls/results, command execution/results, file reads/writes,
network indicators, permission requests/decisions, and session boundaries where
the agent exposes structured payloads. numbat maps only fields present in the
payload. It does not infer exit codes, durations, diffs, errors, or permission
verdicts from prose.

See [agent-coverage.md](agent-coverage.md) for the per-agent matrix, event
families, enforcement eligibility, and deferred surfaces.

## OTLP/HTTP collection

`collect` receives OTLP/HTTP **logs** from Claude Code, Codex, Gemini CLI, Qwen
Code, OpenCode, and compatible log exporters. It does not ingest OTLP traces or
metrics, so trace-only exporters such as VS Code Copilot Chat and OpenHands
observability should use hooks or a full OpenTelemetry collector. The `/v1/logs`
endpoint and per-agent setup are documented in [cli.md](cli.md#collect).

## Delivering files off-host

With file-only output, hooks do not wait on the network. The file is the durable
record stream; ship it with the fleet's existing log forwarder, EDR, or OS
retention tooling. Where the host has no such shipper, `numbat ship` is an
optional native forwarder that tails that file and
delivers eligible retained records at-least-once to an HTTP endpoint while their
input segments remain available; records larger than 8 MiB are skipped. See
[cli.md](cli.md#ship) for the complete limits. Use file-only hook output with
`ship` so the same record is not also sent through direct HTTP.
