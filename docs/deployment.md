# Deployment

Practical rollout patterns for forensic scans, live hooks, OTLP collection, and
durable local output.

numbat supports macOS, Linux, and native Windows endpoints.

## Choose a mode

| Goal | Command | Install required |
|---|---|---|
| Forensic review of existing agent activity | `numbat scan` / `numbat timeline` | no |
| Live hook capture | `numbat hook install --agent ...` | yes, per agent/user/path; managed where supported |
| Live OTLP/HTTP capture | `numbat collect` | yes, configure the agent exporter |
| Async HTTP delivery with no external shipper | `numbat ship` | no; runs as a long-lived process |
| Local inventory | `numbat agents --all` | no |

One release binary provides every mode. `hook install` writes that binary's
absolute path into agent-specific integration artifacts; each lifecycle event
launches a short-lived `numbat hook ...` callback. `ship` is an optional,
separate long-lived process of the same binary that tails the callback's file
output. It is not a second binary, daemon dependency, or hook receiver.

## Local use

```bash
numbat scan
numbat agents --all
numbat hook install --agent codex
numbat hook install --agent claude
numbat hook install --agent openclaw
```

Installed hooks default to a durable local file:

```text
~/.numbat/findings.ndjson
```

That stream includes findings and enforcement decisions for matched,
enforce-capable pre-action callbacks. Join an
`enforcement` record to its findings with `finding_ids`. Its `deny` or
`no_override` value is numbat's computed decision, not proof that the control
response was delivered or honored by the host.

Use `--emit all --output-file ~/.numbat/live.ndjson` when you want the complete
live event stream. It uses conversation previews by default; add
`--content full` only when bounded, redacted message text is required. Use
repeated `--output` flags when you also want a direct HTTP delivery attempt:

```bash
numbat hook install --agent claude \
  --emit all \
  --output file \
  --output http \
  --output-file ~/.numbat/live.ndjson \
  --http-url https://ingest.example/numbat
```

Direct HTTP is not a disk queue. If the endpoint is down, numbat reports delivery
failure for that run; it does not spool hours of records for later replay. Keep
file output enabled and let your existing log forwarder, EDR, or OS retention
policy ship and rotate the file. In `collect` mode, an OTLP success response
confirms local acceptance, not downstream acknowledgement by the HTTP sink.

`collect` has no client authentication or TLS. Keep its default loopback bind,
or place an off-loopback listener behind network controls and an authenticated
proxy.

Where the host has no external shipper, `numbat ship` is an optional native
forwarder that tails the file output and delivers eligible retained records
at-least-once while their input segments remain available, off the hook's
critical path (see [cli.md](cli.md#ship)). Records larger than 8 MiB are skipped.
It uses the capture file as its only on-disk queue and does not replace a mature
shipper where one already runs. Configure
the hook with file output only; combining direct HTTP with `ship` sends the same
records through both paths.

## Choose an install scope

Hook scope answers two questions: who controls the configuration, and which
agent sessions load it. Choose the boundary that matches the rollout.

| Scope | Command shape | What it means | Good fit |
|---|---|---|---|
| User (default) | `hook install --agent NAME` | Writes agent-specific configuration artifacts under one operating-system user's normal agent root. It usually applies to that user's projects and remains editable by that user. | Local use and pilots |
| Project / explicit | `hook install --agent NAME --settings PATH` | Targets one upstream-supported file or directory; some installers create owned companion artifacts beside it. It is project-scoped only when `PATH` is that agent's documented repository location. | One controlled workspace, or an alternate agent home |
| Managed / system | `hook install --agent NAME --managed` | Writes a vendor-defined machine policy file. The file can be admin-owned, but the hook still executes inside the agent user's process. | Durable fleet rollout where the vendor exposes a managed hook layer |

In practice, choose user scope for one developer across their normal
workspaces, project scope when a controlled repository should carry its own
configuration, and managed scope when administrators need a vendor-supported
machine policy. Not every agent exposes every scope; the managed table below
and the [coverage matrix](agent-coverage.md#matrix) are authoritative.

`--settings` is a path selector, not a trust or scope guarantee. Use it only for
a file or directory the target agent documents and loads. It can select a
project target, an alternate user home, or a staging target. When staging a
managed-policy artifact for MDM, pass both `--managed --settings PATH`;
`--settings` alone generates the agent's ordinary user/project schema.

Staging relocates the policy **file**, not the command embedded inside it. Build
each artifact on the target operating system with the same numbat release at
the same final absolute binary path used on endpoints. Generating directly on
the endpoint after placing the binary is safer when that invariant is awkward
to guarantee.

Most managed targets are a single relocatable file. Auggie is the exception:
its settings reference generated companion scripts by absolute path. For Auggie,
an explicit `--settings` value is the **final runtime location**, not a movable
staging path. Install it at the final endpoint path and deploy the settings plus
its adjacent `hooks/` directory together.

Use the same scope flags for `hook status` and `hook uninstall`. `--agent all`
targets every supported agent's **effective user** path, including documented
environment overrides; it does not add secondary profiles or install managed
policy. It excludes OpenHands because OpenHands has only repository hooks.

OpenClaw's default user target is the serving Gateway's global plugin config
root. It resolves in this order:

1. `$OPENCLAW_STATE_DIR/extensions/numbat/`
2. the directory containing `$OPENCLAW_CONFIG_PATH`, plus
   `extensions/numbat/`
3. `${OPENCLAW_HOME:-~}/.openclaw/extensions/numbat/`

Run numbat as the same operating-system user and with the same path environment
as the Gateway. OpenClaw's `--profile <profile>` flag projects concrete state
and config paths only inside that OpenClaw process; `OPENCLAW_PROFILE` alone is
not a path override. For a named profile, pass its concrete
`OPENCLAW_STATE_DIR` to numbat or use an explicit `--settings` package
directory, then use the matching profile flag for OpenClaw activation checks.
`--agent all` does not add secondary profiles.

At-rest discovery is a separate path decision: without an explicit state
override it can fall back to an existing
`${OPENCLAW_HOME:-~}/.clawdbot` when `.openclaw` is absent. The global plugin
loader does not make that legacy fallback. On a legacy-only installation,
migrate the state root or explicitly select `OPENCLAW_STATE_DIR`; alternatively
use `--settings` and pin that exact directory in `plugins.load.paths`. numbat
refuses a default install in this ambiguous legacy-only state instead of
creating `.openclaw` implicitly.

OpenClaw also loads workspace packages from
`<workspace>/.openclaw/extensions/numbat/`. Use
`--settings <workspace>/.openclaw/extensions/numbat` only for an intentional
development/project deployment. It is not the production default, and a
workspace package with the same ID can otherwise shadow an unpinned global
package.

OpenHands therefore always needs an explicit repository path:

```bash
numbat hook install --agent openhands \
  --settings /repo/.openhands/hooks.json
```

Managed installs are available for Claude Code, Codex, Cursor, Copilot CLI,
Gemini CLI, Windsurf, Qwen Code, and Auggie:

| Agent | macOS / Linux | Windows | Important policy behavior |
|---|---|---|---|
| Claude Code | macOS: `/Library/Application Support/ClaudeCode/managed-settings.d/numbat.json`; Linux: `/etc/claude-code/managed-settings.d/numbat.json` | `C:\Program Files\ClaudeCode\managed-settings.d\numbat.json` | Claude uses one active managed delivery tier; server, MDM/OS, and file tiers do not merge. Check `/status` and place the hooks in the tier your fleet actually activates. |
| Codex | `/etc/codex/requirements.toml` | `C:\ProgramData\OpenAI\Codex\requirements.toml` | Adds marked managed hook blocks and pins `[features].hooks=true`; installation refuses an existing `hooks=false` until policy is reconciled. Set `allow_managed_hooks_only=true` separately if administrators need to suppress non-managed hooks. |
| Cursor | macOS: `/Library/Application Support/Cursor/hooks.json`; Linux: `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` | All matching Enterprise, Team, Project, and User hooks run. Only conflicting responses use Enterprise → Team → Project → User priority; project hooks also require a trusted workspace. |
| Copilot CLI | `/etc/github-copilot/policy.d/numbat.json` | `C:\ProgramData\GitHub\Copilot\policy.d\numbat.json` | Policy hooks are machine-wide and cannot be disabled by user or repository `disableAllHooks` settings. Protect both the policy file and binary. |
| Gemini CLI | macOS: `/Library/Application Support/GeminiCli/settings.json`; Linux: `/etc/gemini-cli/settings.json` | `C:\ProgramData\gemini-cli\settings.json` | The system file is administrator-controlled and wins for scalar settings, but hook arrays concatenate across sources. User, project, and system hooks can all run, and any `BeforeTool` block wins. |
| Windsurf | macOS: `/Library/Application Support/Windsurf/hooks.json`; Linux: `/etc/windsurf/hooks.json` | `C:\ProgramData\Windsurf\hooks.json` | System hooks are administrator-owned and run first, but user and workspace hooks are merged and also execute. |
| Qwen Code | macOS: `/Library/Application Support/QwenCode/settings.json`; Linux: `/etc/qwen-code/settings.json` | `C:\ProgramData\qwen-code\settings.json` | System settings override user and project settings. `QWEN_CODE_SYSTEM_SETTINGS_PATH` can relocate the file. |
| Auggie | `/etc/augment/settings.json` | `C:\ProgramData\Augment\settings.json` | The system file cannot be overridden by lower-precedence user or project settings. Generated scripts live beside it under `hooks/` and settings contain their absolute final paths. |

A mandatory managed numbat hook and an exclusive hook policy are different.
Cursor, Gemini, Windsurf, and Copilot combine applicable lower-scope hooks. Where
strict exclusivity is required, set Claude's `allowManagedHooksOnly:true` or
Codex's `allow_managed_hooks_only=true` separately; numbat does not set either
automatically. Installing a mandatory numbat sensor does not itself prohibit
other hooks.

Run direct managed installs as root or Administrator. A typical managed hook
uses a literal `$HOME` output path so the callback resolves the monitored
user's profile, not the installer's:

```bash
sudo numbat hook install --agent codex --managed --emit all \
  --output-file '$HOME/.numbat/live.ndjson'
```

Factory Droid uses Factory's vendor management plane rather than a documented
local system file. That plane can distribute authoritative organization hooks
and, with `allowManagedHooksOnly`, suppress user and project hooks; numbat does
not write the remote policy. OpenCode does publish highest-priority OS-wide
managed JSON directories and macOS managed preferences, but those locations are
not documented as local source-plugin directories. Because numbat generates a
local TypeScript plugin, it does not yet expose an OpenCode `--managed` target;
deploy its supported user plugin per user instead. OpenClaw similarly exposes
per-state-directory native plugins, not a documented machine-policy plugin
path, so it has no `--managed` target. Deploy it for the Gateway service user
and manage OpenClaw's plugin policy declaratively instead. Agents not listed in
the table have no first-class `--managed` target in numbat; use their documented
user/project mechanism or vendor management plane instead of inventing a policy
path.

## Hook trust and activation

Writing valid configuration does not prove that an agent loaded or authorized
it. Install scope and trust are separate decisions: user, project, and managed
describe where configuration lives and who controls it; the agent still decides
whether that source is enabled, trusted, and loaded. A project hook can wait on
workspace trust, while a managed hook can still depend on a feature gate or
reload.

Only the rows below have a material documented trust, consent, or plugin-policy
gate. Unlisted repository scopes may load without a separate per-hook prompt,
subject to host folder trust or organization/feature enablement; treat committed
hook configuration as executable code. Generate hooks with the final absolute
numbat binary path: moving the binary or changing baked-in arguments such as
output flags changes the hook definition and can trigger a new review.

### Trust, consent, and policy exceptions

Most user hooks load without a separate approval. These agents add a material
trust or consent gate:

| Agent and scope | Required action |
|---|---|
| Codex user or project | Review the current hook definitions in `/hooks` or Settings > Hooks. Trust is tied to the definition, so reinstalling with a different command, arguments, or timeout can require review again. A project `.codex` layer must also be trusted. Managed definitions are policy-trusted. |
| Claude Code project/local | Accept Claude's workspace trust before relying on `.claude/settings.json` or `.claude/settings.local.json`. User hooks have no separate hook prompt. Server-managed hooks on v2.1.211+ require interactive security approval; rejection exits. Noninteractive print/SDK mode (`-p`) applies them for that run without persisting approval. Verify the active source with `/status`. |
| Cursor project | Trust the workspace before relying on `.cursor/hooks.json`. User, Team, and Enterprise hooks have no separate per-hook consent prompt. |
| Gemini CLI project | Gemini fingerprints project hooks by `name` plus `command`. A new identity triggers a warning, then executes and is recorded as trusted; the warning is not an approval gate. If optional folder trust is enabled, an untrusted folder causes project settings and hooks to be ignored. |
| Qwen Code project | Optional folder trust can prevent project settings from loading, and `disableAllHooks` can suppress them. This is a load/enable gate, not per-command consent. |
| Copilot CLI project | The CLI asks whether to trust a repository directory when launched there. Managed policy hooks remain available regardless of folder trust and have no separate per-hook approval. |
| Grok Build project | Approve repository `.grok/hooks` through `/hooks-trust`. The default user hook directory does not require this project step. |
| Factory Droid project | Trust the folder before relying on repository `.factory` configuration, including hooks and MCP servers. User hooks do not need this project step. |
| Hermes | Consent is per exact event/command pair. Interactive CLI can approve first use. Gateway, cron, and CI must start with `--accept-hooks`, `HERMES_ACCEPT_HOOKS=1`, or exact allowlist entries; otherwise new hooks remain unregistered. `hooks_auto_accept:true` accepts future commands and should be an explicit policy choice. Consent does not hash script contents, so run `hermes hooks doctor` after script changes. |
| OpenClaw Gateway user/config root | Treat the package as executable Gateway code and complete the policy checklist below. Eight baseline callbacks include inbound message content when the channel emits it; two model callbacks require `allowConversationAccess:true`. WhatsApp inbound callbacks have a separate channel opt-in. |

### OpenClaw production policy

Install the package as the operating-system account that runs the Gateway. An
administrator staging it as another account must deliberately set ownership
and restrictive permissions before startup; OpenClaw rejects suspiciously
owned or world-writable plugin sources. The generated package embeds numbat's
absolute binary path, so that binary and package must exist inside the serving
host or container.

OpenClaw's plugin allowlist is exclusive. If `plugins.allow` already exists,
merge `numbat` into it without dropping other approved IDs. If introducing an
allowlist, enumerate every plugin that should continue to load. Add `numbat` to
the allowlist before running `openclaw plugins enable numbat`; otherwise the CLI
can report the plugin as blocked. `plugins.deny` wins over the allowlist, and
`plugins.enabled:false` disables all plugins.

For production, also pin the generated package's exact absolute directory in
`plugins.load.paths`. Configured load paths take precedence over workspace and
global discovery, preventing a workspace package with the same `numbat` ID from
shadowing the approved package. Merge these fields into the selected Gateway's
existing JSON5 configuration; do not replace unrelated plugin IDs, paths, or
entries:

```json5
plugins: {
  enabled: true,
  allow: [/* existing approved IDs */, "numbat"],
  load: {
    paths: [
      /* existing approved paths */
      "/absolute/config-root/extensions/numbat",
    ],
  },
  entries: {
    /* existing entries */
    numbat: {
      enabled: true,
      // Opt in only when model/harness conversation access is approved.
      hooks: { allowConversationAccess: true },
    },
  },
}
```

The conversation-access grant enables `llm_input` and `llm_output`. Those hooks
forward only the current model input or nonempty assistant text and omit system
prompt, history, reasoning, tools, usage, and raw message objects. Omit the grant
when that content is outside collection policy; the eight baseline callbacks
still load. Review inbound-message collection separately because
`message_received` can already contain the current message.

For MDM or service management, install in the Gateway service user's context
and manage that user's OpenClaw configuration declaratively. There is no numbat
`--managed` target; preserve the same config-root or profile selection in every
activation command.

Verify the serving Gateway, not just the files on disk:

1. Confirm OpenClaw v2026.7.1 or newer. Keep numbat's generated ten-second
   `before_tool_call` host timeout. Any override must remain strictly above the
   nine-second child deadline; an equal or shorter deadline can race into
   OpenClaw's fail-closed `before_tool_call` host timeout.
2. Restart the actual Gateway with `openclaw gateway restart`, then run
   `openclaw gateway status --deep --require-rpc`.
3. Run `openclaw plugins inspect numbat --runtime --json`. Confirm the reported
   source is the exact pinned package. Expect eight active callbacks without
   conversation access and ten with it; investigate any other load, trust, or
   provenance diagnostic.
4. For a pilot installed with `--emit events` or `--emit all`, trigger one benign
   covered action and confirm that its numbat record reaches the expected local
   and remote destinations. Under the default findings-only mode, use a
   controlled non-destructive action that intentionally matches a test rule.

Cold `plugins list` or plain `inspect` proves only registry/manifest state. In a
container, restart the `openclaw gateway run` child and ensure the package and
embedded absolute numbat path both exist inside that runtime.

### Reload and feature gates

| Agent | Activation check |
|---|---|
| Factory Droid | Ensure the effective hook map does not set `hooksDisabled:true`. A default install safely consolidates the older `.factory/hooks/hooks.json` source into canonical `.factory/hooks.json`. A running Droid snapshots external changes, so review and apply them in `/hooks` or start a new session. |
| Hermes Gateway | Restart an active Gateway, then run `hermes hooks list` and `hermes hooks doctor`. |
| OpenClaw | Complete the policy and serving-Gateway verification above with the same config-root environment or `--profile` selection used for installation. |
| Amp | Run `plugins: reload` after installation. |
| Cline | Restart the current CLI/SDK. Legacy editor hooks under `~/Documents/Cline/Hooks` also need the Hooks-tab toggle. |
| Qwen Code | Use version 0.17.0 or newer and confirm `disableAllHooks` is not active. |
| Kiro IDE / CLI v3 | The default file requires IDE 1.0.182+ or CLI 2.13.0+ launched with `kiro-cli --v3`. Confirm the entries are enabled in the IDE's Agent Hooks panel. `KIRO_HOME` relocates the CLI target only; when both roots are active, install and check the IDE's `~/.kiro/hooks/numbat.json` separately with `--settings`. |
| Goose | Confirm `numbat` is not listed in `disabledPlugins`. |
| Kilo Code | Reload or restart after install and do not use `KILO_PURE=1`, which disables external plugins. |
| OpenHands | Install per repository; the next repository conversation loads the file. |
| Crush | Restart after an external configuration edit. |
| Junie CLI | Use the Early Access CLI and restart it. Hooks run in interactive and batch CLI hosts, not ACP or server mode. |
| VS Code Copilot | Hooks are a Preview feature and can be disabled by organization policy. Confirm the file appears in the Load Hooks log and GitHub Copilot Chat Hooks output before testing. |
| Cursor | Cursor watches hook configuration and reloads it automatically. Verify it in Customize > Hooks and hook output; restart only if the new configuration does not appear. |
| Gemini CLI | After an external user, project, or system settings deployment, start a new Gemini CLI process, then confirm the hook in `/hooks`. |
| Windsurf / Devin Desktop | Dashboard hooks load when Devin Desktop starts; system-file hot reload is not documented. After external MDM deployment, restart the app for a deterministic rollout, then trigger a benign covered action. |

### What status proves

`numbat hook status` verifies only that numbat-owned configuration is present
and readable at the requested scope. It does **not** prove that the agent loaded
or trusted the hook, that a particular lifecycle event fires, or that a sink
acknowledged the resulting record.

For OpenClaw specifically, status validates the owned manifest and package
contract plus the generated source checksum. That detects drift; it is not a
signature or proof of provenance. Status does not read plugin policy, contact
the Gateway, or prove runtime hook registration.

A rollout health check should validate all four layers:

1. Run `hook status` with the same `--managed` or `--settings` selection used
   for installation.
2. Inspect the agent's effective hook/trust view where it exposes one.
3. With events enabled, perform a benign known action and confirm a local numbat
   record appears. Under findings-only mode, use a controlled non-destructive
   action that intentionally matches a test rule.
4. Confirm the forwarder or remote sink acknowledges that record.

## Fleet rollout

1. Place the final numbat binary at an administrator-controlled absolute path.
2. Inventory the agents actually deployed, then select user, project, or managed
   scope for each one.
3. Install only the approved targets and complete their trust/activation steps.
4. Perform the four-layer health check above before enabling enforcement.
5. Rerun the idempotent installer after binary, output, or policy changes.

The endpoint platform remains responsible for binary distribution, choosing
the target users and agents, rerunning the idempotent install after upgrades,
injecting sink credentials into the agent environment, and supervising any
`ship` process. A small MDM/script wrapper is normally enough; hook-schema
editing belongs to `numbat hook install`, not to that wrapper.

Default hook installs write user-owned configuration artifacts each agent reads.
A user who owns those artifacts can edit or remove them. Hook mode is visibility
into endpoint agent activity, not a tamper-proof insider control by itself.
Parser-backed agents can still be investigated with `scan` after the fact.

Managed configuration protects the policy file, not everything the user process
touches. Keep the binary admin-controlled. A `$HOME/.numbat/...` output remains
in the user's profile unless its ACL says otherwise, so forward records promptly
to an admin-controlled sink when tamper resistance matters. An external
`--rules-dir` is part of this policy surface: deploy it outside agent workspaces
and make it read-only to the monitored user when enforcement must resist local
tampering. Official binaries embed the shipped catalog; a private immutable
catalog can instead be built after editing `rules/<group>/*.yaml`. GUI-launched
agents may not inherit secrets exported by a root or login-shell installer; make
`NUMBAT_HTTP_TOKEN` or `NUMBAT_HTTP_HMAC_KEY` available to the actual agent
process. File output plus a managed forwarder is usually safer than direct HTTP
for fleet GUI agents.

## MDM pilot

For a small pilot, distribute the binary and run user-context inventory and
install scripts. Use a managed package when you need signed placement, version
inventory, or managed upgrade and uninstall. numbat does not require a
background collector package for discovery or hook capture.

Suggested pilot layout:

```text
/usr/local/bin/numbat                # or /opt/numbat/bin/numbat
/var/log/numbat/agents.<user>.json   # root-owned discovery output
~/.numbat/live.ndjson                # per-user live hook record stream
```

Daily discovery should run in the user context, because most agent configs and
artifacts live under that user's home. If your macOS MDM script runs as root,
resolve the active console user first and execute numbat with that user's
`HOME`. On Linux, use the equivalent user-context timer or MDM runner for the
target user.

```sh
#!/bin/sh
set -eu

NUMBAT=/usr/local/bin/numbat
LOG_DIR=/var/log/numbat
CONSOLE_USER=$(stat -f %Su /dev/console)

case "$CONSOLE_USER" in
  ""|root|loginwindow|_mbsetupuser) exit 0 ;;
esac
USER_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')
[ -n "$USER_HOME" ] || exit 0

umask 077
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"
tmp="$LOG_DIR/agents.$CONSOLE_USER.tmp"

sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$NUMBAT" agents --all --format json > "$tmp"
mv "$tmp" "$LOG_DIR/agents.$CONSOLE_USER.json"
```

For hook rollout, run a separate user-context script at login or on a recurring
MDM cadence. Start with default user paths, then move supported agents to managed
policy after the pilot. Populate `TARGET_AGENTS` from inventory and an approved
rollout list; do not create every agent's default config path on every endpoint.
Use project paths only for known workspaces you manage, because each path needs
its own deployment and may need the agent's project-trust step.

```sh
#!/bin/sh
set -eu

NUMBAT=/usr/local/bin/numbat
CONSOLE_USER=$(stat -f %Su /dev/console)

case "$CONSOLE_USER" in
  ""|root|loginwindow|_mbsetupuser) exit 0 ;;
esac
USER_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')
[ -n "$USER_HOME" ] || exit 0
HOOK_OUT="$USER_HOME/.numbat/live.ndjson"

# Set this from the intersection of inventory and your approved rollout list,
# for example: TARGET_AGENTS="claude codex"
: "${TARGET_AGENTS:?set TARGET_AGENTS to approved agents detected for this user}"

# Codex user hooks are skipped until approved in /hooks. Use a separate
# elevated --managed install for unattended Codex rollout.
for agent in $TARGET_AGENTS; do
  sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$NUMBAT" hook install --agent "$agent" \
    --emit all \
    --output file \
    --output-file "$HOOK_OUT"
done
```

The `copilot` target covers both Copilot CLI and VS Code Copilot Chat because
they load the same user hook file.

For an OpenClaw target, the loop above must run as the Gateway service account
with its config-root environment. Target a named profile separately with its
concrete `OPENCLAW_STATE_DIR` or with `--settings`, and use the matching
`--profile` flag for every OpenClaw command. Apply the
[OpenClaw production policy](#openclaw-production-policy)
through MDM or service configuration: merge the exclusive allowlist, enable and
path-pin the package, restart the actual Gateway, then verify its exact runtime
source and the expected eight or ten callbacks.

For a container or remote Gateway, install the package and numbat binary in that
runtime filesystem; installing them only on an administrator's workstation or
container host provides no coverage.

Add any other target from the
[coverage matrix](agent-coverage.md#matrix) only when inventory confirms that
agent is in the pilot population. Install OpenHands separately for each approved
repository. For managed production delivery, either run `--managed` elevated on
the endpoint or, for a single-file target, generate a staging artifact with
**both** `--managed --settings STAGING_PATH` and deploy it through MDM. A staged
artifact must be generated on the target OS from the same final absolute numbat
path used on endpoints. Install Auggie at its final runtime path because its
companion-script references are not relocatable.

For a lower-volume steady-state stream, keep the local file sink and emit only
findings plus deduplicated indicators:

```sh
sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$NUMBAT" hook install --agent codex \
  --emit findings --emit indicators \
  --output file \
  --output-file "$USER_HOME/.numbat/findings.ndjson"
```

For a full event stream plus direct HTTP delivery, keep the file sink as the
durable record stream:

```sh
sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$NUMBAT" hook install --agent codex \
  --emit all \
  --output file \
  --output http \
  --output-file "$USER_HOME/.numbat/live.ndjson" \
  --http-url https://ingest.example/numbat
```

Complete the relevant [trust and activation](#hook-trust-and-activation) step
for every target. With events enabled, exercise a benign action and verify both
local capture and delivery; under findings-only mode, use a controlled
non-destructive action that intentionally matches a test rule. Do not infer
runtime health from a successful config write.

Start in monitor mode. After validating payload and output coverage, deploy a
validated operator policy in which the selected additive rules or same-id
replacements set `enforce: true`, then reinstall one agent in enforce mode:

```sh
numbat hook install --agent gemini --enforce --emit all \
  --rules-dir /etc/numbat/rules
```

Enforcement is available for rows marked **yes** in the
[coverage matrix](agent-coverage.md#matrix). numbat withholds its deny response
on an uncertain decision path, but the host can still deny independently; see
[enforcement.md](enforcement.md) for decision and failure semantics and
[agent-coverage.md](agent-coverage.md#enforcement) for host coverage.

### Windows fleet pilot

Place the binary in an administrator-controlled location such as
`C:\Program Files\numbat\numbat.exe`; hook config must not point at a binary the
monitored user can replace. Run user-level installs in each target user's
context. Run managed installs elevated:

```powershell
$Numbat = "C:\Program Files\numbat\numbat.exe"
& $Numbat hook install --agent claude --managed --emit all `
  --output-file '$HOME/.numbat/live.ndjson'
& $Numbat hook install --agent codex --managed --emit all `
  --output-file '$HOME/.numbat/live.ndjson'
```

`$HOME` is intentionally left literal in managed hook config and resolves in
the agent user's process. Output under the user profile inherits Windows ACLs;
for another destination, create an ACL-protected parent directory first. An
Intune/SYSTEM inventory task must impersonate each user or pass explicit
`--path` values, because the system account has a different profile.

## Operational checks

```bash
numbat agents --all
numbat hook status --agent codex
numbat hook status --agent codex --managed
tail -f ~/.numbat/live.ndjson
numbat scan --path ~/.codex --emit findings --emit indicators
```

Windows PowerShell equivalents:

```powershell
.\numbat.exe agents --all
.\numbat.exe hook status --agent codex
.\numbat.exe scan --path "$HOME\.codex" --emit findings --emit indicators
Get-Content "$HOME\.numbat\live.ndjson" -Wait
```

For live OTLP/HTTP, run `numbat collect` and point the agent exporter at
`http://127.0.0.1:4318/v1/logs` when the agent supports OTLP/HTTP logs. See
[cli.md](cli.md#collect) for per-agent exporter notes.

## Primary operational references

- Codex: [hooks](https://learn.chatgpt.com/docs/hooks) and
  [managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
- Claude Code: [settings](https://code.claude.com/docs/en/settings) and
  [server-managed settings](https://code.claude.com/docs/en/server-managed-settings)
- Gemini CLI: [hooks](https://geminicli.com/docs/hooks/),
  [hook trust](https://geminicli.com/docs/hooks/best-practices/), and
  [trusted folders](https://geminicli.com/docs/cli/trusted-folders/)
- Cursor: [hooks, scope, and reload](https://cursor.com/docs/hooks)
- Windsurf / Devin Desktop: [Cascade hooks and enterprise distribution](https://docs.devin.ai/desktop/cascade/hooks)
- VS Code Copilot: [agent hooks](https://code.visualstudio.com/docs/agent-customization/hooks)
- Qwen Code: [hooks and folder trust](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/)
- Grok Build: [hooks and project trust](https://docs.x.ai/build/features/hooks)
- Hermes: [shell-hook consent](https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks/)
- Factory Droid: [hook files and loading](https://docs.factory.ai/reference/hooks-reference)
- Copilot CLI: [hooks and managed policy](https://docs.github.com/en/copilot/reference/hooks-reference)
- Auggie: [hooks and configuration scope](https://docs.augmentcode.com/cli/hooks)
- OpenHands: [repository hooks](https://docs.openhands.dev/openhands/usage/customization/hooks)
- OpenCode: [managed settings](https://opencode.ai/docs/config/#managed-settings)
- OpenClaw: [plugin loading and policy](https://docs.openclaw.ai/plugins),
  [typed hooks](https://docs.openclaw.ai/plugins/hooks), and
  [plugin CLI](https://docs.openclaw.ai/cli/plugins)
- Kiro: [hook management](https://kiro.dev/docs/hooks/management/) and
  [IDE global-hook release](https://kiro.dev/changelog/ide/1-0-182/)
