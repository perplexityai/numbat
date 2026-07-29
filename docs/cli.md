# CLI reference

This page describes every `numbat` subcommand, its flags, and its output.
For an overview and quick start, see the [README](../README.md); for rule
authoring, see [rules.md](rules.md); for shipped coverage, see the
[built-in catalog](rule-catalog.md); for wiring up live capture, see
[live-capture.md](live-capture.md); for blocking semantics and failure
behavior, see [enforcement.md](enforcement.md).

```
numbat agents [--all]                    report detected agents; --all includes absent agents
numbat scan [--agent NAME ... | --path FILE|DIR ...]
                                        scan agent artifacts; emit records (NDJSON)
numbat timeline [--agent NAME ... | --path FILE|DIR ...]
                                        reconstruct a per-session chronological view
numbat collect [--addr HOST:PORT]        receive OTLP/HTTP protobuf logs; emit records
numbat ship --input-file F --http-url U  tail a local record file to an HTTP endpoint
numbat hook EVENT --agent NAME           live integration callback (normally not run by hand)
numbat hook install --agent NAME|all     install numbat's live integrations
numbat hook uninstall --agent NAME|all   remove numbat-owned live integrations
numbat hook status [--agent NAME|all]    inspect numbat-owned integration configuration
numbat rules check                       validate and compile rules; run companion tests
numbat rules list                        list effective compiled rule ids
numbat rules test --fixture FILE         evaluate rules against NDJSON events
numbat case build <case-id> --from FILE  bundle findings, enforcement decisions, and cited events
numbat case verify DIR                   check a bundle against its manifest digests
numbat version                           print version and schema version
```

Every command supports `--help`; `numbat help <subcommand>` prints subcommand
help to stdout.

`scan`, `collect`, `hook EVENT`, `hook install`, and `rules check|list|test`
accept `--rules-dir DIR` (repeatable) to add operator rules or replace embedded
rules by id, and `--no-builtin-rules` to load only operator rules. For live hook
behavior and installation, see [live-capture.md](live-capture.md).
`--no-builtin-rules` requires at least one `--rules-dir`.

## agents

`agents` is a read-only discovery report for supported local agents. By default
it shows agents with local signals on this machine: a config directory, at-rest
artifact, wired hook or plugin, or unreadable hook configuration. `--all`
includes absent supported agents. Each row reports whether the agent has a
local config signal (`CONFIG`), whether numbat found at-rest
artifacts (`ARTIFACTS`), its live capture mode (`LIVE`), whether numbat is wired
there (`WIRED`), and the next useful command (`NEXT`). It makes no changes,
executes no agent binary, and supports text (default) or JSON output.

For OpenClaw, `WIRED=yes` means the native package is present and readable in
the selected Gateway plugin config root and matches numbat's manifest, package,
and generated-source checksum contract. It does not prove provenance or that
OpenClaw enabled, allowlisted, loaded, or registered it in the serving Gateway.

### agents flags

```
--all                        include absent supported local agents
--format text|json           output format (default text)
```

```
numbat agents
numbat agents --all
numbat agents --format json
```

## scan

`scan` parses agent artifacts at rest, runs the rules over the reconstructed
event stream, and writes one NDJSON record stream.

With no `--agent` or `--path`, `scan` checks every existing parser-backed root in
the [coverage matrix](agent-coverage.md#matrix). Repeat `--agent` to limit that
automatic discovery, for example `--agent claude --agent codex`. Use repeated
`--path` instead for mounted or acquired artifacts; the two flags cannot be
combined because `--agent` is a discovery filter, not a parser override.

On native Windows, default `~` roots resolve under `%USERPROFILE%`; WSL has its
own Linux home. Classification is path-based, so preserve each vendor's
documented directory layout when copying artifacts. A bare JSONL outside a
recognized layout falls back to Claude Code and must not be used for another
agent's transcript.

### scan flags

```
--agent NAME                  limit automatic discovery to a parser-backed agent
                              (repeatable; cannot be combined with --path)
                              claude|codex|copilot|cowork|cursor|gemini|kimi|
                              openclaw|opencode|pi|windsurf
--path FILE|DIR              artifact to scan (repeatable; defaults to known
                             agent locations under $HOME plus supported
                             agent home/data env overrides)
--case-id ID                 case identifier stamped on every emitted event and derived finding
--emit KIND                  record kind to emit: findings, events, indicators,
                             or all (repeatable; default findings)
--profile evidence|full      capture depth; evidence omits reasoning/model context
                             (default evidence)
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
--output SINK                record sink: stdout, file, or http
                             (repeatable; default stdout; stdout cannot be combined)
--output-file PATH           destination path (required when output includes file)
```

HTTP sink flags (used when output includes `http`):

```
--http-url URL               ingest URL (required)
--http-auth none|bearer|hmac-sha256        auth mode (default none)
--http-batch-size N          target records per POST; may flush early
                             (default 500)
--http-gzip                  gzip the POST body
--http-timeout DURATION      request timeout (default 30s)
--http-sig-header NAME       header carrying the hmac-sha256 signature
                             (default X-Numbat-Signature)
--http-timestamp-header NAME header carrying the signed timestamp; empty signs
                             the bare body (default X-Numbat-Timestamp)
--http-allow-insecure        allow plain http to non-loopback hosts
```

HTTP auth secrets are read from the environment only, never passed as flags:
`bearer` → `NUMBAT_HTTP_TOKEN`, `hmac-sha256` → `NUMBAT_HTTP_HMAC_KEY`.

HTTP sinks send `application/x-ndjson` and do not follow redirects. Bearer mode
uses `Authorization: Bearer <token>`. HMAC mode writes
`sha256=<lowercase-hex-hmac>` to `X-Numbat-Signature` by default. With the
default timestamp header, `X-Numbat-Timestamp` contains Unix seconds and the
signed bytes are `<unix-seconds>.<exact-wire-body>`. Setting
`--http-timestamp-header ''` signs only the wire body. When gzip is enabled, the
signature covers the compressed body. Receivers should reject stale timestamps
and compare signatures in constant time.

With file output, `scan` creates or truncates the destination and requires its
parent directory to exist. `collect` and `hook` append and create missing parent
directories.

Repeat `--output` to fan out the same NDJSON stream to more than one sink, for
example `--output file --output http`. Direct HTTP is not a durable queue. Its
16 MiB memory buffer rejects any larger record. A failed batch is retried
after the retry interval when another record arrives, then once more at close;
it is never spooled to disk. After a delivery failure, a full buffer drops the
oldest complete records to retain the newest records; the close error reports
the drop count. A retry after an ambiguous transport failure can duplicate a
batch, so receivers should tolerate repeated record ids. For production
retention, keep file output and let a log forwarder ship it. numbat does not
rotate files itself.

```
# scan only automatically discovered Codex artifacts
numbat scan --agent codex

# scan several explicit roots by repeating --path
numbat scan --path ~/.claude/projects --path ~/.codex --path ~/.gemini

# stream HMAC-signed records to an HTTP ingest endpoint (key from the environment)
NUMBAT_HTTP_HMAC_KEY=... numbat scan \
  --output http --http-url https://ingest.example/numbat \
  --http-auth hmac-sha256 --http-gzip
```

### Emit modes

- `findings` (default) — rule matches over the event stream.
- `events` — the full typed event timeline.
- `indicators` — a deduplicated projection of indicators mined from
  the event stream (domains, IPv4/IPv6 addresses, URLs, emails, and
  md5/sha1/sha256 hashes), each with a count and first/last-seen window. Values
  are redacted before extraction (URL userinfo stripped, query secrets masked),
  defanged forms (`hxxp`, `[.]`) refanged, then canonicalized and deduped.
  Non-actionable noise (loopback, RFC1918/link-local/multicast IPs, `localhost`,
  `*.local`) is filtered out by default. Shared-hosting domains are retained for
  downstream enrichment or threat-intelligence correlation. Each indicator
  carries `source_agent`, `sample_event_id`, `sample_session_id`, and
  `sample_project_path_hash` as a pivot back to one representative observation.
  Here, `source_agent` belongs to that sample; the indicator may also have been
  observed from other agents.
  Project-path hashes are stable, unsalted join keys, not anonymization; treat
  them as pseudonymous endpoint metadata. Use `--emit all` when you need every
  contributing event. The in-memory catalog keeps at most 10,000 unique
  indicators per run and 256 candidates from one field; reaching either limit
  emits one warning and makes a scan summary `partial`.
  `scan` emits one final record per `(type,value)`. `collect` emits a cumulative
  snapshot when the count changes; consumers should upsert by
  `(run_id,type,value)`.
- `--emit findings --emit indicators` — findings plus the deduplicated indicator
  projection, without the full event stream. This is the low-volume mode for
  continuous monitoring sinks that want alerts and indicators but not every
  event.
- `all` — events, findings, and indicators; enforcement records and scan
  summaries are emitted automatically when applicable.

An indicator record (a `https://get.example.sh/install` URL seen twice):

```json
{
  "schema_version": "0.2.0",
  "record_type": "indicator",
  "run_id": "run-example-01",
  "endpoint": {
    "hostname": "developer-workstation",
    "os": "linux",
    "arch": "arm64",
    "username": "agent",
    "uid": "10001"
  },
  "type": "url",
  "value": "https://get.example.sh/install",
  "count": 2,
  "first_seen": "2026-06-02T10:00:00Z",
  "last_seen": "2026-06-02T10:04:12Z",
  "source_agent": "codex",
  "sample_event_id": "evt_01",
  "sample_session_id": "s1",
  "sample_project_path_hash": "sha256:6780eeb53603bd5da1c0ec3e25d9e94d8be668392f24def8903a2a34f8e3fcb0"
}
```

### Capture profiles

- `evidence` (default) — evidence-bearing events: prompts, assistant messages,
  tool and command calls and their results (including `command.result` with an
  exit code), file operations, config and MCP changes, network indicators, and
  session lifecycle. It omits reasoning blocks and low-evidentiary model/session
  context.
- `full` — everything in `evidence` plus `message.reasoning` and model/provider
  session context. Use it only when the additional context is required; it has
  higher volume and sensitivity.

`model`, `model_provider`, and `entrypoint` are source-specific and omitted when
the source does not provide them; numbat does not infer these values.

Finding `timestamp` is the matched event's activity time (the completing event
for a sequence); `detected_at` is when numbat created the finding. `timestamp`
is omitted when that event has no valid timestamp.

### The record stream

numbat writes typed NDJSON streams. Each record carries a `record_type` (`event`,
`finding`, `enforcement`, `indicator`, or `scan_summary`) plus a `run_id` and
`schema_version` (`0.2.0`). Every line carries an `endpoint` object with
`hostname`, `os`, `arch`,
`username`, and `uid`; set `NUMBAT_DEVICE_ID` to add a stable opaque
`endpoint.device_id` for fleet joins.
`enforcement` is hook-only; `scan_summary` is scan-only.

Event and finding value fields are redacted before emission. Masking covers
credential-bearing URL query values, secret-like assignments, self-identifying
token formats, a URL userinfo password (emitted as
`postgres://user:%5Bredacted%5D@host:5432/db`, percent-encoded so the URL still
parses), and an `Authorization: Bearer` credential. Event/timeline
output keeps a readable, redacted `project_path`; findings and indicators use
`project_path_hash` / `sample_project_path_hash` for joins. On findings,
`redacted:true` means at least one emitted finding field was masked. File-backed
evidence refs keep `local_path` so an investigator can reopen the source; live
hook and OTLP refs may omit it because there is no source file.
Semantic `project_path`, `file_path`, and `observed_file_path` fields always use
`/` separators; `evidence.local_path` keeps the endpoint's native path syntax.
A scan stream always terminates with a `scan_summary` whose `status` is
`complete`, `partial`, or `error`. `partial` covers parsed runs with artifact
failures or record-delivery failures observed before the summary was written.
Operational diagnostics normally use a separate NDJSON stream on stderr. After
an enforce-mode hook opens its required file or HTTP sink, diagnostics are
written to that sink so details stay out of the host control channel.
Exit codes: `0` when the scan parses at least one artifact and output delivery
succeeds; `1` when initialization fails before scanning (home/default-root
discovery, `--rules-dir` validation, or rule-engine compilation), when zero
artifacts are discovered, when discovered artifacts produce no parsed records,
or when output delivery fails (HTTP delivery or sink close); `2` on a usage
error.
The terminal `scan_summary.status` (`complete` | `partial` | `error`) records the
run outcome at serialization time. A failure sending the final HTTP batch can
only be reported through stderr and the process exit code.

With HTTP output, the summary is serialized before its final batch is sent, so
`http_batches_sent` and `http_records_sent` cover earlier acknowledged batches.
A one-batch run can therefore report zero for both; use `http_failed`,
diagnostics, and the process exit code to determine delivery health.

Machine-readable JSON Schemas for the record stream and each `record_type` live
under [schema/v0.2.0](schema/v0.2.0/). Use `record-stream.schema.json` when
validating arbitrary NDJSON lines, or route on `record_type` and validate against
the per-record schema.

`confidence` is parser/extraction certainty, not a probability that the activity
is malicious. `high` means direct source evidence; `medium` and `low` are
reserved for inferred or best-effort normalizations.

## timeline

`timeline` is a read-only view over the same extraction `scan` uses. It groups
events by `source_agent`, `source_type`, and `session_id`; sessionless at-rest
events fall back to their artifact path. Each chronological step retains its
evidence reference.

Unlike sequence correlation, a timeline does not split a conversation when the
project path is missing or the agent changes its working directory;
`project_path` remains display context. The command evaluates no rules and emits
no findings. Text is the default format; `--format json` returns the grouped
reconstruction. It exits `0` when at least one artifact parses, even if that
artifact yields no events; `1` when no artifacts are found or none parse; and
`2` on usage errors.

It accepts the same mutually exclusive automatic-discovery `--agent` and
explicit-root `--path` modes as `scan`.

### timeline flags

```
--agent NAME                  limit automatic discovery to a parser-backed agent
                              (repeatable; cannot be combined with --path)
                              claude|codex|copilot|cowork|cursor|gemini|kimi|
                              openclaw|opencode|pi|windsurf
--path FILE|DIR              artifact to read (repeatable; defaults to known
                             agent locations under $HOME plus supported
                             agent home/data env overrides)
--case-id ID                 case identifier stamped on every event
--profile evidence|full      capture depth; evidence omits reasoning/model context
                             (default evidence)
--format text|json           output format (default text)
```

```
numbat timeline --agent claude
numbat timeline --path ~/.claude/projects
numbat timeline --path ~/.claude/projects --path ~/.codex --format json
```

## collect

`collect` runs an in-process OTLP/HTTP logs receiver and maps live agent
telemetry through the same pipeline `scan` uses. It listens on
`127.0.0.1:4318` by default and accepts protobuf-encoded OTLP logs at `/v1/logs`
(the standard OTLP/HTTP path), with identity or gzip content encoding. It serves
**OTLP/HTTP only** — there is no gRPC listener (`:4317`), so an agent that
defaults to gRPC must be switched to HTTP.
The startup banner, shutdown note, and diagnostics are written to stderr; the
selected record sink (`stdout`, `file`, `http`, or repeated `file` + `http`)
stays reserved for records.

The receiver has no client authentication or TLS. Keep the default loopback
bind, or place an off-loopback listener behind network controls and an
authenticated proxy; any client that can reach it can inject telemetry. Each
request is limited to a 4 MiB wire body, a 4 MiB decompressed body, and 10,000
log records, with additional bounds on protobuf groups, attributes, nested
values, and nesting depth.

An empty `200` response means local acceptance, not downstream acknowledgement
by a batched HTTP sink. A `200` response can instead contain OTLP
`partial_success` with `rejected_log_records`; exporters should surface its
message. Sink write failures and a pending direct-HTTP delivery failure return
`503`. A byte-identical retry within one collector run reuses event and finding
IDs so receivers can deduplicate it.

### collect flags

```
--addr HOST:PORT             OTLP/HTTP listen address (default 127.0.0.1:4318)
--case-id ID                 case identifier stamped on every emitted event and derived finding
--emit KIND                  record kind to emit: findings, events, indicators,
                             or all (repeatable; default findings)
--output SINK                record sink: stdout, file, or http
                             (repeatable; default stdout; stdout cannot be combined)
--output-file PATH           destination path (required when output includes file)
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
```

The HTTP sink flags (`--http-url`, `--http-auth`, `--http-batch-size`,
`--http-gzip`, `--http-timeout`, `--http-sig-header`, `--http-timestamp-header`,
`--http-allow-insecure`) have the same meaning as in the [scan section](#scan),
including the env-only auth secrets.

```
numbat collect
numbat collect --addr 127.0.0.1:4318 --emit all
```

Claude Code, Codex, Gemini CLI, Qwen Code, and OpenCode can emit OTLP logs that `collect`
normalizes. None points at numbat by default, so configure the logs exporter
explicitly:

- **Claude Code** — set `CLAUDE_CODE_ENABLE_TELEMETRY=1`,
  `OTEL_LOGS_EXPORTER=otlp`,
  `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL=http/protobuf`, and
  `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://127.0.0.1:4318/v1/logs`. Set
  `OTEL_LOG_TOOL_DETAILS=1` when command, file, URL, and MCP parameters are
  needed; prompt and assistant text remain controlled by Claude's separate
  content-capture settings.

- **Gemini CLI** — defaults to gRPC on `:4317`, which numbat does not serve. Set
  `otlpProtocol=http` (in `~/.gemini/settings.json` telemetry settings or via the
  CLI flags) and point the OTLP endpoint at numbat's `http://127.0.0.1:4318`.
- **Qwen Code** — enable telemetry, set `otlpProtocol` to `http`, and set
  `otlpLogsEndpoint` (or `QWEN_TELEMETRY_OTLP_LOGS_ENDPOINT`) to
  `http://127.0.0.1:4318/v1/logs`. Keep `logPrompts` disabled when prompt content
  is not required; tool inputs and model responses can also be sensitive.
- **Codex** — configure its protobuf log exporter:

  ```toml
  [otel]
  exporter = { otlp-http = { endpoint = "http://127.0.0.1:4318/v1/logs", protocol = "binary" } }
  ```

  Codex redacts prompt text by default; set `log_user_prompt = true` in the same
  `[otel]` table if you want prompt content captured in `content_preview`.
- **OpenCode** — via the [`@devtheops/opencode-plugin-otel`](https://www.npmjs.com/package/@devtheops/opencode-plugin-otel)
  logs plugin, which defaults to gRPC on `:4317`. Set
  `OPENCODE_OTLP_PROTOCOL=http/protobuf` and
  `OPENCODE_OTLP_ENDPOINT=http://127.0.0.1:4318` (the HTTP exporter appends
  `/v1/logs`). OpenCode emits `prompt_length`, not prompt text, so a `prompt.user`
  carries no `content_preview`.

Claude Code, Codex, Gemini CLI, and Qwen Code use vendor-specific
`claude_code.*`, `codex.*`, `gemini_cli.*`, and `qwen-code.*` event names;
OpenCode emits bare names such as `user_prompt` and `tool_result`. numbat matches
documented activity records, including Gemini/Qwen session, assistant, tool, and
subagent lifecycle events, and skips records with no normalized analog.

`collect` does not ingest OTLP traces or metrics. VS Code Copilot Chat, Copilot
CLI, and OpenHands observability emit their actionable telemetry primarily as
traces; use their hook/forensic path or a full OpenTelemetry collector for those
signals. OpenClaw's official diagnostics plugin likewise places tool execution
in traces, so use numbat's native OpenClaw plugin for live actions or a full
collector for that telemetry.

## ship

`ship` is an optional forwarder for hosts without an existing log shipper. It
tails a numbat NDJSON file and sends batches to an HTTP endpoint outside the
agent's hook path. Its state advances only after a `2xx`, so eligible retained
records are delivered at-least-once across endpoint outages and process restarts
while the input and its rotations remain available. Records larger than 8 MiB
are not eligible for HTTP delivery, as detailed below.

Use file-only hook output with `ship`. Selecting direct HTTP on the same hook
would send each record through both paths.

### ship flags

```
--input-file PATH            append-only NDJSON file to ship (required)
--state-file PATH            delivery checkpoint (default <input-file>.ship-state)
--poll DURATION              interval between input-file polls (default 2s)
--http-url URL               ingest URL (required)
--http-timeout DURATION      request timeout (default 30s)
--http-auth MODE             none, bearer, or hmac-sha256 (default none)
--http-sig-header NAME       HMAC signature header (default X-Numbat-Signature)
--http-timestamp-header NAME signed timestamp header; empty signs the bare body
                             (default X-Numbat-Timestamp)
--http-gzip                  gzip the POST body
--http-allow-insecure        allow plain http to non-loopback hosts
```

```
numbat hook install --agent codex --emit all \
  --output file --output-file ~/.numbat/records.ndjson

NUMBAT_HTTP_TOKEN=... numbat ship \
  --input-file ~/.numbat/records.ndjson \
  --http-url https://ingest.example/numbat \
  --http-auth bearer
```

The default state file is `<input-file>.ship-state`; override it with
`--state-file`. It binds the acknowledged offset to the input file and endpoint.
On rotation, `ship` drains retained, same-directory record files before moving
to the active file. Keep rotations uncompressed until the state reaches the new
active file; a segment deleted during an outage cannot be recovered.
Changing the endpoint or losing valid state replays retained records. Receivers
must tolerate duplicates, using stable record identifiers where present.

`ship` never truncates or rotates the input. Retention remains the operator's
responsibility, and undelivered records are only as durable as that file and its
host. A complete record larger than 8 MiB remains in the input but is skipped
from HTTP delivery with a stderr diagnostic so later records can continue.
Prefer an existing fleet forwarder when one is already available.

`--http-auth`, `--http-timeout`, `--http-gzip`, the HMAC header options, and
`--http-allow-insecure` match the [scan HTTP options](#scan), including the wire
contract and environment-only secrets. Failed delivery retries use exponential
backoff with jitter. `ship` runs until SIGINT or SIGTERM; an in-flight request
is bounded by `--http-timeout`.

## hook

`numbat hook EVENT` is the callback written by `hook install`; operators do not
normally invoke it directly. It reads one agent lifecycle-hook
payload as JSON on stdin, maps it into the same event model `scan` uses, and
runs it through the same detection pipeline as `scan`. In monitor mode
(default) it prints the agent's non-blocking response on stdout and exits 0;
Kiro's successful response is zero bytes because Kiro adds stdout to agent context.
With `--enforce`, an enforce-capable pre-action callback may block after a clean
match of a rule marked `enforce: true`; a sequence match can block
only its final action. Rules that use `shell_commands` can deny only from the
[static enforcement subset](enforcement.md#rule-effect). Structured-response
agents return native deny JSON and
exit 0; Windsurf, Kimi Code, Qwen Code, Auggie, Kiro, Goose, OpenHands, Crush,
and Junie return exit 2 with the reason on stderr. Any decoding, relevant rule
or state, or output error handled by numbat suppresses its deny response;
unavailable sequence state does not suppress an independent stateless deny.
OpenClaw's generated wrapper likewise returns no block when the numbat child
fails or does not emit a clean deny. OpenClaw's host can still fail closed on an
escaped handler error or host timeout; see
[enforcement.md](enforcement.md#coverage-limits) for that boundary.
Copilot CLI may still deny when the hook process itself fails to launch,
crashes, or exits non-zero; its hook timeouts allow. In monitor mode,
Antigravity returns its required `decision:"ask"`; enforce mode can return its
documented hard deny.

For a matched, enforce-capable pre-action callback, `--emit findings` also emits
one action-level `record_type:"enforcement"` record. It carries numbat's
computed `decision:"deny"` or `decision:"no_override"` and joins to the
triggering records through `finding_ids` and `action_event_ids`. A finding by
itself never implies a deny. The decision shares the existing operator batch,
before the host control response; it does not prove response delivery or that
the host honored it.
`EVENT` is the agent lifecycle moment (e.g. `PreToolUse`); the
accepted names are per-agent (see [live-capture.md](live-capture.md)). The
`--agent` value selects how the payload is parsed; accepted values are listed
below.

### hook flags

```
--agent NAME                 source agent (required): claude|codex|gemini|
                             cursor|windsurf|copilot|vscode|opencode|openclaw|
                             antigravity|factory|grok|devin|hermes|pi|kimi|
                             qwen|cline|amp|auggie|kiro|goose|kilo|openhands|
                             crush|junie
--case-id ID                 case identifier stamped on every emitted event and derived finding
--emit KIND                  record kind to emit: findings, events, indicators,
                             or all (repeatable; default findings; enforce mode
                             requires findings)
--enforce                    opt-in enforce mode: block an action when a rule
                             marked enforce: true matches, including the final
                             action of a sequence. Off by default: monitor mode
                             detects but never blocks.
                             A relevant numbat error, panic, or uncertain match
                             suppresses its deny response.
--state-db PATH              bbolt file holding live sequence-window state
                             (default $HOME/.numbat/state.db)
--installed-by NAME          provenance marker written by `hook install`;
                             accepted but inert (ignored at runtime)
--output SINK                record sink: stdout, file, or http
                             (repeatable; default stdout; stdout cannot be combined
                             and is unavailable in enforce mode)
--output-file PATH           destination path (required when output includes file)
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
```

On `numbat hook`, stdout is reserved for the agent's control response, so
monitor-mode `--output=stdout` records are written to **stderr** instead.
Enforce mode requires `--emit findings` (or `all`) and a `file` and/or `http`
sink; stdout output is rejected so operator findings cannot enter the agent's
control channel. After that sink opens, enforce-mode diagnostics are emitted as
records on it even when only findings were selected; decision failures return
only a generic message on hook stderr. For durable capture use
`--output=file`; repeat `--output file --output http` only when you also want a
direct HTTP delivery attempt. `--emit` has the same record selection as `scan`
and `collect`. Hook HTTP requests default to a five-second timeout so a slow
sink does not consume the agent hook's full execution window.

The HTTP sink flags (`--http-url`, `--http-auth`, `--http-batch-size`,
`--http-gzip`, `--http-timeout`, `--http-sig-header`, `--http-timestamp-header`,
`--http-allow-insecure`) and the shared rule flags (`--rules-dir`,
`--no-builtin-rules`) have the same meaning as in the [scan section](#scan),
including the env-only auth secrets.

### hook install / status / uninstall

`numbat hook install` wires the live handler into an agent's hook integration (and
`uninstall` removes it, `status` reports it). Each action is idempotent. Installers
that edit shared configuration keep a pristine backup. Backup behavior for
owned standalone artifacts is installer-specific; OpenClaw's generated
multi-file package replaces each owned file atomically without a separate
backup. Where the
agent's schema supports a native command timeout, install writes a finite deadline
on every numbat callback rather than inheriting a potentially ten-minute agent
default. This agent process deadline is separate from the hook handler's
`--http-timeout`.

```
--agent NAME|all             agent to target (required for install/uninstall;
                             status defaults to all):
                             claude|codex|gemini|cursor|windsurf|copilot|
                             vscode|opencode|openclaw|antigravity|factory|grok|
                             devin|hermes|pi|kimi|qwen|cline|amp|auggie|kiro|
                             goose|kilo|openhands|crush|junie
--settings PATH              override the install-target path for one agent
                             (requires --agent; selects an agent-specific file
                             or directory and may create companion artifacts)
--managed                    target the agent's admin-managed hook config
                             (requires --agent; claude, codex, cursor,
                             copilot, gemini, windsurf, qwen, or auggie)
--emit KIND                  record kind installed hook commands emit:
                             findings, events, indicators, or all
                             (repeatable; default findings; enforce mode requires
                             findings)
--output SINK                record sink installed hook commands use:
                             stdout, file, or http (repeatable; default file;
                             stdout cannot be combined and writes records to
                             hook stderr because hook stdout is reserved for
                             the agent response; unavailable in enforce mode)
--output-file PATH           destination path when output includes file
                             (default findings.ndjson for findings only;
                             records.ndjson when events/indicators are selected)
--rules-dir DIR              operator rules installed hooks add or replace by id
                             (repeatable)
--no-builtin-rules           install hook commands that load only --rules-dir
                             rules
--enforce                    install in enforce mode: block pre-tool matches
                             from rules marked enforce: true (claude, codex,
                             cursor, copilot/vscode, gemini, windsurf,
                             antigravity, factory, grok, devin, hermes,
                             openclaw, pi, kimi, qwen, cline, amp, auggie,
                             kiro, goose, kilo,
                             openhands, crush, junie). Off by default:
                             monitor, detection-only, never blocks.
```

With `--enforce`, install first compiles the effective catalog and refuses to
change agent configuration unless it contains an enabled `enforce: true` rule.
Each `--rules-dir` must be a concrete, readable install-time path; deferred
paths such as `$HOME/rules` are rejected in this mode.

Install-time output flags are baked into the command written to the agent's hook
configuration. Findings-only installs write
`$HOME/.numbat/findings.ndjson`; selecting events or indicators changes the
default to `$HOME/.numbat/records.ndjson`. Use `--output-file PATH` to change
that file, or
`--output file --output http --http-url URL` to keep the local file and also
attempt direct delivery. HTTP auth secrets are not written into hook settings; the
installed hook reads `NUMBAT_HTTP_TOKEN` or `NUMBAT_HTTP_HMAC_KEY` from its
runtime environment when `--http-auth` selects one of those modes.

`hook install` accepts the same eight HTTP flags listed under
[hook](#hook-flags), with the same defaults, including the five-second
`--http-timeout`.

Without a scope flag, install and uninstall resolve the target agent's default
user path. OpenHands is the exception: it has no default user file and requires
`--settings /repo/.openhands/hooks.json`. `--agent all` operates only on each
agent's effective user target (including supported environment overrides), does
not add secondary profiles, excludes OpenHands, and cannot be combined with
`--settings`, `--managed`, or `--enforce`.

`--settings PATH` selects one explicit agent target, which may be a file or
directory; it does not by itself make the target project-scoped, trusted, or
active. Some installers create owned companion artifacts next to the selected
path. `--managed` selects the documented policy schema and path. For
single-file targets, use both `--managed --settings PATH` to generate that
schema at an explicit staging path. The generated hook command still contains
the current operating system's quoting and the generator's absolute numbat
path; see the deployment guide for staging constraints. Auggie's selected path
must be its final runtime location because
its generated scripts are referenced absolutely. Literal `$HOME` output paths
in managed hook commands expand in the agent user's process, not during the
administrator's install.

The OpenClaw target is a package directory under the Gateway's plugin config
root. Resolution is `$OPENCLAW_STATE_DIR`, the directory containing
`$OPENCLAW_CONFIG_PATH`, then
`${OPENCLAW_HOME:-~}/.openclaw`; numbat appends `extensions/numbat/`. This
plugin-root selection is separate from at-rest discovery's legacy `.clawdbot`
fallback. A default install, including `--agent all`, refuses to create
`.openclaw` when only the legacy root exists; migrate it, explicitly select
`OPENCLAW_STATE_DIR`, or use `--settings` plus a matching `plugins.load.paths`
entry.

A profile selected with `openclaw --profile <profile>` is not visible to a
standalone numbat process. OpenClaw projects the concrete state/config paths
only inside its own invocation; exporting `OPENCLAW_PROFILE` alone does not do
that. Pass the profile's `OPENCLAW_STATE_DIR` to numbat, or use `--settings` for
its package directory and use the same profile for activation commands.

Installation does not run OpenClaw or edit `openclaw.json`. OpenClaw has no
numbat `--managed` target. `status` validates the package files and checksum,
not activation; `uninstall` does not rewrite Gateway policy. Production setup is
centralized in [deployment.md](deployment.md#openclaw-production-policy).

Scope choices, managed paths, vendor trust/activation, and output durability
are centralized in [deployment.md](deployment.md#choose-an-install-scope).

```
numbat hook install --agent claude
numbat hook install --agent codex --emit all --output-file ~/.numbat/codex.ndjson
numbat hook install --agent codex --managed --emit all \
  --output-file '$HOME/.numbat/live.ndjson'
numbat hook install --agent openclaw --rules-dir /etc/numbat/rules --enforce
numbat hook install --agent openhands --settings /repo/.openhands/hooks.json
numbat hook status --agent codex
numbat hook uninstall --agent claude
```

## rules

`rules check` strictly loads and compiles rule files without scanning artifacts;
it also runs companion `*_tests.yaml` files found under `--rules-dir`. Every rule
declares its own `version`, which is copied to `rule_version` in findings.
`rules list` prints each id in the effective compiled catalog (embedded rules
plus operator additions and replacements), one per line. A same-id operator
rule replaces the complete embedded definition; `enabled: false` removes that
id from the compiled list. `rules test` evaluates the compiled rules
against an ad hoc fixture of valid normalized NDJSON events (one event per line)
and prints each match as `rule_id<TAB>event_id`. Malformed JSON, event-contract
violations, and rule-evaluation errors report the fixture line number. `check`,
`list`, and `test` accept the shared rule-loading flags.

### rules check flags

```
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
```

### rules list flags

```
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
```

### rules test flags

```
--fixture FILE               NDJSON events file to evaluate (required)
--require-match              exit non-zero if no rule matches (for positive fixtures)
--expect RULE_ID             exit non-zero if this rule id does not match
                             at least once (repeatable)
--expect-none                exit non-zero if any rule matches
--rules-dir DIR              operator rules to add or replace by id
                             (repeatable)
--no-builtin-rules           load only --rules-dir rules
```

```
numbat rules check --rules-dir ./my-rules
numbat rules list
numbat rules test --fixture events.ndjson --require-match
numbat rules test --fixture positive.ndjson --expect secrets.agent_read_env
numbat rules test --fixture negative.ndjson --expect-none
```

## case bundles

`case build` curates captured record streams into a portable `case.numbat`
directory an investigator can hand off: the case's findings, the events their
`cited_event_ids` name, any case-scoped hook enforcement decisions, and a
`manifest.json` of per-file SHA-256 digests. Records are copied byte-for-byte
from the source streams, deduplicated by record id, and sorted.
Identical ordered inputs produce identical record files. Reusing an id for
conflicting content is an error. If a source contains findings but not their
cited event records, the build succeeds
with an incomplete-events warning; capture `--emit all` when the bundle should
contain both. Inputs use the current record schema; other schema versions are
skipped with a warning, and a source line that reaches the 8 MiB input cap fails
the build. The
manifest also records the build time. `case verify` is an integrity check, not a
re-scan: it re-hashes a bundle against its manifest
— every listed file must match its digest, record files must match their record
counts, and nothing unlisted may be present — but it never re-runs rules.

The build `<case-id>` must match records produced with `scan --case-id <case-id>`
or live records captured with the same `--case-id`; otherwise there are no
case-scoped findings to bundle.

### case build flags

`case build` takes the case id as its first positional argument, then:

```
--from FILE                  captured NDJSON record-stream file to read
                             (repeatable; at least one required)
-o, --out DIR                bundle directory to create (default case.numbat;
                             must not exist)
--include-raw-evidence       copy cited evidence files verbatim (opt-in; may
                             include secrets/transcripts)
--include-redacted-evidence  copy cited evidence files with each line redacted
                             (mutually exclusive with --include-raw-evidence)
```

`case verify` takes the bundle directory as its only positional argument and has
no flags.

```
numbat scan --case-id inv-42 --emit all --output file --output-file records.ndjson
numbat case build inv-42 --from records.ndjson -o inv-42.numbat
numbat case verify inv-42.numbat
```

By default no evidence file contents are copied — only references and digests
travel. `--include-raw-evidence` copies the cited files verbatim (they can hold
`.env` contents, keys, or transcripts — share with care), and
`--include-redacted-evidence` copies them with each line run through the same
redaction pipeline used for findings. The manifest digests prove *integrity* —
that the bundle is self-consistent and unmodified since it was written. These
digests do not prove authenticity: bundles are unsigned, and anyone can rebuild
a manifest.

## version

`numbat version` prints the tool version and the record schema version
(`0.2.0`). Release and schema versions advance independently; the schema changes
only when the emitted record contract changes.

## Exit status

Most commands other than `hook EVENT` use `0` for success, `2` for CLI syntax
or option-validation errors, and `1` for failures after validation, including
rule or configuration loading, data, and output failures. The command sections
above document additional scan and timeline conditions.

- `collect` exits `0` after a graceful signal-driven shutdown and `1` for an
  initialization, listener, server, or sink failure.
- `ship` keeps retrying delivery failures. SIGINT or SIGTERM stops it with `0`,
  even while delivery is stalled; setup, lock, or state failures return `1`, and
  invalid CLI configuration returns `2`.
- `hook EVENT` returns `0` for passthrough, a structured deny, and handled
  callback errors so those errors fail open. It returns `2` only when the host's
  deny contract uses exit code 2.
