# Writing rules

Each numbat rule is one YAML file with [CEL](https://cel.dev/) boolean
expressions. It evaluates either one [normalized event](event-model.md) or an
ordered sequence of events.

Rule expressions can use:

- `event`, a stable projection of normalized action and context fields using
  emitted JSON names.
- `shell_commands`, a rule-only parsed view of commands found in
  `event.command`.

Embedded rules are monitor-only by default. See the
[built-in catalog](rule-catalog.md) for coverage and [`rules/`](../rules/) for
the authoritative YAML.

## Quick start

Create one rule and an optional companion test:

```text
my-rules/
  env_read.yaml
  env_read_tests.yaml
```

```yaml
# env_read.yaml
id: acme.secrets.env_read
version: "1.0"
title: Environment file read
severity: high
expr: |-
  event.event_type == "file.read" &&
  event.file_path.matches("(^|/)\\.env$")
tags: [secret_file_read]
```

```yaml
# env_read_tests.yaml
rule_id: acme.secrets.env_read
cases:
  - name: env-file
    expect: match
    events:
      - event_type: file.read
        file_path: /repo/.env

  - name: example-file
    expect: no_match
    events:
      - event_type: file.read
        file_path: /repo/.env.example
```

Validate the rule and its companion tests:

```sh
numbat rules check --rules-dir ./my-rules
```

Use `--no-builtin-rules` when the directory should be evaluated alone:

```sh
numbat rules check --no-builtin-rules --rules-dir ./my-rules
```

## Choose the right input

Use the simplest input that preserves the distinction your rule needs:

| Need | Use |
| --- | --- |
| File, URL, MCP, approval, model, or other normalized fields | `event.<field>` |
| A literal check over the original command text | `event.command` |
| Prompt, assistant, or source-recorded reasoning text | `event.content` |
| Parsed executable names, arguments, pipes, redirects, or wrappers | `shell_commands` |
| Ordered activity across multiple events | `sequence` |

Rules may use `event.command`; it is supported and not deprecated:

```cel
event.event_type == "command.exec" &&
event.command.contains("terraform destroy")
```

Raw text is appropriate when literal text is the signal. It can also match
comments, quoted examples, commit messages, or here-doc data, so prefer
`shell_commands` when a match should depend on executable command semantics.
This distinction matters most for rules that may block.

Longer built-in expressions encode narrow false-positive exclusions; they are
policy implementations, not a required template for custom rules.

## Rule format

A rule file is one top-level YAML object. A `rules:` wrapper, multiple YAML
documents, and multiple rules per file are rejected.

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable, dot-separated rule ID |
| `version` | yes | Rule-owned version copied to findings |
| `title` | yes | Finding title |
| `severity` | yes | `info`, `low`, `medium`, `high`, or `critical` |
| `expr` | one of | CEL predicate for a single event |
| `sequence` | one of | Ordered multi-event definition |
| `description` | no | Operator-facing explanation |
| `tags` | no | Strings copied to findings |
| `enabled` | no | Defaults to `true`; disabled rules are still validated |
| `enforce` | no | Defaults to `false`; permits blocking on supported hooks |
| `deny_message` | no | Single-line blocking response, at most 512 UTF-8 bytes |

Set exactly one of `expr` and `sequence`.

Rule IDs use lowercase letters, digits, `_`, and `-` in dot-separated
segments. Each segment must start and end with a letter or digit. Give new
operator rules an organization-specific namespace, such as `acme.*`, to avoid
future built-in collisions.

Each rule owns its version. It is independent of numbat's record
`schema_version`; bump it whenever rule logic changes, including a
false-positive fix. numbat does not impose a versioning scheme.

Built-ins additionally require `description`, explicit `enabled`, and at least
one behavior or ATT&CK tag. Those are catalog review policies, not requirements
for operator rules.

## CEL expressions

An expression must return a boolean and should begin by selecting the event
types it understands. Fields differ by event type, and pre-action events
describe requested actions rather than confirmed outcomes.

Common CEL operations include:

| Operation | Example |
| --- | --- |
| Boolean logic | `a && b`, `a || b`, `!a` |
| Membership | `value in ["a", "b"]` |
| String tests | `contains`, `startsWith`, `endsWith`, `matches` |
| List predicates | `exists`, `all`, `exists_one` |
| List range | `items.slice(start, end)` |
| Integer indexes | `lists.range(n).exists(i, ...)` |
| Missing nullable value | `event.exit_code == null` |

`matches` uses RE2 regular expressions. CEL string literals require their own
escaping; for example, a literal dot is written as `"\\.env"`.

Action types are alternatives, not layers. A recognized shell action is a
`command.exec`, not both a `tool.call` and a `command.exec`; file and network
actions are specialized the same way. `tool.call` is the fallback when numbat
cannot safely specialize the action. A later `command.result` is the correlated
outcome, not a second invocation.

Long-running commands may produce multiple `command.result` updates with the
same `tool_call_id`. A missing `exit_code` means the source did not report one;
it does not imply success.

Do not add `tool.call` as a catch-all branch to a command rule. Generic tool
calls have no `event.command`; write a separate tool rule only when the generic
tool identity is itself the signal.

For command activity, choose the events you mean. Hooks and artifacts normally
provide the requested action as `command.exec`. Some OTLP sources expose only a
completed `command.result`, so shipped command rules commonly use:

```cel
event.event_type == "command.exec" ||
(event.source_type == "otel" && event.event_type == "command.result")
```

That gate avoids matching both the request and result for sources that emit
both. A custom rule may use only `command.exec` when it cares strictly about
requested actions, or only `command.result` when completion matters.

For conversation events, `event.content` is the unredacted mapped message text,
bounded to 1 MiB per event. A rule that references a content field automatically
enables this analysis; `--content full` is needed only to emit it. Use
`event.content_truncated` when a rule must reject incomplete input.
`event.content_bytes` is the mapped body size before Numbat's bound. These
fields never include file bodies, patches, or arbitrary tool output.

### Event fields

The CEL `event` map always contains every key below. `exit_code`, `duration_ms`,
and `approval_required` use `null` when absent; strings use `""`, `diff_bytes`
uses `0`, and `tags` uses an empty list.

| Field | Type | Field | Type |
| --- | --- | --- | --- |
| `event.actor` | string | `event.approval_decision` | string |
| `event.approval_reason` | string | `event.approval_required` | bool|null |
| `event.cli_version` | string | `event.command` | string |
| `event.confidence` | string | `event.content` | string |
| `event.content_bytes` | int | `event.content_preview` | string |
| `event.content_preview_truncated` | bool | `event.content_truncated` | bool |
| `event.decision` | string | `event.diff_bytes` | int |
| `event.diff_sha256` | string | `event.duration_ms` | int|null |
| `event.entrypoint` | string | `event.event_type` | string |
| `event.exit_code` | int|null | `event.file_path` | string |
| `event.git_branch` | string | `event.mcp_server` | string |
| `event.mcp_tool` | string | `event.model` | string |
| `event.model_provider` | string | `event.project_path` | string |
| `event.tags` | list(string) | `event.session_id` | string |
| `event.source_agent` | string | `event.source_type` | string |
| `event.sub_agent` | string | `event.timestamp` | string |
| `event.tool_call_id` | string | `event.tool_name` | string |
| `event.url` | string |  |  |

The [event schema](schema/v0.3.0/event-record.schema.json) defines closed values
for fields such as `source_agent`, `source_type`, `actor`, `decision`, and
`confidence`.

Use `event.exit_code != null`, not `has(event.exit_code)`. The key is always
present even when the value is null.

Rule loading rejects unknown fields and computed access. Use direct field
syntax such as `event.command`.

### Event-type fields

Context fields such as source, timestamp, project, session, actor, model,
branch, entrypoint, sub-agent, preview, tags, and confidence are valid on every
event type. Full `content` fields are valid only on conversation events.
Non-empty action fields follow this compatibility table:

| Event type | Allowed action fields |
| --- | --- |
| `session.start`, `session.end`, `prompt.user`, `message.assistant`, `message.reasoning`, `config.agent` | none |
| `tool.call` | `tool_name`, `tool_call_id`, `mcp_server`, `mcp_tool`, `url`, `file_path`, `decision` |
| `tool.result` | `tool_name`, `tool_call_id`, `mcp_server`, `mcp_tool`, `decision` |
| `command.exec` | `command`, `tool_name`, `tool_call_id`, `decision` |
| `command.result` | `command`, `tool_name`, `tool_call_id`, `exit_code`, `duration_ms`, `decision` |
| `file.read` | `file_path`, `tool_name`, `tool_call_id`, `decision` |
| `file.write` | `file_path`, `tool_name`, `tool_call_id`, `decision`, `diff_sha256`, `diff_bytes` |
| `file.delete` | `file_path`, `tool_name`, `tool_call_id`, `diff_sha256`, `diff_bytes` |
| `permission.requested`, `permission.approved`, `permission.denied` | `tool_name`, `tool_call_id`, `decision`, `approval_required`, `approval_decision`, `approval_reason` |
| `config.mcp` | `mcp_server`, `mcp_tool` |
| `network.indicator` | `url`, `tool_name`, `tool_call_id`, `mcp_server`, `mcp_tool`, `decision` |

Companion fixtures are normalized and validated against the same contract.

## Parsed command rules

`shell_commands` is a list of statically identified POSIX shell, PowerShell,
and `cmd.exe` commands. It is derived from `event.command` during rule
evaluation and is never emitted.

A basic command rule usually needs only `name` and `argv`:

```yaml
id: acme.network.curl_upload
version: "1.0"
title: Curl upload requested
severity: high
expr: |-
  event.event_type == "command.exec" &&
  shell_commands.exists(command,
    command.name == "curl" &&
    command.argv.slice(1, command.argv.size()).exists(arg,
      arg in ["--upload-file", "-T"]
    )
  )
```

`name` is the lowercase executable basename with common Windows executable
suffixes removed. `argv` includes the executable at index 0.

### Common patterns

Match an option:

```cel
command.argv.size() > 1 &&
command.argv.slice(1, command.argv.size()).exists(arg,
  arg in ["--force", "-f"]
)
```

Match an option followed by its value:

```cel
command.argv.size() > 1 &&
lists.range(command.argv.size() - 1).exists(i,
  command.argv[i] == "--output" &&
  command.argv[i + 1] == "/tmp/result"
)
```

Match two commands in the same pipeline:

```cel
shell_commands.exists(download,
  download.name in ["curl", "wget"] &&
  download.pipeline_id > 0 &&
  shell_commands.exists(interpreter,
    interpreter.statement_id != download.statement_id &&
    interpreter.pipeline_id == download.pipeline_id &&
    interpreter.name in ["sh", "bash", "zsh"]
  )
)
```

The nested `exists` does not introduce a new rule construct. It asks whether
one parsed command and a second parsed command satisfy the stated relationship.
The [built-in pipe-to-shell rule](../rules/exec/download_pipe_shell.yaml) adds
argument checks because it distinguishes interpreters that execute standard
input from ones given a local script.

Match a launcher around a command:

```cel
command.wrappers.exists(wrapper, wrapper.name in ["sudo", "doas"])
```

Match an output redirect:

```cel
command.redirects.exists(redirect,
  redirect.op in ["write", "append"] &&
  redirect.target.endsWith("/authorized_keys")
)
```

### Command fields

Most rules need only `name`, `argv`, and, for pipelines, the relationship IDs.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Normalized executable basename |
| `executable` | string | Statically parsed executable value |
| `argv` | list(string) | Parsed, non-runtime-expanded values including the executable |
| `arguments` | list(argument) | `argv` plus source, quoting, and expansion data |
| `assignments` | list(assignment) | Command-scoped shell assignments |
| `redirects` | list(redirect) | Input and output redirections |
| `dialect` | string | `posix`, `powershell`, or `cmd` |
| `wrappers` | list(wrapper) | Recognized launchers around the command |
| `statement_id` | int | This command's relation ID |
| `pipeline_id` | int | Shared by commands in one pipeline; `0` means none |
| `parent_statement_id` | int | Enclosing command relation; `0` means none |
| `preview` | string | `normal`, `preview`, or `uncertain` |
| `function_call` | bool | Statically resolved shell function call |
| `recursive` | bool | Statically resolved recursive function call |

Relationship IDs are local to one event. Compare them for equality; do not
interpret their numeric values beyond `0` meaning no relationship.

Nested object fields:

| Object | Fields |
| --- | --- |
| `argument` | `value`, `source`, `quote`, `expands`, `subcommands` |
| `assignment` | `name`, `value`, `append` |
| `redirect` | `fd`, `op`, `target`, `target_source`, `target_quote`, `target_expands`, `subcommands` |
| `wrapper` | `name`, `executable`, `argv` |

`argument.quote` and `target_quote` are `none`, `single`, `double`, or `mixed`.
`subcommands` contains relation IDs for statically identified nested commands.
Redirect operations are `read`, `write`, `append`, `read_write`, `here_doc`,
`duplicate`, or `close`; `fd: -1` means a combined stdout/stderr redirect.
`source` and `target_source` preserve token spelling; `value` and `target` hold
parsed text without runtime expansion. The corresponding `expands` flag marks
syntax whose final value depends on runtime state. Use `arguments` instead of
`argv` when quoting or expansion determines whether an operand is active.

### Analysis boundary

The parser identifies only statically visible commands. It does not execute
code, expand variables, or read referenced scripts. Comments and quoted
examples do not become commands. Data-only literal here-docs stay inert; a
here-doc supplied to an interpreter such as `sh` is executable input and is
parsed. Supported static wrappers, inline scripts, substitutions, redirects,
and shell functions are projected when their meaning can be established.

Known `tool_name` values select POSIX shell, PowerShell, or `cmd.exe` parsing;
otherwise numbat infers the dialect from command syntax. Set `tool_name` in a
fixture when a Windows command depends on a specific dialect.

If part of a command is dynamic, malformed, unsupported, or over a parser
bound, numbat emits a diagnostic. Proven independent commands remain available
for detection. If no usable projection remains, rules that reference
`shell_commands` skip that event.

Detection recognizes explicit PowerShell `-WhatIf` requests and a statically
visible `$WhatIfPreference = $true` for known cmdlet names and exact
module-qualified forms. Ambient preference and command-resolution state are not
inferred.

For a shell-derived match, blocking has a narrower eligibility boundary than
detection: the complete shell program must be one static simple command or one
static POSIX pipeline. Supported transparent launchers are allowed only when
their final child command is also in that subset. Multiple statements, control
flow, same-script functions, inline child interpreters, `eval` or
`Invoke-Expression`, substitutions, runtime-dependent values, PowerShell or CMD
pipelines, previews, parser diagnostics, and truncated projections remain
detection-only. A rule may still use `shell_commands` alongside structured
fields such as `event.file_path`; a matching commandless structured event does
not require a shell projection. See [Enforcement](enforcement.md).

## Enforcement rules

Set `enforce: true` to make a rule eligible for blocking when a supported
pre-action hook is installed in enforce mode. Severity remains independent:
it prioritizes the finding; it does not decide whether a rule may block.

Enforcement uses the same CEL expressions as detection; there is no separate
rule language or required predicate shape. Raw `event.command` remains
available, but it matches literal input and can therefore match text that the
shell would not execute. Use `shell_commands` when blocking depends on parsed
command semantics. A shell-derived match can detect broad shell syntax, but a
deny requires the complete shell program to be inside the static subset
described above.

All built-ins ship monitor-only. To enforce one, copy its complete YAML into an
operator directory, keep the same ID, set `enforce: true`, and bump the rule
version. `--enforce` alone never converts monitor-only findings into denies.

`deny_message` overrides the generic message returned to the agent:

```yaml
enforce: true
deny_message: Contact the workspace owner.
```

The deny response does not include rule IDs or evidence. Those remain in the
finding. See [Enforcement](enforcement.md) for hook support, decision timing,
and fail-open behavior.

## Rule tests

`numbat rules check` automatically runs an adjacent companion with the same
extension and a reserved `_tests` suffix:

```text
agent_read_env.yaml
agent_read_env_tests.yaml
```

```yaml
rule_id: secrets.agent_read_env
cases:
  - name: direct-read
    expect: match
    events:
      - event_type: file.read
        file_path: /repo/.env

  - name: benign-readme
    expect: no_match
    events:
      - event_type: file.read
        file_path: /repo/README.md
```

Each case uses `expect: match` or `expect: no_match`. Events use emitted JSON
field names. Fixtures may omit `schema_version`, `event_id`, `source_agent`,
`source_type`, `confidence`, and `evidence`; the test runner supplies defaults
and validates the resulting event.

For an enforce-enabled rule, an optional assertion checks enforcement
eligibility as well as detection:

```yaml
- name: powershell-preview
  expect: match
  expect_enforcement: false
  events:
    - event_type: command.exec
      tool_name: PowerShell
      command: Stop-Process -Name target -Force -WhatIf
```

`expect_enforcement` is valid only with `expect: match`. It tests rule-engine
eligibility, not whether a particular host or hook mode would block the action.
For an enforce-enabled rule that uses `shell_commands`, include at least one
eligible case and one detection-only case.

For an ad hoc NDJSON fixture:

```sh
numbat rules test \
  --rules-dir ./my-rules \
  --fixture positive.ndjson \
  --expect acme.secrets.env_read

numbat rules test \
  --rules-dir ./my-rules \
  --fixture negative.ndjson \
  --expect-none
```

Unlike companion fixtures, NDJSON fixtures receive no defaults. Each line must
be a valid normalized event object; emitted event records can be used directly.
See the [event schema](schema/v0.3.0/event-record.schema.json) for required
fields.

## Sequence rules

A sequence rule declares `sequence` instead of `expr`. Each step is an ordinary
CEL predicate evaluated against one event:

```yaml
id: acme.chain.env_read_then_curl
version: "1.0"
title: Environment file read followed by curl
severity: high
sequence:
  within_events: 64
  steps:
    - expr: |-
        event.event_type == "file.read" &&
        event.file_path.matches("(^|/)\\.env$")
    - expr: |-
        event.event_type == "command.exec" &&
        shell_commands.exists(command, command.name == "curl")
```

| Sequence field | Meaning |
| --- | --- |
| `steps` | Two to eight ordered CEL predicates |
| `within` | Optional wall-clock window in Go duration syntax, such as `30m` |
| `within_events` | Optional event-count window, up to 4096 |
| `max_matches` | Findings per rule and correlation partition, default `1`, maximum `16` |

Set `within`, `within_events`, or both. When both are present, both must hold.
`within_events` must be at least the number of steps.

A completed sequence emits one finding citing each contributing event in
order. Its confidence is the weakest contributing event's extraction
confidence. Finding identity is deterministic over the rule ID, rule version,
and cited event IDs.

Sequence matching is conservative:

- Events stay within one agent, source, session, and project partition.
  Artifact scans also stay within one source file. Live events without a
  session ID do not correlate across events.
- Steps match only in declared order.
- The tracker chooses one canonical chain and emits at most `max_matches`
  findings per partition. This cap never suppresses enforcement.
- `within` requires parseable, ordered endpoint timestamps.
- State is bounded. Overflow misses a chain rather than growing without limit.

`scan`, `collect`, and `rules test` keep sequence windows in memory. One-shot
hook callbacks persist their bounded window in `$HOME/.numbat/state.db`
(`--state-db` overrides the path). A change to the loaded sequence-rule set
that affects matching, enforcement, or rule version invalidates old windows. If
the state cannot be opened, correlation fails open with a warning.

An enforced sequence may block only the action matching its final step.
Earlier steps have already been observed. Scan, OTLP, post-action, and monitor
mode remain detection-only. Use result events in a detection-only sequence when
confirmed completion matters.

Companion tests for sequence rules list the ordered events inside one case.

## Loading and replacing rules

Pass `--rules-dir DIR` more than once to load multiple operator directories.
numbat walks each directory recursively in path order and skips companion test
files.

```sh
numbat scan --rules-dir ./team-rules --rules-dir ./host-rules
numbat rules list --rules-dir ./team-rules
numbat rules list --no-builtin-rules --rules-dir ./team-rules
```

A new ID adds a rule. An operator rule with the same ID as a built-in replaces
that built-in completely; fields are not merged. Copy the complete YAML, make
the change, and bump its version. An invalid replacement fails the load and
never falls back silently.

Operator IDs must be unique across all supplied directories. A replacement
with the same ID and `enabled: false` disables the built-in. Disabled rules are
validated but absent from `rules list`, which prints the effective compiled
catalog.

For fleet policy, deploy a versioned operator directory separately from the
binary. Installed hook callbacks reload it on each invocation; a running
`collect` process must restart after a change. Keep policy files outside agent
workspaces and read-only to the monitored user when possible. numbat validates
rules but does not verify signed rule bundles:

```sh
numbat hook install --agent claude --rules-dir /etc/numbat/rules
```

See [Deployment](deployment.md) for scope, permissions, trust, and rollout
guidance.

Custom builds may instead edit `rules/<group>/*.yaml`; those files become part
of the embedded catalog and require a new binary for every policy change.

Rule loading is strict. Missing metadata, invalid IDs or severity, unknown YAML
keys, duplicate IDs, invalid CEL, unknown event fields, and nonexistent or
empty `--rules-dir` paths fail the command. Use `numbat rules check` in CI
before deploying a catalog.
