# Event model

numbat maps supported artifacts, hooks, and OTLP logs into the same closed
event vocabulary. Rules and outputs therefore use stable action names even
when agents record the same activity differently.

The model preserves source identity and evidence. It does not try to reproduce
every vendor field or infer action types from prose.

## Classification

A tool request becomes the most specific event that its structured name and
arguments support:

| Observed action | Normalized type | Principal field |
| --- | --- | --- |
| Shell or process request | `command.exec` | `command` |
| File access or change | `file.read`, `file.write`, `file.delete` | `file_path` |
| Known web or network request | `network.indicator` | `url` when available |
| Other or unknown tool request | `tool.call` | `tool_name` |

These types are alternatives, not layers. A recognized shell request produces
`command.exec`, not an additional `tool.call`. `tool.call` preserves visibility
when numbat cannot safely assign a more specific type. `event_type` carries the
action category; there is no parallel category field.

Classification is deliberately narrow:

- Artifact and hook parsers use agent-specific tool names and structured
  argument keys verified from that source.
- OTLP uses supported semantic-convention attributes and explicit operation
  fields. A path-bearing record remains `tool.call` when its direction is
  ambiguous.
- Unknown tools are not promoted by loose name or content matching.
- Command output, assistant prose, and free-form previews are not searched to
  invent file or network actions.
- A supported wrapper may be specialized when it contains exactly one
  statically recoverable action. numbat never evaluates embedded code; dynamic
  or compound wrappers remain `tool.call`.

`confidence` describes how directly the source supports the mapping. The
source provenance, including its location when available, remains in
`evidence`.

## Requests and results

A result is a separate observation, not a second request. When the source
provides an identifier, `tool_call_id` joins:

- `command.exec` to `command.result`
- `tool.call` to `tool.result`
- specialized file or network requests to later tool or permission records

Some agents persist only one side, and long-running commands may emit more than
one result update. An absent `exit_code` means the source did not provide one;
it does not mean success.

## Message content

Prompt, assistant, and source-recorded reasoning events carry a normalized
`content_preview` of at most 200 Unicode code points. Rules and indicator
extraction inspect mapped message text through `content`, bounded to 1 MiB per
event.
This analysis content is not emitted by default; `--content full` emits its
redacted form with `content_bytes` and `content_truncated`.
Reasoning is emitted only when the source exposes it and
`--include-reasoning` is selected.

`content_preview_truncated` states that the preview omits text. A long token is
kept as a rune-safe prefix rather than disappearing. `content_bytes` counts the
mapped body before Numbat's bound and output redaction. Message content does not
include file bodies, patch text, or arbitrary tool output. Findings carry the
same signal as `observed_content_preview_truncated`.

## MCP

MCP is a facet of a tool action, not a separate event category. A qualified
tool such as `mcp__github__create_issue` remains `tool.call` with
`mcp_server: github` and `mcp_tool: create_issue`. The canonical MCP fetch tool
becomes `network.indicator` by exact server and tool identity; a structured
target is promoted to `url` only when it is valid HTTP(S). It retains the MCP
fields.

`config.mcp` describes an observed MCP configuration. It does not represent a
tool invocation.

## Examples

The examples below show only the source fragment and the relevant normalized
fields. Emitted records also contain the versioned envelope, source and session
context, confidence, endpoint identity, and evidence reference.

A Claude Code tool block:

```json
{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"git status"}}
```

becomes:

```json
{"event_type":"command.exec","tool_name":"Bash","tool_call_id":"toolu_1","command":"git status"}
```

A Codex MCP call whose server and tool identify the canonical fetch service:

```json
{"type":"function_call","name":"mcp__fetch__fetch","call_id":"call_1","arguments":"{\"url\":\"https://example.com/a\"}"}
```

becomes:

```json
{"event_type":"network.indicator","tool_name":"mcp__fetch__fetch","tool_call_id":"call_1","mcp_server":"fetch","mcp_tool":"fetch","url":"https://example.com/a"}
```

## Contracts

The event vocabulary and allowed field combinations are closed and validated
before detection or emission. Context fields such as `model`, `project_path`,
and `sub_agent` are present only when the source records them. Semantic paths
use `/` separators on every operating system; evidence paths remain native so
the source can be reopened on the endpoint.

See [Writing rules](rules.md) for the CEL field and event-type contracts,
[Agent coverage](agent-coverage.md) for source-specific support, and the
[record schemas](schema/v0.3.0/) for the emitted wire format.
