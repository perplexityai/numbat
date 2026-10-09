# Content capture

Use `--emit events --content raw` when downstream security analysis needs
original mapped message and tool content. Use `--content full` when the
export should mask recognized secrets, or `--content preview` for the default
compact output. The same modes apply to scan, hooks, installed hooks and the
OTLP collector; timeline supports full and raw with `--format json`.

One option controls message bodies, tool arguments and tool results. Separate
input/result switches would make partial capture easy to configure by mistake.
Full retains its existing redaction policy while expanding to tool content;
raw makes the unredacted choice explicit. The default remains preview.

Rules inspect retained original payloads before this output choice is applied.
Use `event.tool_input` and `event.tool_result` for tool content; `event.content`
keeps its conversation-only meaning. Payloads are JSON-encoded strings so the
flat schema accommodates objects, arrays, strings, numbers, booleans and null.
See [rule semantics](rules.md#event-fields) and the
[0.5.0 migration](schema/v0.5.0/README.md#migration-from-040).

## Retention and delivery

| Boundary | Limit and behavior |
| --- | --- |
| Message body | Retains up to 1 MiB with byte count and truncation flag. |
| Each mapped tool input/result | Retains up to 16 MiB of JSON with byte count and truncation flag. |
| Artifact JSONL line | Existing 16 MiB source-line bound; oversized lines produce diagnostics. Whole-artifact limits also apply. |
| Live hook / OTLP request | Existing 4 MiB request bound; oversized requests are rejected with diagnostics. |
| HTTP sink buffer | 64 MiB; a larger record cannot be buffered. Delivery failures remain observable. |
| Shipper / case / rule-fixture record | 64 MiB record bound; receiver limits can be lower. |

The tool bound aligns with the existing artifact record bound instead of
introducing another small preview limit. Larger downstream bounds accommodate
JSON escaping and paired input/result content. None of these limits guarantees
that the originating agent supplied a complete result. Inspect diagnostics as
well as truncation flags. A receiver's HTTP 413 can still prevent delivery;
`ship` retains the source file record and reports the rejected record.

Incomplete tool JSON is retained as a flagged prefix in raw mode. Full mode
replaces it with an omission marker because a partial document cannot safely
be redacted by key. Rules that read an incomplete tool body receive a scoped
evaluation error, preserving the existing fail-open enforcement contract.
Keep the original artifacts when analysis needs content beyond these bounds.

## What is preserved

Argument capture also applies to specialized shell, file and network actions,
not just generic `tool.call` events. Result capture preserves unknown fields,
structured results and non-text blocks instead of extracting only text previews.
It does not follow paths or URLs found in content, execute tools, decode image
content, or retrieve files that an agent chose to offload.

| Source | Captured representation |
| --- | --- |
| Claude artifacts | Tool-use input and result blocks; source-native `toolUseResult` is retained alongside a single attributable result. |
| Codex artifacts | Function/custom arguments or input and output; correlated native MCP results are retained alongside model-facing output. |
| Other mapped artifacts | Source arguments and recorded result objects at their evidence locations, including OpenCode read output. |
| Hooks | Arguments and the supported completion hook's response, including empty, scalar and structured values. |
| Generated integrations | OpenCode output, Pi content/details/error, Amp output and OpenClaw result/error are forwarded. Reinstall hooks to update generated integrations. |
| OTLP | Record-level tool arguments and results when the producer sends them. Resource attributes do not fabricate completion events. |

Claude's [hook contract](https://code.claude.com/docs/en/hooks#posttoolbatch)
distinguishes the native `PostToolUse` output from the model-facing
`PostToolBatch` response. The installed integration currently uses the former;
it does not subscribe to `PostToolBatch`. Artifact capture can expose both
representations, but hooks alone are not a complete model-input archive.
When a source-native result accompanies multiple result blocks without an
unambiguous join, it is not assigned to an arbitrary tool call.

Codex's existing command normalization can fold internal execution polling
into the original command. A native MCP end record without a corresponding
mapped output is not independently emitted. Raw mode does not turn these
normalized timelines into an archive of every source record.

Synthetic MCP runtime experiments with Claude Code 2.1.293 and Codex 0.161.0
found that Claude can replace large results with an offload notice and can
round an integer before emitting its hook payload. Codex exposed a large
result and both text and structured MCP content in its live JSON stream.
The saved rollout in that environment contained execution-wrapper results
instead, and did not retain all nested MCP responses. Numbat's rollout parser
does not ingest the separate `codex exec --json` stream. Synthetic rollout
fixtures test the native MCP mapping, but do not establish completeness for
that runtime configuration.
These observations describe those versions and modes, not universal host
guarantees. Tests preserve numbers and original supplied values inside Numbat.

For downstream completeness, retain raw-mode records, monitor diagnostics,
retain agent artifacts where available, and reconcile by source, session and
tool-call ID. A hook observation and an artifact observation of the same call
are separate evidence sources; counting both as invocations inflates totals.

Case bundles copy selected event records as supplied. Evidence redaction
options apply to copied evidence files, not to the record stream: building a
case from raw-mode records preserves their unredacted content.
