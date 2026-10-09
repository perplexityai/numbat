# numbat record schemas v0.5.0

This directory contains JSON Schema Draft 2020-12 contracts for numbat's emitted
NDJSON records.

- `record-stream.schema.json` accepts any record line from the main record
  stream (`event`, `finding`, `enforcement`, `indicator`, or terminal
  `scan_summary`) or the separate diagnostic stream (`diagnostic`).
- The per-record schemas are the contracts to use when a downstream receiver
  routes on `record_type`.

Configure your validator to resolve the relative `$ref` values in
`record-stream.schema.json` against this directory.
Enable `date-time` format assertions when validating. The time-field patterns
enforce lexical and UTC shape; format assertions reject impossible dates.

Every emitted line carries an `endpoint` object with `hostname`, `os`, `arch`,
`username`, and `uid`. Set `NUMBAT_DEVICE_ID` to add a stable opaque
`endpoint.device_id` for fleet joins.

The schemas describe the emitted wire shape. They do not change runtime
behavior. They keep numbat's flat [event model](../../event-model.md): rules
evaluate the same field names that records emit.

Action event types are alternatives, not layers. A recognized shell, file, or
network tool action uses `command.exec`, `file.*`, or `network.indicator`
instead of an additional `tool.call`; `tool.call` is the fallback. When a
source provides a separate outcome, shell outcomes use `command.result` and
other outcomes use `tool.result`. A structured multi-file edit may expand to
one file event per affected path.

When findings are selected, a matched, enforce-capable pre-action hook also
emits an `enforcement` record with numbat's computed `deny` or `no_override`
decision. It joins to rule matches and the proposed action through
`finding_ids` and `action_event_ids`. The record is written before the control
response and does not prove response delivery or host behavior.

Evidence refs always carry `artifact_type`. File-backed refs also carry
`local_path`; live hook and OTLP refs may omit it because there is no local file
to reopen.

`event.project_path`, `event.file_path`, and finding `observed_file_path` use `/`
separators on every operating system so one rule works across platforms.
`evidence.local_path` remains host-native because it is an endpoint reopen path.

Context fields such as `model`, `model_provider`, and `entrypoint` are
source-specific and omitted when the source does not record them.

## Migration from 0.4.0

Records are stamped `0.5.0`. Consumers that validate exact versions or closed
schemas must select this directory. Earlier schema directories remain valid
for earlier records.

Tool actions and outcomes now support `tool_input`, `tool_result` and each
field's `_bytes` and `_truncated` metadata. Bodies are JSON-encoded strings;
missing bodies are omitted, while explicit JSON null is the string `"null"`.
The fields also occur on specialized command, file, network and permission
events. Preview records can contain metadata without bodies.

`--content full` now includes redacted tool arguments and results as well as
message bodies. Existing full-mode consumers must allow larger records and
potentially sensitive source code, file bodies and patches. `--content raw`
opts into unredacted mapped content. `content` remains conversation-only.
Messages retain their 1 MiB bound; each tool payload has a 16 MiB bound.
Tool byte counts describe JSON bytes before retention and redaction, not the
size of a source file or an assurance that upstream content was complete.
Truncated JSON is omitted with a marker in full mode; raw mode can retain a
flagged prefix. See [content capture](../../content-capture.md).

Local rules receive original tool payloads regardless of export mode. A rule
that reads an incomplete tool body receives a scoped evaluation error. Preview
exports with known omitted bodies behave the same way during rule replay.

On findings, `timestamp` is the matched event's activity time (the completing
event for a sequence) and may be absent when that event has no valid timestamp.
`detected_at` is when numbat created the finding.
