# numbat record schemas v0.3.0

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

Conversation events always use a bounded `content_preview`. Optional `content`,
`content_bytes`, and truncation fields describe the fuller source text when the
caller explicitly requests it; file bodies, patches, and arbitrary tool output
are outside this contract.

On findings, `timestamp` is the matched event's activity time (the completing
event for a sequence) and may be absent when that event has no valid timestamp.
`detected_at` is when numbat created the finding.
