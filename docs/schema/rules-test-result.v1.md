# rules-test-result.v1

`numbat rules test --json` emits an NDJSON result stream on stdout. This
document is the authoritative machine-readable contract; every consumer must
treat unknown fields as reserved. The schema versions independently of the
record wire schema (`model.SchemaVersion`) because it describes a CLI-adjacent
direct-evaluator surface, not a record shape emitted by the pipeline.

- Every line is one JSON object.
- One `event_result` object per fixture line that reached evaluation.
- Exactly one terminal `summary` object.
- Stdout carries only these objects; logs, human-facing messages, and errors
  go to stderr.

Exit codes:

- `0`: `summary.status == "completed"` with a passed or unchecked assertion,
  delivered as a well-formed NDJSON stream terminated by exactly one
  `summary` object.
- `1`: `summary.status == "partial"` OR a failed assertion, delivered as a
  well-formed NDJSON stream terminated by exactly one `summary` object.
  This is a successfully delivered result, not a delivery failure.
- `2`: one of two cases that share this exit code and are distinguished
  by looking at stdout and stderr:
  - Handled JSON delivery failure. A stdout write for an `event_result`
    or the terminal `summary` returned an OS write error (ENOSPC,
    read-only descriptor); the process caught it, wrote a
    `write rules-test-result:` diagnostic to stderr, and short-circuited
    the remainder of the stream. Any partial stream on stdout is not
    terminated by a `summary`.
  - Usage or setup failure raised before any stream is produced. For
    example, `rules test --json` without `--fixture` prints a usage
    diagnostic to stderr and exits 2 with empty stdout.

Exit code alone is not sufficient to identify delivery failure. A
usage/setup failure exits 2 before any stream, and abnormal process
termination (SIGPIPE on a real broken pipe, SIGKILL, panic, host death)
may end the process before the handled exit-2 path runs and before a
terminal `summary` is written - the observed exit status in that case is
signal-encoded (for example a Python subprocess returncode of `-13` for
SIGPIPE), not `2`.

Consumer rule: only a well-formed NDJSON stream terminated by exactly one
`summary` object AND an exit status compatible with that summary
(`0`/`1`/`2` as described above) proves the documented outcome. A missing
terminal `summary`, a malformed or truncated final JSON line, or an
abnormal/signal-encoded termination cannot prove a clean no-match and
must be treated as an indeterminate delivery outcome - not silently
reclassified as delivery failure, and not silently accepted as success.
Consumers should read the summary object rather than infer completeness
from the exit code alone.

## event_result

```
{
  "type": "event_result",
  "schema_version": "rules-test-result.v1",
  "fixture_line": 1,
  "event_id": "e1",
  "status": "completed",
  "findings": [
    {
      "rule_id": "secrets.agent_read_env",
      "rule_version": "1.0",
      "severity": "high",
      "enforcement_eligible": true,
      "via": "engine"
    }
  ],
  "coverage": {"shell_parse": "ok", "sequence_tracker_active": false}
}
```

A `status == "completed"` event carries no `evaluator_errors` and no
`error`; both fields are omitted from the wire when empty. Any per-rule CEL
failure or sequence-tracker error promotes the event to
`status == "evaluation_failure"`, at which point those errors appear in
`evaluator_errors` and `error` is populated with the failing `kind`.

- `fixture_line` (int, required): 1-based line number in the fixture. Blank
  lines are skipped and do not receive an `event_result`.
- `event_id` (string, optional): copied from the decoded event; absent when
  decoding failed before an id was known.
- `status` (string enum, required): one of
  - `completed`: the event was evaluated and any matches appear in
    `findings`. `findings: []` (or the field omitted) is the only legitimate
    representation of a clean no-match. A downstream consumer must not
    infer "no match" from a missing `event_result`.
  - `malformed_input`: the fixture line failed JSON decode or event
    validation, or the input stream itself could not be scanned (line too
    long, IO error). `error.kind` is `decode`, `validate`, or `scan`.
    Fixture processing stops at this event; the summary reports
    `status: partial`. A `scan` failure attributes the failing
    `fixture_line` to the next unread line and carries no `event_id`.
  - `evaluation_failure`: at least one rule's CEL program errored at
    runtime, or the sequence tracker returned an error. Matches from other
    rules on the same event still appear in `findings`; every failing rule
    still appears in `evaluator_errors`, and a per-rule CEL failure and a
    sequence-tracker failure may both surface for the same event.
    `error.kind` names the failure that stopped the fixture (`sequence`
    when the tracker failed, otherwise `evaluation`). Fixture processing
    stops.
- `findings` (array, optional): one entry per matching rule.
  - `rule_id` (string, required)
  - `rule_version` (string, required)
  - `severity` (string, optional): the compiled rule's declared severity.
  - `enforcement_eligible` (bool, required): mirrors the flag that gates
    the live enforce path (accounting for shell-enforcement-safety). A
    finding with `enforcement_eligible: false` is advisory even though the
    rule declares `enforce: true`.
  - `via` (string enum, required): `engine` for a single-event evaluation,
    `sequence` for a completed sequence chain. Sequence findings cite the
    event that terminated the chain.
- `evaluator_errors` (array, optional): named rule failures for the event.
  - `rule_id` (string, optional): missing when the failure was not
    attributable to one rule (for example, a sequence tracker error).
  - `message` (string, required): raw error text; treat as diagnostic only.
- `coverage` (object, optional):
  - `shell_parse` (string enum, required): `ok`, `degraded`, or `unusable`.
    `unusable` means rules that read `shell_commands` were skipped for the
    event; a consumer must not infer a clean no-match in that case.
  - `sequence_tracker_active` (bool, required): true when the compiled
    catalog contains at least one sequence rule (i.e. a window tracker
    exists for this run). The tracker is only asked to observe events that
    carry a `session_id`; a `true` value does not by itself imply this
    event was folded into a window.

- `error` (object, optional): populated when `status` is not `completed`.
  - `kind` (string enum, required): `decode`, `validate`, `scan`,
    `evaluation`, or `sequence`.
  - `message` (string, required): includes the fixture line for context.

## summary

```
{
  "type": "summary",
  "schema_version": "rules-test-result.v1",
  "status": "completed",
  "events_evaluated": 3,
  "matches": 2,
  "rules_loaded": 51,
  "enforce_eligible_rules": 24,
  "assertion_outcome": "unchecked",
  "assertion_missing": null,
  "stopped_at": null,
  "numbat_version": "dev+abc123",
  "record_schema": "0.3.0"
}
```

- `status` (string enum, required): `completed` if every fixture line was
  processed, `partial` if the stream stopped early. A completed run with a
  failed assertion is still `completed`; see `assertion_outcome`.
- `events_evaluated` (int, required): number of fixture lines that
  reached direct evaluation, including any final line that ended in
  `evaluation_failure`. Lines that failed decode/validate/scan before
  evaluation are excluded.
- `matches` (int, required): total findings emitted across all
  `event_results` (single-event and sequence combined). `matches` may
  exceed `events_evaluated`: several direct rules can match one event, and
  each sequence finding adds to `matches` without adding to
  `events_evaluated`. Consumers must not assert `matches <=
  events_evaluated`.
- `rules_loaded` (int, required): count of compiled rules in the effective
  catalog.
- `enforce_eligible_rules` (int, required): count of compiled rules that
  may block in live enforce mode. Independent of whether any matched.
- `assertion_outcome` (string enum, required): `passed`, `failed`, or
  `unchecked`. A `partial` run always reports `unchecked` so that
  fixture-processing failures are not conflated with assertion failures.
- `assertion_missing` (array, optional): rule ids passed via `--expect` that
  produced no matches when `assertion_outcome == "failed"`.
- `stopped_at` (object, optional): populated when `status == "partial"`
  and only then; every `partial` run carries it.
  - `fixture_line` (int, required)
  - `reason` (string enum, required): `malformed_input` or
    `evaluation_failure`; mirrors the last event_result's status.
- `numbat_version` (string, required): the running binary's version string
  (as `numbat version` would report).
- `record_schema` (string, required): the current event/finding wire schema
  version (`model.SchemaVersion`). Independent of `schema_version` above.

## Compatibility

A future `rules-test-result.v2` will change `schema_version`. Additive
fields inside a version (new optional keys, new enum values in a documented
enum extension) do not bump the major version; consumers must ignore unknown
keys and treat unknown enum values as an unrecognized class rather than
`completed`.
