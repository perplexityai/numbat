# Bounded transport representations v0.5.0

This version describes only shortened event and finding representations emitted
by `ship`. It is not a new ordinary `model.Event` schema: unchanged records and
exact retained originals keep their original version, normally `0.4.0`.

## Receiver migration

One ship stream may contain both ordinary records and `0.5.0` bounded
representations. Select the schema by `schema_version`, then `record_type`.
A receiver supporting only the closed `0.4.0` schema must be updated before
bounded delivery; a successful transport acknowledgment does not prove that
downstream schema validation or ingestion succeeded.

The logical event or finding ID is unchanged. Do not interpret shortened
commands as the complete observed command or rerun detection against them.
The original remains necessary for complete evidence.

## Representation contract

`event.evidence.transport` or `finding.evidence_refs[0].transport` is required.
Its version-1 marker names the shortened field and records the exact original
NDJSON and field byte counts and SHA-256 digests. Original-record bytes include
the trailing newline. Evidence provenance and all other envelope fields remain
unchanged, except `schema_version`.

For shortened event `content`, `content_bytes` retains its original value and
`content_truncated` becomes true. Preview boundaries preserve complete UTF-8
characters. Indicator, enforcement and diagnostic records are not shortened.

Only known versioned originals (`0.2.0`, `0.3.0`, `0.4.0`) with required evidence
provenance support this fallback. An unversioned, unknown-version, or otherwise
unrepresentable oversized original remains pending with an error; ordinary
delivery does not add or change its version. Existing transport markers are
rejected rather than overwritten.

The file original remains subject to local file retention. For a spool, the
exact original is retained atomically with acknowledgment after a bounded
representation receives HTTP success. Use the read-only spool export workflow
to recover it; the shortened representation cannot reconstruct it.
