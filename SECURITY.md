# Security Policy

## Reporting a vulnerability

Report vulnerabilities through GitHub's private vulnerability reporting for
this repository:

<https://github.com/perplexityai/numbat/security/advisories/new>

Include the affected version, impact, reproduction steps, and any suggested
mitigation. Use synthetic data and remove credentials, transcripts, and customer
content. Do not file a public issue or disclose the finding before the
maintainers have assessed it and coordinated a fix.

## Supported versions

Only the most recent minor release receives security fixes.

## Security model

numbat processes untrusted, highly sensitive agent artifacts and live payloads.
They can contain prompts, tool output, commands, source snippets, local paths,
environment values, credentials, and MCP configuration.

### Data handling

- Artifact scans and timelines are read-only. numbat never executes an agent,
  package manager, or command found in an artifact. Explicit commands can write
  hook configuration, output files, sequence state, and case bundles.
- numbat makes no outbound request unless an operator configures an HTTP sink,
  runs `ship`, or explicitly enables a decision evaluator through
  `--decision-config`. Decision evaluation requires HTTPS and separate
  `send_content` consent; it can transmit projected tool arguments and results
  to the configured model provider. Ordinary rules and offline commands do not
  enable it. Non-loopback HTTP sink destinations require HTTPS unless
  `--http-allow-insecure` is set explicitly.
- `collect` binds to `127.0.0.1:4318` by default. It provides no client
  authentication or TLS when bound to another interface. Do not expose it to an
  untrusted network; use network controls or an authenticated proxy.
- Default record output is findings only. Normal output never includes a
  complete raw transcript, but records can retain redacted commands, paths,
  URLs, content previews, endpoint identity, and model context.
- `--content full` explicitly includes bounded, redacted message text and tool
  arguments/results, including source code, file bodies and patches when
  provided. `--content raw` includes mapped content without redaction. Neither
  mode archives the entire source transcript. Scope defaults to `all`;
  `--content-scope messages` omits tool bodies while keeping redacted previews,
  typed fields and tool size/truncation metadata. In raw messages scope, only
  message bodies are unredacted.
  Rules inspect retained originals before output redaction. Choose the mode,
  scope and storage access controls for the intended analysis; redaction can
  remove security-relevant evidence.
- Redaction masks recognized secret patterns; it is not a declassification or
  data-loss-prevention boundary. Review records and redacted case evidence
  before sharing them.
- Project-path hashes are stable, unsalted join keys. Treat them as
  pseudonymous sensitive metadata; they do not anonymize predictable paths.
- File-backed evidence can include a local path and SHA-256 digest. Hook and
  OTLP evidence can omit both because there may be no local artifact.
- Sequence state can contain event identifiers, evidence references, tags,
  confidence, and timestamps. Protect the state database and output files as
  sensitive endpoint data.
- Opt-in session decision evaluation additionally retains its bounded inference
  projection in the state database. Its directory must be private (0700), and
  the database private (0600). Logical retention does not securely erase bbolt
  pages. Raw inference egress is separate from raw output and requires explicit
  configuration; redaction is not declassification.
- Copying raw evidence into a case bundle is opt-in. Raw and redacted bundles
  can still contain secrets or private content.

### Hooks and enforcement

- Installed hooks run with the agent process's operating-system privileges.
  User-scoped configuration, state, and output remain mutable or readable by
  that user unless stronger OS controls protect them.
- Monitor mode is the default. Enforce mode is opt-in, applies only to supported
  synchronous pre-action hooks and enforcement-enabled rules or explicitly
  configured decision policies, and asks the agent host to deny an action.
  The host remains the enforcement point.
- A decoding error, relevant evaluation error, or output failure suppresses
  numbat's deny response. Unavailable sequence state prevents a sequence-based
  deny but does not suppress an independent clean stateless deny. The host can
  still prompt, deny, or fail closed under its own hook contract. See
  [docs/enforcement.md](docs/enforcement.md).
- An optional evaluator error, timeout, malformed answer, or abstention
  contributes no semantic deny and never cancels an independently proven
  deterministic deny. A model's non-matching answer is not host authorization.
  Semantic enforcement requires policy, binding, and global enforcement
  opt-ins, complete/fresh evidence, and the operator's verified
  `no_argument_rewriters` assertion. See the
  [decision evaluator design](docs/design/decision-evaluators.md).
- Decision configuration, policy files and credentials are root-owned and
  non-writable by the agent by default. `--decision-user-config` explicitly
  weakens ownership to permit the current user and offers no protection against
  that same user. Even root-owned credentials readable by a hook are readable
  by other processes with its OS identity; use a narrowly scoped credential.
  Optional policy fingerprints detect changes relative to operator-supplied
  pins; they are not signatures, approval records or a substitute for file
  ownership. Requests are always bound to the actual loaded policy.
- Hook payloads and writable evidence state are not authenticated against the
  agent's OS identity. A same-user process can forge observations, alter context,
  or force fail-open. Protected configuration and random state generations do
  not make the captured prefix tamper-resistant.
- Complete-prefix status describes observed callback consistency, not guaranteed
  delivery. A proposal lost before state observation may remain invisible until
  an unpaired outcome exposes it; a fully lost callback cannot be inferred.
  Contextual evaluation is best-effort, not a gap-free execution ledger.
- Identified Claude child activity invalidates parent contextual enforcement;
  child histories are separate and cannot contribute semantic denies. Partial
  parent/child assessments remain available. A malformed `agent_id` or a child
  boundary without identity records a gap, not main-agent evidence. An ordinary
  tool callback without any child marker relies on the host's identity contract.
  Delegation can avoid semantic blocking, and known background launches are
  ineligible. These policies are not a containment boundary for those actions.
- Hook input is limited to 4 MiB. Oversized or malformed input produces a
  diagnostic and no numbat deny response.
- `hook status` verifies numbat-owned configuration on disk; it does not prove
  that an agent trusted, loaded, or ran the hook or delivered a record.

Findings report observed evidence and rule matches, not conclusions that cannot
be established from the source data.
