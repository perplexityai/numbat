# Enforcement

numbat hooks monitor by default. Enforce mode is an explicit opt-in that lets a
supported synchronous pre-action hook ask the host to deny an action matched by
a rule marked `enforce: true`.

This page defines the enforcement model and trust boundary. See
[agent-coverage.md](agent-coverage.md#enforcement) for per-agent coverage,
[live-capture.md](live-capture.md) for installation, and
[rules.md](rules.md) for rule authoring.

## Control flow

The agent host remains the enforcement point:

1. The model proposes a tool action.
2. The host invokes its pre-action hook before executing the tool.
3. numbat validates and normalizes the payload, evaluates rules, and emits
   operator records.
4. On a clean enforced match, numbat returns that host's native deny response.
   Otherwise it returns no override of the host's normal permission flow.
5. The host interprets the response and decides whether to execute, prompt, or
   reject the action.

numbat does not execute or cancel the tool itself. A structured deny field or
blocking exit status asks the host to reject the action. The host—and often the
model—can still observe that request. The generic response keeps rule and
evidence details out of the control channel; it does not conceal the deny.

## Rule effect

Enforcement is selected per rule:

```yaml
id: local.protected_action
version: "1.0"
title: Protected action
severity: high
enforce: true
expr: |-
  event.event_type == "command.exec" &&
  shell_commands.exists(command, command.name == "example")
```

Severity describes a finding's priority; it does not enable blocking. A rule
without `enforce: true` remains detection-only at every severity.
The shipped catalog is monitor-only; `--enforce` alone does not turn its
findings into denies.
An enforce-mode install compiles the effective catalog before changing agent
configuration and refuses unless at least one enabled rule sets
`enforce: true`. Its rule directories must be concrete and readable at install
time; deferred paths such as `$HOME/rules` are not accepted for enforcement.

To enforce a shipped detection selectively, copy its complete YAML file from
the matching release's [shipped catalog](../rules/) into a controlled operator
rules directory, keep the same id, set `enforce: true`, and bump the rule
version. Validate the effective catalog, then deploy the same directory with
the hook:

```sh
numbat rules check --rules-dir /etc/numbat/rules
numbat hook install --agent codex --managed --rules-dir /etc/numbat/rules --enforce
```

The same-id operator rule replaces the embedded definition as a whole; omitted
fields are not inherited. Protect that directory like the numbat binary and
managed hook configuration.

numbat exposes only observe and deny effects. Agent hosts do not share portable
approval, rewrite, or stop semantics, and an explicit allow could bypass a
host's own approval flow.

Enforcement uses the same CEL expressions as detection; setting `enforce: true`
is the only rule-format change. Raw `event.command` is valid, but it matches
literal input and can include comments, quoted examples, or other text the
shell would not execute. Use the parsed `shell_commands` view when a deny
depends on executable command semantics.

Detection parses a broad set of shell structures. When a match is derived from
`shell_commands`, blocking uses a smaller static subset:

- POSIX shells: one simple command or one pipeline of simple commands
- PowerShell and `cmd.exe`: one simple command
- supported transparent launchers, only when the final child command meets the
  same rules

Every projected command must have static arguments, assignments, and redirect
targets. Multiple statements, conditionals, loops, shell background syntax,
substitutions, same-script functions, inline child interpreters, `eval`,
`Invoke-Expression`, PowerShell or CMD pipelines, previews, parser diagnostics,
and truncated projections stay detection-only. This event-wide gate avoids
denying an action based on a command that may not execute.

numbat recognizes explicit `-WhatIf` and a statically visible
`$WhatIfPreference = $true` for known cmdlets. It does not infer ambient
preference or command-resolution state. Recognized mutable PowerShell aliases
cannot authorize a deny.

## Decisions

| numbat decision | Hook response | Host behavior |
|---|---|---|
| `no_override` | Native passthrough; exit 0 | Preserve the host's normal permission flow |
| `deny` | Native structured deny, or exit 2 with a reason where required | Host interprets the deny request according to its hook contract |

Passthrough syntax is also host-specific. For example, Amp spells it
`action:"allow"` and Antigravity spells it `decision:"ask"`. Those are adapter
encodings of the normal host path, not additional numbat rule effects.

Fail-open means numbat withholds its deny response. It does **not** guarantee
that the tool executes: the host may still prompt, deny, time out, or apply
another hook or policy. Copilot CLI is a notable host-level exception because
some hook launch failures and non-zero exits deny even when numbat did not
produce a decision.

When findings are selected, each matched, enforce-capable pre-action callback
also emits a `record_type:"enforcement"` record. Its `deny` or `no_override`
decision joins to findings and action events by identifier and names the deny
rule when applicable. The record is written in the existing operator batch
before the control response; it does not prove response delivery or host
behavior.

## Deny reason and operator output

The default deny reason is:

```text
Action denied. Do not retry or attempt an equivalent action.
```

It intentionally omits rule ids, titles, expressions, and evidence. A rule can
provide an operator-approved replacement:

```yaml
enforce: true
deny_message: Contact the workspace owner.
```

`deny_message` must be a single control-free line of at most 512 UTF-8 bytes.
Use an override only when that text is safe to disclose. The host decides
whether its reason is shown to the model, the user, or both.

Operator detail travels separately. Enforce mode requires findings and a
`file`, `spool`, or `http` sink. It rejects stdout because hook stdout is part
of the host control protocol. Once the sink is open,
numbat routes available operational diagnostics there as diagnostic records
rather than onto the immediate agent channel.

The default file is owned by the same OS user as the agent. Calling it
out-of-band means it is separate from the hook response, not that the agent
cannot read it. Deployers that require stronger isolation must protect the
binary, hook configuration, sequence state, output path, and network
destination with OS or platform controls.

## Clean-decision gate

numbat requests a deny only when all applicable checks complete cleanly:

- the callback is a supported synchronous pre-action lifecycle
- the payload is a bounded JSON object that maps to a valid normalized event
- an enabled rule with `enforce: true` matches
- any shell command match is within the static enforcement subset above
- the matching rule's relevant projection evaluates successfully
- finding emission is enabled
- every selected event, finding, indicator, and enforcement record is accepted,
  and the configured sink closes cleanly
- sequence state is available when the decision depends on a sequence

Malformed payloads, relevant evaluation errors, panics, and output failures
suppress the numbat deny. If sequence state is unavailable, correlation is
skipped, but an independent clean stateless match can still deny.
An unrelated rule diagnostic does not erase a separately proven match.

Hook input is limited to 4 MiB. Oversized input follows the same fail-open path:
numbat emits no deny response and reports a diagnostic.

For a sequence rule, only the action matching its final step can be denied;
earlier steps are already-observed history. `max_matches` caps sequence
findings, not enforcement, so repeating the final action cannot use a finding
quota to bypass a deny.

## Coverage limits

Only synchronous pre-action hooks can block. Post-action hooks, OTLP records,
and at-rest artifacts arrive after execution and are observation-only.
OpenCode is currently monitor-only. Other integrations remain bounded by the
events and tools their hosts actually expose; hook coverage is not a complete
endpoint policy boundary.

OpenClaw has two distinct failure boundaries. Its generated wrapper returns no
block when the numbat child fails or reaches its internal nine-second deadline,
but OpenClaw's `before_tool_call` host runner fails closed if the plugin handler
itself escapes with an error or exceeds the host timeout. Keep that host timeout
strictly above nine seconds (the generated value is ten seconds). numbat
evaluates the tool
parameters presented at `before_tool_call`; another modifying plugin can
contribute final rewritten parameters regardless of priority/order because
OpenClaw gives every handler the original event and merges their results.

Host protocols and tool names can change independently. numbat keeps native
request mappers and deny renderers behind its hook adapter layer and tests each
implemented enforcement capability against exactly one deny transport. The
coverage matrix documents known upstream gaps and version requirements.

## Rollout

Follow the [live-capture rollout](live-capture.md#monitor-and-enforce): validate
payloads and durable output in monitor mode before enabling enforcement. Test a
known non-match, a known deny, malformed input, sink unavailability, and the
host's approval behavior. Keep monitoring delivery because an unavailable sink
intentionally suppresses numbat's deny.
