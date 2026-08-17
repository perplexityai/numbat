# Contributing to numbat

numbat is a single Go module and binary. Contributions should preserve its
deterministic, endpoint-local design and the architecture boundaries below.

## Before you start

- Report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md),
  not a public issue.
- For a bug, include the output of `numbat version`, the operating system and
  architecture, a minimal reproduction, and sanitized diagnostics.
- Discuss large features or architecture changes in an issue before investing
  in an implementation.

## Development setup

Use Go 1.26.6 or newer; CI pins 1.26.6.

```sh
go build ./cmd/numbat
go test ./...
```

Normal builds use the committed generated rule data. After changing a built-in
rule or the CEL environment, regenerate it with `go generate ./rules`.

## Required checks

The gating jobs are defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
Run the applicable checks from the repository root before opening a pull request:

```sh
go mod tidy
git diff --exit-code -- go.mod go.sum
go generate ./rules
git diff --exit-code -- rules/internal/checked
test -z "$(git ls-files --others --exclude-standard -- rules/internal/checked)"
gofmt -l .
go vet ./...
go test -race ./...
go build -buildvcs=false ./cmd/numbat
golangci-lint run
golangci-lint fmt --diff
govulncheck ./...
```

`gofmt -l .` must print nothing. CI uses golangci-lint v2.12.2 and
govulncheck v1.6.0. It also runs bounded 30-second fuzz targets for selected
artifact parsers, redaction decoder, and OTLP decoder. To reproduce one target:

```sh
go test -run='^$' -fuzz='^FuzzString$' -fuzztime=30s ./internal/redact/
```

Coverage is reported but does not gate changes. Windows CI runs the non-race
test suite; Linux and macOS run the race-enabled suite.

## Design constraints

Every change must preserve these project contracts:

- **Observe and fail open by default.** numbat blocks only after an operator
  enables enforce mode. A numbat error, panic, or uncertain result suppresses
  its deny response; an agent host can still impose a stricter failure policy.
- **High precision; no fabrication.** Prefer a documented false negative to a
  false positive. Emit only values supported by the source artifact or payload.
- **Verify vendor schemas with evidence.** Agent-adapter changes must cite
  current primary documentation or source and add a sanitized fixture or
  generated-integration contract test for every mapped action.
- **One module and one binary.** Do not split the monitoring and forensics planes
  into separate modules or executables.
- **No cgo, SQLite, or unreviewed heavy dependencies.** Direct dependencies are
  limited to `github.com/google/cel-go`, `github.com/klauspost/compress`,
  `go.etcd.io/bbolt`, `golang.org/x/sys`, `google.golang.org/protobuf`,
  `google.golang.org/genproto/googleapis/api`, `go.yaml.in/yaml/v3`, and
  `mvdan.cc/sh/v3`. Adding one requires explicit review.
- **Use `indicator` on the wire.** Do not introduce `IOC` into record fields or
  record-type names.
- **Version the wire contract deliberately.** A breaking record-shape change
  requires a schema-version bump, updated JSON Schemas, and migration guidance.

## Architecture boundaries

The `internal/archguard` tests enforce the package and dependency boundaries:

- **Core** (`applypatch`, `model`, `redact`, `rule`, `sequence`, `finding`,
  `pipeline`, `output`, `winfile`) must not import a plane package.
- **Forensics** (`extract`, `discover`, `casebundle`) and **monitoring** (`hook`,
  `otel`, `state`) remain independent; neither imports the other.
- Only `state` and `sequence` may import `bbolt`.
- In `cmd/numbat`, scan, timeline, and case files must not import the monitoring
  plane or bbolt. Hook, collect, and ship files must not import the forensics
  plane. `agents.go` is the sole cross-plane reporting bridge.

The same tests reject cgo, unexpected direct dependencies, `replace` directives,
and unclassified non-test files in `cmd/numbat`. Raise any necessary boundary
change in the pull request; do not weaken the guard as a shortcut.

## Pull requests

- Keep each pull request focused on one logical change.
- Add or update tests for behavior changes and documentation for user-visible
  changes.
- Explain contract, schema, rule-version, security, and compatibility effects in
  the pull-request description.
- Include the exact verification commands you ran.
- Follow the surrounding naming and style. Comments should explain rationale or
  constraints that the code cannot express.
- Remove obsolete code and keep abstractions tied to a demonstrated need.
