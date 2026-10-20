# Executable work acceptance

`work-acceptance` executes explicitly trusted checks against an immutable work package and current plan/spec. It preserves separate build, unit, live-harness and original-comparison results. Passing a build never establishes behavior equivalence, and a local test result never automatically accepts a work-ledger submission.

## Run and inspect

```sh
recarve work-acceptance run ./task --root ./implementation \
  --checks ./checks.json --plan ./plan.json --spec ./work-spec.json \
  --out ./acceptance-run --execute
recarve work-acceptance read ./acceptance-run --package ./task \
  --root ./implementation --plan ./plan.json --spec ./work-spec.json
```

`carve_work_acceptance` exposes `run` and `read` to MCP clients. Run requires `execute:true` and existing authorization to execute the supplied trusted code. Commands use host permissions; path validation and a clean environment are not a malicious-code sandbox. The MCP confines its own package/spec/input/report reads to authorized paths, but executed programs can access the host. REA remains separate.

## Check specification

A `carve/acceptance-spec@1` object has:

- `packageId`: the exact work-package ID.
- `files`: 1–64 implementation-relative `{path, sha256}` pins, including every command entry and cases file. Declare supporting dependencies as well; unlisted transitive dependencies are not authenticated.
- `checks`: 1–32 checks, each with a unique `id`, `kind`, named `acceptance` criteria and `command`.

A command is `{runtime:"node"|"direct", file:"relative/path", args:[]}`. Node uses RECarve's current executable; direct mode executes the pinned file. No implicit shell is used. Scripts may themselves launch tools; those tools and libraries are not automatically inventoried. Do not put credentials in command arguments, specifications or outputs: reports retain them. The implementation root is the working directory; stdin is empty for non-comparison checks. Environment contains PATH, local HOME/temp and a fixed language, without inheriting credential variables.

`build` checks require zero exit status and optionally exact `expectedStdout`. `unit` and `live` checks require exact `expectedStdout` (empty is allowed). These are declared assertions/harness observations, not proof of test quality or direct UI exercise. Behavior scenario criteria additionally need a matching `validation` kind. A build cannot satisfy any generated behavior criterion; stateful scenarios require sequence comparison. Unmapped criteria remain `not-run`.

`original-comparison` adds `comparison` with a distinct pinned `original` command, pinned `cases` path, `mode`, declared `scope` (`target-cli` or `declared-harness`) and explicit `limitations`. Each command receives one JSON argument array on stdin and must emit one finite JSON value with exit status zero. Matching command failures never count as a pass. Non-sequence cases use:

```json
{"schema":"carve/acceptance-cases@1","cases":[{"name":"positive","args":[5],"expected":10}]}
```

`mode:"stateful-sequences"` reuses `carve/sequence-cases@1`. A whole sequence's positional argument arrays are sent together; each command returns ordered `{kind:"return",value:...}` or `{kind:"throw",error:{name,message}}` outcomes. Unexpected throw outcomes do not pass by matching one another; represent explicitly expected failure behavior as typed return data in a reviewed adapter. A fresh process is used per sequence, with shared state only inside that sequence's adapter. Contract `sequenceCase` hash/name pins must match. This protocol cannot prove the adapter invoked an original binary, UI or device; review its implementation and declared scope.

## Bounds and results

Pinned input files are streamed in1MiB chunks, capped at8GiB each; JSON specifications/case documents are limited to1MiB. Preflight validates current package/plan/spec pins, criterion names, scenario modes, all declared files and case documents. Execution rechecks file hashes between checks and after execution. Input changes invalidate the run. Commands have 50–30000ms deadlines, 1MiB combined output, cancellation and process-group cleanup on Unix. A run has a 120-second execution deadline, at most 200 comparison cases, 8MiB retained observations and a 16MiB report limit. These are execution bounds, not an OS resource sandbox; Windows descendant termination is weaker. Interrupted/oversized runs can retain an owned partial output directory without a committed manifest; they are not successful reports. Output directories are exclusive and never overwritten.

The result folder contains `report.json` and a SHA256/byte-count manifest. Reports bind package/task/plan/spec IDs, the normalized checks, runtime executable hash, current input pins, actual observations and per-criterion/category results. Read validates report integrity, check/case bindings and totals, current inputs/runtime and current package revision. Stale inputs or tampered reports are refused. Budgeted acceptance rows have exact JSON byte receipts and pagination; full observations remain in the report file. Reporting failure after a command ran does not undo its side effects.

## Bind a reported verification claim

```sh
recarve work-acceptance read ./acceptance-run --package ./task \
  --root ./implementation --plan ./plan.json --spec ./work-spec.json \
  --claim ./reported-claim.json --check-id compare
```

Optional `claim`/`checkId` in MCP performs the same check: a `verified-behavior` claim must match a passing comparison's report, original command file, candidate command file and cases hashes. Failed comparisons and mismatched pins are rejected. Claim prose and adapter invocation remain agent-declared; inspect the actual report scope and limitations. Report scope is finite, never whole-program parity. A claim added to a subsequent plan changes that plan's task identity; it is historical evidence, not acceptance of the revised task.

Reports are **unsigned local integrity records**. Hash checks detect stale/mismatched content; an attacker who can replace both report and manifest can fabricate a record. This is not cryptographic producer authentication. Arbitrary imported reports are not promoted into authenticated provenance, and neither reading a report nor binding claim hashes changes the behavior check's `not-run` state or the work-ledger decision. Existing reconstruction/device verifiers retain their own separate scopes. No generic GUI driver, automated proof of scenario semantics, application merging or skeleton wiring is introduced here.
