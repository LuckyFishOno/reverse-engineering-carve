# Claim provenance

Behavior requirements can carry optional `provenance` with schema `carve/provenance@1`. Classification belongs to an individual claim about a requirement, not to an entire program or report. This keeps resource observations, semantic hypotheses and chosen target behavior separate.

| Claim kind | Required declaration | Meaning |
| --- | --- | --- |
| `original-evidence` | Source SHA256, evidence ID, locator and limits | A reported original static observation; not runtime equivalence |
| `hypothesis` | Basis references (possibly empty) and uncertainty | An inference that still needs investigation |
| `target-design` | Design rationale | A chosen behavior for the new implementation |
| `verified-behavior` | Original/candidate/cases/report SHA256, scope, environment and limitations | A reported comparison claim; not automatically authenticated by this checker |

Every claim includes a unique ID, a `subject` matching a behavior requirement ID, and a precise statement. Multiple claims may describe different aspects of the same requirement. They do not supersede one another or resolve contradictions automatically. Missing classifications remain `unclassified`; legacy evidence IDs and build success never become original-behavior evidence automatically.

## Inspect and preserve

```sh
carve behavior-check examples/behavior/interactive-console.json --view provenance
carve behavior-check examples/behavior/interactive-console.json --view requirements
```

The read-only `carve_behavior_check` MCP supports the same `provenance` view and byte-budgeted pages. Summary returns counts and the number of unclassified requirements. Requirement rows link claim IDs/kinds, while full statements and references are available in provenance pages and the contract file.

Put provenance inside `feature.behavior`, feature-request `contract`, or project-plan `contract.behavior`. Existing contract propagation retains it in immutable scope records and work-package `interface.contract.behavior`, including dependency snapshots. Changes to classifications, source/report pins or comparison scope change contract/task identities; regenerate assignments instead of reusing old work packages. Generated task instructions require preserving the distinctions. The example contains target design only.

## Authority and limits

The checker validates structure, known requirement subjects, unique IDs and content-pin formats. It does not open evidence or report paths, check current source files, run a comparison or authenticate arbitrary declarations. Its summary always returns `authenticated:false`; behavior verification remains `not-run` and semantic match `unconfirmed`, even if a supplied claim uses `verified-behavior`. That label must be presented as a **reported verification claim** until a separate verification path has checked the actual artifacts and result.

Use existing evidence readers and comparison tools for their specific authenticated scopes; do not reinterpret these labels as equivalent to those tools' results. Static callback candidates remain candidates, target UI policy remains design, and a finite original comparison never establishes whole-program equivalence. This schema does not rewrite historical evidence or existing capability manifests. Executable acceptance can check local report/input integrity separately; producer authentication remains outside this schema. REA remains an independent MCP server.

Separate [executable work acceptance](WORK_ACCEPTANCE.md) can run trusted checks and bind reported comparison hashes. This does not automatically promote these declarations or authenticate report producers.
