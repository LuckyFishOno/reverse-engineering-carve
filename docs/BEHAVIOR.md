# Structured behavior contracts

`carve/behavior@1` preserves requirements that plain input/output examples cannot express: instance lifetime, UI actions, continuous protocols, persistence and failure recovery. It records desired behavior and validation scenarios; it does not recover or execute behavior.

## Inspect a contract

```sh
recarve behavior-check examples/behavior/interactive-console.json
recarve behavior-check examples/behavior/interactive-console.json --view requirements
recarve behavior-check examples/behavior/interactive-console.json --view gaps
```

The separate read-only MCP tool is `carve_behavior_check`. It accepts a contract and returns byte-budgeted summary, requirements, scenarios or gaps pages. Follow pagination and byte receipts. Larger individual scenarios may require a larger response budget; records are not silently shortened.

The bundled [interactive contract](../examples/behavior/interactive-console.json) distinguishes a persistent interactive shell from independent command requests, direct canvas input from a separate command field, and retained metadata from live session state. It is authored target design, not an original observation or a runtime pass.

## Contract locations

| Input | Structured contract field |
| --- | --- |
| Feature specification | `feature.behavior` |
| Feature request / scope record | `request.contract` |
| Project-plan feature | `contract.behavior` |
| Generated work record | `interface.contract.behavior` |

The schema contains `lifecycle`, `interaction`, `protocol`, `persistence`, `errors` and ordered `scenarios`. Each scenario supplies an ID, validation kind, requirement IDs in `covers`, and action/expected-observation steps. Unknown modes, missing expectations, recovery definitions or matching scenarios produce clarification gaps. Feature requests also flag incompatible legacy state declarations and UI exclusions.

Interactive UI requirements need `ui` scenarios; protocol requirements need `protocol` scenarios; restart requirements need `restart` scenarios. A build-only statement or a plain function example cannot replace these declarations. Coverage is explicit bookkeeping: RECarve does not prove that free text or expected observations are semantically adequate.

`stateful-sequence` scenarios pin a named case and SHA256 of an existing sequence-cases file. This check neither opens nor authenticates that file and does not execute the sequence verifier. Run existing comparison tools explicitly when validation is authorized.

## Work-package acceptance

When supplied, unresolved behavior contracts block work-package creation, including unresolved direct dependency contracts. A complete declaration adds one acceptance row per scenario and preserves the exact contract in the interface. Contract changes alter plan/interface/task identities, so an old work package cannot silently represent changed protocol or state requirements. Generated rows are checked against the pinned scenario IDs when records are read.

Legacy specifications without this optional field remain supported. Their absence does not establish behavioral completeness. Readiness is `declared-for-validation`, execution remains `not-run`, and semantic match remains `unconfirmed`. Work-ledger acceptance, runtime executors, evidence provenance classification and generated application wiring are separate work; this feature does not implement them. REA and RECarve remain independent MCP servers.

Optional per-requirement [claim provenance](PROVENANCE.md) separates original observations, hypotheses, target design and reported comparisons; inspect it with `--view provenance`. Classifications remain unauthenticated declarations.

Separate [executable work acceptance](WORK_ACCEPTANCE.md) can run trusted checks and bind reported comparison hashes. This does not automatically promote these declarations or authenticate report producers.
