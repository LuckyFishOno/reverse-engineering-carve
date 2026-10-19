# Target App skeleton

`createSkeleton` turns a project plan (`carve/project-plan@1`) and its work specification (`carve/work-spec@1`, the same revision the work packages use) into a target App shell that really builds. Every feature starts as a stub that only reports `not-implemented`. When an agent's work package replaces those feature files, the shell builds again unchanged, and the self-test shows which features now run.

A skeleton is not a port. It implements no behavior and is not compared with the original program.

This version targets **macOS only**, as a Swift Package:

| Delivery | Result |
| --- | --- |
| `desktop-app` | SwiftUI window listing feature status, plus headless `--self-test` / `--flow` |
| `cli` | Command-line executable with `--self-test` / `--flow` |
| `module` | Libraries and tests only |

Any other target is refused with `unsupported-target` and the list of supported combinations. Nothing is generated for it. CLI/MCP registration is not part of this version.

## Inputs and refusals

The plan and spec go through the same checks as work packages (`bindWorkContract`):
- current `planId` and task ids,
- non-overlapping files,
- complete interfaces for assigned features.

The skeleton additionally needs:

- **An acyclic plan.** Swift targets cannot depend on each other in a cycle. Features in or behind a cycle are listed in the refusal.
- **One Swift module per feature.** A feature id becomes a module name by capitalizing its `-`/`.`/`_` parts (`storage-core` → `StorageCore`). Duplicates, and names reserved by the skeleton or by system modules (for example `CarveShared`, `Foundation`, `SwiftUI`), are refused.
- **The assignment layout.** All of a feature's `.swift` sources must be in one `Sources/<dir>/`, and its tests (optional) in one `Tests/<dir>/`. Other files, several directories for one feature, a shared directory, or a skeleton-owned path are refused as `layout-unsupported`.
- **A new folder.** The output folder must not exist; its parent must.

Every refusal happens before anything is written.

## What is generated

| Path | Owner |
| --- | --- |
| `Package.swift`, `Sources/CarveShared/Feature.swift`, `Sources/CarveApp/*`, `SKELETON.md`, `carve-skeleton.json` | skeleton |
| Each assigned file of a feature | that feature's work package |
| `Sources/<id>/Module.swift` for a feature without an assignment | the skeleton, marked `skeleton-unassigned-feature` |

- The manifest `carve-skeleton.json` records:
  - plan and spec identity and the target,
  - each feature's module, phase, dependencies and contract pin,
  - every file with its owner and initial sha256.
- Plan dependencies become Swift target dependencies. A module can `import` the modules of its direct dependencies.
- A feature's primary file (`Module.swift` when present) declares the module enum; additional assigned files start as placeholder comments.
- Plan text such as interface descriptions is written only as `//` comment lines, so it cannot become code.

## Feature module interface

`CarveShared` defines `FeatureRequest`, `FeatureResponse` (string payloads), `FeatureOutputs`, `FeatureError` and the protocol:

```swift
public protocol CarveFeature {
    static var id: String { get }
    static var contractSha256: String { get }
    static var dependsOn: [String] { get }
    static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse
}
```

- Each feature file declares `public enum <Module>Feature: CarveFeature`.
- A dependency's output is read as `dependencies[feature: "model"]`.
- `contractSha256` is the plan's pin for that feature's interface.
- Payloads are strings (JSON is a good fit) because plan interfaces are text; typed interfaces are later work.

## Self-test and flow

- `--self-test` runs every feature in plan phase order and prints one `CARVE-SELF-TEST` JSON line. Each feature gets one status:

  | Status | Meaning |
  | --- | --- |
  | `implemented-ok` | the module returned without error |
  | `not-implemented` | the module is still a stub |
  | `failed` | the module threw; the message is included |
  | `blocked-by-dependency` | a direct dependency did not succeed, so it was not run |
  | `contract-mismatch` | the module's pin differs from the plan |

- `--flow FEATURE [--input TEXT]` runs that feature's dependency closure and reports each step and, when it completes, the output. The default flow is the feature with the most dependencies in the last phase.
- Exit code:

  | Code | When |
  | --- | --- |
  | 0 | features ran or reported, including `not-implemented` |
  | 2 | a contract pin differs from the plan |
  | other non-zero | a crash |

## Checking a skeleton

`checkSkeleton(dir, {test, flow, scratchPath})`:
- verifies that every manifest file exists as a regular file, and refuses if a skeleton-owned file was edited,
- reports which feature files changed from their stubs,
- runs `swift build`, then `--self-test` and `--flow` for app deliveries, and optionally `swift test`.

All of it runs through the supervised tool runner, with timeouts, cancellation and bounded logs in `.carve-check/`. Build products go to `<skeleton>/.build` unless `scratchPath` is given; they can be hundreds of MiB.

`implemented-ok` only means a module returned without error. It is not evidence that the module matches the original program.

## Checks

- `test/skeleton.test.mjs`:
  - refusals: unsupported target, every layout rule, module name collisions, cycles, a stale plan, existing folder,
  - ownership, stub placement and comment-only plan text,
  - module delivery,
  - one real build (skipped without a macOS Swift toolchain): stubs report honestly; replacing the `model` and `parser` feature files gives `implemented-ok` for both, with `parser` receiving `model`'s output; `swift test` passes; a changed pin gives `contract-mismatch` and exit 2; an edited `Package.swift` is refused.
- `node scripts/verify-skeleton.mjs` builds `desktop-app`, `cli` and `module` from the bundled example plan, repeats the simulated submission, and launches the desktop app for 4 seconds to check that the process stays up. The window content is not inspected. Build products are kept in a temporary directory that is removed afterwards.
