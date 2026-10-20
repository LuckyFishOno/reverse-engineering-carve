# RECarve0.43.1

This alpha patch corrects command/configuration naming and simplifies both README editions. It retains the functionality introduced in0.43.0: UI evidence, explicit behavior requirements, claim provenance, executable task acceptance and Swift project wiring. RECarve remains a local CLI/skill/MCP companion to an independent REA MCP. It exposes52MCP tools and is not published to npm.

## Naming correction

Use `carve` for the CLI, MCP configuration entry and bundled skill. The project/package remains `reverse-engineering-carve`; RECarve is only a prose abbreviation. Existing `carve_*` tool IDs, `carve/*` formats and stored filenames remain unchanged. Update a0.43.0 client entry named `recarve` to `carve`, retaining its command, arguments and workspace. No REA reinstall or server merge is needed.

## Existing REA users

Keep REA and its MCP entry unchanged. Install RECarve separately and add one `carve` entry to the same client's `mcpServers` map. Reload the client's MCP connections; the LLM calls both servers. RECarve neither patches nor starts REA. [Existing REA setup](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_COMPANION.md#existing-rea-users).

## README and documentation

Both README editions now focus on purpose, installation, adding carve beside an existing REA server and a short usage prompt. Detailed capabilities, verification, installation alternatives and limits live here and in the linked references.

## Included capabilities

- **PE UI evidence:** source-pinned menu/dialog/string/accelerator graphs, numeric command edges and AFX-like callback candidates. Candidate ownership and semantics remain unverified. [PE UI](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/PE_UI.md).
- **Behavior contracts:** preserve lifecycle, direct UI interaction, protocol modes, persistence and recovery. Missing declarations/scenario coverage block supplied work contracts. [Behavior](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/BEHAVIOR.md).
- **Claim provenance:** separate original static evidence, hypotheses, target design and reported verification claims. Missing provenance stays unclassified. Labels alone do not authenticate behavior. [Provenance](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/PROVENANCE.md).
- **Executable acceptance:** trusted build/unit/live-harness checks and finite original/candidate comparisons, including ordered sequences. Pin inputs/results and reject stale or mismatched records. Unsigned local integrity reports do not automatically accept ledger work. [Acceptance](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/WORK_ACCEPTANCE.md).
- **Swift project wiring:** expose skeleton create/inspect/check, preserve explicitly pinned implementations/resources, wire vendored or revision-pinned packages and per-feature link settings, and regenerate new snapshots. Supports macOS SwiftPM desktop/CLI/module targets. [Skeletons](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/SKELETON.md).

## Install from source

Requires Node22.19 in the22 line or Node24.11+. Swift generation itself does not need a Swift compiler; building the supported macOS targets requires a macOS Swift toolchain.

```sh
git clone --branch v0.43.1 https://github.com/LuckyFishOno/reverse-engineering-carve.git
cd reverse-engineering-carve
npm ci
npm run build
node dist/cli.js --version
node dist/cli.js serve --root /absolute/path/to/workspace
```

Configure MCP using the absolute `dist/cli.js` path; do not launch a second interactive CLI as part of the MCP process. No additional LLM API key or domain is required by RECarve. Existing agent/client and REA requirements remain their own. For the current existing-server configuration, see the [setup guide](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_COMPANION.md).

## Install the release package

Download `reverse-engineering-carve-0.43.1.tgz` and `SHA256SUMS` from this release into the same folder. The tarball contains built JavaScript, docs and runtime package metadata; npm installs its declared dependencies.

```sh
shasum -a 256 -c SHA256SUMS
npm install --ignore-scripts --prefix ./carve-local ./reverse-engineering-carve-0.43.1.tgz
node ./carve-local/node_modules/reverse-engineering-carve/dist/cli.js --version
```

Use the resulting absolute `node_modules/reverse-engineering-carve/dist/cli.js` path in the additional RECarve MCP entry. This installs locally from a GitHub asset, not from an npm registry release. The checksum detects content mismatch; it is not a signed provenance attestation.

## Verification and scope

Local macOS/Node24.20.0 verification: all6release checks passed, including388tests with zero failures/skips, build/content hygiene, the archive demo,7public packages/47cases and clean tarball CLI/fresh MCP installation. Source-owned Swift integration exercised text/localization resources, opaque binary copying, a vendored package, framework/library settings and chained feature outputs. Actual native/device/REA integration suites and remote package fetching were not rerun for this release.

This remains an alpha. It does not recover unavailable server logic, prove arbitrary binary or whole-program equivalence, automatically synthesize every feature, update arbitrary Xcode projects or produce a signed/distributed native App. Execution-enabled checks run trusted code with host permissions. Build success, declared scenario coverage and recorded hashes are distinct from original behavior equivalence. Private analysis inputs, generated workspaces and engine downloads are excluded from the repository and release package.

## Detailed workflow and prior verification

The following reference material was moved from the README. Native/device cases describe earlier selected verification boundaries; they were not rerun for this naming/documentation patch.

## What you get

| Input and boundary | Deliverable |
| --- | --- |
| Supported JavaScript / ASAR declaration closure | Extracted function with its required source dependencies |
| Selected compiled behavior with complete code evidence | Agent-authored reconstruction plus provenance and scoped comparisons |
| Checked package | Local function folder with index.mjs, metadata, SKILL.md and recorded verification |
| Missing server, hardware or unresolved dependency | An explicit unknown or incomplete boundary |

Store a checked package with `carve_library_add`. Later use `carve_library_find`, `carve_library_get`, then import `index.mjs` or call `carve_invoke`. These folders need no standalone program. [Function library](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/LIBRARY.md)

For compatible REA JS/ASAR Evidence, save the actual response as JSON and pass it to RECarve for module/artifact byte binding. For the supported native Ghidra profile, save matching complete procedure_pseudo_code and procedure_info Evidence and call carve_import_rea_native. RECarve checks source bytes, canonical record/profile commitments and body metadata, then retains owned snapshots and original producer IDs. Optional procedure_callees and outgoing procedure_references preserve typed call sites, missing helper code and unresolved callbacks; trace/context follow only matching REA analysis profiles. No REA process is started by RECarve MCP. [Native handoff](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_NATIVE.md) · [JS handoff](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_COMPANION.md)

## Concrete checks

- **Independent REA native handoff:** real REA/Ghidra code and function records imported after REA closes;160direct original native CLI comparisons, exact producer identities and library-only reuse. The relationship case adds two helpers, three bound code records and160original CLI comparisons; unresolved callback and external thunk targets stay explicit. Recorded static edges do not establish dependency closure. [Reproduce it](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_NATIVE.md)
- **REA cross-image bridge:** original direct-call instruction, symbol stub/library ordinal, local load path and defined export bind two separately analyzed functions;162original CLI cases and function-folder reuse, with a same-name decoy rejected. Runtime/ABI/environment closure remains unknown. [Cross-image workflow](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_BRIDGE.md)
- **Separate analysis workspaces:** caller and library retain independent indexes and REA snapshots. Cross-workspace bridges rebind both sources and require declared/authorized endpoints; sibling workspace relocation preserves immutable relative commitments. A fresh independent REA check compares162original CLI cases and rejects a same-name wrong-path library. [Workflow and limits](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/REA_BRIDGE.md#cross-workspace-handoff)
- **Stateful sequences**: one original process and one candidate module instance per ordered sequence;32 source-owned native sequences /635 steps compared, including add/set/undo and a reset-per-call counterexample. Whole sequence examples survive function-folder reuse. Separate requests start fresh. [Protocol and reproduction](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/STATEFUL.md)
- **Third-party stateful operation**:31 sequences /405 steps against the shipped JDK Adler32 object, combining complete Java class evidence with independent REA native code. Initialization, chunks, empty updates and reset survive function-folder reuse. The runtime class hash matches the analyzed module-image bytes; the invocation adapter remains explicitly scoped. [Evidence and reproduction](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/JDK_STATEFUL.md)
- **Original Android object state**:33 sequences /692 steps against the shipped ZXing APK BitArray on Android15/API35 ARM64 ART. Clear preserves length, new explicitly constructs a fresh object, and per-call reset is rejected. Original DEX is retained; the independent function folder works through direct import, CLI and two fresh MCP requests. Uses the existing managed backend, without starting or proxying REA. [Boundary and reproduction](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/ZXING_STATEFUL.md)
- **Actual Android JNI:** shipped Termux DEX → native getZip on ART →80metadata query comparisons covering3490ZIP entries; reusable metadata-only catalog. [Scope and report](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/TERMUX_BOOTSTRAP.md)
- **Cross-component reconstruction:** owned stripped executable and library,162original CLI cases, independent reuse. [Multi-artifact evidence](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/MULTI_ARTIFACT.md)

## Develop and validate

```sh
npm test
npm run verify:project-intent
npm run verify:feature-scope
npm run verify:rea-native -- --engines ./artifacts/engines/config.json
npm run verify:rea-relationships -- --engines ./artifacts/engines/config.json
npm run verify:rea-bridge -- --engines ./artifacts/engines/config.json
npm run check
```

The native REA checks install a pinned package in a new artifacts directory by default and run independent REA and RECarve processes. They exercise selected source-owned native boundaries, not every REA provider. Other checks: [native tracing](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/NATIVE.md), [Android](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/ANDROID.md), [JNI](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/JNI.md), [large analysis budgets](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/ENGINE_RESOURCES.md), [resumable queue](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/QUEUE.md), [bounded context](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/CONTEXT.md), [verification reports](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/VERIFICATION.md), [full reconstruction workflow](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/docs/RECONSTRUCTION.md).

## Current limits

RECarve supplies tools and durable records; your agent performs the reasoning and authors any reconstruction. The candidate menu currently recognizes ten explicit categories plus literal custom matches. Names and graph leads do not prove feature semantics. Full native/mobile automation, arbitrary external Evidence import, complex state/OS dependencies, missing server logic and general equivalence remain unfinished. Each comparison covers only its declared cases and reference boundary.

Generated capabilities retain provenance and applicable notices and default to UNLICENSED until rights are established. RECarve's MIT license does not relicense analyzed software. Development remains local; there is no published npm release.

Writing policy: project content is English; the Traditional Chinese README is the only translated documentation. See [Contributing](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.1/CONTRIBUTING.md).
