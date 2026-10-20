# REA native Evidence handoff

RECarve imports complete REA6.7.0 Ghidra function records into its own observation index. REA MCP performs analysis; RECarve MCP validates saved Evidence files without starting REA/Ghidra/targets. This is not a universal native/mobile/dynamic provider importer.

`rea-ghidra-function@1` supports code/info; @2 adds optional direct callees and typed outgoing references. Existing snapshots stay compatible.

## Separate configuration

Use [two MCP servers](REA_COMPANION.md), configuring engines only on REA:

```json
{"mcpServers":{
 "rea":{"command":"npx","args":["-y","rea-agents@6.7.0","mcp"],"env":{"REA_ANALYSIS_PROVIDER":"ghidra","GHIDRA_INSTALL_DIR":"/absolute/path/to/ghidra","JAVA_HOME":"/absolute/path/to/jdk-21/Contents/Home"}},
 "recarve":{"command":"node","args":["/absolute/path/to/reverse-engineering-carve/dist/cli.js","serve","--root","/absolute/path/to/workspace"]}
}}
```

This import path needs no RECarve --engines setting. Configuration examples do not install engines or modify global configuration.

## Capture and import complete records

In independent REA, open_binary with the selected actual path/provider, then call procedure_pseudo_code and procedure_info with the same full selector. Optionally call procedure_callees and procedure_references with direction:outgoing. Any explicit document must match across records.

Save complete Evidence JSON objects (SDK structuredContent), not code previews, summaries or whole MCP transport envelopes.

```sh
node dist/cli.js reverse /absolute/path/to/program --out ./work
node dist/cli.js import-rea-native ./work --file program --code ./rea-code.json --info ./rea-info.json --callees ./rea-callees.json --references ./rea-references.json
node dist/cli.js features ./work --query operation_name
```

Omit both optional relationship arguments for code/info-only capture. MCP uses `carve_import_rea_native({workspace,file,code,info,callees?,references?})`. File is an indexed relative path. All workspace/input/evidence/output paths must be root-confined. Reply includes RECarve observationId, source SHA256, original REA IDs, analysis profile digest and owned snapshot location.

Read full observations/context and bind RECarve observationIds into reconstruction contracts; original ev_ IDs remain provenance. The agent writes implementations. Reconstruction packages/binds them; verify-reconstruction compares explicit original cases. Then store reusable [function folders](LIBRARY.md).

## Validation and integrity limits

Inputs are freshly rehashed against subject SHA/format/architecture and rechecked during import. RFC8785 semantic IDs, analysis profile digest, provider and selectors must match. Historical display paths are not opened or treated as semantic identity.

Only observed/shipped-artifact complete pseudocode and matching procedure_info are accepted; raw/normalized results must agree. Null/excerpt/metadata bodies, code/info per-result limitations, external functions and incomplete bodies are refused. Relationship limitations and partial/unknown coverage remain explicit.

Entry, inclusive ranges, total body length/span, contiguity and CPU address width must agree. Supported headers: unencrypted thin Mach-O/ELF/native PE, x86/x86_64/arm/arm64. Actual original runtime integration is local ARM64 Mach-O; synthetic header tests do not prove execution on other platforms.

Owned versioned snapshots preserve original JSON bytes including BOM/whitespace, file hashes and records. New-file/atomic-link publication avoids overwriting; identical imports may reuse records. Reconstruction/verification rebind snapshots and normalized SQL, rejecting modified pseudocode/provider records. Explicit [relocation](RELOCATE.md) handles moved workspaces. Saving records removes dependency on live REA processes or original external JSON paths.

Content hashes establish self-consistency/input identity, not producer signatures, trusted engine execution or functional correctness. Compare behavior independently.

Bounds:16MiB per JSON,4MiB pseudocode,64MiB owned snapshot, depth64/200000 JSON nodes. Summaries/context are byte-budgeted with bodies read on demand; bytes are not model token/cost estimates.

## Relationship records

@2 checks function-body-call-coverage-v5 / complete-body-and-entry-reference-manager-v2 records, function ownership, in-body reference source addresses, target body/classification, unresolved calls and raw/normalized coverage consistency.

Only typed call references and procedure_callees establish callee leads; stack/data references do not. Preserve call sites, external/thunk classification and address spaces. Up to20 sites are shown per callee; complete data remains in snapshots.

Trace indexed:false / resolution:missing-compatible-observation means no compatible function observation exists yet. Independently obtain that callee's full REA records and import them. Trace/context link only same-source/provider/profile records; they do not automatically open binaries or install providers.

Read relationshipEvidence, coverageReasons, perResultLimitations and unresolvedCalls. Unknown callback targets retain positions/reasons. Disagreement between callee/reference sets preserves their union and incomplete status. relationshipScope:rea-ghidra-outgoing@1 is only the recorded local set. relationshipsIncomplete:false does not establish dependency closure; inspect missing edges and depth/maxNodes truncation. dependencyClosure:not-established remains explicit.

@1 retains relationshipScope:not-imported. Providing only one relationship record remains incomplete; empty edges are not proof of zero dependencies. Cross-image loading, state, OS and servers require separate work. [Mach-O bridges](REA_BRIDGE.md) provide narrow byte-bound support, not universal loader closure. Bind every used implementation observation in its artifact evidenceIds; name/trace matches do not prove completeness.

## Reproduction

```sh
npm run verify:rea-native -- --engines ./artifacts/engines/config.json
npm run verify:rea-relationships -- --engines ./artifacts/engines/config.json
```

Optional --rea-install reuses an explicit REA installation; otherwise scripts install pinned6.7.0 project-locally without setup. Configured Ghidra/JDK must exist. Source-owned C inputs are analyzed only through REA; RECarve imports after REA closes, refuses mismatched/tampered records, retains owned snapshots and compares160 selected original CLI cases. Relationship integration captures20 Evidence records, links three functions/two direct sites and separately retains unresolved callback/thunk leads. These are same-image cases, not general App or platform proofs.

## Stateful operations

Follow [sequence verification](STATEFUL.md) for process-local state. Declare initialization/reset dependencies and compare ordered steps with reference@3. One fresh call does not verify accumulation, undo, concurrency or arbitrary OS/server state.

## Terminal-boundary diagnostics

A narrow @3 snapshot policy admits matching function-boundary-v4 terminal-call diagnostics only with four complete records, exact supported profiles, complete callee coverage, matching direct typed name/entry/reference and a terminal instruction. Zero-diagnostic paths retain @1/@2 identities.

The source must be thin ARM64 Mach-O. RECarve maps both endpoints into file-backed code and decodes original B-immediate bytes. BL, indirect/conditional flow, wrong/non-code targets, other headers/architectures, absent records, unknown/truncation messages and inconsistent warnings are refused. Rebinding happens again during packaging/verification. Bytes establish absence of machine-code fallthrough, not the provider's semantic flow reason or closure.

Observations retain decompilationStatus:completed-with-boundary-warnings, original bounded statements, byte coordinates/hash and reasonForProviderFlow:not-established. Context/trace expose boundaryWarningCount; full statements remain owned. Relationship limitations remain. Older versions cannot rebind @3, while old @1/@2 identities stay unchanged.

The [JDK stateful case](JDK_STATEFUL.md) exercises an actual wrapper/native target with original JDK comparison. It does not authorize arbitrary diagnostics as complete code. Warnings force packaged-with-unknowns, remain in provenance/verification/function usage and are never cleared by passing supplied cases.

For separately indexed callees use explicit [cross-workspace bridging](REA_BRIDGE.md#cross-workspace-handoff). No callee code is copied into caller indexes; original loader-path checks remain.
