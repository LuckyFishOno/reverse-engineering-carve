# Static REA handoff across images

`bridge-rea-native` / `carve_bridge_rea_native` checks complete REA function records and original Mach-O bytes, then records an explicit direct import relation as a support observation. REA and Carve remain independent; the bridge starts no engine or target.

## Supported boundary

The exercised runtime case is macOS ARM64 executable plus dylib: thin little-endian64 Mach-O, two-level executable namespace, matching CPU/subtype, readable nlist/indirect tables, strong symbols, direct LC_LOAD_DYLIB, explicit local loader paths and a defined code export. AArch64 BL-immediate and x86_64 E8-rel32 have byte-validator tests; x86 has no original runtime comparison.

Fat slices, ELF/PE bridges, weak/flat/special ordinals, export-trie-only, reexports/forwarding, computed calls, ambiguous/missing local rpaths, inherited runpaths, environment overrides and interposition remain unsupported. @rpath requires one expandable local rpath. Absolute/loader_path/executable_path must resolve to the explicitly selected indexed input. This is not a general dyld emulator.

Import complete caller code/info/callees/outgoing references through [native handoff](REA_NATIVE.md). Inspect trace for missing thunks, investigate the selected callee independently through REA, and import its complete implementation. Names are leads; the bridge checks actual bytes.

```sh
node dist/cli.js bridge-rea-native ./work --from CALLER_ID --to CALLEE_ID --stub 0x100000598
```

Replace IDs and stub with actual observations/addresses. MCP uses `{workspace,from,to,stub}`. IDs are Carve64-hex observation IDs; stub belongs to caller image. Sources/evidence/workspace must be inside MCP root.

## Cross-workspace handoff

```sh
node dist/cli.js bridge-rea-native ./caller-work --from CALLER_ID --to CALLEE_ID --stub 0x100000598 --to-workspace ../library-work
```

MCP adds `toWorkspace`, resolved relative to caller workspace, not server root or shell cwd. Explicit absolute paths are allowed; snapshots keep normalized relative commitments. MCP root must contain both indexes, inputs and evidence. No automatic index discovery occurs.

Separate workspaces use carve/rea-bridge@2 with per-endpoint namespace and original source/REA hashes. Only caller gets the support observation. Even identical source/observation IDs in different indexes cannot substitute for the declared endpoint namespace. Without toWorkspace, existing snapshot@1 remains compatible. Historical reads do not replace fresh bridge/reconstruction/verification checks.

Original images must still satisfy the original loader path. Moving a library arbitrarily or selecting a same-name export does not establish a link. Two indexes of one actual source cannot represent two images.

## Byte checks

- Rehash both indexed sources; rebind owned REA snapshots and normalized SQL records. Both endpoints require complete compatible implementation observations and the same underlying provider; target must be a defined non-thunk function.
- Require a typed caller reference to the thunk. Independently decode the file-backed BL/E8 instruction and its actual destination.
- Resolve stub section reserved1/reserved2 through the indirect symbol table to exact undefined nlist symbol and positive library ordinal. Data references are not calls.
- Select exact LC_LOAD_DYLIB by ordinal; check loader string/local lexical path and target LC_ID_DYLIB.
- Require a unique strong same-name defined export in file-backed instruction code, with original VA equal to REA callee entry. Retain coordinates/hashes of instructions, symbols and load commands.

Success returns status:byte-bound-static-link plus support ID. runtimeLoading:unverified and dependencyClosure:not-established always remain. Static compatibility does not prove actual environment loading, ABI compatibility, semantic feature selection or general equivalence. Canonical hashes are not producer signatures.

Bounds:8MiB per table,500000 symbols,1000000 indirect entries,4096 commands,255 sections,20 selected call sites,256KiB snapshot. Truncation remains explicit; whole images are not sent to the LLM.

## Reconstruction binding

A reconstruction@2 caller artifact lists the bridge in supportingEvidenceIds. The relationship must specify bridgeEvidenceId and both implementation observations must be present in their own artifact evidenceIds:

```json
{
 "artifacts":[
  {"key":"app","file":"quote","evidenceIds":["CALLER_ID"],"supportingEvidenceIds":["BRIDGE_ID"]},
  {"key":"charge","workspace":"../library-work","file":"libcharge.dylib","evidenceIds":["CALLEE_ID"]}
 ],
 "relationships":[{"from":{"artifact":"app","id":"CALLER_ID"},"to":{"artifact":"charge","id":"CALLEE_ID"},"kind":"calls","basis":"reviewed-static","bridgeEvidenceId":"BRIDGE_ID","description":"Exact original caller, loader path and callee are byte-bound."}]
}
```

Replace illustrative IDs and add remaining goal/primary/behavior/dependencies/unknowns from [multi-artifact reconstruction](MULTI_ARTIFACT.md). Support never replaces implementation code. Validate all declared workspace permissions before reading referenced indexes; a snapshot cannot introduce an undeclared third workspace.

Packaging/comparison rehash both sources, snapshots and SQL and recompute byte witnesses. Missing/mismatched endpoints, unused bridges or changed records are refused. semanticMatch remains unconfirmed; original CLI comparison is separate. Historical contracts without bridgeEvidenceId retain agent-reviewed semantics.

Move related analysis workspaces together while preserving relative positions, then explicitly relocate each. snapshot@2 stays immutable and witnesses must match. Changed relative layout needs a new bridge. Historical packages preserve their absolute provenance; repackage and compare anew rather than relabeling old verification.

## Reproduction

```sh
npm run verify:rea-bridge -- --engines ./artifacts/engines/config.json
npm run verify:rea-bridge-cross-workspace
```

Scripts default to fresh local REA6.7.0 without setup; --rea-install reuses an explicit install. Engines are configured only for REA. Source-owned CLI/dylib/decoy inputs produce12 complete records across three images; REA closes before Carve imports. A same-name wrong-path decoy is rejected, selected reconstruction compares162 original CLI cases, and library-only MCP reuse is exercised. A real dyld observation is separate from static bridge status. Cross-workspace mode additionally relocates indexes while retaining bridge bytes.

See local generated artifacts/rea-bridge-verification-summary.json and artifacts/rea-bridge-cross-workspace-verification-summary.json after running. These are owned ARM64 operation-boundary cases, not arbitrary App, loader, state or closure proofs.
