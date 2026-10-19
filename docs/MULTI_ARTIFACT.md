# Reconstruct a feature spanning several artifacts

Carve0.12 accepts `carve/reconstruction@2` when one behavior crosses an executable, shared library, DEX or another separately analyzed component. Your existing agent chooses the boundary and writes the independent implementation. This adds source/evidence binding and reviewable relationship records; it does not automatically resolve arbitrary imports or discover a complete dependency graph. Version1 single-artifact contracts remain supported.

For candidate discovery use the [loader-only linkage index](NATIVE_LINKS.md); reviewed imports/exports may become supporting evidence, while matching names remain leads.

Index the relevant input directories with reverse/survey. Analyze each selected component through native/managed or their durable queue. Use the returned complete code observation IDs. A shared-library export name is a lead; inspect the actual caller, loader/registration data and callee behavior. Keep any missing remote/OS/hardware dependency explicit.

Example contract (replace observation placeholders with actual64-character SHA256 IDs):

```json
{
  "schema": "carve/reconstruction@2",
  "goal": "Reconstruct the complete quote",
  "primary": "app",
  "artifacts": [
    {"key":"app","file":"bin/quote","evidenceIds":["CALLER_CODE_ID"],"supportingEvidenceIds":["OPERATION_STRING_ID"]},
    {"key":"charge","file":"lib/libcharge.dylib","evidenceIds":["LIBRARY_CODE_ID"]}
  ],
  "relationships": [
    {
      "from":{"artifact":"app","id":"CALLER_CODE_ID"},
      "to":{"artifact":"charge","id":"LIBRARY_CODE_ID"},
      "kind":"calls",
      "basis":"reviewed-static",
      "description":"Reviewed caller import, exact library export/code and loader records; runtime cases are checked separately."
    }
  ],
  "behavior":{"description":"Shared calculation plus caller surcharge","inputDomain":"Three signed int32 values","outputDomain":"One integer"},
  "dependencies":[{"name":"charge calculation","status":"reimplemented","detail":"Covered by the independent implementation from library evidence."}],
  "unknowns":["UI, hidden state, other libraries and inputs outside the stated domain remain unverified."]
}
```

Implementation artifacts require complete code observations produced by the existing Ghidra/JADX paths or the explicitly supported independent REA handoff. A JS queue summary or data-only/resource file cannot replace implementation code. Since0.18, ancillary declarations/resources may instead be explicit boundary-support artifacts as below; this binds their bytes without recovering their behavior. JS closures still use the JS backend and mixed native/JS/JNI execution needs additional adapters. Record unsupported dependencies explicitly.

Each implementation artifact has a unique key (letter followed by up to63 letters/digits/underscores/hyphens), an indexed relative file and1–100 complete code evidenceIds. supportingEvidenceIds optionally adds up to100 string/window/inventory records without replacing code. workspace defaults to `.` and resolves relative to the workspace passed to reconstruct/verify, not the contract file. An absolute path or e.g. `../library-work` can explicitly select another analysis workspace, including a separately unpacked container. MCP authorizes each referenced workspace, its target and inventory root against the configured server root. It refuses out-of-root related workspaces even if a package was created through CLI elsewhere.

Since0.18, version2 can include an ancillary artifact with `role:"boundary-support"`, `evidenceIds:[]` and at least one supportingEvidenceId. Example: `{"key":"manifest","file":"AndroidManifest.xml","role":"boundary-support","evidenceIds":[],"supportingEvidenceIds":["MANIFEST_OBSERVATION_ID"]}`. It keeps its own source hash, evidence and container lineage and needs a directed relationship path from primary like every other artifact. Source/evidence hashes are checked before/after packaging/comparison and the file is included in reference boundFiles. It is not automatically staged/loaded or proven to affect the tested behavior.

The primary must contain implementation code. An omitted role retains the original implementation requirement; explicit role:"implementation" also requires code. Support-only declarations cannot use implementation evidenceIds or omit supporting evidence. Never relabel unrecovered behavior/code as support to hide a dependency gap. The role cannot establish complete boundary discovery or semantic correctness. Older contracts/package bindings without role retain their exact field shape; older Carve versions cannot consume this new role. See the actual [APK contact case](ZXING_VCARD.md).

Limits:1–32 artifacts, up to400 distinct artifact/evidence pairs in total,0–128 relationships. Two keys cannot select the same actual input path. Every non-primary artifact needs a directed relationship path from primary; each endpoint must name evidence declared on that artifact. This checks record consistency, not semantic connectivity. All selected source bytes and evidence-file hashes must match the current inventory. Each component retains its own format and container/member lineage.

Since0.30, a reviewed-static calls relationship can optionally provide bridgeEvidenceId from the [REA cross-image byte bridge](REA_BRIDGE.md). Declare that ID in the caller supportingEvidenceIds and both exact endpoint IDs in their artifacts implementation evidenceIds. Both images must be in the bridge workspace. Packaging and verification rederive the original call/stub/symbol/ordinal/local-path/export witness and reject stale/tampered/mismatched endpoints. The relationship gains staticBridge metadata while runtimeLoading and semanticMatch remain unverified/unconfirmed. Unused bridge support is refused; legacy relationships without this field retain their original agent-reviewed status.

Relationship kinds are calls, loads, data and other. basis is hypothesis (default) or reviewed-static. Both are agent declarations. Every stored relationship says semanticMatch:unconfirmed. reviewed-static records that the agent reviewed its static basis; it is not runtime verification. A hypothesis remains in unresolvedRelationships and causes packaged-with-unknowns, even when the explicit unknowns array is empty or comparison cases later pass. Claims such as observed-runtime are not accepted as a substitute for an actual reference comparison. Additional runtime loader traces can support an investigation but do not turn a name match into a universal edge resolver.

```sh
node dist/cli.js reconstruct ./work --contract ./contract.json \
  --implementation ./rewrite.mjs --export quote --out ./independent-tool
node dist/cli.js verify-reconstruction ./work --package ./independent-tool \
  --cases ./cases.json --reference ./reference.json --execute
```

The existing MCP tools carve_reconstruct and carve_verify_reconstruction accept both contract versions. Version2 packages use carve/reconstruction-provenance@2 and record artifacts, evidence tagged by artifact, relationships and unresolvedRelationships. original remains the primary artifact for compatibility. use/capability_info show the additional bindings without opening the original app. Candidate packages contain the rewritten implementation, not copies of the analyzed binaries.

Packaging checks every source/evidence binding before and after implementation extraction. Verification repeats every binding before and after the cases, and automatically hashes every selected artifact alongside the reference executable/declared boundFiles. A changed secondary library or decompiler record invalidates verification. target-cli must execute the selected primary binary itself; external-harness/Android references retain their explicit scope. Hash binding does not prove a harness actually loaded every declared artifact or executed every relationship. Android dependencies still require an explicitly reviewed adapter and reference configuration; declaring an artifact does not stage or invoke it automatically.

`npm run verify:multi -- ./engines.json` builds a small owned macOS-arm64 executable plus dynamic library. The executable is stripped; the library retains its required dynamic export. The agent follows real Ghidra string/call evidence, separately decompiles both code bodies and reviews import/export/load data. An actual dyld trace names the selected library. Ghidra leaves imported-call argument types unresolved; the reviewed CLI boundary and original comparisons are used instead of a guessed C ABI.162 original executable cases cover negative/int32 boundary durations, membership and zone flags. The test removes both original binaries and the rewrite source, then calls the independent CLI/MCP. This is one real split-component case, not a large third-party application or automatic dependency-closure claim.

For an explicit native direct-call relation across separately indexed workspaces, [REA bridge0.34](REA_BRIDGE.md#cross-workspace-handoff) accepts toWorkspace relative to the caller. Declare both workspace/code endpoints in reconstruction@2; a retained bridge cannot introduce an undeclared third index. Both sources and owned records are rebound during packaging and comparison. Historical packages/verification remain bound to their recorded paths.
