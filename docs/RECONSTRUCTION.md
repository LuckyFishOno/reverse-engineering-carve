# Capability reconstruction (experimental)

RECarve 0.14 gives an existing agent local analysis and verification tools. The agent interprets the user's request, investigates boundaries and writes any reimplementation. RECarve does not contain an LLM. The tested native path currently uses POSIX launchers; Windows launchers, arbitrary software reconstruction and broad device/UI automation are unfinished. Explicit Android DEX runtime references are available.

## User entry point

```sh
node dist/cli.js reverse /path/to/software --goal 'Extract the capability I need' --out ./work
```

Give the returned TASK.md to your agent. Repeat the command to finish an incomplete inventory; edits to the draft contract are preserved. Different goals have separate task directories sharing the same binary index/cache. `--refresh` restarts inventory revision discovery. The SQLite directory queue, file hashes, logs and engine result files persist on disk. Engine cache reuse requires a completed analysis; an interrupted first Ghidra import is restarted, not resumed internally.

Suggested agent instruction:

> Read the returned TASK.md, investigate the requested feature using the appropriate analysis backend, and locate boundaries through strings, references and calls. Preserve missing server/OS dependencies. Reconstruct a reusable capability and compare concrete cases against a trusted original. Decompiled text or unverified behavior is not successful recovery.

## Inventory and engines

```sh
node dist/cli.js index ./work --limit 50
node dist/cli.js index ./work --backend ghidra --query executable
node dist/cli.js native ./work --file relative/program \
  --ghidra /path/to/ghidra --java-home /path/to/jdk
node dist/cli.js search ./work 'visible operation text'
node dist/cli.js trace ./work OBSERVATION_ID --depth 2 --max-nodes 50
node dist/cli.js native ./work --file relative/program \
  --ghidra /path/to/ghidra --java-home /path/to/jdk --function OBSERVED_ADDRESS
node dist/cli.js observation ./work OBSERVATION_ID
node dist/cli.js managed ./work --file relative/classes.dex \
  --jadx /path/to/jadx/bin/jadx --java-home /path/to/jdk
```

Ghidra and JADX are separate installations, not bundled executables. Tested here: [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), full JDK 21, [JADX 1.5.6](https://github.com/skylot/jadx/releases/tag/v1.5.6). On this macOS arm64 host the Ghidra native decompiler needed compilation; see [upstream build instructions](https://github.com/NationalSecurityAgency/ghidra#building-a-development-version). Native integration uses Google's D8/R8 9.5.26 only to create the owned DEX fixture. These tool binaries live in an ignored local artifacts directory; no global Java or agent settings are modified.

Header recognition includes ELF, Mach-O/fat, PE/CLI, DEX, Java class, ZIP/APK/JAR/IPA hints, WASM, JS/ASAR and source extensions. **Recognition is not implemented backend support.** .NET/ILSpy, WASM and non-JS source analysis still need adapters. IPA/ZIP native members can be extracted with unpack; encrypted code needs an authorized unencrypted input. Backend errors remain failures with logs, never recovered-source claims.

Default inventory batch: 10,000 files and 1,000 directory listings (each configurable 1–1,000,000 with --max-files / --max-directories, or maxFiles / maxDirectories in MCP). Each listing streams names into a disk-backed SQLite queue and finishes as one unit; completed listings are reused across file batches. An interrupted listing may replay, deduplicating existing queue entries and committed files. Directory-only inputs can return indexing with zero processed files; continue while pending work remains. Inventory is not an atomic filesystem snapshot; use refresh after changes. Hashes stream through <=1 MiB buffers; there is no JS 16 MiB source limit on inventory. Metadata matching accelerates refresh only; selected inputs are fully rehashed before analysis/reconstruction/verification. Symlinks and .git are skipped. Older workspaces migrate by relisting and reusing metadata-matching file hashes.

Add --progress to survey/reverse for checkpoint JSON lines on stderr; the final result remains one stdout JSON object. SIGINT/SIGTERM and MCP request cancellation preserve committed checkpoints. MCP clients can request standard progress notifications; listing/processed counts describe work observed so far, not a completion percentage. SQLite index status is authoritative after interruption; a previous survey.json describes its recorded revision and last completed batch.

Ghidra inventory pages contain <=500 functions by default, configurable to 10,000, and first-page strings are bounded to 1,000. Follow `summary.nextAddress`; a page is not a whole-program inventory. Each selected function has a 60-second decompiler deadline and <=1 MiB pseudocode preview. Engine deadline defaults to 600 seconds, heap budget 1 GiB and retained log budget 32 MiB. Local completed Ghidra databases are reused but not independently authenticated against external modification. Dynamic calls, data flow and cross-binary closure remain incomplete. Imported-call thunks must not be mistaken for local feature implementations.

JADX generated sources stay on disk. Indexed source previews are <=1 MiB and explicitly flagged if truncated; a truncated preview cannot serve as reconstruction evidence. `--class` narrows the scope. Decompiler-produced Java/C is reconstructed analysis text, not original source. `observation` labels records matching the current inventory versus historical input revisions. `search` hides old revisions. Static call graphs are bounded investigation aids, not dependency proofs.

## Selected component jobs

Use the [component analysis queue](QUEUE.md) to persist selected native/DEX/JS requests across sessions. Queue completion is bounded static analysis; feature selection, cross-binary relationships, reconstruction and behavior comparisons remain separate. Real process ownership is checked before retrying interrupted engines.

## Container members

```sh
node dist/cli.js unpack ./work --file relative/application.ipa --max-files 1000
# Repeat while status is unpacking, then use the returned content directory:
node dist/cli.js reverse /returned/content --goal 'Extract the selected capability' --out ./members-work
```

Extraction streams one ZIP member at a time through CRC32/SHA256 checks, records completed members in SQLite, and refuses traversal paths, duplicate files, symlinks, special files and encrypted members. Defaults: 1,000 new files per batch, 100,000 total entries, 4 GiB input/total output and 1 GiB per member. Set explicit byte/count budgets when needed. Nested archives are separate operations. An interrupted output-link/database checkpoint can recover without overwriting existing files; changed cached bytes fail.

Members have no executable permission. Parsing/decompiling them does not require it. Executing a trusted reconstructed reference is a separate explicitly authorized step. This does not decrypt signed/encrypted iOS executables or establish installable APK/IPA validity. Index the exact returned content directory to retain lineage; analysis/package manifests then bind both container SHA256 and selected member SHA256. That historical lineage comes from the owned extraction records; it does not authenticate externally modified workspaces.

Native string/data-pointer/registration investigation is documented in [native boundaries](NATIVE.md). Identical repeated analysis records preserve existing package evidence rather than replacing its provenance.

## Reconstruction contract

The draft starts with null/empty fields. The agent must complete it from evidence:

```json
{
  "schema": "carve/reconstruction@1",
  "goal": "Extract the calculation",
  "file": "relative/program",
  "evidenceIds": ["64-character observation SHA256 ID"],
  "supportingEvidenceIds": [],
  "behavior": {
    "description": "The actual invocation and calculation boundary",
    "inputDomain": "Two signed 32-bit integers: minutes and membership flag",
    "outputDomain": "One JSON integer"
  },
  "dependencies": [],
  "unknowns": ["UI integration has not been verified"]
}
```

Each dependency is `{name,status,detail}`; statuses are `available`, `reimplemented`, `host-required`, `remote-required`, `unknown`. The last three remain unresolved. Missing server recommendation/matching logic cannot be reconstructed from client bytes alone. A substitute must be labeled as such. Static evidence cannot establish all hidden dependencies; these declarations are agent judgments retained for review.

```sh
node dist/cli.js reconstruct ./work --contract ./contract.json \
  --implementation ./reimplementation.mjs --export calculate --out ./independent-tool
```

This bundles the agent's closed JS implementation and creates a standalone Node CLI/module. The manifest says `extractionKind: behavior-reconstruction`; `source`/`inputs` refer to the actual implementation, while `reconstruction.original` refers to the analyzed binary. Evidence must match current binary bytes and unchanged decompiler output. Inventory-only names and truncated code are refused. Packaging is always unverified; unknowns and unresolved dependencies remain in the manifest even if examples later pass.

For a capability spanning multiple binaries or analysis workspaces, use the backward-compatible [version2 multi-artifact contract](MULTI_ARTIFACT.md). It binds every selected source/evidence identity and records agent-declared relationships with explicit uncertainty.

## Reference execution and comparisons

Prepare `cases.json` with 1–200 uniquely named `{name,args,expected?}` objects. Optional expected values must match both sides. Without expected values, equality is a comparison observation, not proof that the user requested the selected feature.

Reference configuration:

```json
{
  "schema": "carve/reference@1",
  "command": ["/absolute/path/to/original", "fixed-argument"],
  "mode": "argv-values",
  "scope": "target-cli",
  "description": "Actual original CLI operation",
  "boundFiles": []
}
```

`target-cli` requires the selected indexed executable itself. `argv-values` appends scalar args as separate argv entries without a shell. `json-stdin` sends the JSON args array on stdin. stdout must contain exactly one JSON value; stderr is diagnostic. Nonzero exits, protocol errors, nonfinite numbers, timeouts and >1 MiB total output fail. For reference@1/@2, a process starts fresh per case. Errors are harness failures, not equivalent target exceptions.

For a real command that reads or writes raw data, use the compatible `carve/reference@2` schema with an explicit `output` format. This keeps the selected original executable as the process being compared, without adding a JSON wrapper just for encoding:

```json
{
  "schema": "carve/reference@2",
  "command": ["/absolute/openssl", "base64", "-A"],
  "mode": "bytes-stdin",
  "output": "utf8",
  "scope": "target-cli",
  "description": "Original CLI encodes raw input bytes as single-line Base64",
  "boundFiles": ["/absolute/libcrypto.3.dylib", "/absolute/libssl.3.dylib"]
}
```

Use a case such as `{"name":"binary","args":[[0,1,2,254,255]],"expected":"AAEC/v8="}`. `bytes-stdin` requires exactly one JSON array of integer bytes0–255; `text-stdin` requires exactly one well-formed Unicode string, converted to UTF8. Both reject extra arguments and send no case arguments through argv. Empty data is valid; NUL/newlines remain data. Input is bounded to1MiB; JSON case/candidate limits still apply. Version2 also retains `argv-values` and `json-stdin`.

`output:json` keeps finite-JSON parsing. `output:utf8` returns the exact decoded string, including empty output, BOM, NUL, trailing whitespace and newlines; malformed UTF8 fails instead of becoming replacement characters. `output:bytes` returns raw stdout as a JSON byte array. Pipe chunks are joined before decoding. stderr remains diagnostic, and the existing combined raw stdout/stderr1MiB limit, exit/deadline/cancellation controls and fresh source/evidence checks apply. Protocol failures never pass as matching target errors. Version1 accepts only its original fields/modes and JSON stdout.

The [installed OpenSSL case](OPENSSL.md) demonstrates this protocol with real CLI/libcrypto decompilation and direct original invocation.

`external-harness` permits an explicitly described wrapper/reference executable. Include class/module/library files in `boundFiles` so the report hashes their bytes; command arguments themselves are not automatically inferred as files. This comparison only establishes the declared harness cases. A JVM class used to build a DEX does not prove DEX/Android runtime equivalence. For process-local state use the explicit [reference@3 sequence protocol](STATEFUL.md). UI automation, persistent sessions across requests, arbitrary output formats and hardware-specific flows still require additional adapters.

```sh
node dist/cli.js verify-reconstruction ./work --package ./independent-tool \
  --cases ./cases.json --reference ./reference.json --execute
node dist/cli.js use ./independent-tool
node dist/cli.js invoke ./independent-tool --args '[16,1]' --execute
node dist/cli.js serve-tool ./independent-tool --execute
```

Reference execution uses user permissions and can access host state/libraries/network. Selected artifacts and explicitly declared reference files are hashed; a temporary directory and Node permissions are not a malicious-code sandbox. Candidate package bytes are snapshotted and checked, and execution only receives the emitted package plus runner. Original target and explicitly bound reference files are rehashed before/after comparison. A `passed-supplied-cases` result does not resolve declared unknowns or prove complete equivalence.

Since0.19 the CLI and MCP verification response defaults to a byte-budgeted summary with a pinned workspace report ID. Use verification / carve_verification to inspect case cards, selected values and metadata without re-executing originals. --full-report / fullReport:true explicitly returns the legacy complete response; the direct JavaScript API is unchanged. See [bounded verification results](VERIFICATION.md) for budgets, JSON fragment offsets, archive identity and compatibility.

Full results stay in carve.verification.json. Verification also writes carve.verification-summary.json with the manifest/report identity, byte count, status/counters/scope and a recorded example bounded to4096 UTF8 bytes. For reports over the1MiB usage preview limit, use/capability_info rehash the complete report on disk and read this small summary (up to64KiB), rather than returning the case bodies. A missing/stale/inconsistent summary stays unreadable; it never substitutes a pass. This is local recorded metadata with a checked checksum, not signed evidence or independent recomputation/authentication of its counters. Reports beyond512MiB are outside this preview route.

Library import retains the full source report plus the small recorded summary metadata under verification.source. It does not rerun comparisons. Large old reports without a summary remain unreadable for preview until a real verification writes the summary; their bytes are still preserved. Case-file/candidate-message limits are unchanged.

For an actual Android runtime reference, use `carve/android-reference@1`; exact selected DEX bytes are staged and compared through a reviewed adapter on an explicit serial. See [Android runtime setup, schema and evidence scope](ANDROID.md). A generic JVM reference remains JVM-only.

Mach-O load commands can be inspected without an external engine using `loader` / `carve_loader`; see [loader evidence](LOADER.md). Native-loader observation IDs may support a contract but cannot replace complete decompiled code.

Moved workspaces can be repaired through the CLI or `carve_relocate` MCP tool; see [workspace relocation](RELOCATE.md). Old absolute `from` paths are mapping data; every live target/evidence path must remain within the MCP root.

## MCP

Create a local engine configuration:

```json
{
  "ghidra": "/absolute/path/to/ghidra",
  "javaHome": "/absolute/path/to/jdk",
  "jadx": "/absolute/path/to/jadx/bin/jadx"
}
```

```sh
node dist/cli.js serve --root /path/to/workspace --engines ./engines.json
```

The 12 existing JS/runtime tools remain. Additional tools: `carve_analysis_enqueue`, `carve_analysis_jobs`, `carve_analysis_run`, `carve_analysis_start`, `carve_analysis_runs`, `carve_analysis_cancel`, `carve_unpack`, `carve_reverse`, `carve_survey`, `carve_relocate`, `carve_index`, `carve_native`, `carve_links`, `carve_loader`, `carve_manifest`, `carve_library_add`, `carve_library_find`, `carve_library_get`, `carve_context`, `carve_managed`, `carve_search`, `carve_observation`, `carve_trace`, `carve_reconstruct`, `carve_verify_reconstruction`, `carve_verification`. Engine executable locations are fixed by startup configuration. Without it, native/managed calls report setup requirements; carve_loader reads Mach-O commands and carve_manifest reads compiled Android declarations without engine setup. Each MCP server permits at most two synchronous engine calls. Background batches have one execution lease per workspace and no global concurrency limit; normal MCP disconnect leaves delegated work running. Retain the run UUID, inspect runs and explicitly cancel when needed; see the [queue workflow](QUEUE.md). Synchronous request cancellation terminates owned tools. Comparison requires `execute:true` and existing trusted-execution authorization.

## Reproduce checks

```sh
npm test
npm run verify:scale
npm run verify:native -- /path/to/engines.json /path/to/r8.jar
```

The native script currently targets macOS arm64 and fixture-specific recovered arithmetic. It builds a stripped native executable and DEX from the bundled owned sources, uses actual configured MCP engine calls, unpacks a deflated ZIP containing native/DEX members with lineage, compares 54 cases per implementation, deletes originals/implementation sources and then runs the independent packages. It does not claim third-party-app, Android runtime or large-system reconstruction. Latest local reports are under artifacts; unavailable external checks are not counted as passed.


For unpacked Android APK entrypoints use `manifest` / `carve_manifest`; see [compiled manifest analysis](APK_MANIFEST.md). It records static declarations separately from implementation code, with resource/UI/runtime unknowns preserved.

## Ordered stateful verification

`carve/reference@3` (host command) or `carve/android-reference@4` (selected ART VM), with `carve/sequence-cases@1`, compare ordered calls in one original process and one candidate module instance per sequence. See [the protocol, limits and reuse rules](STATEFUL.md). Reference@1/@2 and Android-reference@1/@2/@3 remain scalar/fresh-per-case. Results count sequences as passed/total and steps separately; mismatches are retained at their step index. A new request starts fresh; passing does not establish arbitrary state recovery or dependency closure.
