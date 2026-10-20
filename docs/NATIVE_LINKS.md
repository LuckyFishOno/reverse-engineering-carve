# Native import/export discovery

For exact Mach-O load commands and bounded local path expansions, use the engine-free [loader reader](LOADER.md). It preserves competing paths and records support evidence; it does not change this symbol query's matching rules or prove runtime binding.

RECarve0.12 provides a bounded loader-metadata pass before full native analysis. It reads the configured Ghidra importer's external libraries/import locations/external-entry symbols without running auto-analysis or target code. It uses a separate ghidra-linkage-v1 project cache; a metadata-only project is never accepted as completed full auto-analysis. Native function decompilation retains the existing full-analysis profile.

```sh
node dist/cli.js native ./work --file bin/program --linkage imports \
  --ghidra /path/to/ghidra --java-home /path/to/jdk --limit 100
node dist/cli.js native ./work --file bin/program --linkage libraries \
  --ghidra /path/to/ghidra --java-home /path/to/jdk
node dist/cli.js native ./work --file lib/library --linkage exports \
  --ghidra /path/to/ghidra --java-home /path/to/jdk
```

The equivalent MCP call is carve_native with linkage:imports/exports/libraries. Native function/strings/window/linkage selectors are mutually exclusive. For large investigations enqueue requests such as `{file:"bin/program",native:{linkage:"imports",limit:100}}` through the existing [queue/background workflow](QUEUE.md). A completed job means one selected metadata page, not all imports or a reconstructed feature.

Each page emits up to10000 records (default500), nextCursor or null, source SHA256, language, exporter identity and immutable observation IDs. Use the returned opaque nextCursor as after / --after for the same file and kind. Cursors bind the selected relative path, source hash and exporter profile. Changed sources/profiles or another kind reject an old cursor. The importer streams records and may rescan an ordinal prefix on later pages; it does not put all symbols into a JS array. Ghidra still loads the selected program database within the existing engine budgets. This is not a claim of constant-time paging or unrestricted billion-symbol support.

```sh
node dist/cli.js links ./work --file bin/program --kind imports --limit 20
node dist/cli.js links ./work --kind libraries --query libname
node dist/cli.js links ./work --from RETURNED_IMPORT_OBSERVATION_ID --limit 20
```

MCP carve_links has the same file/kind/query or from candidate mode, with page limit1–100 (default20) and offset. It queries SQLite, not the target filesystem. Records must match the current inventory revision/source hash and latest indexed exporter profile for that artifact/kind. New source revisions and newer indexed profiles exclude old rows without deleting historical evidence. freshBytesChecked:false means this read did not independently rehash the current files or evidence; native analysis and reconstruction rehash selected inputs afterward. Latest indexed profile does not authenticate the current full tool installation.

Record-mode query is a literal case-sensitive name/library fragment. Candidate mode searches only this analysis workspace; it does not automatically join version2 contract workspaces. It selects exports in other indexed artifacts having the exact symbol name, Ghidra language and recognized format. symbolMatch:leading-underscore / --symbol-match leading-underscore explicitly removes one leading underscore from both names; it does not demangle C++ or establish ABI compatibility. Every candidate remains semanticMatch:unconfirmed and runtimeLoading:unverified. libraryBasenameHint compares the import's declared library basename with the candidate path basename. A hint never resolves @rpath, search order, environment, symlinks, symbol versions, weak imports, reexports or ordinals. Same-name candidates remain listed, including misleading alternatives.

pageCoverage reports a contiguous covered prefix, knownComplete, inspectedPages and a nextCursor for the first missing page. Overlapping pages can fill a gap; an isolated final page does not prove earlier pages were indexed. Inspection is bounded to10000 page records and reports inspectionTruncated when needed. knownComplete covers only the selected Ghidra metadata category; it never means all project dependencies or dynamically loaded code are known. links.nextOffset pages the records already indexed; it is different from pageCoverage.nextCursor, which requests another engine metadata page. Empty queries do not establish missing runtime dependencies.

Import addresses are Ghidra external-space locations. Export addresses are loader external-entry-symbol locations in the imported program model, not runtime ASLR addresses or file offsets. External-entry classification is not a complete independent binary export-table resolver. Raw records and provider/evidence identity can be read through observation pages. They may support a version2 [multi-artifact contract](MULTI_ARTIFACT.md) as supportingEvidenceIds; they cannot replace complete caller/callee code evidenceIds. Review actual code, loader configuration and operation behavior before selecting a feature boundary.

The updated `verify:multi` case indexes an owned executable plus two same-export libraries. Both candidates remain visible; an actual alternate executable linked to the decoy returns1006 for a case where the selected target returns47. Actual load/code evidence selects the intended library. The independently reconstructed behavior still passes162 original CLI comparisons and works after originals/rewrite source removal. `npm run verify:links -- ./engines.json` separately copies this host's installed Homebrew ripgrep/PCRE2 bytes, records actual versions/SHA256 and library load, runs metadata requests in a background batch, resumes a five-record import page from a fresh MCP session and finds a PCRE2 candidate. It currently requires macOS arm64 and the installed `/opt/homebrew` paths. This latter case verifies discovery only; it does not reconstruct regex behavior or index system shared-cache libraries.
