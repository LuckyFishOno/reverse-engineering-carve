# Budgeted analysis context

RECarve context queries existing disk-backed observations without running an LLM, decompiler or new source analysis. Default auto combines outlines with complete short recorded pseudocode when it fits. Long records stay on disk until requested.

```sh
node dist/cli.js context ./work --query 'duration charge' --budget-bytes 8192
node dist/cli.js context ./work --query charge --view outline
node dist/cli.js context ./work --id OBSERVATION_ID --code --budget-bytes 8192
node dist/cli.js context ./work --query charge --known-fingerprint PREVIOUS_FINGERPRINT
```

MCP carve_context takes workspace plus query or1–20 explicit observation IDs, optional file/view/code/offset/budgetBytes/knownFingerprint. Query splits up to12 identifier/word terms (queryTermsLimited marks omitted terms), preferring name substring hits and also using the persisted full-text index. It ranks a bounded64-seed pool deterministically and diversifies it by artifact before adding sibling spans. Up to four seeds contribute up to12 recorded callees each. Only indexed functions in that same artifact/source hash are linked; matching import names in another binary never create automatic call edges. For imported REA records, callee expansion additionally requires the same REA provider id/name/version and analysis profile digest; a newer record from another profile or internal Ghidra run cannot substitute for missing code. Foreign/imported targets remain unresolved. The query runs in one SQLite read snapshot. Explicit focus IDs retain distinct records at the same location, including different provider/mode evidence; lexical neighbours collapse duplicate locations.

This is a local lexical/static graph aid, not a semantic model, whole-project PageRank or a complete dependency graph. Source strings, metadata-only loader observations and inventory names may appear as cards but cannot replace complete implementation-code evidence. It does not analyze previously unseen components; use the native/JADX/JS workflows first. Current-inventory means matching recorded revision/hash, not a fresh filesystem/evidence check. Changed source bytes require refresh and selected-byte validation before reconstruction.

Schema carve/analysis-context@2 stores shared sources (file/sha256) and providers arrays. Each card's source/provider is a zero-based dictionary index (provider may be null). Cards retain names, locations, display signatures, recorded code/truncation/failure state and nullable external/thunk flags. Each callee contains either item (zero-based index into this page's items), or an observation id with name/address; null id means unresolved. A differing observed call alias stays in name. All these are recorded static calls. Each page builds its own dictionaries/indices and contains no references to omitted dictionary entries. Use a card's id with carve_observation; a repeated read.id is unnecessary.

view:auto includes pseudocode only if its complete stored text is at most1024 UTF8 bytes, its provider has not marked it truncated/failed and its status is completed or unspecified. It must fit the full response budget; otherwise that whole card falls back to an outline. view:outline never includes bodies. view:excerpt (CLI --view excerpt or --code, MCP code:true) includes at most1200 Unicode code points of pseudocode/record content. code:false is an outline alias; conflicting explicit selectors fail.

Optional text contains source (pseudocode or record-content), value, complete and nextOffset. complete means the entire stored text is present, not original-source recovery or semantic completeness. recordTruncated/decompilationStatus/provider analysisMode remain separate, including fallback instruction output. An explicit excerpt can contain the entire text of a provider-truncated record; it still cannot establish complete implementation evidence. text.nextOffset is a JavaScript UTF16 string offset usable with carve_observation/observation, including non-BMP characters. Continue reading before reconstructing from an incomplete excerpt. An omitted text field means read the observation separately if needed. Names/signatures are bounded display metadata.

budgetBytes is1024–65536, default8192. The full compact JSON payload, including shared dictionaries, fingerprint and receipt, fits the budget; CLI adds one newline. MCP framing is outside the payload. Whole items are retained or omitted with nextOffset, never silently cut into invalid JSON. Auto can fall back from inline text to a whole outline; an explicitly requested excerpt never silently downgrades. A budget unable to fit one complete item yields an explicit minimum-size error. candidateScanLimited/calleeExpansionLimited/budgetLimited describe different omissions; recorded callee truncation also marks expansion limited. Offset pages the bounded ranked pool; it does not promise all project matches. Narrow the file/query or use observation/search/index pages for more.

The receipt gives exact responseBytes and rawSelectedTextBytes for selected pseudocode (or content for records without pseudocode); library-find instead reports catalogued implementation bytes. Raw text size is descriptive, not a comparable complete API response or a savings claim. It never uses an entire executable as a fictitious token baseline. estimatedTokens is ceil(UTF8 response bytes/4), explicitly a heuristic that can be inaccurate for a particular language/model. No provider token usage or actual billing is measured. Even a compact card can cost more than a short raw function.

A fingerprint identifies the exact selected recorded packet, request scope, inventory revision and budget. Supplying that same fingerprint returns unchanged-recorded-context with no repeated cards. This is opt-in: the caller must still possess that packet. RECarve does not silently suppress text after a context reset. It does not authenticate current source/evidence files or a mutable local database; reconstruction gates remain required.

The design was informed by the user-supplied [Trail-Code repository](https://github.com/trailhq/Trail-Code), inspected at [ead585b2707055f47f1e97d9b0d4209af5285805](https://github.com/trailhq/Trail-Code/tree/ead585b2707055f47f1e97d9b0d4209af5285805): structural reads before bodies, file-diverse query results, bounded snippets and content-derived reuse. Relevant sources were ask/ask.ts, ask/file-selection.ts, ask/graphrank.ts, ask/index-file.ts and graph/extract-cache.ts. RECarve implements these principles independently over its native/DEX SQLite evidence; no upstream code, hooks, daemon, transcript access, API-key setup or model calls were imported. Upstream benchmark claims are not RECarve benchmark results.

Tests check large bodies, UTF8 receipts, NUL preservation, non-BMP continuation, scope/content changes, exact reuse, provider variants, auto budget fallback, page-local links and actual CLI/MCP payload bounds. verify:multi builds outline/auto/reuse packets from actual Ghidra caller/callee observations before the original two-component program is compared and removed.

## Optional reproducible payload benchmark

scripts/benchmark-context.mjs compares an archived old dist/context.js with the current module on a local JSON request array: [{"name":"case","workspace":"/absolute/work","options":{"ids":["OBSERVATION_ID"]}}]. Each request uses65536 bytes so both versions must return the same entire bounded pool. Archive the old complete dist directory before replacing it so relative imports resolve. Do not use view/code/knownFingerprint inside benchmark options.

```sh
python3 -m venv ./artifacts/tokenizer-venv
./artifacts/tokenizer-venv/bin/python -m pip install tiktoken==0.12.0
node scripts/benchmark-context.mjs --cases ./requests.json \
  --baseline ./artifacts/context-baseline-0.14.0/dist/context.js \
  --python ./artifacts/tokenizer-venv/bin/python --out ./artifacts/context-benchmark-run
```

The optional benchmark dependency is isolated; normal RECarve queries need no Python/tokenizer/network. The first named-encoding load may fetch and verify public tokenizer vocabulary bytes, stored and hashed under the benchmark output directory. No source code or payload goes to a model. The report saves exact compact JSON payloads, hashes, o200k_base counts via pinned tiktoken, provider/source identities and separately fresh source/evidence checks. It compares outlines to outlines; auto is compared with the old outline plus full observation responses only for bodies now included inline. These responses share selected IDs and inline text, but old full reads also contain extra reference/evidence metadata. Counts exclude transport, prompts, tools' schemas, model output and billed usage. The benchmark is not an accuracy or whole-task cost evaluation.

Migration from0.14: cards' file/sourceSha256/provider/read and excerpt fields are replaced by source/provider indices and text. selectionReason is now reason. Fingerprints change with the schema; old fingerprints cannot suppress new packets. Request scope is bound privately into the fingerprint without repeating explicit focus IDs in every response.

## Local0.15 measurement

Three hand-selected requests from the already analyzed shipped jq1.8.2 Mach-O and scrcpy5.0.1 DEX, measured with tiktoken0.12.0/o200k_base. The native request retains four observation IDs; each normal/fallback DEX request retains two. Fresh source/evidence checks passed separately. These are selected retrieval examples, not a representative whole-project workload or new execution-equivalence tests.

| Request | 0.14 outline tokens | 0.15 outline tokens | Payload reduction |
| --- | ---: | ---: | ---: |
| jq-1.8.2-native | 3031 | 1840 | 39.3% |
| scrcpy-5.0.1-dex-auto | 867 | 548 | 36.8% |
| scrcpy-5.0.1-dex-fallback | 848 | 557 | 34.3% |

For jq, auto includes three whole short bodies:2786 tokens versus5678 for the old outline plus three full observation reads (50.9% fewer payload tokens,4 responses to1). Old full reads include extra reference/evidence metadata, so this is a comparison of retrieval paths for the same selected IDs/inline text, not identical complete response information. DEX bodies exceed the auto threshold and remain outlines. Auto fingerprint-reuse responses measure114–115 tokens.

Exact local payloads, identities, assumptions and tokenizer cache hashes: artifacts/context-benchmark-0.15.0-final/report.json. The baseline captured before edits is artifacts/context-baseline-0.14.0/dist/context.js (SHA2568c9f2c18b2413b21972e9b9984a50686e04b8e5b03982bb3714d81c982153576). Changing requests, paths, hashes, budget or tokenizer can change counts. No model/billing savings or accuracy result was measured.

Native records admitted under the bounded terminal-boundary policy retain decompilationStatus:completed-with-boundary-warnings and boundaryWarningCount in context items. A complete recorded text body does not resolve those warnings. Read the observation for bounded warning/byte-witness details and its owned snapshot for full provider data; see [native handoff](REA_NATIVE.md).
