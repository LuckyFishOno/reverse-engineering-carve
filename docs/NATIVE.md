# Native feature boundaries and registration tables

RECarve 0.7 adds paginated string queries, bounded loaded-memory/reference/pointer/instruction windows and code/data tracing. This helps an existing agent locate native capabilities that are reached through a registration table rather than a direct call. It is an investigation workflow; arbitrary registration layouts and semantic feature selection are not automatically solved.

For analysis performed by an independent REA MCP, use the [explicit native Evidence handoff](REA_NATIVE.md). Optional complete callees and typed outgoing references retain direct call sites, address spaces, thunks and unresolved callback positions. Trace/context link only source/provider/profile-compatible REA code observations; indexed:false asks for further separate REA analysis, never an implicit cross-image match. relationshipsIncomplete concerns recorded coverage, and dependencyClosure stays not-established.

## Real stripped-release case

The pinned [jq-1.8.2 macOS arm64 release](https://github.com/jqlang/jq/releases/tag/jq-1.8.2) asset has SHA256 `2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e`. Function symbols did not reveal the requested builtin. The agent requested UTF8 byte length and investigated its shipped bytes:

1. A Ghidra defined-string query finds `utf8bytelength` at `1000b59df`, referenced from the data slot `1000bcd20`.
2. A 128-byte window at `1000bcd00` shows repeated function/name/arity entries. Neighboring names include `length` and `type`. The reviewed layout for this release is a 24-byte record, with function at offset0, name at offset8 and arity at offset16. This is a release-specific observation, not a universal layout rule.
3. The associated function is at `10000a8d8`; following its callees finds the byte-length helper at `10002086c`, which reads a stored string length field and shifts its flag bit. The adjacent `length` implementation follows another path for codepoint counting. Inferred C signatures/ABI are not treated as an original-source contract.
4. The agent implements an independent Unicode-string to UTF8-byte-count function and compares it through the actual jq executable's JSON CLI. No original jq function is recompiled as the reference.

Actual local result: **160/160 original executable cases**, including Chinese, astral characters, combining characters, embedded NUL and larger strings. The independent CLI/invoke/MCP still work after the original invocation path and reimplementation source are removed. Analysis snapshots remain retained. The input's COPYING notices are retained in the generated package. This is one bounded builtin from a real native program, not full jq or arbitrary system reconstruction.

## Commands

```sh
carve reverse /path/to/native-program --goal 'Extract the capability I need' --out ./work
carve native ./work --file relative/program --ghidra /path/to/ghidra --java-home /path/to/jdk \
  --strings 'observed text' --limit 20
carve observation ./work RETURNED_ID
carve native ./work --file relative/program --ghidra /path/to/ghidra --java-home /path/to/jdk \
  --window OBSERVED_DATA_ADDRESS --bytes 256
carve native ./work --file relative/program --ghidra /path/to/ghidra --java-home /path/to/jdk \
  --function OBSERVED_FUNCTION_ADDRESS
carve trace ./work STRING_OR_WINDOW_ID --depth 3 --max-nodes 50
```

Large binaries can select `--heap-mib` / `--threads` (MCP heapMiB/threads); defaults stay1024MiB/2. A logged OutOfMemoryError fails the call and is never cached as completed analysis. See [engine resource budgets](ENGINE_RESOURCES.md).

Native and managed results return up to100 exact `observationIds` plus a truncation flag, so a caller can inspect that export without guessing which earlier search match belongs to it. Search results also retain provider identity. Observations are immutable: identical native records retain their first evidence provenance; changed records and generated JADX source bytes receive distinct IDs. Re-querying an input must not invalidate evidence already bound by a package. Original filesystem bytes still must match the current inventory before reconstruction/verification.

`observation` text is paginated: follow `nextOffset` until null before parsing a long JSON data window or treating a function body as fully read. Provider-preview truncation and response pagination are separate. Bounded reference/callee/pointer summaries include their own truncation flags. Do not confuse a first page with a complete record.

## Query scope and bounds

`--function`, `--strings` and `--window` are mutually exclusive. Omission exports a function inventory page. String search is a case-folded literal substring over Ghidra-defined top-level strings, not every possible runtime string. An empty substring requests all defined strings. Use `summary.nextAddress` as `--after` for function/string pages; a window/function selector cannot use that cursor. Default limit500, maximum10,000. The old first-inventory-page string cap remains1,000; explicit string pages can search beyond it.

`--window` reads1–4,096 bytes (256 default), clamped to initialized memory in one loaded block. It contains byte order/pointer width, raw hex, analyzer outgoing references, up to100 incoming references at its start, aligned raw pointer interpretations and up to256 instructions. Outgoing references are capped at512. This is **loaded program memory**, including loader interpretation/relocation, not a raw file-offset view. Raw pointer values can be coincidental and nearby functions can belong to other registrations; inspect neighboring entries and verify the operation.

The trace follows data references into indexed windows even when a pointer lies inside a window rather than at its first byte. Unsigned address-range keys stay in SQLite without JavaScript Number precision loss. Unknown data references remain visible as unindexed leads; inspect them explicitly. Data-pointer interpretation is distinct from a static call. The graph is bounded and does not prove dataflow closure, cross-binary linkage or semantics.

## Reconstruction evidence

The contract requires at least one complete decompiled function/class in `evidenceIds`. Optional `supportingEvidenceIds` hold verified string, registration-window or other boundary evidence from the same current input. Each record retains role, provider and file/hash binding. Metadata cannot replace implementation-code evidence. Unknown dependencies and incomplete behavior remain explicit even if examples pass.

```json
{
  "evidenceIds": ["selected-function-id", "required-helper-id"],
  "supportingEvidenceIds": ["operation-string-id", "registration-window-id"]
}
```

This is a fragment of `carve/reconstruction@1`; see [the full contract](RECONSTRUCTION.md). jq's internal jv representation and numeric boxing were replaced by a declared JSON-string contract, not copied as an opaque native object. Non-string behavior, malformed Unicode, invalid raw UTF8, other builtins and other platforms remain unverified. The comparison uses `target-cli` with `json-stdin`; a guessed C ABI is not used.

## Cache and reproducibility

Completed Ghidra auto-analysis is keyed by source bytes, Ghidra version and an explicit analysis profile. Export-script hashes belong to evidence/export identity, so adding an export query need not repeat the expensive import. The 0.7 profile creates a new cache generation; older evidence remains retained. The owned Ghidra database is not independently authenticated against external modifications, and the full engine installation is not comprehensively hashed.

```sh
npm run verify:jq -- /path/to/engines.json
npm run check -- /path/to/rea --native-engines /path/to/engines.json --jq
```

The optional jq check needs the actual macOS arm64 executable plus Ghidra/JDK. It verifies the pinned download, actual MCP string/window/decompile calls, string cursors, table evidence, instruction pagination, preservation of packaged evidence after another export, original/candidate cases and independent output. Other hosts must supply and verify a suitable release before claiming that runtime path. A missing engine or mismatching comparison fails; it is not a successful reconstruction.

For large multi-component inputs, begin with the [loader-only native linkage pass](NATIVE_LINKS.md) to page imports, external-entry symbols and library names before selecting code for full auto-analysis. Candidate name matches and basename hints remain unresolved.
