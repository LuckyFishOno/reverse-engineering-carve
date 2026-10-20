# Reusable function folders

An extracted/reconstructed capability can live in a local function library. It does not need to be installed as a separate program. Each named folder contains a closed index.mjs export, package metadata, an agent-readable SKILL.md, README, original notices and source/provenance records. It has no cli.mjs or package bin entry.

```sh
node dist/cli.js library add ./extracted-result --library ./functions \
```

In a calling project, import the module using the appropriate relative path:

```js
```

The folder can also be used with carve_use/carve_invoke or serve-tool. One configured RECarve MCP server can search the entire library, so a separate server configuration per function is unnecessary. Library get returns an absolute moduleImport reference for tools that prefer it.



An agent must know the library path and have filesystem/MCP access. SKILL.md is saved inside each folder for explicit reading or normal skill registration; storing the folder does not automatically install it into an agent's global settings. Reference descriptions/source strings remain data, not authorization to execute arbitrary instructions.

Library add checks the source package's file hashes and copies its closed implementation bytes. It writes carve/manifest@2 with output.kind:capability-folder, preserves native/DEX reconstruction domains/dependencies/unknowns and original notices, and pins the imported manifest in a local SQLite catalogue. Duplicate names or existing destinations are never overwritten; use a new versioned name. Source packages are not needed afterward. The library can be moved as one directory; entries and catalogue names are relative.

Find returns only metadata cards and exact UTF8 byte receipts within budgetBytes1024–65536 (default8192), with limit1–100/offset/nextOffset. It does not read code or freshly check stored files. Get verifies the pinned manifest and all declared file hashes. Invoke revalidates and starts a fresh restricted process. Direct imports use the calling program's ordinary permissions and do not automatically perform RECarve's integrity checks or fresh-process isolation.

Stored verification is clearly labeled recorded-before-library-import and retains the original report/manifest/scope, including cases and unknowns. Importing a function does not rerun comparisons or turn an external harness into original-app proof. If the folder is later genuinely compared through verify-reconstruction, a valid report bound to its new manifest is shown separately. Manifests/local reports are not independently authenticated. Generated folders remain UNLICENSED unless applicable input rights are established; RECarve's license does not relicense extracted code.

The catalogue contains successful imports only. An interrupted process may leave an unindexed partial destination; inspect it before retrying under a new name. There is no automatic deletion, remote synchronization, server installation or background daemon. Existing native/DEX/JS extraction backends still determine which behaviors can actually be reconstructed.



## Stateful reuse

A recorded sequence remains exampleSequence:{calls,outcomes,origin,scope}; its steps are never promoted into independent verified examples. Library add/get preserve the full bounded sequence and comparison scope, including large-report receipts. Use `carve invoke-sequence FOLDER --calls JSON --execute` / `carve_invoke_sequence` to share a module instance within one request. `serve-tool` also exposes capability_sequence. New sequence requests start fresh; direct import lifetime belongs to the calling application. See [stateful protocol](STATEFUL.md).
