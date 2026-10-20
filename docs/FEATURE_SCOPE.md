# Feature scope and clarification

`scope` / `carve_scope` stores requirements, missing answers and selected leads in an analysis workspace. The agent presents clarification questions in conversation. RECarve does not launch an LLM or REA.

## Minimal request

Save `request.json`:

```json
{"schema":"carve/feature-request@1","origin":"agent-proposed","goal":"Extract image size calculation","choice":"image","facet":"transform"}
```

```sh
node dist/cli.js scope ./work --request ./request.json
node dist/cli.js scope ./work --id RETURNED_ID
node dist/cli.js scope ./work --id RETURNED_ID --view record --characters 2000
```

MCP accepts `{workspace, request}` directly. Questions distinguish `audience:user` (trigger, input, exact output, state and UI/remote/host requirements) from `audience:agent` (indexed files, hashes and observations). Custom requests may omit choice/facet. Origin defaults to agent-proposed; user-described and test-fixture are also declarations, not identity or approval proofs.

## Revisions and selected sources

Submit a complete replacement request with CLI `--parent OLD_ID` or MCP `parentId`. Fields are not merged automatically.

| Field | Meaning |
| --- | --- |
| behavior.trigger/input/output | Each 1–2000 characters |
| behavior.state | stateless, sequence or unknown |
| boundary.ui/remote/host | excluded, required or unknown |
| leads | Up to 16 selected workspace/file/sourceSha256/optional observationId records |

A lead workspace defaults to `.` relative to this scope's workspace. The file is an index key; sourceSha256 identifies the input, not the observation or evidence. An optional observation must belong to that exact file/revision. Writing freshly hashes selected inputs and checks index/observation ownership. MCP confines workspaces, inputs, SQLite sidecars, container metadata and storage to its root; this is not an execution sandbox.

Selected leads do not establish call relations, complete code, provider authenticity or dependency closure. `recordedCompleteCode` is indexed metadata, not a substitute for reading code and rebinding reconstruction evidence. Boundary declarations do not prove implementability.

Status is `needs-clarification`, `needs-evidence` or `ready-for-investigation`. The last only permits further investigation; `verification:not-run` and `semanticMatch:unconfirmed` remain. Encryption and incomplete inventory stay explicit.

## Storage and bounded reads

Normalized records are immutable content-addressed `WORKSPACE/feature-requests/ID.json`; identical content reuses the ID. Parent links preserve revisions, not signatures or approval. Limit: 1 MiB per record. Symlink redirection and conflicting overwrites are refused.

Reading an ID is historical, with `sourceIdentityCheck:recorded-only-no-current-source-check`; it does not rehash current files. New writes recheck selected inputs. Reconstruction and verification perform their own complete evidence checks. Explicitly [relocate](RELOCATE.md) moved workspaces before reuse.

Summary includes a 160-character goal preview and bounded source cards. `view:sources` uses offset/limit. `view:record` returns JSON text chunks: concatenate every page before parsing. Offsets are UTF-16 units without splitting surrogate pairs; characters <=12000. Only a complete single page contains the whole record. Budget: 1024–65536 bytes, default8192. Insufficient metadata budget is refused before writing. Receipts measure compact UTF-8 bytes, not model tokens/cost. Embedded instructions remain data.

Read requirements, investigate complete code/calls/dependencies through separate REA or analysis backends, then author a [reconstruction contract](RECONSTRUCTION.md). A TASK reference such as `scope-request:ID` is a lookup aid, not automatic contract binding.

`npm run verify:feature-scope` requires the retained ZXing4.7.8 APK and local JADX/JDK setup. It checks static inventory, DEX/manifest analysis, payload refinement, missing answers, two workspaces, immutable revisions, fresh MCP reads, pagination and stable tasks. Synthetic answers are labeled test-fixture. It does not run the target or claim whole-App recovery. [ART behavior checks](ZXING_STATEFUL.md) are separate evidence.

## Output target

Optional `target` is independent of source format:

```json
{"schema":"carve/feature-request@1","goal":"Rebuild data processing as a browser module","target":{"schema":"carve/target@1","platform":"browser","delivery":"module","language":"JavaScript"}}
```

Platforms: windows, macos, linux, ios, android, browser, server, portable. Deliveries: desktop-app, mobile-app, web-app, module, cli, service. Optional language/runtime are 1–100 characters; architecture is x86/x86_64/arm/arm64/universal. These declarations do not invoke compilers or select analysis backends.

Desktop apps require desktop OS targets; mobile apps require iOS/Android; web apps require browser. Browser allows web-app/module, portable only module, server module/cli/service. Backend requirements must be declared separately; nothing is deployed automatically.

Responses add `targetAssessment:not-performed` only when a target exists. Historical requests receive no default target, preserving immutable IDs. Change destination through a complete child revision. This is not a platform execution support matrix. See [project planning](PROJECT_PLAN.md) for agent-declared dependencies, which are not proven decompiler closure.
