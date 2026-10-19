# Changes

## Unreleased — public repository refresh

- Remove retired case-specific fixtures, demos, verifier entry points and their documentation references. Keep core extraction, contrast and independent native REA integrations.
- Standardize project prose, feature labels and clarification prompts in English; retain bilingual README editions and escaped Unicode regression data/search aliases.
- Add CONTRIBUTING.md and a release content-hygiene check. Refresh clean-install verification after removing the old packaged template.

## 0.38.1 — work-ledger attempt budget and path diagnostics

- A plain `released` claim no longer consumes a task's work-attempt budget. Up to 100 work attempts (closed as failed, proposed or submitted) are allowed per task, and a separate bound of 1000 claims in total, including releases, keeps stored history finite. Previously 100 claim/release cycles without any work left a task permanently unclaimable while it still showed `queued`.
- `read --view jobs` rows add `workAttempts` and `claimability` (`available`, `needs-explicit-retry`, `held`, `awaiting-review`, `exhausted`), so an exhausted task is not shown as simply queued. Claim refusals name the limit that was reached. Attempt numbers in claims, requeue and result reads accept up to 1000; existing records are unchanged.
- Path refusals distinguish a real symlink (the linked component and the canonical path are named) from a name that differs only by letter case or Unicode normalization on case-insensitive or normalizing file systems such as default APFS (the exact on-disk name is given). This applies to ledger and output directories, ledger sidecars and submitted artifacts. Both are still refused; nothing is recorded under a different name.
- Found by a read-only review with reproductions (multi-process claims, killed-writer recovery and read-only reads were also exercised and behaved as documented). Two regression tests added.

## 0.38.0 — durable task coordination and PE platform guidance

- Add work-ledger CLI and47th MCP carve_work_ledger: one pinned plan/spec per SQLite ledger, atomic claims, bounded persistent attempts, explicit release/failure/retry and stale attempt rejection. Proposal and implementation handoffs remain distinct; exact result-bound review requeue preserves history. No automatic lease expiry or agent launch.
- Check current declared revision and immutable package at adoption/submission; implementation handoffs hash every assigned external regular file. Preserve agent-reported checks as unexecuted/unverified, with no acceptance, target build or merge. Short transactions check response budgets before commit; recover SQLite journals without stealing external worker claims.
- Integrate Claude’s43-rule PE source dependency classifier and57-rule target adapter guidance through platform CLI and48th MCP carve_platform. Source hashes, immutable boundary evidence, bounded pages, explicit unknown non-system modules and static-guidance-not-verified. No SDK/runtime availability or port completion claim.
- Include the actual-installer RPCRT4 finding: classify the Windows RPC runtime conservatively as os-specific, preserving rule identity/hash without guessing network behavior.
- Exercise independent MCP claim races/restarts, stale/retry/review paths, killed-writer recovery, historical0.37 work-package compatibility, actual declared-file handoffs and separate real-PE platform guidance. Extend clean tarball install for both new tools.

## 0.37.0 — complete interface pins and immutable agent work packages

- Add strict work-spec@1 and selected work-package@1: complete own/direct dependency input/output/state/errors, whole-plan/spec revision pins, declared editable files, acceptance criteria, selected source references and explicit unknowns. Reject stale IDs, cycles and ambiguous portable file ownership across supplied assignments.
- Add work-package create/read/check CLI and46th MCP carve_work_package. Exclusive new directory, canonical record, fixed TASK instructions, hash/size manifest, bounded views, root guards and read-back checks. Preserve partial writes and immutable history; check current declarations before adoption. No source authentication, persistent dispatch, filesystem sandbox, implementation, acceptance execution or app assembly.
- Package a complete four-module plan/spec example; check actual CLI, fresh MCP sessions, stale revisions, ownership conflicts, tampering and installed tarball usage. Measure local UTF8 bytes without a claimed model token savings ratio.
- Include Claude’s independently delivered PE loader/import/export and x86/x64 import call/bridge modules in the unified regression build. These remain library APIs pending CLI/MCP integration; candidate byte scans and static import linkage do not establish Windows runtime behavior.

## 0.36.0 — independent destinations and declared project dependencies

- Add optional carve/target@1 to feature requests: source-independent platform, delivery form and optional runtime/language/architecture. Reject incompatible declared pairs without claiming target build support. Historical requests without target keep their normalized shape and immutable IDs; target-bearing views retain targetAssessment:not-performed.
- Add strict agent-authored project-plan@1, iterative cycle/phase analysis, downstream blockage and stable plan/feature/interface/task identities. Bound500features,4000edges and1MiB input; page cards with exact response budgets, leaving descriptions, full contracts and whole graphs off the summary. Graph ready only means structurally orderable.
- Expose project-plan CLI and the45th Carve MCP tool carve_project_plan. Read-only local plan-file input with MCP root confinement, no source/evidence authentication, automatic discovery, dispatch, builds or app assembly. Add a packaged four-module example and installed CLI/MCP/target round trips.
- Verify original0.35 scope bytes/IDs against retained APK analysis, preserve newly declared Windows/Mac/browser module intents, and check graph paging/cycles through fresh MCP sessions. No new original-runtime comparison or actual platform port. Codex implements target/integration; Claude independently delivers the graph core and tests under disjoint claims.

## 0.35.0 — saved feature clarification and boundary choices

- Add choice/facet refinement to the recorded feature menu, separating direction arithmetic, UI interaction and remote matching questions. Facets use literal name/path filtering; unmatched facets retain only explicitly labeled broader leads and never fall back to a successful custom match.
- Add scope CLI and the44th MCP tool carve_scope. Persist strict, content-addressed requests with missing user/agent questions, explicit behavior/state/UI/remote/host intent, bounded source identities across authorized workspaces and immutable parent revisions. New writes rehash selected inputs; historical ID reads do not.
- Bound summary/source/JSON-text pages by actual response bytes; reject stale or mismatched sources, invalid observation ownership, symlink storage, tampered records and MCP paths outside root. Intent and recorded metadata never substitute for complete code evidence, dependency relationships, user approval or behavior verification.
- Add real retained-ZXing-APK clarification/resumption check through two fresh MCP sessions, scoped JADX analysis, separately indexed manifest and unchanged original inputs. Answers are labeled test-fixture; no Android/target execution, new recovery claim or REA proxy. Extend clean tarball install coverage and task/skill documentation.

## 0.34.0 — byte-bound REA relations across independent workspaces

- Add optional toWorkspace / --to-workspace to the existing bridge tool, resolved relative to the caller workspace. Cross-workspace snapshot@2 binds both namespaces and original source/evidence identities without copying callee records; same-workspace snapshot@1/IDs remain unchanged.
- Rebind both source images and REA records, preserve the exact original Mach-O loader-path policy, and reject undeclared contract endpoints, wrong-index substitutions, stale bytes or changed evidence. MCP checks both workspace/index/source/evidence paths during creation, packaging and verification; canonicalize recorded OS aliases without widening the physical root.
- Preserve immutable relative commitments when sibling workspaces are explicitly relocated together. Historical package paths/comparisons stay historical. Add seven focused tests for namespace identity, decoys, revisions/tampering, relocation and actual CLI/MCP confinement.
- Extend the independent REA integration with three image indexes, relocation before reconstruction,162 original CLI cases, wrong-path decoy rejection and library-only reuse after construction paths are archived. REA and Carve stay independent; no new MCP tool/server, target execution by bridge or general runtime/ABI/closure proof.

## 0.33.0 — original DEX stateful sequences on ART

- Add explicit android-reference@4 json-sequence-stdin. One fresh original ART VM per sequence, one finite return/throw outcome per ordered step, existing bounded input/output/remote deadlines and before/after staging hashes. Android references1–3 retain scalar behavior; optional named native-library staging keeps its existing ABI policy.
- Preserve selected-dex-android-harness-sequences scope, sequence/step counters, runtime lifetime metadata and whole exampleSequence through archives, receipts, usage and reusable function folders. Object lifetime remains a reviewed harness claim, not an independent call trace.
- Add original shipped ZXing APK BitArray reconstruction:33 sequences /692 steps on API35 ARM64 ART, clear retains length, explicit new invokes the constructor, and reset-per-call fails. Direct import, CLI and two fresh library-only MCP requests reuse the independent local folder. Pure managed case uses existing JADX; no REA proxy/server merge.
- Cover sequence preflight, archive/receipt scope, logical-state lifecycle/domain checks and actual malformed-producer Android protocol rejection. Sync README, task/skill and Android/stateful documentation. Restore previously omitted0.31/0.32 changelog summaries from their retained checkpoints; no historical integration is relabeled as a new run.

## 0.32.0 — shipped JDK state and retained REA boundary diagnostics

- Add original runtime-module Adler32 reconstruction and framing adapter:31 sequences /405 steps with class-resource identity, independent REA native Evidence and function-library reuse. Keep external-harness-sequences scope; host JVM is not Android.
- Add narrow REA snapshot/adapter@3 acceptance for known Ghidra terminal-call diagnostics only with complete agreeing typed records and independently decoded original ARM64 B target. Preserve warning text through reconstruction/verification/library; arbitrary diagnostics remain refused and dependency closure unknown.

## 0.31.0 — ordered stateful comparison and reuse

- Add reference@3 / sequence-cases@1, invoke-sequence / carve_invoke_sequence and standalone capability_sequence. Await ordered calls in one fresh module per request, immediately snapshot per-step returns/throws and keep whole-sequence examples/counters.
- Original source-owned native counter verified32 sequences /635 steps through independent clean REA investigation, with reset-per-call negative, bounded archive reads and function-folder reuse. No cross-request state or broad application equivalence claim.

## 0.30.0 — explicit original-byte REA bridge across Mach-O images

- Add bridge-rea-native / carve_bridge_rea_native. Bind two complete independent REA function observations to original BL/E8 call bytes, indirect-symbol stub, strong undefined nlist/library ordinal, exact local load path/install name and defined instruction-section export entry. No REA/engine/target launch.
- Save immutable source-bound support snapshots. Optional multi-artifact relationship.bridgeEvidenceId requires the exact implementation endpoints and caller support binding; rederive both images and records during packaging/comparison. Runtime loading, ABI and semantic/dependency closure stay unknown. Legacy contracts remain agent-reviewed.
- Restrict the initial bridge to thin little-endian64 Mach-O executable/dylib pairs, supported direct instruction encodings and unambiguous selected-image paths. Reject weak/flat/special-ordinal/ambiguous or stale/mismatched data. Original-byte parser ranges and snapshot/output budgets stay explicit.
- Add independent REA/Carve integration using two implementation images plus a same-basename/install-name/export/address decoy. Wrong local path is refused; real dyld log,162original CLI comparisons and reusable function-folder import/invoke retained.

## 0.29.0 — source/profile-bound REA call and reference handoff

- Extend import-rea-native / carve_import_rea_native with optional complete procedure_callees and outgoing procedure_references Evidence. New owned snapshot/function adapter@2 preserves typed call sites, address spaces, external/thunk classifications, coverage diagnostics and unresolved calls; code/info-only@1 remains compatible.
- Validate source/provider/profile/selector, raw coverage, body membership and endpoint identities. Data references do not become calls. Unknown/partial coverage and disagreeing call inventories remain incomplete. Rebind all records during packaging and verification.
- Trace and budgeted context follow only source/provider/profile-compatible REA observations. Missing compatible code stays unindexed, unresolved callback reasons are bounded and dependencyClosure remains not-established. These are recorded local edges, not cross-image/runtime closure.
- Add a real two-server native integration:20REA records,3selected implementation functions,2direct helper call sites,1unresolved callback, an unindexed puts thunk,160original CLI comparisons and reusable function-folder invocation. REA closes before Carve imports; only REA has engine configuration. No merged/proxy MCP or global setup.

## 0.28.0 — explicit native Evidence handoff from independent REA

- Add `import-rea-native` / `carve_import_rea_native`. It consumes a complete REA Ghidra procedure_pseudo_code/procedure_info pair without starting REA or a Carve analysis engine. Check freshly hashed native source, format/architecture, RFC8785 record/profile commitments, exact selector/raw results and body ranges before retaining versioned owned snapshots.
- Preserve original producer IDs and underlying analysis provider; rebind normalized observations to captured records during reconstruction/verification. Reject source/selector/profile mismatches, partial/null/external results, impossible body metadata, snapshot/SQL tampering and out-of-root MCP paths. Owned evidence survives closed producer sessions, missing external JSON paths and workspace relocation.
- Keep unimported calls/references explicit; static boundary results now include relationshipsIncomplete. Imported code can participate in bounded context and feature choices, with capped metadata/errors and no behavioral or producer-attestation claim from hashes.
- Add actual independent REA6.7.0/Ghidra native integration: source-owned compiled CLI, mismatched real procedure metadata and modified-record rejection,160direct original CLI comparisons, then function-library import/invoke with only the library directory accessible. The explicit Ghidra complete-body profile is supported; other native/dynamic providers remain outside this adapter.

## 0.27.0 — independent REA companion and grounded feature choices

- Position Carve as a companion to a separately launched REA MCP. Keep tool catalogs/processes independent; no proxy or merged server. Rewrite product/readme entrypoints and document a tested two-entry setup.
- Add `features` / `carve_features`: bounded path/recorded-name candidate cards, source identities, custom descriptions, no-match states, scan/candidate pagination and explicit incomplete-inventory coverage. `reverse` can omit goal to ask for a feature choice while preserving per-goal tasks and the existing explicit-goal flow. Rules are investigation leads, not semantic confidence or extraction success.

## 0.26.0 — original APK JNI references and reusable bootstrap catalog

- New android-reference@3 explicitly stages named native ELF libraries outside the DEX classpath, checks primary ABI headers and64MiB/file256MiB/total limits, supplies java.library.path and binds/hash-checks native inputs with the existing cleanup/deadline flow. Staging identity is not load/JNI/RegisterNatives proof. Versions1/2 retain their fields and transport.
- New actual Termux0.118.3 whole-APK case: complete selected DEX class → matching JNI declaration/export → native byte-array copy and exact ELF data mapping → original ART getZip returned ZIP SHA256 plus80 metadata query comparisons covering3490entries. Reuse a metadata-only function folder after tool-created source/original invocation paths are gone. The query is a new adapter projection, not an original Termux API, payload/installer recovery or dynamic registration tracing.
- Add native schema/ELF checks, immutable query-result tests, actual ABI/non-ELF/tamper/cleanup checks and optional verify:termux-bootstrap / check --termux-bootstrap integration. Context byte measurements retain compact/actual-text distinctions rather than model-token claims.

## 0.25.1 — moved Android runtime startup

- Add a source-development Android emulator launcher with configuration-relative paths, explicit AVD/serial/port validation and a read-only `--check`. It refuses stale AVD paths, missing private ADB servers and occupied emulator ports; it never rewrites/wipes an AVD or starts/stops ADB. Foreground signals target the newly spawned child.
- Fresh post-move Android15/API35 ARM64 ART checks pass:12 protocol checks,160 original scrcpy cases and160 original ZXing contact-payload cases. The newly owned emulator and private ADB were stopped, with actual process/port absence observed. Existing behavior boundaries remain explicit.
- Replace the local hardcoded pre-move launcher with a wrapper around the new helper. Reference execution and its explicit runtime selection remain unchanged. New tests cover configuration symlinks, another working directory, moved AVD metadata refusal, live socket preflight and direct argv/exit handling.

## 0.25.0 — MCP workspace relocation

- New carve_relocate repairs moved workspace bindings through the main stdio MCP server (39 tools), with optional target and old absolute from mapping. It checks live target/evidence/SQLite/container/marker paths against the server root before committing; old mapping strings do not need to be under the new root. No input move/deletion or behavior re-verification is implied.
- Add actual MCP recovery, explicit mappings, root/symlink refusal and container-order coverage, plus clean installed-tarball relocation and inspection. CLI/API relocation remain available. Marker write interruptions after the SQLite commit remain recoverable by rerunning.
- Local-only maintenance: GitHub CI, Git ignore and contribution files were removed, followed by both npmignore files at the user's request. Third-party sources/notices stay intact. Main local tarballs still use package.json files; the retired root prototype has no packaging exclusion list.

## 0.24.0 — relocatable workspaces

- New `carve relocate WORKSPACE [--target PATH] [--from PATH]` (direct API `relocateWorkspace`). After a project folder moves, it rewrites the workspace's target binding, container lineage and observation evidence paths in one SQLite transaction. It first checks every indexed file's size at the new target (and rehashes a file target) and hashes every evidence file at its new location against the recorded hash; any mismatch changes nothing. A target that moved together with the workspace is found automatically; one that moved elsewhere needs `--target`. Inventories of unpacked containers require their container workspace to be relocated first. Running it again is safe.
- Workspaces now record their own location. `survey`/`reverse` and every analysis that selects an indexed file refuse a moved workspace with a `run carve relocate` message, so new evidence is never written next to records naming the old location. Pre-0.24 workspaces are detected through `survey.json`; when that was rewritten after a move, relocation refuses missing evidence and asks for `--from`.
- History is not rewritten: queue results, run logs, task reports, engine logs and verification archives keep their recorded paths; observation IDs and evidence files are never edited. Ghidra caches stay reusable after relocation.
- Real check: all eight pre-move third-party workspaces (jq, OpenSSL, scrcpy, Termux, ZXing inventories and their container workspaces) relocated with hash-verified evidence (up to 10736 rows), indexed-file selection with container lineage works again, and a relocated jq workspace reused its completed Ghidra analysis.

## 0.23.0 — host-wide heap registry, strict modified UTF-8, relocatable engine configuration

- Ghidra/JADX heap reservations are now shared by every Carve process of the user on the host (CLI, MCP servers, queue runs, background workers), not only within one MCP server. The registry lives under the account home directory (`~/Library/Caches/carve/engine-reservations` on macOS, `~/.cache/carve/engine-reservations` elsewhere) instead of `os.tmpdir()`, so processes with different `TMPDIR` values can no longer each reserve the whole host budget. `CARVE_ENGINE_RESERVATIONS` remains an explicit shared override. Owners that have verifiably exited are reclaimed.
- The modified UTF-8 decoder for class-file and DEX strings rejects overlong forms like HotSpot and ART: a two-byte unit must encode NUL or at least 0x80, a three-byte unit at least 0x800. Class files of major version 47 or older keep HotSpot's legacy acceptance. Checked against Temurin 21 `defineClass` at major 55, 48 and 45.
- Engine and Android runtime configuration files may use paths relative to the configuration file. `carve serve --engines`, `queue add/run/start --engines` and all verify scripts read them through one loader. The bundled `artifacts/engines/config.json` and `artifacts/android/config.json` now use relative paths, so the project folder can move.
- Tests: new cross-process registry tests with distinct `TMPDIR` values, a full-registry refusal and SIGKILL reclamation; overlong UTF-8 rejection for class and DEX inputs; relative engine configuration through an actual stdio MCP server started from another working directory.

## 0.22.0 — JDK Adler32 across JNI

- New optional check `verify:jni-adler32` (check --jni-adler32). Starting from the shipped Temurin 21 java.util.zip.Adler32 class, it follows the JNI declaration through the libzip export into three decompiled native functions (JNI entry → adler32 → adler32_z). JVM jni+resolve/library logs show the actual native link and libzip load.
- Independent closed JS Adler-32 (examples/jvm/adler32.mjs) passes 160 comparisons against the installed JDK. The reference is a source-owned adapter (examples/jvm/Adler32Harness.java) run in the interpreter with the diagnostic Adler32 intrinsic disabled, so libzip is the code compared. The result is stored as a reusable function folder and checked through direct import, restricted invoke and MCP after intermediates are removed.
- `verify:jni` now also compares one JVM start's jni+resolve log with the static results: the 23 java.lang natives without exports are exactly the runtime-registered ones, and the symbol-linked ones are static-export candidates.

## 0.21.0 — JNI boundaries

- New engine-free `jni` CLI / `carve_jni` MCP tool (38 main tools). It strictly parses native method declarations from indexed Java class files and DEX files, decoding modified UTF-8, and records them as immutable evidence with fresh source hashes. It derives JNI short/long names per the JNI specification.
- Declarations are matched to indexed loader export pages of current-inventory libraries: exact ELF names, plus the underscore form on Mach-O. Results report per-library page completeness and cursors, JNI_OnLoad exports as dynamic-registration leads, overload ambiguity, libraries with no export index, and byte-budgeted pages. A match is a static-binding candidate only.
- Real check with pinned Temurin 21 `java.base`: all 27 java.util.zip declarations equal libzip's 27 nm-listed Java_ exports. An official D8 DEX of the same classes yields identical results. java.lang Object/Thread give 3 static matches and 23 JNI_OnLoad-lead results, consistent with nm. Shipped scrcpy/ZXing DEX files parse and declare no natives. Fixtures generated with javac/D8 check names against `javac -h` headers.

## 0.20.0 — engine resource budgets

- Ghidra and JADX accept an explicit JVM maximum heap and worker-thread budget through CLI --heap-mib/--threads, MCP heapMiB/threads, queue resources:{heapMiB,threads} and the direct API. Defaults stay 1024 MiB / 2 workers, so existing launches are unchanged. Requests above 75% of host physical memory or the available parallelism fail before an engine starts.
- Concurrent engine calls in one MCP server share a heap reservation. A call that would exceed it is refused without launching. Separate processes and background runs are not counted.
- The whole engine log is scanned for java.lang.OutOfMemoryError. Ghidra exit 0 after a logged heap failure no longer produces a completed cache; JADX heap failures are not indexed.
- Results report the launch resources. Native results also report analysisResources for the completed cached auto-analysis (null for pre-0.20 caches). Resources do not change cache identity. Queue requests without resources keep their exact previous job identity.
- Actual Ghidra (jq-1.8.2) and JADX (scrcpy 5.0.1 DEX) JVM command lines were observed carrying the requested -Xmx, -max-cpu and --threads-count. Peak memory, speed and a real engine heap exhaustion were not measured.

## 0.19.0 — bounded verification results

- Reconstruction verification CLI/MCP now default to exact byte-budgeted summaries. Explicit --full-report / fullReport:true preserve legacy complete replies; the direct API is unchanged. Complete reports and hashed cases are archived in the workspace outside disposable outputs.
- New verification / carve_verification reads whole case cards and selected case/metadata JSON text pages with pinned identity, UTF16 offsets and byte receipts. Unknowns/scope/time remain explicit; recorded reads never execute originals or claim current equivalence. There are37 main tools.
- Add tamper/symlink/concurrent-publication and actual CLI/MCP compatibility checks, clean installed reader coverage, and an optional own-payload benchmark over four recorded reports. Measured byte reduction is not token/billing/accuracy evidence or a fresh original comparison. The verifier/writer still materialize full reports in memory.

## 0.18.0 — structured Android inputs and APK contact payload

- Android reference@2 sends full positional JSON through stdin for structured/NUL-containing values, while scalar reference@1 remains supported. Source-owned reflection adapters invoke exact original DEX bytes on ART.
- Multi-artifact contracts accept explicit ancillary boundary-support roles with separate evidence/source identities; primary and implementation artifacts still require complete code. All freshness/confinement checks remain.
- A real shipped ZXing4.7.8 APK supplies a bounded contact-vCard payload function folder, verified for160 original ART cases. QR pixels, discarded display formatting, UI and server behavior remain excluded.

## 0.17.0 — compiled APK manifest evidence

- Engine-free bounded binary Android XML analysis exposes paginated component/intent/permission/feature/node declarations as immutable support evidence. Class aliases/names guide actual DEX investigation; effective OS/resource/UI behavior remains unknown.
- Optional whole shipped APK integration compares all69 elements/100 attributes against AAPT2 and decompiles selected entrypoint classes. Static declarations alone do not establish runtime behavior.

## 0.16.0 — raw CLI references and shipped multi-image case

- Reference@2 accepts exact byte-array/Unicode stdin and explicit finite JSON, UTF8 text or byte-array stdout. Original CLI commands can be compared directly without a JSON-formatting adapter; reference@1 remains supported. Empty/NUL/newline/BOM output is preserved and malformed UTF8/input/extra arguments fail. Existing limits, cancellation, exit handling and fresh evidence/source checks remain.
- Add an optional installed OpenSSL3.6.4 macOS arm64 investigation: real CLI/libcrypto decompilation, callback-table/import/export/loader evidence, actual load log,160 direct CLI cases and an independent reusable Base64 function folder. Reports retain exact status/scope; no complete cryptographic software or large-App recovery is claimed.
- Preserve full large comparison reports on disk while exposing a small local summary after rehashing the complete report. Function-folder imports retain the original report/counters/scope without presenting them as newly verified behavior. Missing/stale summaries stay unreadable; checksums do not independently authenticate counters.

## 0.15.0 — adaptive compact static context

- Context schema@2 shares source/provider dictionaries and page-local callee references. Default auto includes complete recorded pseudocode up to1024 UTF8 bytes when it fits; explicit outline/excerpt views and the code alias remain available. Provider failure/truncation stays separate from text completeness.
- Budgets include dictionaries and every receipt byte. Auto can fall back to a whole outline; explicit excerpts fail if one item cannot fit. Fingerprints bind request scope, inventory and selected content; reuse receipts omit repeated metadata. Explicit IDs retain distinct provider records at one location.
- Add an optional reproducible old/new payload benchmark with named o200k_base token counts over fresh-checked native/DEX evidence. Counts exclude prompts/model output/transport and do not claim actual billing, semantic accuracy or universal savings.

## 0.14.0 — reusable function folders and budgeted context

- Store closed extracted/reconstructed capabilities in local named folders, without standalone CLI files or per-function installation. Library add/find/get and MCP equivalents preserve provenance/domains/unknowns and recorded source-comparison scope; functions can be imported or invoked through existing MCP/runtime tools.
- SQLite catalogue search returns small byte-budgeted metadata cards; get checks pinned manifests/file hashes. Generated SKILL.md remains local and no global agent settings are edited.
- Context queries return observation outlines, bounded recorded static neighbours and optional text excerpts under an exact compact-JSON byte budget. Caller-supplied fingerprints avoid repeated recorded packets; source/evidence freshness and semantic completeness stay explicit. Token estimates are heuristic, not provider/billing measurements.
- User-supplied Trail-Code/Graft source informed structural retrieval/content-reuse principles. No upstream benchmark savings are claimed for Carve, and no external model/hooks/daemon are installed.

## 0.13.0 — Mach-O loader evidence

- CLI loader and MCP carve_loader inspect bounded thin/universal32/64 Mach-O load commands directly, without Ghidra or target execution. Universal inputs require explicit slice selection. Source hashes, parser identity and immutable raw-command observations can support reconstruction contracts.
- Declared dependencies, install names, local rpaths and modern dependency flags are recorded with original file offsets. Bounded lexical paths preserve competing candidates and mark outside-inventory/unknown contexts. Candidate bytes, symbol binding and actual runtime loading remain unverified.
- Actual installed ripgrep/PCRE2 and compiled universal binaries are compared against Apple otool. An owned ambiguous rpath case retains both same-basename libraries and a separate actual load log. Multi-artifact reconstruction binds loader evidence as support while keeping full code/behavior requirements.

## 0.12.0 — native linkage discovery

- Native linkage imports/exports/libraries run in a separate loader-only Ghidra cache without full auto-analysis. Source/kind/exporter-bound cursors and SQLite page coverage preserve bounded continuation. Queue/background requests accept linkage pages.
- CLI links and MCP carve_links page current-inventory metadata or unresolved import-to-export candidates. Exact or explicitly normalized names, architecture/format and basename hints do not establish ABI, loader-path or semantic resolution. Historical evidence stays immutable.
- Owned split-library verification now retains two same-export candidates, binds metadata as support and independently verifies code/runtime behavior. A separate real installed ripgrep/PCRE2 workflow exercises background metadata paging, continuation and candidate discovery without claiming regex reconstruction.

## 0.11.0 — multi-artifact reconstruction evidence

- Version2 reconstruction contracts bind1–32 separately indexed artifacts with complete code/supporting observations, current source identities and explicit relationship claims. Single-artifact version1 remains supported. Every related MCP workspace is confined to the server root.
- Packaging and verification recheck every source/evidence binding; selected artifacts are automatically included in reference byte checks. Secondary source/evidence changes invalidate comparisons. Hypotheses remain unresolved after passing cases; matching names do not automatically resolve dependencies.
- Provenance and independent capability info expose artifact identities and relationship scope. An owned executable/shared-library check uses real Ghidra decompilation of both components, actual dyld load evidence and162 original CLI cases, then removes both binaries and rewrite source before independent CLI/MCP calls.

## 0.10.0 — background analysis batches

- CLI queue start/runs/cancel and three corresponding MCP tools persist bounded background runs, progress, deadlines and result hashes. Work survives normal launcher exit/MCP disconnect; fresh sessions can inspect and request cancellation. Existing active work retains its original options.
- Exact process-identity lease delegation gates startup. Actual launcher SIGKILL before/after delegation, worker death, concurrent starts, suspended-worker cancellation and supervised engine cleanup have dedicated lifecycle tests. Missing or uninspectable workers are never assumed complete.
- Cancellation/deadline reasons are durable; final status is serialized with late cancellation. One queue execution lease per workspace; no global background-engine limit. Tools remain trusted and POSIX-only; this adds no website, service installation or LLM.
- Separate real jq/scrcpy background verification exercises CLI/MCP disconnect, actual analyzing JVM identity, fresh-client cancellation and explicit retry. Static analysis is separate from existing runtime comparison evidence; full-program reconstruction remains unfinished.

## 0.9.0 — durable component analysis jobs and process ownership

- CLI queue add/list/run and three MCP analysis tools persist selected native/DEX/JS requests, configured-provider/source identities, attempts, result hashes and actual process records. Bounded job/attempt pages, idempotent enqueue, explicit retry and stale/unsupported/partial states preserve investigation scope.
- SQLite CAS native-cache/workspace leases inspect owner start identities, supervisors and real engine groups. Guarded startup registers a worker group before allowing execution. An external supervisor repeats cleanup across process-start races and parent disconnect; a surviving orphan blocks recovery. Legacy PID-only analysis locks require explicit inspection.
- Actual process-kill/orphan/concurrent-startup-cancel regressions, plus combined jq native/scrcpy JADX/JS analysis across fresh CLI/MCP sessions. Completed jobs mean bounded static analysis, not full-program reconstruction or behavior equivalence.

## 0.8.0 — disk-backed inventory continuation

- Stream directory listings into a persistent SQLite file queue. Completed listings are reused across hash batches; interrupted listings replay with deduplicated queue entries and committed file checkpoints. Older inventories migrate with metadata-hash reuse.
- Add maxDirectories alongside maxFiles, including CLI/reverse/MCP routing. Directory-only trees can return a bounded batch with zero files. One directory listing finishes as a streaming unit; cancellation can interrupt it. Inventory remains a non-atomic filesystem observation.
- CLI progress uses stderr JSON lines; MCP supports progress tokens and request cancellation. SIGINT/SIGTERM preserve committed scan checkpoints. Existing selected-input fresh hashing still gates downstream analysis.
- Actual process-kill, cancellation, refresh/migration, queue starvation and stdio integration regressions. The 25,002-file synthetic scale check asserts one directory listing across26 batches. This is inventory progress; full-program feature reconstruction remains unfinished.

## 0.7.0 — native registration evidence and durable observations

- Native defined-string substring pages and bounded loaded-memory/reference/pointer/instruction windows through CLI/MCP. Data-only string references remain visible; traces can enter containing indexed windows using unsigned SQLite address keys without Number precision loss. Raw pointer proximity remains unconfirmed semantic evidence.
- Real stripped jq-1.8.2 macOS arm64 release: investigate the builtin registration table, decompile the selected function and length helper, reconstruct a Unicode-string/UTF8-byte-count contract and compare160 original CLI cases. Independent CLI/invoke/MCP work without the original invocation path.
- Separate Ghidra completed-analysis cache identity from export-script identity. Export changes can reuse the completed project; actual old/new exporter reuse was verified. Observation results return bounded exact IDs and link summaries; long text still requires response pagination.
- Native/JADX observations preserve immutable evidence: changed records/generated bytes get distinct IDs, while identical native records retain their first provenance. Later queries must not invalidate packaged evidence.
- Reconstruction contracts support separate supportingEvidenceIds for string/table boundary records while retaining mandatory complete implementation-code evidence. Missing dependencies and unverified behavior remain explicit; full software recovery is unfinished.

## 0.6.0 — Android runtime reference and real third-party case

- `verify-reconstruction` and its MCP tool accept `carve/android-reference@1`: explicit ADB serial/server, exact selected DEX/archive and harness snapshots, remote SHA256 checks, Android/VM identity, remote execution deadlines, quoted argv, cleanup and cancellation. Command/JVM comparisons retain their separate scope.
- Genuine scrcpy v5.0.1 released Android server: reconstruct the software-only size-constraint branch and compare 160 cases on Android 15 ARM64 ART. The reference invokes original shipped DEX methods without rebuilding their implementation. Hardware codec constraints, UI/server and other-device behavior remain excluded.
- JADX auto/simple/fallback output modes retain distinct provider/version/mode evidence. Raw instruction output helps resolve high-level decompiler control-flow ambiguity. Whole-file decompilation errors remain failures; selected successful scopes do not imply full-app recovery.
- Reconstructed package usage and capability_info expose domains/unknowns and manifest-bound recorded comparison examples, including their verification scope and timestamp.
- Optional actual Android protocol checks exercise remote shell quoting, stderr, nonzero exits, output limits, deadlines and cleanup. Existing native/JS engines remain available; the complete broad reconstruction goal is still unfinished.

## 0.5.0 — experimental native/mobile reconstruction

- General `reverse` task entry, streaming format/SHA256 inventory, SQLite directory checkpoints and paginated queries for large inputs. Old JS extraction limits are scoped to that backend.
- Real Ghidra function/string/call evidence and selected-function decompilation with completed-project cache reuse; real JADX DEX/Java analysis with bounded indexed source previews. Engine logs, failures, hashes and truncation remain visible. CLI and eleven new MCP tools; engine paths configured explicitly at server startup.
- Resumable ZIP/APK/IPA/JAR-family member extraction with CRC32/SHA256, explicit byte/count budgets, unsafe-path/symlink/encryption rejection and container/member provenance.
- Evidence-bound agent reimplementation packaging with `behavior-reconstruction` provenance, original-binary vs implementation inputs, declared dependencies and unknowns.
- Scoped executable-reference comparisons: original target CLI or explicitly disclosed external harness, JSON argv/stdin protocols, bounded output/deadlines, hashed reference files and independent candidate snapshots. Harness errors cannot pass as equivalent behavior.
- Reproducible own-source stripped Mach-O / DEX integration and synthetic 25,002-file resumable inventory check. Native cases execute the actual original CLI; mobile cases compare a source-equivalent JVM harness and do not claim Android runtime verification.
- Existing JavaScript backend, independent output CLI/MCP and REA integration remain available. Arbitrary software reconstruction, missing server logic, cross-binary closure and broad mobile/device automation remain unfinished.

## 0.4.0 — local alpha

- App-path artifact location and task setup: `locate`, `start`, `carve_locate`, `carve_start`. Unknown expectations stay unknown; ambiguous/incomplete artifact scans are explicit.
- Standalone output CLI supports help without loading code, exact raw text and exclusive output files.
- `invoke`/`carve_invoke` and `serve-tool` execute integrity-checked extracted capabilities without the original app. Actual stdio capability tools use fresh processes, bounded input/output, deadlines and cancellation.
- Shared package validation rejects changed files and symlinks before use; runtime snapshots are checked again after copying.

## 0.3.0 — local alpha

- `carve contrast` and `carve_contrast` turn ambiguous passing candidates into concrete input/output questions. Deterministic boundary probes or explicit inputs produce candidate observations; expected product behavior stays unknown until confirmed or observed.
- CommonJS literal dependency graphs, JSON requires, directory package mains, import/require export conditions, circular requires and admitted native builtin bridges are bundled into independent output.
- Closed statically exported CommonJS declarations can omit unrelated application imports. Other CommonJS modules are retained whole, with explicit manifest retention and runtime-export warnings.
- Minified CommonJS bundles can be extracted from ASAR using a known public export. Nested factory discovery and module-minimal slicing inside arbitrary bundles remain outside scope.
- Eight stdio MCP tools, a complete ambiguity-to-observation demo, seven pinned public-package regressions, and one-command local release checks.

## 0.2.0 — local alpha

- Observable feature specifications, lexical discovery, candidate probing and complete feature extraction through CLI/MCP/skill.
- Cross-module ESM slicing, JSON data, initialization closure, source/REA evidence binding, provenance, notices and independent runtime verification.
