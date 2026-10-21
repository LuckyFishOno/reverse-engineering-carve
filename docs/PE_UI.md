# PE UI resource and command-handler evidence

`carve pe-ui` and the independent RECarve MCP tool `carve_pe_ui` connect original Windows PE UI declarations to numeric commands and candidate callbacks. They do not execute the target or launch/proxy REA. The LLM can inspect a candidate address using the separate REA MCP and retain complete code with RECarve's existing native-evidence tools.

## Workflow

```sh
node dist/cli.js survey ./program.exe --workspace ./ui-work
node dist/cli.js pe-ui ./ui-work --file program.exe
node dist/cli.js pe-ui ./ui-work --file program.exe --view nodes --query folder
node dist/cli.js pe-ui ./ui-work --file program.exe --view boundary --command 1001
node dist/cli.js pe-ui ./ui-work --file program.exe --view edges --command 1001
node dist/cli.js pe-ui ./ui-work --file program.exe --view issues
```

Replace1001 with an actual command found in the nodes view. Command IDs are scoped to the selected image, not globally unique feature names. A command may occur in several menus/dialogs and match several notification codes or table rows. These alternatives remain visible.

MCP request to `carve_pe_ui`:

```json
{"workspace":"ui-work","file":"program.exe","view":"boundary","command":1001,"limit":20,"budgetBytes":8192}
```

Views:

| View | Contents |
| --- | --- |
| summary | Source/provider hashes, counts, issue count, evidence path and limitations |
| nodes | Resources, items, controls, strings, accelerators, commands, import modules and callback/table candidates |
| edges | Resource containment, command declarations and candidate dispatch/pointer relationships |
| boundary | One command's declarations, containing ancestors, table rows and callbacks; each node includes up to8 selected incident edges, their total and an explicit truncation flag |
| dependencies | Bounded recorded call dependencies from a selected entry; original IAT instruction witnesses and selected DLL export candidates stay separate from runtime loading |
| entries | One command's handler candidates bound to explicitly selected, revalidated imported REA function observations; static entry matching never confirms UI dispatch |
| issues | Malformed/unsupported selected resource-template diagnostics, retaining resource identity |

Use `query` for a literal case-insensitive node-label filter and `command` to select one numeric command. Summary has no filters; boundary/entries/dependencies require a command; issues accepts neither filter. Edge filtering requires both endpoints in the selected node set. Page using nextOffset until null and require the same observationId across pages. Each request freshly rehashes source bytes, so changed sources require an inventory refresh. Budgets measure actual compact UTF8 JSON bytes; the heuristic token estimate is not billing. Text fields longer than512 Unicode scalars are explicit previews: previewFields identifies them and fullValuesInEvidence points to the complete immutable graph. Boundary nodes preview at most8 incident edges with edgesTotal/edgesTruncated; use the edges view for all selected edges. Large cards may require a larger budget, up to65536 bytes.

## Evidence strength

| Relationship | What it establishes |
| --- | --- |
| image → resource → menu item/control | Original PE directory/template declarations and exact file offsets |
| item/control/accelerator → command | A numeric ID encoded in that resource |
| command → dispatch-row candidate | An AFX-like WM_COMMAND byte pattern whose ID/range includes that command |
| dispatch row → handler candidate | A pointer field targets an unambiguously mapped executable section RVA |
| image → imported module | An artifact-level PE import declaration; no callback attribution or runtime loading proof |

Rows retain source offsets, preferred-image RVA/VA, complete row bytes, notification codes, signatures and selected pointer-layout assumptions. A handler address is **not a verified function entry**. Class/message-map ownership is not established. String-table IDs remain separate from commands even when numbers happen to match. UI data and this graph are boundary support, not complete implementation code or behavior verification.

The complete graph is published atomically under ui-evidence with source and parser hashes. Existing evidence is never overwritten. Its observation is indexed for `carve_search`/`carve_context`; use compact node/boundary views before requesting complete records. Windows controls created only at runtime may have no dialog declaration. UI labels alone do not establish search behavior, persistence, drag/drop, keyboard semantics or dependency closure.

## Supported layouts and bounds

- PE32/PE32+ named/numeric resource paths with standard or extended menus/dialogs, string tables and accelerator tables. Malformed individual templates become explicit issues with no partially parsed resource nodes. Invalid directory trees/ranges and aggregate budget exhaustion fail the operation.
- AFX-like x86 24-byte and x64 32-byte WM_COMMAND rows in file-backed non-executable sections. Signature, ID range and executable pointer checks reduce false positives but do not remove them. Other machines retain resource evidence and report unsupported handler scanning.
- No WM_NOTIFY owner inference, dynamic UI reconstruction, encoded/member-pointer variants, non-MFC dispatch recognition, settings-path access proof or automatic feature recovery. The base resource graph has no callback-to-DLL attribution; dependencies view adds only selected byte-bound static import/export candidates. Existing PE dependency and REA tools remain separate investigation steps.
- Resource directory and individual payload limit16MiB; cumulative selected payload and message-map scanning each64MiB;50000 directory entries/nodes,100000 edges,10000 candidate rows,32 menu levels and8192 UTF16 code units per string. No target execution or external paths are read from resource labels.

MCP confines the workspace, inventory, SQLite sidecars and evidence directory to its root. Source files are read-only. Candidate DLL names are not opened or loaded.

## Validation

Source-owned fixtures exercise x86/x64, standard/extended templates, named/localized resources, Unicode, notification ambiguity, exact bytes, malformed templates, cycles, invalid pointers, unsupported architectures, immutable evidence, source freshness, search/indexing, CLI/MCP parity, bounded paging and root confinement. Clean-tarball installation also exercises the installed CLI and a fresh MCP server.

Format references: [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [MENUITEMTEMPLATE](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplate), [MENUEX_TEMPLATE_ITEM](https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-template-item), [DLGTEMPLATEEX](https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex), [DLGITEMTEMPLATEEX](https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex).

## Bind imported REA function entries

After reading a command boundary, ask the separate REA MCP to inspect each candidate's exact address in the same PE image. Retain complete `procedure_pseudo_code` and `procedure_info` Evidence JSON; optionally retain outgoing callees/references. Import those records with `carve import-rea-native` (see [native evidence handoff](REA_NATIVE.md)). Use the returned observation IDs explicitly:

```sh
node dist/cli.js pe-ui ./ui-work --file program.exe --view entries --command 1001 \
  --function-ids OBSERVATION_ID
```

MCP uses the same view and a `functionIds` array. Supply up to16unique64hex observation IDs; omit the array to inspect candidates with no selected function evidence. Selection is explicit and never silently chooses an analysis profile. `entries` requires `command` and refuses `query`; `functionIds` is accepted in entries and dependencies views.

| Status | Meaning |
| --- | --- |
| static-entry-matched | One selected imported REA record has exactly the candidate's preferred-image virtual entry address |
| ambiguous-function-evidence | Several selected records match; all profiles/snapshot identities remain visible |
| candidate-only | No supplied function record matches this candidate; other unselected evidence may exist |
| missing-handler-candidate | The UI command exists but has no supported candidate callback |
| missing-ui-command | The requested command is absent from the supported UI graph |

Each selected function snapshot is revalidated against its canonical imported observation, current input bytes, complete code/body records and optional relationships. Reject mismatched artifacts, stale sources, changed snapshots/SQL metadata, redirected snapshot storage and a cumulative snapshot read above64MiB. Source bytes are rehashed again before publication. Normalized address comparison does not infer rebasing, containing functions, thunk destinations or semantic equivalence.

The response retains function observation IDs, snapshot/profile hashes, original producer Evidence IDs and relationship incompleteness. It omits code bodies. `bindingId` is the SHA256 of the immutable `bindingEvidence` report under ui-evidence/; the report pins the UI graph and selected functions. Ordering the same function IDs differently does not change this identity. Page entries using nextOffset while retaining the same bindingId. Dispatch previews contain at most8rows with total/truncation markers; full rows are in the report.

A matched entry is self-reported static evidence, not producer authentication, observed dispatch or restored behavior. `dispatchConfirmed` stays false; ownership, notification selection, semantics and dependency closure remain unverified. Preserve the competing UI sources and investigate actual dispatch separately. This step never starts REA or executes the original program.

## Inspect selected call dependencies

Use the same command and explicit entry `functionIds`, then supply helper/DLL function observations with `dependencyIds`. All selected functions must already be imported from the separate REA MCP into the same workspace; no file discovery or REA launch occurs here. For a multi-image case, survey a source directory containing both images so their function observations share one workspace.

```sh
node dist/cli.js pe-ui ./ui-work --file program.exe --view dependencies --command 1001 \
  --function-ids ENTRY_OBSERVATION_ID \
  --dependency-ids HELPER_OBSERVATION_ID DLL_OBSERVATION_ID \
  --dependency-depth 3
```

MCP `carve_pe_ui` accepts `view: "dependencies"`, `functionIds`, `dependencyIds` and optional `dependencyDepth`. Up to16entry observations plus32dependency observations,16source images and64MiB of captured snapshots may be selected. Expansion depth defaults to3and ranges from0to8; the matched entry is depth0. Explicitly selected but unreachable records are still validated. Other views refuse dependency-only options.

| Row/status | Meaning |
| --- | --- |
| ui-entry | The same entry status and dispatch uncertainty as entries view; ambiguous/unmatched entries do not start traversal |
| function-coverage | Imported relationship coverage, unresolved/provider limitations, non-call reference count, inspected typed state references and explicit unanalysed resource semantics |
| data-reference | Imported source/target/access metadata, target section permissions, bounded initial file bytes and conservative data/state candidates |
| internal-code-match | A recorded callee matches selected complete function code in the same image and analysis profile |
| missing-function-code | No compatible selected function body matches the recorded callee |
| ambiguous-function-evidence | Multiple compatible selected observations match; no observation is silently chosen |
| dll-export-candidate | An imported typed call location decodes to an original IAT call and exactly one selected compatible DLL export/function entry matches |
| ambiguous-dll-export | Several selected DLL/function alternatives match; none is traversed automatically |
| import-target-unresolved | The import call has a byte witness but no unique compatible selected definition; forwarded exports remain explicit alternatives |
| unresolved-call | A recorded unresolved/computed call; it does not become a guessed target |

Recorded callee-inventory leads without typed call sites remain `callee-inventory-only`; they do not supply import instruction witnesses. Import decoding is limited to the supported x86/x64 indirect call and direct-call-to-import-jump-thunk forms. The full call instruction must fit within the imported caller body, and its IAT slot must have one unambiguous import declaration. Export matching uses the explicit selected image basename, matching PE machine/DLL flags, exact case-sensitive export name or ordinal and an executable export RVA equal to the selected function entry. Source and DLL preferred image bases are handled independently. Cross-image analyses must use the same underlying provider; each image keeps its own profile. Internal edges never mix profiles. Forwarders, API-set routing, dynamic loads and runtime loader search remain unresolved.

A single matching DLL export is a **static candidate**, never proof that Windows loaded that file. Expansion may inspect its explicitly selected static function record, with `runtimeLoading: "unverified"` and `dependencyClosure: "not-established"`. Cycles stop at visited observations; depth limits remain explicit. State/resource/OS dependencies and unselected code do not disappear when all displayed function edges match.

Every selected source and captured snapshot is checked; sources are rehashed before publication, and MCP authorizes additional selected paths before reads. The immutable `dependencyEvidence` report pins source/function/profile/snapshot identities and original call bytes. `dependencyId` is its SHA256 and must remain stable while paging. Counts summarize the emitted rows, not complete program coverage. Reports cap5000rows and expose `rowLimitReached`; response previews cap nested arrays at8and strings at512Unicode scalars, with previewFields and complete data retained in the report. No code bodies are returned.

The matching tests use synthetic source-owned PE/REA commitment fixtures with real import/call/export bytes. They validate binding rules, not original Windows UI execution or arbitrary application equivalence.

Dependency rows include `nextSteps` for missing entry/callee code, ambiguous evidence, unresolved imports/calls, incomplete relationship coverage, recorded data references and unexpanded depth boundaries. Each task identifies available source addresses or import names/ordinals; `counts.byNextAction` summarizes tasks across the report, independently of the current page. Depth tasks exclude targets already visited through another path. Tasks guide manual investigation through the separate REA process; they do not execute tools, resolve loader behavior or establish dependency closure. An empty task list does not prove that state, resources, runtime loading or UI behavior were verified. Row limits and response preview limits still apply.

## Executable comparison example

The optional [owned PE behavior integration](PE_BEHAVIOR.md) exercises these views with actual independent REA records, original PE/DLL instruction execution in a declared Unicorn harness, multi-artifact reconstruction,160comparisons and independent library reuse. It never labels emulator results as Windows/UI execution.

[Data references and the state example](PE_DATA.md) document bounded source-byte/string/scalar evidence, explicit mutable/unknown states, and an original/candidate session comparison using a readonly settings table and writable counter.

## Non-UI function roots

For a DLL export or another reviewed function without a UI command, the dependencies
view accepts `entryMode: "selected-functions"` and 1–16 explicit `functionIds`.
Omit `command`. CLI uses `--entry-mode selected-functions --function-ids <ids...>`.
All roots must belong to the selected current indexed PE file. Optional
`dependencyIds` retain the same profile/source/byte-bound call rules and depth,
page, row, authorization and freshness limits as UI-derived traversal.

The report emits `function-entry` rows with `selected-function` status and keeps
`dispatchConfirmed: false`. The mode is part of immutable report identity and does
not claim an export match, runtime reachability or semantic closure. The default
`ui-command` mode still requires a command and never silently falls back to selected
functions. See [the third-party version case](PE_VERSION.md) for a real DLL example.
