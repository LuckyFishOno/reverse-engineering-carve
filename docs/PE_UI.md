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
| issues | Malformed/unsupported selected resource-template diagnostics, retaining resource identity |

Use `query` for a literal case-insensitive node-label filter and `command` to select one numeric command. Summary has no filters; boundary requires a command; issues accepts neither filter. Edge filtering requires both endpoints in the selected node set. Page using nextOffset until null and require the same observationId across pages. Each request freshly rehashes source bytes, so changed sources require an inventory refresh. Budgets measure actual compact UTF8 JSON bytes; the heuristic token estimate is not billing. Text fields longer than512 Unicode scalars are explicit previews: previewFields identifies them and fullValuesInEvidence points to the complete immutable graph. Boundary nodes preview at most8 incident edges with edgesTotal/edgesTruncated; use the edges view for all selected edges. Large cards may require a larger budget, up to65536 bytes.

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
- No WM_NOTIFY owner inference, dynamic UI reconstruction, encoded/member-pointer variants, non-MFC dispatch recognition, callback-to-DLL attribution, settings-path access proof or automatic feature recovery. Existing PE dependency and REA tools remain separate investigation steps.
- Resource directory and individual payload limit16MiB; cumulative selected payload and message-map scanning each64MiB;50000 directory entries/nodes,100000 edges,10000 candidate rows,32 menu levels and8192 UTF16 code units per string. No target execution or external paths are read from resource labels.

MCP confines the workspace, inventory, SQLite sidecars and evidence directory to its root. Source files are read-only. Candidate DLL names are not opened or loaded.

## Validation

Source-owned fixtures exercise x86/x64, standard/extended templates, named/localized resources, Unicode, notification ambiguity, exact bytes, malformed templates, cycles, invalid pointers, unsupported architectures, immutable evidence, source freshness, search/indexing, CLI/MCP parity, bounded paging and root confinement. Clean-tarball installation also exercises the installed CLI and a fresh MCP server.

Format references: [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [MENUITEMTEMPLATE](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-menuitemtemplate), [MENUEX_TEMPLATE_ITEM](https://learn.microsoft.com/en-us/windows/win32/menurc/menuex-template-item), [DLGTEMPLATEEX](https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgtemplateex), [DLGITEMTEMPLATEEX](https://learn.microsoft.com/en-us/windows/win32/dlgbox/dlgitemtemplateex).
