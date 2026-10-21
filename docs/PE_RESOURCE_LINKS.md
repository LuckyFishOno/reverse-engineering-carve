# Direct PE resource references

The dependencies view of `pe-ui` / `carve_pe_ui` associates selected imported typed data references with successfully parsed PE menu, dialog, string-table and accelerator payloads. A target must have captured original file bytes and lie inside a parsed payload RVA range. Numeric resource IDs, matching UI command numbers or imported resource API names alone never establish a link.

Each data row's `resourceAssociation` reports:

| Status | Meaning |
| --- | --- |
| inside-parsed-resource-payload | One parsed payload contains the target |
| ambiguous-resource-payload | Several parsed paths contain it; no language/path is silently selected |
| no-parsed-payload-match | No supported successfully parsed payload contains it; this does not exclude other resources |
| unresolved-reference | The underlying data location lacks a valid captured file-byte mapping |

Matches retain resource ID/path, complete payload SHA256, file offset, RVA, byte size and target offset within the payload. At most8matches are returned, with exact matchesTotal/matchesTruncated fields. Report-level `counts.byResourceStatus` summarizes association statuses independently of paging. Full immutable dependency evidence includes per-image `resourceCatalogs`, selected source hashes, parsed resource metadata and parsing issues. Catalogs are cached per visited image; the existing resource/parser/source/response bounds apply. The row previews retain existing explicit truncation flags.

This is static containment, not an executed resource lookup. `runtimeUse:unverified` and `dependencyClosure:not-established` remain. General API argument/data-flow tracking, complete numeric-ID resolution, Windows language fallback, MUI/external resource modules, unsupported resource types, malformed templates, dynamic creation and semantic UI usage remain unresolved. A shared payload may represent several language paths. Resource hash equality does not establish which path Windows chooses.

[Bounded resource API leads](PE_RESOURCE_API.md) separately recover a limited subset of x86/x64 numeric parameters at byte-bound import calls. They list caller-image candidates while keeping module/language/runtime binding unverified; they never become direct payload references automatically.

## Pin a reviewed resource in reconstruction

A version2 artifact's [data binding](RECONSTRUCTION_DATA.md) may optionally declare `resource` with:

- `path`: exact three-element type/name/language array, preserving number versus string keys.
- `payloadSha256`: SHA256 of the complete original parsed payload, not only the selected byte prefix.

The binder re-parses current source resources and requires exactly one payload containing the exact imported data target, with matching path and payload hash. Any selected byte prefix must stay entirely inside that payload. The usual data handling/section/write restrictions still apply. An unmatched language, modified hash, ambiguous payload or crossing prefix is rejected before packaging. Rebound provenance retains the association; legacy bindings without resource stay unchanged. Review declarations never become runtime/immutability/implementation-use proofs.

## Owned original-machine-code example

`npm run verify:pe-state` now compiles a real readonly RT_STRING array into the owned PE. Its existing string-table directory entry points at that array as `[6,63,1033]`; string1001is `ready`. The owned function reads UTF-16 code units from the actual payload. Independent REA captures those data references; RECarve links them to the parsed payload and packages a fourth explicit data binding with the complete42byte resource hash.

The declared Unicorn harness separately observes original memory reads inside the payload. Original/candidate40sequences/926steps cover the prior settings/state behavior and resource characters. Modified resource bytes invalidate acceptance. With the original PE temporarily unavailable, fresh library-only MCP invocation and direct module import still return resource-derived character values. The implementation contains reviewed reconstructed content; it does not fetch the original file at runtime.

Prerequisites and commands remain those in [the PE state example](PE_DATA.md). This is an owned finite harness demonstration, not generic Windows resource API resolution, Windows/UI execution or arbitrary application equivalence.
