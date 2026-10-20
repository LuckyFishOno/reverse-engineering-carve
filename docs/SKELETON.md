# Swift project snapshots and wiring

RECarve can generate a macOS SwiftPM CLI, module or desktop-app shell from a current project plan and work specification. Feature-to-feature dependencies become Swift targets, with shared request/response types and a registry. Unimplemented features remain explicit stubs. The new CLI/MCP entry points expose the existing skeleton core and add pinned implementation, package, linker and resource wiring.

## Basic workflow

```sh
carve skeleton create ./plan.json ./work-spec.json --out ./snapshot
carve skeleton inspect ./snapshot --limit 8
carve skeleton check ./snapshot --plan ./plan.json --spec ./work-spec.json --execute --test
```

The MCP tool is `carve_skeleton` with `create`, `inspect` and `check` actions. Create needs current plan/spec and a new output directory. Inspect pages recorded feature metadata without building or checking current source integrity. Check needs the current plan/spec, directory and `execute:true`; it compiles and runs trusted Swift manifests, dependencies and feature code with host permissions. This is not a security sandbox. Remote package resolution may access the network only during an explicitly authorized build, not during creation.

Supported generation targets remain `macos/desktop-app`, `macos/cli` and `macos/module`. This does not add Windows, browser, mobile or arbitrary Xcode project generation. The desktop output is a SwiftPM application shell, not a signed/distributed `.app`. The CLI/module targets also retain the existing small string-payload interface; richer native interfaces require deliberate design.

## Preserve existing implementations and resources

```sh
carve skeleton create ./plan.json ./work-spec.json --out ./next-snapshot \
  --wiring ./wiring.json --source-root ./implementation
```

The optional wiring document uses `carve/skeleton-wiring@1`, exact `planId` and normalized work `specId`. Obtain those IDs from a work package made with the same plan/spec. Fields are:

| Field | Contents |
| --- | --- |
| `files` | Assigned implementation/resource `{path,sha256}` inputs relative to source root |
| `resources` | `{feature,path,rule}` entries; `rule` is `copy` or `process` |
| `packages` | Local vendored or remote revision-pinned packages and product-to-feature mappings |
| `links` | Feature-specific framework/library names |

Assignments still own one `Sources/<dir>/` and optionally one `Tests/<dir>/` per feature. Swift source/test paths retain their usual layout. Non-Swift assigned resources must live under `Sources/<dir>/Resources/`, with matching pins and rules. Resource entries are files, not unbounded directory copies. `.process` preserves supported SwiftPM localization/resource processing; `.copy` preserves opaque bytes. The generated manifest sets `defaultLocalization:"en"` when resources are declared. Use explicit `.lproj` paths and review the resulting language behavior. Feature implementations can use `Bundle.module` when their target declares resources.

Example resource and linker entries:

```json
{
  "resources":[
    {"feature":"core","path":"Sources/core/Resources/greeting.txt","rule":"process"},
    {"feature":"core","path":"Sources/core/Resources/en.lproj/Localizable.strings","rule":"process"},
    {"feature":"core","path":"Sources/core/Resources/opaque.bin","rule":"copy"}
  ],
  "links":[{"feature":"core","frameworks":["Foundation"],"libraries":["z"]}]
}
```

This fragment must be combined with schema/plan/spec IDs and actual `files` hashes. RECarve validates ownership and hashes; it does not infer missing resource dependencies from arbitrary source code. Source files absent from `files` receive stubs or placeholders. Copied files retain their exact bytes; RECarve does not rewrite imports or automatically adapt their APIs.

## External packages

A local package declares `kind:"local"`, a lowercase `id`, pinned `files` (including `Package.swift`) and `products`. Its input files live under `sourceRoot/Vendor/<id>/`; only listed files are copied into the new snapshot. A product is `{name:"Helpers",features:["core"]}`. RECarve generates the local package declaration and target `.product` dependency. Include all sources, manifests and resources required by the vendored package; transitive package resolution is not automatically closed or authenticated.

A remote package declares `kind:"remote"`, an HTTPS `url`, exact lowercase 40-hex Git `revision`, `id` and `products`. Branch names and version ranges are refused. Creation only writes the declaration. Build resolution, platform compatibility, transitive dependencies, credentials and package licensing remain separate concerns; a commit pin alone does not prove trust or behavior. Framework/library links are declared settings, not proof the host provides those APIs.

## Regeneration, ownership and checks

Update the plan/spec or wiring pins, then generate a **new snapshot**. Existing output directories are refused. Keep the implementation folder as the input source, or explicitly pin desired assigned files from an earlier snapshot. RECarve does not overwrite a working project or silently merge shell edits. Generated `Package.swift`, registry/shared shell and vendored package inputs remain generator-owned; changes require regeneration. Assigned source/resources remain feature-owned and can be edited for the next build.

`carve-skeleton.json` records generated file hashes/owners, plan/spec IDs, wiring and input pins. Check refuses altered generator-owned files, unsafe paths and symlink redirects. Its report distinguishes copied-input baselines from generated stubs. New wiring/schema errors fail before output creation. Copying is bounded to512inputs,8MiB/file and64MiB total; wiring JSON is at most1MiB. Interrupted creation retains owned partial files. Check logs are bounded and commands have configurable50–900000ms deadlines. Build tools retain host access; this is not a build reproducibility or OS resource sandbox.

Budgeted CLI/MCP responses page feature metadata and reference full on-disk build reports. `implemented-ok` means a feature returned without error. Build success, unit success, a resource lookup and dependency flow do not establish equivalence to an original program. Use [work acceptance](WORK_ACCEPTANCE.md) for explicit behavior assertions/comparisons and retain [claim provenance](PROVENANCE.md). No REA server merge, automatic work-ledger acceptance, code synthesis or full-application port is claimed.
