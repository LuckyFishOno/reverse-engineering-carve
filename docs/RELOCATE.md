# Moving a workspace

A RECarve workspace records absolute paths: the surveyed target, the lineage of unpacked container content, and the evidence file behind every observation. After you move a project folder, run `relocate` on each workspace before using it again.

```sh
carve relocate ./work
```

Since 0.24, RECarve detects a moved workspace. `survey`, `reverse` and every analysis that selects an indexed file stop with `Workspace was moved from OLD to NEW. Run "carve relocate NEW" first`. This happens before any new evidence is written next to records that still name the old location.

## What relocation does

1. It finds the previous location. Workspaces record it since 0.24. Older ones are read from `survey.json`. If neither is right, pass `--from OLD_ABSOLUTE_PATH`.
2. It finds the target. If the recorded target still exists, it is kept. Otherwise RECarve looks at the same position relative to the moved workspace, for example `../input` when both lived in one project folder. If the target moved somewhere else, pass `--target NEW_PATH`.
3. It checks the target before changing anything. Every indexed file must exist with its recorded size, and a file target is rehashed. Selected files are still rehashed before each analysis, as before.
4. It checks container lineage. An inventory of unpacked APK/IPA/ZIP content needs the container workspace that unpacked it to be relocated first. The error names the lineage marker that still points at the old location.
5. It rewrites evidence paths only after hashing every evidence file at its new location against the recorded `evidence_sha256`. Evidence that is not under the previous location must still exist where it was recorded; otherwise relocation stops and asks for `--from`.
6. In one SQLite transaction it updates the target, root, workspace location, container lineage and evidence paths, and adds a `relocate` event. It then rewrites `.carve-workspace.json` and this workspace's own container cache markers.

Validation failures leave the live target/evidence bindings unchanged. SQLite commits before the JSON marker files are replaced; an I/O failure or process interruption after that commit may require rerunning relocation to repair markers. Running `relocate` again is safe: a workspace already in place reports `moved: false` and only repairs markers that do not match its index.

## Order for unpacked containers

```sh
carve relocate ./container-work   # the workspace that ran unpack
carve relocate ./work             # the inventory of the unpacked content
```

## MCP for agents

Since0.25 the main server exposes `carve_relocate` without native/Android engines:

```json
{"workspace":"moved-project/work"}
```

If the target moved separately or an old survey recorded the wrong prior location:

```json
{"workspace":"moved-project/work","target":"new-input","from":"/previous/project/work"}
```

`workspace` and optional `target` are relative to the MCP server root, or absolute paths inside it. `from` must be the previous absolute workspace path; it is a string used for path mapping and is never opened, so it may name an old location outside the current root. The automatic target must also be inside the server root. If the old target still exists elsewhere, explicitly select its new in-root location instead.

The tool checks live target, evidence, SQLite, lineage and marker destinations against the server root before updating bindings. Symlink escapes are refused. It can repair a workspace whose old marker target is outside the new root; the normal analysis-workspace guard is applied again by subsequent inspection calls. A validation refusal does not change target/evidence bindings. Root checks are not a malicious-code sandbox or an atomic snapshot against concurrent filesystem changes.

Relocate a container workspace before its unpacked inventory, using one MCP call for each. Relocation rewrites records and markers; it does not move/delete input files, re-execute programs or establish new behavior equivalence. The direct API remains `relocateWorkspace`; host integrations may supply its optional `authorizePath` callback to enforce their own path boundary. CLI behavior is unchanged.

## What is not rewritten

Historical queue results, run logs, task reports, engine logs and verification archives keep the paths recorded at the time. Verification archives are content-addressed and resolve their files relative to their own folder, so they keep working. Observation IDs and evidence files are never edited.

Relocation refuses to run while queued or background analysis is running in the workspace.

Ghidra project caches are path-independent: a relocated workspace reuses its completed auto-analysis. This was checked with the real jq-1.8.2 workspace, where a function export after relocation reported `reusedAnalysis: true` without re-analysis.
