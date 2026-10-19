# Pinned interfaces and agent work packages

`work-package` turns an agent-declared feature graph into local handoff folders containing the selected task, complete direct dependency interfaces, target, assigned files, acceptance criteria, source leads and unknowns. Existing agents perform the work; Carve does not dispatch agents or implement features.

```sh
node dist/cli.js project-plan examples/work-plan.json --limit 4
node dist/cli.js work-package create examples/work-plan.json examples/work-spec.json --feature parser --out ./parser-task
node dist/cli.js work-package read ./parser-task --view dependencies
node dist/cli.js work-package check ./parser-task --plan examples/work-plan.json --spec examples/work-spec.json
```

The output folder must be new with an existing parent. It contains TASK.md, work.json (`carve/work-package@1`) and manifest.json (sizes/SHA256 of both). The [complete plan](../examples/work-plan.json) and [spec](../examples/work-spec.json) are synthetic declarations, not recovered code or a runnable App. The [other plan](../examples/project-plan.json) deliberately contains incomplete interfaces.

## Work specification

Author [project-plan@1](PROJECT_PLAN.md) first. Selected tasks and every direct dependency require nonblank contract input/output/state/errors (<=2000 characters each). State stateless/no-errors explicitly. Cyclic or cycle-blocked tasks are refused; ready means sortable, not implemented.

A `carve/work-spec@1` object contains planId and assignments. Each assignment has feature, taskId, explicit relative files, acceptance entries (`name`, `criterion`), and optional sourceContext entries (`workspace`, `file`, `sourceSha256`, `evidenceIds`). Obtain actual planId/taskId from current project-plan pages and keep planId consistent across pages. Source context is at most16 unopened, unauthenticated leads, not complete REA evidence.

Limits: 500 assignments, 1 MiB JSON, 4000 total files; each assignment <=64 files and32 uniquely named acceptance entries. Directory/glob ownership is not supported. Absolute paths, traversal, backslashes, Windows reserved names, trailing spaces/dots, case/Unicode aliases and file/descendant conflicts are refused. Every supplied assignment is checked. Omitted features appear in unassignedFeatures. Ownership is a collaboration instruction, not an OS sandbox or persistent claim. Acceptance criteria are pending declarations; no compilation, tests, ABI or semantic verification occurs.

## MCP

`carve_work_package` remains separate from REA:

| action | Required fields | Behavior |
| --- | --- | --- |
| create | plan, spec, feature, out | Read declarations and create a verified new folder |
| read | package | Read immutable historical content |
| check | package, plan, spec | Also reject disagreement with supplied current declarations |

Paths are confined to MCP root. Source-context files are not opened. Because create writes, readOnlyHint is false.

```json
{"action":"create","plan":"plan.json","spec":"spec.json","feature":"parser","out":"tasks/parser","budgetBytes":4096}
```

Before editing, check the package and read all record pages with matching id/planId/specId. Implement only assigned files, obtain actual dependency outputs and perform acceptance checks. [Work ledger](WORK_LEDGER.md) records persistent claims and submissions; submission is not acceptance or automatic integration.

## Pagination and integrity

Views: summary (assigned files), dependencies (interface hash cards), acceptance (pending criteria), record (complete JSON text). Budget1024–65536 is actual compact UTF-8 JSON excluding stdio framing. List views use offset/limit1–100; record uses UTF-16 offsets/characters1–12000 without splitting surrogate pairs. Follow nextOffset until null. Raise an insufficient budget rather than dropping content.

planId pins the whole plan; taskId pins the feature/direct interfaces; specId pins the whole spec. Any declaration change requires newly calculated IDs/new folders, even when another task changed. Read returns currentPlanCheck:not-performed; create/check can report matched-supplied-plan-and-spec. Hashes establish content consistency, not authenticity.

Creation validates inputs/budget before exclusive folder creation, then publishes a non-overwriting manifest. Interruption may leave partial files for inspection; missing-manifest folders are not ready and are not overwritten automatically. Reads refuse symlinks, oversized files, hash/format mismatches and rewritten handoff text. This is not a malware sandbox.

`npm run verify:work-package` checks four synthetic packages, shared pins, fresh MCP continuation, stale/conflicting declarations and measured output bytes. It does not dispatch agents or execute a target App.
