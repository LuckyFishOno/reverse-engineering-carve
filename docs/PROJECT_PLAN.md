# Project plan: feature dependencies and development order

A whole-project port starts from a plan written by the agent: the features to rebuild, which ones depend on which, and the interface each one must keep. `planProject` checks that plan and orders it into development phases. It is a pure function: it does not read files, run programs, start REA or other agents, or write anything.

In0.36, use the read-only `project-plan PLAN.json` CLI or `carve_project_plan({plan:"PLAN.json",offset,limit,budgetBytes})` MCP tool. The wrapper reads one local JSON file (<=1MiB); MCP confines it to the configured root. It does not open declared evidence IDs or write plans, dispatch agents or assemble apps. Plan-file persistence remains the caller's responsibility.

```sh
node dist/cli.js project-plan examples/project-plan.json --limit 2 --budget-bytes 4096
```

Use nextOffset with the same file and check planId across pages. If the file changes, restart pagination; offset does not pin a revision. taskId commits to its stated target/feature/direct-interface fields, while planId commits to the whole declaration. Any handoff/execution must bind the relevant project revision as well as the task identity. Neither ID is source authentication or a recorded behavior pass.

## Input: `carve/project-plan@1`

```json
{
  "schema": "carve/project-plan@1",
  "goal": "Port the editor to macOS",
  "target": {"schema": "carve/target@1", "platform": "macos", "delivery": "desktop-app", "language": "Swift"},
  "features": [
    {"id": "core", "title": "Document model", "contract": {"input": "bytes", "output": "document tree", "state": "immutable snapshot"}},
    {"id": "parser", "title": "Parser", "dependsOn": ["core"], "contract": {"input": "text", "output": "tokens", "errors": "syntax error list"}},
    {"id": "editor", "title": "Editor shell", "dependsOn": ["parser"], "unknowns": ["Clipboard behavior on Windows not observed"]}
  ],
  "unknowns": ["Server-side sync not analyzed"]
}
```

- `target` uses `targetSpecSchema` from `src/target.ts` (`carve/target@1`), including its platform/delivery compatibility check. That check is about the declared intent, not whether the target can be built.
- `features`: 1–500. Each has:
  - `id`: 1–64 characters of `a-z 0-9 . _ -`, starting with a letter or digit.
  - `title`: up to 200 characters.
  - `description` (optional): up to 2000 characters.
  - `dependsOn`: up to 64 feature ids. The ids are features that must exist before this one.
  - `contract` (optional): `input`, `output`, `state`, `errors`. Each is text up to 2000 characters, and at least one must be given.
  - `unknowns`: up to 32 entries.
  - `evidenceIds`: up to 32 sha256 hex strings.
- `unknowns` at the plan level: up to 64 entries of up to 500 characters each.
- Limits on the whole plan:
  - at most 4000 dependencies in total
  - at most 1 MiB of JSON
  - every object is strict, so unknown keys are rejected
- Rejected with the failing path:
  - duplicate feature ids
  - a dependency on an unknown feature
  - a feature depending on itself
  - the same dependency listed twice
  - the same evidence id listed twice
  - an incompatible target
  - anything over a limit
- `evidenceIds` and `unknowns` are recorded as the agent declared them. `evidenceIds` are counted, not opened or authenticated.

## Ordering

- Dependencies form a graph from each dependency to the feature that needs it. Strongly connected components are found with an iterative Tarjan pass, so long chains do not use the call stack.
- A component with more than one feature is a cycle. Cycles are kept and named `cycle-1`, `cycle-2`, … in order of their smallest member id, so names are stable for one plan. Their members have `status: "in-cycle"` and `phase: null`.
- Everything downstream of a cycle has `status: "blocked"`, `phase: null` and `blockedBy` listing the upstream cycles. A cycle below another cycle stays `in-cycle` and also lists the upstream cycle in `blockedBy`.
- All other features are `ready`, with `phase` = 1 + the highest phase among their dependencies (phase 1 has no dependencies). Features in one phase do not depend on each other in the declared plan.
- Task order: ready features by phase, then cycle members by cycle, then blocked features. Ties are broken by id.

## Identities

- Canonical JSON with sorted keys, after trimming strings and sorting features, `dependsOn` and `evidenceIds`. Reordering the input therefore does not change any identity.
- `planId`: sha256 of the whole normalized plan.
- `featureSha256`: the feature's own id, title, description, contract, unknowns and evidence ids.
- `contractSha256`: the feature's contract, or `null` when it has none.
- `taskId`: the target, the `featureSha256`, and each direct dependency's id and `contractSha256`. A task changes when:
  - the target changes,
  - the feature itself changes,
  - a direct dependency's contract changes, or
  - its dependency list changes.

  It does not change when only a dependency's free-text description changes.

## Output: `carve/project-plan-view@1`

```js
planProject(plan, {offset: 0, limit: 20, budgetBytes: 8192})
```

- Each page includes:
  - `planId`
  - `goal`: clipped to 160 UTF-16 units, never splitting a surrogate pair
  - `target`
  - `summary`: counts of features, dependencies, phases, ready, cycles, in-cycle, blocked and project unknowns
  - `order` and `authority` statements
  - `total`, `offset`, `limit`, `items`, `nextOffset`, `budgetLimited`
  - an exact `receipt` from the shared `context-budget` helper
- The page never contains the whole graph, all contracts or all cycle member lists.
- Each card contains:
  - `id`, `taskId`
  - `title`: clipped to 120 units; `titleTruncated` when clipped
  - `status`, `phase`, `cycle`
  - `dependsOn` and `blockedBy`: at most 16 each, plus `dependsOnTotal` / `blockedByTotal` when longer
  - `dependents`: a count
  - `contract`: `present`, field names and `sha256`, not the text
  - `featureSha256`
  - `declaredUnknowns` and `declaredEvidenceIds`: counts
- Descriptions and contract text are not echoed into cards.
- `limit` is 1–100 and `offset` must name an existing task. `budgetBytes` is 1024–65536 bytes of compact JSON. A page stops before exceeding the budget and returns `nextOffset`. A budget that cannot hold the page metadata plus one complete card is refused; no card is silently dropped.
- `analyzeProjectPlan(parseProjectPlan(plan))` returns the full in-memory analysis (all tasks and cycle members) for integrations that need it. The full analysis is not meant to be sent in one response.

## What a plan does not establish

- A plan is agent-declared and ordered as written. It is not engine evidence, verified code, a complete feature inventory, proof that the target can be built, or work that has been dispatched to anyone.
- A feature being `ready` only means its declared dependencies come earlier. Missing server logic and OS or hardware dependencies stay unknown unless they are written into the plan as unknowns.

## Checks

`test/project-plan.test.mjs` covers:
- a diamond DAG plus an independent feature
- two cycles, including a cycle below another one, and the blocked features downstream
- a 500-feature chain paged in full, and a 500-feature ring as one cycle
- the feature, dependency, length and input-size limits
- every rejected reference and shape
- identity stability and its changes
- Unicode clipping at a surrogate boundary
- small budgets paged to completion with exact receipts
- refusal of a too-small budget
- instruction-like text in descriptions that is neither executed nor echoed
- prototype-pollution keys rejected by strict parsing

All plans in these tests are synthetic. Passing them does not show that any real application was ported.

## Prepare selected work

In0.37, [work-package](WORK_PACKAGES.md) binds the complete plan revision and a separate work-spec revision into an immutable selected-task folder. It requires all four interface fields on the selected feature and its direct dependencies, declared nonoverlapping output files and acceptance criteria. The optional/partial contracts allowed by project-plan still support planning; complete them before preparing work. Neither preparing a folder nor checking its pins dispatches an agent or executes acceptance.
