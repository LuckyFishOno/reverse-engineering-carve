# Component analysis queue

RECarve0.12 persists selected static-analysis requests across CLI/MCP sessions. Your existing agent still locates the requested behavior, selects components, follows evidence, writes a reconstruction and tests it. A completed queue job only means that its bounded analysis request finished.

After `reverse`/`survey`, choose paths from index pages and save a bounded `requests.json`:

```json
[
  {"file":"bin/program","native":{"strings":"visible feature text","limit":50}},
  {"file":"classes.dex","managed":{"class":"example.SelectedClass","mode":"auto"}},
  {"file":"resources/module.mjs"}
]
```

```sh
node dist/cli.js queue add ./work --requests ./requests.json --engines ./engines.json
node dist/cli.js queue list ./work --limit 20
node dist/cli.js queue run ./work --engines ./engines.json --max-jobs 1 --progress
node dist/cli.js queue list ./work --id RETURNED_JOB_ID --limit 20
```

`engines.json` names the local Ghidra, JDK and JADX installations: `{"ghidra":"...","javaHome":"...","jadx":"..."}` (an `r8` jar is optional for the verify scripts). Since 0.23 a relative path is resolved against the directory of the configuration file itself, not the current directory, so a project folder holding both the engines and their configuration can move. Absolute paths are used as written. `recarve serve --engines` and the Android runtime configuration of the verify scripts follow the same rule.

For a short synchronous batch, repeat `queue run` while queued work remains. Defaults: one job/run (maximum10), up to100 requests/enqueue, pages of20 jobs/attempts (maximum100). CLI progress uses stderr JSON lines. Synchronous MCP equivalents are `carve_analysis_enqueue`, `carve_analysis_jobs`, `carve_analysis_run`; engine paths come from `serve --engines`. Standard progress tokens and cancellation are supported. SIGINT/SIGTERM stop the owned synchronous analysis group and preserve attempts.

For analysis that should continue after the CLI exits or the MCP connection closes:

```sh
node dist/cli.js queue start ./work --engines ./engines.json --max-jobs 2 --max-run-ms 3600000
node dist/cli.js queue runs ./work --id RETURNED_RUN_UUID
node dist/cli.js queue cancel ./work --id RETURNED_RUN_UUID
```

MCP equivalents are `carve_analysis_start`, `carve_analysis_runs`, `carve_analysis_cancel`. A start returns a durable run UUID within a bounded startup handshake. Slow acknowledgement returns an inspectable starting handle; it does not restart the engine. Existing active work returns created:false and its original options; different requested options do not change that work. After start has returned its handle, normal launcher exit, MCP disconnect or a later status-call timeout leaves the batch running. To stop it, send cancel and query runs until actual worker/supervisor/group liveness is gone. Cancellation of an in-flight start request persists cancellation for its newly created run. A returned existing active run retains its original lifecycle; requesting different options does not cancel it.

This forks a bounded local worker, installs no service and launches no LLM. One execution lease serializes queue batches per workspace; there is no global limit across background workspaces. The MCP server separately limits synchronous analysis calls to two and makes them share one heap reservation; background workers are not counted in it. maxRunMs1000–86400000 (default24hours) is the worker execution budget; tool shutdown can take longer. Native/managed requests retain their own timeoutMs. These are cooperative trusted-tool controls, not a hard CPU/memory sandbox. The run processes at most maxJobs1–10 requests, then exits; it does not watch for future jobs. Use a new start for another batch.

`queue runs` pages run records (limit1–100, default20), including recordedStatus, observedStatus, actual process identities/liveness, progress, log, deadline, error and result-file SHA256. Run states include starting, running, cancelling, completed, partial, failed, cancelled, deadline-exceeded and launch-failed. Dead workers without a saved terminal state are observed as interrupted; live orphaned tools are engine-cleanup-pending, and uninspectable liveness is unknown. Cancelling is not proof of termination, including a suspended worker that has not consumed the durable request yet. Run records and component-job records describe different scopes: a cancelled run can contain completed earlier jobs and an interrupted current job. A completed empty batch says nothing about old failed/unsupported jobs. Inspect `queue list` and its attempt history separately. Lost workers require explicit retry after actual recovery. Background progress is persisted and logged; use the status tools instead of keeping a progress notification connection open.

Native selectors match `native`: choose one of function, strings, window or linkage (imports/exports/libraries); linkage uses a separate loader-only cache and its opaque nextCursor as after. A completed linkage job covers one page. See [native links](NATIVE_LINKS.md). bytes only accompanies window; after only accompanies inventory/string pages; limit is1–10000. Omit native selectors for one function-inventory page. Managed options are class and auto/simple/fallback mode. An optional timeoutMs is1000–86400000 (default600000). Ghidra/JADX requests may add resources:{heapMiB,threads} (defaults1024/2, host-checked at enqueue and run); omitting it keeps the pre-0.20 job identity. See [engine resource budgets](ENGINE_RESOURCES.md). Incompatible selectors are rejected. JS modules get bounded static export/symbol inspection; use existing discover/plan/probe/extract tools afterward. ASAR follows the existing JS container workflow. Unimplemented formats remain unsupported; header recognition does not establish an analysis backend.

Each job identity binds its selected relative path, fresh source SHA256, request and configured provider identity. Selected launchers, primary JADX jars, Ghidra export/native decompiler files and JDK executable are hashed. This does not authenticate every installed library or the local Ghidra database. Source and selected provider identities are checked again before/after analysis. Result files have recorded hashes, and attempts retain logs and process records. Queue result metadata is historical; reconstruction still checks the actual binary/decompiler evidence. matchesCurrentInventory compares against the current indexed revision; fresh bytes are rehashed when running.

States include queued, running, completed, partial, failed, interrupted, stale-input, stale-provider and unsupported. Partial analysis stays partial. Failed/interrupted work is not silently repeated: inspect its error, then use `queue run --retry` / retry:true. Each batch attempts a selected job at most once. Stale inputs/providers require refreshing when appropriate and enqueueing a new request; old jobs/attempts remain. If the exact original identity becomes valid again, a fresh enqueue requeues its stale job while preserving attempts. An unchanged completed request deduplicates to its existing job. `queue list --id` includes attemptTotal/nextAttemptOffset for history pagination.

Analysis ownership uses SQLite compare-and-swap leases and POSIX process start identities. A supervisor stays outside the engine group; the parent records both before authorizing tool startup. The supervisor handles parent disconnect, repeats cleanup across startup races, reaps the worker and checks actual group absence. A live parent can clean up after a killed supervisor. Recovery requires the previous owner/supervisor and engine group to be gone; unknown process inspection refuses recovery. Current engine launchers require POSIX and `ps`. Configured tools are trusted; this is not process isolation against a tool that deliberately detaches itself.

Legacy .analysis.lock files are preserved and require actual engine inspection before explicit removal. A dead PID alone cannot exclude an old detached Ghidra process. Interrupted first imports restart only after process recovery; completed Ghidra analysis can be reused. Other local workspace files remain trusted state, not authenticated evidence.

The optional `npm run verify:queue -- ./engines.json` uses cached pinned jq1.8.2 and scrcpy5.0.1 release files from their existing verification workflows. It runs native string/function requests, selected-class JADX and a JS inspection across fresh CLI/MCP runners, checks source/result identities and observes stopped engine groups. It observes a real analyzing Ghidra JVM, cancels that CLI attempt, checks actual process termination, then explicitly retries the incomplete initial import in a fresh CLI process. The jq function address comes from the earlier same-byte registration investigation. This test does not independently rediscover it, reconstruct all components or prove cross-binary dependencies. Runtime equivalence remains the separate native/Android verification workflows.

`npm run verify:background -- ./engines.json` separately exercises real pinned jq Ghidra analysis, released scrcpy selected-class JADX and JS static inspection through background batches. It observes an actual analyzing JVM after its CLI launcher exits, cancels from a fresh MCP connection, confirms process cleanup, and explicitly retries from another MCP session that immediately closes. Fresh clients inspect final component results. It does not compare runtime behavior or prove a whole-project feature boundary. Unit lifecycle tests use synthetic engine fixtures; their process results are separate from this actual decompilation check.
