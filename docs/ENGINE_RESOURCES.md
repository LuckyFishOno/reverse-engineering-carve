# Engine resource budgets

RECarve 0.20 lets a caller choose the JVM maximum heap and worker-thread budget for Ghidra and JADX. Before 0.20 both engines used a fixed 1 GiB heap and two workers. Those remain the defaults, so existing calls launch exactly as before.

## Options

| Surface | Heap | Threads |
| --- | --- | --- |
| CLI `native` / `managed` | `--heap-mib <MiB>` | `--threads <count>` |
| MCP `carve_native` / `carve_managed` | `heapMiB` | `threads` |
| Queue request (`queue add`, `carve_analysis_enqueue`) | `resources.heapMiB` | `resources.threads` |
| Direct API `nativeAnalysis` / `managedAnalysis` | `resources.heapMiB` | `resources.threads` |

```sh
carve native ./work --file relative/large-program --ghidra /path/to/ghidra --java-home /path/to/jdk \
  --heap-mib 8192 --threads 4 --timeout 7200000
```

```json
[{"file":"relative/large-program","timeoutMs":7200000,"resources":{"heapMiB":8192,"threads":4}}]
```

- Ghidra receives the heap through `GHIDRA_HEADLESS_MAXMEM` (its launcher adds `-Xmx`) and the thread budget through `-max-cpu`.
- JADX receives the heap through `JADX_OPTS` and the thread budget through `--threads-count`. Its launcher sets `-XX:MaxRAMPercentage=70.0` by default, and an explicit `-Xmx` overrides that.
- Every result reports the `resources` used for that launch. A native result also includes `analysisResources`: the budget of the run that completed the cached auto-analysis. Ghidra caches created before 0.20 report `analysisResources: null` and a limitation saying that budget is unknown.

## Checks before launch

- `heapMiB` must be 256 or more and no more than 75% of host physical memory. `threads` must be 1 or more and no more than the host's available parallelism. Requests outside these limits fail before any engine starts.
- Every Ghidra/JADX launch on the host takes a heap reservation in one per-user registry before the engine starts: CLI calls, MCP servers, queue runs and background workers all count against the same 75% host limit. A launch that would exceed it fails with `Engine heap budget busy` and does not start an engine. A queued job refused this way is recorded as failed and needs `retry`. Reservations of a process that has verifiably exited are reclaimed on the next admission; an owner whose liveness cannot be inspected is kept.
- The registry is `~/Library/Caches/carve/engine-reservations/heap.sqlite` on macOS and `~/.cache/carve/engine-reservations/heap.sqlite` elsewhere, using the account home directory from the user database. It does not depend on `TMPDIR`, `HOME` or XDG variables, so processes started by different launchers still share it. `CARVE_ENGINE_RESERVATIONS=<directory>` overrides the location; every cooperating process must use the same value. The directory must be private to the user (mode 0700, not a symlink).
- Queue requests apply resources only to Ghidra/JADX backends. A request without `resources` keeps its exact pre-0.20 job identity. Two requests that differ only in resources are different jobs.

## Heap exhaustion

After every Ghidra/JADX launch, RECarve scans the whole retained engine log for `java.lang.OutOfMemoryError`. Ghidra analyzers can report a heap failure and still exit 0. When that happens the call fails, the project is not marked as a completed cache, and the next call imports and analyzes again. A JADX heap failure also fails the call before anything is indexed. The error names the heap that was used and the host limit, so you can retry with a larger heap or a narrower scope.

## What resources do not change

Resources do not enter the analysis cache identity. A cached auto-analysis completed under one budget can be reused for exports under another. `analysisResources` records which budget completed it. The heap is the JVM maximum only. The native decompiler process, JVM metaspace/stacks and OS caches use memory beyond it. RECarve does not measure peak memory or provide a CPU/memory sandbox, and does not claim any speedup.

## Real check

`npm run verify:engine-resources` (or `npm run check -- --engine-resources`) runs the installed engines on the pinned jq-1.8.2 release and the pinned scrcpy 5.0.1 `classes.dex` member. While each engine runs, it reads the command lines of the live JVMs in the registered engine process group:

- **Ghidra, fresh auto-analysis:** the main `AnalyzeHeadless` JVM carries `-Xmx1536M -max-cpu 1`, and the cache records `{heapMiB:1536,threads:1}`.
- **Ghidra, reused export:** with default resources the JVM carries `-Xmx1024M -max-cpu 2`, and the cache still reports `{heapMiB:1536,threads:1}` for the completed analysis.
- **JADX:** both the version-check JVM and the decompilation JVM carry `-Xmx768m`. The decompilation JVM carries `--threads-count 1`.
- **CLI:** `--heap-mib 640 --threads 1` reach the JADX result.

This check does not cause or establish a real engine heap exhaustion. The `OutOfMemoryError` path is covered by tests with stand-in engines.
