# Ordered stateful operations

Use this workflow when the same function updates module/global state: a counter, accumulator, undo stack or local parser session. REA investigates the original; the existing agent writes the reconstruction; RECarve compares explicitly supplied sequences. REA MCP and RECarve MCP remain independent.

Every sequence starts a fresh original command or Android VM process and a fresh restricted candidate Node process. Within that candidate process the module is imported once and each call is awaited in order. Return values are serialized immediately, so later mutations cannot rewrite earlier recorded results. A thrown exception is recorded and the next requested step still runs. Serialization, import, timeout, cancellation, output or protocol errors invalidate the complete sequence; they are not matching target exceptions.

## Reference protocol

Save a reference configuration (absolute original executable path):

```json
{
  "schema": "carve/reference@3",
  "command": ["/absolute/path/to/original"],
  "mode": "json-sequence-stdin",
  "scope": "target-cli",
  "description": "The shipped original executes all supplied operations in one process",
  "boundFiles": []
}
```

`target-cli` must execute the selected indexed binary itself. Use `external-harness` with a precise description and bound files when an adapter is required; that scope does not prove the original binary was executed. Arguments in command are not automatically inferred to be files. Reference@1/@2 and Android-reference@1/@2/@3 keep their existing scalar behavior. Android-reference@4 explicitly selects the sequence protocol on ART; see [Android sequences](ANDROID.md#ordered-android-object-operations).

The reference receives an array of positional argument arrays on stdin, for example `[[0,0],[1,5],[0,0]]`. It must emit exactly one JSON array with exactly one outcome per call, in order:

```json
[
  {"kind":"return","value":7},
  {"kind":"return","value":12},
  {"kind":"return","value":12}
]
```

A target exception uses `{"kind":"throw","error":{"name":"RangeError","message":"message"}}`. Only return/throw are valid step outcomes; a missing value, extra fields, wrong count, nonfinite value, malformed JSON, nonzero process exit or unexpected stdout fails the reference protocol. stderr is diagnostic. RECarve checks the declared command/output boundary, not whether an external harness secretly recreates the function or spawns per-step processes.

## Cases and comparison

```json
{
  "schema":"carve/sequence-cases@1",
  "cases":[
    {
      "name":"accumulate without losing state",
      "steps":[
        {"args":[0,0],"expected":7},
        {"args":[1,5],"expected":12},
        {"args":[0,0],"expected":12}
      ]
    },
    {"name":"new process starts fresh","steps":[{"args":[0,0],"expected":7}]}
  ]
}
```

Each supplied expected value is optional and additionally checked against the original return. Without expected, matching original/candidate return values or exact exception name/message pass that step. A whole sequence passes only if every step passes. Preserve meaningful initial-state, repetition, order, boundary, reset and recovery cases. Do not silently reset before each step or replace an unknown stateful operation with a stateless function.

```sh
node dist/cli.js verify-reconstruction WORK --package PACKAGE \
  --reference reference.json --cases sequences.json --execute
```

The existing MCP tool `carve_verify_reconstruction` uses the same files. Reports retain status passed-supplied-cases or failed; comparisonMode is stateful-sequences, passed/total count whole sequences and passedSteps/totalSteps count steps. verifiedScope is selected-original-cli-sequences, declared-external-harness-sequences or selected-dex-android-harness-sequences. Read compact archived results through `verification` / `carve_verification`; field:steps and item:INDEX selects a recorded step. Bound original/evidence/reference bytes are checked before/after, and original inputs are never copied into the candidate.

Limits:1–200 uniquely named sequences,1–64 calls each, at most1000 total steps,1MiB cases/reference JSON and1MiB call input per sequence. Each process has a combined1MiB output limit and50–30000ms whole-sequence deadline (default3000ms). No timeout extends automatically for more steps. Reference and candidate have separate deadlines. These limits preserve the existing bounded verifier; they are not a hostile-code sandbox.

## Reuse

```sh
node dist/cli.js invoke-sequence FUNCTION_FOLDER \
  --calls '[[0,0],[1,5],[0,0]]' --execute
```

Use `carve_invoke_sequence` with `{package,calls,execute:true}` or standalone `capability_sequence` with `{calls}`. The return contains an ordered array of return/throw outcomes. `invoke` / `carve_invoke` / standalone capability still start fresh per single call.

`use` / `library get` retain a bounded complete exampleSequence with calls and outcomes, and show a runnable sequence command. They never promote an isolated sequence step into a verified independent example. Library import preserves this sequence and the original comparison scope; it does not rerun verification. Directly importing capability shares the caller's module instance/lifetime and ordinary permissions; the caller decides when to reset/reload it.

## Real native verification

```sh
npm run verify:rea-stateful
```

This local test client creates a fresh project-local pinned REA6.7.0 install with install scripts disabled and no global setup. It compiles the owned examples/native-app/stateful-counter.c, then sends only that original executable to independent REA/Ghidra. It saves four complete Evidence records, closes REA, imports them into an engine-free RECarve MCP and archives external producer JSON paths before reconstruction.

The original executable itself parses each input sequence and calls its shipped stateful_step repeatedly in that process. The reconstruction implements two persistent signed32 cells initialized to7, read/add/set/swap-undo, and compiled -fwrapv addition.32 sequences /635 steps include initial-state checks, repeated undo, signed32 overflow and deterministic mixed operations. An alternative that resets both cells before every call fails later steps. Complete sequence examples survive function-library import; direct import, CLI and two consecutive library-only MCP requests work and start fresh per request. Original executable bytes remain unchanged and retained. The script records source, producer/install identity, report and scope under artifacts/rea-stateful-e2e-*/report.json. `--rea-install PREFIX` explicitly reuses an existing local install instead, and the report records that distinction.

This is one source-owned native operation, not a third-party App or a generic state reconstruction engine. Evidence hashes check byte consistency, not producer authentication. Passing supplied sequential observations does not establish concurrency, timing, arbitrary initialization/global-memory recovery, cross-request sessions, OS/files/network/hardware behavior, absent server logic or general semantic/dependency closure.

## Third-party lifecycle case

The separate [JDK Adler32 lifecycle check](JDK_STATEFUL.md) compares31 shipped-object sequences /405 steps, binding a class extracted from the runtime lib/modules image and three independent REA native functions. It verifies initial state, chunk accumulation, empty updates and reset through a framing-only JVM adapter. That comparison retains external-harness-sequences scope; it does not change the scope of the owned native CLI example above.

The [original APK BitArray case](ZXING_STATEFUL.md) compares33 sequences /692 steps on actual API35 ARM64 ART through Android-reference@4. The adapter retains one original object per sequence, clear preserves logical length, and new explicitly calls the constructor again. It is separate from host-JVM and native-CLI cases; original method tracing and general object/dependency recovery remain unestablished.
