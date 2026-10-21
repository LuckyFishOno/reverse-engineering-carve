# Generated bounded PE verification tasks

Reconstruction can optionally prepare a repeatable original-machine-code task from
an existing [instruction/ABI review](RECONSTRUCTION_INSTRUCTIONS.md). This replaces
case-specific register/buffer adapter code with explicit declarative bindings.
Preparation writes files but does not execute Python, the original or the candidate.

The initial policy is `single-function-readonly-inputs@1`: one AMD64 PE function,
Windows x64 register inputs, an EAX uint32 result, and caller-supplied readonly data.
Every byte of every imported body range must have a reviewed byte witness. The source
file/image must fit 16 MiB, use an aligned low canonical preferred base and avoid the
fixed harness regions. External functions, initialization, globals, rebasing, callbacks,
floating point, writable/out buffers and arbitrary OS/UI dependencies are unsupported.

A `carve/pe-verification-task@1` specification selects `artifact`, `observationId`,
an absolute `python` executable invocation path, and exactly one binding for every
reviewed ABI parameter. Parameter names/types must match the review. Bindings are:

| kind | Input |
| --- | --- |
| uint32 | `argument`: one unsigned32 JSON integer |
| bytes | `argument`: byte array; `maxLength` 1–4096, empty input allowed |
| uint32-array | `argument`: fixed array; `length` 1–1024 unsigned32 elements |
| length | `of`: a declared bytes parameter; derive its actual byte count |

Input indices must be unique, contiguous and start at zero. Derived lengths consume
no candidate argument. Buffers must correspond to pointer parameters; lengths may use
uint32 or uint64 registers. An optional instructionLimit is 1–1000000 (default100000),
and timeoutMicros is 1000–1000000 (default1000000). The runtime pins Unicorn2.1.4.
Python installation/library availability is checked when executing, not preparing.

For the real CRC review, parameters state/data/length/table bind to uint32 argument0,
bytes argument1(max4096), a length derived from data, and a256entry uint32-array argument2.
The candidate still accepts `(state, bytes, table)`; no machine pointer is exposed.
Register locations come from the exact review rather than from a case-specific script.

Pass optional `verificationTask: {spec, out}` to the existing `carve_reconstruct` MCP
operation, or CLI `reconstruct --verification-spec spec.json --verification-out task`.
Both CLI options must be supplied together. The task output is a new directory outside
the candidate package. Result status is `prepared-not-executed`. Existing workflows
without the option keep their output shape and behavior.

Three files are generated: task.json, the fixed bundled runner.py, and reference.json.
Use reference.json with existing verify-reconstruction / carve_verify_reconstruction,
explicit cases and execute authorization. The `carve/pe-reference@1` reference pins the
complete task file. Before execution Carve rebinds source/review/package identity,
rederives register/body/memory policy from the current evidence and compares the
runner with the trusted bundled template. A modified task cannot override reviewed
registers or body metadata merely by recomputing its file pin. An explicitly changed
valid specification can select another permitted budget or interpreter; it remains
a declared environment, not an attestation.

The runner maps the pinned image readonly with executable text, readonly caller
buffers ending at unmapped pages, a bounded stack and a return sentinel. It rejects
execution outside the reviewed body, undeclared memory reads, uninitialized stack
reads, non-stack writes, instruction/time exhaustion, unbalanced return stacks and
changed integer nonvolatile registers. It models neither complete Windows ABI behavior
nor arbitrary machine/environment state. Inputs are bounded to64KiBof JSON. The original
must return normally; faults are harness errors and never passing error equivalence.

The explicit Python invocation path is preserved so virtual environments retain their
packages; verification also hashes the resolved executable. Task/runner/source hashes
are recorded and checked before/after comparisons. Python libraries are trusted local
runtime dependencies, not a fully fingerprinted environment or an OS sandbox.

The real CRC integration compares200cases through both the generated task and its
independent earlier adapter, and rejects a modified generated runner before execution.
Passing finite cases does not promote the reviewed ABI or static graph into a universal
proof. The package remains independently invocable with original inputs offline; the
original source workspace is still required for later machine-code verification.

## Bounded scalar state sequences

An optional `sequence` field selects `reviewed-functions-stateful-inputs@1` and
produces a `carve/reference@3` sequence reference through the same preparation API.
Main bindings may use uint32 scalars, readonly bytes, fixed uint32 arrays and derived lengths. For example:

```json
{
  "initializers": [[3], [5]],
  "memory": [
    {"address": "0x140001000", "length": 4, "access": "read-write"}
  ]
}
```

Initializer argument arrays invoke the same reviewed function in order, once
before each sequence. They are explicit caller declarations, not inferred loader
initialization. Up to8 initial calls and64 compared calls are supported. Different
sequences start with fresh source bytes and PE zero-fill. State survives calls
within one sequence; register and stack initialization tracking restart each call.
Initializer results are discarded; compared calls return EAX uint32 values.

Memory ranges must be disjoint, total at most64KiB, and fit readable,
non-executable PE sections. Read-write ranges additionally require section write
permission. Reads and writes are checked against exact declared byte ranges even
when an emulator page has broader permissions. Original source hashing binds
initial bytes; zero-filled state follows PE image mapping. Declared memory does
not establish semantic types, initialization intent, or equivalence beyond cases.
Calls outside the selected entry and explicitly reviewed helper bodies remain
forbidden. Arbitrary caller addresses, writable caller buffers, OS APIs and arbitrary stubs are unsupported; the restricted initialization predicate form is described below.

Use `carve/sequence-cases@1` cases. The candidate exports one scalar-argument
function with module state; each sequence receives a fresh candidate process.
For the example above, `let state=11; export const value=n=>state=(2*state+n)>>>0`
is the corresponding owned demonstration, starting from zero-filled original
state and two initializer calls of `state = 2 * state + input`.

The opt-in original machine-code regression runs with
`CARVE_PE_PYTHON=/absolute/unicorn-2.1.4-python node --test test/pe-verification-task.test.mjs`.
Its source-owned AMD64 bytes execute under Unicorn; its imported REA records are
synthetic validator fixtures and are not claimed as real REA analysis.

## Separate reviewed initializer and helper functions

An initializer may instead select another instruction review from the same
artifact and original image:

```json
{
  "initializers": [
    {"observationId": "<selected initializer observation SHA256>", "args": [5]}
  ],
  "helpers": ["<selected helper observation SHA256>"],
  "memory": [
    {"address": "0x140001000", "length": 4, "access": "read-write"}
  ]
}
```

This uses `reviewed-functions-stateful-inputs@1`. The initializer's own ABI
maps positional uint32 arguments to its reviewed registers; these may differ
from the main function's registers. A void or EAX uint32 result is allowed and
is discarded after return and ABI checks. Plain argument arrays retain their
meaning of invoking the main function. Mixed initializer forms preserve order.

Each selected initializer/helper must have its own complete imported function
body and original byte witnesses. Reviews are rebound from the current package;
arbitrary entry addresses, missing reviews, partial body coverage and overlapping
bodies belonging to distinct observations are rejected before execution. Helper
IDs must be unique, with at most8 declared helper functions. The original input
image is shared, with the same exact declared data-memory bounds for all phases.

During an invocation, execution is confined to that entry's body plus the
explicit helper bodies. An initializer is not automatically executable during
main calls. Helpers declare a body allowlist; this does not prove intended call
edges, infer dependencies, enforce each nested helper's ABI, or infer stub semantics.
The outer invocation checks integer nonvolatile registers and balanced return.
No system loader, real CPU detection or cross-image invocation is added.

The owned machine-code regression includes a void initializer taking its seed in
RDX and a main function taking its update in RCX. The main calls a separately
reviewed helper. Tests confirm ordered initialization, persistent updates, fresh
sequences, refusal of an undeclared helper, and rejection of a modified initializer
entry even after the task-file hash is updated. Imported REA records in this
regression remain explicitly synthetic validator fixtures.

## Invocation-local sequence buffers and real REA integration

Sequence calls may now reuse the existing readonly `bytes`, `uint32-array` and
`length` binding forms. Initializers remain scalar-only. Each invocation receives
fresh guarded buffer mappings; mappings are removed after execution, and addresses
are not reused within the sequence. Retaining a caller pointer in image state and
reading it on a later invocation fails, even when a new buffer was supplied.
The reserved sequence buffer range is 0x71000000 through 0x714fffff; original images
that overlap it are rejected. Entire stdin JSON remains bounded to64KiB, with at
most64 compared calls,8 initializer calls and4096bytes per caller buffer.

`npm run verify:pe-sequence` compiles `examples/pe-sequence/rolling.c`, captures
five real REA/Ghidra function records and instruction listings through an
independent producer, closes that producer, and imports the source-bound evidence
into Carve. The owned PE contains a separate void table initializer, a one-byte CRC
helper and a session update function accepting caller bytes. The generated runner
executes those original instructions directly; no fixture-specific register/buffer
adapter is written. The independent JavaScript reconstruction uses a bit recurrence
rather than the original mutable table. This is source-owned validation, not a claim
about third-party CRC dispatch or CPU detection.

The integration compares40 sequences and156 steps, including a split standard CRC
vector, empty calls, all256byte values, fresh state and a4096byte buffer. It checks
missing initialization, an undeclared helper, reset-per-call reconstruction and
oversize caller input as negative cases. Direct module import and a fresh MCP
sequence also work while the original image directory is offline. Complete reports
and original instruction evidence are retained in `artifacts/pe-sequence-e2e-*`.
Use `node scripts/check-release.mjs --pe-sequence` to include this real integration
in the local release gate. Without that flag, no REA/Ghidra execution is claimed.

## Declared initialization predicate boundaries

A sequence may declare at most4 `boundaries`, each selecting a complete instruction
review in the same artifact and source image. For example:

```json
{
  "observationId": "<reviewed predicate observation SHA256>",
  "result": 0,
  "phase": "initialization",
  "expectedCalls": 1,
  "reason": "Explicit environment assumption; original CPU detection is not executed."
}
```

Only a reviewed no-argument EAX uint32 ABI is accepted, with a constant result0or1.
Boundary IDs must be unique and cannot also be executable entries/helpers. Original
boundary bodies require full byte witnesses for identity but are never executed.
The runner intercepts the exact entry only during initializer invocations, checks a
previously written stack return into an allowed caller body, supplies EAX and
returns. It rejects execution during compared calls, excess calls and missing calls
relative to the required1to8call count. The prepared task and reference description
record the reason and substituted result. This is an explicit environment boundary,
not evidence of hardware detection or arbitrary external-call support.

Memory access `initialize-write` permits writes during initialization only; compared
calls retain read access but writes fail at the exact byte-range hook. Optional
`initializedSha256` hashes a whole declared region after all initialization and
before any compared call, including ordinary readonly regions. This can check every
initialized CRC table cell and dispatch slot without injecting their contents.
Readonly byte bindings also accept a fixed `alignment`0through7; caller pointer
modulo8 equals that value for every invocation, independent of payload length.
Exact read bounds remain enforced even when alignment leaves mapped page slack.

The third-party CRC dispatch integration uses the original initializer, dispatcher
and one selected T4/T8 helper, with the source-bound CPU_Is_InOrder entry replaced by
one declared predicate result. It checks the full8192byte table, three initialized
pointer slots and two original readonly function-pointer constants. Generated tasks
compare16 sequences194steps across two predicates and eight caller alignments.
Missing/wrong boundaries, wrong helper, skipped initialization, incorrect call count
and incorrect expected table hash fail explicitly. Original CPU detection is not
executed. See [original CRC dispatch](PE_CRC_DISPATCH.md) for the independent manual
harness comparison and remaining limits.

## Bounded output buffers

A main-function pointer parameter can use `output-bytes` with a caller capacity:

```json
[
  {"parameter": "target", "kind": "output-bytes", "argument": 0, "maxLength": 4096},
  {"parameter": "capacity", "kind": "length", "of": "target"}
]
```

The JSON argument is an integer capacity0through maxLength, not an initial byte
array. Derived length bindings can refer to either readonly bytes or output
capacity. The reviewed ABI must declare the buffer as a pointer and the capacity
as uint32 or uint64. Optional fixed modulo8alignment works as for readonly bytes.
Output bindings select `single-function-output-buffers@1` or
`reviewed-functions-stateful-outputs@1`. Existing scalar/readonly tasks keep their
result protocol.

With any output binding, each observed return becomes:

```json
{"returnValue": 7, "outputs": {"target": [42, null, null]}}
```

Every declared output buffer is observed over its complete supplied capacity.
A byte actually written by the original is returned as0through255; any unwritten
byte is null. Physical zero-fill is not evidence of an initialized output byte.
The candidate must return the same object shape; a matching scalar return with
wrong bytes or invented zeros for unwritten bytes fails comparison. The return
ABI remains EAX uint32; void main functions are not added by this feature.

Output memory is writable only within its exact declared span. Reads require prior
writes for every accessed byte. Underflow, overflow and reads before writes are
harness errors, including accesses into otherwise mapped page slack. Output
buffers are disjoint from caller inputs and from each other; pointer aliasing is unsupported. Initialized inout contents require the distinct
inout-bytes binding described below. Buffers expire after each invocation, with fresh
addresses in sequences. Initializer arguments remain scalar-only. Existing64KiB
stdin and reference stdout budgets apply; large aggregate observations may fail
explicitly rather than return partial successful results.

The real REA sequence integration additionally captures owned `session_transform`,
which writes a bounded prefix using persistent CRC state, leaves the remaining
capacity unwritten, and returns a count. Its independent reconstruction returns
explicit observed outputs. Cases include empty/zero capacity, truncated prefixes,
written zero versus unwritten null,4096byte output, fresh sessions and repeated
stateful calls. A candidate with correct counts but wrong bytes must fail; a fresh
MCP sequence still works with the original image directory offline.

## Initialized read/write caller buffers

`inout-bytes` takes a caller byte array rather than a capacity:

```json
[
  {"parameter": "target", "kind": "inout-bytes", "argument": 0, "maxLength": 4096},
  {"parameter": "length", "kind": "length", "of": "target"}
]
```

The reviewed target must be a pointer; derived length is the actual caller array
length, with a uint32 or uint64 ABI parameter. Arrays contain only integer bytes
0through255, including explicit zero; nulls and booleans are invalid. Empty arrays
are allowed and have no readable/writable extent. Optional fixed alignment and
all existing4096byte limits apply. Initializers remain scalar-only.

The original receives a disjoint, invocation-local copy of those exact bytes.
Initial contents may be read immediately; reads and writes remain confined to the
full supplied span. The result uses the existing `{returnValue,outputs}` protocol
and includes every final byte under the parameter name. Untouched bytes retain
caller values, including zeros; they are not null observations and are not replaced
with defaults. The verification report's input arguments retain the before-image,
and the returned output array supplies the after-image. Observation does not claim
that an unchanged byte was written. Native pointer aliasing and retained pointers
across invocations remain unsupported.

Access modes are independent within one call: readonly `bytes` reject writes,
pure `output-bytes` reject reads until written and preserve unwritten nulls, while
`inout-bytes` permit initial reads and preserve untouched data. Mixing all three
modes does not broaden their individual permissions. Initialized inout bindings
select the same observed-output policies as pure output bindings; ordinary scalar
and readonly task protocols remain unchanged.

The real independent REA integration now includes owned `session_inplace`, which
reads and transforms only a bounded prefix using persistent CRC state. The suffix
must stay equal to original caller bytes. A separate portable reconstruction keeps
its own isolated session per verification sequence. It compares24 sequences89steps,
including zero prefix length, empty arrays, written zero, retained zero/nonzero
suffixes, full4096byte input and limits greater than the buffer length. A candidate
that clears the caller buffer before transforming is rejected even when return
counts match. A fresh MCP inout call works while original inputs are offline.
