# Original CRC initialization and selected indirect dispatch

`npm run verify:pe-crc-dispatch` extends [the explicit-table CRC case](PE_CRC.md)
to the actual `CrcGenerateTable` initializer and `CrcUpdate` indirect dispatcher
in the same pinned Windows AMD64 DLL. It runs original initialization instructions
and original selected T4/T8 instructions, rather than injecting an independently
generated table into the original process.

The DLL SHA256 remains
`c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27`.
Retained COFF symbols and independent REA instruction/function records identify:

| Role | Preferred VA |
| --- | --- |
| CrcGenerateTable | 0x6a42c510 |
| CrcUpdate | 0x6a42c4a0 |
| CrcUpdateT4 | 0x6a42c5c0 |
| CrcUpdateT8 | 0x6a42c680 |
| CPU_Is_InOrder | 0x6a41e6a0 |

The producer closes before Carve imports these records. Explicit non-UI roots
inspect the initializer and dispatcher with selected helper evidence. Runtime BSS
references are retained as unresolved reconstruction data selections; disk bytes
do not establish the initialized table, pointer identity or lifetime. Static
indirect-call uncertainty is not promoted into a resolved call edge by execution.

The declared input is `(cpuPredicate, state, bytes, alignment)`: CPU predicate 0 or 1,
uint32 state, up to 4096 bytes, and buffer alignment 0–7. The harness intercepts
exactly the original `CPU_Is_InOrder` entry and returns the declared predicate.
It does not execute or validate hardware CPU detection. The remainder of the
initializer executes unchanged, producing all 2048 uint32 table cells and writing
the dispatch globals. Predicate 1 selects T4; predicate 0 overwrites selection with T8.

The harness starts with zero-filled BSS as an explicit loader assumption, checks
2048 table writes, one CPU boundary call and three/four pointer writes, and compares
every table cell and its complete 8192-byte SHA256 with the portable initializer.
The initialized image then becomes read-only except executable code. Calling the
original dispatcher must enter exactly its selected T4 or T8 implementation once.
Original reads must stay within the actual input, generated table, dispatch slot
and stack. Unexpected global writes or data reads fail; execution is bounded.

The portable module regenerates the equivalent tables and computes the same CRC
byte recurrence. Its `implementation` output models the declared original selection;
it does not retain the original optimized instruction sequences or establish their
performance. Outputs are `{value, implementation}` with raw unsigned CRC state and
T4/T8 selection. Initialization is immutable within the portable module; independent
calls accept explicit caller state and do not share an original emulated instance.

The 194 original/candidate comparisons cover both predicates, eight alignments,
empty inputs, loop/alignment thresholds, high-bit state and 4096-byte buffers.
Original chunk updates match the standard vector. Skipping original initialization
must fail; a candidate selecting the opposite CPU branch must fail; changed original
bytes invalidate saved acceptance. Direct and fresh library-only MCP calls reuse
the package while the integration's original copy is offline, then restore it.

Prerequisites and override options match [PE CRC validation](PE_CRC.md). Run:

```sh
node scripts/check-release.mjs --pe-crc-dispatch
```

Evidence is retained in a fresh `artifacts/pe-crc-dispatch-e2e-*` directory and the
successful summary `artifacts/pe-crc-dispatch-verification-summary.json`.
No Windows loader, DLL startup, real hardware detection, JVM, UI, archive operation,
concurrent initialization or rebasing is verified. This is a source-pinned, reviewed
CRC feature comparison under an explicit environment, not generic application recovery.

## Generated initialization and dispatch tasks

The same integration now additionally creates a scalar-result reconstruction and
source-bound generated tasks:16 sequences194steps, each using the original
CrcGenerateTable followed by repeated CrcUpdate calls on one initialized image.
All five imported functions have complete instruction/byte reviews. Only the
selected T4 or T8 body is executable as a helper in each task. CPU_Is_InOrder has
a reviewed no-argument identity but its original body is not executed: the task
supplies a declared0or1 exactly once during initialization.

Original readonly pointer constants at0x6a571c10 and0x6a571c20 are explicitly
readable. The full2048cell generated table and three BSS pointer slots are checked
against expected SHA256 values before computation, then exact-region hooks forbid
further writes. Both predicate paths initialize the T8 slot; the selected dispatch
slot differs. Inputs use fixed modulo8 alignments0through7, independent of length.

`generated-summary.json`, per-profile/alignment task manifests, fixed runner copies,
sequence cases and comparisons are retained. Their full bytes and SHA256 values,
plus raw producer/workspace evidence, are captured in `evidence-bundle.json`, whose
exact bytes are acceptance pinned. Loose files remain convenience copies; the
pinned bundle is the evidence snapshot. Runtime inputs remain individually pinned,
within the64file acceptance limit. Changing the bundle invalidates saved acceptance.
Negative tasks omit the CPU boundary, whitelist the wrong helper, change the CPU
outcome, skip initialization, require an incorrect boundary-call count or demand an
incorrect table hash. Each fails as a harness-policy error; it is not counted as
an equivalent target exception. The earlier manual194case comparison is retained
as separate evidence with its original trace checks and dispatch-label mutant.

The generated scalar result establishes supplied CRC outputs under the declared
predicate and allowed helper bodies. It does not execute original hardware detection,
preserve optimized-code performance, or prove untested behavior. Prepared tasks bind
the current trusted runner; older pinned tasks must be freshly prepared after runner
changes. Historical failure reports are preserved with their original status.
