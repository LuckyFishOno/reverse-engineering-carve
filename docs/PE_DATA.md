# PE data references and state example

The `pe-ui` / `carve_pe_ui` dependencies view includes `data-reference` rows for explicitly selected, source-bound REA references marked data/read/write. No additional server or REA proxy is introduced. Use the same command, function IDs, dependency IDs and paging options described in [PE UI dependencies](PE_UI.md).

## Static evidence

Each row preserves the caller observation, source and target preferred-image virtual addresses, imported reference type and access (`read`, `write`, `read-write`, `address-only`). `sourceSection` locates the reference instruction; `section` identifies the target section and declared permissions. `targetDirectories` identifies containing declared data directories, excluding the certificate directory whose location is a file offset. This is location evidence, not resource-ID or loader interpretation.

Source locations must fall in the captured function body and one unique image section. External coordinates, addresses outside the image, overlapping sections, headers, unmapped locations, virtual-only tails and unavailable file data remain explicit statuses. No runtime bytes or zero-fill values are invented. A captured prefix must not overlap another section or cross its file-backed extent. File truncation during a read fails the inspection; selected image hashes are rechecked before report publication.

`bytes` contains at most64initial file bytes at the target, with exact file offset, length, hex and SHA256. The hash covers this prefix, while the report also pins the entire selected source. `objectExtent:unknown` means this is not a declared variable size or complete data dependency. Section padding can occur in the prefix. Bounds apply per reference; the existing5000row report cap and response budgets remain in force.

Readable, non-executable data may include these conservative interpretations:

- `stringCandidates`: printable ASCII or ASCII-range UTF-16LE with at least4characters and an observed zero terminator entirely inside the prefix. Other encodings, unterminated/truncated strings and non-ASCII Unicode remain unidentified.
- `scalarPreview`: first4bytes interpreted as uint32 little-endian. `declaredType:unknown` prevents that interpretation from becoming an inferred variable type or size.
- `read-only-data-candidate`: section permissions allow reading and exclude writing/execution, with no exact selected write target recorded.
- `mutable-state-candidate`: writable section or a recorded write to that exact target among selected observations. Initial bytes and string interpretations remain initialization evidence only.

Selected references cannot rule out writes through aliases, unselected code, runtime patching or OS behavior. Read-only candidates are not proven immutable constants. Read/write kinds are imported typed static records (`referenceBasis:imported-typed-reference`), not freshly decoded instruction semantics or observed execution. `instructionSemantics:not-decoded`, `runtimeValue:unverified` and `dependencyClosure:not-established` remain explicit. Resource semantics, state lifetime, initialization order and persistence require separate review and behavior checks.

Rows include investigation `nextSteps`, including state modeling and object-extent review. Function coverage reports `stateDependencies:typed-references-inspected-semantics-unverified`; this does not promote the references into complete state analysis.

After reviewing the rows, [bind selected data into a reconstruction contract](RECONSTRUCTION_DATA.md) with exact reference coordinates, byte prefix length/hash and explicit data/state handling. This preserves the review through packaging and later evidence revalidation.

[Direct resource links](PE_RESOURCE_LINKS.md) associate valid reference targets with parsed menu/dialog/string-table/accelerator payloads and optionally pin their exact paths and complete payload hashes during reconstruction.

## Owned executable state comparison

With the same local Clang, [REA/Ghidra and Unicorn prerequisites](PE_BEHAVIOR.md) as the arithmetic example:

```sh
npm run verify:pe-state
# Include both optional real-producer/emulator examples in the release checks:
node scripts/check-release.mjs --pe-behavior --pe-state
```

Overrides: `node scripts/verify-pe-state.mjs --engines CONFIG --rea-install DIRECTORY --python EXECUTABLE`. `check-release` uses `--pe-python` for the Python override. Default Node-only checks do not require these optional dependencies.

The owned `examples/pe-feature/state.c` is compiled into real x64 COFF code and narrowly linked into a source-owned PE envelope. Only its trusted text and two fixed data sections are supported; switch jump tables are disabled. The example is not a general linker. Separate REA6.7.0/Ghidra captures complete function/code/reference records and closes before RECarve imports them. The dependency report must identify readonly settings, writable counter references, typed writes and the source-backed label.

The reviewed reconstruction in `state-implementation.mjs` embeds rates2/5/9, the label `counter`, and initial counter7. One `stateSequence(steps)` invocation creates one isolated session, retaining counter state across every ordered step. Operation0resets to0, operation1adds nonnegative input times an indexed rate with uint32 wrapping, operation2reads, and operation3reads a label byte, and operation4reads a UTF-16 code unit from the compiled `ready` PE string-table payload. Invalid operations return-1; negative additions return-2without changing state. No disk persistence is claimed. The session interface is an explicit reconstruction design, not recovered Windows UI behavior.

The original harness maps the original image once per sequence with declared x64 ABI and section permissions; each step executes original instructions while preserving image state. It bounds inputs, steps, instruction count and execution time. Memory hooks separately assert actual reads of settings, the PE string-table payload and reads/writes of the counter.40sequences/926steps cover initial state, updates, reset, labels, signed wrapping, error preservation and deterministic operation mixes. Passing finite cases do not prove universal equivalence.

Acceptance pins the image, harness, candidate, cases, complete REA/UI reports and package. A mutant resetting the counter every step must fail. A changed settings byte or resource string byte invalidates the acceptance read. With the original image temporarily unavailable, original emulation fails but a fresh library-only MCP and direct module import still return the expected ordered values; repeated module invocations confirm session isolation. Originals are restored and rehashed afterward.

Results are retained in `artifacts/pe-state-e2e-*/report.json` and `functions/pe-state`; the latest pointer is `artifacts/pe-state-verification-summary.json`. Scope remains `declared-harness`, `windowsExecuted:false`, `uiExecuted:false`. This validates the owned example's data/state reconstruction and independent reuse, not arbitrary PE recovery, Windows loading, GUI dispatch or OS semantics.
