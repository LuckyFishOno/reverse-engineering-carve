# Third-party PE table-driven CRC helper

`npm run verify:pe-crc` extracts the real internal `CrcUpdateT1` function from the
Windows AMD64 7-Zip JNI DLL installed with Ghidra. This extends
[the version metadata case](PE_VERSION.md) to conditional branches, a byte loop,
unsigned state and a caller-provided lookup table. The DLL is not redistributed.

The exact SHA256 is
`c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27`.
Retained COFF symbols identify the internal function at `0x6a42c4e0`; it is not an
exported DLL entry. The script verifies that symbol and collects LLVM disassembly
and independent REA function/instruction records before closing the producer.
Carve then imports the complete function evidence and inspects it using explicit
non-UI roots. No UI command, DLL load or runtime dispatch is inferred.

The captured Ghidra pseudocode incorrectly infers a void return and elides the
CRC computation. Preserve that evidence as-is. The reviewed JavaScript module is
based on the actual instructions, and its uint32 return convention is checked by
executing those original instructions. Pseudocode alone is insufficient here.

The bounded signature is `crcUpdate(state, bytes, table)`, where state is uint32,
bytes contains 0–4096 integers in 0–255, and table has exactly 256 uint32 entries.
State is returned without initial/final complement. For the standard CRC32 table,
the raw result starting at `0xffffffff` for ASCII `123456789` is `0x340bc6d9`;
complementing gives the usual `0xcbf43926`. Python zlib separately checks this vector.
Nonstandard tables are valid declared inputs too. They are supplied arguments,
not recovered constants or source-bound data bindings. The original table generator
and original global dispatch pointer are never initialized or executed.

Original instructions execute under Unicorn2.1.4 at the preferred image base with
explicit Windows x64 register arguments. The input ends at an unmapped page and
the table/input are read-only. Memory hooks verify one byte read and one aligned
uint32 table read per iteration; branch hooks check the empty path and loop count.
Instruction/time limits and a source hash guard every run. Unexpected data reads
outside the input, table and stack fail the harness.

Two hundred acceptance cases cover all 256 table slots, empty/high-bit states,
the standard vector, zero/identity/random caller tables and a 4096-byte input.
Two-byte inputs deliberately exercise two distinct table slots each, so a separate
original-instruction trace confirms all slots within 128 cases. Original chunked
updates also match the standard vector. A mutant that ignores the supplied table
must fail, and changed DLL bytes must invalidate saved acceptance.

After comparison, direct imports and a fresh library-only MCP reuse the packaged
module while the integration's original DLL copy is offline; the distribution
remains unchanged. Input errors and incremental reuse are checked independently.
Saved acceptance pins the original, producer/instruction evidence, candidates,
contract, receipt, cases and runtime inputs.

Prerequisites match [PE version validation](PE_VERSION.md), plus Xcode's LLVM
`llvm-nm` and `llvm-objdump`. Optional release invocation:

```sh
node scripts/check-release.mjs --pe-crc
```

Results go to a fresh `artifacts/pe-crc-e2e-*` directory and, on success,
`artifacts/pe-crc-verification-summary.json`. This is reviewed reconstruction of
one internal helper under a declared ABI, not proof of full DLL/JVM/Windows/UI
execution, table generation, compression, archive extraction or generic synthesis.
