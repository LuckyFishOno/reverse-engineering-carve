# Reviewed instruction and ABI bindings

Version2 reconstruction implementation artifacts may optionally declare
`instructionReviews`. These retain original byte witnesses, complete committed REA
instruction records and a separately declared ABI. They do not replace inferred
pseudocode signatures or establish that a declared ABI is correct.

This addresses cases such as [the real CRC helper](PE_CRC.md), where Ghidra infers
a void prototype and elides computation even though original instructions use R9
and return a value in EAX. Packaging preserves both observations and declarations.

Each review contains:

| Field | Meaning |
| --- | --- |
| observationId | Complete selected imported PE/REA implementation observation |
| instructions.file | Relative regular file inside the artifact workspace, without redirects |
| instructions.sha256 | Hash of the exact complete REA read_function_instructions JSON file |
| inferredSignature | Exact signature retained in the imported function record |
| difference | Agent explanation of the declared ABI and inferred-prototype difference or review boundary |
| abi.convention | windows-x64; currently requires an AMD64 PE input |
| abi.parameters | Up to four uniquely named RCX/RDX/R8/R9 arguments with uint32, uint64 or pointer type and descriptions |
| abi.result | EAX/uint32, RAX/uint64 or pointer, or none/void |
| bytes | One to sixteen ordered nonoverlapping original byte ranges, each address/length/SHA256 |

Byte range lengths are 1–256. Each range starts at a listed instruction coordinate
and ends at another listed coordinate or the end of one imported body range.
The range must map to exactly one executable, file-backed PE section. Original bytes
are read and hashed; disassembly is not independently decoded or authenticated.
Instruction text remains a source-bound producer observation rather than proof of
instruction semantics or boundary correctness.

The instruction record's semantic commitment, raw/normalized result consistency,
source SHA256, format, architecture, provider, profile digest, exact function selector,
name, external/thunk flags and complete body metadata must match the imported observation.
Pseudocode SHA256 and inferred signature are retained alongside the agent ABI. Paths
are authorized before reading. Nonregular files, symlinks, redirects, changed pins,
guessed observations, stale sources/signatures and incompatible architectures fail.

Limits: 16 reviews per artifact, 32 per contract, one review per selected observation;
each instruction JSON file is at most 1 MiB and cumulative files per artifact at most
4 MiB. Existing imported snapshot limits still apply. Artifact boundary-support roles
cannot declare instruction reviews. Contracts without the optional field keep their
previous shape and do not gain default fields.

Provenance includes the instruction file hash/semantic ID/provider/profile/selector,
source and imported snapshot hashes, original byte hex/file offsets/sections and the
declared ABI/difference. Byte witnesses retain the count and complete selected listing
hash, with a bounded preview of 16 lines of 512 characters. Truncation is explicit;
the pinned instruction file contains the complete listing. These are unsigned local
integrity records. They do not prove producer execution, calling convention correctness,
pointer extents, ownership, lifetime, register preservation or semantic equivalence.

Any review adds `unverifiedInstructionReviews` and forces `packaged-with-unknowns`.
Packaging binds again after building; `verify-reconstruction` rebinds before and after
comparison. Changed instruction evidence, source bytes, imported records or packaged
review provenance are rejected. A finite later comparison does not silently promote
the declared ABI into a universal proof.

The existing CLI/MCP reconstruct operations read the same contract field. The real
CRC and [initializer/dispatch](PE_CRC_DISPATCH.md) integrations copy independent REA
instruction records into `work/instruction-evidence`, bind reviewed ABI/byte witnesses,
pin those files in executable acceptance and retain original-free module/MCP reuse.
The source workspace/evidence is required for later rebinding, but not for invoking
the independently packaged implementation.

Reviewed interfaces may additionally feed [generated bounded PE verification tasks](PE_VERIFICATION_TASKS.md).
The optional preparation step writes a fixed runner and pinned reference without
executing either program; explicit comparison is still required.
