# Bounded PE resource API argument leads

The dependencies view of `pe-ui` / `carve_pe_ui` may attach `resourceApi` to byte-bound import calls. This supplements [direct resource payload references](PE_RESOURCE_LINKS.md); it does not turn numeric-ID guesses into complete resource bindings.

## Supported declarations and parameters

The analyzer recognizes exact imported A/W function names from these declared modules. The table shows x64 register roles; x86 uses the same positional parameters in32bit stack slots:

| Module | API | Numeric parameter interpretation |
| --- | --- | --- |
| user32.dll | LoadStringA/W | RDX string ID; candidate type6/block floor(ID/16)+1 and string index ID%16 |
| user32.dll | LoadMenuA/W | RDX resource name/ID; type4 |
| user32.dll | LoadAcceleratorsA/W | RDX resource name/ID; type9 |
| kernel32.dll/kernelbase.dll | FindResourceA/W | RDX name/ID, R8type/ID |
| kernel32.dll/kernelbase.dll | FindResourceExA/W | RDXtype/ID, R8name/ID, R9requested language |

These roles follow Microsoft's [LoadStringW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringw), [LoadMenuW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadmenuw), [LoadAcceleratorsW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadacceleratorsw), [FindResourceW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcew), [FindResourceExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourceexw) and [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention) documentation. The imported spelling is a declaration, not authentication of the loaded DLL/function. Only numeric values0–65535are interpreted in this implementation; larger constants and name pointers remain unresolved. No named-string pointer decoding, ANSI conversion or API-set ordinal routing is performed.

## Instruction evidence

The call must decode from original bytes at an imported typed call location or a recorded unresolved-call instruction address. Its full original call instruction must lie in the captured function body, and the IAT slot must have one unambiguous declaration. Jumps, arbitrary byte-pattern scan hits and callee names without call locations do not qualify. An unresolved-call record remains unresolved even when its original bytes yield an import/argument lead; it is not promoted into a resolved dependency edge or traversal target.

The analyzer decodes forward from the exact recorded function entry to the call. The prefix must fit one executable file-backed section, one captured body range,256bytes and64instructions. For x64 it supports register immediate moves, register copies, self-XOR zeroing, canonical RSP immediate adjustments, RSP-relative LEA stack addresses and single-byte NOP.32bit register writes zero-extend; stack addresses and entry register values remain unknown. Unsupported memory/arithmetic instructions, branches, preceding calls, other control flow, truncation and limit violations stop the analysis and discard argument conclusions. ARM and unsupported instruction forms remain unresolved. This is a narrow whitelist decoder, not a general disassembler or control-flow/data-flow engine.

For x86, a separate whitelist follows Microsoft's [stdcall right-to-left argument passing](https://learn.microsoft.com/en-us/cpp/cpp/stdcall). It tracks32bit immediate/register pushes, sign extension of8bit pushed immediates, register pops, register moves/self-XOR and four-byte-aligned ESP immediate adjustments. At most64stack words are retained. ESP/EBP-relative LEA addresses, loads and memory pushes produce unknown values; entry registers/memory are unknown. A pushed value remains independent of later changes to its source register. Unmodeled memory writes, stack realignment, explicit ESP replacement, other instructions, branches and calls discard conclusions. No stack frame, buffer validity, stack cleanup correctness or execution success is inferred.

`prefix` retains exact source offset/bytes, decoded operations and completion status. Known arguments are hexadecimal values and unknowns are null: x64 uses rcx/rdx/r8/r9, while x86 uses stack0/stack1/stack2/stack3 at the pre-call stack top. `callingConvention` discloses windows-x64-registers or x86-stack-arguments. Source/snapshot identities remain pinned by the parent dependency report and source hashes are rechecked before publication.

## Candidate scope

`caller-image-candidates` lists matching supported parsed resource blocks in the caller image, with exact paths, payload hashes and bounded8candidate previews. `candidatesTotal/candidatesTruncated` retain coverage; `no-caller-image-match` does not exclude another image or unsupported resource type. `arguments-unresolved` identifies unsupported/unknown parameter recovery. `counts.byResourceApiStatus` summarizes emitted API rows, not unique executed calls.

Module handles are never automatically bound to the caller image, even if null or a literal preferred image base. All results retain `moduleBinding:unverified`, `languageSelection:unverified` and `runtimeUse:unverified`. A known requested language is recorded and compared to each listed path, without silently filtering alternatives or simulating fallback. Import forwarding, actual DLL search, MUI/remote modules, resource loading success, buffer validity, API side effects and Windows/UI execution remain unverified.

These are investigation leads only. The existing reconstruction resource pin still requires an exact imported data target inside one unique payload. An API candidate alone does not meet that requirement or establish complete dependencies.

## Real producer probe

`npm run verify:pe-state` additionally compiles `examples/pe-feature/resource-api.c` into separate owned x64 `probe.exe` and x86 `probe32.exe` images with a LoadStringW import and constant1001argument. The source declares the Windows API stdcall convention explicitly; the narrow trusted COFF fixture linker supports only the required x64 REL32/x86 DIR32 import relocation forms. Independent REA/Ghidra captures real code/info/relationship records before RECarve imports them. Both probes must produce byte-bound string-table63candidates while preserving module uncertainty and any unresolved-call coverage. `resource-api-boundary.json`, `resource-api32-boundary.json`, complete UI/native evidence and both probe images are retained/pinned.

Neither probe is executed. The existing40sequence/926step original state/resource machine-code comparison remains a separate declared-harness check and does not execute either Windows API probe. No Windows/API/UI runtime equivalence is inferred from static parameter results.
