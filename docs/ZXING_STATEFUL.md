# Original APK object lifecycle reconstruction

This case extracts a reusable mutable bit-vector boundary from the shipped ZXing Barcode Scanner4.7.8 APK. It uses RECarve's existing managed JADX backend and an actual Android ART runtime. REA MCP remains independent; this pure DEX case does not launch REA, proxy its tools or claim a native Evidence handoff.

The original APK is the retained [upstream release](https://github.com/zxing/zxing/releases/tag/BS-4.7.8). Local SHA256 is `4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3`; original classes.dex is `cfa20314b24e002b195501a59e02da4b023447b42808eab89b4757406a8ad0e3`. The script pins these bytes, preserves container/member provenance and decompiles the complete com.google.zxing.common.BitArray class. The local hash is an identity commitment, not an authenticated publisher checksum/signature claim.

The [reviewed Java adapter](../examples/android/ZxingBitArraySequenceHarness.java) compiles only framing/reflection code. It creates the original shipped no-argument BitArray once per sequence, invokes its actual methods on ART and snapshots original getSize/getSizeInBytes/get(i) results. It never compiles a replacement BitArray. An additional runtime probe records the resolved class name, classloader, VM identity and empty constructor snapshot. RECarve separately verifies staged DEX/harness hashes before and after comparisons. These observations and source review do not independently trace every method call or prove dependency closure.

## Selected boundary

| Call arguments | Operation and returned snapshot |
| --- | --- |
| `["read"]` | Observe logical length, byte count and a0/1 string |
| `["append",5,3]` | Invoke appendBits(int,int); append the low3 bits in most-significant-first order |
| `["clear"]` | Invoke original clear: zero bits **while preserving length** |
| `["reverse"]` | Invoke original reverse on current logical bits |
| `["set",0]`, `["flip",0]` | Invoke original set/flip at an existing logical index |
| `["new"]` | Explicit adapter lifecycle operation: invoke the original constructor again |

Append values are signed32 integers and counts0–32. Existing-bit indices only; logical size is capped at4096. Each sequence has1–64 calls. Invalid requests are adapter-domain failures, outside the original Java invalid-input/exception behavior. The [independent JavaScript implementation](../examples/android/zxing-bitarray-stateful.mjs) exposes bitArrayStep and returns `{size,sizeInBytes,bits}`. It needs no Android runtime, APK, ZXing or network after packaging.

```json
{
  "schema":"carve/sequence-cases@1",
  "cases":[{
    "name":"clear and constructor differ",
    "steps":[
      {"args":["append",5,3],"expected":{"size":3,"sizeInBytes":1,"bits":"101"}},
      {"args":["clear"],"expected":{"size":3,"sizeInBytes":1,"bits":"000"}},
      {"args":["new"],"expected":{"size":0,"sizeInBytes":0,"bits":""}}
    ]
  }]
}
```

## Reproduce locally

From the RECarve source directory, prepare the configured JADX/JDK/D8 tools and retained APK; verify:apk-manifest is the existing APK acquisition workflow. Start only your explicitly selected private emulator/server using the [Android workflow](ANDROID.md). The verification script requires an already connected serial; it does not start/stop devices, install apps or alter global settings.

```sh
npm run verify:zxing-stateful
# Optional configuration overrides:
node scripts/verify-zxing-stateful.mjs \
  --engines /absolute/engines.json --runtime /absolute/android.json
```

Actual API35 ARM64 ART result: **33 sequences /692 steps**. Cases cover fresh construction without an explicit reset, zero-bit appends, signed32 inputs, lengths around8/32/64/96/128, reversal followed by further mutations, clear with retained length, constructor replacement, one64-step sequence reaching2016 bits and deterministic mixed operations. A deliberately wrong implementation that resets before every operation fails at clear in the first sequence. Six malformed/domain adapter requests are separate protocol checks, not additional original-behavior cases. Two direct adapter invocations also verify fresh VM state. The owned general Android protocol test separately refuses finite JSON that is not the required outcome array.

Full analysis, contract, original/candidate outcomes, negative result, runtime identity, selected-step archive read and reusable folder are under artifacts/zxing-stateful-e2e-*/. The local artifacts/zxing-stateful-verification-summary.json points to the latest successful run and function folder. Construction source/intermediate packages are archived, original APK/DEX retained and unchanged. The function library then passes direct import, CLI and two fresh library-only MCP requests. Complete ordered exampleSequence is preserved; no state-dependent step becomes an independently verified scalar example.

```sh
recarve invoke-sequence /absolute/functions/zxing-bitarray \
  --calls '[["read"],["append",5,3],["clear"],["new"]]' --execute
```

Use carve_library_find/get then carve_invoke_sequence with the stored folder, or import capability from its index.mjs in an existing project. Direct import shares the caller's module lifetime; CLI/MCP sequence requests each start fresh. Snapshot output is a deliberate adapter projection of original logical state, not a recovered original JSON API.

This result is scoped to **selected-dex-android-harness-sequences**. Backing capacity/padding/aliasing, other constructors/methods, clone/equality/hash/toBytes, original invalid-input exceptions, physical phones/other ART versions, QR/scanning/UI/server/hardware, concurrent/timed behavior and state across requests remain unverified. It does not recover a whole application or prove general equivalence.
