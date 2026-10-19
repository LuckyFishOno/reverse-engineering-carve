# JDK Adler32 across JNI

This optional local check follows a shipped Java API into its native implementation and reconstructs it as a reusable function. The selected behavior is `new java.util.zip.Adler32(); update(bytes, 0, bytes.length); getValue()` in the pinned Temurin 21.0.12.1+1 JDK on macOS arm64.

```sh
npm run verify:jni-adler32
# Or include it in the local release checks:
node scripts/check-release.mjs --jni-adler32
```

## Boundary evidence

1. **Java declaration:** `jni` reads `Adler32.class`, unpacked from `java.base.jmod` by the JDK's own `jmod extract`. It finds `static native int updateBytes(int, byte[], int, int)` and derives `Java_java_util_zip_Adler32_updateBytes`.
2. **Export:** the loader-only libzip export index has that symbol as the only candidate.
3. **Java code:** JADX decompilation of the class shows the `adler = 1` initial state, `update` calling `updateBytes`, and `getValue` widening the int as unsigned.
4. **Native code:** Ghidra decompiles three functions, followed through actual callee records:
   - the JNI entry, which reads JNIEnv slots `0x6f0`/`0x6f8` (Get/ReleasePrimitiveArrayCritical) and calls `adler32`;
   - `adler32`, which calls `adler32_z`;
   - `adler32_z`, which uses modulus `0xfff1` (65521) and reduces every `0x15b0` (5552) bytes.
5. **Runtime:** one JVM run with `-Xlog:jni+resolve` and `-Xlog:library` logs `Dynamic-linking native method java.util.zip.Adler32.updateBytes ... JNI` and the load of the JDK's `lib/libzip.dylib`. These are link/load logs, not per-call tracing.

The contract binds both artifacts:

- **java:** complete JADX code, plus the JNI declaration record as support.
- **native:** three complete Ghidra code records, plus the export record as support.

It also records a reviewed-static `calls` relationship between them.

## Reconstruction and comparison

`examples/jvm/adler32.mjs` is a closed JavaScript loop with no JVM, JNI or native dependency. The reference is the source-owned adapter `examples/jvm/Adler32Harness.java`. It reads raw stdin bytes, calls the installed JDK's `java.util.zip.Adler32` and prints `getValue()` as JSON. The adapter contains no checksum code. Its class, source, `lib/libzip.dylib`, `lib/modules` and `libjvm.dylib` are hashed as bound files.

HotSpot enables an Adler32 JIT intrinsic by default (`UseAdler32Intrinsics`, a diagnostic flag), and that intrinsic can bypass libzip. The comparison therefore runs the interpreter with `-Xint -XX:+UnlockDiagnosticVMOptions -XX:-UseAdler32Intrinsics`. Intrinsic equivalence is not claimed.

Actual local result: **160/160 cases** through the installed JDK. The cases cover lengths 0–99, the 5552/11104/16656 reduction boundaries, all-0xff and all-zero runs, known vectors (`abc`, `Wikipedia`), all byte values, Unicode bytes and random lengths up to 16657 bytes. Longer inputs were not compared, because the cases file is limited to 1 MiB.

The function folder `adler32` is checked after the intermediate package and rewrite source are removed:

- direct import;
- restricted fresh-process invoke;
- actual stdio MCP.

The JDK stays installed.

## Runtime confirmation of the static JNI results

The same `jni+resolve` log confirms the [JNI boundary](JNI.md) classification for `java.lang`. A `java -version` start registers exactly the 23 `Object`/`Thread` natives that `jni` reported without a static export, through the JVM and `Thread.registerNatives`. It links `Object.getClass` and `Thread.registerNatives` by their exported names. `verify:jni` now asserts both facts.

## Limits

This is one small checksum crossing a Java class and a native library. That original whole-array check does not reconstruct: `update(int)`, ByteBuffer/direct-memory paths, offsets, `reset` and multi-call state. Signatures and JNIEnv slot meanings are analyzer/JNI-table interpretations. The analyzed class bytes come from `java.base.jmod`, while the JVM executes the same build's `lib/modules`. The report is the authority for actual run status.

## Incremental lifecycle follow-up

Version0.32 adds a separate [stateful REA companion case](JDK_STATEFUL.md):31 sequences /405 steps covering initialization, incremental whole-array chunks, empty updates, getValue and reset. It extracts the analyzed class from the runtime lib/modules image and checks the bootstrap class resource hash. Three native functions come from the independent REA MCP; the JNI terminal-boundary warning is retained and its original ARM64 B target checked. This does not rerun or relabel the earlier160 whole-array report; offsets, ByteBuffer, update(int), exceptions and default intrinsic behavior remain excluded.
