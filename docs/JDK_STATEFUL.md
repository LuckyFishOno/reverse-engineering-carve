# Third-party JDK Adler32 lifecycle

This optional local case investigates the shipped Temurin21.0.12.1+1 JDK on macOS arm64. The behavior is one java.util.zip.Adler32 object initialized once, then updated with successive whole byte-array chunks, read and explicitly reset. The [Java21 API](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/zip/Adler32.html) defines update/getValue/reset; selected compiled bytes and original observations determine this reconstruction. The [zlib checksum manual](https://zlib.net/manual.html#Checksum) documents the underlying incremental checksum interface; its current version is not assumed to be the version embedded in the pinned JDK.

```sh
npm run verify:rea-adler32-stateful
# Explicitly reuse a prior local REA installation instead of a new install:
node scripts/verify-rea-adler32-stateful.mjs --rea-install /path/to/local/prefix
```

The default makes a fresh pinned REA6.7.0 project-local installation with install scripts disabled and no global setup. Existing engines/config.json supplies Ghidra12.1.4, JDK and JADX. This is a local test client, not a new or merged MCP server. The recorded0.32 run had207 REA tools and43 Carve tools (0.35 adds carve_scope as the44th). Carve is configured only for its existing JADX managed-analysis path in this case, while REA performs all native decompilation.

## Evidence and runtime identity

1. The JDK jimage tool extracts exactly java/util/zip/Adler32.class from the runtime lib/modules image. The class and native libzip hashes are pinned. No original checksum function is recompiled.
2. Independent REA analyzes the copied libzip and saves12 complete code/info/callees/outgoing-reference records for the JNI updateBytes entry, adler32 wrapper and adler32_z core. REA closes before Carve imports its owned snapshots; external producer paths are later archived.
3. Carve's JADX path decompiles the entire original class, including field initialization/reset to1, previous state passed to native updateBytes, and unsigned getValue widening. The JNI declaration parser retains its own source identity. Export metadata is deliberately not indexed in this run; its no-indexed-static-export status remains explicit. The exact REA JNI name, reviewed class call and runtime probe are separate evidence.
4. The eight-byte adler32 wrapper carries an actual Ghidra terminal-call boundary warning. The [narrow snapshot@3 policy](REA_NATIVE.md) checks the original last ARM64 B-immediate instruction against the typed target while preserving that warning. The provider flow-model reason and dependency closure stay not-established; graph completeness is not inferred from successful import.
5. A source-owned [Java invocation adapter](../examples/jvm/Adler32SequenceHarness.java) constructs the original JDK object. Its identity probe reads the bootstrap java.base class resource and checks the exact analyzed class hash, module, bootstrap loader and java.home. All three compiled harness classes, source, lib/modules, libzip and libjvm are bound reference files.
6. An actual probe with JNI/library logs shows updateBytes linked through JNI and the pinned JDK libzip loaded. Comparisons use -Xint, disabled diagnostic UseAdler32Intrinsics and -Xshare:off. The logs cover one probe, not per-call tracing or default-JIT/intrinsic equivalence.

The reconstruction@2 contract binds both implementation artifacts: the full class plus JNI declaration support, and all three complete REA native code observations. Its Java-to-native relationship remains reviewed-static and semanticMatch:unconfirmed. Raw records/selected source bytes are rebound on packaging and verification.

## Operation boundary

The JSON wrapper is a Carve-facing interface, not the original Java method signatures:

| Call | Original operation | Observed result |
| --- | --- | --- |
| `[0]` | getValue() | Current unsigned checksum |
| `[1,[87,105,107,105]]` | update(bytes,0,length), then getValue() | Updated checksum |
| `[2]` | reset(), then getValue() | Initial checksum1 |

Valid chunks contain0–65536 integer bytes0–255. One sequence owns one original Adler32 object and one candidate module instance; a new request starts fresh. Empty byte-array update preserves existing state. The adapter has a narrow bounded JSON parser; it frames operations and contains no checksum algorithm. Malformed inputs are rejected before execution/output. Input validation policy is not claimed as recovered Java exception behavior.

The independent [JavaScript implementation](../examples/jvm/adler32-stateful.mjs) needs no JDK/JNI/native library at invocation time. It carries two running sums from the previous state, modulus65521, and5552-byte reduction blocks. reset and initialization follow the compiled class evidence.

## Actual checks and reuse

31 sequences /405 steps compare the original installed JDK object with the reconstruction through [reference@3](STATEFUL.md). Cases cover initialization without reset, known Wiki→pedia chunks, empty updates after existing data, repeated reads/reset, reduction boundaries5551/5552/5553 and multiple blocks, deterministic mixed lifecycles and unsigned outputs above2147483647. A deliberately wrong implementation that restarts its sums on each update fails later steps. Passing covers these supplied valid inputs and the declared adapter boundary only.

The source remains explicitly declared-external-harness-sequences, not an original-application CLI. The retained report contains all sequence/step results, selected class/native commitments and runtime flags. Invalid framing/byte/count requests are separately checked; those are adapter tests, not additional third-party behavior cases.

The named local function folder preserves the complete exampleSequence and original scope. Direct import, CLI invoke-sequence and two fresh library-only-root MCP requests work after this run's construction source and intermediate package are archived. Original JDK and analyzed input bytes remain unchanged and retained.

```sh
node dist/cli.js invoke-sequence FUNCTION_FOLDER \
  --calls '[[0],[1,[87,105,107,105]],[1,[112,101,100,105,97]],[0],[2]]' --execute
```

Expected step values for that complete sequence are1,64618901,300286872,300286872,1. Use carve_library_find/get to locate the actual folder and carve_invoke_sequence to reuse it. Reports are saved under artifacts/rea-adler32-stateful-e2e-*/report.json; rea-adler32-stateful-verification-summary.json points to the latest result and records whether REA was freshly installed or reused.

## Limits

This is a bounded shipped Java/native operation, not full JDK/zlib/application recovery. update(int), explicit offsets/lengths, ByteBuffer/direct memory, original exception names/messages, parallelism, timing and default intrinsic execution are excluded. No persistent session across MCP requests, arbitrary initial-memory discovery, OS/files/network/hardware behavior or absent server reconstruction is established. Provider records and byte hashes check consistency, not producer authentication or general behavior/dependency equivalence. The earlier [whole-array JNI case](JNI_ADLER32.md) retains its separate160-case scope and is not relabeled as this run.

Boundary warnings are automatically bound into reconstruction evidence/provenance, make packaging status packaged-with-unknowns even when the agent omits manual unknowns, and remain in verification analysisWarningCount/metadata and function-folder usage. Passing supplied cases never clears them. Preview fields are bounded; full statements remain in the manifest and owned records.
