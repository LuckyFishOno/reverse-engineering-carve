# JNI boundaries

RECarve 0.21 connects the Java/Android side of an application to its native libraries. `jni` / `carve_jni` reads the `native` method declarations in selected Java class or DEX files and derives each method's JNI symbol names. It then compares those names with the loader export pages already indexed for native libraries. No engine runs and no target code executes.

## Workflow

```sh
# 1. Unpack the APK/JAR and survey it, so class/DEX/.so files are indexed.
carve unpack ./work --file app.apk
# 2. Index complete export pages for each candidate library (loader only, no auto-analysis).
carve native ./work --file lib/arm64-v8a/libapp.so --ghidra /path/to/ghidra --java-home /path/to/jdk --linkage exports --limit 1000
# Repeat with --after NEXT_CURSOR until nextCursor is null.
# 3. Match declarations to exports.
carve jni ./work --file classes.dex classes2.dex --library lib/arm64-v8a/libapp.so
```

MCP: `carve_jni` with `files` (1–500 indexed class/DEX paths), optional `libraries`, `query`, `limit`, `offset` and `budgetBytes`.

## What it records

- **Declarations:** for each selected file, every method with `ACC_NATIVE`, giving its owner class, name, descriptor, static flag and overload flag. Class files are parsed per JVMS chapter 4, DEX files per the Android DEX format, and both decode modified UTF-8 strictly. The declarations are saved as immutable `jni-declarations` evidence (`jni-evidence/<id>.json` plus an observation row). Source bytes are freshly hashed before and after parsing.
- **Names:** the JNI short name `Java_<class>_<method>` and long name `<short>__<argument signature>`. Mangling follows the JNI specification: `_1`, `_2`, `_3`, `_0xxxx` for other UTF-16 units, and `/` becomes `_`. For an overloaded native method, only the long name identifies one overload, and the result says so.
- **Matches:** exact export names in libraries whose export index matches the current inventory. On Mach-O, the leading-underscore form also counts. On ELF, a leading-underscore symbol is not treated as a JNI name. Each library reports whether its export pages are known complete, a continuation cursor, and any `JNI_OnLoad` / `JNI_OnLoad_<lib>` exports.

## Statuses

| Status | Meaning |
| --- | --- |
| `static-export-candidate` | Exactly one library exports a matching name. |
| `multiple-library-candidates` | More than one library exports a match, for example per-ABI copies or a decoy. |
| `no-indexed-static-export` | No match in the indexed pages. Some pages are incomplete, or some library exports `JNI_OnLoad`; those libraries are listed as `dynamicRegistrationLeads`. |
| `no-static-export-in-complete-index` | Every selected export index is complete and no library exports `JNI_OnLoad`. Registration by the runtime itself (as the JVM does for `java.lang.Object`) is still possible. |

A static-export candidate is not a binding. RECarve does not establish which library `System.loadLibrary` loads, whether `RegisterNatives` overrides the static name, ABI/architecture selection, signature correctness or behavior. Requested libraries without an export index, and native artifacts without one, are reported.

## Real check

`npm run verify:jni` (or `npm run check -- --jni`) uses the pinned Temurin 21.0.12.1+1 JDK. The JDK's own `jmod extract` tool unpacks `java.base.jmod`:

- **java.util.zip classes → libzip.dylib:** all **27** native declarations match the 27 `Java_` exports, and the derived names equal Apple `nm -gU` exactly. The export index is complete, and every match is a single short-name candidate.
- **Official D8 (r8 9.5.26) DEX of the same class bytes:** gives the same 27 declarations and matches.
- **java.lang.Object/Thread → libjava.dylib:** 3 static-export candidates, matching `nm`. The other 23 declarations, for example `Thread.start0`, are reported as `no-indexed-static-export` with libjava's `_JNI_OnLoad` as a lead. A `java -version` start with `-Xlog:jni+resolve` registers exactly those 23 natives at runtime, and links `Object.getClass` and `Thread.registerNatives` by their exported names. The check asserts both facts.
- **Shipped scrcpy 5.0.1 and ZXing 4.7.8 DEX files:** parse without errors. They declare no native methods according to this parser; no other DEX tool was used to confirm that count.
- **MCP `carve_jni`:** returns the three Adler32 candidates.

Unit tests use javac/D8-generated fixtures, with expected names taken from `javac -h` JNI headers, covering overloads, `_`, `$` inner classes and non-ASCII names.

Apart from that one JVM start, this check does not observe library loading, trace `RegisterNatives` call sites or verify native behavior. For a behavior case across JNI, see [JDK Adler32](JNI_ADLER32.md).

## Original APK JNI runtime case

The [Termux bootstrap inventory](TERMUX_BOOTSTRAP.md) follows a shipped APK's `TermuxInstaller.loadZipBytes()` through `System.loadLibrary("termux-bootstrap")` and `getZip()[B` into the exact ARM64 ELF. Static export matching stays a candidate; separate actual ART comparisons exercise the reviewed call. The reusable function is a copied ZIP metadata catalog with a new prefix/page projection. It does not reproduce ZIP payload bytes, bootstrap installation or a preexisting Termux catalog method. Dynamic registration tracing remains unfinished.

Use [Android reference version3](ANDROID.md#shipped-native-jni-libraries) to hash-stage explicit ELF libraries outside the DEX classpath. Staged identities alone never become runtime invocation proof.
