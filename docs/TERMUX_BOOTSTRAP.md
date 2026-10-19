# Termux bootstrap inventory across APK JNI

Carve0.26 investigates the existing pinned [Termux app v0.118.3 GitHub ARM64 release](https://github.com/termux/termux-app/releases/tag/v0.118.3). APK SHA256: `72fdb596045116bf5ba1b5bdf5b26fddb9acc0bd074ad9f2da9eb0ae85e83a4e`,35106607bytes. The reusable output is a **ZIP member metadata catalog and a new query projection**, not the ZIP payload or an installer.

## Evidence and original invocation

The whole APK is indexed/unpacked with container/member lineage. A complete class-scoped JADX observation from the APK shows `TermuxInstaller.loadZipBytes()` loading `termux-bootstrap` and returning `getZip()`. The exact member `classes20.dex` declares `getZip()[B`; indexed ARM64 ELF exports give one matching JNI candidate. Ghidra decompilation shows JNIEnv calls at0x580 and0x680. The [JNI function table](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/functions.html#newprimitivetypearray-routines) identifies these64-bit slots as NewByteArray(index176) and SetByteArrayRegion(index208).

Bounded Ghidra data windows identify `blob_size` and `blob`. The case helper derives the loaded image base from the JNI export's ELF virtual address, then requires the complete data range to map to one file-backed PT_LOAD segment. It extracts29388903bytes at file offset1328; SHA256 `c8d702b6f742935001c37cda81b8ac69504a95d5cf28f2899532dd8cd4b057eb`. This is a pinned-case helper, not a general embedded-resource finder. Its central directory contains3490entries.

The [reviewed Java adapter](../examples/android/TermuxBootstrapHarness.java) invokes the original whole-APK `loadZipBytes` by reflection. It hashes the complete native-returned byte array and uses Android's Java ZipFile to enumerate its central directory, then applies the declared prefix/page projection. No original Java/native implementation, precomputed catalog or expected hash is compiled into the harness. It creates/removes only its own temporary ZIP in the private reference-session directory. The original shipped ELF is hash-staged through [android-reference@3](ANDROID.md#shipped-native-jni-libraries), not recompiled.

Local development comparison:80/80 cases on actual Android15/API35 ARM64 ART, including35pages covering all3490metadata rows, prefix/empty/NUL/Unicode/nonmatching queries, page boundaries and the complete returned ZIP hash in every case. These are metadata projection comparisons; they do not prove original ZIP payload recreation or a complete installer. The final local report is indexed by `artifacts/termux-bootstrap-verification-summary.json` in the source checkout.

## Reusable function folder

The closed JavaScript output embeds only copied catalog metadata and the [new query operation](../examples/android/termux-bootstrap-catalog.mjs). It does not bundle Android, the APK, native ELF, ZIP payload, installer or npm dependencies. Input is one plain query object:

```js
import {capability} from '/absolute/functions/bootstrap-catalog/index.mjs';
const page = capability({prefix: 'bin/', offset: 0, limit: 2});
// archiveBytes, archiveSha256, totalEntries, matchedEntries, items, nextOffset
```

`prefix` defaults to empty and is limited to256UTF16 units. `offset` is an integer0..1000000(default0); `limit` is1..100(default20). Unknown fields/coercion are rejected. Entries retain original order, name, uncompressed/compressed sizes, CRC32 and directory flag. Paging applies after exact case-sensitive prefix filtering. Returned rows are copied, so a caller cannot modify later query results through a previous result.

```sh
carve invoke /absolute/functions/bootstrap-catalog \
  --args '[{"prefix":"bin/","limit":2}]' --execute
```

Agents can search/get the returned library folder, import its module or use `carve_invoke`. Source comparison provenance stays recorded; library import does not rerun behavior. The check validates direct module, restricted invocation, CLI and MCP after removing only that check's new original-invocation paths, rewrite and intermediate package. Upstream cached inputs and immutable analysis snapshots remain retained.

## Reproduce and limits

The previously approved pinned APK must already exist in `artifacts/third-party/termux-0.118.3/`. Ghidra/JADX/JDK/D8 and an explicitly selected running Android runtime are required. The upstream license notice is downloaded from the pinned tag only if absent; no APK is automatically downloaded. No app is installed, bootstrapped or launched through its UI.

```sh
npm run verify:termux-bootstrap -- --engines ./artifacts/engines/config.json \
  --runtime ./artifacts/android/config.json
# Optional release integration, alongside existing Android checks:
npm run check -- --android-runtime ./artifacts/android/config.json --termux-bootstrap
```

Separate native protocol checks refuse an owned foreign-ABI header, a non-ELF file and a mutated private remote ELF; cleanup and host snapshot absence are checked for every run. The MCP comparison returns a bounded summary; the full report remains on disk. Measurements compare compact JSON UTF8 bytes with compact JSON and separately record actual summary text bytes; no model token/billing reduction or upstream savings ratio is claimed.

Only this release/primary ABI/identified runtime and supplied cases are compared. ZIP contents, installation, execution, process/PTY state, UI, hardware, server logic, dynamic registration and all-device equivalence remain outside the boundary. OS/boot/native dependency closure is not comprehensively hashed or resolved. The catalog is copied data and the adapter projection is new code, not recovered original Termux source or a claim that Termux exposes this query API. Upstream license notices are retained; the generated output remains UNLICENSED pending review.
