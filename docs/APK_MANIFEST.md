# Find Android entrypoints in a shipped APK

Carve0.17 reads compiled AndroidManifest.xml locally through `manifest` / `carve_manifest`. It needs no SDK, Java, decompiler, network or running device. Unpack the APK and index its members first; container/member SHA256 lineage stays available. Your existing agent uses the declarations to choose DEX classes to investigate.

```sh
node dist/cli.js reverse /path/to/app.apk --goal 'Reuse the QR encoding function' --out ./apk-work
node dist/cli.js unpack ./apk-work --file app.apk
# Replace CONTENT below with the unpack response's actual content path.
node dist/cli.js reverse CONTENT --goal 'Reuse the QR encoding function' --out ./member-work
node dist/cli.js manifest ./member-work --file AndroidManifest.xml
node dist/cli.js manifest ./member-work --file AndroidManifest.xml --query Encode --budget-bytes 16384
node dist/cli.js manifest ./member-work --file AndroidManifest.xml --section permissions
node dist/cli.js manifest ./member-work --file AndroidManifest.xml --section nodes --limit 10
```

Resume incomplete inventory/unpack batches before proceeding. `section` accepts components (default), permissions, features or nodes. Literal case-insensitive query filters that section. Follow `nextOffset`; responses keep whole entries and an exact compact UTF8 JSON receipt, within1024–65536 bytes (default8192). Increase the budget when one complete entry does not fit; use observation text pages for very large records. No model-token or billing savings are asserted.

Component cards preserve activity/activity-alias/service/receiver/provider declarations, original attributes and typed data, alias target candidates, actions/categories/data in each intent filter, and the presence of MAIN+LAUNCHER in the same filter. Unqualified or dot-prefixed class names are expanded using the literal manifest package. `codeClassCandidate` is a search lead: inspect actual DEX code and call sites before assigning semantics. An alias points to its target candidate, not a class assumed to exist for the alias itself.

Absent exported/enabled declarations stay null. This reader does not infer Android-version defaults, effective exposure, permissions, availability or intent resolution. A launcher declaration can still refer to a disabled or unavailable component. Resource references retain raw numeric IDs; labels, icons, resource tables, localization and overlays are unresolved. Read root/application/full node attributes through section nodes. Nested queries/other containers do not become application components.

The parser follows [AOSP binary resource structures](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/libs/androidfw/include/androidfw/ResourceTypes.h) and preserves raw attribute type/data beside decoded strings, booleans, signed decimal/hex integers and static references. Limits:8MiB input,32768 strings/16MiB decoded string storage,1MiB per encoded string and expanded XML text,8192 nodes,128 levels,256 attributes per element,32768 total attributes/chunks. Unsupported style pools, text chunks, unknown layouts, plain XML, protobuf/AAB manifests and malformed structures fail explicitly; no partial declaration success is stored. APK ZIP handling and malicious-code sandboxing are separate concerns.

Every query freshly hashes the selected source, checks the bytes actually parsed and rehashes afterwards. A complete closed evidence file is published exclusively before its searchable SQLite observation. Concurrent pages share the same immutable ID; changed evidence is refused. `carve_search`, `carve_context` and `carve_observation` can inspect the recorded result. Context reuse is recorded-index reuse, not a fresh manifest verification.

Manifest evidence has its own source identity and never counts as complete decompiled implementation code. Since0.18, bind it as a separate reconstruction@2 artifact with role:"boundary-support", empty evidenceIds and its own supportingEvidenceIds; the primary and all implementation artifacts still need complete code. Preserve a reviewed/static or hypothetical relationship and its limits. Do not attach the manifest ID to classes.dex or use support to hide unrecovered code. See [multi-artifact roles](MULTI_ARTIFACT.md) and the [actual contact payload case](ZXING_VCARD.md).

## Actual full APK check

The optional check uses the official [ZXing Barcode Scanner4.7.8 APK](https://github.com/zxing/zxing/releases/tag/BS-4.7.8),815360 bytes, local SHA256 `4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3`. The release API has no digest for this old asset; the pinned local hash identifies downloaded bytes without authenticating an upstream signature. Its Apache2 notice is retained with the local input; no application code is distributed in the Carve package.

Carve extracts/indexes the full APK and finds69 manifest elements/100 attributes,9 Activities,9 permissions and5 features. Every ordered element/parent/line and attribute namespace/resource ID/raw string/typed value is independently compared with official [AAPT2 xmltree](https://developer.android.com/tools/aapt2). CLI and actual stdio MCP queries find EncodeActivity. With JADX configured, two complete selected class observations from the shipped classes.dex retain EncodeActivity/QRCodeEncoder use-site leads. These are static records; the app is not installed or executed, and QR encoding, camera, UI events, server behavior and device compatibility are not verified by this check.

For reproduction, install an appropriate official AAPT2 separately (normal Carve manifest queries do not need it), and configure JADX/JDK as for other managed analyses:

```sh
npm run verify:apk-manifest -- --aapt2 /path/to/aapt2 --engines /path/to/engines.json
npm run check -- --apk-manifest --aapt2 /path/to/aapt2
```

The optional script defaults to the local artifacts engine configuration and pinned APK cache. It can download that one official asset if absent; a supplied `--apk` must have the exact pinned hash. It records AAPT2 identity, complete comparison output, selected DEX/source hashes and explicit static-only scope. A missing tool or mismatched APK fails. Ordinary tests use source-owned binary fixtures and never download/install/run an app.
