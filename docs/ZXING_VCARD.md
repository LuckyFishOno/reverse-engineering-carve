# Reuse a contact payload from a shipped Android APK

RECarve0.18 includes a real whole-APK investigation that produces a reusable local function folder. Input: the official [ZXing Barcode Scanner4.7.8 release](https://github.com/zxing/zxing/releases/tag/BS-4.7.8),815360 bytes, local SHA256 `4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3`. This old release has no published asset digest in its API record; local pinning is not an upstream signature authentication claim.

The selected operation is **contact vCard payload text**, the first result from the original `VCardContactEncoder.encode` with phoneTypes=null. It excludes the original display string, non-null phone-type metadata, QR pixels, camera/scanning and UI events. This makes a useful function without assuming those other behaviors have been recovered.

The pipeline inventories/unpacks the complete APK, reads its compiled manifest, selects EncodeActivity and follows actual shipped DEX records through QRCodeEncoder to the contact encoder/formatters. Seven complete selected class observations preserve the reviewed static basis. The manifest binds as a separate [boundary-support artifact](MULTI_ARTIFACT.md); its ID never impersonates DEX code evidence. All selected bytes/evidence are freshly checked before/after packaging and runtime comparison. Static associations remain unconfirmed relationships, not instrumented UI traces or complete dependency closure.

The independent JavaScript function preserves the observed behavior, including details that a fresh vCard formatter might change: Java String.trim removes boundary code units<=32; name/address use the first nonempty value; other lists deduplicate trimmed strings before escaping in input order; backslash/comma/semicolon are escaped; LF is removed but internal CR/control characters remain. It does not repair or certify RFC conformance.

Input is one JSON contact object. Optional fields: names/addresses/phones/emails/urls (arrays of strings/null or null), organization/note (string/null), phoneTypes (absent/null only). Limits:128 elements per list,8192 UTF16 units per well-formed string and32768 combined units; unknown keys are rejected. Output is the exact payload string. These are the reconstruction's admitted domain, not a claim that the original app imposes the same validation limits.

With the resulting folder in the user library:

```sh
node dist/cli.js invoke ./functions/contact-vcard --args '[{"names":["Ada, Lovelace"],"organization":"R&D;Lab","phones":["123","123"]}]' --execute
node dist/cli.js library find ./functions --query vcard
```

Or import its function directly:

```js
import {capability} from './functions/contact-vcard/index.mjs';
const payload = capability({names:['Ada, Lovelace'], emails:['ada@example.test']});
```

The folder needs no original app/SDK or standalone executable. It retains the source comparison, provenance, notices, input domain and unknowns. Importing it into a library preserves recorded comparisons; it does not repeat them. Generated outputs remain UNLICENSED until rights are reviewed; the input's Apache2 notice is retained.

## Actual original execution

A source-owned [reflection adapter](../examples/android/ZxingVCardHarness.java) parses stdin with Android org.json, constructs the original package-private encoder, invokes its original eight-argument method and serializes only result[0]. No original algorithm is recompiled into the adapter. The original method still computes discarded display text via Android PhoneNumberUtils; display output and phone-type ordering are excluded from comparison.

The optional actual check passes160 supplied original-Dex comparisons on Android15/API35 ARM64 ART. Cases include nested/null arrays, Unicode/NUL/BOM, Java-versus-Unicode trim, escape collisions/deduplication, LF/CR differences, name/address caps and admitted input/list limits. A classpath identity does not independently instrument method execution; review the adapter. OS/boot libraries are identified but not comprehensively hashed; this is neither a physical-device test nor an all-input equivalence proof. The app is not installed or driven through its UI.

After verification, the check removes its owned original APK/DEX/manifest invocation paths, rewrite source and intermediate package. The function folder still passes direct module import, restricted invoke, CLI invoke and actual MCP invocation. Analysis snapshots and the upstream cache remain for auditing; it does not claim to delete every copy of the original.

Reproduction requires the existing JADX/JDK/D8 setup, pinned APK cache (obtain with verify:apk-manifest) and an explicitly selected running Android runtime:

```sh
npm run verify:zxing-vcard -- --engines /path/to/engines.json --runtime /path/to/runtime.json
npm run check -- --zxing-vcard --android-runtime /path/to/runtime.json
```

The script does not start a device/server, install an app or change global agent settings. Runtime lifecycle and stdin protocol details are in [ANDROID.md](ANDROID.md). Missing setup or failing original execution fails the check; no reconstructed result is substituted for the original.
