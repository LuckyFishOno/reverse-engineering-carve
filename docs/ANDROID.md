# Android runtime reference

RECarve can compare a reconstruction against exact selected DEX/archive bytes on an explicitly selected Android runtime. This is separate from JVM/source-equivalent references. It requires trusted execution authorization, an already running ADB server/device and a small reviewed DEX invocation harness.

## Actual third-party case

The pinned [scrcpy v5.0.1 release](https://github.com/Genymobile/scrcpy/releases/tag/v5.0.1) Android server is an Apache-2.0 input. Its official asset SHA256 is `764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536`. RECarve unpacks the release, retains the container/member hashes, and analyzes `Size` and `VideoConstraints` with JADX. The reference invokes the original shipped DEX methods through [a RECarve-owned reflection adapter](../examples/android/ScrcpySizeHarness.java); no original algorithm is recompiled into the harness.

Selected behavior: `Size.constrain(constraints, preserveAspect)` where encoder capabilities are null. Preserve aspect-ratio selection, max-size clamp, alignment and signed-int32 arithmetic. The [independent implementation](../examples/android/scrcpy-size.mjs) has no Android dependency. Hardware codec constraints, capture/encoding, UI/server and non-int32 inputs remain outside the selected boundary.

Actual local result: **160/160 cases on Android 15 / API35 ARM64 ART**, plus standalone CLI/invoke after original invocation paths and implementation sources were removed. The emulator is a real Android runtime, not a physical phone or evidence about every device. Analysis snapshots remain retained for auditing. The whole-release JADX attempt failed with 73 errors; successful class-scoped analyses do not turn that into full-app recovery. Raw fallback instructions were used to resolve a high-level control-flow ambiguity.

## Prerequisites and selection

Install [Android platform tools](https://developer.android.com/tools/releases/platform-tools) and provide an authorized device or [emulator](https://developer.android.com/studio/run/emulator-commandline). This host used an isolated AOSP API35 arm64 emulator and a custom ADB server on port5039, with separate SDK/AVD/user directories under local artifacts. No physical device or global agent configuration was changed.

Reference verification requires an explicit serial. It does not pick the first connected device, install apps, request root, remount, wipe or start/stop an emulator. Start the server explicitly first; preflight refuses an absent server. Standard ADB client behavior and device authorization still apply. Custom server ports can keep development traffic separate from another ADB instance.

For example, after creating your private emulator configuration:

```sh
adb -P 5039 --one-device CARVE_NO_USB start-server
# Start your configured emulator with an even console port, e.g. 5580,
# and ANDROID_ADB_SERVER_PORT=5039. Verify its readiness:
adb -P 5039 devices -l
adb -P 5039 -s emulator-5580 shell getprop sys.boot_completed
```

`CARVE_NO_USB` is a deliberately unmatched USB selector for this development server. An emulator's serial/ports must match its actual startup configuration. The tool itself uses only the explicit configured serial/server. Do not copy commands that stop/wipe an unrelated device.

## Local development emulator launcher

From a source checkout with an existing SDK, AVD and runtime configuration:

```sh
npm run build
npm run android:emulator -- --config ./artifacts/android/config.json --check
# Start the selected private ADB server explicitly, then run in the foreground:
npm run android:emulator -- --config ./artifacts/android/config.json
```

The development helper resolves SDK/AVD/user paths against the real configuration file, including when the caller uses another working directory or a configuration symlink. It requires `sdkRoot`, `adb`, `emulator`, `image`, `avdHome`, `userHome`, `avd`, `serial`, `consolePort` and `serverPort`. The console port must be even and agree with `serial`; the ADB server port must be separate. `--check` reads paths and probes localhost IPv4 sockets without invoking ADB or the emulator. It does not prove that a listening server is ADB or that Android has booted.

Before launching, the helper refuses an absent ADB server or occupied emulator ports. It never stops an existing process. AVD `.ini` files contain an absolute `path=` even when the SDK configuration uses relative paths: after moving the folder, review that entry yourself. The helper refuses a missing or mismatched entry and does not rewrite AVD metadata, reset userdata or delete lock files. An already-running emulator must be stopped through its verified owner before moving it. Port inspection is a preflight check, not an exclusive reservation against concurrent launchers.

The emulator stays in the foreground; interruption signals are forwarded to that newly spawned child. The helper never starts or stops ADB. After startup, separately verify the actual AVD name, `sys.boot_completed`, build/API/ABI and current process/port ownership before comparisons. After stopping the owned emulator and private server, observe process and port absence instead of trusting a historical PID. SDK installation and this development script are not bundled in the installed RECarve package; normal reference verification still accepts any explicitly selected authorized runtime.

## Reference configuration

```json
{
  "schema": "carve/android-reference@1",
  "adb": "/absolute/sdk/platform-tools/adb",
  "serial": "emulator-5580",
  "serverPort": 5039,
  "harness": "/absolute/path/to/harness.dex",
  "entryClass": "carve.reference.ScrcpySizeHarness",
  "dependencies": [],
  "description": "Reflection adapter calls the original DEX method with null codec capabilities"
}
```

`harness` and optional classpath dependencies are precompiled DEX or DEX-bearing archives. Compile only the adapter, using a JDK and D8. The selected original DEX/archive is automatically taken from the package's bound reconstruction contract, placed first on the runtime classpath and rehashed; it must not be substituted by recompiled source. Java `.class` input is refused for direct ART execution. AAB/AAR/other archives must actually contain executable DEX for this path to work; format recognition alone does not make them executable.

```sh
carve verify-reconstruction ./work --package ./independent-tool \
  --cases ./cases.json --reference ./android-reference.json --execute
```

The invocation harness takes scalar positional arguments and emits exactly one JSON value on stdout. stderr remains diagnostic. Harness exceptions/nonzero exits, non-JSON/nonfinite results, >1 MiB output and deadlines fail. Each case starts a fresh VM process. ADB shell argv is individually quoted; strings are data. A remote `timeout` process bounds VM execution even after the host transport is cancelled, with up to two seconds of host transport allowance. A pending remote process may remain until that deadline after cancellation.

RECarve snapshots exact host bytes, creates a random `/data/local/tmp/carve-*` directory, pushes read-only files, verifies remote SHA256 before and after the cases, records Android build/API/ABI plus ART executable/version/hash, and removes its private staging directory. Host snapshot copies are removed; logs and identity evidence remain in `WORKSPACE/verification/android/run-*`. A transport failure can prevent cleanup and is reported explicitly.

## Structured Android arguments

RECarve0.18 also accepts `carve/android-reference@2` with the same fields plus explicit `mode:"json-stdin"` or `mode:"argv-values"`. Version1 remains scalar argv without silent changes. JSON-stdin sends the complete positional argument array as UTF8 JSON through ADB stdin to the VM, with no case values added to the shell command/argv. A reviewed harness must read stdin, parse the JSON and invoke the original method. It supports nested objects/arrays/null and NUL inside JSON strings; plain finite JSON only, no undefined/functions/BigInt/cycles or implicit toJSON conversion. Input is limited to1MiB before a per-case process starts. JSON stdout remains mandatory; the existing combined output cap, fresh processes, remote timeout, identity checks and cleanup apply. The recorded runtime includes inputMode.

This is a data transport, not automatic method discovery or an Android ABI bridge. The owned structured protocol check echoes nested/NUL/Unicode/shell-looking values and a300000-byte string on actual ART, keeping it separate from third-party feature cases. The [shipped APK contact case](ZXING_VCARD.md) uses it for a structured contact object and compares160 original payload results through reflection.

## Ordered Android object operations

RECarve0.33 adds `carve/android-reference@4` with required `mode:"json-sequence-stdin"`. Use the same explicit adb/serial/serverPort/harness/entryClass/dependencies/description fields as above. Versions1–3 remain scalar. Optional named nativeLibraries use the version3 staging and ABI checks; the new managed-object integration does not establish JNI stateful coverage.

```json
{
  "schema":"carve/android-reference@4",
  "mode":"json-sequence-stdin",
  "adb":"/absolute/sdk/platform-tools/adb",
  "serial":"emulator-5580",
  "serverPort":5039,
  "harness":"/absolute/sequence-harness.dex",
  "entryClass":"carve.reference.ZxingBitArraySequenceHarness",
  "dependencies":[],
  "description":"Reviewed adapter retains one original BitArray per sequence; new explicitly invokes its original constructor again"
}
```

Use [sequence-cases@1](STATEFUL.md) with1–200 uniquely named sequences,1–64 calls each and at most1000 total steps. Each sequence starts one fresh original ART VM and one fresh candidate Node module. All calls arrive in one stdin array; the reviewed harness must invoke the original methods on the intended shared object and emit exactly one return/throw outcome per call. RECarve validates outcome shape/count. A finite JSON echo, missing outcome, process/protocol failure, timeout or excessive output is a harness error, never a target exception. An explicit lifecycle operation such as new belongs to the adapter boundary and must be labeled.

The existing whole-sequence deadline is50–30000ms; the remote timeout bounds the VM and host transport allows up to two additional seconds. Input/output limits and per-run byte hashing/cleanup remain unchanged. Runtime schema android-runtime@2 records inputMode:json-sequence-stdin, processLifetime:one-sequence, freshVmPerSequence:true and crossSequenceVmState:false. Object retention is defined by the reviewed harness; these fields are not independent method instrumentation. OS/device state can persist between processes.

The report scope is **selected-dex-android-harness-sequences**, with sequence and step counters plus complete exampleSequence preserved through archive, usage and library. Separate invocation requests start fresh. See the [original shipped APK BitArray case](ZXING_STATEFUL.md):33 sequences /692 steps on API35 ARM64 ART, using original DEX and an adapter compiled without the target algorithm. Host-JVM examples remain separately scoped.

## Shipped native JNI libraries

RECarve0.26 adds `carve/android-reference@3` for a selected DEX-bearing target plus explicitly declared native libraries. It retains version2's input modes; versions1/2 do not accept native-library fields.

```json
{
  "schema": "carve/android-reference@3",
  "mode": "json-stdin",
  "adb": "/absolute/sdk/platform-tools/adb",
  "serial": "emulator-5580",
  "serverPort": 5039,
  "harness": "/absolute/harness.dex",
  "entryClass": "carve.reference.TermuxBootstrapHarness",
  "dependencies": [],
  "nativeLibraries": [
    {"file": "/absolute/libtermux-bootstrap.so", "name": "libtermux-bootstrap.so"}
  ],
  "description": "Reviewed adapter invokes original DEX loadZipBytes/getZip JNI and projects ZIP metadata"
}
```

Each library has a unique portable `lib*.so` basename (up to20 libraries). RECarve snapshots it, verifies the snapshot hash and checks a little-endian ELF shared-object header against the selected device's primary ABI: arm64-v8a, armeabi-v7a, x86 or x86_64. It does not automatically select another ABI. Limits are64MiB per native library and256MiB total. ELF header compatibility is a preflight check; a malformed file or unresolved dependency can still fail at the real loader.

Native files are staged under the session's private `lib/` directory, separately from the DEX classpath. ART receives `-Djava.library.path` for that directory. The original class or reviewed harness must actually load/invoke the library. Host reference bindings and before/after remote hashes include native bytes; runtime metadata records their role, ELF header/ABI and remote paths. Native staging, all failure paths and tamper checks share the existing private-directory cleanup.

`nativeLibraryBytesVerified` means exact bytes were staged and hashed. It does not mean every library loaded, a JNI method ran, `RegisterNatives` resolved or `DT_NEEDED` closure was discovered. Java class-loader rules, OS libraries, loader namespaces and native constructors remain relevant; native code runs with Android shell permissions. The [Termux bootstrap inventory case](TERMUX_BOOTSTRAP.md) reviews the actual DEX/native call and compares the original returned byte array's complete SHA256 plus projected metadata on ART.

## What a passing result means

| Reference | Verified scope |
| --- | --- |
| Native target CLI | Supplied cases of the selected original executable |
| Generic command/JVM harness | Only the declared command/harness cases |
| Android DEX classpath harness | Supplied cases of the reviewed adapter on the identified Android runtime, with exact selected target bytes on its classpath |

The Android report's `selectedDexBytesVerified` and classpath hashes prove staging identity. They do not independently instrument which methods a user-provided harness calls. Review the adapter; a harness could ignore the original. The bundled scrcpy adapter only constructs original classes, invokes the original method and serializes dimensions. Passing cases do not establish UI/server/hardware behavior, complete app recovery, all-input equivalence or other-device behavior. The identified OS and boot libraries are not comprehensively hashed, and neither host permissions nor Android shell permissions are a malicious-code sandbox.

## Reproduce the optional checks

Create a runtime file containing `adb`, `serial`, `serverPort`; keep Ghidra/JADX/JDK paths in the existing engine config. Add `r8` there if its JAR is outside the default local artifacts directory.

```sh
npm run verify:android -- --engines /path/to/engines.json --runtime /path/to/runtime.json
npm run verify:android-protocol -- /path/to/engines.json /path/to/runtime.json
npm run check -- /path/to/rea --native-engines /path/to/engines.json \
  --android-runtime /path/to/runtime.json
```

The third-party script downloads only the pinned official release if it is not already cached and verifies its digest. Engines/SDK/device must already be available. Protocol checks use a separate source-owned harness for quoting, stderr, failures, timeout, output budget, remote integrity and cleanup. These are not counted as extra third-party feature cases. A missing device/setup fails; it is not reported as a successful Android test.
