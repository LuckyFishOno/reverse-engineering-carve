# Third-party PE version feature

`npm run verify:pe-version` extracts a deliberately small feature from the actual
Windows AMD64 `lib7-Zip-JBinding.dll` shipped inside the configured Ghidra
distribution. It does not compile a replacement input fixture. The reviewed DLL
SHA256 is `c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27`;
a different DLL is rejected instead of silently applying old reconstruction values.
The third-party DLL remains a local prerequisite and is not bundled by this project.

The six selected exports expose major, minor, build, version, date and copyright.
An independent REA MCP captures complete function records, closes, and only then
does Carve import those records and package the reviewed JavaScript implementation.
This is agent-authored reconstruction from binary evidence, not automatic synthesis.

The string exports make an indirect tail call through JNI table offset `0x538`.
The integration compiles an assertion against the installed JDK's `jni.h` to check
the 64-bit `NewStringUTF` slot. The dependency report keeps the indirect calls
unresolved: a harness declaration does not resolve a static call graph.

This non-UI DLL uses `entryMode: "selected-functions"` in `carve_pe_ui`'s
dependencies view. Six explicit same-file imported function IDs seed traversal;
no UI command is supplied or invented. The report captures three readonly string
addresses in `.rdata`. Reconstruction pins exactly each terminated string's bytes
as `embedded-readonly`, rather than copying the entire neighboring byte preview.

Original instructions execute at the preferred image base under Unicorn2.1.4.
The harness maps sections with their declared read/write/execute permissions,
supplies a synthetic JNI environment and models exactly one `NewStringUTF` call
for each string export. It accepts only a bounded, terminated printable ASCII
string inside the original image and returns an opaque handle. Instruction/time
limits, source hashes, declared fields and JNI call counts are checked explicitly.
No DLL initializer, Windows loader, OS API or JVM runs. JNI allocation errors,
non-ASCII modified UTF8 and archive/compression operations are outside this case.

Acceptance compares all six selected outputs. It pins the original DLL, captured
evidence, dependency report, reconstruction receipt, harness, candidates and cases.
A deliberately incorrect candidate must fail; modifying the original copy must
invalidate saved acceptance. The integration then temporarily moves its own input
directory offline and checks all six outputs through direct module imports and a
fresh library-only MCP session. The original distribution is never modified.

Prerequisites are the configured local Ghidra/JDK, REA6.7.0 in
`artifacts/rea-local`, clang, and the Unicorn2.1.4 Python environment used by
[PE behavior comparison](PE_BEHAVIOR.md). Override `--engines`, `--rea-install`
or `--python` when invoking the script directly. Run the optional release check as:

```sh
node scripts/check-release.mjs --pe-version
```

Each run writes a separate `artifacts/pe-version-e2e-*` directory, including failures.
Only a successful run updates `artifacts/pe-version-verification-summary.json`.
Six passing metadata cases establish this small feature's declared harness result;
they do not establish generic DLL/JNI recovery or full 7-Zip equivalence.
