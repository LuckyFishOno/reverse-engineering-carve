# Mach-O load commands and static paths

`loader` / `carve_loader` reads a selected Mach-O header directly. No Ghidra, JDK, REA or target execution is needed for this step. It complements the [Ghidra symbol index](NATIVE_LINKS.md): symbol-name candidates and declared library paths are different evidence, and neither establishes runtime binding.

```sh
node dist/cli.js loader ./work --file bin/program --limit 20
node dist/cli.js loader ./work --file bin/program --offset 20
node dist/cli.js loader ./work --file Universal.app/Contents/MacOS/program --slice 1
```

The equivalent MCP call is `carve_loader` with workspace/file and optional slice/limit/offset. It writes a local evidence observation, so it is not marked read-only. It requires an existing successfully indexed file in the MCP root. It does not need an engines configuration. ELF, PE and other loaders remain unsupported by this reader; their existing format recognition/Ghidra workflows are unchanged.

The parser accepts thin32/64 and universal32/64 Mach-O headers in either byte order. Universal inputs with several slices require an explicit slice index; the error lists slice indices, CPU type/subtype, offsets and sizes. It does not silently select the host architecture. Fat ranges must fit without overlap and agree with the selected thin CPU identity. Command sizes/alignment/count, string ranges/termination and UTF8 are checked. Limits are64 slices,4096 commands,8MiB command data and4096 bytes per decoded name. A source file itself may be larger; selected source bytes are freshly hashed before and after reading commands, so this is not a constant-time whole-file operation.

The result records ordered load/weak/reexport/lazy/upward library declarations, LC_ID_DYLIB install names, LC_RPATH, LC_DYLD_ENVIRONMENT and command offsets in the original file. Current/compatibility versions are raw packed integers. Modern dylib_use_command flags are recorded without claiming loader-policy interpretation. Other command types/ranges are retained in the evidence without parsing their payload. Encryption, code signing, platform compatibility, chained fixups, export tries and bind/symbol ordinals are not resolved by this header pass. It does not establish that the binary is executable or valid in all other respects.

Dependency pages use limit1–100 (default20) and nextOffset. The parser rereads the bounded command section on each call; it does not claim constant-time pagination. Each dependency gets at most32 path expansions and the returned page at most256. pathsTruncated / bounded-partial means expansions were omitted; inspect the complete raw commands in the evidence before drawing conclusions. A dependency with no local LC_RPATH reports no-local-rpaths; inherited search context is not invented.

Static expansions currently map POSIX host layouts; on Windows the header reader still works but path context remains unresolved. They use only bases known from the selected image:

- Absolute dependency/rpath names remain lexical absolute paths.
- `@loader_path` uses the selected image directory in the inventoried layout.
- `@executable_path` is available only when the selected image declares MH_EXECUTE. A library does not invent a main executable directory.
- `@rpath/name` expands over this image's own ordered LC_RPATH entries. All bounded alternatives remain visible. Relative/unknown tokens and inherited runpath stacks remain unresolved.

These are lexical path candidates, not simulated dyld results or a selected first match. Environment variables, LC_DYLD_ENVIRONMENT content, fallback paths, SIP/hardened-runtime policy, symlinks/case folding, architecture/version compatibility, shared caches and indirect loading can change actual loading. The tool neither reads nor executes candidate paths. Paths outside the inventory are labeled outside-inventory. Inside paths are matched against current-revision inventory records; candidate freshBytesChecked:false means they were not rehashed. Copied binaries retain their original absolute install names: the tool does not follow them back into the original installation or pretend copying relocated the library relationship.

The selected image's immutable native-loader observation stores exact raw commands, parser identity and source/evidence hashes. Repeat pages preserve its ID/evidence file. Concurrent calls publish a complete closed temporary file by an exclusive hard link before indexing it, so another call cannot hash a partial final file. A forced termination may leave an unindexed .tmp file, never a successful partial observation. Path expansions and inventory candidate hints are calculated for the current query and are not part of this raw-command observation. Read raw evidence with observation; pass its ID as supportingEvidenceIds in a [multi-artifact contract](MULTI_ARTIFACT.md). It cannot satisfy complete implementation-code evidenceIds. Reconstruction still rehashes every selected artifact and evidence file. Inspect caller/callee code and an actual operation boundary before choosing a relationship. `links` keeps its name-based candidates; loader results do not automatically discard any of them.

`npm run verify:loader` currently requires macOS arm64, Xcode's clang/lipo/otool and this host's installed Homebrew ripgrep/PCRE2. It compares six real thin/universal command views against independent otool output. An owned executable has two same-basename rpath candidates; both remain in the result while a separate actual dyld log records the library that ran. Copied ripgrep's original absolute PCRE2 path is correctly marked outside the copy's inventory. This check is loader metadata/path evidence, not recovered regex functionality. The separate updated verify:multi binds raw loader evidence alongside real decompiled caller/callee code and compares162 original executable cases before removing originals/rewrite source.
