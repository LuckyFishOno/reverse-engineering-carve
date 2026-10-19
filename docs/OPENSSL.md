# Installed OpenSSL feature reconstruction

This optional local check investigates the installed Homebrew OpenSSL3.6.4 macOS arm64 distribution. It does not build a source-owned substitute. The selected behavior is finite raw bytes → padded standard Base64 without line breaks, matching `openssl base64 -A`.

```sh
npm run verify:openssl -- --prefix /opt/homebrew/opt/openssl@3
# Or include it in the local release checks:
node scripts/check-release.mjs --openssl
```

The check requires configured Ghidra/JDK at artifacts/engines/config.json. Use `--engines FILE` and `--workspace DIRECTORY` on scripts/verify-openssl.mjs to select an existing configuration/persistent workspace. It verifies the installed version and actual selected hashes, inventories the whole prefix, preserves Ghidra caches and saves a new report/output directory on each run. It never uninstalls or modifies OpenSSL.

The reviewed boundary starts in CLI enc_main: the base64 branch creates BIO_f_base64, applies the no-newline flag and writes/flushes through BIO. The separately analyzed libcrypto BIO_f_base64 returns methods_b64. A bounded loaded-memory window records pointers to b64_write and b64_ctrl; their decompilation shows the chunk/remainder paths calling EVP_EncodeBlock, which delegates to evp_encodeblock_int. The latter records the alphabet, six-bit selection and `=` padding. Complete code records bind both images; the callback window and native import/export/loader records are supporting evidence. Matching names alone are not treated as a resolved call graph.

A separate actual dyld log checks which installed libcrypto is loaded. This is library-load evidence, not instruction-level instrumentation of every declared edge. Host configuration/system shared-cache libraries and complete dynamic dependency closure are not authenticated.

The reimplementation is a closed pure JavaScript byte loop with no native library, process or npm dependency. It accepts one array of at most65536 integer bytes. Valid-input cases cover every length0–129, three-byte padding boundaries, all256 byte values, NUL/high bytes/Unicode byte sequences, write/read buffer boundaries and a65535-byte case. Known short vectors also have explicit expected results. Own API validation is an added guard; it is not a claim about the original C API's invalid pointers/lengths.

`carve/reference@2`, bytes-stdin and utf8 stdout invoke the installed original CLI directly for160 comparisons. The result is stored as a function folder, preserving its original comparison report, analyzed-input notice and unknowns. The intermediate CLI package and rewrite source are removed; direct import, restricted fresh-process invoke and actual stdio MCP are checked on the folder. Original installed OpenSSL remains present. Independence is demonstrated by a closed implementation and restricted invocation, not by claiming that the software was uninstalled.

Use the report's returned function path with `library get` or `invoke`, or import its index.mjs export capability. No per-function program installation or website is needed. The generated folder stays UNLICENSED; preserved OpenSSL notices do not automatically relicense reconstructed output.

This is one bounded shipped third-party operation crossing two images. It does not reconstruct OpenSSL encryption/TLS/providers, nonblocking BIO behavior, OS state, arbitrary native software or a large mobile App. The report is the authority for actual run status; a script or documentation page alone is not a passing result.
