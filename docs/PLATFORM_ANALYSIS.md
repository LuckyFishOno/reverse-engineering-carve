# Windows PE dependencies and target adapter guidance

`carve_platform` classifies imports from indexed .exe/.dll inputs and returns guidance for an independent `carve/target@1` destination. The same PE may be investigated for a macOS App, Windows module or browser Web App. This is static guidance, not a generated or verified replacement.

```sh
node dist/cli.js survey ./program.exe --workspace ./native-work
node dist/cli.js platform dependencies ./native-work --file program.exe --view categories
node dist/cli.js platform dependencies ./native-work --file program.exe --view imports --category ui-graphics
node dist/cli.js platform adapters ./native-work --file program.exe --target ./target.json --view cards
```

Example target.json:

```json
{"schema":"carve/target@1","platform":"macos","delivery":"desktop-app"}
```

An installer may itself be a PE: launcher imports describe that launcher, not the installed App. Third-party DLLs, compressed/encrypted payloads, server logic and dynamic loading may remain outside the current view.

## MCP

```json
{"workspace":"native-work","file":"program.exe","request":{"kind":"dependencies","view":"categories","budgetBytes":8192}}
```

```json
{"workspace":"native-work","file":"program.exe","request":{"kind":"target-adapters","target":{"schema":"carve/target@1","platform":"browser","delivery":"web-app"},"view":"cards","budgetBytes":8192}}
```

REA remains independent. Carve reads supported PE declarations/byte patterns without running REA, Ghidra or the target. Each call rehashes selected input, records immutable boundary evidence/observation and returns byte-budgeted pages. MCP confines workspace, input, SQLite sidecars and evidence to its root.

Categories: file-system, process-thread, network, ui-graphics, registry-system, crypto-security, dynamic-loading, text-locale-time, console-stdio, runtime-library, os-specific, unknown. Imports retain module/name/ordinal/slot, ruleId, surface and available call-site counts.

There are43 ordered name/module rules, with first-match semantics, version and rulesSha256. These are lexical rules, not semantic confidence. Surface distinguishes Windows system, C runtime and other-module; other DLLs need independent analysis. Dependencies views: summary/categories/imports/rules; category filtering applies only to imports. Rules exposes exact conditions/order.

Declared imports do not prove execution. x86/x64 call locations are byte-pattern candidates; ARM64/IA-64 scanning is absent and null does not mean zero dependencies. Bound imports without lookup tables, GetProcAddress, COM and dynamic loading remain unknown. .NET imports may only describe a runtime stub. RPC runtime imports remain conservative os-specific guidance.

Target guidance has57 versioned rules matched by category/platform/delivery. Cards include guidanceId, alternatives, cautions and availability: same-platform, standard-library, native-framework, web-platform-api, restricted, requires-helper, not-applicable, decision-required, inspect-separately. These do not prove SDK availability, version compatibility, implementation or equivalence. Browser helper/backend requirements remain explicit decisions.

Target-adapters views: summary/cards. Assessment is always static-guidance-not-verified; work-package targetAssessment:not-performed is not upgraded automatically. Import counts are not development estimates or feature coverage.

Both requests use offset/limit1–100, budgetBytes1024–65536 and nextOffset, with exact compact UTF-8 receipts. Read all pages with matching observationId/sourceSha256. Reinvestigate when sources or rule versions change. Synthetic PE32/PE32+, local shipped PE fixtures and target-combination tests exercise static behavior without executing Windows Apps or proving large-program ports.
