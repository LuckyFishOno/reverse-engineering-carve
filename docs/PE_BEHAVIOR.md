# Owned PE function behavior comparison

This optional integration connects actual independent REA analysis, PE UI entry/dependency evidence, multi-artifact reconstruction, executable acceptance and library-only reuse. It uses two owned freestanding Windows x64 function images built from [quote.c](../examples/pe-feature/quote.c) and [rate.c](../examples/pe-feature/rate.c). Clang emits real COFF machine code; a deliberately narrow fixture builder places its text/relocations into the owned PE resource/import/export envelopes. This builder is not a general linker or application packager.

The original machine code runs in Unicorn with an explicit Windows x64 function ABI, fixed image addresses and one reviewed IAT-to-export mapping. **It does not execute Windows, its loader or a UI event loop.** Reports always use `scope: "declared-harness"`, `windowsExecuted: false` and `uiExecuted: false`. The selected menu command supplies static candidate evidence, not proof of real UI dispatch.

## Prerequisites

Use the supported Node version, Clang with the x86_64 Windows target, configured Ghidra/JDK and these separate project-local optional installations:

```sh
python3 -m venv artifacts/pe-behavior-venv
artifacts/pe-behavior-venv/bin/python -m pip install unicorn==2.1.4
npm install --prefix artifacts/rea-local --ignore-scripts --no-audit --no-fund rea-agents@6.7.0
npm run build
```

The integration does not install prerequisites or change client/global configuration automatically. REA and RECarve remain separate MCP processes. The test client closes REA after complete code/info/callee/reference records are captured. RECarve then imports the serialized files without its own engine configuration. No server proxy or merged catalog is introduced.

[Unicorn documentation](https://www.unicorn-engine.org/docs/) describes CPU emulation; its [FAQ](https://github.com/unicorn-engine/unicorn/blob/master/docs/FAQ.md) distinguishes it from an OS environment. This fixture-specific harness is trusted test code, not a security sandbox for arbitrary software.

## Run

From the source clone:

```sh
npm run verify:pe-behavior
```

Override local paths when needed:

```sh
npm run verify:pe-behavior -- \
  --engines /absolute/path/to/config.json \
  --rea-install /absolute/path/to/rea-local \
  --python /absolute/path/to/pe-behavior-venv/bin/python
```

Or include it as an optional release check:

```sh
node scripts/check-release.mjs --pe-behavior
```

Release-check overrides are `--pe-python` and `--rea-install`. The engine config defaults to artifacts/engines/config.json; the existing `--native-engines` option overrides it and also enables the separate native/DEX integration.

## What is exercised

1. Compile owned caller/internal-helper and DLL functions independently; preserve original PE source hashes and metadata.
2. Use actual REA/Ghidra to export complete records for all three functions. Preserve originals unchanged and close the producer process.
3. Import via RECarve MCP, bind command1001to its source-pinned entry, and obtain one internal call and one selected DLL-export candidate with original IAT instruction bytes. Different images retain their own analysis profiles.
4. Author a closed JavaScript implementation after reviewing actual captured decompilation. Package it with the multi-artifact contract and complete code evidence for both images. The test does not claim automatic synthesis.
5. Run separate module-load, local assertion, emulator-protocol and original-comparison checks. The protocol check observes actual entry/helper/DLL instruction addresses for positive, negative and free cases.
6. Compare160finite signed32 boundary/deterministic sample cases. Some hand-reviewed expected values prevent an identical but incorrect constant response from passing unnoticed. A separately pinned constant-zero mutant must fail original comparison.
7. Bind a reported verification claim to the exact passing local report, wrapper and cases hashes. Editing original DLL bytes must invalidate a report read; restored original bytes must validate again.
8. Temporarily move the original input directory offline. Original emulation must fail while the closed candidate still works via a library-only MCP root and direct import. Restore and rehash original inputs afterward.

The Python harness verifies owned image hashes, maps bounded PE sections with their read/write/execute permissions, patches only the declared selected import and sets the x64 argument/return ABI. It stops at an explicit return address, with a5000instruction/one-second emulation bound. It does not implement loader search, relocation, forwarders, delayed imports, Windows APIs, callbacks, SEH, TLS or dynamic libraries beyond this fixture's declared map.

## Results and limits

Every run creates a new artifacts/pe-behavior-e2e-* folder and updates artifacts/pe-behavior-verification-summary.json. Inspect report.json, producer/, entry-boundary.json, dependency-boundary.json, accepted/report.json, claim-binding.json, mutant-rejection.json and stale-rejection.json. The independent function is retained under that run's functions/pe-quote/ directory.

Executable acceptance pins the declared wrappers, images, source metadata, captured snapshots, candidate package and cases. Toolchain metadata records the external Python executable, Unicorn version and Clang version; this is not a cryptographic attestation of the runtime or its transitive dependencies. Reports remain unsigned local integrity records.

A passing declared emulator harness is narrower than Windows runtime, original UI, loader/OS/state behavior or whole-program equivalence. Decompiler signedness/type rendering is also not a universal semantic proof. Other inputs, dependencies, architectures and stateful operations need their own evidence and actual scoped comparisons. See [PE UI evidence](PE_UI.md), [multi-artifact reconstruction](MULTI_ARTIFACT.md) and [work acceptance](WORK_ACCEPTANCE.md).
