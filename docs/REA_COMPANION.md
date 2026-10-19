# Use Carve beside a clean REA installation

REA performs reverse-engineering analysis. Carve turns selected evidence and explicit requirements into bounded reconstruction tasks, behavior checks and reusable local function folders. They are two independent MCP servers called by the same LLM. Neither server merges, proxies or starts the other.

## Project-local setup

Install a pinned REA package in a separate directory without setup/global registration:

```sh
mkdir rea-local
cd rea-local
npm init -y
npm install --ignore-scripts --no-audit --no-fund rea-agents@6.7.0
```

Build Carve with `npm ci && npm run build` in its own source directory. Configure the client with actual absolute paths:

```json
{
  "mcpServers": {
    "rea": {"command":"node","args":["/absolute/path/to/rea-local/node_modules/rea-agents/dist/cli.js","mcp"]},
    "carve": {"command":"node","args":["/absolute/path/to/carve/dist/cli.js","serve","--root","/absolute/path/to/workspace"]}
  }
}
```

Confirm the installed package's `bin` field and use that entry if it differs. Native engines belong in REA's environment; see [native handoff](REA_NATIVE.md). Carve also has its own explicitly configured analysis backends, but this does not make it a REA proxy. Installing a package does not prove every provider is available.

## Evidence handoff

1. Use REA to investigate the selected input and save the complete returned Evidence JSON.
2. Use Carve to inventory the input and show feature choices.
3. Clarify the trigger, input, output, state and required platform/server boundaries.
4. Bind supported evidence to exact input bytes. Read complete code and dependencies, then implement the selected behavior independently.
5. Compare concrete cases with a trusted original reference. Store the resulting package in a [local function library](LIBRARY.md) for direct import or MCP invocation.

The agent/client explicitly persists evidence files. There is no automatic universal shared session or server-to-server transfer. JavaScript evidence uses exact archive/module identities; [native imports](REA_NATIVE.md) support a specific Ghidra profile. Other providers may require separate investigation.

## Reproducible native integration

```sh
npm run verify:rea-native -- --engines ./artifacts/engines/config.json
npm run verify:rea-relationships -- --engines ./artifacts/engines/config.json
```

These scripts create fresh project-local REA6.7.0 installations by default; optional `--rea-install` reuses an explicit installation. Ghidra/JDK must be configured. They use source-owned native fixtures and independent processes, preserve complete records, close REA before Carve reuse, and compare selected original CLI cases. Read [native limits](REA_NATIVE.md) and [bridge limits](REA_BRIDGE.md).

Tests do not prove all providers, arbitrary App recovery, native/mobile compatibility, missing server logic or global configuration isolation. Run the selected integration on your host; historical reports are not a fresh verification of changed code.
