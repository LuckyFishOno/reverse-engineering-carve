# Add RECarve beside REA

REA performs reverse-engineering analysis. RECarve turns selected evidence and explicit requirements into bounded reconstruction tasks, behavior checks and reusable local function folders. They are two independent MCP servers called by the same LLM. Neither server merges, proxies or starts the other.

## Existing REA users

Keep your working REA installation, engine paths and MCP server entry unchanged. Install/build RECarve in its own directory:

```sh
git clone https://github.com/LuckyFishOno/reverse-engineering-carve.git
cd reverse-engineering-carve
npm ci
npm run build
node dist/cli.js --version
```

Version0.43.0 requires Node22.19 in the22 line or Node24.11+. Add only this entry to the existing client's `mcpServers` map; merge it with existing entries instead of replacing them:

```json
{
  "recarve": {
    "command": "node",
    "args": ["/absolute/path/to/reverse-engineering-carve/dist/cli.js", "serve", "--root", "/absolute/path/to/workspace"]
  }
}
```

This is the entry fragment, not the entire client configuration. Use an absolute Node executable path if the client does not inherit your shell's PATH. The workspace must exist and contain the inputs, exported evidence and output directories needed by RECarve. Reload MCP connections using your client's own mechanism. Do not run RECarve inside REA or alter REA's package files.

Confirm two separate servers and ask the agent to list their tools. RECarve0.43.0 exposes52tools, including carve_features, carve_behavior_check, carve_work_acceptance and carve_skeleton. A request to inventory/select features does not authorize executing the target; later comparison/build actions still require their execution flags and authorization. The agent saves compatible evidence from REA and explicitly supplies it to RECarve. No additional LLM API key, website, domain or server-to-server connection is required by RECarve.

If using the downloadable release tarball instead of a source clone, install it into a local prefix and use that installation's absolute `node_modules/reverse-engineering-carve/dist/cli.js` path. See [release installation](RELEASE_0.43.0.md).

## Project-local setup

Install a pinned REA package in a separate directory without setup/global registration:

```sh
mkdir rea-local
cd rea-local
npm init -y
npm install --ignore-scripts --no-audit --no-fund rea-agents@6.7.0
```

Build RECarve with `npm ci && npm run build` in its own source directory. Configure the client with actual absolute paths:

```json
{
  "mcpServers": {
    "rea": {"command":"node","args":["/absolute/path/to/rea-local/node_modules/rea-agents/dist/cli.js","mcp"]},
    "recarve": {"command":"node","args":["/absolute/path/to/reverse-engineering-carve/dist/cli.js","serve","--root","/absolute/path/to/workspace"]}
  }
}
```

Confirm the installed package's `bin` field and use that entry if it differs. Native engines belong in REA's environment; see [native handoff](REA_NATIVE.md). RECarve also has its own explicitly configured analysis backends, but this does not make it a REA proxy. Installing a package does not prove every provider is available.

## Evidence handoff

1. Use REA to investigate the selected input and save the complete returned Evidence JSON.
2. Use RECarve to inventory the input and show feature choices.
3. Clarify the trigger, input, output, state and required platform/server boundaries.
4. Bind supported evidence to exact input bytes. Read complete code and dependencies, then implement the selected behavior independently.
5. Compare concrete cases with a trusted original reference. Store the resulting package in a [local function library](LIBRARY.md) for direct import or MCP invocation.

The agent/client explicitly persists evidence files. There is no automatic universal shared session or server-to-server transfer. JavaScript evidence uses exact archive/module identities; [native imports](REA_NATIVE.md) support a specific Ghidra profile. Other providers may require separate investigation.

## Reproducible native integration

```sh
npm run verify:rea-native -- --engines ./artifacts/engines/config.json
npm run verify:rea-relationships -- --engines ./artifacts/engines/config.json
```

These scripts create fresh project-local REA6.7.0 installations by default; optional `--rea-install` reuses an explicit installation. Ghidra/JDK must be configured. They use source-owned native fixtures and independent processes, preserve complete records, close REA before RECarve reuse, and compare selected original CLI cases. Read [native limits](REA_NATIVE.md) and [bridge limits](REA_BRIDGE.md).

Tests do not prove all providers, arbitrary App recovery, native/mobile compatibility, missing server logic or global configuration isolation. Run the selected integration on your host; historical reports are not a fresh verification of changed code.
