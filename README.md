# reverse-engineering-carve

**Extract investigated software behavior into reusable local capabilities.**

reverse-engineering-carve (RECarve) is an independent companion MCP for [REA](https://github.com/morluto/rea). Your agent uses REA to investigate software, then `carve` to define a feature, extract or rebuild it, verify behavior and save a reusable function folder. REA and carve run as separate MCP servers.

[繁體中文](README.zh-TW.md) · [Releases and detailed capabilities](https://github.com/LuckyFishOno/reverse-engineering-carve/releases/latest)

## Install

Requires Node22.19 in the22 line or Node24.11+. In the cloned repository:

```sh
npm ci
npm run build
node dist/cli.js --version
```

CLI: `carve`. MCP entry: `carve`. Project/package: `reverse-engineering-carve`. RECarve is a prose abbreviation. Release packages are available on GitHub; the project is not published to npm.

## Add to an existing REA setup

Keep your working REA installation and MCP entry. Merge the following entry into your client's existing `mcpServers` map, replacing the absolute paths:

```json
{
  "carve": {
    "command": "node",
    "args": ["/absolute/path/to/reverse-engineering-carve/dist/cli.js", "serve", "--root", "/absolute/path/to/workspace"]
  }
}
```

Reload MCP connections. Your agent should see REA and carve separately. No REA reinstallation, additional LLM API key or website is required. [Setup details](docs/REA_COMPANION.md).

## Use

> Use REA to investigate this application and carve to suggest reusable features. Show the evidence and unknowns. Once I select a feature, define its boundary, extract or rebuild it, compare concrete behavior and save a reusable local folder.

Describe where the feature is triggered, its inputs and expected outputs. The agent still needs to investigate dependencies; native/mobile support remains experimental, and a successful build does not prove original behavior equivalence. Execution-enabled actions require trusted code and authorization.

[Release notes, capabilities and verification scope](https://github.com/LuckyFishOno/reverse-engineering-carve/releases/latest) · [MIT license](LICENSE)
