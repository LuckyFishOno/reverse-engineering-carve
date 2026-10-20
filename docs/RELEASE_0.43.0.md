# RECarve0.43.0

This alpha release brings the changes since0.38.1 into one public release: UI evidence, explicit behavior requirements, claim provenance, executable task acceptance and Swift project wiring. RECarve remains a local CLI/skill/MCP companion to an independent REA MCP. It exposes52MCP tools and is not published to npm.

## Existing REA users

Keep REA and its MCP entry unchanged. Install RECarve separately and add one `recarve` entry to the same client's `mcpServers` map. Reload the client's MCP connections; the LLM calls both servers. RECarve neither patches nor starts REA. [Existing REA setup](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/REA_COMPANION.md#existing-rea-users).

## Naming and compatibility

The project/repository/package is now `reverse-engineering-carve`, abbreviated **RECarve**. The CLI is `recarve`, the MCP configuration entry is `recarve`, and the bundled skill is `recarve`. The old `carve` CLI remains an alias. Existing `carve_*` tool IDs, `carve/*` schema IDs, stored filenames and generated Swift interface names remain compatible; they identify protocols/data rather than the current display brand. No existing workspace migration is required.

## Included changes

- **PE UI evidence:** source-pinned menu/dialog/string/accelerator graphs, numeric command edges and AFX-like callback candidates. Candidate ownership and semantics remain unverified. [PE UI](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/PE_UI.md).
- **Behavior contracts:** preserve lifecycle, direct UI interaction, protocol modes, persistence and recovery. Missing declarations/scenario coverage block supplied work contracts. [Behavior](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/BEHAVIOR.md).
- **Claim provenance:** separate original static evidence, hypotheses, target design and reported verification claims. Missing provenance stays unclassified. Labels alone do not authenticate behavior. [Provenance](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/PROVENANCE.md).
- **Executable acceptance:** trusted build/unit/live-harness checks and finite original/candidate comparisons, including ordered sequences. Pin inputs/results and reject stale or mismatched records. Unsigned local integrity reports do not automatically accept ledger work. [Acceptance](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/WORK_ACCEPTANCE.md).
- **Swift project wiring:** expose skeleton create/inspect/check, preserve explicitly pinned implementations/resources, wire vendored or revision-pinned packages and per-feature link settings, and regenerate new snapshots. Supports macOS SwiftPM desktop/CLI/module targets. [Skeletons](https://github.com/LuckyFishOno/reverse-engineering-carve/blob/v0.43.0/docs/SKELETON.md).

## Install from source

Requires Node22.19 in the22 line or Node24.11+. Swift generation itself does not need a Swift compiler; building the supported macOS targets requires a macOS Swift toolchain.

```sh
git clone --branch v0.43.0 https://github.com/LuckyFishOno/reverse-engineering-carve.git
cd reverse-engineering-carve
npm ci
npm run build
node dist/cli.js --version
node dist/cli.js serve --root /absolute/path/to/workspace
```

Configure MCP using the absolute `dist/cli.js` path; do not launch a second interactive CLI as part of the MCP process. No additional LLM API key or domain is required by RECarve. Existing agent/client and REA requirements remain their own.

## Install the release package

Download `reverse-engineering-carve-0.43.0.tgz` and `SHA256SUMS` from this release into the same folder. The tarball contains built JavaScript, docs and runtime package metadata; npm installs its declared dependencies.

```sh
shasum -a 256 -c SHA256SUMS
npm install --ignore-scripts --prefix ./recarve-local ./reverse-engineering-carve-0.43.0.tgz
node ./recarve-local/node_modules/reverse-engineering-carve/dist/cli.js --version
```

Use the resulting absolute `node_modules/reverse-engineering-carve/dist/cli.js` path in the additional RECarve MCP entry. This installs locally from a GitHub asset, not from an npm registry release. The checksum detects content mismatch; it is not a signed provenance attestation.

## Verification and scope

Local macOS/Node24.20.0 verification: all6release checks passed, including388tests with zero failures/skips, build/content hygiene, the archive demo,7public packages/47cases and clean tarball CLI/fresh MCP installation. Source-owned Swift integration exercised text/localization resources, opaque binary copying, a vendored package, framework/library settings and chained feature outputs. Actual native/device/REA integration suites and remote package fetching were not rerun for this release.

This remains an alpha. It does not recover unavailable server logic, prove arbitrary binary or whole-program equivalence, automatically synthesize every feature, update arbitrary Xcode projects or produce a signed/distributed native App. Execution-enabled checks run trusted code with host permissions. Build success, declared scenario coverage and recorded hashes are distinct from original behavior equivalence. Private analysis inputs, generated workspaces and engine downloads are excluded from the repository and release package.
