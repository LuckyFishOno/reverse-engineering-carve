# Bounded verification results

`verify-reconstruction` executes the original/reference and the reconstructed capability for the supplied cases. Since0.19 its CLI/MCP response defaults to a small summary. The complete report is preserved on disk. This avoids sending every input, return value and runtime detail to the LLM after every comparison.

```sh
node dist/cli.js verify-reconstruction ./work --package ./tool \
  --cases ./cases.json --reference ./reference.json --execute --budget-bytes 4096
```

Keep the returned `workspace` and `id`. The summary includes status, passed/total, original comparison time, manifest/report hashes, invocation scope, unknown/dependency counts and available metadata fields. Unknowns and limitations still require inspection; a count does not resolve them.

`carve_verify_reconstruction` uses the same defaults, with `execute:true` and optional `budgetBytes`. CLI comparison failures still exit1; MCP failures retain the failed status. This change only affects reconstruction verification, not the older JS `verify` command.

For a caller that deliberately needs the previous complete response, use `--full-report` or MCP `fullReport:true`. That explicit compatibility reply is unbounded by `budgetBytes`; existing case/process limits still apply. The direct JavaScript `verifyReconstruction` API continues returning the full report. The complete package report and usage summary are unchanged.

## Inspect recorded cases

Reading uses `verification` / `carve_verification`, without `execute`. Replace `REPORT_ID` with the returned64-character ID.

```sh
# Whole case cards, without arguments or return bodies
node dist/cli.js verification ./work --id REPORT_ID --view cases --failed-only --limit 10

# The original outcome of case0
node dist/cli.js verification ./work --id REPORT_ID --view case --case-index 0 --field original

# Read one unknown or the reference invocation metadata
node dist/cli.js verification ./work --id REPORT_ID --view metadata --field unknowns --item 0
node dist/cli.js verification ./work --id REPORT_ID --view metadata --field reference
```

The MCP equivalents use `workspace`, `id`, `view`, `failedOnly`, `limit`, `caseIndex`, `field`, `item`, `offset`, `characters` and `budgetBytes`. The main server exposes37 tools; this reader is available without native/Android engines. Server root/workspace confinement still applies. A missing original source may remain recorded in the workspace: historical reads do not need to reopen it.

- `summary` returns no case bodies. It is also the default view.
- `cases` pages whole cards with zero-based `index`, name, passed status, outcome kinds, byte count and checksum. `total` counts the filtered cards; `verificationPassed` and `verificationTotal` retain the report counters. Follow `nextOffset` in the same filtered list. Default limit20, maximum100.
- `case` selects one zero-based `caseIndex`, then a top-level field such as `args`, `original`, `candidate` or `expected`. Default field is `original`. An absent field returns `present:false`.
- `metadata` selects one report field outside `results`, such as `unknowns`, `limitations`, `reference`, `androidRuntime`, `relationships` or `unresolvedDependencies`. The summary lists the actual fields present. Default field is `unknowns`. Optional `item` selects one element of an array before paging its text.

Case/metadata `text` is a slice of the selected value's **JSON serialization**. It may be an incomplete JSON fragment. Append text pages in order and parse only once the final `nextOffset` is null. `complete:true` means the whole value fits in this single page, starting at offset0. Each field/array item has its own offset sequence. Offsets and `characters` use JavaScript UTF16 code units, not UTF8 bytes or Unicode character counts; use returned offsets rather than calculating them. Pages do not split surrogate pairs. Default characters2000, maximum12000. A one-unit window cannot hold an emoji; increase `characters` in that case.

## Budgets and archive identity

Default budget8192 UTF8 bytes; allowed1024–65536. `receipt.responseBytes` measures exact `JSON.stringify(response)` bytes, including the receipt itself. It excludes the CLI newline and MCP transport framing. Small budgets may not hold mandatory metadata; the operation then reports an error instead of omitting scope. A comparison already archived before this error need not run again: read its ID from the error with a larger budget.

Archives live outside the disposable output package:

```text
WORKSPACE/verification/reports/REPORT_ID/
  index.json
  report.json
  cases/0.json
  cases/1.json
  ...
```

`REPORT_ID` is SHA256 of the exact index bytes. The index binds full report identity/size, all non-case metadata and every ordered case checksum. Publication uses a temporary directory and atomic rename; repeated identical publication checks the existing record. Keep the ID to detect subsequent index changes.

Every read checks the pinned index and streams the entire full report through SHA256. Reading a case additionally checks its file. Symlinked directories/files, malformed indexes, inconsistent counters and changed selected bytes are refused. These are local identity checks; they do not authenticate an original publisher, independently rederive case outcomes, instrument an adapter, revalidate current originals or establish new equivalence. Reading an old pass never runs a new comparison. The original scope and time remain visible.

Bounds:1–200 cases, full report at most512MiB, index at most4MiB, individual case at most16MiB. The reader bounds index/case memory, but the verifier and archive writer still materialize the report in memory. This is not a streaming verifier for arbitrary large outputs. Every page rereads/hashes the full report, so large archives have an I/O cost. Keep the complete report and index together. Deleting the original/output package does not delete this archive; deleting the workspace does.

Function-library import preserves its own full source report and recorded usage summary. It does not copy this workspace paging index. Use the retained workspace/ID for paginated investigation; function import and invocation stay independent of that workspace.

## Local payload measurement

`npm run benchmark:verification` archives four recorded0.18 comparisons and measures actual JavaScript compact JSON against actual stdio MCP summary content text. It **does not rerun the originals**. On the development host, the measured full/summary pairs were:

| Recorded operation | Cases | Full UTF8 bytes | Summary UTF8 bytes |
| --- | ---: | ---: | ---: |
| Shipped APK contact vCard |160|289966|1661|
| Installed OpenSSL Base64 |160|1068338|1655|
| Owned executable/library quote |162|25885|1653|
| Shipped scrcpy size operation |160|34653|1606|

Absolute workspace paths affect summary size. Results and payload/code checksums are saved under `artifacts/verification-payload-benchmark-0.19.0.json`. The summary contains less inline information, with complete cases/metadata/unknowns accessible on disk. These byte counts exclude prompts, model output and transport framing; they are not token, billing, accuracy or arbitrary-workload savings measurements. No upstream Trail-Code/Graft percentage is applied.

## Stateful sequence records

Reference@3 and Android-reference@4 reports add comparisonMode:stateful-sequences, totalSteps and passedSteps. passed/total count whole sequences. Cases retain calls, original/candidate outcome arrays and steps; read view:case, caseIndex, field:steps and item:STEP_INDEX for one step. Protocol/timeout failures invalidate the sequence and have no invented step result. Scope is selected-original-cli-sequences, declared-external-harness-sequences or selected-dex-android-harness-sequences. See [stateful protocol](STATEFUL.md); checksum-bound historical reads do not re-execute any sequence.
