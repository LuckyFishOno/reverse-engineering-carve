# Reviewed PE data bindings

Version2 reconstruction artifacts may optionally include `dataBindings`. These explicitly connect reviewed [PE data references](PE_DATA.md) to the agent's declared reconstruction treatment. They do not infer a data model, copy arbitrary dependencies or synthesize implementation code. CLI `reconstruct` and MCP `carve_reconstruct` use the same contract file.

Each selection contains:

| Field | Meaning |
| --- | --- |
| observationId | One of this artifact's complete implementation evidence IDs |
| sourceAddress | Exact imported reference source preferred-image VA |
| targetAddress | Exact imported target coordinate |
| handling | embedded-readonly, modeled-state or unresolved |
| description | Agent review of the selected data and intended handling,1–2000 characters |
| bytes.length | Explicit initial prefix length,1–64 bytes |
| bytes.sha256 | SHA256 of exactly that prefix, excluding unrelated preview bytes |

`bytes` is required for embedded-readonly/modeled-state and optional for unresolved. Obtain the source/target and raw hex from the full dependency report, review the object boundary and hash only the selected prefix. For example, a12-byte settings table should pin12-bytes rather than the entire64-byte preview. Prefix length is a reviewed declaration, not an inferred object extent. Source and target coordinates must exactly match one imported typed data/read/write reference.

Embedded-readonly requires readable, non-executable, non-writable target data with no exact write recorded among the artifact's selected implementation observations. Modeled-state requires a writable section or exact selected write. Both require sufficient original file bytes and the declared hash. Virtual-only or unresolved external data may be retained with unresolved handling and no byte pin; no initializer is invented.

Every implementation observation of an artifact using dataBindings must be an owned complete imported PE/REA record. Revalidation covers current source, snapshots, normalized records, source/body/section positions and selected initial bytes. MCP authorizes selected sources and snapshots before reading them. The existing native snapshot loader limits each artifact's selected snapshots to64 MiB. Boundary-support artifacts cannot declare dataBindings. Limits: 32 bindings per artifact,64 per contract, no duplicate observation/source/target selections. Contracts without the optional field retain their previous shape and semantics.

Resolved provenance stores the declared handling, source/snapshot hashes, typed reference metadata, exact selected byte offset/hex/hash, and explicit limitations. A second binding check runs before successful packaging; later reconstruction verification rebinds the records and compares artifact provenance. Changed sources, snapshots, references, byte pins or packaged bindings are refused. An unresolved selection forces `packaged-with-unknowns` and is listed in `unresolvedDataBindings`, even if the contract's free-text unknowns list is empty.

These are unsigned local integrity records. The treatment and description remain agent declarations. Readonly mapping does not prove runtime immutability or absence of alias writes; matching initialization bytes does not prove that implementation code uses them correctly. State lifetime, updates, reset, persistence and behavior need explicit design and separate executable comparisons. Packaging remains unverified.

Optional `resource:{path,payloadSha256}` additionally pins one exact supported parsed type/name/language payload containing the data target. The complete payload hash is distinct from the selected prefix hash. Ambiguous payloads, mismatched languages/hashes and prefixes crossing the payload boundary are refused. See [direct PE resource links](PE_RESOURCE_LINKS.md) for scope and limitations.

## Owned state example

`npm run verify:pe-state` selects four bindings from real REA-derived dependency rows:

- 12 initial bytes for the readonly rates 2/5/9 table, embedded-readonly.
- 8 initial bytes for the terminated `counter` label, embedded-readonly.
- 4 initial bytes for counter 7, modeled-state with explicit per-sequence initialization/update/reset behavior.
- An explicit prefix at a direct reference to the compiled `ready` string table, with the complete42byte payload hash and exact type/name/language path.

The emitted package retains all four bindings. Existing original/candidate comparisons across 40 sequences and 926 steps, reset-per-step mutant rejection, changed-settings rejection and original-free library/module reuse validate the declared example independently. Contracts and reconstruction receipts are also pinned acceptance inputs. Windows/UI execution and universal data/state closure remain unverified. See [the state example](PE_DATA.md) for prerequisites, runtime scope and result locations.
