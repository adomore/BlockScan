# BlockScan v1.1.0

A precision and provenance release. BlockScan scans smart contracts on Ethereum and
EVM-compatible chains: it discovers a project's contracts, downloads verified source +
on-chain bytecode + details, runs a standardized security audit, and emits machine/human
output — plus a defensive monitoring/alerting subsystem and an agent-callable MCP server.

Two strands since 1.0.0: eight phases deepening the audit engine's precision through the
slang binding graph, and an external source-and-documentation audit whose 17-task manifest
is now 13 tasks complete.

- **794 tests green** (667 unit + 112 integration + 11 MCP hardening + 4 docs lockstep) ·
  `cargo clippy --all-targets` zero warnings · workspace line coverage gated at 97%.
- Every corpus figure below was measured against the committed 42-contract corpus, not estimated.

## Highlights

- **A scan is now reproducible.** Every state read routes through one block — resolved once
  at scan start, or chosen with `--at-block` — and `metadata.json` records `block_number`
  and `block_hash`. Two scans at the same pin produce byte-identical output. The hash sits
  beside the height because a height alone does not identify chain state across a reorg.
- **Audit precision, measured.** Reentrancy state writes and access-control decisions now
  resolve through the binding graph rather than through names: a privileged function is
  judged by what it writes, `_msgSender()` counts as the caller, and the reentrancy call
  surface covers contract-typed and cast receivers (`IERC20(a).m()`). Two rules that used a
  fixed look-ahead of N lines now take their scope from a function body, so a guard
  belonging to an adjacent call no longer suppresses one that has none. Corpus effect:
  `PROXY_UNPROTECTED_INITIALIZER` 17 → 1, `WEAK_BLOCK_RANDOMNESS` 13 → 0,
  `UNSAFE_DOWNCAST_TRUNCATION` 138 → 107, all rules 817 → 773 occurrences.
- **The MCP surface is hardened.** The output directory is constrained to the server's base
  directory; HTTP mode **requires** a bearer credential and mints one when started without
  it; the outbound RPC endpoint comes from a launch-time `--rpc-allow` list rather than from
  the request, and transport failures are collapsed so the tool cannot serve as a port
  scanner. These three closed one reachable path, not three independent ones.
- **Results can be verified by whoever receives them.** `blockscan bundle` assembles the
  artefacts you already produced, an in-toto Statement v1 manifest carrying SLSA Provenance
  v1 (sha256 **and** keccak256 digests, plus the block pin the results describe), and a
  detached signature from `cosign`. No key is handled by this tool and no trust chain is
  invented here.
- **Reports for people, not only pipelines.** `--manifest report.md` / `report.html` produce
  a document with the overview, the severity tally and each contract's findings, locations,
  evidence and remediation. The HTML is a single self-contained file — styles inlined, no
  scripts, no external requests — so it can be attached and forwarded as is. No PDF writer
  was added and none should be; `.pdf` is refused with a pointer at pandoc.
- **Output that does not overstate itself.** A failed explorer lookup is recorded as
  unanswered rather than as absence, and counted as a degraded record; the risk score states
  how many findings suppression removed from it; `import.rs` normalises another analyser's
  results into the same shape without touching the score or inventing fields it cannot know.
- **Declared constraints.** `rust-version = "1.97.1"` (inherited from `slang_solidity`, not
  chosen) with a CI job that builds against exactly it; the bilingual README pair is
  structurally checked in CI; parse errors no longer embed an unbounded response body.

See the [Changelog](README.md#changelog) for the full list and
[docs/](https://github.com/adomore/BlockScan/tree/main/docs) for per-domain design records.

## Artifacts

| File | Contents |
|---|---|
| `blockscan.zip` | the prebuilt `blockscan.exe` (x86_64-pc-windows-msvc) |
| `blockscan-1.1.0-x86_64-pc-windows-msvc.tar.gz` | `blockscan.exe` + `README.md` + `LICENSE` + `RELEASE_NOTES.md` |
| `blockscan-1.1.0-src.tar.gz` | full source tree (build with `cargo build --release`) |
| `SHA256SUMS` | SHA-256 checksums for the archives above |

## Install (prebuilt binary)

1. Download `blockscan.zip` and extract `blockscan.exe`.
2. (Optional) put it on your `PATH`.
3. Configure credentials — copy `.env.example` to `.env`, or pass `--rpc-url` / `--etherscan-key`:

```
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
```

4. Run:

```powershell
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
```

Building from source needs **Rust 1.97.1 or newer**; the floor is declared in `Cargo.toml`
and comes from the `slang_solidity` parser.

## Verify the download

```bash
# Linux/macOS or Git Bash
sha256sum -c SHA256SUMS
```

```powershell
# PowerShell — compare against the value in SHA256SUMS
Get-FileHash .\blockscan.zip -Algorithm SHA256
```

## Notes

- Requires an Ethereum RPC endpoint and an Etherscan V2 API key for source/metadata.
- The security audit engine is a heuristic linter (a triage signal that needs human review),
  not a formal verifier.
- **Changed in 1.1.0:** the MCP HTTP endpoint no longer trusts an unauthenticated local
  process. Started without `--http-token` it generates a credential and logs it, so an
  existing client that sent no `Authorization` header now receives 401. stdio mode is
  unchanged and stays credential-free — it has no network surface.
- `blockscan bundle` shells out to `cosign` for the detached signature. Without it on
  `PATH` the bundle is still written, and the error quotes the exact command to sign it by
  hand; `--unsigned` skips signing and marks the bundle accordingly.

## License

[MIT](LICENSE) © 2026 adomore
