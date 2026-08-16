# BlockScan v1.0.0

First stable release. BlockScan scans smart contracts on Ethereum and EVM-compatible
chains: it discovers a project's contracts, downloads verified source + on-chain
bytecode + details, runs a standardized security audit, and emits machine/human
output — plus a defensive monitoring/alerting subsystem and an agent-callable MCP server.

- Feature-complete · **637 tests green** (532 unit + 105 integration) · `cargo clippy --all-targets` zero warnings · workspace line coverage ~97.9%.
- Core paths verified against real chains.

## Highlights

- **Security audit engine — 36 detectors.** Three-layer taxonomy (OWASP SC Top 10 → SWC → rule_id), multi-factor scoring (risk 0–100 / grade A–F / P0–P3), SARIF 2.1.0 output, and `--suppress`. When source parses, **8 rules are AST-refined** via the `slang_solidity` parser **+ 1 AST-only `DELEGATECALL_ARBITRARY_TARGET`**, and a **binding graph** adds scope-aware name/type resolution (kills `uint160(addrVar)` / `uint8(enumVar)` / interface-receiver `endpoint.send(payload)` false positives). Graceful degradation to heuristics on any parse failure.
- **Discovery (`discover`)** from 7 sources: Blockscout name, GitHub deploys + audit scope, website/docs crawl, DefiLlama, Token Lists, **CoinGecko**, on-chain event topics, and Google web search.
- **Defensive monitoring** (`monitor` / `watch`): 8 security-event classes, new-deployment risk scoring, large-transfer alerts, cross-run baseline dedup, throttling/grouping, real-time chain-head alerting, multichain parallel watch — to `alerts.jsonl` / webhook / stdout.
- **MCP server** (`blockscan mcp`): JSON-RPC 2.0, 9 agent-callable tools + resources, over **stdio or local HTTP** (loopback-only + Origin validation + bounded body + optional Bearer auth).
- **Pipeline**: RPC + Etherscan V2 + Sourcify fallback, multi-standard proxy detection (EIP-1167/1967/Beacon/1822), static analysis + clone clustering, multichain `--chains`, resume/dedup, `--format json/ndjson/sarif`.

See the [Changelog](README.md#changelog) for the full list and [docs/](docs/) for per-domain design records.

## Artifacts

| File | Contents |
|---|---|
| `blockscan.zip` | the prebuilt `blockscan.exe` (x86_64-pc-windows-msvc) |
| `blockscan-1.0.0-x86_64-pc-windows-msvc.tar.gz` | `blockscan.exe` + `README.md` + `LICENSE` + `RELEASE_NOTES.md` |
| `blockscan-1.0.0-src.tar.gz` | full source tree (build with `cargo build --release`) |
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
- The security audit engine is a heuristic linter (a triage signal that needs human review), not a formal verifier.
- Without `--http-token`, the optional MCP HTTP endpoint trusts any local process; set a token on shared hosts.

## License

[MIT](LICENSE) © 2026 adomore
