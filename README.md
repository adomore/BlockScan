# BlockScan

[English](README.md) · [简体中文](README.zh-CN.md)

Scan smart contracts on Ethereum (and EVM-compatible chains): download **verified source**, **on-chain bytecode**, and **contract details**, save them per-contract, and automatically **discover** a project's related contracts. Written in Rust.

> Status: **1.0 stable** — feature-complete, **637 tests green, zero clippy warnings**, core paths verified against real chains.
>
> New here? Start with the **Getting Started guide: [English](docs/GETTING_STARTED.en.md) · [中文](docs/GETTING_STARTED.md)** (install → configure → first scan in ~10 min).
> User manual: **[English](docs/USER_MANUAL.en.md)** · **[中文](docs/USER_MANUAL.md)**; architecture / module inventory / LOC / feature-status matrix in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** (top-level design doc).

## Feature overview

| Area | Capability |
|---|---|
| **Scan modes** | `addresses` (explicit addresses) · `range` (historical blocks) · `watch` (real-time chain-head, graceful Ctrl-C) |
| **Data sources** | RPC (discovery/bytecode/balance) + Etherscan V2 (source/ABI/metadata/creator) + **Sourcify fallback** (source when unverified on Etherscan) |
| **Proxy detection** | EIP-1167 (bytecode) · EIP-1967 impl · **Beacon** (`eth_call implementation()` resolves the real logic address) · EIP-1822 UUPS — works even for unverified contracts |
| **Static analysis** | Zero-network derivation over downloaded bytecode: **ERC interface detection** (20/721/1155/165, even unverified) · **dangerous-opcode flags** (SELFDESTRUCT/DELEGATECALL/CALLCODE/CREATE/CREATE2) · **bytecode fingerprint + clone clustering** (metadata-stripped keccak, writes `clusters.json` with `--manifest`) |
| **Security audit engine** | A standalone, standardized engine that **detects vulnerabilities and scores them while scanning**: three-layer taxonomy (OWASP SC Top 10 → SWC → rule_id) · **36 detectors** (11 base + 25 deep: Access/Proxy/Reentrancy/Arithmetic/Oracle/Flash-loan/Token/**Governance/MEV/Bridge**, comment/string-aware source + bytecode + function-window; **8 rules AST-refined via slang + 1 AST-only `DELEGATECALL_ARBITRARY_TARGET`**) · multi-factor scoring (impact×likelihood×confidence×exposure) → **risk 0–100 + grade A–F + P0–P3** · report matrix · `--min-risk`/`--only-vulnerable` filters · `audit` offline re-scan subcommand · **SARIF 2.1.0 + partialFingerprints** (GitHub Code Scanning baselining/dedup) · **`--suppress` config** (silence FPs by rule/contract/swc/category/fingerprint, before scoring) |
| **Project → contracts** `discover` | name → Blockscout · `--github` → deployment artifacts + **audit scope** (README/scope markdown, Code4rena/Sherlock) · `--website` → site/docs shallow crawl (measured 304 contracts from one page) · `--defillama` → protocol anchor contract · `--tokenlist` → Token List filtered by chain (measured 390 from Uniswap) · `--coingecko` → a coin's `platforms` contract for the chain · `--topic` → on-chain event scan · Google web search |
| **Enrichment (`--table`)** | Blockscout name tag / project URL / token holdings (USD Top-3), cached + rate-limited |
| **Defensive monitoring** `monitor` / `watch` | Scan a range via `eth_getLogs`, decode **8 security-event classes** (proxy upgrade ×2 · ownership · admin · role granted/revoked · paused/unpaused); **`--min-transfer`** large transfers, **`--audit-deployments`** new-deployment risk scoring, **`watch --alert-on-risk`/`--alert-events`** real-time chain-head alerting, **`--baseline`** cross-run dedup, **`--throttle`** burst cap → structured `Alert` to `alerts.jsonl` / webhook / stdout stream; `--watchlist` to scope addresses |
| **Output** | Per-contract directory (metadata.json / bytecode.hex / abi.json / source/) · width-aware table · `--manifest` export json/csv · **`--format json\|ndjson`** machine-readable stdout (logs/progress/summary to stderr, for jq/agent pipelines) |
| **MCP server** `mcp` | `blockscan mcp` runs an MCP server (JSON-RPC 2.0, hand-written, zero new deps; **stdio or local HTTP** via `--http`) exposing audit/SARIF/scan as **agent-callable tools**: `audit_source` · `audit_corpus` · `get_contract` · `list_contracts` · `export_sarif` · `cluster_corpus` · `scan_addresses` · `scan_block_range` · `monitor_range`, plus the corpus via `resources/*` |
| **Multichain & ops** | `--chains` scan several chains in one run · filters `--only-verified/--min-balance/--only-proxy` · concurrency + rate-limit · resume/dedup · automatic RPC/Etherscan backoff retry (incl. rate-limit) |

See the sections below for detailed usage.

## Install & build

Requires **Rust 1.97.1 or newer** (`rust-version` in `Cargo.toml`; the floor comes from the `slang_solidity` parser, not from a preference) and a C/C++ linker (MSVC Build Tools recommended on Windows, or MinGW). A CI job builds against exactly that version.

```bash
cargo build --release
```

Prebuilt binaries for tagged releases are attached on the GitHub **Releases** page (see [Releases](#releases)).

## Configuration

Copy `.env.example` to `.env` and fill in:

```
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
```

You can also override on the command line with `--rpc-url` / `--etherscan-key`.

## Usage

```bash
# Scan explicit addresses (fastest sanity check)
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
blockscan addresses --file addrs.txt

# Scan a historical block range
blockscan range --from 19000000 --to 19000010

# Watch new deployments in real time (Ctrl-C to exit)
blockscan watch --confirmations 2 --poll-ms 4000

# Discover & scan a project's contracts (Blockscout name search + GitHub deploys)
blockscan discover "Uniswap V4"
blockscan discover --github Uniswap/v4-core --github aave/aave-v3-core

# Scan several chains at once (per-chain RPC from ETH_RPC_URL_<id>) and export a manifest
blockscan addresses 0xA0b8...EB48 --chains 1,8453 --manifest index.csv

# Keep only verified / high-balance / proxy contracts
blockscan range --from 19000000 --to 19000010 --only-verified --min-balance 100
```

Common global flags:

| Flag | Meaning | Default |
| --- | --- | --- |
| `--out, -o` | Output directory | `output` |
| `--concurrency` | Contracts processed concurrently | `5` |
| `--rate` | Etherscan requests/sec cap (set to your key's tier; free keys are often 3–5/s) | `5` |
| `--retries` | Attempts per RPC/Etherscan request (resilience against public-node jitter; also drives Etherscan rate-limit backoff retry) | `5` |
| `--chain-id` | Chain id (1 = Ethereum mainnet) | `1` |
| `--chains` | Scan several chains (comma-separated ids); each chain's RPC from `ETH_RPC_URL_<id>` | single chain |
| `--overwrite` | Re-fetch already-saved contracts | off |
| `--trace` | Additionally discover factory contracts via `trace_block` | off |
| `--table` | Print a normalized detail table per contract (balance in ETH) | off |
| `--no-sourcify` | Disable the Sourcify source fallback | on |
| `--sourcify-base` | Sourcify server URL | `https://sourcify.dev/server` |
| `--only-verified` | Keep only contracts with verified source | off |
| `--min-balance` | Keep only contracts with balance ≥ N ETH | `0` |
| `--only-proxy` | Keep only proxy contracts | off |
| `--manifest` | Export a summary to a file after scanning (`.json`/`.csv`) | none |
| `--blockscout-base` | Blockscout v2 API for `--table`/`discover`; empty to disable | `https://eth.blockscout.com/api/v2` |
| `--blockscout-rate` | Blockscout requests/sec cap (enrichment rate-limit) | `4` |
| `-v, -vv` | Increase log verbosity | info |

### Proxy detection (multi-standard)

`is_proxy`/`implementation`/`proxy_kind` are resolved in this order: Etherscan flag → bytecode **EIP-1167** minimal proxy → on-chain storage slots **EIP-1967** (a beacon further `eth_call`s `implementation()` to resolve the final logic address) / **EIP-1822 UUPS** (`eth_getStorageAt`). Works and fills in the implementation address even for unverified contracts.

### Source fallback (Sourcify)

When Etherscan has no verified source, BlockScan falls back to **Sourcify v2** (`verified_via` records the source `etherscan`/`sourcify`). Disable with `--no-sourcify`.

### Multichain & export

`--chains 1,8453,42161` scans several chains at once: Etherscan V2 routes by chainid, the Blockscout base is mapped per chain, and output lands in `<out>/<chainname>/`. Each chain's RPC is read from `ETH_RPC_URL_<id>` (the primary chain falls back to `ETH_RPC_URL`); missing ones are skipped with a warning. `--manifest index.json|index.csv` aggregates all saved contracts after the scan (recursively reading `metadata.json`).

### Project discovery (`discover`)

Given a project name / GitHub repo, BlockScan collects related contract addresses and runs them through the scan pipeline:

- **name** → Blockscout `/search` (matches name tag / token / contract).
- **name + Google credentials** → Google web search, extracting addresses from `/address/0x…` links in results (see below).
- **`--github owner/repo`** (repeatable) → reads deployment artifacts: hardhat-deploy `deployments/<net>/*.json` (incl. `implementation`) and Foundry `broadcast/**/run-latest.json`; and parses `0x{40}` + explorer links from `README.md` / `*scope*.md` — so you can point it straight at a **Code4rena / Sherlock contest repo** to pull the in-scope contracts (`GITHUB_TOKEN` raises rate limits).
- **`--website <url>`** (repeatable) → fetches site/docs pages, extracts addresses from body text and explorer links, and shallow-crawls one hop of same-host links containing `contract/deploy/docs/...` (`--crawl-depth` default 1, page-capped). Official "deployed addresses" docs pages are often the most authoritative source and need **no API key**.

  ```powershell
  blockscan discover --website https://docs.lido.fi/deployed-contracts/ --rate 3 -o out
  ```

  > Real result (that page, `--crawl-depth 0` = single page): **442 candidate addresses** extracted → on-chain `eth_getCode` drops **138 non-contracts** (EOAs etc.) → **304 contracts saved, 304/304 verified**, 0 failures.

- **`--defillama <slug>`** (repeatable) → a DefiLlama protocol's main token/governance contract (`/protocol/{slug}`'s `address`, one per protocol). Free, broadest, a good "project anchor".

  ```powershell
  blockscan discover --defillama lido --rate 3 -o out   # → LDO 0x5a98…1b32
  ```

- **`--tokenlist <url>`** (repeatable) → a standard Token List's `tokens[]`, filtered to the active `--chain-id`.

  ```powershell
  blockscan discover --tokenlist https://tokens.uniswap.org --rate 3 -o out   # 390 chain-1 contracts
  ```

- **`--coingecko <id>`** (repeatable) → a CoinGecko coin's contract on the active `--chain-id` (`/api/v3/coins/{id}`'s `platforms` map, free, no key). Chain id maps to a platform key (1→ethereum, 137→polygon-pos…).

  ```powershell
  blockscan discover --coingecko dai --coingecko usd-coin --rate 3 -o out
  ```

- **`--topic <hash> --from <block> --to <block>`** (topic repeatable) → `eth_getLogs` by event topic over a range, collecting the **emitting contracts**. e.g. `Upgraded`/`BeaconUpgraded` for proxies, `PoolCreated` for pools, `Transfer` for tokens. Chunked (`--log-chunk`, default 2000) + concurrent (`--log-concurrency`, default 4); a failed chunk is only a warning.

  ```powershell
  blockscan discover --topic 0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e `
    --from 19000000 --to 19000500 --log-chunk 50 --log-concurrency 8 --rate 3 -o out
  ```

  > Measured: a single Transfer block surfaced 53 contracts (47 verified). Concurrency matters: 500-block `eth_getLogs` took 36s at `--log-concurrency 1` vs 7s at `8` (**~5×**).

At least one source is required, or `discover` errors with the list of available sources.

#### Optional: Google web search

`discover` does no web search by default; provide two credentials to enable it (missing either → skipped, other sources unaffected):

1. **API key**: Google Cloud Console → new project → enable **Custom Search API** → create an API key → `GOOGLE_API_KEY`.
2. **Search engine id (cx)**: at [programmablesearchengine.google.com](https://programmablesearchengine.google.com/) create an engine with "Search the entire web" → copy the **Search engine ID** → `GOOGLE_CSE_ID`.
3. Free quota: 100/day.

```powershell
$env:GOOGLE_API_KEY = "AIza..."
$env:GOOGLE_CSE_ID  = "xxxxxxx:yyyy"
blockscan discover "Uniswap V4"          # the name goes to both Blockscout + Google
```

### Enrichment table (`--table`)

`--table` enriches each contract via the **free Blockscout API** (best-effort; `-` on failure/no-data, never blocks the scan): **name tag**, **project URL**, **token holdings** (top 3 by USD). Results are **cached per address** and **token-bucket rate-limited** (`--blockscout-rate`, default 4/s). Use `--blockscout-base` for a non-mainnet chain, or `--blockscout-base ""` to disable.

```text
+------------+--------------------------------------------------------------------+
| Address    | 0x000000000004444c5dc75cb358380d2e3de08a90                         |
| Name       | PoolManager                                                        |
| Verified   | yes                                                                 |
| Compiler   | v0.8.26+commit.8a97fa7a                                            |
| Proxy      | no                                                                 |
| Balance    | 51,092.965160 ETH                                                  |
| Holdings   | DOT(~$141.3M), USDT(~$65.7M), USDC(~$57.5M) …                      |
+------------+--------------------------------------------------------------------+
```

## Output layout

```
output/
  0xa0b8.../                 # contract address (lowercase)
    metadata.json            # full contract details
    bytecode.hex             # on-chain runtime bytecode
    abi.json                 # ABI (when verified)
    source/                  # verified source (project tree preserved)
      Contract.sol
      @openzeppelin/...
```

`metadata.json` fields: address, chain_id, bytecode + size, balance (wei), verified flag, contract name, compiler version, optimization, EVM version, license, constructor args, proxy flag + implementation, creator, creation tx hash, has-ABI, source file count, `analysis` (static analysis, below), `audit` (security audit, below).

## Security audit engine

A **standalone, standardized audit engine** (module `audit`) that detects vulnerabilities and scores them **while scanning**; results go into `metadata.json.audit`, the `--manifest` CSV, the `--table` view, and `--format json/ndjson/sarif`. It is a **Slither-lite heuristic linter** — a triage signal that **needs human review** (expect false positives/negatives). On by default; `--no-audit` disables it. See [docs/AUDIT_DESIGN.md](docs/AUDIT_DESIGN.md).

**Three-layer taxonomy**: `category` (L1 = OWASP Smart Contract Top 10, e.g. `SC01:Access Control`) → `swc` (L2 = SWC Registry id, e.g. `SWC-115`) → `rule_id` (L3 internal rule, e.g. `TX_ORIGIN_AUTH`). Each finding (SecurityFinding v2) carries severity, confidence, impact/likelihood, exploitability, asset-at-risk, blast-radius, risk (0–100), priority (P0–P3), locations, evidence, exploit scenario, recommendation, references, and FP notes.

**Detection layers**:
- **Source** (verified, line-scanned, comment/string-aware): tx.origin auth, selfdestruct, unprotected `initialize()`, delegatecall, low-level call, weak randomness, ecrecover, floating pragma, outdated compiler, assembly, deprecated constructs.
- **AST refinement** (when the source parses, via `slang_solidity`): 8 rules are upgraded from substring heuristics to context-aware AST checks — `TX_ORIGIN_AUTH` / `UNCHECKED_LOW_LEVEL_CALL` (+ intra-function dataflow) / `REENTRANCY_*` (CEI, incl. `receive`/`fallback`) / `ACCESS_MISSING_GUARD_PRIVILEGED_FN` / `WEAK_BLOCK_RANDOMNESS` / `ECRECOVER_NO_ZERO_CHECK` / `HARDCODED_GAS_TRANSFER_SEND` (arg-count) / `UNSAFE_DOWNCAST_TRUNCATION`. A **binding graph** (`slang BindingGraph`) adds scope-aware name/type resolution, eliminating type-dependent false positives (`uint160(addrVar)`, `uint8(enumVar)`, an interface receiver's `endpoint.send(payload)`). Plus one AST-only rule: `DELEGATECALL_ARBITRARY_TARGET`. On parse failure / deep nesting / panic it degrades to the line heuristics; **scoring is unchanged**.
- **Bytecode** (all contracts, reusing `analysis`): SELFDESTRUCT / DELEGATECALL / CALLCODE / CREATE2, unverified source.

**Scoring**: per finding `risk = impact × likelihood × confidence × exposure`; the overall risk is a probabilistic-OR aggregation deduped by weakness key (capped at 100) → grade A–F, risk_level, priority P0–P3.

```bash
# Scan, keep only contracts with a high/critical finding, JSON for jq
blockscan addresses --file addrs.txt --only-vulnerable --format json -o out \
  | jq -r '.contracts[] | "\(.audit.grade) \(.audit.risk_score) \(.address)"'

# Offline re-audit of an already-downloaded corpus (re-score after rule upgrades), sorted by risk
blockscan audit --by-risk -o out

# Export SARIF 2.1.0 for GitHub Code Scanning / CI
blockscan audit --format sarif -o out > findings.sarif

# Suppress confirmed FPs / accepted baseline (removed before scoring)
blockscan audit --suppress suppress.json -o out
```

**`--suppress <file>`** (global; applies to scanning and `audit`): a JSON config silencing confirmed **false positives** or **accepted baseline**. Each entry matches by `rule`/`contract`/`swc`/`category`/`fingerprint` (non-empty keys AND within an entry, OR across entries); matches are removed **before scoring**. A missing file / bad JSON / keyless entry → `warn` and suppress **nothing** (fail-safe).

```json
{ "suppress": [ { "rule": "ORACLE_SPOT_PRICE", "contract": "0xabc…", "reason": "uses TWAP" },
                { "swc": "SWC-112" }, { "fingerprint": "deadbeef12345678" } ] }
```

## Static analysis (`analysis`)

A zero-network derivation over each contract's **downloaded runtime bytecode**, written to `metadata.json.analysis` (and `--manifest` CSV / `--table`). Works even for **unverified** contracts.

- **ERC interface detection** `interfaces`: from `PUSH4` selectors (requires all core selectors of the standard; conservative, low FP).
- **Dangerous-opcode flags** `opcodes`: PUSH-immediate-aware linear scan flagging SELFDESTRUCT / DELEGATECALL / CALLCODE / CREATE / CREATE2.
- **Bytecode fingerprint** `code_hash` / `code_hash_nometa`: keccak of the full bytecode, and of the bytecode with the trailing CBOR metadata stripped — so "same logic, different metadata" clones share a fingerprint.
- **Clone clustering**: with `--manifest`, also writes `clusters.json` grouping size≥2 clone families by `code_hash_nometa`.

```bash
blockscan addresses --file addrs.txt --manifest out/index.json -o out
cargo run --release --example analyze -- 24000 100000   # CPU probe: 24KB ≈ 0.13ms
```

## Defensive monitoring (`monitor`)

Scans a block range for **security-relevant events**, decodes them into structured alerts, and lands them in `alerts.jsonl` / webhook / stdout — turning on-chain "proxy upgrades, ownership/admin changes" into a consumable threat-intel stream (cron-friendly).

| Event | Meaning |
|---|---|
| `Upgraded` / `BeaconUpgraded` | proxy implementation/beacon upgraded |
| `OwnershipTransferred` | ownership transferred |
| `AdminChanged` | proxy admin changed |
| `RoleGranted` / `RoleRevoked` | AccessControl role granted/revoked |
| `Paused` / `Unpaused` | Pausable emergency pause/resume |
| `Transfer` (large, opt-in) | ERC-20 transfer ≥ `--min-transfer` |

```bash
# Monitor a recent range for upgrades/ownership changes → alerts.jsonl + webhook
blockscan monitor --from 25417000 --to 25417200 \
  --alerts alerts.jsonl --webhook-url https://hooks.example.com/x -o out

# New-deployment risk scoring: audit all new contracts, alert only on risk ≥ 50 (needs key)
blockscan monitor --from 25417000 --to 25417200 --audit-deployments --min-risk 50 \
  --alerts alerts.jsonl -o out

# Cross-run dedup: re-run the same range periodically; --baseline records seen fingerprints
blockscan monitor --from 25417000 --to 25417200 --baseline seen.fp --alerts alerts.jsonl -o out
```

- **`--audit-deployments`**: full audit of each new deployment; alerts `kind:"risky-deployment"` when `risk_score > 0 && ≥ --min-risk`. Needs an Etherscan key; mutually exclusive with `--no-audit`.
- **`--baseline <file>`**: cross-run dedup via a stable `chain|block|contract|event|tx_hash|log_index|…` fingerprint.
- **`--min-transfer <amount>`** / **`--throttle <N>`** / **`--group`**: large-transfer monitoring (opt-in), per-`(chain,contract,kind)` burst cap, and folding high-frequency alerts into an end-of-run digest, respectively.
- **stdout** is a per-alert JSON stream; `--alerts` appends; `--webhook-url` is best-effort POST; any sink failure only `warn!`s — the monitor loop never aborts.

### Real-time alerting (`watch --alert-on-risk` / `--alert-events`)

Adding any alert flag to `watch` enters **real-time alert mode**: it follows the chain head and runs the alert pipeline per confirmed block, reusing the sinks + `--baseline` dedup.

```bash
# Real-time: new-deployment audit + security events, alert at risk ≥ 50, dedup across ticks
blockscan watch --alert-on-risk --alert-events --min-risk 50 \
  --alerts alerts.jsonl --baseline seen.fp --confirmations 2 -o out

# Events only: proxy upgrades/ownership changes, no Etherscan key needed
blockscan watch --alert-events --webhook-url https://hooks.example.com/x
```

- **`--chains` (alert mode only)**: multichain **parallel** watch (per-chain RPC from `ETH_RPC_URL_<id>`); independent dedup/throttle/group per chain, a single Ctrl-C stops all.
- A block whose logs/receipts fail to fetch **does not advance** — the next tick re-scans (with `--baseline` dedup), never silently skipping.

## Machine-readable output (`--format`)

`--format` (global, default `human`) controls **stdout**: in machine modes **stdout carries data only**, with logs/progress/summary on **stderr** — pipe straight to `jq` or an agent.

| Mode | stdout |
|---|---|
| `human` (default) | tables (`--table`), summary line |
| `json` | one `{ run, stats, contracts }` document (with full `analysis`/`audit`) |
| `ndjson` | **streaming**: one compact JSON line per saved contract |
| `sarif` | **SARIF 2.1.0** (audit findings) for GitHub Code Scanning / CI / IDE |

```bash
blockscan addresses --file addrs.txt --format json -o out \
  | jq -r '.contracts[] | select(.analysis.interfaces|index("ERC-20")) | .address'
```

## MCP server (`blockscan mcp`)

Exposes BlockScan as **agent-callable tools** via an MCP (Model Context Protocol) server speaking JSON-RPC 2.0. Hand-written, **zero new runtime deps**; `stdout` carries protocol messages only, logs go to `stderr`. See [docs/MCP_DESIGN.md](docs/MCP_DESIGN.md).

Register it in your MCP client (Claude Desktop / IDE) as a stdio server:

```json
{ "mcpServers": { "blockscan": { "command": "blockscan", "args": ["mcp"] } } }
```

**Local HTTP transport (Streamable HTTP, optional)**: `blockscan mcp --http <addr>` serves a single `/mcp` POST endpoint on a loopback address. `<addr>` may be a bare port (`8765`), `host:port`, or a bare host (default port 8765); **loopback-only** (non-loopback aborts at startup), with `Origin` validation against DNS-rebinding.

```bash
blockscan mcp --http 8765                                                  # 127.0.0.1:8765/mcp
blockscan mcp --http 127.0.0.1:9000 --http-token "$BLOCKSCAN_MCP_TOKEN"     # Bearer auth
```

> ⚠️ Without `--http-token` the endpoint is open to any local process (no auth; the Origin/loopback guard only stops browser cross-site, not a local malicious process). On multi-user/shared hosts always set `--http-token` (or `BLOCKSCAN_MCP_TOKEN`); clients send `Authorization: Bearer <token>`. HTTP and stdio share the exact same handler and 9 tools.

| Tool | Network | Purpose |
|---|---|---|
| `audit_source` | offline | audit inline Solidity source +/or bytecode → standardized `Audit` |
| `audit_corpus` | offline | re-audit all contracts under `--out` |
| `get_contract` | offline | read a saved contract's metadata (optionally source) |
| `list_contracts` | offline | list saved contracts (light), filter by last audit |
| `export_sarif` | offline | re-audit the corpus and export SARIF 2.1.0 |
| `cluster_corpus` | offline | cluster clone families by metadata-stripped bytecode hash |
| `scan_addresses` | online | scan given addresses (code+source+audit+save), needs `rpc_url`+`etherscan_key` |
| `scan_block_range` | online | scan a bounded range (≤500 blocks), audit + save |
| `monitor_range` | online | decode security events over a bounded range (≤500), return alerts; only needs `rpc_url` |

Also exposes **resources**: `resources/list` lists each saved contract as `blockscan://contract/<address>`, `resources/read` returns its metadata JSON. Address args are validated to prevent path traversal.

## Tests

```bash
cargo test                 # 693 tests: 588 unit + 105 integration
cargo clippy --all-targets # zero warnings
```

Integration tests use `wiremock` to mock RPC and Etherscan/Blockscout/Sourcify/GitHub/Google/website/DefiLlama/TokenList/CoinGecko locally — **no real network access**. Coverage (needs `cargo install cargo-llvm-cov`):

```bash
cargo llvm-cov --ignore-filename-regex 'main\.rs' --show-missing-lines
```

Workspace line coverage **97.76%** (regions 97.27%, functions 98.86%) — measured by the `coverage` job on every push and gated there at 97%, never maintained by hand. Only the percentage is recorded here: exact line counts shift with every commit, so that job's log is the source of truth.
`audit.rs`, `model.rs`, `events.rs`, `group.rs`, `suppress.rs`, `baseline.rs`, `report.rs`, `sarif.rs`, `config.rs`, `chains.rs` and `throttle.rs` are at 100%; `ast.rs` 97.00%, `mcp.rs` 97.54%.
The largest single gap is `lib.rs` at **91.3%** (roughly four in ten of all uncovered lines) — the watch/monitor loops and multichain fan-out, whose error paths need a live chain to reach. The rest are defensive `?`/unreachable cursor-API guards.

## Factory discovery (`--trace`)

Default block discovery uses receipt `contract_address` (top-level deploys only). With `--trace`, `range`/`watch` also call `trace_block` per block to find contracts deployed **internally** via CREATE/CREATE2, merged + deduped with receipts.

```bash
blockscan range --from 19000000 --to 19000010 --trace
blockscan watch --trace
```

- Requires an RPC with the `trace_` namespace enabled (Erigon / Reth / Nethermind / archive providers).
- If the RPC does not support it, the `trace_block` call is **warned-and-skipped** (not fatal); the block is still processed for top-level deploys.

## Known limitations

- Source comes from Etherscan, falling back to Sourcify when unverified; with neither, only bytecode + available metadata are saved.
- `discover` web search uses Google Custom Search (needs `GOOGLE_API_KEY` + `GOOGLE_CSE_ID`, 100/day free).
- Multichain RPCs are provided per chain via `ETH_RPC_URL_<id>`; single-chain uses `--rpc-url`.
- Human-mode stdout uses standard prints; a closed downstream pipe can surface as an I/O error (the tool's primary output is the filesystem).
- The audit engine is a heuristic linter — a triage signal, not a verifier. Review findings.

## Releases

Tagged releases attach a prebuilt Windows binary on the GitHub **Releases** page:

- `blockscan.zip` — contains `blockscan.exe` (x86_64-pc-windows-msvc).
- `blockscan-<version>-x86_64-pc-windows-msvc.tar.gz` — the binary bundled with `README.md`, `LICENSE`, and `RELEASE_NOTES.md`.
- `SHA256SUMS` — SHA-256 checksums for every release artifact (verify with `sha256sum -c SHA256SUMS`, or PowerShell `Get-FileHash`).
- `RELEASE_NOTES.md` — notes for the release.

## Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

### [1.0.0] - 2026-06-30

First stable release (everything since 0.1.0 hardened into 1.0). On top of 0.1.0:

- **Security audit engine** deepened to **36 detectors**: when source parses, **8 rules are AST-refined via slang + 1 AST-only `DELEGATECALL_ARBITRARY_TARGET`** (tx-origin / unchecked-call + intra-function dataflow / reentrancy CEI incl. `receive`/`fallback` / access-control / weak-randomness / ecrecover / transfer-send arg-count / narrowing cast); a **binding graph** (`slang BindingGraph`) brings scope-aware name/type resolution, eliminating type-dependent false positives (`uint160(addrVar)`/`uint8(enumVar)`/`endpoint.send(payload)`), with three-level graceful degradation.
- **Discovery** added `--coingecko` (a coin's contract for the chain).
- **Defensive monitoring** full suite (`monitor`/`watch` real-time + deployment risk scoring + `--baseline` dedup + `--throttle`/`--group`/`--digest-interval` + alert-mode multichain parallel); **MCP server** with 9 tools + resources (stdio + local HTTP; loopback + Origin validation + bounded body + optional Bearer).
- **Pre-release hardening audit** fixed a batch of robustness/security issues: Etherscan 5xx/429 retry, websearch/github status + address-boundary checks, `min_balance` fail-closed, Blockscout no-cache-on-failure, `storage` write-boundary sanitize, MCP constant-time token compare + reject `Origin: null`, stable risky-deployment digest ordering, AST depth-guard covering flat chains; added the MIT LICENSE + publish metadata.
- Engineering: **637 tests** (532 unit + 105 integration), `cargo clippy --all-targets` zero warnings, workspace line coverage ~97.9%.

### [0.1.0] - 2026-06-28

First version: the three scan modes, RPC + Etherscan V2 + Sourcify data sources, multi-standard proxy detection, static analysis + clone clustering, the standardized security audit engine, `discover` from multiple sources, defensive monitoring, machine-readable output, the MCP server, multichain scanning, and resume/dedup. See [docs/](docs/) for the per-phase design records.

## License

[MIT](LICENSE) © 2026 adomore
