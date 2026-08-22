# BlockScan User Manual

> 🌐 Language: **English** · [中文](USER_MANUAL.md)

BlockScan is a Rust command-line tool that **discovers Ethereum (and EVM-compatible) smart contracts → downloads verified source + on-chain bytecode + contract details → runs static analysis and a security audit → filters → persists → emits human/machine-readable output**, plus a **defensive monitoring/alerting** track and an **MCP server** that exposes all of the above to AI agents.

> 🚀 **First time?** Start with the [Getting Started guide (GETTING_STARTED.en.md)](GETTING_STARTED.en.md) — install, configure, and scan your first contract in ten minutes. This manual is the full per-flag reference.

> This manual is for users. For architecture and module internals see [ARCHITECTURE.md](ARCHITECTURE.md); per-area design docs are [AUDIT_DESIGN.md](AUDIT_DESIGN.md) / [MONITOR_DESIGN.md](MONITOR_DESIGN.md) / [DISCOVERY_DESIGN.md](DISCOVERY_DESIGN.md) / [OUTPUT_DESIGN.md](OUTPUT_DESIGN.md) / [MCP_DESIGN.md](MCP_DESIGN.md).

### Feature status at a glance

**✅ Done**: three scan modes (`addresses`/`range`/`watch` download + `--trace` factory discovery + `--chains` multichain) · project discovery `discover` (Blockscout/GitHub/website/Google/DefiLlama/TokenList/CoinGecko/event-topic) · detail download (RPC + Etherscan V2 + Sourcify fallback, proxies EIP-1167/1967/1822) · static analysis (opcodes/ERC interfaces/keccak fingerprints/clone clustering) · **security audit engine** (36 detectors · OWASP→SWC→rule_id→SCWE/EthTrust · multi-factor scoring · **AST refinement + intra-function dataflow + reentrancy + access-control + weak-randomness + ecrecover + arbitrary delegatecall + transfer/send arg-count + narrowing cast**) · `--suppress` · SARIF 2.1.0 · human/machine output (`--format`/`--manifest`/`--table`) · **defensive monitoring** (`monitor` range + `watch` chain-head + deployment risk scoring + `--baseline` dedup + `--throttle`/`--group` + `--digest-interval` + alert-mode multichain) · **MCP server** (9 tools + resources; stdio + local HTTP transport).

**🔜 Next**: binding-graph follow-ups (audit Phase 23+) — extend Phase 22's `BindingGraph` to reentrancy (arbitrary external-call surface + cross-file inherited state), access-control (drop the name heuristics), and delegatecall local-alias resolution; more discovery sources (CMC, ethereum-lists, full Sourcify, 4byte clustering, factory expansion, Dune); WS `subscribe` instead of polling; multichain download-mode `watch`.

**📋 TODO**: more discovery sources (CMC, ethereum-lists, full Sourcify enumeration, 4byte clustering, factory expansion, Dune) · more AST detectors & deep rule families.

> Full ✅/🔜/📋 status matrix: [ARCHITECTURE.md#功能状态矩阵](ARCHITECTURE.md).

---

## Contents
1. [Install & build](#1-install--build)
2. [Configuration](#2-configuration)
3. [Quickstart](#3-quickstart)
4. [Subcommand reference](#4-subcommand-reference)
5. [Security audit engine](#5-security-audit-engine)
6. [Defensive monitoring & alerts](#6-defensive-monitoring--alerts)
7. [MCP server](#7-mcp-server)
8. [Output formats & on-disk layout](#8-output-formats--on-disk-layout)
9. [Global options cheat-sheet](#9-global-options-cheat-sheet)
10. [Troubleshooting / FAQ](#10-troubleshooting--faq)

---

## 1. Install & build

Requires Rust (2021 edition) and a working C linker toolchain.

```bash
# Build (on Windows you need the MSVC toolchain; see note below)
cargo build --release        # produces target/release/blockscan
cargo test                   # 637 tests, all green (532 unit + 105 integration)
cargo clippy --all-targets   # zero warnings
```

- **Windows**: the toolchain must be `stable-x86_64-pc-windows-msvc` (the gnu toolchain lacks dlltool/gcc and can't link); install the MSVC Build Tools (C++ workload + Windows SDK).
- **Networking**: default HTTP/2 to `api.etherscan.io` and some public RPCs can fail with "error sending request"; BlockScan internally forces **HTTP/1.1 + 30s timeout + retries** for both the Etherscan and RPC clients, so no extra setup is needed.

Put `target/release/blockscan` on your `PATH` to use `blockscan` globally.

---

## 2. Configuration

Credentials and endpoints can come from **CLI flags** or **environment variables** (a `.env` in the working directory is honored).

| Env var | Equivalent flag | Notes |
|---|---|---|
| `ETH_RPC_URL` | `--rpc-url` | JSON-RPC endpoint (discovery / bytecode / chain state). e.g. `https://ethereum-rpc.publicnode.com` (no key) |
| `ETHERSCAN_API_KEY` | `--etherscan-key` | Etherscan **V2** API key (verified source/metadata). Not needed for `monitor` (events only) or `watch --alert-events` |
| `GITHUB_TOKEN` | `--github-token` | Higher rate limits for GitHub discovery (optional) |
| `GOOGLE_API_KEY` / `GOOGLE_CSE_ID` | `--google-api-key` / `--google-cse-id` | Enable Google web-search discovery (optional) |

`.env` example:
```
ETH_RPC_URL=https://ethereum-rpc.publicnode.com
ETHERSCAN_API_KEY=YourEtherscanV2Key
```

> The Etherscan free tier is often **3 req/s** — set `--rate` to your tier (excess is rate-limited but retried with backoff).

---

## 3. Quickstart

```bash
# Download one verified contract (fastest check): source + bytecode + details + audit
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 -o out

# Scan a historical block range for new deployments
blockscan range --from 19000000 --to 19000050 -o out

# Discover & scan a project's contracts (Blockscout search + GitHub deploy files)
blockscan discover "Uniswap V4" --github Uniswap/v4-core -o out

# Re-audit a local corpus offline, sorted by risk
blockscan audit --by-risk -o out

# Monitor a range for security events (proxy upgrades / ownership changes…) -> alerts.jsonl
blockscan monitor --from 21000000 --to 21000100 --alerts alerts.jsonl -o out

# Start an MCP server so an agent can call the audit/scan tools
blockscan mcp -o out
```

Machine-readable output: add `--format json` (or `ndjson`/`sarif`) to any command — **stdout carries only data**, logs/progress/summary go to stderr, so you can pipe straight to `jq`.

---

## 4. Subcommand reference

### `addresses` — scan specific addresses
```bash
blockscan addresses <addr...> [--file addrs.txt] [global options] -o out
```
- Pass one or more addresses, and/or `--file` (one per line, `#` comments and blank lines ignored).
- Per address: fetch on-chain runtime bytecode (empty ⇒ EOA/self-destructed, skipped) + balance + Etherscan source/ABI/metadata + creation info; detect proxies (EIP-1167/1967/1822); fall back to Sourcify when unverified (unless `--no-sourcify`); run the security audit (unless `--no-audit`); persist if it passes filters.

### `range` — scan a historical block range
```bash
blockscan range --from <N> --to <M> [--trace] -o out
```
- Walks `[N, M]`, using each receipt's `contractAddress` to find **top-level deployments**. `--trace` additionally uses RPC `trace_block` to find factory (CREATE/CREATE2) children (requires the RPC's `trace_` namespace; failure is only a warning).

### `watch` — follow the chain head in real time
Two modes:
- **Download mode (default)**: follow the head, downloading every new deployment in each newly confirmed block.
  ```bash
  blockscan watch --confirmations 2 --poll-ms 4000 -o out   # Ctrl-C for graceful exit
  ```
- **Real-time alert mode** (with any alert flag): each confirmed block runs the alert pipeline instead of bulk-downloading. See [§6](#6-defensive-monitoring--alerts).
  ```bash
  blockscan watch --alert-on-risk --alert-events --min-risk 50 \
    --alerts alerts.jsonl --baseline seen.fp --confirmations 2 -o out
  ```
- `--confirmations` lags the head (avoids reorgs); `--poll-ms` is the poll interval.

### `discover` — discover & scan a project's contracts
```bash
blockscan discover [name] [--github owner/repo]... [--website url]... \
  [--defillama slug]... [--tokenlist url]... [--coingecko id]... \
  [--topic 0x.. --from N --to M] -o out
```
Multi-source fan-out (each source's failure is only a warning); the union (deduped) feeds the scan pipeline (**at least one source is required, else it errors**):
- **name** → Blockscout name search (+ optional Google web search, needs credentials).
- `--github owner/repo` (repeatable) → addresses from hardhat-deploy / Foundry broadcasts / audit-scope markdown.
- `--website <url>` (repeatable) + `--crawl-depth` → addresses from the site/docs pages and explorer links (shallow same-host crawl).
- `--defillama <slug>` (repeatable) → the protocol's anchor contract.
- `--tokenlist <url>` (repeatable) → a standard Token List's `tokens[]` (filtered by `--chain-id`).
- `--coingecko <id>` (repeatable) → the coin's contract on the active `--chain-id` from CoinGecko `/coins/{id}` `platforms` (free, no key).
- `--topic <hash> --from --to` → `eth_getLogs` by event topic over a range, collecting the emitting contracts (`--log-chunk`/`--log-concurrency` control chunking/concurrency).

### `monitor` — range-based security-event monitoring
See [§6](#6-defensive-monitoring--alerts).

### `audit` — re-audit a downloaded corpus offline
```bash
blockscan audit [--by-risk] [--min-risk N] [--only-vulnerable] [--suppress f.json] \
  [--format human|json|ndjson|sarif] -o out
```
- **No network**: re-runs the audit over every contract already saved under `-o` (batch re-scoring after rule upgrades). `--by-risk` sorts by risk score descending. Filters as in scan mode. See [§5](#5-security-audit-engine).

### `mcp` — MCP server
Defaults to stdio; `--http <addr>` switches to local HTTP transport, `--http-token <token>` (or env `BLOCKSCAN_MCP_TOKEN`) adds Bearer auth. See [§7](#7-mcp-server).

---

## 5. Security audit engine

A **standalone, standardized heuristic audit engine**: it detects vulnerabilities while scanning and scores them. Results go into `metadata.json`'s `audit` field, the `--manifest` CSV, the `--table` view, and the `--format json/ndjson/sarif` output. It is a **Slither-lite linter** — a **triage signal that needs human review** (expect false positives/negatives). On by default; `--no-audit` disables it.

- **Three-layer taxonomy**: OWASP Smart Contract Top 10 (`category`) → SWC registry (`swc`, only when it genuinely matches) → internal `rule_id`; plus external `scwe` (OWASP SCWE) and `ethtrust` (EEA EthTrust requirement) refs (filled only on a high-confidence exact match); **36 detectors** (Access / Proxy-Upgrade / External-Calls / Reentrancy / Oracle / Flash-loan / Token / Governance / MEV / Bridge / Arithmetic…), over source (comment- and string-aware) + bytecode + function-window scans.
- **AST refinement + intra-function dataflow** (when the source parses, via the `slang_solidity` parser): `TX_ORIGIN_AUTH` only fires in an authorization context (`==`/`!=`/`<`/`>`/`if`/`require`/`assert`) and `UNCHECKED_LOW_LEVEL_CALL` only when a low-level `.call`'s result is not consumed — eliminating the substring heuristics' false positives (`return tx.origin`, `mytx.origin`, `require(x.call())`); tagged `detection: ast`. For the bound form (`(bool ok,)=a.call()`) it adds **intra-function dataflow**: the success flag is only suppressed when gated after the call (`require`/`assert`, an `if`/`while`/`for` condition, or a direct `return`) — so `(bool ok,)=a.call(); require(ok);` is no longer a false positive, while a bound-but-unchecked `(bool ok,)=x.call{value:..}("")` still fires (SWC-104). `REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE` is also AST-based: a low-level external call followed by a **state-variable** write (assignment/`++`/`delete`/tuple/`push`-`pop`) with no `nonReentrant` guard — writing a **local** or a CEI-safe ordering (write before the call) is no longer a false positive. `ACCESS_MISSING_GUARD_PRIVILEGED_FN` is AST-based: a privileged-named, public/external, implemented, **non-view/pure** function with no guard (a structural `only*`/`auth`/`restrict` modifier, a `msg.sender` check in a require/if/comparison, or a `_checkOwner`/`_checkRole` call) — with structural modifier detection, whole-function `msg.sender` scanning, and interface/abstract declarations skipped. `WEAK_BLOCK_RANDOMNESS` is AST-based: a block source (`block.timestamp`/`number`/`difficulty`/`prevrandao`/`blockhash(..)`) is flagged only in a randomness context (`%` modulo or a `keccak`/`sha` seed) — deadline checks and timestamp bookkeeping are no longer false positives. `ECRECOVER_NO_ZERO_CHECK` is AST-based: an `ecrecover(..)` whose recovered address is never compared to `address(0)`/`0` (inline or via a bound variable) — well-written verification (`require(s != address(0))`, EIP-2612 permit / meta-tx) is no longer a false positive. A new **AST-only** `DELEGATECALL_ARBITRARY_TARGET` (**Critical**, SWC-112) fires only when a `.delegatecall`'s target base identifier is a **parameter of the enclosing function** (caller-controlled, Parity-wallet-class takeover) — a fixed `impl` state-variable target or another function's same-named parameter is not flagged, while modifier/constructor parameters are caught. `HARDCODED_GAS_TRANSFER_SEND` is AST-based: the **argument count** discriminates — a 1-arg `addr.transfer/send(x)` (2300-gas ETH send) fires, a ≥2-arg ERC-20 `transfer(to,amt)`/`transferFrom(..)` does not (removing the `dai.transfer(to,amt)` false positive), and a string/bytes-literal or `abi.encode*` argument means a messaging send (`bridge.send(payload)`), not ETH, so it is suppressed. `UNSAFE_DOWNCAST_TRUNCATION` is AST-based: a narrowing `uintN/intN` cast (N<256) fires only when its argument is not a numeric literal, not a same-family equal-or-narrower nested cast, and not a lossless `uint160+(address(..))`. On parse failure / excessive nesting / a parser panic it degrades back to the line heuristics; **scoring is unchanged**. (Residual over-reports that need type resolution — `uint160(addrVar)`, `uint8(enumVar)`, an identifier receiver like `endpoint.send(x)` — are deferred to the scope-aware name/type resolution phase.)
- **Scoring**: per finding `risk = impact × likelihood × confidence × exposure`; the overall score is a probabilistic-OR aggregation deduped by weakness key (capped at 100) → **risk score 0–100 + grade A–F + risk_level + priority P0–P3**.
- **Filters**: `--min-risk <0–100>` keeps contracts with risk ≥ threshold; `--only-vulnerable` keeps only contracts with a high/critical finding.
- **SARIF**: `--format sarif` emits SARIF 2.1.0 (with `partialFingerprints`), ready for GitHub Code Scanning / CI.

### Suppressing false positives: `--suppress <file>`
A JSON file that silences findings you've triaged as **false positives** or accepted as a **baseline**; matched findings are dropped **before scoring** (so the score and summary drop too). Honored by both scan mode and the offline `audit` subcommand.

```json
{
  "suppress": [
    { "rule": "ORACLE_SPOT_PRICE", "contract": "0xabc…", "reason": "uses a TWAP" },
    { "rule": "DELEGATECALL_USAGE" },
    { "swc": "SWC-112" },
    { "category": "SC06:Unchecked External Calls" },
    { "fingerprint": "deadbeef12345678" }
  ]
}
```
- Every key in an entry is optional; an entry matches when **all of its non-empty keys match** (AND); entries are OR-ed. `reason` is documentation only.
- `rule` = rule_id; `contract` is case-insensitive (when present, it scopes `rule` to that contract); `swc`/`category` are exact; `fingerprint` is a finding's SARIF fingerprint (`keccak16(rule|contract|file|evidence)`, to suppress a single instance / build a baseline).
- **Safe direction**: a missing / malformed / key-less config only **warns** and suppresses nothing (better to over-report than silently hide).

### Limitations
Heuristic, not formal verification; `TX_ORIGIN_AUTH`/`UNCHECKED_LOW_LEVEL_CALL`/`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`/`ACCESS_MISSING_GUARD_PRIVILEGED_FN`/`WEAK_BLOCK_RANDOMNESS`/`ECRECOVER_NO_ZERO_CHECK` use AST refinement + intra-function dataflow when the source parses (else they fall back to heuristics). Residual tradeoffs: indirect tx.origin auth (stored then required in a later statement, or used as a mapping-write key) is not flagged; a low-level `.call` has no type info, so a user function literally named `call` is a false positive; reentrancy only recognizes low-level external-call sinks (an arbitrary `x.foo()` external call is not flagged) + same-file state variables (a base contract's state var in another file is missed — flattened sources are unaffected) + `nonReentrant`-style modifier guards (a hand-rolled boolean lock without a modifier over-reports); access-control is name-based (a 26-name privileged list) with broad guard detection (any `msg.sender` comparison / `only*` modifier counts); weak-randomness only recognizes `%`/`keccak` contexts (indirect modulo via a local variable is not flagged); ecrecover treats the recovered address as safe if any `!= address(0)` check on it exists in the function (`require(s == signer)` or a zero-check on a different variable is still reported as "no explicit zero check"); the dataflow is intra-function and name-based, so extreme same-name shadowing and cross-function checks are handled conservatively. Source-level detection requires verified source — unverified contracts get only bytecode-level signals + an `unverified` marker.

---

## 6. Defensive monitoring & alerts

Turns on-chain security events and risky new deployments into a **structured alert stream** (to `alerts.jsonl` / webhook / stdout JSONL), runnable as a periodic cron job or live against the chain head.

### Monitored events (default set, 8 kinds)
| Event | Meaning |
|---|---|
| `Upgraded` / `BeaconUpgraded` | Proxy implementation / beacon upgrade |
| `OwnershipTransferred` | Ownership transfer |
| `AdminChanged` | Proxy admin change |
| `RoleGranted` / `RoleRevoked` | AccessControl role grant/revoke |
| `Paused` / `Unpaused` | Pausable emergency stop/resume |

`Transfer` (large) is **not** in the default set (high volume) — included only with `--min-transfer`. `--alert-topic 0x..` (repeatable) adds custom topic0s (those without a decoder are recorded as `event=unknown`).

### `monitor` (range)
```bash
blockscan monitor --from <N> --to <M> [options] -o out
```
| Option | Effect |
|---|---|
| `--alerts <file>` | Append JSON lines to `alerts.jsonl` (write errors only warn) |
| `--webhook-url <url>` | Best-effort POST of each alert |
| `--watchlist <file>` | Only alert on listed addresses (one per line, `#` comments) |
| `--audit-deployments` | Audit **new deployments** in the range; emit a `risky-deployment` alert (with `risk_score`/`grade`) when `risk ≥ --min-risk`. Needs an Etherscan key; mutually exclusive with `--no-audit` |
| `--min-transfer <amount>` | Include ERC-20 `Transfer`, alert only on `value ≥ amount` (raw uint256 base units); auto-excludes ERC-721; pair with `--watchlist` |
| `--baseline <file>` | **Cross-run de-dup**: each alert gets a stable fingerprint; seen ones are suppressed, new ones appended; overlapping ranges / periodic reruns don't repeat |
| `--throttle <N>` | **Burst cap**: at most N alerts per `(chain, contract, kind)` this run; the excess is dropped (throttled alerts aren't recorded in the baseline, so they can fire on a later run) |
| `--group` | **Digest mode**: fold same-`(chain, contract, event)` alerts into one end-of-run digest (`event:"Grouped"`, `amount`=count); mutually exclusive with `--throttle` (group wins) |
| `--log-chunk` / `--log-concurrency` | `eth_getLogs` window size / concurrency |

The summary line reports `(N suppressed, M throttled, G grouped)`; a partial-scan note is appended if any log/receipt fetch failed.

### `watch` (real-time, chain head)
Adding `--alert-on-risk` (audit new deployments; needs a key) and/or `--alert-events` (events only; no key) puts `watch` into real-time alert mode, reusing all the sink/filter/de-dup/throttle/group options above. If a block range's fetch fails it **does not advance and re-scans next tick** (de-duped with `--baseline`); Ctrl-C exits gracefully and finalizes per `--format`.

- **`--digest-interval <secs>`** (with `--group`): flush group digests every N seconds, not only at shutdown.
- **`--chains 1,10,…`** (alert mode only): **parallel multichain** watch. Each chain's RPC comes from `ETH_RPC_URL_<id>` (the primary falls back to `--rpc-url`); each chain has independent de-dup/throttle/group (keys include chain_id, so no locks needed), the shared `alerts.jsonl`/baseline files are appended line-atomically, and a single Ctrl-C (fanned out via `Shared`) stops all chains and aggregates. Download mode stays single-chain.

### Alert structure (each line of `alerts.jsonl`)
```json
{ "block": 21000002, "chain_id": 1, "contract": "0x…", "event": "OwnershipTransferred",
  "kind": "ownership", "new_value": "0x…(new)", "previous": "0x…(old)", "tx_hash": "0x…",
  "log_index": 0, "amount": null, "risk_score": null, "grade": null }
```
`risky-deployment` alerts carry `risk_score`/`grade`; `large-transfer` carries `amount`; a `Grouped` digest's `amount` = folded count and `previous` = "blocks first..last".

---

## 7. MCP server

`blockscan mcp` runs a **Model Context Protocol** server (JSON-RPC 2.0), exposing BlockScan as **agent-callable tools + resources**. It defaults to **stdio** (newline-delimited; **stdout carries only protocol messages, logs go to stderr**), or switches to **local HTTP** transport with `--http` (see below). Hand-rolled, lean dependencies.

Register it as a stdio server in an MCP client (Claude Desktop / IDE, etc.):
```json
{ "mcpServers": { "blockscan": { "command": "blockscan", "args": ["mcp", "-o", "out"] } } }
```
`-o`/`--out` becomes the default corpus directory for the offline tools and resources.

#### Local HTTP transport (optional)

When you need URL-based access (instead of a stdio subprocess), add `--http <addr>` to start a Streamable HTTP endpoint on a **loopback** address (single `/mcp`, POST JSON-RPC, fully sharing the stdio dispatch):

```bash
blockscan mcp -o out --http 8765                  # listens on 127.0.0.1:8765/mcp
blockscan mcp -o out --http 127.0.0.1:9000 \
  --http-token "$BLOCKSCAN_MCP_TOKEN"             # add Bearer auth (env var also works)
```

- `<addr>` may be a bare port (`8765`), `host:port`, or a bare host (default port 8765); **loopback only** — a non-loopback bind is rejected at startup.
- The server validates `Origin` (allows only `localhost`/`127.0.0.1`/`::1`, exact host match) against DNS-rebinding; request body is capped at 1 MiB (over → 413).
- Being tools-only, there is no server-initiated streaming, so **a POST returns its response directly — no SSE / session needed** (`GET`/`DELETE` → 405).
- ⚠️ **Without `--http-token` the endpoint is open to any local process (no auth)** — the Origin/loopback checks stop browser cross-site calls, not a malicious local process. On multi-user / shared hosts always set a token; clients supply it as `Authorization: Bearer <token>`.

### Tools
| Tool | Network | Purpose |
|---|---|---|
| `audit_source` | offline | Audit inline Solidity source and/or bytecode → standardized `Audit` |
| `audit_corpus` | offline | Re-audit every saved contract under `out` |
| `get_contract` | offline | Read one contract's metadata (optionally its source) |
| `list_contracts` | offline | Lightweight list of saved contracts (filtered by the last saved audit) |
| `export_sarif` | offline | Re-audit the corpus and export SARIF 2.1.0 |
| `cluster_corpus` | offline | Cluster clone families by metadata-stripped bytecode hash |
| `scan_addresses` | online | On-chain scan of given addresses (needs `rpc_url`+`etherscan_key`) |
| `scan_block_range` | online | Scan a **bounded** range (≤500 blocks) of new deployments and audit/persist (needs key) |
| `monitor_range` | online | Decode security events in a **bounded** range (≤500 blocks) (with `min_transfer`/`watchlist`) and **return** the alerts (needs only `rpc_url`) |

### Resources
- `resources/list`: lists every saved contract under `out` as `blockscan://contract/<address>`.
- `resources/read`: reads `blockscan://contract/<address>` → that contract's metadata JSON.

### Conventions & security
- A tool **execution** failure (contract not found, network error, arg validation) returns `result.isError=true` + text (so the model sees it); only **argument/method** errors use a JSON-RPC `error` (`-32700/-32601/-32602`).
- The address argument to `resources/read` and `get_contract` is validated as an `Address`, **preventing path traversal**; `scan_block_range`/`monitor_range` reject ranges over 500 blocks (so the agent paginates).
- Continuous `watch` loops don't fit a synchronous `tools/call`, so only the bounded primitives are exposed (the agent paginates).
- Online tools take `rpc_url`/`etherscan_key` inline per call, injected by the MCP client config — **don't hard-code them into prompts**.

---

## 8. Output formats & on-disk layout

### `--format` (global, default `human`)
| Mode | stdout |
|---|---|
| `human` | CJK width-aware tables (`--table`) + summary; logs/progress on stderr |
| `json` | One `{ run, stats, contracts }` document at the end (with full `analysis`/`audit`) |
| `ndjson` | **Streaming**: one compact JSON object per saved contract |
| `sarif` | **SARIF 2.1.0** audit log (GitHub Code Scanning / CI / IDE) |

In machine modes **stdout is data only** (pipe to `jq`); `monitor`/`watch` stdout is always a per-alert JSONL stream.

### On-disk directory (one per contract, lowercase address)
```
<out>/<address>/
  metadata.json     # full details (incl. analysis and audit)
  bytecode.hex      # on-chain runtime bytecode
  abi.json          # ABI (when verified)
  source/           # verified source (multi-file projects keep their original paths)
```
- **Resume/dedup**: an existing `metadata.json` is skipped by default; `--overwrite` forces a re-fetch.
- `--manifest <file>`: format chosen by **extension**. `.json` / `.csv` are the pipeline formats (under a scan command a `clusters.json` — clone families by metadata-stripped bytecode hash — is written alongside); `.md` / `.html` are a **report somebody reads**, carrying the overview, the severity tally and each contract's findings with their locations, evidence and remediation. The HTML is a **single self-contained file** (styles inlined, no scripts, no external requests), so it can be attached and forwarded as is.
  - With the `audit` subcommand it writes the **filtered** set, so `--min-risk` / `--only-vulnerable` / `--by-risk` decide what goes in the report: `blockscan audit --only-vulnerable --manifest report.md`.
  - **No PDF**: `.pdf` is refused rather than silently written as JSON. For PDF, hand the `.md` or `.html` to an established pipeline (pandoc, or a browser's print-to-PDF).
- `--table`: print a normalized per-contract table (Blockscout's free API is queried for name tag / project URL / token holdings enrichment).
- **Multichain** `--chains 1,10,8453,…`: each chain's RPC comes from `ETH_RPC_URL_<id>` (falling back to `ETH_RPC_URL`); non-mainnet/multichain output is segregated into per-chain subdirs so the same address on different chains never collides.

---

## 9. Global options cheat-sheet

| Option | Default | Notes |
|---|---|---|
| `--rpc-url` / `ETH_RPC_URL` | — | JSON-RPC endpoint |
| `--etherscan-key` / `ETHERSCAN_API_KEY` | — | Etherscan V2 key |
| `--chain-id` | 1 | Chain id |
| `--at-block <BLOCK>` | — | Read chain state as of this block (default: resolve the head once at start and pin the whole run) |
| `--chains 1,10,…` | — | Scan multiple chains in one run |
| `-o`/`--out` | `output` | Output directory |
| `--concurrency` | 5 | Contracts processed concurrently |
| `--rate` | 5 | Max Etherscan requests/sec |
| `--retries` | 5 | Attempts per request |
| `--overwrite` | false | Re-fetch already-saved contracts |
| `--trace` | false | `range`/`watch`: also find factory children |
| `--table` | false | Print the details table |
| `--no-sourcify` | false | Disable the Sourcify source fallback |
| `--only-verified` / `--only-proxy` / `--min-balance <eth>` | — | Pre-save filters |
| `--no-audit` | false | Disable the security audit |
| `--min-risk <0–100>` / `--only-vulnerable` | — | Audit filters |
| `--suppress <file>` | — | Audit suppression config |
| `--manifest <file>` | — | By extension: `.json`/`.csv` summary (+clusters.json), `.md`/`.html` report document, `.pdf` refused |
| `--format human\|json\|ndjson\|sarif` | human | Output format |
| `-v` / `-vv` | — | Increase log verbosity (stderr) |

Subcommand-specific options are in [§4](#4-subcommand-reference) / [§6](#6-defensive-monitoring--alerts).

---

## 10. Troubleshooting / FAQ

- **"error sending request" / can't reach Etherscan or RPC**: usually an HTTP/2 issue; BlockScan already forces HTTP/1.1, so normally nothing to do. Verify `--rpc-url` is reachable and the key is valid.
- **Rate-limited (Etherscan)**: set `--rate` to your tier (free is often 3); it backs off and retries. Lower `--concurrency` too.
- **Contract "unverified"**: Etherscan has no verified source; BlockScan falls back to Sourcify (unless `--no-sourcify`), and otherwise stores only bytecode + bytecode-level audit signals + `is_verified=false`.
- **`--min-risk`/`--only-vulnerable` filtered everything out**: they need the audit — don't also pass `--no-audit` (it errors). `--min-risk` is capped at 100.
- **`watch`/`monitor` produced no alerts**: confirm the range actually contains such events; an empty `--watchlist` **suppresses everything** (it warns); event-only monitoring needs no Etherscan key.
- **`monitor --audit-deployments` errors**: it's mutually exclusive with `--no-audit` and needs an Etherscan key.
- **MCP client gets no response / disconnects**: make sure nothing else writes to that process's stdout; BlockScan keeps its own stdout pure (logs go to stderr).
- **Logs leaked into a machine pipeline**: use `--format json|ndjson|sarif`; data is on stdout, logs/progress/summary on stderr.
- **Exit codes**: 0 on success; config/validation errors exit non-zero with `error: …` on stderr.

---

> For design details see the docs under `docs/`; test coverage and quality gates are in [ARCHITECTURE.md](ARCHITECTURE.md).
