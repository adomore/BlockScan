# BlockScan — Getting Started

> 🌐 Language: **English** · [中文](GETTING_STARTED.md)

Get BlockScan running from zero in about ten minutes: install it, configure it, scan your first contract, and read the result. For the per-flag reference, read this first, then move on to the [User Manual (USER_MANUAL.en.md)](USER_MANUAL.en.md).

---

## 1. What BlockScan is

A Rust command-line tool that, in one command:

> **discovers** Ethereum (and EVM-compatible) smart contracts → **downloads** verified source + on-chain bytecode + contract details → **static analysis + security audit scoring** → **filters** → **writes to disk** → human/machine-readable output.

Plus two side tracks: **defensive monitoring & alerting** (`monitor` / `watch`) and an **MCP server** (`mcp`) that exposes all of it as agent-callable tools.

Who it's for: security auditors / researchers, engineers who need to bulk-pull contract source for analysis, and developers who want to give an AI agent on-chain audit capabilities.

---

## 2. Before you start

| Required? | What | How to get it |
|---|---|---|
| Required | **Rust** (2021 edition) + a linkable C toolchain | On Windows, install MSVC Build Tools; see below |
| Required | An **Ethereum RPC endpoint** | A free public node works: `https://ethereum-rpc.publicnode.com` (no key) |
| Strongly recommended | **Etherscan V2 API key** | Register free at [etherscan.io](https://etherscan.io/) → API Keys; needed to pull verified source |
| Optional | GitHub token / Google CSE credentials | Only needed for the matching `discover` sources |

> You can run without an Etherscan key — but you won't get verified source, only bytecode + bytecode-level audit signals. **For your first run, get a free key.**

### Windows toolchain (this project's primary environment)
- Set the rustup default toolchain to **`stable-x86_64-pc-windows-msvc`** (the gnu toolchain lacks dlltool/gcc and cannot link):
  ```powershell
  rustup default stable-x86_64-pc-windows-msvc
  ```
- Install **MSVC Build Tools** (the "Desktop development with C++" workload + Windows SDK). cargo auto-detects `link.exe`.
- Network note: against Etherscan / public RPC, default HTTP/2 fails with `error sending request` in some environments. **You don't need to do anything** — BlockScan forces HTTP/1.1 + timeout + retry on those clients internally.

---

## 3. Install (build)

```bash
cargo build --release      # produces target/release/blockscan (blockscan.exe on Windows)
```

Smoke-test it:

```bash
./target/release/blockscan --version      # prints: blockscan 1.0.0
./target/release/blockscan --help         # shows the 7 subcommands
```

Put `target/release/blockscan` on your `PATH` and you can just type `blockscan` — which is what the rest of this guide does.

---

## 4. Configure credentials (once)

Drop a `.env` file in your working directory (flags work too, but `.env` is easiest):

```
ETH_RPC_URL=https://ethereum-rpc.publicnode.com
ETHERSCAN_API_KEY=YourEtherscanV2Key
```

> The Etherscan free tier is often **3 req/s**. If you get rate-limited, add `--rate 3` (it backs off and retries automatically) or lower `--concurrency`.

---

## 5. Your first scan

Scan a well-known verified contract — the USDC token:

```bash
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --table -o out
```

This fetches on-chain bytecode + balance → pulls Etherscan verified source/ABI/metadata → detects whether it's a proxy → runs the security audit and scores it → writes to `out/` → and `--table` prints a details table.

**You'll see** (illustrative):
```
+---------------+--------------------------------------------------------------------+
| Address       | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48                         |
| Contract name | FiatTokenProxy                                                     |
| Verified      | yes                                                                |
| Proxy         | yes -> 0x... (EIP-1967)                                            |
| ...           | ...                                                               |
+---------------+--------------------------------------------------------------------+
Done. saved=1 (verified=1), skipped=0, non-contract=0, failed=0
```

**On-disk layout** (one directory per contract, address lowercased):
```
out/0xa0b86991.../
  metadata.json     # full details (includes analysis and audit results)
  bytecode.hex      # on-chain runtime bytecode
  abi.json          # ABI
  source/           # verified source (original paths preserved for multi-file projects)
```

The audit result lives under the `audit` field in `metadata.json`: risk score (0–100), grade (A–F), and each finding (severity / rule_id / evidence / recommendation).

> Re-running the same command shows `skipped` (already saved). Add `--overwrite` to re-fetch.

---

## 6. The five most common tasks

```bash
# (1) Bulk-scan a list of addresses (one per line, # comments)
blockscan addresses --file addrs.txt -o out

# (2) Scan a historical block range for newly deployed contracts
blockscan range --from 19000000 --to 19000050 -o out

# (3) Discover & scan a project's contracts (Blockscout name search + GitHub deploy files)
blockscan discover "Uniswap V4" --github Uniswap/v4-core -o out

# (4) Keep only contracts with high-risk findings (audit filter, good for triage)
blockscan addresses --file addrs.txt --only-vulnerable --min-risk 50 -o out

# (5) Re-audit already-downloaded contracts offline, sorted by risk (rescore after rule upgrades)
blockscan audit --by-risk -o out
```

Need machine-readable output (pipelines / CI)? Add `--format json` (or `ndjson` / `sarif`) to any command: **stdout carries only data**, logs/progress/summary go to stderr, so you can pipe straight to `jq`.

```bash
blockscan addresses 0xA0b8... --format json -o out | jq '.contracts[0].audit.risk_score'
blockscan audit --format sarif -o out > findings.sarif   # feed GitHub Code Scanning
```

---

## 7. Where to go next

You now know BlockScan's core workflow. To go deeper:

| You want to | See |
|---|---|
| Full per-flag, per-subcommand reference | [User Manual (USER_MANUAL.en.md)](USER_MANUAL.en.md) |
| Security audit engine (36 detectors / scoring / suppressing FPs / SARIF) | [Manual §5](USER_MANUAL.en.md#5-security-audit-engine) · [AUDIT_DESIGN.md](AUDIT_DESIGN.md) |
| Real-time monitoring & alerts (`monitor` / `watch --alert-*`) | [Manual §6](USER_MANUAL.en.md#6-defensive-monitoring--alerts) · [MONITOR_DESIGN.md](MONITOR_DESIGN.md) |
| Give the capabilities to an AI agent (MCP server) | [Manual §7](USER_MANUAL.en.md#7-mcp-server) · [MCP_DESIGN.md](MCP_DESIGN.md) |
| Multi-source project discovery (DefiLlama/TokenList/CoinGecko/website…) | [Manual §4](USER_MANUAL.en.md#4-subcommand-reference) · [DISCOVERY_DESIGN.md](DISCOVERY_DESIGN.md) |
| Architecture & modules | [ARCHITECTURE.md](ARCHITECTURE.md) |

---

## 8. Stuck? (quick triage)

- **`error sending request` / can't connect**: usually an HTTP/2 issue; BlockScan already forces HTTP/1.1 internally, so normally nothing to do — confirm `--rpc-url` is reachable and the Etherscan key is valid.
- **Rate-limited (Etherscan)**: `--rate 3` (free tier); it backs off and retries. Lower `--concurrency` if needed.
- **Contract shows "unverified"**: Etherscan has no verified source; BlockScan falls back to Sourcify (unless `--no-sourcify`), and if still nothing, stores just the bytecode.
- **`--min-risk` / `--only-vulnerable` filtered everything out**: these depend on audit results — don't also pass `--no-audit` (it errors).
- **Windows link failure (missing link.exe / dlltool)**: confirm the toolchain is `msvc` and MSVC Build Tools are installed (see §2).

Full FAQ in [Manual §10](USER_MANUAL.en.md#10-troubleshooting--faq).
