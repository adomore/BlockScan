use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Output format. `stdout` carries structured data; all human-readable text
/// (logs, progress, summary, tables) goes to `stderr` in the machine modes.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable: tables + summary on stdout, logs/progress on stderr.
    #[default]
    Human,
    /// A single `{run, stats, contracts}` JSON document on stdout at the end.
    Json,
    /// Streaming: one compact JSON object per saved contract on stdout.
    Ndjson,
    /// SARIF 2.1.0 log of audit findings on stdout (GitHub Code Scanning / CI).
    Sarif,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Human => "human",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Sarif => "sarif",
        })
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "blockscan",
    version,
    about = "Scan Ethereum smart contracts: download source, bytecode and details"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Ethereum JSON-RPC endpoint (env: ETH_RPC_URL).
    #[arg(long, env = "ETH_RPC_URL", global = true, default_value = "")]
    pub rpc_url: String,

    /// Etherscan API key (env: ETHERSCAN_API_KEY).
    #[arg(long, env = "ETHERSCAN_API_KEY", global = true, default_value = "")]
    pub etherscan_key: String,

    /// Etherscan V2 API base URL.
    #[arg(
        long,
        global = true,
        default_value = "https://api.etherscan.io/v2/api"
    )]
    pub etherscan_base: String,

    /// Blockscout v2 API base, used for `--table` enrichment (name tag, project
    /// URL, token holdings). Set empty to disable.
    #[arg(
        long,
        global = true,
        default_value = "https://eth.blockscout.com/api/v2"
    )]
    pub blockscout_base: String,

    /// Max Blockscout requests per second (`--table` enrichment).
    #[arg(long, global = true, default_value_t = 4)]
    pub blockscout_rate: u32,

    /// Chain id (1 = Ethereum mainnet).
    #[arg(long, global = true, default_value_t = 1)]
    pub chain_id: u64,

    /// Read chain state as of this block instead of the chain head. A scan
    /// takes minutes; without a pin its reads land on whichever head was
    /// current at each moment, so a run is not reproducible. Omitted, the head
    /// is resolved once at scan start and used for the whole run.
    #[arg(long = "at-block", global = true, value_name = "BLOCK")]
    pub at_block: Option<u64>,

    /// Output directory.
    #[arg(long, short, global = true, default_value = "output")]
    pub out: PathBuf,

    /// Number of contracts processed concurrently.
    #[arg(long, global = true, default_value_t = 5)]
    pub concurrency: usize,

    /// Max Etherscan requests per second.
    #[arg(long, global = true, default_value_t = 5)]
    pub rate: u32,

    /// Attempts per RPC / Etherscan request before giving up (handles transient
    /// public-node hiccups).
    #[arg(long, global = true, default_value_t = 5)]
    pub retries: u32,

    /// Re-fetch and overwrite contracts already saved.
    #[arg(long, global = true, default_value_t = false)]
    pub overwrite: bool,

    /// Also discover factory-deployed (CREATE/CREATE2) contracts via the RPC
    /// `trace_block` method. Requires an RPC with the `trace_` namespace enabled.
    #[arg(long, global = true, default_value_t = false)]
    pub trace: bool,

    /// Print a normalized details table for each scanned contract.
    #[arg(long, global = true, default_value_t = false)]
    pub table: bool,

    /// Disable the Sourcify source fallback (used when Etherscan has no source).
    #[arg(long, global = true, default_value_t = false)]
    pub no_sourcify: bool,

    /// Sourcify server base URL.
    #[arg(long, global = true, default_value = "https://sourcify.dev/server")]
    pub sourcify_base: String,

    /// Only keep contracts with verified source.
    #[arg(long, global = true, default_value_t = false)]
    pub only_verified: bool,

    /// Only keep contracts holding at least this much ETH.
    #[arg(long, global = true, default_value_t = 0.0)]
    pub min_balance: f64,

    /// Only keep proxy contracts.
    #[arg(long, global = true, default_value_t = false)]
    pub only_proxy: bool,

    /// Disable the heuristic security audit (it runs during scan by default).
    #[arg(long, global = true, default_value_t = false)]
    pub no_audit: bool,

    /// Keep only contracts whose audit risk score is at least this (0–100).
    #[arg(long, global = true, default_value_t = 0)]
    pub min_risk: u8,

    /// Keep only contracts with at least one high/critical audit finding.
    #[arg(long, global = true, default_value_t = false)]
    pub only_vulnerable: bool,

    /// JSON file of audit findings to suppress (confirmed false positives /
    /// accepted baseline). Matched findings are dropped before scoring.
    #[arg(long, global = true)]
    pub suppress: Option<PathBuf>,

    /// Write a summary of all saved contracts to this file (`.json` or `.csv`).
    #[arg(long, global = true)]
    pub manifest: Option<PathBuf>,

    /// Scan multiple chains in one run (comma-separated chain ids). Each chain's
    /// RPC is read from env `ETH_RPC_URL_<id>` (falls back to ETH_RPC_URL for the
    /// primary chain). Not supported with `watch`.
    #[arg(long, global = true, value_delimiter = ',')]
    pub chains: Vec<u64>,

    /// Output format: `human` (default) / `json` / `ndjson`. The machine formats
    /// put only data on stdout; logs, progress and the summary go to stderr.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Increase log verbosity (-v, -vv).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug, Clone)]
// `Discover` carries many optional flags; boxing it would break clap's derive and
// the enum is only ever constructed once per run.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Scan a historical block range for newly deployed contracts.
    Range(RangeArgs),

    /// Watch new blocks in real time and scan freshly deployed contracts.
    Watch(WatchArgs),

    /// Scan a specific set of contract addresses.
    Addresses(AddressesArgs),

    /// Discover and scan contracts belonging to a project (by name and/or GitHub repos).
    Discover(DiscoverArgs),

    /// Scan a block range for security events (proxy upgrades, ownership/admin
    /// changes) and emit structured alerts to JSONL / webhook / stdout.
    Monitor(MonitorArgs),

    /// Re-run the security audit over already-downloaded contracts under `--out`
    /// (offline; no network) and report risk scores + findings.
    Audit(AuditArgs),

    /// Run a Model Context Protocol (MCP) server over stdio, exposing BlockScan's
    /// scan/audit/SARIF capabilities as agent-callable tools (JSON-RPC 2.0).
    Mcp(McpArgs),
}

#[derive(Args, Debug, Clone)]
pub struct McpArgs {
    /// Serve over HTTP (Streamable HTTP, JSON-only) on this loopback address instead
    /// of stdio, e.g. `127.0.0.1:8765` or just `8765`. Must be a loopback address.
    #[arg(long, value_name = "ADDR")]
    pub http: Option<String>,
    /// Optional bearer token required on the `Authorization` header in HTTP mode.
    /// When omitted, one is generated and printed to stderr at startup — the
    /// surface is never served unauthenticated.
    #[arg(long, value_name = "TOKEN", env = "BLOCKSCAN_MCP_TOKEN")]
    pub http_token: Option<String>,
    /// An RPC endpoint the `monitor_range` tool may dial. Repeatable.
    ///
    /// Without at least one, the tool refuses every request: the endpoint is an
    /// operator decision made once at launch, not something a caller picks per
    /// request. Matched whole, so a permitted `http://h:8545` does not admit
    /// `http://h:8545.evil.example`.
    #[arg(long = "rpc-allow", value_name = "URL")]
    pub rpc_allow: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct RangeArgs {
    /// First block (inclusive).
    #[arg(long)]
    pub from: u64,
    /// Last block (inclusive).
    #[arg(long)]
    pub to: u64,
}

#[derive(Args, Debug, Clone)]
pub struct WatchArgs {
    /// Stay this many blocks behind the head to avoid reorgs.
    #[arg(long, default_value_t = 2)]
    pub confirmations: u64,
    /// Polling interval in milliseconds.
    #[arg(long, default_value_t = 4000)]
    pub poll_ms: u64,

    // ---- Real-time alert mode (Phase 14) ----
    // When any alert flag is set, `watch` becomes a real-time monitor: each newly
    // confirmed block runs the alert pipeline instead of bulk-downloading contracts.
    /// Audit each NEW deployment as blocks confirm and alert on risky ones
    /// (`risk_score > 0 && >= --min-risk`). Reuses the security audit (needs a key).
    #[arg(long, default_value_t = false)]
    pub alert_on_risk: bool,
    /// Emit security-event alerts (proxy upgrade / ownership / admin) per block.
    #[arg(long, default_value_t = false)]
    pub alert_events: bool,
    /// Only alert on contracts/events from addresses in this file (one per line, `#` comments).
    #[arg(long)]
    pub watchlist: Option<PathBuf>,
    /// Extra event topic0 hash(es) for `--alert-events`, beyond the built-in set. Repeatable.
    #[arg(long = "alert-topic")]
    pub alert_topic: Vec<String>,
    /// Append decoded alerts as JSON lines to this file (`alerts.jsonl`).
    #[arg(long)]
    pub alerts: Option<PathBuf>,
    /// POST each alert as JSON to this URL (best-effort).
    #[arg(long)]
    pub webhook_url: Option<String>,
    /// De-duplicate across ticks/runs via a fingerprint baseline file.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Burst throttle: max alerts per (contract, kind) this run (extra dropped).
    #[arg(long)]
    pub throttle: Option<usize>,
    /// Collapse same (contract, kind) alerts into one digest at shutdown (vs `--throttle`).
    #[arg(long, default_value_t = false)]
    pub group: bool,
    /// With `--group`, also flush group digests every N seconds (not only at shutdown).
    #[arg(long)]
    pub digest_interval: Option<u64>,
    /// Also watch ERC-20 `Transfer` and alert on transfers whose value is at least
    /// this (raw uint256). Opt-in (high volume) — pair with `--watchlist`.
    #[arg(long)]
    pub min_transfer: Option<String>,
}

impl WatchArgs {
    /// Whether any real-time alert mode is requested.
    pub fn alert_mode(&self) -> bool {
        self.alert_on_risk || self.alert_events
    }
}

#[derive(Args, Debug, Clone)]
pub struct AddressesArgs {
    /// One or more contract addresses.
    pub addresses: Vec<String>,
    /// File with one address per line (`#` comments allowed).
    #[arg(long)]
    pub file: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    /// Sort the report by risk score (descending) instead of address order.
    #[arg(long, default_value_t = false)]
    pub by_risk: bool,

    /// Merge findings from another analyser's output file (SARIF 2.1.0 or
    /// Slither JSON), attributed to the contracts they belong to. Repeatable.
    ///
    /// The file is read, never executed: run your own analyser, pass what it
    /// wrote. Imported findings are excluded from blockscan's risk score and
    /// reported under their own tool name.
    #[arg(long = "import", value_name = "FILE")]
    pub import: Vec<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct MonitorArgs {
    /// First block (inclusive).
    #[arg(long)]
    pub from: u64,
    /// Last block (inclusive).
    #[arg(long)]
    pub to: u64,
    /// Only alert on events emitted by addresses in this file (one per line, `#` comments).
    #[arg(long)]
    pub watchlist: Option<PathBuf>,
    /// Extra event topic0 hash(es) to watch beyond the built-in security set. Repeatable.
    #[arg(long = "alert-topic")]
    pub alert_topic: Vec<String>,
    /// Append decoded alerts as JSON lines to this file (`alerts.jsonl`).
    #[arg(long)]
    pub alerts: Option<PathBuf>,
    /// POST each alert as JSON to this URL (best-effort).
    #[arg(long)]
    pub webhook_url: Option<String>,
    /// De-duplicate across runs: a fingerprint baseline file. Alerts whose
    /// fingerprint is already recorded are suppressed; new ones are appended.
    #[arg(long)]
    pub baseline: Option<PathBuf>,
    /// Burst throttle: max alerts per (contract, kind) this run. Beyond it, extra
    /// same-kind alerts from that contract are dropped (counted as throttled).
    #[arg(long)]
    pub throttle: Option<usize>,
    /// Collapse same (contract, kind) alerts into one end-of-run digest instead of
    /// emitting each (and instead of `--throttle`). Good for high-frequency events.
    #[arg(long, default_value_t = false)]
    pub group: bool,
    /// Also watch ERC-20 `Transfer` and alert on transfers whose value is at least
    /// this (raw uint256, token base units). Opt-in (high volume) — pair with `--watchlist`.
    #[arg(long)]
    pub min_transfer: Option<String>,
    /// Also audit NEW contract deployments in the range and alert on risky ones
    /// (`risk_score > 0 && >= --min-risk`). Requires an Etherscan key (pulls source).
    #[arg(long, default_value_t = false)]
    pub audit_deployments: bool,
    /// Block window size per `eth_getLogs` call.
    #[arg(long, default_value_t = 2000)]
    pub log_chunk: u64,
    /// Concurrent `eth_getLogs` windows in flight.
    #[arg(long, default_value_t = 4)]
    pub log_concurrency: usize,
}

#[derive(Args, Debug, Clone)]
pub struct DiscoverArgs {
    /// Project name to search on Blockscout (matches name tags / tokens / contracts).
    pub name: Option<String>,
    /// GitHub repos to scan for deployment artifacts (`owner/repo`), repeatable.
    #[arg(long = "github")]
    pub github: Vec<String>,

    /// Project website / docs URL to crawl for contract addresses, repeatable.
    #[arg(long = "website")]
    pub website: Vec<String>,

    /// How many hops to shallow-crawl from each `--website` URL (same domain).
    #[arg(long, default_value_t = 1)]
    pub crawl_depth: usize,

    /// DefiLlama protocol slug(s) — pulls the protocol's main contract, repeatable.
    #[arg(long = "defillama")]
    pub defillama: Vec<String>,

    /// Token List URL(s) — pulls `tokens[]` for the active `--chain-id`. Repeatable.
    #[arg(long = "tokenlist")]
    pub tokenlist: Vec<String>,

    /// CoinGecko coin id(s) — pulls the coin's contract on the active `--chain-id`
    /// from `/coins/{id}` `platforms` (free, no key). Repeatable.
    #[arg(long = "coingecko")]
    pub coingecko: Vec<String>,

    /// Event topic0 hash(es) to scan via `eth_getLogs` (e.g. Upgraded/BeaconUpgraded),
    /// collecting the emitting contracts. Requires `--from`/`--to`. Repeatable.
    #[arg(long = "topic")]
    pub topic: Vec<String>,

    /// First block for `--topic` log scan (inclusive).
    #[arg(long)]
    pub from: Option<u64>,

    /// Last block for `--topic` log scan (inclusive).
    #[arg(long)]
    pub to: Option<u64>,

    /// Block window size per `eth_getLogs` call (many RPCs cap the range).
    #[arg(long, default_value_t = 2000)]
    pub log_chunk: u64,

    /// Concurrent `eth_getLogs` windows in flight.
    #[arg(long, default_value_t = 4)]
    pub log_concurrency: usize,
    /// GitHub API token for higher rate limits (env: GITHUB_TOKEN).
    #[arg(long, env = "GITHUB_TOKEN", default_value = "")]
    pub github_token: String,

    /// Google Custom Search API key — enables web-search discovery (env: GOOGLE_API_KEY).
    #[arg(long, env = "GOOGLE_API_KEY", default_value = "")]
    pub google_api_key: String,

    /// Google Programmable Search Engine id / `cx` (env: GOOGLE_CSE_ID).
    #[arg(long, env = "GOOGLE_CSE_ID", default_value = "")]
    pub google_cse_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, ValueEnum};

    #[test]
    fn output_format_display_default_and_value_enum() {
        assert_eq!(OutputFormat::Human.to_string(), "human");
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Ndjson.to_string(), "ndjson");
        assert_eq!(OutputFormat::default(), OutputFormat::Human);
        // ValueEnum round-trip for every variant (covers the derived parser).
        for f in [OutputFormat::Human, OutputFormat::Json, OutputFormat::Ndjson] {
            let parsed = OutputFormat::from_str(&f.to_string(), true).unwrap();
            assert_eq!(parsed, f);
        }
        assert!(OutputFormat::from_str("nope", true).is_err());
    }

    #[test]
    fn cli_parses_format_flag() {
        let cli = Cli::parse_from(["blockscan", "--format", "ndjson", "addresses", "0xabc"]);
        assert_eq!(cli.global.format, OutputFormat::Ndjson);
        // Default when omitted.
        let cli = Cli::parse_from(["blockscan", "addresses", "0xabc"]);
        assert_eq!(cli.global.format, OutputFormat::Human);
    }
}
