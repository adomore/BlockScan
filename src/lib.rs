pub mod analysis;
pub mod alert;
pub mod ast;
pub mod audit;
pub mod baseline;
pub mod chains;
pub mod cli;
pub mod coingecko;
pub mod config;
pub mod defillama;
pub mod discovery;
pub mod enrich;
pub mod error;
pub mod etherscan;
pub mod events;
pub mod export;
pub mod github;
pub mod import;
pub mod group;
pub mod mcp;
pub mod model;
pub mod report;
pub mod rpc;
pub mod sarif;
pub mod scanner;
pub mod sourcify;
pub mod storage;
pub mod suppress;
pub mod throttle;
pub mod tokenlist;
pub mod website;
pub mod websearch;

use std::collections::HashSet;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::{Address, B256};

use crate::cli::{
    AuditArgs, Cli, Command, DiscoverArgs, GlobalArgs, MonitorArgs, OutputFormat, WatchArgs,
};
use crate::config::Config;
use crate::enrich::Blockscout;
use crate::etherscan::EtherscanClient;
use crate::model::{Alert, Audit, ContractDetails};
use crate::rpc::RpcClient;
use crate::scanner::{RunStats, Scanner};
use crate::sourcify::Sourcify;

const DEFAULT_BLOCKSCOUT: &str = "https://eth.blockscout.com/api/v2";

/// Build a [`Config`] from parsed CLI global args (single-chain baseline).
pub fn config_from_cli(g: &GlobalArgs) -> Config {
    Config {
        rpc_url: g.rpc_url.clone(),
        etherscan_key: g.etherscan_key.clone(),
        etherscan_base: g.etherscan_base.clone(),
        blockscout_base: g.blockscout_base.clone(),
        blockscout_rate: g.blockscout_rate,
        chain_id: g.chain_id,
        pin_block: g.at_block,
        out_dir: g.out.clone(),
        concurrency: g.concurrency,
        rate: g.rate,
        retries: g.retries,
        overwrite: g.overwrite,
        trace: g.trace,
        table: g.table,
        sourcify: !g.no_sourcify,
        sourcify_base: g.sourcify_base.clone(),
        only_verified: g.only_verified,
        min_balance_wei: (g.min_balance.max(0.0) * 1e18) as u128,
        only_proxy: g.only_proxy,
        manifest: g.manifest.clone(),
        format: g.format,
        audit: !g.no_audit,
        min_risk: g.min_risk.min(100), // scores cap at 100; >100 would filter everything
        only_vulnerable: g.only_vulnerable,
        suppressions: suppress::Suppressions::load_or_warn(g.suppress.as_deref()),
    }
}

/// RPC endpoint for `chain`: env `ETH_RPC_URL_<chain>`, else `--rpc-url` for the
/// primary chain, else empty (chain is skipped).
fn per_chain_rpc(g: &GlobalArgs, chain: u64) -> String {
    if let Ok(u) = std::env::var(format!("ETH_RPC_URL_{chain}")) {
        if !u.trim().is_empty() {
            return u;
        }
    }
    if chain == g.chain_id {
        g.rpc_url.clone()
    } else {
        String::new()
    }
}

/// Per-chain [`Config`]: overrides chain id, RPC, Blockscout base and (when
/// scanning multiple chains) the output subdirectory.
fn build_chain_config(g: &GlobalArgs, chain: u64, multichain: bool) -> Config {
    let mut cfg = config_from_cli(g);
    cfg.chain_id = chain;
    cfg.rpc_url = per_chain_rpc(g, chain);
    // Map Blockscout base by chain unless the user set a custom one.
    if g.blockscout_base == DEFAULT_BLOCKSCOUT {
        cfg.blockscout_base = chains::blockscout_base(chain).map(String::from).unwrap_or_default();
    }
    // Segregate output per chain whenever it isn't a plain mainnet scan, so the
    // same address on different chains never collides under a shared --out.
    if multichain || chain != 1 {
        cfg.out_dir = g.out.join(chains::chain_name(chain));
    }
    cfg
}

/// Build the RPC client + scanner for one chain.
fn build_scanner(cfg: &Config) -> error::Result<(RpcClient, Scanner)> {
    let rpc = RpcClient::new(&cfg.rpc_url, cfg.retries)?;
    let etherscan = EtherscanClient::new(
        &cfg.etherscan_base,
        &cfg.etherscan_key,
        cfg.chain_id,
        cfg.rate,
        cfg.retries,
    )?;
    let blockscout = Blockscout::new(&cfg.blockscout_base, cfg.blockscout_rate);
    let sourcify_base = if cfg.sourcify { cfg.sourcify_base.as_str() } else { "" };
    let sourcify = Sourcify::new(sourcify_base, cfg.chain_id);
    let scanner = Scanner::new(
        Arc::new(cfg.clone()),
        rpc.clone(),
        etherscan,
        blockscout,
        sourcify,
    );
    Ok((rpc, scanner))
}

/// Validate + build a chain's clients, or `None` when no RPC is configured.
///
/// Async because the block pin is resolved here, once, before the first
/// address is read: every state read in the run then answers from the same
/// block. `--at-block` overrides the head.
async fn prepare_chain(
    g: &GlobalArgs,
    chain: u64,
    multichain: bool,
) -> error::Result<Option<(Config, RpcClient, Scanner)>> {
    let cfg = build_chain_config(g, chain, multichain);
    if cfg.rpc_url.trim().is_empty() {
        tracing::warn!("no RPC for chain {chain} (set ETH_RPC_URL_{chain}); skipping");
        return Ok(None);
    }
    cfg.validate()?;
    if multichain {
        tracing::info!("=== chain {chain} ({}) ===", chains::chain_name(chain));
    }
    let (rpc, scanner) = build_scanner(&cfg)?;
    let (rpc, scanner) = pin_to_block(&cfg, rpc, scanner).await?;
    Ok(Some((cfg, rpc, scanner)))
}

/// Resolve the block every state read in this run answers from, and pin both
/// clients to it.
///
/// `cfg.pin_block` wins when set; otherwise the head is read once here. The
/// block hash is recorded alongside the height because a height alone does not
/// survive a reorg — two runs at "block 19000000" can be different chains. A
/// node that cannot serve the hash is not fatal: the pin still holds the run
/// together, it is only less identifiable afterwards.
pub(crate) async fn pin_to_block(
    cfg: &Config,
    rpc: RpcClient,
    scanner: Scanner,
) -> error::Result<(RpcClient, Scanner)> {
    let block = match cfg.pin_block {
        Some(n) => n,
        // An unreachable node cannot serve a state read either, so this failure
        // resurfaces on the first address that actually needs one. Refusing to
        // start here would break the offline case that reads nothing at all —
        // a rerun over contracts already on disk. The run continues unpinned,
        // and says so twice: in this warning and as a null `block_number` on
        // every record it writes.
        None => match rpc.block_number().await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("could not resolve a head to pin state reads to: {e}");
                return Ok((rpc, scanner));
            }
        },
    };
    let hash = match rpc.block_hash(block).await {
        Ok(Some(h)) => Some(format!("{h:#x}")),
        // Only reachable for an explicit --at-block: a head just read back from
        // this same node is a block it knows.
        Ok(None) => {
            return Err(error::AppError::Config(format!(
                "--at-block {block} is not a block this RPC knows"
            )))
        }
        Err(e) => {
            tracing::warn!("could not read the hash of block {block}: {e}");
            None
        }
    };
    tracing::info!(
        "state reads pinned to block {block}{}",
        hash.as_deref().map(|h| format!(" ({h})")).unwrap_or_default()
    );
    Ok((rpc.pinned_at(block), scanner.pinned_at(block, hash)))
}

/// Build just the RPC client for a chain. `monitor` needs only `eth_getLogs`, so
/// it must NOT require an Etherscan API key (unlike the scan modes). `None` when
/// the chain has no RPC configured.
fn prepare_chain_rpc(g: &GlobalArgs, chain: u64, multichain: bool) -> error::Result<Option<RpcClient>> {
    let cfg = build_chain_config(g, chain, multichain);
    if cfg.rpc_url.trim().is_empty() {
        tracing::warn!("no RPC for chain {chain} (set ETH_RPC_URL_{chain}); skipping");
        return Ok(None);
    }
    if multichain {
        tracing::info!("=== chain {chain} ({}) ===", chains::chain_name(chain));
    }
    Ok(Some(RpcClient::new(&cfg.rpc_url, cfg.retries)?))
}

/// Write the run manifest if `--manifest` was set, plus a `clusters.json`
/// (clone families by metadata-stripped bytecode) alongside it.
fn write_manifest_if_set(g: &GlobalArgs) -> error::Result<()> {
    if let Some(path) = &g.manifest {
        let all = storage::load_all_metadata(&g.out);
        export::write_manifest(path, &all)?;
        tracing::info!(
            "wrote manifest with {} contract(s) to {}",
            all.len(),
            path.display()
        );

        let clusters = analysis::cluster_by_code(&all);
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        let clusters_path = match dir {
            Some(d) => d.join("clusters.json"),
            None => std::path::PathBuf::from("clusters.json"),
        };
        std::fs::write(&clusters_path, serde_json::to_string_pretty(&clusters)?)?;
        tracing::info!(
            "wrote {} clone cluster(s) to {}",
            clusters.len(),
            clusters_path.display()
        );
    }
    Ok(())
}

/// Top-level dispatch for a parsed CLI invocation.
///
/// `watch_shutdown` resolves to stop `watch` mode; ignored for other subcommands.
/// The binary passes a Ctrl-C future; tests inject a controllable one.
pub async fn run<S>(cli: Cli, watch_shutdown: S) -> error::Result<()>
where
    S: Future<Output = ()>,
{
    let mut g = cli.global.clone();
    let chains: Vec<u64> = if g.chains.is_empty() {
        vec![g.chain_id]
    } else {
        g.chains.clone()
    };
    let multichain = chains.len() > 1;
    // A single requested chain becomes the primary so an explicit --rpc-url
    // applies to it even when it differs from the default --chain-id.
    if !multichain {
        g.chain_id = chains[0];
    }
    let g = &g;

    if g.format != OutputFormat::Human && g.table {
        tracing::warn!("--table has no effect with --format {}; tables print only in human mode", g.format);
    }
    // The audit filters need the audit; refuse the contradictory combination.
    if g.no_audit && (g.min_risk > 0 || g.only_vulnerable) {
        return Err(error::AppError::Config(
            "--min-risk / --only-vulnerable require the security audit; remove --no-audit".into(),
        ));
    }

    match cli.command {
        Command::Watch(args) => {
            // --alert-on-risk needs the audit; --no-audit would make it a silent no-op.
            if args.alert_on_risk && g.no_audit {
                return Err(error::AppError::Config(
                    "--alert-on-risk requires the security audit; remove --no-audit".into(),
                ));
            }
            if args.alert_mode() {
                // Real-time alert mode — supports --chains (parallel per-chain).
                let total = watch_alerts_multichain(g, &chains, multichain, args, watch_shutdown).await?;
                report_alert_total(&total);
            } else {
                // Download mode: single chain only.
                if multichain {
                    return Err(error::AppError::Config(
                        "watch (download mode) scans a single chain; drop --chains".into(),
                    ));
                }
                // Surface alert-only flags that download mode silently ignores.
                if args.alerts.is_some()
                    || args.webhook_url.is_some()
                    || args.baseline.is_some()
                    || args.throttle.is_some()
                    || args.group
                    || args.digest_interval.is_some()
                    || args.min_transfer.is_some()
                    || args.watchlist.is_some()
                    || !args.alert_topic.is_empty()
                {
                    tracing::warn!(
                        "watch download mode ignores alert flags (--alerts/--webhook-url/--baseline/--throttle/--group/--digest-interval/--min-transfer/--watchlist/--alert-topic); pass --alert-events or --alert-on-risk to use them"
                    );
                }
                match prepare_chain(g, chains[0], false).await? {
                    Some((cfg, rpc, scanner)) => {
                        let (total, contracts) = watch_with_shutdown(
                            &rpc, &scanner, args, cfg.trace, g.format, watch_shutdown,
                        )
                        .await?;
                        write_manifest_if_set(g)?;
                        emit_run_output(g, &total, &contracts, "watch")?;
                    }
                    None => return Err(error::AppError::Config("no RPC configured".into())),
                }
            }
        }

        Command::Addresses(args) => {
            let addrs = discovery::load_addresses(&args.addresses, args.file.as_deref())?;
            if addrs.is_empty() {
                return Err(error::AppError::Config(
                    "no addresses provided (pass addresses or --file)".into(),
                ));
            }
            let mut grand = RunStats::default();
            let mut contracts: Vec<ContractDetails> = Vec::new();
            for chain in &chains {
                if let Some((_cfg, _rpc, scanner)) = prepare_chain(g, *chain, multichain).await? {
                    tracing::info!("scanning {} address(es)", addrs.len());
                    let (stats, mut got) = scanner.process_addresses(addrs.clone()).await;
                    print_summary(&stats, g.format);
                    merge(&mut grand, stats);
                    contracts.append(&mut got);
                }
            }
            write_manifest_if_set(g)?;
            emit_run_output(g, &grand, &contracts, "addresses")?;
        }

        Command::Range(args) => {
            if args.from > args.to {
                return Err(error::AppError::Config("--from must be <= --to".into()));
            }
            let mut grand = RunStats::default();
            let mut contracts: Vec<ContractDetails> = Vec::new();
            for chain in &chains {
                if let Some((cfg, rpc, scanner)) = prepare_chain(g, *chain, multichain).await? {
                    tracing::info!("scanning blocks {}..={}", args.from, args.to);
                    let mut total = RunStats::default();
                    for n in args.from..=args.to {
                        process_block(&rpc, &scanner, n, cfg.trace, &mut total, &mut contracts).await?;
                    }
                    print_summary(&total, g.format);
                    merge(&mut grand, total);
                }
            }
            write_manifest_if_set(g)?;
            emit_run_output(g, &grand, &contracts, "range")?;
        }

        Command::Discover(args) => {
            if args.name.is_none()
                && args.github.is_empty()
                && args.website.is_empty()
                && args.defillama.is_empty()
                && args.tokenlist.is_empty()
                && args.coingecko.is_empty()
                && args.topic.is_empty()
            {
                return Err(error::AppError::Config(
                    "discover needs at least one source: <name> / --github / --website / --defillama / --tokenlist / --coingecko / --topic".into(),
                ));
            }
            let mut grand = RunStats::default();
            let mut contracts: Vec<ContractDetails> = Vec::new();
            for chain in &chains {
                if let Some((_cfg, _rpc, scanner)) = prepare_chain(g, *chain, multichain).await? {
                    let addrs = discover_addresses(&scanner, &args).await;
                    if addrs.is_empty() {
                        tracing::warn!("no contracts discovered on chain {chain}");
                        continue;
                    }
                    tracing::info!("scanning {} discovered contract(s)", addrs.len());
                    let (stats, mut got) = scanner.process_addresses(addrs).await;
                    print_summary(&stats, g.format);
                    merge(&mut grand, stats);
                    contracts.append(&mut got);
                }
            }
            write_manifest_if_set(g)?;
            emit_run_output(g, &grand, &contracts, "discover")?;
        }

        Command::Monitor(args) => {
            run_monitor(g, &chains, multichain, &args).await?;
        }

        Command::Audit(args) => {
            run_audit(g, &args)?;
        }

        Command::Mcp(args) => {
            // `-o`/--out becomes the default corpus dir for offline tools + resources.
            match &args.http {
                // stdio (default): stdout carries only JSON-RPC; logs go to stderr.
                None => mcp::serve_stdio(g.out.clone()).await?,
                // HTTP transport on a loopback address.
                Some(addr) => {
                    mcp::serve_http(
                        g.out.clone(),
                        addr,
                        args.http_token.clone(),
                        args.rpc_allow.clone(),
                    )
                    .await?
                }
            }
        }
    }

    Ok(())
}

/// Collect candidate contract addresses for `discover` from Blockscout name
/// search and GitHub deployment artifacts, deduplicated.
pub async fn discover_addresses(scanner: &Scanner, args: &DiscoverArgs) -> Vec<Address> {
    let mut raw: Vec<String> = Vec::new();
    if let Some(name) = &args.name {
        let hits = scanner.blockscout_search(name).await;
        tracing::info!("blockscout: {} contract(s) matching '{name}'", hits.len());
        raw.extend(hits);

        // Optional Google web-search source (only when credentials are set).
        let google = websearch::Google::new(&args.google_api_key, &args.google_cse_id);
        let hits = google
            .search_addresses(&format!("{name} smart contract address etherscan"))
            .await;
        if !hits.is_empty() {
            tracing::info!("web search: {} address(es) for '{name}'", hits.len());
            raw.extend(hits);
        }
    }
    for repo in &args.github {
        let hits = github::discover_repo(repo, &args.github_token).await;
        tracing::info!("github {repo}: {} address(es)", hits.len());
        raw.extend(hits);
    }
    for site in &args.website {
        let scraper = website::WebsiteScraper::new(20);
        let hits = scraper.discover(site, args.crawl_depth).await;
        tracing::info!("website {site}: {} address(es)", hits.len());
        raw.extend(hits);
    }
    if !args.defillama.is_empty() {
        let client = defillama::Defillama::new();
        for slug in &args.defillama {
            let hits = client.fetch_addresses(slug).await;
            tracing::info!("defillama {slug}: {} address(es)", hits.len());
            raw.extend(hits);
        }
    }
    if !args.tokenlist.is_empty() {
        let client = tokenlist::TokenList::new();
        for url in &args.tokenlist {
            let hits = client.fetch(url, scanner.chain_id()).await;
            tracing::info!("tokenlist {url}: {} address(es)", hits.len());
            raw.extend(hits);
        }
    }
    if !args.coingecko.is_empty() {
        let client = coingecko::CoinGecko::new();
        for id in &args.coingecko {
            let hits = client.fetch_addresses(id, scanner.chain_id()).await;
            tracing::info!("coingecko {id}: {} address(es)", hits.len());
            raw.extend(hits);
        }
    }
    if !args.topic.is_empty() {
        match (args.from, args.to) {
            (Some(from), Some(to)) if from > to => {
                tracing::warn!("--topic range inverted: --from {from} > --to {to}; skipping log scan");
            }
            (Some(from), Some(to)) => {
                let topics: Vec<B256> =
                    args.topic.iter().filter_map(|t| t.parse::<B256>().ok()).collect();
                if topics.is_empty() {
                    tracing::warn!("--topic given but no valid 32-byte hashes");
                } else {
                    let hits = scanner
                        .find_by_logs(from, to, topics, args.log_chunk, args.log_concurrency)
                        .await;
                    tracing::info!("log scan {from}..={to}: {} contract(s)", hits.len());
                    raw.extend(hits.iter().map(|a| format!("{a:#x}")));
                }
            }
            _ => tracing::warn!("--topic requires --from and --to"),
        }
    }

    let mut seen = HashSet::new();
    let mut addrs = Vec::new();
    for s in raw {
        if let Ok(a) = Address::from_str(&s) {
            if seen.insert(a) {
                addrs.push(a);
            }
        }
    }
    addrs
}

/// Re-run the security audit over every contract already saved under `--out`,
/// offline (no network). Honors `--min-risk` / `--only-vulnerable` and `--format`.
/// True if an audit has any High/Critical finding (case-insensitive).
fn has_high_or_critical(a: &Audit) -> bool {
    a.findings.iter().any(|f| {
        f.severity.eq_ignore_ascii_case("high") || f.severity.eq_ignore_ascii_case("critical")
    })
}

/// Load every contract saved under `out`, re-audit it offline (honoring `suppress`),
/// and apply the `min_risk` / `only_vulnerable` filters; sort by risk if `by_risk`.
/// Shared by the `audit` subcommand ([`run_audit`]) and the MCP `audit_corpus` tool.
pub fn audit_corpus(
    out: &std::path::Path,
    min_risk: u8,
    only_vulnerable: bool,
    by_risk: bool,
    supp: &suppress::Suppressions,
) -> Vec<ContractDetails> {
    let min_risk = min_risk.min(100); // scores cap at 100; >100 would drop all
    let mut contracts: Vec<ContractDetails> = storage::load_all_metadata_with_dirs(out)
        .into_iter()
        .map(|(dir, mut d)| {
            // Load source from the contract's real directory (which may be a
            // per-chain subdir like out/<chainname>/<addr>/), not a path
            // recomputed from out + address — otherwise non-mainnet corpora
            // silently load no source and all source-level detectors are skipped.
            let sources = storage::load_sources_from_dir(&dir);
            d.audit = Some(audit::audit_with(&d, &sources, supp));
            d
        })
        .filter(|d| {
            let a = d.audit.as_ref().expect("audit just set");
            if min_risk > 0 && a.risk_score < min_risk {
                return false;
            }
            if only_vulnerable && !has_high_or_critical(a) {
                return false;
            }
            true
        })
        .collect();

    if by_risk {
        contracts.sort_by(|a, b| {
            let (ra, rb) = (
                a.audit.as_ref().map(|x| x.risk_score).unwrap_or(0),
                b.audit.as_ref().map(|x| x.risk_score).unwrap_or(0),
            );
            rb.cmp(&ra).then_with(|| a.address.cmp(&b.address))
        });
    }
    contracts
}

pub fn run_audit(g: &GlobalArgs, args: &AuditArgs) -> error::Result<()> {
    let supp = suppress::Suppressions::load_or_warn(g.suppress.as_deref());
    let mut contracts = audit_corpus(&g.out, g.min_risk, g.only_vulnerable, args.by_risk, &supp);

    // Imports land *after* scoring and filtering, so a foreign finding can
    // neither move a risk number nor pull a contract past --min-risk. What it
    // could not place is said out loud rather than dropped.
    if !args.import.is_empty() {
        let sources = storage::corpus_source_paths(&g.out);
        for path in &args.import {
            let s = import::merge(&mut contracts, &sources, import::load(path)?);
            tracing::info!(
                "imported {}/{} finding(s) from {} ({}); {} ambiguous, {} unmatched",
                s.attributed,
                s.total,
                path.display(),
                s.tool,
                s.ambiguous,
                s.unmatched
            );
            if s.ambiguous + s.unmatched > 0 {
                tracing::warn!(
                    "{} finding(s) from {} could not be attributed to a contract in this corpus",
                    s.ambiguous + s.unmatched,
                    s.tool
                );
            }
        }
    }
    let contracts = contracts;

    let vulnerable = contracts
        .iter()
        .filter(|d| d.audit.as_ref().is_some_and(has_high_or_critical))
        .count();

    match g.format {
        OutputFormat::Json => {
            let doc = serde_json::json!({
                "audited": contracts.len(),
                "vulnerable": vulnerable,
                "contracts": contracts,
            });
            use std::io::Write;
            let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string_pretty(&doc)?);
        }
        OutputFormat::Sarif => {
            use std::io::Write;
            let doc = sarif::build_sarif(&contracts);
            let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string_pretty(&doc)?);
        }
        OutputFormat::Ndjson => {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            for d in &contracts {
                if let Ok(line) = serde_json::to_string(d) {
                    let _ = writeln!(out, "{line}");
                }
            }
        }
        OutputFormat::Human => {
            // Per-contract rating line + remediation-priority tally.
            for d in &contracts {
                if let Some(a) = &d.audit {
                    let name = d.contract_name.as_deref().unwrap_or("(未验证)");
                    let prio: Vec<String> = ["P0", "P1", "P2", "P3"]
                        .iter()
                        .filter_map(|p| a.summary.by_priority.get(*p).map(|n| format!("{p}:{n}")))
                        .collect();
                    println!(
                        "{} {:>3}/100 {:<8} {} {}  [{}]",
                        a.grade, a.risk_score, a.risk_level, d.address, name, prio.join(" ")
                    );
                }
            }
            // Aggregate severity matrix across the corpus.
            let mut matrix: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
            for d in &contracts {
                if let Some(a) = &d.audit {
                    for f in &a.findings {
                        *matrix.entry(f.severity.as_str()).or_insert(0) += 1;
                    }
                }
            }
            let mtx: Vec<String> = ["Critical", "High", "Medium", "Low", "Info"]
                .iter()
                .filter_map(|s| matrix.get(*s).map(|n| format!("{s}:{n}")))
                .collect();
            eprintln!(
                "\nDone. audited {} contract(s); {} with high/critical findings. findings: [{}]",
                contracts.len(),
                vulnerable,
                mtx.join(" ")
            );
        }
    }

    // `--manifest` from here writes the *filtered, ordered* set this subcommand
    // just built, not the whole corpus: with a `.md` or `.html` extension that
    // is the document the audit produces, and --min-risk / --only-vulnerable /
    // --by-risk are exactly the knobs that decide what belongs in it.
    if let Some(path) = &g.manifest {
        export::write_manifest(path, &contracts)?;
        tracing::info!(
            "wrote {} contract(s) to {}",
            contracts.len(),
            path.display()
        );
    }
    Ok(())
}

/// Running tally of alerts: how many were emitted vs. suppressed by the baseline,
/// and whether any underlying log/receipt fetch came back partial (so real-time
/// `watch` knows not to advance past a block range it didn't fully scan).
#[derive(Debug, Default)]
pub struct AlertCounts {
    pub emitted: usize,
    pub suppressed: usize,
    pub throttled: usize,
    /// Alerts folded into a `--group` digest (the digests themselves count as `emitted`).
    pub grouped: usize,
    pub incomplete: bool,
}

impl AlertCounts {
    fn add(&mut self, other: AlertCounts) {
        self.emitted += other.emitted;
        self.suppressed += other.suppressed;
        self.throttled += other.throttled;
        self.grouped += other.grouped;
        self.incomplete |= other.incomplete;
    }
}

/// Shared context for the alert-emitting scans (monitor range + watch ticks):
/// the sinks, the cross-run baseline, the burst throttle, the address watchlist,
/// the chain id, and the optional large-transfer value threshold.
pub struct AlertCtx<'a> {
    pub sink: &'a alert::AlertSink,
    pub baseline: &'a mut baseline::AlertBaseline,
    pub throttle: &'a mut throttle::Throttle,
    pub grouper: &'a mut group::Grouper,
    pub watchlist: &'a Option<HashSet<Address>>,
    pub chain: u64,
    /// Minimum value for `large-transfer` alerts (None = no transfer monitoring).
    pub min_transfer: Option<alloy::primitives::U256>,
}

/// Parse `--alert-topic`s on top of the built-in security set (dropping invalid/dupes).
fn build_topics(extra: &[String]) -> Vec<B256> {
    let mut topics = events::default_alert_topics();
    for t in extra {
        match t.parse::<B256>() {
            Ok(b) if !topics.contains(&b) => topics.push(b),
            Ok(_) => {}
            Err(_) => tracing::warn!("ignoring invalid --alert-topic '{t}'"),
        }
    }
    topics
}

/// Load an optional `--watchlist` into a set, warning when it resolves to empty
/// (which would otherwise silently suppress every alert on a security tool).
fn load_watchlist(path: Option<&std::path::Path>) -> error::Result<Option<HashSet<Address>>> {
    let Some(path) = path else { return Ok(None) };
    let wl: HashSet<Address> = discovery::load_addresses(&[], Some(path))?.into_iter().collect();
    if wl.is_empty() {
        tracing::warn!("--watchlist resolved to 0 addresses; all alerts will be suppressed");
    }
    Ok(Some(wl))
}

/// Scan `[from, to]` for security events on each chain, decode them into
/// [`Alert`]s, and deliver to the configured sinks (JSONL / webhook / stdout).
pub async fn run_monitor(
    g: &GlobalArgs,
    chains: &[u64],
    multichain: bool,
    args: &MonitorArgs,
) -> error::Result<()> {
    if args.from > args.to {
        return Err(error::AppError::Config("--from must be <= --to".into()));
    }

    // --audit-deployments needs the audit; --no-audit would make it a silent no-op.
    if args.audit_deployments && g.no_audit {
        return Err(error::AppError::Config(
            "--audit-deployments requires the security audit; remove --no-audit".into(),
        ));
    }

    let mut topics = build_topics(&args.alert_topic);
    let min_transfer = parse_min_transfer(args.min_transfer.as_deref());
    if min_transfer.is_some() {
        // Opt-in: only scan the high-volume Transfer topic when a threshold is set.
        let t = events::transfer_topic();
        if !topics.contains(&t) {
            topics.push(t);
        }
    }
    let watchlist = load_watchlist(args.watchlist.as_deref())?;
    let sink = alert::AlertSink::new(args.alerts.clone(), args.webhook_url.clone());
    let mut base = baseline::AlertBaseline::load(args.baseline.clone());
    let mut throttle = throttle::Throttle::new(args.throttle);
    let mut grouper = group::Grouper::new(args.group);
    if args.group && args.throttle.is_some() {
        tracing::warn!("--throttle is ignored in --group mode (grouping supersedes throttling)");
    }
    let min_risk = g.min_risk.min(100);

    let mut total = AlertCounts::default();
    for chain in chains {
        let mut ctx = AlertCtx {
            sink: &sink,
            baseline: &mut base,
            throttle: &mut throttle,
            grouper: &mut grouper,
            watchlist: &watchlist,
            chain: *chain,
            min_transfer,
        };
        if args.audit_deployments {
            // Needs the full scanner (Etherscan source) to audit deployments.
            let Some((_cfg, rpc, scanner)) = prepare_chain(g, *chain, multichain).await? else {
                continue;
            };
            total.add(
                scan_events_range(&rpc, args.from, args.to, &topics, args.log_chunk, args.log_concurrency, &mut ctx)
                    .await?,
            );
            total.add(
                scan_risky_deployments_range(&rpc, &scanner, args.from, args.to, min_risk, &mut ctx).await?,
            );
        } else if let Some(rpc) = prepare_chain_rpc(g, *chain, multichain)? {
            total.add(
                scan_events_range(&rpc, args.from, args.to, &topics, args.log_chunk, args.log_concurrency, &mut ctx)
                    .await?,
            );
        }
    }
    // Emit one digest per group (no-op unless --group).
    flush_groups(&mut grouper, &sink, &mut total).await;
    report_alert_total(&total);
    Ok(())
}

/// Final monitor/watch summary line: emitted count, plus suppressed/throttled
/// counts when nonzero and a partial-scan note when any log/receipt fetch failed.
fn report_alert_total(total: &AlertCounts) {
    let mut extra: Vec<String> = Vec::new();
    if total.suppressed > 0 {
        extra.push(format!("{} suppressed", total.suppressed));
    }
    if total.throttled > 0 {
        extra.push(format!("{} throttled", total.throttled));
    }
    if total.grouped > 0 {
        extra.push(format!("{} grouped", total.grouped));
    }
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(" ({})", extra.join(", "))
    };
    let partial = if total.incomplete {
        " — some scans were partial (see warnings)"
    } else {
        ""
    };
    eprintln!("\nDone. {} alert(s){extra}{partial}", total.emitted);
}

/// Parse `--min-transfer` (decimal uint256). Logs and ignores an invalid value.
fn parse_min_transfer(s: Option<&str>) -> Option<alloy::primitives::U256> {
    let s = s?;
    match s.parse::<alloy::primitives::U256>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!("ignoring invalid --min-transfer '{s}' (want a decimal uint256)");
            None
        }
    }
}

/// Deliver one alert to the sinks + stdout through two gates: cross-run baseline
/// de-dup (exact repeats) then in-run burst throttle (per chain+contract+kind cap).
/// The baseline fingerprint is committed only AFTER both gates pass, so a throttled
/// alert isn't permanently recorded — it can still fire on a later run with budget.
async fn deliver_alert(ctx: &mut AlertCtx<'_>, alert: Alert, counts: &mut AlertCounts) {
    if ctx.baseline.seen(&alert) {
        counts.suppressed += 1;
        return;
    }
    // Group mode: fold into a per-(chain,contract,kind) digest instead of emitting
    // individually (and instead of throttling). Digests are flushed at end of run.
    // The baseline is recorded here so grouped alerts are de-duplicated across runs
    // (a tested, intended feature). Known minor edge: if the process is killed
    // between this fold and the end-of-run/periodic flush, that alert's digest is
    // not emitted yet its fingerprint is recorded, so a later run won't re-surface
    // it — a narrow window (ms for `monitor`, one digest interval for `watch`).
    if ctx.grouper.enabled() {
        ctx.baseline.record(&alert);
        ctx.grouper.add(&alert);
        counts.grouped += 1;
        return;
    }
    if !ctx.throttle.allow(alert.chain_id, &alert.contract, &alert.kind) {
        counts.throttled += 1;
        return;
    }
    ctx.baseline.record(&alert);
    ctx.sink.emit(&alert).await;
    emit_alert_line(&alert);
    counts.emitted += 1;
}

/// Emit one digest per accumulated group (end of `--group` run), counted as emitted.
async fn flush_groups(grouper: &mut group::Grouper, sink: &alert::AlertSink, total: &mut AlertCounts) {
    for digest in grouper.drain() {
        sink.emit(&digest).await;
        emit_alert_line(&digest);
        total.emitted += 1;
    }
}

/// Periodic-flush variant operating through the live [`AlertCtx`] (used by the watch
/// loop's `--digest-interval` timer, where the grouper is borrowed by `ctx`).
async fn flush_groups_via_ctx(ctx: &mut AlertCtx<'_>, total: &mut AlertCounts) {
    flush_groups(ctx.grouper, ctx.sink, total).await;
}

/// Scan `[from,to]` for security-event logs and emit alerts (de-dup aware).
async fn scan_events_range(
    rpc: &RpcClient,
    from: u64,
    to: u64,
    topics: &[B256],
    log_chunk: u64,
    log_concurrency: usize,
    ctx: &mut AlertCtx<'_>,
) -> error::Result<AlertCounts> {
    let (logs, failed) = rpc.fetch_logs(from, to, topics.to_vec(), log_chunk, log_concurrency).await?;
    let mut counts = AlertCounts { incomplete: failed > 0, ..Default::default() };
    for log in &logs {
        if let Some(wl) = ctx.watchlist {
            if !wl.contains(&log.address) {
                continue;
            }
        }
        let mut alert = events::parse_alert(log).unwrap_or_else(|| events::unknown_alert(log));
        alert.chain_id = ctx.chain;
        // Large-transfer gate: a Transfer alert is emitted ONLY when a `--min-transfer`
        // threshold is set AND the log carries a decodable ERC-20 value at/above it.
        // This makes Transfer strictly opt-in (a Transfer topic injected via
        // --alert-topic without a threshold is dropped) and excludes ERC-721 transfers
        // (tokenId indexed, no data value) regardless of the threshold.
        if alert.kind == "large-transfer" {
            let value = alert.amount.as_deref().and_then(|s| s.parse::<alloy::primitives::U256>().ok());
            let keep = matches!((ctx.min_transfer, value), (Some(t), Some(v)) if v >= t);
            if !keep {
                continue;
            }
        }
        deliver_alert(ctx, alert, &mut counts).await;
    }
    Ok(counts)
}

/// Scan `[from,to]` for NEW deployments, audit each, and alert on risky ones
/// (`risk_score > 0 && >= min_risk`), de-dup aware.
async fn scan_risky_deployments_range(
    rpc: &RpcClient,
    scanner: &Scanner,
    from: u64,
    to: u64,
    min_risk: u8,
    ctx: &mut AlertCtx<'_>,
) -> error::Result<AlertCounts> {
    let mut counts = AlertCounts::default();
    for block in from..=to {
        let created = match rpc.contract_creations_in_block(block).await {
            Ok(c) => c,
            Err(e) => {
                // A receipts failure would otherwise silently drop this block's
                // deployments; flag it so watch retries instead of skipping ahead.
                tracing::warn!("creations for block {block} failed: {e}");
                counts.incomplete = true;
                continue;
            }
        };
        for addr in created {
            if let Some(wl) = ctx.watchlist {
                if !wl.contains(&addr) {
                    continue;
                }
            }
            let Some(d) = scanner.scan_and_audit(addr).await else { continue };
            let Some(audit) = &d.audit else { continue };
            if audit.risk_score == 0 || audit.risk_score < min_risk {
                continue;
            }
            // Highest-risk finding, with a stable tie-break on title so the digest
            // (and its baseline fingerprint) is order-independent across runs.
            let top = audit
                .findings
                .iter()
                .max_by(|a, b| a.risk.cmp(&b.risk).then_with(|| b.title.cmp(&a.title)))
                .map(|f| f.title.clone())
                .unwrap_or_default();
            let alert = Alert {
                block,
                chain_id: ctx.chain,
                contract: d.address.clone(),
                event: "RiskyDeployment".to_string(),
                kind: "risky-deployment".to_string(),
                new_value: if top.is_empty() { None } else { Some(top) },
                previous: None,
                tx_hash: d.creation_tx_hash.clone(),
                log_index: None, // one risky-deployment alert per address per block
                amount: None,
                risk_score: Some(audit.risk_score),
                grade: Some(audit.grade.clone()),
            };
            deliver_alert(ctx, alert, &mut counts).await;
        }
    }
    Ok(counts)
}

/// Write one alert as a compact JSON line to stdout (broken-pipe safe).
fn emit_alert_line(a: &Alert) {
    use std::io::Write;
    if let Ok(line) = serde_json::to_string(a) {
        let _ = writeln!(std::io::stdout(), "{line}");
    }
}

/// Discover and process all contract creations in a single block.
///
/// Always uses transaction receipts (top-level deployments). When `trace` is set,
/// it additionally queries `trace_block` for factory (CREATE/CREATE2) deployments
/// and merges the two sets. A `trace_block` failure is logged, not fatal.
pub async fn process_block(
    rpc: &RpcClient,
    scanner: &Scanner,
    number: u64,
    trace: bool,
    total: &mut RunStats,
    contracts: &mut Vec<ContractDetails>,
) -> error::Result<()> {
    let mut found = rpc.contract_creations_in_block(number).await?;
    if trace {
        match rpc.trace_creations_in_block(number).await {
            Ok(mut extra) => found.append(&mut extra),
            Err(e) => tracing::warn!(
                "trace_block failed for block {number} (is the trace_ namespace enabled?): {e}"
            ),
        }
        found.sort();
        found.dedup();
    }
    if found.is_empty() {
        tracing::debug!("block {number}: no new contracts");
        return Ok(());
    }
    tracing::info!("block {number}: {} new contract(s)", found.len());
    let (stats, mut got) = scanner.process_addresses(found).await;
    merge(total, stats);
    contracts.append(&mut got);
    Ok(())
}

/// Emit the run's structured output to stdout when `--format json`.
/// `contracts` is the run-scoped set actually processed this invocation (so the
/// doc's `stats` and `contracts` agree). Human mode already printed its summary;
/// ndjson already streamed per contract.
fn emit_run_output(
    g: &GlobalArgs,
    stats: &RunStats,
    contracts: &[ContractDetails],
    mode: &str,
) -> error::Result<()> {
    use std::io::Write;
    // Ignore write errors (e.g. BrokenPipe from `| head`) instead of panicking.
    match g.format {
        OutputFormat::Json => {
            let chains: Vec<u64> = if g.chains.is_empty() {
                vec![g.chain_id]
            } else {
                g.chains.clone()
            };
            let doc = serde_json::json!({
                "run": { "mode": mode, "chains": chains, "out": g.out.display().to_string() },
                "stats": stats,
                "contracts": contracts,
            });
            let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string_pretty(&doc)?);
        }
        OutputFormat::Sarif => {
            // A SARIF log of the audit findings from this run's contracts.
            let doc = sarif::build_sarif(contracts);
            let _ = writeln!(std::io::stdout(), "{}", serde_json::to_string_pretty(&doc)?);
        }
        // Human: already printed; ndjson: already streamed per contract.
        OutputFormat::Human | OutputFormat::Ndjson => {}
    }
    Ok(())
}

/// Watch the chain head, scanning each newly confirmed block until `shutdown` resolves.
/// Returns the accumulated run stats (used for `--format json` at shutdown).
pub async fn watch_with_shutdown<S>(
    rpc: &RpcClient,
    scanner: &Scanner,
    args: WatchArgs,
    trace: bool,
    format: OutputFormat,
    shutdown: S,
) -> error::Result<(RunStats, Vec<ContractDetails>)>
where
    S: Future<Output = ()>,
{
    let confirmations = args.confirmations;
    let poll = std::time::Duration::from_millis(args.poll_ms);

    let head = rpc.block_number().await?;
    let mut next = head.saturating_sub(confirmations).saturating_add(1);
    tracing::info!("watching from block {next} (confirmations={confirmations}); Ctrl-C to stop");

    let mut total = RunStats::default();
    let mut contracts: Vec<ContractDetails> = Vec::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutting down");
                break;
            }
            _ = tokio::time::sleep(poll) => {
                poll_tick(rpc, scanner, &mut next, confirmations, trace, &mut total, &mut contracts).await;
            }
        }
    }

    print_summary(&total, format);
    Ok((total, contracts))
}

/// One watch iteration: read the head and process every newly confirmed block.
/// Errors are logged and swallowed so the watch loop keeps running.
pub async fn poll_tick(
    rpc: &RpcClient,
    scanner: &Scanner,
    next: &mut u64,
    confirmations: u64,
    trace: bool,
    total: &mut RunStats,
    contracts: &mut Vec<ContractDetails>,
) {
    let head = match rpc.block_number().await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("block_number failed: {e}");
            return;
        }
    };
    let confirmed = head.saturating_sub(confirmations);
    while *next <= confirmed {
        if let Err(e) = process_block(rpc, scanner, *next, trace, total, contracts).await {
            tracing::warn!("block {next} failed: {e}");
            break;
        }
        *next += 1;
    }
}

/// Default `eth_getLogs` window / concurrency for alert-mode `watch` (the
/// confirmed range per tick is small, so these rarely matter).
const WATCH_LOG_CHUNK: u64 = 2000;
const WATCH_LOG_CONCURRENCY: usize = 4;

/// Real-time alert mode for `watch`: follow the chain head and, for each newly
/// confirmed block, emit security-event and/or risky-deployment alerts (reusing
/// the monitor range helpers + cross-run baseline). Returns the alert tally.
pub async fn watch_alerts_with_shutdown<S>(
    g: &GlobalArgs,
    rpc: &RpcClient,
    scanner: Option<&Scanner>,
    args: WatchArgs,
    chain: u64,
    shutdown: S,
) -> error::Result<AlertCounts>
where
    S: Future<Output = ()>,
{
    let mut topics = build_topics(&args.alert_topic);
    let min_transfer = parse_min_transfer(args.min_transfer.as_deref());
    if min_transfer.is_some() {
        // Transfer alerts ride the event path, which only runs under --alert-events.
        if args.alert_events {
            let t = events::transfer_topic();
            if !topics.contains(&t) {
                topics.push(t);
            }
        } else {
            tracing::warn!("--min-transfer needs --alert-events to take effect on watch; ignoring");
        }
    }
    let watchlist = load_watchlist(args.watchlist.as_deref())?;
    let sink = alert::AlertSink::new(args.alerts.clone(), args.webhook_url.clone());
    let mut base = baseline::AlertBaseline::load(args.baseline.clone());
    let mut throttle = throttle::Throttle::new(args.throttle);
    let mut grouper = group::Grouper::new(args.group);
    if args.group && args.throttle.is_some() {
        tracing::warn!("--throttle is ignored in --group mode (grouping supersedes throttling)");
    }
    let min_risk = g.min_risk.min(100);
    let confirmations = args.confirmations;
    let poll = std::time::Duration::from_millis(args.poll_ms);

    let head = rpc.block_number().await?;
    let mut next = head.saturating_sub(confirmations).saturating_add(1);
    let mode = match (args.alert_events, args.alert_on_risk) {
        (true, true) => "events+risk",
        (true, false) => "events",
        _ => "risk",
    };
    tracing::info!(
        "watching from block {next} (confirmations={confirmations}, mode={mode}); Ctrl-C to stop"
    );

    // Persistent poll timer — must NOT be a per-iteration `sleep`, or the always-ready
    // digest branch would keep restarting it and starve `poll_alert_tick`.
    let mut poll_timer = tokio::time::interval(poll);
    // Optional periodic group-digest timer (only with --group + --digest-interval).
    let mut digest_timer = args
        .digest_interval
        .filter(|s| *s > 0 && args.group)
        .map(|s| tokio::time::interval(std::time::Duration::from_secs(s)));

    let mut total = AlertCounts::default();
    {
        let mut ctx = AlertCtx {
            sink: &sink,
            baseline: &mut base,
            throttle: &mut throttle,
            grouper: &mut grouper,
            watchlist: &watchlist,
            chain,
            min_transfer,
        };
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("shutting down");
                    break;
                }
                _ = poll_timer.tick() => {
                    poll_alert_tick(
                        rpc, scanner, &args, &topics, &mut ctx, min_risk, &mut next, confirmations, &mut total,
                    ).await;
                }
                // Periodic digest flush. When no timer is configured this branch's
                // future is `pending` forever, so it never fires.
                _ = async {
                    match digest_timer.as_mut() {
                        Some(t) => { t.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    flush_groups_via_ctx(&mut ctx, &mut total).await;
                }
            }
        }
    } // drop ctx -> releases the &mut grouper borrow before flushing
    // Emit any remaining group digests at shutdown (no-op unless --group).
    flush_groups(&mut grouper, &sink, &mut total).await;
    Ok(total) // caller reports (run() aggregates across chains for --chains)
}

/// Run alert-mode `watch` across one or more chains concurrently, returning the
/// aggregate tally. Each chain gets its own RPC/scanner + independent
/// baseline/throttle/grouper — safe without locks because all keys/fingerprints are
/// chain-scoped (distinct chains never collide), and the shared `alerts.jsonl` /
/// baseline file appends are line-atomic. The single `shutdown` is fanned out via
/// `Shared` so Ctrl-C stops every chain.
pub async fn watch_alerts_multichain<S>(
    g: &GlobalArgs,
    chains: &[u64],
    multichain: bool,
    args: WatchArgs,
    shutdown: S,
) -> error::Result<AlertCounts>
where
    S: Future<Output = ()>,
{
    use futures::FutureExt;
    // Build each chain's clients up front (so the spawned futures can borrow them).
    let mut prepared: Vec<(u64, RpcClient, Option<Scanner>)> = Vec::new();
    for chain in chains {
        if args.alert_on_risk {
            if let Some((_cfg, rpc, scanner)) = prepare_chain(g, *chain, multichain).await? {
                prepared.push((*chain, rpc, Some(scanner)));
            }
        } else if let Some(rpc) = prepare_chain_rpc(g, *chain, multichain)? {
            prepared.push((*chain, rpc, None));
        }
    }
    if prepared.is_empty() {
        return Err(error::AppError::Config("no RPC configured for any chain".into()));
    }

    let shutdown = shutdown.shared();
    let futs = prepared.iter().map(|(chain, rpc, scanner)| {
        watch_alerts_with_shutdown(g, rpc, scanner.as_ref(), args.clone(), *chain, shutdown.clone())
    });
    let mut total = AlertCounts::default();
    for result in futures::future::join_all(futs).await {
        total.add(result?);
    }
    Ok(total)
}

/// One alert-mode watch iteration: read the head and run the configured alert
/// scans over every newly confirmed block. Errors are logged and swallowed so the
/// loop keeps running. `next` only advances when the tick scanned the whole range
/// *completely* — a hard error OR a partial log/receipt fetch leaves `next` put so
/// the range is retried next tick (rather than silently dropping a block's alerts).
/// On retry, already-emitted alerts re-fire unless `--baseline` de-dups them, so
/// `--baseline` is recommended for long-running watches.
#[allow(clippy::too_many_arguments)]
pub async fn poll_alert_tick(
    rpc: &RpcClient,
    scanner: Option<&Scanner>,
    args: &WatchArgs,
    topics: &[B256],
    ctx: &mut AlertCtx<'_>,
    min_risk: u8,
    next: &mut u64,
    confirmations: u64,
    total: &mut AlertCounts,
) {
    let head = match rpc.block_number().await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("block_number failed: {e}");
            return;
        }
    };
    let confirmed = head.saturating_sub(confirmations);
    if *next > confirmed {
        return; // nothing new yet
    }
    let mut incomplete = false;
    if args.alert_events {
        match scan_events_range(
            rpc, *next, confirmed, topics, WATCH_LOG_CHUNK, WATCH_LOG_CONCURRENCY, ctx,
        )
        .await
        {
            Ok(c) => {
                incomplete |= c.incomplete;
                total.add(c);
            }
            Err(e) => {
                tracing::warn!("event scan {next}..={confirmed} failed: {e}");
                return; // hard error: don't advance; retry the range next tick
            }
        }
    }
    if args.alert_on_risk {
        // `alert_on_risk` is only reachable with a full scanner (see run()'s dispatch).
        let scanner = scanner.expect("alert_on_risk requires a scanner");
        match scan_risky_deployments_range(rpc, scanner, *next, confirmed, min_risk, ctx).await {
            Ok(c) => {
                incomplete |= c.incomplete;
                total.add(c);
            }
            Err(e) => {
                tracing::warn!("deployment scan {next}..={confirmed} failed: {e}");
                return;
            }
        }
    }
    if incomplete {
        // Some window/block in the range failed; retry it next tick instead of
        // advancing past unscanned blocks.
        tracing::warn!("blocks {next}..={confirmed} only partially scanned; will retry");
        return;
    }
    *next = confirmed + 1;
}

/// Accumulate per-batch stats into a running total.
pub fn merge(total: &mut RunStats, s: RunStats) {
    total.saved += s.saved;
    total.verified += s.verified;
    total.skipped += s.skipped;
    total.not_contract += s.not_contract;
    total.filtered += s.filtered;
    total.failed += s.failed;
    total.degraded += s.degraded;
}

/// Print the final run summary line. In machine output modes (`json`/`ndjson`)
/// it goes to stderr so stdout stays pure data.
pub fn print_summary(s: &RunStats, fmt: OutputFormat) {
    let mut line = format!(
        "\nDone. saved={} (verified={}), skipped={}, non-contract={}, filtered={}, failed={}",
        s.saved, s.verified, s.skipped, s.not_contract, s.filtered, s.failed
    );
    // Only shown when non-zero: a degraded scan is the exception, and a
    // permanent `degraded=0` on every run trains the eye to skip it.
    if s.degraded > 0 {
        line.push_str(&format!(", degraded={}", s.degraded));
    }
    if fmt == OutputFormat::Human {
        println!("{line}");
    } else {
        eprintln!("{line}");
    }
}

/// Configure tracing from a verbosity count (0=info, 1=debug, 2+=trace).
pub fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("blockscan={level}"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr) // keep stdout pure for --format json/ndjson
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(args)
    }

    #[test]
    fn config_from_cli_maps_fields() {
        let c = cli(&[
            "blockscan",
            "--rpc-url",
            "http://r",
            "--etherscan-key",
            "k",
            "--chain-id",
            "10",
            "--concurrency",
            "3",
            "--rate",
            "7",
            "--overwrite",
            "-o",
            "myout",
            "addresses",
            "0xabc",
        ]);
        let cfg = config_from_cli(&c.global);
        assert_eq!(cfg.rpc_url, "http://r");
        assert_eq!(cfg.etherscan_key, "k");
        assert_eq!(cfg.chain_id, 10);
        assert_eq!(cfg.concurrency, 3);
        assert_eq!(cfg.rate, 7);
        assert!(cfg.overwrite);
        assert_eq!(cfg.out_dir, std::path::PathBuf::from("myout"));
    }

    #[test]
    fn merge_accumulates() {
        let mut t = RunStats::default();
        merge(
            &mut t,
            RunStats {
                saved: 1,
                verified: 1,
                degraded: 1,
                skipped: 2,
                not_contract: 3,
                filtered: 1,
                failed: 4,
            },
        );
        merge(
            &mut t,
            RunStats {
                saved: 1,
                verified: 0,
                degraded: 0,
                skipped: 0,
                not_contract: 0,
                filtered: 2,
                failed: 1,
            },
        );
        assert_eq!(t.saved, 2);
        assert_eq!(t.verified, 1);
        assert_eq!(t.skipped, 2);
        assert_eq!(t.not_contract, 3);
        assert_eq!(t.filtered, 3);
        assert_eq!(t.degraded, 1);
        assert_eq!(t.failed, 5);
    }

    #[test]
    fn print_summary_runs() {
        // Human -> stdout, machine modes -> stderr; exercise both branches.
        print_summary(&RunStats::default(), OutputFormat::Human);
        print_summary(&RunStats::default(), OutputFormat::Json);
    }

    #[test]
    fn emit_run_output_human_is_noop_json_emits() {
        let tmp = tempfile::tempdir().unwrap();
        let mut g = cli(&["blockscan", "-o", tmp.path().to_str().unwrap(), "addresses", "0xabc"]).global;
        // Human mode: no stdout doc, returns Ok.
        g.format = OutputFormat::Human;
        emit_run_output(&g, &RunStats::default(), &[], "addresses").unwrap();
        // Json mode over an empty out dir: emits a valid doc (contracts: []).
        g.format = OutputFormat::Json;
        emit_run_output(&g, &RunStats::default(), &[], "addresses").unwrap();
    }

    #[test]
    fn init_tracing_all_levels() {
        init_tracing(0);
        init_tracing(1);
        init_tracing(2);
    }

    #[test]
    fn run_audit_loads_source_from_per_chain_subdir_and_filters() {
        use crate::cli::AuditArgs;
        use crate::model::{ContractDetails, SourceFile};

        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");

        // A verified contract saved under a per-chain subdir (out/optimism/<addr>/),
        // exactly the layout a non-mainnet scan produces. Its source uses tx.origin,
        // so a SOURCE-level detector must fire — which only happens if run_audit
        // loads the source from the real subdir, not the flat out/<addr>/ path.
        let mut vuln = ContractDetails::minimal("0xVULN", 10);
        vuln.is_verified = true;
        vuln.bytecode = "0x6001".into();
        let vuln_src = vec![SourceFile {
            path: "C.sol".into(),
            content: "contract C { function f() public { require(tx.origin == msg.sender); } }".into(),
        }];
        storage::save_contract(&out.join("optimism"), &vuln, &vuln_src, None).unwrap();

        // A clean mainnet contract under the flat layout (no source findings).
        let mut clean = ContractDetails::minimal("0xCLEAN", 1);
        clean.is_verified = true;
        clean.bytecode = "0x00".into();
        let clean_src = vec![SourceFile { path: "Clean.sol".into(), content: "contract Clean {}".into() }];
        storage::save_contract(&out, &clean, &clean_src, None).unwrap();

        let mut g = cli(&["blockscan", "-o", out.to_str().unwrap(), "audit"]).global;

        // Sanity: the per-chain contract's source really is detected as vulnerable
        // while the clean one is not (the core of the bug being fixed).
        let by_dir = storage::load_all_metadata_with_dirs(&out);
        assert_eq!(by_dir.len(), 2);
        for (dir, d) in &by_dir {
            let a = audit::audit(d, &storage::load_sources_from_dir(dir));
            let vulnerable = a.findings.iter().any(|f| f.rule_id == "TX_ORIGIN_AUTH");
            assert_eq!(vulnerable, d.address == "0xVULN", "addr {}", d.address);
        }

        // Exercise run_audit's output/sort/filter branches in-process (the binary
        // integration test runs it in a subprocess, which llvm-cov can't see here).
        g.format = OutputFormat::Json;
        run_audit(&g, &AuditArgs { by_risk: true, import: Vec::new() }).unwrap();
        g.format = OutputFormat::Ndjson;
        run_audit(&g, &AuditArgs { by_risk: false, import: Vec::new() }).unwrap();
        g.format = OutputFormat::Human;
        g.only_vulnerable = true; // keeps only the tx.origin contract
        run_audit(&g, &AuditArgs { by_risk: false, import: Vec::new() }).unwrap();
        g.only_vulnerable = false;
        g.min_risk = 101; // clamped to 100; drops everything without panicking
        run_audit(&g, &AuditArgs { by_risk: false, import: Vec::new() }).unwrap();
    }

    #[tokio::test]
    async fn run_validate_error() {
        // Empty Etherscan key -> validate fails before any network use.
        let c = cli(&["blockscan", "--rpc-url", "http://r", "addresses", "0xabc"]);
        assert!(run(c, std::future::ready(())).await.is_err());
    }

    #[tokio::test]
    async fn run_addresses_empty_error() {
        let c = cli(&[
            "blockscan",
            "--rpc-url",
            "http://r",
            "--etherscan-key",
            "k",
            "addresses",
        ]);
        let err = run(c, std::future::ready(())).await.unwrap_err();
        assert!(matches!(err, error::AppError::Config(_)));
    }

    #[tokio::test]
    async fn run_watch_without_rpc_errors() {
        // No --rpc-url and no ETH_RPC_URL_<id> -> chain skipped -> watch has no RPC.
        std::env::remove_var("ETH_RPC_URL");
        let c = cli(&["blockscan", "watch", "--rpc-url", "", "--etherscan-key", "k"]);
        assert!(run(c, std::future::ready(())).await.is_err());
    }

    #[test]
    fn build_topics_dedups_and_skips_invalid() {
        let base = events::default_alert_topics().len();
        let dup = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"; // UPGRADED
        let new = format!("0x{}", "ab".repeat(32));
        let topics = build_topics(&[new.clone(), dup.to_string(), "not-a-hash".into()]);
        // The valid new topic is added; the duplicate and the invalid one are not.
        assert_eq!(topics.len(), base + 1);
        assert!(topics.iter().any(|t| format!("{t:#x}") == new));
    }

    #[test]
    fn parse_min_transfer_valid_and_invalid() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        assert!(parse_min_transfer(None).is_none());
        assert_eq!(
            parse_min_transfer(Some("1000")),
            Some(alloy::primitives::U256::from(1000u64))
        );
        // A non-numeric value warns and yields None (monitoring still runs).
        assert!(parse_min_transfer(Some("not-a-number")).is_none());
    }

    #[test]
    fn load_watchlist_none_and_empty() {
        // No path -> None.
        assert!(load_watchlist(None).unwrap().is_none());
        // Comments-only file -> Some(empty) (and warns).
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("wl.txt");
        std::fs::write(&p, "# just a comment\n\n").unwrap();
        let wl = load_watchlist(Some(p.as_path())).unwrap().unwrap();
        assert!(wl.is_empty());
    }

    #[tokio::test]
    async fn run_range_from_after_to_error() {
        let c = cli(&[
            "blockscan",
            "--rpc-url",
            "http://r",
            "--etherscan-key",
            "k",
            "range",
            "--from",
            "10",
            "--to",
            "5",
        ]);
        assert!(run(c, std::future::ready(())).await.is_err());
    }

    /// A scanner pointed at a closed port: every networked discovery source
    /// fails fast, so only the no-network branches under test can emit anything.
    fn offline_scanner() -> Scanner {
        let g = cli(&[
            "blockscan",
            "--rpc-url",
            "http://127.0.0.1:1",
            "--etherscan-key",
            "k",
            "addresses",
            "0xabc",
        ])
        .global;
        build_scanner(&build_chain_config(&g, 1, false)).unwrap().1
    }

    /// Parses `DiscoverArgs` on its own rather than through `Command`, so the
    /// helper needs no unreachable fallback arm for the other subcommands.
    #[derive(Parser)]
    struct DiscoverOnly {
        #[command(flatten)]
        args: DiscoverArgs,
    }

    fn discover_args(extra: &[&str]) -> DiscoverArgs {
        let mut argv = vec!["blockscan"];
        argv.extend_from_slice(extra);
        DiscoverOnly::parse_from(argv).args
    }

    #[test]
    fn prepare_chain_rpc_skips_chain_without_rpc() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // A secondary chain with no ETH_RPC_URL_<id> is skipped, not an error —
        // a multichain run has to survive a chain the user has no endpoint for.
        std::env::remove_var("ETH_RPC_URL_424242");
        let g = cli(&[
            "blockscan",
            "--rpc-url",
            "http://127.0.0.1:1",
            "--etherscan-key",
            "k",
            "addresses",
            "0xabc",
        ])
        .global;
        assert!(prepare_chain_rpc(&g, 424242, true).unwrap().is_none());
        // The primary chain still resolves from --rpc-url.
        assert!(prepare_chain_rpc(&g, g.chain_id, true).unwrap().is_some());
    }

    #[tokio::test]
    async fn discover_topic_without_valid_hash_skips_log_scan() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // The range is well formed, but no --topic parses as a 32-byte hash, so
        // the log scan is skipped rather than issuing an unfiltered eth_getLogs.
        let args = discover_args(&["--topic", "not-a-hash", "--from", "1", "--to", "2"]);
        assert!(discover_addresses(&offline_scanner(), &args)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn discover_topic_without_range_skips_log_scan() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // A valid topic but no --from/--to: there is no range to scan, so the
        // log scan is skipped entirely.
        let topic = format!("0x{}", "ab".repeat(32));
        let args = discover_args(&["--topic", topic.as_str()]);
        assert!(discover_addresses(&offline_scanner(), &args)
            .await
            .is_empty());
    }

    /// Same trick as [`DiscoverOnly`], for the watch flags.
    #[derive(Parser)]
    struct WatchOnly {
        #[command(flatten)]
        args: WatchArgs,
    }

    #[test]
    fn write_manifest_if_set_writes_manifest_and_clusters() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("manifest.json");
        let mut g = cli(&[
            "blockscan",
            "-o",
            tmp.path().to_str().unwrap(),
            "addresses",
            "0xabc",
        ])
        .global;

        // Without --manifest nothing is written at all.
        write_manifest_if_set(&g).unwrap();
        assert!(!manifest.exists());

        // With --manifest, the clone-cluster file lands beside it rather than in
        // the working directory, so a run never writes outside --out's neighbourhood.
        g.manifest = Some(manifest.clone());
        write_manifest_if_set(&g).unwrap();
        assert!(manifest.exists());
        assert!(tmp.path().join("clusters.json").exists());
    }

    /// T-12 end to end: a Slither file on disk, through the CLI path, into the
    /// document — attributed, tallied apart, and not touching the grade.
    #[test]
    fn audit_merges_an_import_without_moving_the_score() {
        let tmp = tempfile::tempdir().unwrap();
        let addr = "0x00000000000000000000000000000000000000ff";
        let dir = tmp.path().join(addr);
        std::fs::create_dir_all(dir.join("source/src")).unwrap();
        std::fs::write(
            dir.join("source/src/Vault.sol"),
            "pragma solidity ^0.8.0;\ncontract V { function f() public { require(tx.origin == owner); } }",
        )
        .unwrap();
        let mut d = crate::model::ContractDetails::minimal(addr, 1);
        d.contract_name = Some("Vault".into());
        d.is_verified = true;
        std::fs::write(dir.join("metadata.json"), serde_json::to_string(&d).unwrap()).unwrap();

        let imp = tmp.path().join("slither.json");
        std::fs::write(
            &imp,
            serde_json::json!({
                "success": true,
                "results": { "detectors": [{
                    "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
                    "description": "Reentrancy in V.f()",
                    "elements": [{ "source_mapping": {
                        "filename_relative": "src/Vault.sol", "lines": [2]
                    }}]
                }]}
            })
            .to_string(),
        )
        .unwrap();

        // The grade the corpus produces on its own.
        let before = audit_corpus(
            tmp.path(),
            0,
            false,
            false,
            &suppress::Suppressions::default(),
        );
        let native_score = before[0].audit.as_ref().unwrap().risk_score;
        assert!(native_score > 0, "the fixture must actually score something");

        let out = tmp.path().join("report.md");
        let mut g = cli(&["blockscan", "-o", tmp.path().to_str().unwrap(), "audit"]).global;
        g.manifest = Some(out.clone());
        run_audit(
            &g,
            &crate::cli::AuditArgs { by_risk: false, import: vec![imp] },
        )
        .unwrap();

        let body = std::fs::read_to_string(&out).unwrap();
        assert!(body.contains("slither:reentrancy-eth"), "the import is in the document");
        assert!(body.contains("| Severity | blockscan | imported |"), "{body}");
        assert!(
            body.contains(&format!("grade {}", grade_of(native_score))),
            "the grade must be the one the native findings alone produce: {body}"
        );
    }

    /// Mirror of audit.rs's own banding, so this test does not depend on a
    /// private function.
    fn grade_of(score: u8) -> &'static str {
        match score {
            0..=9 => "A",
            10..=24 => "B",
            25..=44 => "C",
            45..=69 => "D",
            _ => "F",
        }
    }

    /// T-14: `audit --manifest report.md` has to produce the document
    /// end-to-end, over the filtered set this subcommand builds rather than the
    /// whole corpus. Dispatch and rendering are tested in export.rs; what this
    /// pins is that the two are wired together and reachable from the CLI.
    #[test]
    fn audit_writes_a_document_when_manifest_names_one() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("0x00000000000000000000000000000000000000ff");
        std::fs::create_dir_all(&dir).unwrap();
        let mut d = crate::model::ContractDetails::minimal(
            "0x00000000000000000000000000000000000000ff",
            1,
        );
        d.contract_name = Some("Sample".into());
        d.is_verified = true;
        std::fs::write(
            dir.join("metadata.json"),
            serde_json::to_string(&d).unwrap(),
        )
        .unwrap();

        for (name, opener) in [("report.md", "# BlockScan audit report"), ("report.html", "<!doctype html>")] {
            let out = tmp.path().join(name);
            let mut g = cli(&["blockscan", "-o", tmp.path().to_str().unwrap(), "audit"]).global;
            g.manifest = Some(out.clone());
            run_audit(&g, &crate::cli::AuditArgs { by_risk: false, import: Vec::new() }).unwrap();
            let body = std::fs::read_to_string(&out).unwrap();
            assert!(body.starts_with(opener), "{name}: {}", &body[..40.min(body.len())]);
            assert!(body.contains("Sample"), "{name} must describe the contract");
        }

        // And the refusal reaches the CLI rather than writing JSON into a .pdf.
        let pdf = tmp.path().join("report.pdf");
        let mut g = cli(&["blockscan", "-o", tmp.path().to_str().unwrap(), "audit"]).global;
        g.manifest = Some(pdf.clone());
        assert!(run_audit(&g, &crate::cli::AuditArgs { by_risk: false, import: Vec::new() }).is_err());
        assert!(!pdf.exists());
    }

    #[test]
    fn emit_run_output_sarif_and_multichain_json() {
        let tmp = tempfile::tempdir().unwrap();
        let mut g = cli(&[
            "blockscan",
            "-o",
            tmp.path().to_str().unwrap(),
            "addresses",
            "0xabc",
        ])
        .global;
        // Sarif mode emits a SARIF log built from this run's contracts.
        g.format = OutputFormat::Sarif;
        emit_run_output(&g, &RunStats::default(), &[], "addresses").unwrap();
        // Json mode reports every scanned chain, not just the primary chain_id.
        g.format = OutputFormat::Json;
        g.chains = vec![1, 10];
        emit_run_output(&g, &RunStats::default(), &[], "addresses").unwrap();
    }

    #[tokio::test]
    async fn run_rejects_audit_filters_without_audit() {
        // --min-risk filters on a score --no-audit never computes; refuse the
        // combination instead of silently returning everything.
        let c = cli(&[
            "blockscan",
            "--rpc-url",
            "http://r",
            "--etherscan-key",
            "k",
            "--no-audit",
            "--min-risk",
            "50",
            "addresses",
            "0xabc",
        ]);
        let err = run(c, std::future::ready(())).await.unwrap_err();
        assert!(matches!(err, error::AppError::Config(_)));
    }

    #[tokio::test]
    async fn run_discover_without_any_source_errors() {
        // `discover` with no name and no --github/--website/--topic/... has
        // nothing to discover from, so it fails before opening any connection.
        let c = cli(&[
            "blockscan",
            "--rpc-url",
            "http://r",
            "--etherscan-key",
            "k",
            "discover",
        ]);
        let err = run(c, std::future::ready(())).await.unwrap_err();
        assert!(matches!(err, error::AppError::Config(_)));
    }

    #[tokio::test]
    async fn watch_alerts_multichain_without_any_rpc_errors() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        // Every requested chain is secondary and has no ETH_RPC_URL_<id>, so each
        // is skipped and nothing is left to watch — that must be an error, not a
        // silently idle watcher.
        std::env::remove_var("ETH_RPC_URL_424242");
        std::env::remove_var("ETH_RPC_URL_424243");
        let g = cli(&[
            "blockscan",
            "--rpc-url",
            "http://127.0.0.1:1",
            "--etherscan-key",
            "k",
            "addresses",
            "0xabc",
        ])
        .global;
        let args = WatchOnly::parse_from(["blockscan", "--alert-events"]).args;
        let err = watch_alerts_multichain(&g, &[424242, 424243], true, args, std::future::ready(()))
            .await
            .unwrap_err();
        assert!(matches!(err, error::AppError::Config(_)));
    }
}
