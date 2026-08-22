use std::sync::Arc;

use alloy::primitives::{Address, Bytes, U256};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::config::Config;
use crate::enrich::Blockscout;
use crate::etherscan::{CreationResult, EtherscanClient, SourceCodeResult};
use crate::model::{ContractDetails, SaveOutcome, SourceFile};
use crate::rpc::RpcClient;
use crate::sourcify::Sourcify;
use crate::storage;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// Everything needed to persist one contract, assembled from RPC + Etherscan data.
pub struct BuiltContract {
    pub details: ContractDetails,
    pub sources: Vec<SourceFile>,
    /// ABI text to write to `abi.json`, when verified and available.
    pub abi: Option<String>,
}

/// Shared, cheap-to-clone handles for the processing pipeline.
#[derive(Clone)]
pub struct Scanner {
    cfg: Arc<Config>,
    rpc: RpcClient,
    etherscan: EtherscanClient,
    blockscout: Blockscout,
    sourcify: Sourcify,
    /// Hash of the block `rpc` pins state reads to, resolved once with the pin.
    /// Recorded on every contract so a reader knows which chain state produced
    /// the result — the height alone does not survive a reorg.
    block_hash: Option<String>,
}

/// Aggregate counters for the run summary.
#[derive(Default, Debug, Serialize)]
pub struct RunStats {
    pub saved: usize,
    pub verified: usize,
    /// Saved, but with at least one lookup unanswered -- see
    /// `ContractDetails::incomplete`. A subset of `saved`, not a separate
    /// bucket: the contract is on disk, it is just not fully described.
    pub degraded: usize,
    pub skipped: usize,
    pub not_contract: usize,
    pub filtered: usize,
    pub failed: usize,
}

impl Scanner {
    pub fn new(
        cfg: Arc<Config>,
        rpc: RpcClient,
        etherscan: EtherscanClient,
        blockscout: Blockscout,
        sourcify: Sourcify,
    ) -> Self {
        Self {
            cfg,
            rpc,
            etherscan,
            blockscout,
            sourcify,
            block_hash: None,
        }
    }

    /// This scanner with every state read pinned to `block`.
    ///
    /// A scan reads code, balance and proxy slots per address over minutes. Left
    /// unpinned each read lands on whatever head the node had at that instant,
    /// so one run can mix pre- and post-upgrade state and is not reproducible.
    /// The pin is resolved once, at scan start, and applies to the whole run.
    pub fn pinned_at(mut self, block: u64, hash: Option<String>) -> Self {
        self.rpc = self.rpc.pinned_at(block);
        self.block_hash = hash;
        self
    }

    /// The chain id this scanner targets.
    pub fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    /// Search Blockscout for contracts matching `query` (for `discover`).
    pub async fn blockscout_search(&self, query: &str) -> Vec<String> {
        self.blockscout.search_contracts(query).await
    }

    /// Find contracts that emitted `topics` in `[from, to]` via `eth_getLogs`.
    pub async fn find_by_logs(
        &self,
        from: u64,
        to: u64,
        topics: Vec<alloy::primitives::B256>,
        chunk: u64,
        concurrency: usize,
    ) -> Vec<Address> {
        match self
            .rpc
            .logs_addresses(from, to, topics, chunk, concurrency)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("log scan failed: {e}");
                Vec::new()
            }
        }
    }

    /// Process a batch of addresses concurrently. Returns aggregate stats and,
    /// when `--format json`, the run-scoped [`ContractDetails`] for the JSON doc
    /// (empty otherwise, so ndjson/human stay memory-flat).
    pub async fn process_addresses(&self, addresses: Vec<Address>) -> (RunStats, Vec<ContractDetails>) {
        if addresses.is_empty() {
            return (RunStats::default(), Vec::new());
        }

        let fmt = self.cfg.format;
        // Progress bar only in human mode (it would be noise in machine pipelines).
        let pb = if fmt == OutputFormat::Human {
            let pb = ProgressBar::new(addresses.len() as u64);
            pb.set_style(
                ProgressStyle::with_template("{spinner} [{pos}/{len}] {wide_bar} {msg}").unwrap(),
            );
            pb
        } else {
            ProgressBar::hidden()
        };

        let results: Vec<SaveOutcome> = stream::iter(addresses)
            .map(|addr| {
                let this = self.clone();
                let pb = pb.clone();
                async move {
                    let outcome = this.process_one(addr).await;
                    pb.inc(1);
                    pb.set_message(format!("{addr:#x}"));
                    outcome
                }
            })
            .buffer_unordered(self.cfg.concurrency)
            .collect()
            .await;

        pb.finish_and_clear();

        match fmt {
            OutputFormat::Human if self.cfg.table => {
                for r in &results {
                    if let SaveOutcome::Saved(details) | SaveOutcome::Skipped(Some(details)) = r {
                        let enrich = self.blockscout.fetch(&details.address).await;
                        println!("{}", crate::report::render_contract_table(details, &enrich));
                    }
                }
            }
            OutputFormat::Ndjson => {
                use std::io::Write;
                // Stream one compact JSON line per saved/known contract to stdout.
                // Ignore write errors (e.g. BrokenPipe from `| head`) instead of panicking.
                let mut out = std::io::stdout().lock();
                for r in &results {
                    if let SaveOutcome::Saved(details) | SaveOutcome::Skipped(Some(details)) = r {
                        if let Ok(line) = serde_json::to_string(details.as_ref()) {
                            let _ = writeln!(out, "{line}");
                        }
                    }
                }
            }
            _ => {}
        }

        // Run-scoped details for the JSON / SARIF document (not needed for ndjson/human).
        let details = if matches!(fmt, OutputFormat::Json | OutputFormat::Sarif) {
            results
                .iter()
                .filter_map(|r| match r {
                    SaveOutcome::Saved(d) | SaveOutcome::Skipped(Some(d)) => Some((**d).clone()),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };

        (fold_outcomes(results), details)
    }

    /// Fetch, audit and persist a single contract, returning its details (with the
    /// `audit` populated) — used by `monitor --audit-deployments` for risk scoring.
    /// Always re-audits FRESH (calls `fetch_and_save` directly, bypassing the
    /// resume/`already_saved` short-circuit) so a stale or absent on-disk audit from
    /// an earlier scan can't make the monitor miss a risky contract. `None` for
    /// EOAs / filtered (below `--min-risk`) / fetch failures.
    pub async fn scan_and_audit(&self, addr: Address) -> Option<ContractDetails> {
        let address_str = format!("{addr:#x}");
        match self.fetch_and_save(addr, &address_str).await {
            Ok(SaveOutcome::Saved(d)) => Some(*d),
            _ => None,
        }
    }

    /// Fetch + persist a single contract.
    async fn process_one(&self, addr: Address) -> SaveOutcome {
        let address_str = format!("{addr:#x}");

        if !self.cfg.overwrite && storage::already_saved(&self.cfg.out_dir, &address_str) {
            // Load the saved details whenever output needs them — `--table` OR any
            // machine format — so resumed contracts still appear in the table /
            // ndjson stream / json document instead of silently vanishing.
            let need_details = self.cfg.table || self.cfg.format != OutputFormat::Human;
            let details = if need_details {
                storage::load_metadata(&self.cfg.out_dir, &address_str)
                    .ok()
                    .map(Box::new)
            } else {
                None
            };
            return SaveOutcome::Skipped(details);
        }

        match self.fetch_and_save(addr, &address_str).await {
            Ok(outcome) => outcome,
            Err(e) => SaveOutcome::Failed(format!("{address_str}: {e}")),
        }
    }

    async fn fetch_and_save(
        &self,
        addr: Address,
        address_str: &str,
    ) -> crate::error::Result<SaveOutcome> {
        // 1. On-chain bytecode — if empty, it's an EOA or self-destructed contract.
        let code = self.rpc.get_code(addr).await?;
        if code.is_empty() {
            return Ok(SaveOutcome::NotAContract);
        }
        let balance = self.rpc.get_balance(addr).await?;

        // 2. Etherscan source + metadata.
        let src = self.etherscan.get_source_code(address_str).await?;

        // 3. Creation info. Non-fatal either way -- one enrichment lookup should
        //    not sink the contract -- but a failure and a genuine absence are
        //    recorded differently: the failure is carried into `incomplete` so
        //    the missing creator reads as unanswered, not as "none exists".
        let mut incomplete: Vec<String> = Vec::new();
        let creation = match self.etherscan.get_contract_creation(address_str).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("{address_str}: creation lookup failed: {e}");
                incomplete.push("creation".to_string());
                None
            }
        };

        let mut built =
            build_details(address_str, self.cfg.chain_id, &code, balance, src, creation);
        // Stamp the chain state these reads were answered at. build_details is
        // pure over the data it is handed; the pin belongs to the scan, not to
        // the contract, so it is applied here where the scan knows it.
        built.details.block_number = self.rpc.pinned_block();
        built.details.block_hash = self.block_hash.clone();
        built.details.incomplete = incomplete;

        // Storage-slot proxy fallback (EIP-1967/1822/zeppelinos) when no
        // implementation yet.
        if built.details.implementation.is_none() {
            if let Ok(Some(p)) = self.rpc.resolve_storage_proxy(addr).await {
                built.details.is_proxy = true;
                built.details.implementation = Some(format!("{:#x}", p.target));
                built.details.proxy_kind = Some(p.kind.to_string());
            }
        }
        // A diamond keeps no implementation slot, so it has to be asked — an
        // extra eth_call per contract. Only worth asking one that delegates at
        // all: every diamond does, most contracts do not, and the opcode scan
        // that answers it has already run.
        if built.details.implementation.is_none() && delegates(&built.details) {
            if let Some(p) = self.rpc.resolve_diamond(addr).await {
                built.details.is_proxy = true;
                built.details.implementation = Some(format!("{:#x}", p.target));
                built.details.proxy_kind = Some(p.kind.to_string());
            }
        }

        // Sourcify fallback when Etherscan has no verified source.
        if !built.details.is_verified && self.cfg.sourcify {
            let files = self.sourcify.fetch_sources(address_str).await;
            if !files.is_empty() {
                built.details.is_verified = true;
                built.details.verified_via = Some("sourcify".to_string());
                built.details.source_file_count = files.len();
                built.sources = files;
            }
        }

        // Security audit (after source/proxy/sourcify are settled, before filtering).
        if self.cfg.audit {
            built.details.audit = Some(crate::audit::audit_with(
                &built.details,
                &built.sources,
                &self.cfg.suppressions,
            ));
        }

        if !passes_filters(&self.cfg, &built.details) {
            return Ok(SaveOutcome::Filtered);
        }

        storage::save_contract(
            &self.cfg.out_dir,
            &built.details,
            &built.sources,
            built.abi.as_deref(),
        )?;

        Ok(SaveOutcome::Saved(Box::new(built.details)))
    }
}

/// Whether a contract passes the active `--only-*` / `--min-balance` filters.
pub fn passes_filters(cfg: &Config, d: &ContractDetails) -> bool {
    if cfg.only_verified && !d.is_verified {
        return false;
    }
    if cfg.only_proxy && !d.is_proxy {
        return false;
    }
    if cfg.min_balance_wei > 0 {
        // Fail *closed* for a filter: an unparseable balance must not satisfy a
        // positive threshold (treat as zero), so junk can't slip past --min-balance.
        let bal = d.balance_wei.parse::<U256>().unwrap_or(U256::ZERO);
        if bal < U256::from(cfg.min_balance_wei) {
            return false;
        }
    }
    // Audit filters (only meaningful when the audit ran).
    if let Some(a) = &d.audit {
        if cfg.min_risk > 0 && a.risk_score < cfg.min_risk {
            return false;
        }
        if cfg.only_vulnerable
            && !a.findings.iter().any(|f| {
                f.severity.eq_ignore_ascii_case("high") || f.severity.eq_ignore_ascii_case("critical")
            })
        {
            return false;
        }
    }
    true
}

/// Assemble a [`BuiltContract`] from raw RPC + Etherscan data. Pure / side-effect free.
pub fn build_details(
    address: &str,
    chain_id: u64,
    code: &Bytes,
    balance: U256,
    src: SourceCodeResult,
    creation: Option<CreationResult>,
) -> BuiltContract {
    let is_verified = !src.source_code.trim().is_empty();
    let sources = storage::parse_sources(&src.source_code, &src.contract_name);
    let abi_available =
        is_verified && !src.abi.trim().is_empty() && !src.abi.contains("not verified");
    let abi = if abi_available {
        Some(src.abi.clone())
    } else {
        None
    };

    let bytecode = code.to_string();
    // Proxy info from Etherscan; fall back to on-chain EIP-1167 detection when
    // Etherscan didn't flag it (common for unverified minimal-proxy clones).
    // Storage-slot proxies (EIP-1967/1822) are resolved later in fetch_and_save.
    let mut is_proxy = src.proxy == "1";
    let mut implementation = non_empty(src.implementation).filter(|s| s != ZERO_ADDRESS);
    let mut proxy_kind = if is_proxy { Some("etherscan".to_string()) } else { None };
    if implementation.is_none() {
        if let Some(impl_addr) = detect_minimal_proxy(&bytecode) {
            is_proxy = true;
            implementation = Some(impl_addr);
            proxy_kind = Some("EIP-1167".to_string());
        }
    }

    let details = ContractDetails {
        address: address.to_string(),
        chain_id,
        // Pure over its inputs: the scan stamps the pin, not this function.
        block_number: None,
        block_hash: None,
        incomplete: Vec::new(),
        bytecode_size: code.len(),
        bytecode,
        balance_wei: balance.to_string(),
        is_verified,
        contract_name: non_empty(src.contract_name),
        compiler_version: non_empty(src.compiler_version),
        optimization_used: non_empty(src.optimization_used),
        optimization_runs: non_empty(src.runs),
        evm_version: non_empty(src.evm_version),
        license_type: non_empty(src.license_type),
        constructor_arguments: non_empty(src.constructor_arguments),
        is_proxy,
        implementation,
        proxy_kind,
        verified_via: if is_verified {
            Some("etherscan".to_string())
        } else {
            None
        },
        creator: creation.as_ref().map(|c| c.contract_creator.clone()),
        creation_tx_hash: creation.as_ref().map(|c| c.tx_hash.clone()),
        has_abi: abi_available,
        source_file_count: sources.len(),
        analysis: crate::analysis::analyze(code.as_ref()),
        audit: None, // set later in fetch_and_save (after source/proxy/sourcify settle)
    };

    BuiltContract {
        details,
        sources,
        abi,
    }
}

/// Fold per-address outcomes into aggregate counters.
pub fn fold_outcomes(results: Vec<SaveOutcome>) -> RunStats {
    let mut stats = RunStats::default();
    for r in results {
        match r {
            SaveOutcome::Saved(details) => {
                stats.saved += 1;
                if details.is_verified {
                    stats.verified += 1;
                }
                if !details.incomplete.is_empty() {
                    stats.degraded += 1;
                }
            }
            SaveOutcome::Skipped(_) => stats.skipped += 1,
            SaveOutcome::NotAContract => stats.not_contract += 1,
            SaveOutcome::Filtered => stats.filtered += 1,
            SaveOutcome::Failed(msg) => {
                stats.failed += 1;
                tracing::warn!("failed: {msg}");
            }
        }
    }
    stats
}

/// Whether the runtime bytecode contains a reachable `DELEGATECALL`, read off
/// the opcode scan `build_details` already ran. The gate on the diamond probe:
/// a contract that never delegates cannot be a proxy of any kind.
fn delegates(d: &ContractDetails) -> bool {
    d.analysis.opcodes.iter().any(|o| o == "DELEGATECALL")
}

/// Detect an EIP-1167 minimal proxy from runtime bytecode and return the
/// implementation address (`0x`-prefixed, lowercase) it delegates to.
///
/// Canonical clone layout (45 bytes):
/// `363d3d373d3d3d363d73` + `<20-byte impl>` + `5af43d82803e903d91602b57fd5bf3`.
pub fn detect_minimal_proxy(bytecode_hex: &str) -> Option<String> {
    const PREFIX: &str = "363d3d373d3d3d363d73";
    const SUFFIX: &str = "5af43d82803e903d91602b57fd5bf3";
    const ADDR_LEN: usize = 40;

    let hex = bytecode_hex
        .strip_prefix("0x")
        .unwrap_or(bytecode_hex)
        .to_ascii_lowercase();
    if hex.len() != PREFIX.len() + ADDR_LEN + SUFFIX.len()
        || !hex.starts_with(PREFIX)
        || !hex.ends_with(SUFFIX)
    {
        return None;
    }
    let addr = &hex[PREFIX.len()..PREFIX.len() + ADDR_LEN];
    if addr.chars().all(|c| c == '0') {
        return None; // zero implementation isn't a real proxy
    }
    Some(format!("0x{addr}"))
}

fn non_empty(s: String) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(source: &str, abi: &str) -> SourceCodeResult {
        SourceCodeResult {
            source_code: source.into(),
            abi: abi.into(),
            contract_name: "MyToken".into(),
            compiler_version: "v0.8.0".into(),
            optimization_used: "1".into(),
            runs: "200".into(),
            evm_version: "london".into(),
            constructor_arguments: "".into(),
            license_type: "MIT".into(),
            proxy: "0".into(),
            implementation: "".into(),
        }
    }

    fn code() -> Bytes {
        Bytes::from(vec![0x60u8, 0x01])
    }

    #[test]
    fn build_details_verified_with_abi() {
        let s = src("contract C {}", r#"[{"type":"function"}]"#);
        let creation = Some(CreationResult {
            contract_creator: "0xcreator".into(),
            tx_hash: "0xhash".into(),
        });
        let b = build_details("0xabc", 1, &code(), U256::from(42u64), s, creation);
        assert!(b.details.is_verified);
        assert!(b.details.has_abi);
        assert!(b.abi.is_some());
        assert_eq!(b.details.balance_wei, "42");
        assert_eq!(b.details.bytecode_size, 2);
        assert_eq!(b.details.contract_name.as_deref(), Some("MyToken"));
        assert_eq!(b.details.creator.as_deref(), Some("0xcreator"));
        assert_eq!(b.details.source_file_count, 1);
        assert!(b.details.bytecode.starts_with("0x"));
    }

    #[test]
    fn build_details_unverified() {
        let s = src("", "Contract source code not verified");
        let b = build_details("0xabc", 1, &code(), U256::ZERO, s, None);
        assert!(!b.details.is_verified);
        assert!(!b.details.has_abi);
        assert!(b.abi.is_none());
        assert_eq!(b.details.source_file_count, 0);
        assert!(b.details.creator.is_none());
    }

    #[test]
    fn build_details_abi_marked_not_verified_is_dropped() {
        // Source present (verified) but ABI string says not verified.
        let s = src("contract C {}", "Contract source code not verified");
        let b = build_details("0xabc", 1, &code(), U256::ZERO, s, None);
        assert!(b.details.is_verified);
        assert!(!b.details.has_abi);
        assert!(b.abi.is_none());
    }

    #[test]
    fn build_details_proxy_and_zero_impl_filtered() {
        let mut s = src("contract C {}", "[]");
        s.proxy = "1".into();
        s.implementation = ZERO_ADDRESS.into();
        let b = build_details("0xabc", 1, &code(), U256::ZERO, s, None);
        assert!(b.details.is_proxy);
        assert!(b.details.implementation.is_none());
    }

    #[test]
    fn build_details_real_implementation_kept() {
        let mut s = src("contract C {}", "[]");
        s.proxy = "1".into();
        s.implementation = "0x000000000000000000000000000000000000dead".into();
        let b = build_details("0xabc", 1, &code(), U256::ZERO, s, None);
        assert_eq!(
            b.details.implementation.as_deref(),
            Some("0x000000000000000000000000000000000000dead")
        );
    }

    #[test]
    fn build_details_blank_optionals_become_none() {
        let mut s = src("contract C {}", "[]");
        s.contract_name = "".into();
        s.compiler_version = "  ".into();
        s.evm_version = "".into();
        s.license_type = "".into();
        let b = build_details("0xabc", 1, &code(), U256::ZERO, s, None);
        assert!(b.details.contract_name.is_none());
        assert!(b.details.compiler_version.is_none());
        assert!(b.details.evm_version.is_none());
        assert!(b.details.license_type.is_none());
    }

    #[test]
    fn fold_outcomes_counts_every_variant() {
        let verified = build_details("0xa", 1, &code(), U256::ZERO, src("contract C {}", "[]"), None);
        let unverified = build_details("0xb", 1, &code(), U256::ZERO, src("", ""), None);
        let results = vec![
            SaveOutcome::Saved(Box::new(verified.details)),
            SaveOutcome::Saved(Box::new(unverified.details)),
            SaveOutcome::Skipped(None),
            SaveOutcome::NotAContract,
            SaveOutcome::Failed("boom".into()),
        ];
        let s = fold_outcomes(results);
        assert_eq!(s.saved, 2);
        assert_eq!(s.verified, 1);
        assert_eq!(s.skipped, 1);
        assert_eq!(s.not_contract, 1);
        assert_eq!(s.failed, 1);
    }

    #[test]
    fn build_details_detects_eip1167_minimal_proxy() {
        // 45-byte EIP-1167 clone pointing at 0x000...dead.
        let impl_hex = "000000000000000000000000000000000000dead";
        let clone = format!("0x363d3d373d3d3d363d73{impl_hex}5af43d82803e903d91602b57fd5bf3");
        let bytes: Bytes = clone.parse().unwrap();
        // Unverified, so Etherscan gives no proxy info.
        let s = src("", "");
        let b = build_details("0xclone", 1, &bytes, U256::ZERO, s, None);
        assert!(b.details.is_proxy);
        assert_eq!(b.details.implementation.as_deref(), Some(&*format!("0x{impl_hex}")));
    }

    #[test]
    fn detect_minimal_proxy_cases() {
        let ok = "0x363d3d373d3d3d363d73000000000000000000000000000000000000dead5af43d82803e903d91602b57fd5bf3";
        assert_eq!(
            detect_minimal_proxy(ok).as_deref(),
            Some("0x000000000000000000000000000000000000dead")
        );
        // Not a proxy: ordinary bytecode.
        assert!(detect_minimal_proxy("0x6080604052").is_none());
        // Right length but zero implementation -> rejected.
        let zero = "0x363d3d373d3d3d363d7300000000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3";
        assert!(detect_minimal_proxy(zero).is_none());
    }

    fn test_config() -> Config {
        Config {
            rpc_url: "x".into(),
            etherscan_key: "k".into(),
            etherscan_base: "x".into(),
            blockscout_base: String::new(),
            blockscout_rate: 4,
            chain_id: 1,
            pin_block: None,
            out_dir: std::path::PathBuf::from("out"),
            concurrency: 1,
            rate: 5,
            retries: 1,
            overwrite: false,
            trace: false,
            table: false,
            sourcify: false,
            sourcify_base: String::new(),
            only_verified: false,
            min_balance_wei: 0,
            only_proxy: false,
            manifest: None,
            format: Default::default(),
            audit: false,
            min_risk: 0,
            only_vulnerable: false,
            suppressions: Default::default(),
        }
    }

    fn details_of(source: &str, balance: u64, proxy: bool) -> ContractDetails {
        let mut s = src(source, "[]");
        if proxy {
            s.proxy = "1".into();
            s.implementation = "0x000000000000000000000000000000000000dead".into();
        }
        build_details("0xa", 1, &code(), U256::from(balance), s, None).details
    }

    #[test]
    fn build_details_sets_verified_via_and_proxy_kind() {
        assert_eq!(
            details_of("contract C {}", 0, false).verified_via.as_deref(),
            Some("etherscan")
        );
        assert!(details_of("", 0, false).verified_via.is_none());
        assert_eq!(
            details_of("contract C {}", 0, true).proxy_kind.as_deref(),
            Some("etherscan")
        );
    }

    #[test]
    fn passes_filters_only_verified() {
        let mut c = test_config();
        c.only_verified = true;
        assert!(passes_filters(&c, &details_of("contract C {}", 0, false)));
        assert!(!passes_filters(&c, &details_of("", 0, false)));
    }

    #[test]
    fn passes_filters_only_proxy() {
        let mut c = test_config();
        c.only_proxy = true;
        assert!(passes_filters(&c, &details_of("contract C {}", 0, true)));
        assert!(!passes_filters(&c, &details_of("contract C {}", 0, false)));
    }

    #[test]
    fn passes_filters_min_balance() {
        let mut c = test_config();
        c.min_balance_wei = 100;
        assert!(passes_filters(&c, &details_of("contract C {}", 100, false)));
        assert!(!passes_filters(&c, &details_of("contract C {}", 99, false)));
    }

    #[test]
    fn passes_filters_default_keeps_everything() {
        assert!(passes_filters(&test_config(), &details_of("", 0, false)));
    }

    #[test]
    fn passes_filters_audit_min_risk_and_only_vulnerable() {
        use crate::model::{Audit, SecurityFinding};
        fn finding(sev: &str) -> SecurityFinding {
            SecurityFinding {
                rule_id: "X".into(), title: "t".into(), category: "SC01:Access Control".into(),
                swc: None, scwe: None, ethtrust: None, severity: sev.into(), confidence: "Medium".into(),
                impact_score: 5, likelihood_score: 5, exploitability: "Moderate".into(),
                asset_at_risk: "x".into(), blast_radius: "single-contract".into(), risk: 30,
                priority: "P1".into(), detection: "source".into(), affected_contract: "0xa".into(),
                locations: vec![], evidence: "e".into(), exploit_scenario: "s".into(),
                recommendation: "r".into(), references: vec![], false_positive_notes: "".into(),
            }
        }
        let audit_with = |score: u8, sev: &str| Audit {
            risk_score: score, grade: "C".into(), risk_level: "Medium".into(),
            findings: vec![finding(sev)], summary: Default::default(),
        };
        let mut d = details_of("contract C {}", 0, false);
        d.audit = Some(audit_with(30, "High"));

        let mut c = test_config();
        c.min_risk = 50;
        assert!(!passes_filters(&c, &d)); // 30 < 50 -> filtered
        c.min_risk = 20;
        assert!(passes_filters(&c, &d)); // 30 >= 20 -> kept
        c.min_risk = 0;
        c.only_vulnerable = true;
        assert!(passes_filters(&c, &d)); // has a High finding -> kept

        // Only low findings -> only_vulnerable filters it out.
        d.audit = Some(audit_with(4, "Low"));
        assert!(!passes_filters(&c, &d));
    }

    #[tokio::test]
    async fn process_addresses_empty_is_default() {
        let cfg = Arc::new(Config {
            rpc_url: "http://localhost:1".into(),
            etherscan_key: "k".into(),
            etherscan_base: "http://localhost:1".into(),
            blockscout_base: String::new(),
            blockscout_rate: 4,
            chain_id: 1,
            pin_block: None,
            out_dir: std::path::PathBuf::from("out"),
            concurrency: 2,
            rate: 5,
            retries: 2,
            overwrite: false,
            trace: false,
            table: false,
            sourcify: true,
            sourcify_base: "https://sourcify.dev/server".into(),
            only_verified: false,
            min_balance_wei: 0,
            only_proxy: false,
            manifest: None,
            format: Default::default(),
            audit: false,
            min_risk: 0,
            only_vulnerable: false,
            suppressions: Default::default(),
        });
        let rpc = RpcClient::new("http://localhost:1", 2).unwrap();
        let es = EtherscanClient::new("http://localhost:1", "k", 1, 5, 2).unwrap();
        let scanner = Scanner::new(cfg, rpc, es, Blockscout::new("", 4), Sourcify::new("", 1));
        let (stats, details) = scanner.process_addresses(vec![]).await;
        assert_eq!(stats.saved, 0);
        assert_eq!(stats.failed, 0);
        assert!(details.is_empty());
        // scan_and_audit on a dead endpoint -> fetch fails -> None (no panic).
        let addr: Address = "0x000000000000000000000000000000000000dead".parse().unwrap();
        assert!(scanner.scan_and_audit(addr).await.is_none());
    }
}
