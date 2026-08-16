use std::path::PathBuf;

use crate::error::{AppError, Result};

/// Runtime configuration assembled from CLI args and environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: String,
    pub etherscan_key: String,
    pub etherscan_base: String,
    /// Blockscout v2 API base for `--table` enrichment. Empty disables it.
    pub blockscout_base: String,
    /// Max Blockscout requests per second.
    pub blockscout_rate: u32,
    pub chain_id: u64,
    pub out_dir: PathBuf,
    pub concurrency: usize,
    /// Max Etherscan requests per second.
    pub rate: u32,
    /// Attempts per RPC / Etherscan request before giving up (>= 1).
    pub retries: u32,
    pub overwrite: bool,
    /// Also discover factory-created (CREATE/CREATE2) contracts via `trace_block`.
    pub trace: bool,
    /// Print a normalized details table per saved contract.
    pub table: bool,

    // ---- Source fallback ----
    /// Fall back to Sourcify for source when Etherscan has no verified source.
    pub sourcify: bool,
    /// Sourcify server base, e.g. `https://sourcify.dev/server`.
    pub sourcify_base: String,

    // ---- Filters (applied before saving) ----
    /// Keep only contracts with verified source.
    pub only_verified: bool,
    /// Keep only contracts whose balance is at least this many wei.
    pub min_balance_wei: u128,
    /// Keep only proxy contracts.
    pub only_proxy: bool,

    // ---- Output ----
    /// Optional summary manifest path; `.json` or `.csv` by extension.
    pub manifest: Option<PathBuf>,
    /// Output format for stdout (`human` / `json` / `ndjson`).
    pub format: crate::cli::OutputFormat,

    // ---- Security audit ----
    /// Run the heuristic security audit on each scanned contract.
    pub audit: bool,
    /// Keep only contracts whose audit risk score is at least this (0 = no filter).
    pub min_risk: u8,
    /// Keep only contracts with at least one high/critical finding.
    pub only_vulnerable: bool,
    /// Findings to suppress (confirmed FPs / accepted baseline), applied in-audit.
    pub suppressions: crate::suppress::Suppressions,
}

impl Config {
    /// Validate required fields, producing actionable errors.
    pub fn validate(&self) -> Result<()> {
        if self.rpc_url.trim().is_empty() {
            return Err(AppError::Config(
                "missing RPC URL. Set ETH_RPC_URL or pass --rpc-url (see .env.example)".into(),
            ));
        }
        if self.etherscan_key.trim().is_empty() {
            return Err(AppError::Config(
                "missing Etherscan API key. Set ETHERSCAN_API_KEY or pass --etherscan-key (see .env.example)".into(),
            ));
        }
        if self.concurrency == 0 {
            return Err(AppError::Config("--concurrency must be >= 1".into()));
        }
        if self.rate == 0 {
            return Err(AppError::Config("--rate must be >= 1".into()));
        }
        if self.retries == 0 {
            return Err(AppError::Config("--retries must be >= 1".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config {
            rpc_url: "http://localhost:8545".into(),
            etherscan_key: "key".into(),
            etherscan_base: "http://localhost/v2/api".into(),
            blockscout_base: String::new(),
            blockscout_rate: 4,
            chain_id: 1,
            out_dir: PathBuf::from("out"),
            concurrency: 5,
            rate: 5,
            retries: 3,
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
            audit: true,
            min_risk: 0,
            only_vulnerable: false,
            suppressions: Default::default(),
        }
    }

    #[test]
    fn rejects_zero_retries() {
        let mut c = valid();
        c.retries = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_valid_config() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn rejects_empty_rpc_url() {
        let mut c = valid();
        c.rpc_url = "  ".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("RPC URL"), "{err}");
    }

    #[test]
    fn rejects_empty_etherscan_key() {
        let mut c = valid();
        c.etherscan_key = "".into();
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("Etherscan API key"), "{err}");
    }

    #[test]
    fn rejects_zero_concurrency() {
        let mut c = valid();
        c.concurrency = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_zero_rate() {
        let mut c = valid();
        c.rate = 0;
        assert!(c.validate().is_err());
    }
}
