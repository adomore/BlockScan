use serde::{Deserialize, Serialize};

/// A single source file recovered from a verified contract.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Relative path inside the `source/` directory (preserves project layout).
    pub path: String,
    pub content: String,
}

/// Static analysis derived from runtime bytecode (no network). See `analysis.rs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Analysis {
    /// keccak256 of the full runtime bytecode (`0x`-prefixed).
    pub code_hash: String,
    /// keccak256 of the runtime bytecode with trailing CBOR metadata stripped,
    /// so clones that differ only in metadata share a hash (`0x`-prefixed).
    pub code_hash_nometa: String,
    /// Notable/dangerous opcodes present, e.g. `SELFDESTRUCT` / `DELEGATECALL` / `CREATE2`.
    pub opcodes: Vec<String>,
    /// Detected ERC interfaces, e.g. `ERC-20` / `ERC-721` / `ERC-1155` / `ERC-165`.
    pub interfaces: Vec<String>,
}

/// A standardized security finding (SecurityFinding v2). Three-layer taxonomy:
/// `category` (OWASP SC Top 10) → `swc` (SWC registry, SCWE's predecessor) →
/// `rule_id` (internal). Carries grading, damage assessment and remediation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFinding {
    /// L3 internal rule id, e.g. `TX_ORIGIN_AUTH`.
    pub rule_id: String,
    pub title: String,
    /// L1 OWASP Smart Contract Top 10 class, e.g. `SC01:Access Control`.
    pub category: String,
    /// L2 SWC registry id, e.g. `SWC-115` (None when no registry mapping).
    pub swc: Option<String>,
    /// OWASP SCWE id, e.g. `SCWE-018` (None when no high-confidence mapping).
    /// `#[serde(default)]` so pre-mapping `metadata.json` files still deserialize.
    #[serde(default)]
    pub scwe: Option<String>,
    /// EEA EthTrust Security Levels requirement ref, e.g. `req-1-no-tx.origin [S]`
    /// (None when no high-confidence mapping). `#[serde(default)]` for back-compat.
    #[serde(default)]
    pub ethtrust: Option<String>,
    /// `Critical` / `High` / `Medium` / `Low` / `Info`.
    pub severity: String,
    /// Detector confidence: `High` / `Medium` / `Low`.
    pub confidence: String,
    /// Damage potential 0–10.
    pub impact_score: u8,
    /// Exploit probability 0–10.
    pub likelihood_score: u8,
    /// `Easy` / `Moderate` / `Hard`.
    pub exploitability: String,
    /// What is at risk, e.g. `Funds (TVL)` / `Owner/Admin authority`.
    pub asset_at_risk: String,
    /// `single-contract` / `protocol` / `user-funds` / `governance` / `cross-chain`.
    pub blast_radius: String,
    /// Computed per-finding risk 0–100.
    pub risk: u8,
    /// Remediation priority `P0`..`P3`.
    pub priority: String,
    /// Where it was detected: `source` / `bytecode`.
    pub detection: String,
    pub affected_contract: String,
    /// `file:line` references (source findings); empty for bytecode findings.
    pub locations: Vec<String>,
    pub evidence: String,
    pub exploit_scenario: String,
    pub recommendation: String,
    pub references: Vec<String>,
    pub false_positive_notes: String,
}

/// Aggregate matrices over a contract's findings (for the report layer).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSummary {
    pub by_severity: std::collections::BTreeMap<String, usize>,
    pub by_category: std::collections::BTreeMap<String, usize>,
    pub by_confidence: std::collections::BTreeMap<String, usize>,
    pub by_priority: std::collections::BTreeMap<String, usize>,
    /// Distinct OWASP categories with at least one finding.
    pub owasp_categories: Vec<String>,
}

/// Standardized security audit of one contract (heuristic; not a formal proof).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Audit {
    /// Overall contract risk 0 (safest) .. 100 (riskiest).
    pub risk_score: u8,
    /// Letter grade: `A` (safest) .. `F` (riskiest).
    pub grade: String,
    /// `Minimal` / `Low` / `Medium` / `High` / `Critical` risk.
    pub risk_level: String,
    pub findings: Vec<SecurityFinding>,
    pub summary: AuditSummary,
}

/// Full set of details we collect and persist for one contract address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDetails {
    pub address: String,
    pub chain_id: u64,

    // ---- On-chain (RPC) ----
    /// Runtime bytecode, hex-encoded with `0x` prefix.
    pub bytecode: String,
    pub bytecode_size: usize,
    /// Balance in wei (decimal string to avoid precision loss).
    pub balance_wei: String,

    // ---- Etherscan metadata ----
    pub is_verified: bool,
    pub contract_name: Option<String>,
    pub compiler_version: Option<String>,
    pub optimization_used: Option<String>,
    pub optimization_runs: Option<String>,
    pub evm_version: Option<String>,
    pub license_type: Option<String>,
    pub constructor_arguments: Option<String>,
    pub is_proxy: bool,
    pub implementation: Option<String>,
    /// How the proxy was detected: `etherscan` / `EIP-1167` / `EIP-1967` /
    /// `EIP-1967-beacon` / `EIP-1822`. `None` when not a proxy.
    pub proxy_kind: Option<String>,
    /// Where the verified source came from: `etherscan` / `sourcify` / `None`.
    pub verified_via: Option<String>,

    // ---- Creation info ----
    pub creator: Option<String>,
    pub creation_tx_hash: Option<String>,

    /// Whether ABI was available (also written to abi.json when present).
    pub has_abi: bool,
    /// Number of verified source files written under `source/`.
    pub source_file_count: usize,

    /// Static analysis of the runtime bytecode. `#[serde(default)]` so older
    /// metadata.json files (written before this field existed) still load.
    #[serde(default)]
    pub analysis: Analysis,

    /// Heuristic security audit. `None` when auditing is disabled (`--no-audit`).
    #[serde(default)]
    pub audit: Option<Audit>,
}

impl ContractDetails {
    /// A bare details record with everything but `address`/`chain_id` defaulted —
    /// handy for tests and incremental construction.
    pub fn minimal(address: &str, chain_id: u64) -> Self {
        Self {
            address: address.to_string(),
            chain_id,
            bytecode: String::new(),
            bytecode_size: 0,
            balance_wei: "0".to_string(),
            is_verified: false,
            contract_name: None,
            compiler_version: None,
            optimization_used: None,
            optimization_runs: None,
            evm_version: None,
            license_type: None,
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: None,
            creator: None,
            creation_tx_hash: None,
            has_abi: false,
            source_file_count: 0,
            analysis: Analysis::default(),
            audit: None,
        }
    }
}

/// A decoded security-relevant event, emitted by `monitor` to the alert sinks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub block: u64,
    /// Chain the event was observed on (distinguishes alerts in `--chains` runs).
    pub chain_id: u64,
    /// Contract that emitted the event (the proxy / owned contract).
    pub contract: String,
    /// Event name, e.g. `Upgraded` / `OwnershipTransferred` / `AdminChanged`.
    pub event: String,
    /// Category: `proxy-upgrade` / `ownership` / `admin` / `unknown`.
    pub kind: String,
    /// The new value the event sets (new implementation / owner / admin), if decodable.
    pub new_value: Option<String>,
    /// The previous value, when the event carries one (owner/admin changes).
    pub previous: Option<String>,
    pub tx_hash: Option<String>,
    /// Per-block log index of the source event — part of the de-dup fingerprint so
    /// two same-signature logs in one tx stay distinct. `None` for risky-deployment
    /// alerts (one per address per block) and older records.
    #[serde(default)]
    pub log_index: Option<u64>,
    /// Transferred value (decimal uint256 string) for `large-transfer` alerts; `None` otherwise.
    #[serde(default)]
    pub amount: Option<String>,
    /// Audit risk score 0–100 (set for `risky-deployment` alerts; `None` for events).
    #[serde(default)]
    pub risk_score: Option<u8>,
    /// Audit grade A–F (set for `risky-deployment` alerts; `None` for events).
    #[serde(default)]
    pub grade: Option<String>,
}

/// Outcome of processing one address, for the run summary.
#[derive(Debug)]
pub enum SaveOutcome {
    /// Successfully saved; carries the details (used for `--table` output).
    Saved(Box<ContractDetails>),
    /// Already saved on disk (resume/dedup). Carries the details loaded back
    /// from `metadata.json` when `--table` is on (and the read succeeded).
    Skipped(Option<Box<ContractDetails>>),
    NotAContract,
    /// Excluded by a `--only-*` / `--min-balance` filter (not saved).
    Filtered,
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ContractDetails {
        ContractDetails {
            address: "0xabc".into(),
            chain_id: 1,
            bytecode: "0x6001".into(),
            bytecode_size: 2,
            balance_wei: "0".into(),
            is_verified: true,
            contract_name: Some("Foo".into()),
            compiler_version: Some("v0.8.0".into()),
            optimization_used: Some("1".into()),
            optimization_runs: Some("200".into()),
            evm_version: Some("london".into()),
            license_type: Some("MIT".into()),
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: Some("etherscan".into()),
            creator: Some("0xdead".into()),
            creation_tx_hash: Some("0xfeed".into()),
            has_abi: true,
            source_file_count: 1,
            analysis: Analysis {
                code_hash: "0xaa".into(),
                code_hash_nometa: "0xbb".into(),
                opcodes: vec!["DELEGATECALL".into()],
                interfaces: vec!["ERC-20".into()],
            },
            audit: None,
        }
    }

    #[test]
    fn contract_details_json_round_trip() {
        let d = sample();
        let json = serde_json::to_string(&d).unwrap();
        let back: ContractDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, d.address);
        assert_eq!(back.contract_name.as_deref(), Some("Foo"));
        assert!(back.is_verified);
        assert_eq!(back.source_file_count, 1);
    }

    #[test]
    fn security_finding_back_compat_without_scwe_ethtrust() {
        // A pre-mapping finding JSON (no scwe/ethtrust keys) must still deserialize,
        // defaulting the new fields to None (serde(default)).
        let json = r#"{
            "rule_id":"X","title":"t","category":"SC01:Access Control","swc":"SWC-115",
            "severity":"High","confidence":"Medium","impact_score":7,"likelihood_score":5,
            "exploitability":"Moderate","asset_at_risk":"x","blast_radius":"user-funds","risk":26,
            "priority":"P1","detection":"source","affected_contract":"0xabc","locations":[],
            "evidence":"e","exploit_scenario":"s","recommendation":"r","references":[],"false_positive_notes":""
        }"#;
        let f: SecurityFinding = serde_json::from_str(json).unwrap();
        assert_eq!(f.swc.as_deref(), Some("SWC-115"));
        assert!(f.scwe.is_none() && f.ethtrust.is_none());
    }

    #[test]
    fn source_file_is_cloneable() {
        let f = SourceFile {
            path: "a/b.sol".into(),
            content: "x".into(),
        };
        let g = f.clone();
        assert_eq!(g.path, "a/b.sol");
        assert_eq!(g.content, "x");
    }

    #[test]
    fn save_outcome_debug() {
        for o in [
            SaveOutcome::Saved(Box::new(sample())),
            SaveOutcome::Skipped(Some(Box::new(sample()))),
            SaveOutcome::Skipped(None),
            SaveOutcome::NotAContract,
            SaveOutcome::Filtered,
            SaveOutcome::Failed("x".into()),
        ] {
            assert!(!format!("{o:?}").is_empty());
        }
    }
}
