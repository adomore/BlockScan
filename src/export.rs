//! Summary manifest export (JSON or CSV) of all saved contracts.

use std::path::Path;

use crate::error::Result;
use crate::model::ContractDetails;

/// Write a manifest of `contracts` to `path`. Format is chosen by extension:
/// `.csv` → CSV, anything else → pretty JSON.
pub fn write_manifest(path: &Path, contracts: &[ContractDetails]) -> Result<()> {
    let is_csv = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("csv"))
        .unwrap_or(false);
    let body = if is_csv {
        render_csv(contracts)
    } else {
        render_json(contracts)?
    };
    std::fs::write(path, body)?;
    Ok(())
}

/// Pretty-printed JSON array of the contracts.
pub fn render_json(contracts: &[ContractDetails]) -> Result<String> {
    Ok(serde_json::to_string_pretty(contracts)?)
}

/// CSV with a fixed column set (one row per contract).
pub fn render_csv(contracts: &[ContractDetails]) -> String {
    let mut out = String::from(
        "address,chain_id,contract_name,is_verified,verified_via,compiler_version,\
is_proxy,proxy_kind,implementation,balance_wei,creator,creation_tx_hash,\
bytecode_size,has_abi,source_file_count,code_hash_nometa,interfaces,risk_opcodes,\
risk_score,risk_grade,risk_level,findings,top_severity,top_category,owasp\n",
    );
    for d in contracts {
        let cols = [
            d.address.clone(),
            d.chain_id.to_string(),
            d.contract_name.clone().unwrap_or_default(),
            d.is_verified.to_string(),
            d.verified_via.clone().unwrap_or_default(),
            d.compiler_version.clone().unwrap_or_default(),
            d.is_proxy.to_string(),
            d.proxy_kind.clone().unwrap_or_default(),
            d.implementation.clone().unwrap_or_default(),
            d.balance_wei.clone(),
            d.creator.clone().unwrap_or_default(),
            d.creation_tx_hash.clone().unwrap_or_default(),
            d.bytecode_size.to_string(),
            d.has_abi.to_string(),
            d.source_file_count.to_string(),
            d.analysis.code_hash_nometa.clone(),
            d.analysis.interfaces.join(";"),
            d.analysis.opcodes.join(";"),
            d.audit.as_ref().map(|a| a.risk_score.to_string()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.grade.clone()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.risk_level.clone()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.findings.len().to_string()).unwrap_or_default(),
            d.audit.as_ref().map(top_severity).unwrap_or_default(),
            d.audit.as_ref().map(top_category).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.summary.owasp_categories.join(";")).unwrap_or_default(),
        ];
        out.push_str(&cols.iter().map(|c| csv_escape(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// Highest-severity finding present, in descending order; empty when none.
fn top_severity(a: &crate::model::Audit) -> String {
    for sev in ["Critical", "High", "Medium", "Low", "Info"] {
        if a.findings.iter().any(|f| f.severity.eq_ignore_ascii_case(sev)) {
            return sev.to_string();
        }
    }
    String::new()
}

/// OWASP category of the highest-risk finding; empty when none.
fn top_category(a: &crate::model::Audit) -> String {
    a.findings
        .iter()
        .max_by_key(|f| f.risk)
        .map(|f| f.category.clone())
        .unwrap_or_default()
}

/// Escape a CSV field: neutralize spreadsheet formula injection (fields whose
/// first char is `= + - @` / tab / CR get a leading `'`), then quote when the
/// field contains a comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(addr: &str, name: Option<&str>) -> ContractDetails {
        ContractDetails {
            address: addr.into(),
            chain_id: 1,
            block_number: None,
            block_hash: None,
            incomplete: Vec::new(),
            bytecode: "0x60".into(),
            bytecode_size: 2,
            balance_wei: "100".into(),
            is_verified: name.is_some(),
            contract_name: name.map(|s| s.into()),
            compiler_version: Some("v0.8.0".into()),
            optimization_used: None,
            optimization_runs: None,
            evm_version: None,
            license_type: None,
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: name.map(|_| "etherscan".into()),
            creator: None,
            creation_tx_hash: None,
            has_abi: name.is_some(),
            source_file_count: if name.is_some() { 1 } else { 0 },
            analysis: Default::default(),
            // Verified row carries an audit; unverified row has none (covers both CSV branches).
            audit: name.map(|_| crate::model::Audit {
                risk_score: 30,
                grade: "C".into(),
                risk_level: "Medium".into(),
                findings: vec![crate::model::SecurityFinding {
                    rule_id: "TX_ORIGIN_AUTH".into(),
                    title: "t".into(),
                    category: "SC01:Access Control".into(),
                    swc: Some("SWC-115".into()),
                    scwe: None,
                    ethtrust: None,
                    severity: "High".into(),
                    confidence: "Medium".into(),
                    impact_score: 7,
                    likelihood_score: 5,
                    exploitability: "Moderate".into(),
                    asset_at_risk: "x".into(),
                    blast_radius: "user-funds".into(),
                    risk: 26,
                    priority: "P1".into(),
                    detection: "source".into(),
                    affected_contract: "0xa".into(),
                    locations: vec![],
                    evidence: "e".into(),
                    exploit_scenario: "s".into(),
                    recommendation: "r".into(),
                    references: vec![],
                    false_positive_notes: "".into(),
                }],
                summary: crate::model::AuditSummary {
                    owasp_categories: vec!["SC01:Access Control".into()],
                    ..Default::default()
                },
            }),
        }
    }

    #[test]
    fn json_round_trips() {
        let json = render_json(&[d("0xa", Some("Foo"))]).unwrap();
        let back: Vec<ContractDetails> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].contract_name.as_deref(), Some("Foo"));
    }

    #[test]
    fn top_helpers_handle_empty_audit() {
        let empty = crate::model::Audit::default();
        assert_eq!(top_severity(&empty), "");
        assert_eq!(top_category(&empty), "");
    }

    #[test]
    fn csv_has_header_and_rows() {
        let csv = render_csv(&[d("0xa", Some("Foo")), d("0xb", None)]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("address,chain_id,"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].contains("0xa") && lines[1].contains("Foo"));
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("he\"llo"), "\"he\"\"llo\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn csv_neutralizes_formula_injection() {
        // Leading formula triggers get a `'` prefix so spreadsheets treat them as text.
        assert_eq!(csv_escape("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_escape("+1"), "'+1");
        assert_eq!(csv_escape("-1"), "'-1");
        assert_eq!(csv_escape("@cmd"), "'@cmd");
        // A normal name is untouched.
        assert_eq!(csv_escape("PoolManager"), "PoolManager");
    }

    #[test]
    fn write_manifest_picks_format_by_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("index.json");
        let csv_path = tmp.path().join("index.csv");
        write_manifest(&json_path, &[d("0xa", Some("Foo"))]).unwrap();
        write_manifest(&csv_path, &[d("0xa", Some("Foo"))]).unwrap();
        assert!(std::fs::read_to_string(&json_path).unwrap().contains("\"address\""));
        assert!(std::fs::read_to_string(&csv_path).unwrap().starts_with("address,"));
    }
}
