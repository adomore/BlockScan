//! SARIF 2.1.0 export of audit findings, for GitHub Code Scanning / CI / IDEs.
//! Pure: turns `ContractDetails.audit` findings into a SARIF log. No I/O.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::model::{ContractDetails, SecurityFinding};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_URI: &str = "https://owasp.org/www-project-smart-contract-top-10/";

/// Build a SARIF 2.1.0 log from every contract's audit findings.
pub fn build_sarif(contracts: &[ContractDetails]) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_idx: BTreeMap<String, usize> = BTreeMap::new();
    let mut results: Vec<Value> = Vec::new();

    for c in contracts {
        let Some(audit) = &c.audit else { continue };
        // Native findings only. This run declares `tool.driver.name: blockscan`,
        // so putting an imported finding in it would be blockscan claiming
        // another analyser's result as its own — and a consumer deduplicating
        // against that analyser's own SARIF would then see it twice.
        for f in audit.findings.iter().filter(|f| f.source == crate::model::NATIVE_SOURCE) {
            if !rule_idx.contains_key(&f.rule_id) {
                rule_idx.insert(f.rule_id.clone(), rules.len());
                rules.push(rule_object(f));
            }
            results.push(result_object(f));
        }
    }

    json!({
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": { "driver": {
                "name": "blockscan",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": TOOL_URI,
                "rules": rules,
            }},
            "results": results,
        }]
    })
}

/// SARIF `reportingDescriptor` (rule metadata) for a finding's rule.
fn rule_object(f: &SecurityFinding) -> Value {
    let mut tags = vec![f.category.clone(), format!("confidence:{}", f.confidence)];
    if let Some(swc) = &f.swc {
        tags.push(swc.clone());
    }
    if let Some(scwe) = &f.scwe {
        tags.push(scwe.clone());
    }
    if let Some(req) = &f.ethtrust {
        tags.push(format!("EthTrust:{req}"));
    }
    json!({
        "id": f.rule_id,
        "name": f.rule_id,
        "shortDescription": { "text": f.title },
        "fullDescription": { "text": f.exploit_scenario },
        "helpUri": f.references.first().cloned().unwrap_or_else(|| TOOL_URI.to_string()),
        "help": { "text": f.recommendation },
        "defaultConfiguration": { "level": level(&f.severity) },
        "properties": {
            "security-severity": security_severity(f.risk),
            "precision": precision(&f.confidence),
            "tags": tags,
        }
    })
}

/// SARIF `result` for a single finding.
fn result_object(f: &SecurityFinding) -> Value {
    let locations: Vec<Value> = if f.locations.is_empty() {
        // No source location (bytecode-level finding): use a logical location.
        vec![json!({
            "logicalLocations": [{ "fullyQualifiedName": f.affected_contract, "kind": "contract" }]
        })]
    } else {
        f.locations.iter().map(|loc| physical_location(loc)).collect()
    };
    json!({
        "ruleId": f.rule_id,
        "level": level(&f.severity),
        "message": { "text": format!("{} — {}", f.title, f.evidence) },
        "locations": locations,
        "partialFingerprints": { "blockscan/v1": fingerprint(f) },
        "properties": {
            "risk": f.risk,
            "priority": f.priority,
            "severity": f.severity,
            "confidence": f.confidence,
            "swc": f.swc,
            "scwe": f.scwe,
            "ethtrust": f.ethtrust,
            "category": f.category,
            "contract": f.affected_contract,
            "detection": f.detection,
        }
    })
}

/// A stable result fingerprint for baseline/dedup across runs (GitHub Code
/// Scanning groups results by `partialFingerprints`). Built from rule id, contract,
/// source file (NOT line — so it survives line shifts), and the matched evidence
/// (the evidence distinguishes multiple instances of one rule in the same file).
pub fn fingerprint(f: &SecurityFinding) -> String {
    let file = f
        .locations
        .first()
        .map(|l| l.rsplit_once(':').map(|(p, _)| p).unwrap_or(l.as_str()))
        .unwrap_or("bytecode");
    let key = format!("{}|{}|{}|{}", f.rule_id, f.affected_contract, file, f.evidence);
    let hash = alloy::primitives::keccak256(key.as_bytes());
    format!("{hash:x}")[..16].to_string() // first 8 bytes of the keccak, lowercase hex
}

/// Parse a `file:line` location into a SARIF physical location.
fn physical_location(loc: &str) -> Value {
    match loc.rsplit_once(':').and_then(|(file, ln)| ln.parse::<u32>().ok().map(|n| (file, n))) {
        Some((file, line)) => json!({
            "physicalLocation": {
                "artifactLocation": { "uri": file },
                "region": { "startLine": line }
            }
        }),
        None => json!({
            "physicalLocation": { "artifactLocation": { "uri": loc } }
        }),
    }
}

/// SARIF result level from a finding severity.
fn level(severity: &str) -> &'static str {
    if severity.eq_ignore_ascii_case("critical") || severity.eq_ignore_ascii_case("high") {
        "error"
    } else if severity.eq_ignore_ascii_case("medium") {
        "warning"
    } else {
        "note"
    }
}

/// GitHub `security-severity` is a 0.0–10.0 string; map our 0–100 risk.
fn security_severity(risk: u8) -> String {
    format!("{:.1}", risk as f64 / 10.0)
}

/// SARIF `precision` from detector confidence.
fn precision(confidence: &str) -> &'static str {
    match confidence {
        "High" => "high",
        "Medium" => "medium",
        _ => "low",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Audit, SecurityFinding};

    fn finding(rule: &str, sev: &str, risk: u8, locs: Vec<String>) -> SecurityFinding {
        SecurityFinding {
            source: crate::model::NATIVE_SOURCE.into(),
            rule_id: rule.into(),
            title: "Title".into(),
            category: "SC01:Access Control".into(),
            swc: Some("SWC-115".into()),
            scwe: Some("SCWE-018".into()),
            ethtrust: Some("req-1-no-tx.origin [S]".into()),
            severity: sev.into(),
            confidence: "High".into(),
            impact_score: 7,
            likelihood_score: 5,
            exploitability: "Easy".into(),
            asset_at_risk: "funds".into(),
            blast_radius: "user-funds".into(),
            risk,
            priority: "P1".into(),
            detection: if locs.is_empty() { "bytecode".into() } else { "source".into() },
            affected_contract: "0xabc".into(),
            locations: locs,
            evidence: "ev".into(),
            exploit_scenario: "scenario".into(),
            recommendation: "fix it".into(),
            references: vec!["https://swcregistry.io/docs/SWC-115".into()],
            false_positive_notes: "".into(),
        }
    }

    fn contract_with(findings: Vec<SecurityFinding>) -> ContractDetails {
        let mut d = ContractDetails::minimal("0xabc", 1);
        d.audit = Some(Audit {
            risk_score: 50,
            grade: "D".into(),
            risk_level: "High".into(),
            findings,
            summary: Default::default(),
        });
        d
    }

    #[test]
    fn builds_valid_top_level_structure() {
        let c = contract_with(vec![finding("TX_ORIGIN_AUTH", "High", 26, vec!["C.sol:3".into()])]);
        let s = build_sarif(&[c]);
        assert_eq!(s["version"], "2.1.0");
        assert!(s["$schema"].as_str().unwrap().contains("sarif"));
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "blockscan");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        let rule = &s["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "TX_ORIGIN_AUTH");
        assert!(rule["helpUri"].as_str().unwrap().contains("SWC-115"));
        assert_eq!(rule["properties"]["security-severity"], "2.6");
        let tags = rule["properties"]["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t == "SWC-115"));
        assert!(tags.iter().any(|t| t == "SC01:Access Control"));
        // SCWE + EthTrust refs surface as tags + result properties.
        assert!(tags.iter().any(|t| t == "SCWE-018"));
        assert!(tags.iter().any(|t| t.as_str().is_some_and(|s| s.starts_with("EthTrust:"))));
        assert_eq!(s["runs"][0]["results"][0]["properties"]["scwe"], "SCWE-018");
    }

    #[test]
    fn result_levels_and_locations() {
        let c = contract_with(vec![
            finding("R_HIGH", "High", 30, vec!["A.sol:10".into()]),
            finding("R_MED", "Medium", 10, vec![]), // bytecode -> logical location
            finding("R_LOW", "Low", 4, vec!["B.sol:7".into()]),
        ]);
        let s = build_sarif(&[c]);
        let res = s["runs"][0]["results"].as_array().unwrap();
        assert_eq!(res[0]["level"], "error");
        assert_eq!(res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "A.sol");
        assert_eq!(res[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 10);
        assert_eq!(res[1]["level"], "warning");
        assert_eq!(res[1]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"], "0xabc");
        assert_eq!(res[2]["level"], "note");
    }

    #[test]
    fn rules_deduped_across_findings_and_contracts() {
        let c1 = contract_with(vec![
            finding("DUP", "High", 30, vec!["A.sol:1".into()]),
            finding("DUP", "High", 30, vec!["A.sol:2".into()]),
        ]);
        let c2 = contract_with(vec![finding("DUP", "High", 30, vec!["B.sol:1".into()])]);
        let s = build_sarif(&[c1, c2]);
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn partial_fingerprints_are_stable_and_distinguishing() {
        // Same rule+contract+file+evidence, different LINE -> same fingerprint
        // (survives line shifts, the point of partialFingerprints).
        let a = fingerprint(&finding("R", "High", 30, vec!["C.sol:10".into()]));
        let b = fingerprint(&finding("R", "High", 30, vec!["C.sol:42".into()]));
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        // Different file -> different fingerprint.
        let c = fingerprint(&finding("R", "High", 30, vec!["D.sol:10".into()]));
        assert_ne!(a, c);
        // Different evidence (distinct instance in same file) -> different fingerprint.
        let mut d = finding("R", "High", 30, vec!["C.sol:10".into()]);
        d.evidence = "other".into();
        assert_ne!(a, fingerprint(&d));
        // Bytecode finding (no locations) still yields a stable fingerprint.
        let bc = fingerprint(&finding("R", "High", 30, vec![]));
        assert_eq!(bc.len(), 16);
        // Surfaced on each SARIF result (same file -> same fingerprint as `a`).
        let s = build_sarif(&[contract_with(vec![finding("R", "High", 30, vec!["C.sol:1".into()])])]);
        assert_eq!(
            s["runs"][0]["results"][0]["partialFingerprints"]["blockscan/v1"].as_str().unwrap(),
            a.as_str()
        );
    }

    /// This run says it is blockscan. An imported finding in it would be
    /// blockscan claiming someone else's result, and would double-count against
    /// that tool's own SARIF in any consumer that merges the two.
    #[test]
    fn an_imported_finding_stays_out_of_blockscans_own_run() {
        let mut native = finding("TX_ORIGIN_AUTH", "High", 30, vec!["A.sol:1".into()]);
        native.source = crate::model::NATIVE_SOURCE.into();
        let mut foreign = finding("slither:reentrancy-eth", "High", 0, vec!["A.sol:2".into()]);
        foreign.source = "slither".into();
        let doc = build_sarif(&[contract_with(vec![native, foreign])]);
        let results = doc["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1, "only the native finding: {results:?}");
        assert_eq!(results[0]["ruleId"], "TX_ORIGIN_AUTH");
        let rules = doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn rule_helpuri_falls_back_when_no_references() {
        let mut f = finding("R", "Low", 4, vec![]);
        f.references = vec![];
        let s = build_sarif(&[contract_with(vec![f])]);
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"], TOOL_URI);
    }

    #[test]
    fn empty_corpus_is_valid_empty_run() {
        let s = build_sarif(&[]);
        assert_eq!(s["version"], "2.1.0");
        assert!(s["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().is_empty());
        // A contract without an audit contributes nothing.
        let s2 = build_sarif(&[ContractDetails::minimal("0x1", 1)]);
        assert!(s2["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn physical_location_without_line_falls_back_to_uri() {
        let v = physical_location("weird-no-line");
        assert_eq!(v["physicalLocation"]["artifactLocation"]["uri"], "weird-no-line");
        assert!(v["physicalLocation"]["region"].is_null());
    }

    #[test]
    fn level_and_precision_mappings() {
        assert_eq!(level("Critical"), "error");
        assert_eq!(level("high"), "error");
        assert_eq!(level("Medium"), "warning");
        assert_eq!(level("Low"), "note");
        assert_eq!(level("Info"), "note");
        assert_eq!(precision("High"), "high");
        assert_eq!(precision("Medium"), "medium");
        assert_eq!(precision("Low"), "low");
        assert_eq!(security_severity(100), "10.0");
        assert_eq!(security_severity(26), "2.6");
    }
}
