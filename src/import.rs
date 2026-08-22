//! Import findings from an external analyser.
//!
//! Two things a team needs and could not get before: both result sets in one
//! place, and blockscan's own precision measured against another tool's on the
//! same input. Both need the foreign results to sit in the same shape as the
//! native ones, attributed to the same contracts.
//!
//! **This module reads files. It never runs anything.** No process is spawned,
//! no analyser is invoked, no path from an input file is ever executed — the
//! user runs their own tool, this reads what it wrote. A test asserts the
//! module's own source contains no process API, because that is the kind of
//! constraint that erodes by accident.
//!
//! ## Formats
//!
//! - **SARIF 2.1.0**, the interchange format blockscan itself emits and that
//!   Slither, Semgrep and others can produce.
//! - **Slither's native JSON**, because it carries impact *and* confidence,
//!   which SARIF flattens away.
//!
//! Detected by shape, not by filename.
//!
//! ## What is not invented
//!
//! A foreign finding fills the fields its tool actually reported. Everything
//! else is left empty rather than derived: blockscan does not know another
//! tool's blast radius, and a plausible-looking guess in a field that reads like
//! a measurement is worse than a blank. In particular `risk`, `impact_score` and
//! `likelihood_score` stay 0 — the scoring path filters imported findings out
//! entirely (see [`crate::model::NATIVE_SOURCE`]), so a number there would be
//! decorative at best and misleading at worst.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::error::{AppError, Result};
use crate::model::{ContractDetails, SecurityFinding};

/// One foreign finding, plus the path its analyser reported it at. The path is
/// what attribution runs on, so it is kept verbatim until then.
#[derive(Debug, Clone)]
pub struct ForeignFinding {
    pub path: String,
    pub finding: SecurityFinding,
}

/// The contents of one import file.
#[derive(Debug, Clone)]
pub struct Import {
    /// Tool name, taken from the file where it says so, else the format name.
    pub tool: String,
    pub findings: Vec<ForeignFinding>,
}

/// What a merge did, so the run can say it out loud rather than quietly
/// dropping what it could not place.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeStats {
    pub tool: String,
    pub total: usize,
    pub attributed: usize,
    /// Matched more than one contract's sources, so no contract was chosen.
    pub ambiguous: usize,
    /// Matched nothing in this corpus.
    pub unmatched: usize,
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

/// Parse an import file, detecting SARIF or Slither JSON by shape.
pub fn parse(text: &str) -> Result<Import> {
    let v: Value = serde_json::from_str(text)
        .map_err(|e| AppError::Config(format!("import: not JSON: {e}")))?;
    if v.get("runs").and_then(Value::as_array).is_some() {
        return Ok(parse_sarif(&v));
    }
    if v.pointer("/results/detectors").and_then(Value::as_array).is_some() {
        return Ok(parse_slither(&v));
    }
    Err(AppError::Config(
        "import: unrecognised file. Expected SARIF 2.1.0 (a top-level \"runs\" array) or \
         Slither JSON (\"results.detectors\")."
            .into(),
    ))
}

/// Read an import file from disk.
pub fn load(path: &Path) -> Result<Import> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| AppError::Config(format!("import: cannot read {}: {e}", path.display())))?;
    parse(&text)
}

/// A finding with every field blank, ready for a tool to fill in what it knows.
fn blank(source: &str) -> SecurityFinding {
    SecurityFinding {
        source: source.to_string(),
        rule_id: String::new(),
        title: String::new(),
        category: String::new(),
        swc: None,
        scwe: None,
        ethtrust: None,
        severity: String::new(),
        confidence: String::new(),
        impact_score: 0,
        likelihood_score: 0,
        exploitability: String::new(),
        asset_at_risk: String::new(),
        blast_radius: String::new(),
        risk: 0,
        priority: String::new(),
        detection: "imported".to_string(),
        affected_contract: String::new(),
        locations: Vec::new(),
        evidence: String::new(),
        exploit_scenario: String::new(),
        recommendation: String::new(),
        references: Vec::new(),
        false_positive_notes: String::new(),
    }
}

/// A rule id that reads as `SWC-<n>` is a registry reference and is kept as one.
/// Anything else is not guessed at: blockscan's own SWC policy assigns an id
/// only on a high-confidence exact match, and importing does not lower that bar.
fn swc_of(rule_id: &str) -> Option<String> {
    let up = rule_id.to_ascii_uppercase();
    let rest = up.strip_prefix("SWC-")?;
    let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!n.is_empty()).then(|| format!("SWC-{n}"))
}

fn sarif_severity(level: &str) -> &'static str {
    match level {
        "error" => "High",
        "warning" => "Medium",
        "note" => "Low",
        _ => "Info",
    }
}

fn parse_sarif(v: &Value) -> Import {
    let mut tool = "sarif".to_string();
    let mut findings = Vec::new();

    for run in v["runs"].as_array().into_iter().flatten() {
        if let Some(name) = run.pointer("/tool/driver/name").and_then(Value::as_str) {
            if !name.is_empty() {
                tool = name.to_ascii_lowercase();
            }
        }
        // Rule metadata lives in the driver, keyed by id; results reference it.
        let mut rules: BTreeMap<&str, &Value> = BTreeMap::new();
        for r in run.pointer("/tool/driver/rules").and_then(Value::as_array).into_iter().flatten() {
            if let Some(id) = r["id"].as_str() {
                rules.insert(id, r);
            }
        }

        for res in run["results"].as_array().into_iter().flatten() {
            let rule_id = res["ruleId"].as_str().unwrap_or("").to_string();
            let rule = rules.get(rule_id.as_str());
            let mut f = blank(&tool);
            f.rule_id = format!("{tool}:{rule_id}");
            f.swc = swc_of(&rule_id);
            f.category = format!("Imported:{tool}");
            f.title = res
                .pointer("/message/text")
                .and_then(Value::as_str)
                .or_else(|| rule.and_then(|r| r.pointer("/shortDescription/text")).and_then(Value::as_str))
                .unwrap_or("")
                .to_string();
            f.severity = sarif_severity(res["level"].as_str().unwrap_or("none")).to_string();
            f.evidence = res.pointer("/message/text").and_then(Value::as_str).unwrap_or("").to_string();
            f.recommendation = rule
                .and_then(|r| r.pointer("/fullDescription/text"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if let Some(u) = rule.and_then(|r| r["helpUri"].as_str()) {
                f.references.push(u.to_string());
            }

            // A SARIF result can carry several locations; the first names the
            // file attribution runs on, and all of them are kept.
            let mut path = String::new();
            for loc in res["locations"].as_array().into_iter().flatten() {
                let uri = loc
                    .pointer("/physicalLocation/artifactLocation/uri")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if uri.is_empty() {
                    continue;
                }
                if path.is_empty() {
                    path = uri.to_string();
                }
                match loc.pointer("/physicalLocation/region/startLine").and_then(Value::as_u64) {
                    Some(line) => f.locations.push(format!("{uri}:{line}")),
                    None => f.locations.push(uri.to_string()),
                }
            }
            findings.push(ForeignFinding { path, finding: f });
        }
    }
    Import { tool, findings }
}

/// Slither's `impact` vocabulary, mapped onto ours. `Optimization` is not a
/// security severity at all and lands at `Info` rather than being dropped —
/// dropping it would make the two tools' totals silently disagree.
fn slither_severity(impact: &str) -> &'static str {
    match impact.to_ascii_lowercase().as_str() {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Info",
    }
}

fn parse_slither(v: &Value) -> Import {
    let tool = "slither".to_string();
    let mut findings = Vec::new();

    for det in v.pointer("/results/detectors").and_then(Value::as_array).into_iter().flatten() {
        let check = det["check"].as_str().unwrap_or("").to_string();
        let mut f = blank(&tool);
        f.rule_id = format!("{tool}:{check}");
        f.swc = swc_of(&check);
        f.category = format!("Imported:{tool}");
        f.severity = slither_severity(det["impact"].as_str().unwrap_or("")).to_string();
        f.confidence = det["confidence"].as_str().unwrap_or("").to_string();
        // `description` is Slither's multi-line prose; the first line is the
        // headline and the rest is the trace, which belongs in evidence.
        let desc = det["description"].as_str().unwrap_or("").trim();
        f.title = desc.lines().next().unwrap_or("").trim().to_string();
        f.evidence = desc.to_string();
        if let Some(m) = det["markdown"].as_str() {
            let _ = m; // present but redundant with `description`
        }
        if let Some(id) = det["id"].as_str() {
            f.false_positive_notes = format!("slither id {id}");
        }

        let mut path = String::new();
        for el in det["elements"].as_array().into_iter().flatten() {
            let sm = &el["source_mapping"];
            let file = sm["filename_relative"]
                .as_str()
                .or_else(|| sm["filename_short"].as_str())
                .or_else(|| sm["filename_absolute"].as_str())
                .unwrap_or("");
            if file.is_empty() {
                continue;
            }
            if path.is_empty() {
                path = file.to_string();
            }
            match sm["lines"].as_array().and_then(|l| l.first()).and_then(Value::as_u64) {
                Some(line) => f.locations.push(format!("{file}:{line}")),
                None => f.locations.push(file.to_string()),
            }
        }
        findings.push(ForeignFinding { path, finding: f });
    }
    Import { tool, findings }
}

// ---------------------------------------------------------------------------
// attribution
// ---------------------------------------------------------------------------

/// Normalize a reported path for comparison: forward slashes, no `./`.
fn norm(p: &str) -> String {
    let p = p.replace('\\', "/");
    p.trim_start_matches("./").to_ascii_lowercase()
}

/// The 0x-prefixed 40-hex address embedded in a path, if there is exactly one
/// path component that is one. This is the case that matters: an analyser run
/// over the corpus reports `out/0xabc.../source/src/Foo.sol`, and the directory
/// name *is* the attribution.
fn address_in_path(p: &str) -> Option<String> {
    p.split('/')
        .find(|seg| {
            seg.len() == 42
                && seg.starts_with("0x")
                && seg[2..].chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(str::to_string)
}

/// Whether `reported` names the source file `owned` (relative to a contract's
/// `source/` root). Compared on whole path components, so `Foo.sol` does not
/// match `MyFoo.sol`.
fn path_owns(reported: &str, owned: &str) -> bool {
    reported == owned || reported.ends_with(&format!("/{owned}"))
}

/// Merge `import` into `contracts`.
///
/// `sources` maps a lowercased contract address to the source paths it owns,
/// relative to its own `source/` root — the same form blockscan's own locations
/// use. Attribution tries the address in the path first, then a unique
/// whole-component suffix match against those paths.
///
/// A finding that matches several contracts is *not* assigned to one of them.
/// Half this feature's point is comparing two tools on the same input, and a
/// guess would corrupt exactly that comparison. Those, and the ones that match
/// nothing, are counted and reported.
pub fn merge(
    contracts: &mut [ContractDetails],
    sources: &BTreeMap<String, Vec<String>>,
    import: Import,
) -> MergeStats {
    let mut stats = MergeStats { tool: import.tool.clone(), total: import.findings.len(), ..Default::default() };

    // address -> index, so attribution can write straight into the record.
    let index: BTreeMap<String, usize> = contracts
        .iter()
        .enumerate()
        .map(|(i, d)| (d.address.to_ascii_lowercase(), i))
        .collect();

    for ff in import.findings {
        let p = norm(&ff.path);
        let hit = match address_in_path(&p).and_then(|a| index.get(&a).copied()) {
            Some(i) => Some(i),
            None => {
                let owners: Vec<usize> = index
                    .iter()
                    .filter(|(addr, _)| {
                        sources
                            .get(*addr)
                            .is_some_and(|paths| paths.iter().any(|o| path_owns(&p, &norm(o))))
                    })
                    .map(|(_, i)| *i)
                    .collect();
                match owners.len() {
                    1 => Some(owners[0]),
                    0 => None,
                    _ => {
                        stats.ambiguous += 1;
                        continue;
                    }
                }
            }
        };
        let Some(i) = hit else {
            stats.unmatched += 1;
            continue;
        };
        let mut f = ff.finding;
        f.affected_contract = contracts[i].address.clone();
        contracts[i].audit.get_or_insert_with(Default::default).findings.push(f);
        stats.attributed += 1;
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NATIVE_SOURCE;

    /// The hard constraint, checked against the source rather than trusted.
    /// "Import only" is the kind of rule that erodes by someone reasonably
    /// adding a convenience later.
    #[test]
    fn this_module_cannot_execute_anything() {
        let src = include_str!("import.rs");
        // Skip this test's own body, which necessarily names what it forbids.
        let code = src.split("mod tests {").next().expect("module body");
        for banned in ["process::Command", "std::process", "Command::new", "exec("] {
            assert!(!code.contains(banned), "import must never run anything; found {banned}");
        }
    }

    fn corpus() -> (Vec<ContractDetails>, BTreeMap<String, Vec<String>>) {
        let a = ContractDetails::minimal("0x00000000000000000000000000000000000000aa", 1);
        let b = ContractDetails::minimal("0x00000000000000000000000000000000000000bb", 1);
        let mut src = BTreeMap::new();
        src.insert(
            a.address.clone(),
            vec!["src/Vault.sol".to_string(), "src/interfaces/IERC20.sol".to_string()],
        );
        src.insert(
            b.address.clone(),
            vec!["src/Router.sol".to_string(), "src/interfaces/IERC20.sol".to_string()],
        );
        (vec![a, b], src)
    }

    fn sarif_doc(uri: &str) -> String {
        serde_json::json!({
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "Semgrep", "rules": [{
                    "id": "solidity.reentrancy",
                    "shortDescription": { "text": "Reentrancy" },
                    "fullDescription": { "text": "Apply checks-effects-interactions." },
                    "helpUri": "https://example.invalid/r"
                }]}},
                "results": [{
                    "ruleId": "solidity.reentrancy",
                    "level": "error",
                    "message": { "text": "state written after an external call" },
                    "locations": [{ "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": 42 }
                    }}]
                }]
            }]
        })
        .to_string()
    }

    fn slither_doc(file: &str) -> String {
        serde_json::json!({
            "success": true,
            "results": { "detectors": [{
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "id": "abc123",
                "description": "Reentrancy in Vault.withdraw()\n\t- External calls: msg.sender.call()",
                "elements": [{ "source_mapping": {
                    "filename_relative": file,
                    "lines": [17, 18, 19]
                }}]
            }]}
        })
        .to_string()
    }

    #[test]
    fn sarif_normalises_into_the_native_shape() {
        let im = parse(&sarif_doc("src/Vault.sol")).unwrap();
        assert_eq!(im.tool, "semgrep");
        assert_eq!(im.findings.len(), 1);
        let f = &im.findings[0].finding;
        assert_eq!(f.source, "semgrep");
        assert_eq!(f.rule_id, "semgrep:solidity.reentrancy");
        assert_eq!(f.severity, "High");
        assert_eq!(f.detection, "imported");
        assert_eq!(f.locations, vec!["src/Vault.sol:42"]);
        assert_eq!(f.title, "state written after an external call");
        assert_eq!(f.recommendation, "Apply checks-effects-interactions.");
        assert_eq!(f.references, vec!["https://example.invalid/r"]);
    }

    #[test]
    fn slither_normalises_into_the_native_shape() {
        let im = parse(&slither_doc("src/Vault.sol")).unwrap();
        assert_eq!(im.tool, "slither");
        let f = &im.findings[0].finding;
        assert_eq!(f.rule_id, "slither:reentrancy-eth");
        assert_eq!(f.severity, "High");
        assert_eq!(f.confidence, "Medium", "slither reports confidence and SARIF does not");
        assert_eq!(f.title, "Reentrancy in Vault.withdraw()");
        assert!(f.evidence.contains("External calls"), "the trace is kept as evidence");
        assert_eq!(f.locations, vec!["src/Vault.sol:17"]);
    }

    /// Nothing blockscan did not learn is filled in. A number in `risk` would be
    /// read as a measurement.
    #[test]
    fn nothing_is_invented_for_a_foreign_finding() {
        let f = parse(&slither_doc("src/Vault.sol")).unwrap().findings.remove(0).finding;
        assert_eq!((f.risk, f.impact_score, f.likelihood_score), (0, 0, 0));
        assert!(f.exploitability.is_empty());
        assert!(f.blast_radius.is_empty());
        assert!(f.asset_at_risk.is_empty());
        assert!(f.priority.is_empty());
        assert!(f.exploit_scenario.is_empty());
        assert!(f.swc.is_none(), "an SWC id is never guessed from a foreign rule name");
        assert!(f.scwe.is_none() && f.ethtrust.is_none());
    }

    /// Except where the foreign id *is* a registry reference.
    #[test]
    fn an_swc_id_in_the_rule_name_is_kept() {
        assert_eq!(swc_of("SWC-107"), Some("SWC-107".to_string()));
        assert_eq!(swc_of("swc-115-tx-origin"), Some("SWC-115".to_string()));
        assert_eq!(swc_of("reentrancy-eth"), None);
        assert_eq!(swc_of("SWC-"), None);
    }

    #[test]
    fn an_address_in_the_path_attributes_the_finding() {
        let (mut c, src) = corpus();
        let im = parse(&sarif_doc(
            "out/0x00000000000000000000000000000000000000BB/source/src/Router.sol",
        ))
        .unwrap();
        let stats = merge(&mut c, &src, im);
        assert_eq!(stats.attributed, 1);
        assert!(c[0].audit.is_none(), "not the other contract");
        let f = &c[1].audit.as_ref().unwrap().findings[0];
        assert_eq!(f.affected_contract, c[1].address);
    }

    #[test]
    fn a_unique_source_path_attributes_the_finding() {
        let (mut c, src) = corpus();
        let stats = merge(&mut c, &src, parse(&slither_doc("src/Router.sol")).unwrap());
        assert_eq!((stats.attributed, stats.ambiguous, stats.unmatched), (1, 0, 0));
        assert_eq!(c[1].audit.as_ref().unwrap().findings.len(), 1);
    }

    /// Both contracts vendor `src/interfaces/IERC20.sol`. Picking one would
    /// corrupt the very comparison this feature exists for.
    #[test]
    fn a_path_two_contracts_own_is_not_attributed_to_either() {
        let (mut c, src) = corpus();
        let stats = merge(&mut c, &src, parse(&slither_doc("src/interfaces/IERC20.sol")).unwrap());
        assert_eq!((stats.attributed, stats.ambiguous, stats.unmatched), (0, 1, 0));
        assert!(c.iter().all(|d| d.audit.is_none()));
    }

    /// A partial component match is not a match.
    #[test]
    fn a_lookalike_filename_is_not_attributed() {
        let (mut c, src) = corpus();
        let stats = merge(&mut c, &src, parse(&slither_doc("contracts/MyVault.sol")).unwrap());
        assert_eq!((stats.attributed, stats.unmatched), (0, 1));
    }

    #[test]
    fn an_unrecognised_file_is_refused_with_a_usable_message() {
        let err = parse("{\"hello\":1}").unwrap_err().to_string();
        assert!(err.contains("SARIF"), "{err}");
        assert!(err.contains("Slither"), "{err}");
        assert!(parse("not json").unwrap_err().to_string().contains("not JSON"));
    }

    /// The acceptance property: merging cannot move blockscan's number.
    #[test]
    fn imported_findings_do_not_change_the_risk_number() {
        let (mut c, src) = corpus();
        let native = crate::audit::audit(&c[1], &[]);
        c[1].audit = Some(native.clone());

        merge(&mut c, &src, parse(&slither_doc("src/Router.sol")).unwrap());
        let after = &c[1].audit.as_ref().unwrap();
        assert_eq!(after.findings.len(), native.findings.len() + 1, "it is there");

        // Re-score the merged set: the imported finding must not reach the sum.
        let rescored = crate::audit::audit(&c[1], &[]);
        assert_eq!(rescored.risk_score, native.risk_score);
        assert_eq!(rescored.grade, native.grade);
        assert_eq!(rescored.summary, native.summary);
    }

    #[test]
    fn a_pre_import_metadata_file_reads_as_native() {
        let json = r#"{
            "rule_id":"X","title":"t","category":"SC01:Access Control","swc":null,
            "severity":"High","confidence":"Medium","impact_score":7,"likelihood_score":5,
            "exploitability":"Moderate","asset_at_risk":"x","blast_radius":"user-funds","risk":26,
            "priority":"P1","detection":"source","affected_contract":"0xabc","locations":[],
            "evidence":"e","exploit_scenario":"s","recommendation":"r","references":[],
            "false_positive_notes":""
        }"#;
        let f: SecurityFinding = serde_json::from_str(json).unwrap();
        assert_eq!(f.source, NATIVE_SOURCE);
    }
}
