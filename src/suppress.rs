//! Audit finding suppression config (`--suppress`).
//!
//! A heuristic linter inevitably reports false positives; teams need to silence
//! findings they've triaged as FPs (or accepted as a baseline) instead of seeing
//! the same noise on every re-audit. A JSON file lists match rules; findings that
//! match are dropped *before* scoring, so suppressing an FP also lowers the score.
//!
//! Loading is fail-safe in the *visible* direction: a missing or malformed file
//! warns and suppresses nothing (you see more findings, never fewer), matching the
//! security-tool philosophy of never silently hiding results.

use std::path::Path;

use serde::Deserialize;

use crate::model::SecurityFinding;

/// A parsed suppression config. Empty by default (nothing suppressed).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Suppressions {
    #[serde(default)]
    suppress: Vec<SuppressEntry>,
}

/// One suppression rule. All match keys are optional; an entry matches a finding
/// when *every non-empty key* matches (AND). Entries are OR-ed together. `reason`
/// is documentation only and ignored by the matcher.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuppressEntry {
    /// Internal `rule_id`, e.g. `DELEGATECALL_USAGE`.
    #[serde(default)]
    pub rule: Option<String>,
    /// Restrict to this contract address (case-insensitive). Pairs with `rule`.
    #[serde(default)]
    pub contract: Option<String>,
    /// SWC registry id, e.g. `SWC-112` (blanket-suppress a registry class).
    #[serde(default)]
    pub swc: Option<String>,
    /// OWASP category, e.g. `SC06:Unchecked External Calls`.
    #[serde(default)]
    pub category: Option<String>,
    /// Exact finding fingerprint (`sarif::fingerprint`) — suppress one instance.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Free-text justification (documentation only).
    #[serde(default)]
    pub reason: Option<String>,
}

impl SuppressEntry {
    /// Whether this entry has at least one usable match key (not `reason`-only).
    fn has_key(&self) -> bool {
        self.rule.is_some()
            || self.contract.is_some()
            || self.swc.is_some()
            || self.category.is_some()
            || self.fingerprint.is_some()
    }

    /// Whether this entry matches `f` (every non-empty key must match).
    fn matches(&self, f: &SecurityFinding) -> bool {
        if !self.has_key() {
            return false; // an all-empty entry must never match anything
        }
        if let Some(rule) = &self.rule {
            if rule != &f.rule_id {
                return false;
            }
        }
        if let Some(contract) = &self.contract {
            if !contract.eq_ignore_ascii_case(&f.affected_contract) {
                return false;
            }
        }
        if let Some(swc) = &self.swc {
            if f.swc.as_deref() != Some(swc.as_str()) {
                return false;
            }
        }
        if let Some(category) = &self.category {
            if category != &f.category {
                return false;
            }
        }
        if let Some(fp) = &self.fingerprint {
            if fp != &crate::sarif::fingerprint(f) {
                return false;
            }
        }
        true
    }
}

impl Suppressions {
    /// Load from an optional path. `None` → empty. A missing/unreadable/malformed
    /// file warns and yields empty (no suppression — the safe direction). Entries
    /// with no match key are dropped with a warning (so a stray `{}` can't be read
    /// as "suppress everything").
    pub fn load_or_warn(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::default();
        };
        let body = match std::fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "suppress file unreadable ({}): {e}; suppressing nothing",
                    path.display()
                );
                return Self::default();
            }
        };
        let mut parsed: Self = match serde_json::from_str(&body) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "suppress file invalid JSON ({}): {e}; suppressing nothing",
                    path.display()
                );
                return Self::default();
            }
        };
        let before = parsed.suppress.len();
        parsed.suppress.retain(SuppressEntry::has_key);
        let dropped = before - parsed.suppress.len();
        if dropped > 0 {
            tracing::warn!("ignoring {dropped} suppress entr(ies) with no match key");
        }
        tracing::info!("loaded {} suppression rule(s) from {}", parsed.suppress.len(), path.display());
        parsed
    }

    pub fn is_empty(&self) -> bool {
        self.suppress.is_empty()
    }

    pub fn len(&self) -> usize {
        self.suppress.len()
    }

    /// Whether any rule suppresses this finding.
    pub fn is_suppressed(&self, f: &SecurityFinding) -> bool {
        self.suppress.iter().any(|e| e.matches(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> SecurityFinding {
        SecurityFinding {
            source: crate::model::NATIVE_SOURCE.into(),
            rule_id: "DELEGATECALL_USAGE".into(),
            title: "delegatecall".into(),
            category: "SC06:Unchecked External Calls".into(),
            swc: Some("SWC-112".into()),
            scwe: None,
            ethtrust: None,
            severity: "Medium".into(),
            confidence: "Low".into(),
            impact_score: 7,
            likelihood_score: 3,
            exploitability: "Hard".into(),
            asset_at_risk: "storage".into(),
            blast_radius: "protocol".into(),
            risk: 20,
            priority: "P2".into(),
            detection: "source".into(),
            affected_contract: "0xAbCdef0000000000000000000000000000000001".into(),
            locations: vec!["C.sol:10".into()],
            evidence: "delegatecall(x)".into(),
            exploit_scenario: "s".into(),
            recommendation: "r".into(),
            references: vec![],
            false_positive_notes: "".into(),
        }
    }

    fn parse(json: &str) -> Suppressions {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn default_suppresses_nothing() {
        let s = Suppressions::default();
        assert!(s.is_empty());
        assert!(!s.is_suppressed(&finding()));
    }

    #[test]
    fn matches_by_rule() {
        let s = parse(r#"{"suppress":[{"rule":"DELEGATECALL_USAGE","reason":"ok"}]}"#);
        assert!(s.is_suppressed(&finding()));
        let other = parse(r#"{"suppress":[{"rule":"TX_ORIGIN_AUTH"}]}"#);
        assert!(!other.is_suppressed(&finding()));
    }

    #[test]
    fn rule_scoped_to_contract_is_case_insensitive() {
        // Same rule but different contract -> not suppressed.
        let s = parse(r#"{"suppress":[{"rule":"DELEGATECALL_USAGE","contract":"0x00000000000000000000000000000000000000ff"}]}"#);
        assert!(!s.is_suppressed(&finding()));
        // Matching contract (upper/lower mix) -> suppressed.
        let s = parse(r#"{"suppress":[{"rule":"DELEGATECALL_USAGE","contract":"0xABCDEF0000000000000000000000000000000001"}]}"#);
        assert!(s.is_suppressed(&finding()));
    }

    #[test]
    fn matches_by_swc_and_category() {
        assert!(parse(r#"{"suppress":[{"swc":"SWC-112"}]}"#).is_suppressed(&finding()));
        assert!(!parse(r#"{"suppress":[{"swc":"SWC-999"}]}"#).is_suppressed(&finding()));
        assert!(parse(r#"{"suppress":[{"category":"SC06:Unchecked External Calls"}]}"#).is_suppressed(&finding()));
        assert!(!parse(r#"{"suppress":[{"category":"SC01:Access Control"}]}"#).is_suppressed(&finding()));
    }

    #[test]
    fn swc_match_needs_finding_to_have_swc() {
        let mut f = finding();
        f.swc = None;
        assert!(!parse(r#"{"suppress":[{"swc":"SWC-112"}]}"#).is_suppressed(&f));
    }

    #[test]
    fn matches_by_fingerprint() {
        let fp = crate::sarif::fingerprint(&finding());
        let json = format!(r#"{{"suppress":[{{"fingerprint":"{fp}"}}]}}"#);
        assert!(parse(&json).is_suppressed(&finding()));
        assert!(!parse(r#"{"suppress":[{"fingerprint":"0000000000000000"}]}"#).is_suppressed(&finding()));
    }

    #[test]
    fn multiple_keys_are_anded() {
        // rule matches but swc doesn't -> entry as a whole does NOT match.
        let s = parse(r#"{"suppress":[{"rule":"DELEGATECALL_USAGE","swc":"SWC-999"}]}"#);
        assert!(!s.is_suppressed(&finding()));
        // both match -> suppressed.
        let s = parse(r#"{"suppress":[{"rule":"DELEGATECALL_USAGE","swc":"SWC-112"}]}"#);
        assert!(s.is_suppressed(&finding()));
    }

    #[test]
    fn empty_entry_matches_nothing() {
        // An entry with only `reason` (no match key) must not suppress anything.
        let s = SuppressEntry { reason: Some("oops".into()), ..Default::default() };
        assert!(!s.matches(&finding()));
        assert!(!s.has_key());
    }

    #[test]
    fn load_none_is_empty() {
        assert!(Suppressions::load_or_warn(None).is_empty());
    }

    #[test]
    fn load_missing_file_warns_empty() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let p = std::path::PathBuf::from("definitely_missing_suppress.json");
        assert!(Suppressions::load_or_warn(Some(&p)).is_empty());
    }

    #[test]
    fn load_bad_json_warns_empty() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bad.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(Suppressions::load_or_warn(Some(&p)).is_empty());
    }

    #[test]
    fn load_drops_keyless_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("s.json");
        std::fs::write(
            &p,
            r#"{"suppress":[{"reason":"keyless"},{"rule":"DELEGATECALL_USAGE"}]}"#,
        )
        .unwrap();
        let s = Suppressions::load_or_warn(Some(&p));
        assert_eq!(s.len(), 1); // the keyless entry was dropped
        assert!(s.is_suppressed(&finding()));
    }

    #[test]
    fn load_valid_file_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("s.json");
        std::fs::write(&p, r#"{"suppress":[{"swc":"SWC-112"}]}"#).unwrap();
        let s = Suppressions::load_or_warn(Some(&p));
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
        assert!(s.is_suppressed(&finding()));
    }
}
