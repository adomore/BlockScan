//! Cross-run alert de-duplication via a persistent fingerprint baseline.
//!
//! Overlapping `monitor` windows or periodic re-runs would otherwise re-emit the
//! same alert. Each alert gets a run-independent fingerprint; fingerprints already
//! recorded in the baseline file are suppressed, new ones are emitted and appended
//! so later runs (and `watch` ticks) see them. The suppression direction can only
//! ever drop *duplicates* — a never-before-seen alert is always new.

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

use crate::model::Alert;

/// A stable, run-independent fingerprint for an alert (first 8 bytes of a keccak,
/// 16 lowercase hex chars — same shape as the SARIF `partialFingerprints`).
///
/// Built from the on-chain identity fields that are constant across runs:
/// `chain_id|block|contract|event|kind|tx_hash|log_index|previous|new_value`.
/// `tx_hash` + `log_index` uniquely identify a log (a tx hash alone does NOT — one
/// tx can emit the same event twice); `block` is a fallback for custom topics
/// without a tx hash; `previous`/`new_value` further separate same-position events.
/// None fields map to `""`. (All current fields are numeric or `0x…` hex, so none
/// can contain the `|` delimiter — no separator-injection collision is possible.)
pub fn alert_fingerprint(a: &Alert) -> String {
    let log_index = a.log_index.map(|i| i.to_string()).unwrap_or_default();
    let key = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        a.chain_id,
        a.block,
        a.contract,
        a.event,
        a.kind,
        a.tx_hash.as_deref().unwrap_or(""),
        log_index,
        a.previous.as_deref().unwrap_or(""),
        a.new_value.as_deref().unwrap_or(""),
    );
    let hash = alloy::primitives::keccak256(key.as_bytes());
    format!("{hash:x}")[..16].to_string()
}

/// An in-memory set of seen alert fingerprints, optionally backed by a file.
///
/// `path == None` disables de-duplication entirely (every alert is "new" and
/// nothing is recorded), preserving the pre-baseline behaviour.
pub struct AlertBaseline {
    seen: HashSet<String>,
    path: Option<PathBuf>,
}

impl AlertBaseline {
    /// Load the baseline. A missing file is the normal first-run case (empty set).
    /// A read failure degrades to an empty set with a `warn!` — we never let
    /// baseline I/O stop monitoring (and "empty" only ever means *fewer*
    /// suppressions, i.e. the safe direction). `None` disables de-duplication.
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut seen = HashSet::new();
        if let Some(p) = &path {
            match std::fs::read_to_string(p) {
                Ok(body) => {
                    for line in body.lines() {
                        let fp = line.trim();
                        if !fp.is_empty() && !fp.starts_with('#') {
                            seen.insert(fp.to_string());
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // first run
                Err(e) => tracing::warn!(
                    "baseline read failed ({}): {e}; starting empty (no suppression)",
                    p.display()
                ),
            }
        }
        Self { seen, path }
    }

    /// Number of fingerprints currently known (for reporting/tests).
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Whether de-duplication is active (a baseline path was configured).
    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Whether `alert`'s fingerprint is already recorded — a NON-mutating peek.
    /// Always `false` when de-dup is disabled (no path). Used to decide suppression
    /// *before* committing the fingerprint, so a later-dropped (e.g. throttled) alert
    /// isn't permanently recorded and silently lost on the next run.
    pub fn seen(&self, alert: &Alert) -> bool {
        if self.path.is_none() {
            return false;
        }
        self.seen.contains(&alert_fingerprint(alert))
    }

    /// Commit `alert`'s fingerprint (in memory + appended to the file). No-op when
    /// de-dup is disabled or the fingerprint is already recorded. Call this only for
    /// alerts that are actually emitted.
    pub fn record(&mut self, alert: &Alert) {
        let Some(path) = self.path.clone() else {
            return; // de-dup disabled
        };
        let fp = alert_fingerprint(alert);
        if self.seen.insert(fp.clone()) {
            if let Err(e) = append_line(&path, &fp) {
                tracing::warn!("baseline write failed ({}): {e}", path.display());
            }
        }
    }

    /// Returns `true` if `alert` has not been seen before, recording it. With no
    /// path, always `true` and records nothing. (Convenience combining
    /// [`Self::seen`] + [`Self::record`] for callers that emit unconditionally.)
    pub fn is_new(&mut self, alert: &Alert) -> bool {
        if self.seen(alert) {
            return false;
        }
        self.record(alert);
        true
    }
}

/// Append `line` plus a newline to `path`, creating it if needed (one `write_all`
/// so concurrent appenders can't interleave a line with another's newline).
fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format!("{line}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(block: u64, tx: Option<&str>, new_value: Option<&str>) -> Alert {
        Alert {
            block,
            chain_id: 1,
            contract: "0xabc".into(),
            event: "Upgraded".into(),
            kind: "proxy-upgrade".into(),
            new_value: new_value.map(String::from),
            previous: None,
            tx_hash: tx.map(String::from),
            log_index: Some(0),
            amount: None,
            risk_score: None,
            grade: None,
        }
    }

    #[test]
    fn fingerprint_is_16_hex_and_stable() {
        let a = alert(10, Some("0xtx"), Some("0ximpl"));
        let fp = alert_fingerprint(&a);
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        // Recomputing the same alert yields the same fingerprint.
        assert_eq!(fp, alert_fingerprint(&alert(10, Some("0xtx"), Some("0ximpl"))));
    }

    #[test]
    fn fingerprint_distinguishes_identity_fields() {
        let base = alert_fingerprint(&alert(10, Some("0xtx"), Some("0ximpl")));
        // Different block / tx / new_value each change the fingerprint.
        assert_ne!(base, alert_fingerprint(&alert(11, Some("0xtx"), Some("0ximpl"))));
        assert_ne!(base, alert_fingerprint(&alert(10, Some("0xOTHER"), Some("0ximpl"))));
        assert_ne!(base, alert_fingerprint(&alert(10, Some("0xtx"), Some("0xOTHER"))));
        // chain_id, event, kind, previous also participate.
        let mut a = alert(10, Some("0xtx"), Some("0ximpl"));
        a.chain_id = 10;
        assert_ne!(base, alert_fingerprint(&a));
        let mut a = alert(10, Some("0xtx"), Some("0ximpl"));
        a.previous = Some("0xprev".into());
        assert_ne!(base, alert_fingerprint(&a));
    }

    #[test]
    fn two_logs_same_tx_different_index_do_not_collide() {
        // Regression (review HIGH): two identical events in one tx must stay distinct
        // — a tx hash alone is not a unique log identity, so log_index participates.
        let mut a = alert(10, Some("0xtx"), Some("0ximpl"));
        a.log_index = Some(0);
        let mut b = alert(10, Some("0xtx"), Some("0ximpl"));
        b.log_index = Some(1);
        assert_ne!(alert_fingerprint(&a), alert_fingerprint(&b));
        // The same log (same index) is still stable -> de-duped.
        let mut base = AlertBaseline::load(None);
        assert!(base.is_new(&a)); // no path -> always new, but fingerprints are what matter
        assert_ne!(alert_fingerprint(&a), alert_fingerprint(&b));
    }

    #[test]
    fn disabled_baseline_never_dedups() {
        let mut b = AlertBaseline::load(None);
        assert!(!b.enabled());
        let a = alert(1, Some("0xtx"), None);
        assert!(b.is_new(&a));
        assert!(b.is_new(&a)); // still new — recording is off
        assert!(b.is_empty());
    }

    #[test]
    fn dedups_within_and_across_load() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("seen.fp");

        let mut b = AlertBaseline::load(Some(path.clone()));
        assert!(b.enabled());
        let a = alert(5, Some("0xtx"), Some("0ximpl"));
        assert!(b.is_new(&a)); // first time -> new, recorded
        assert!(!b.is_new(&a)); // same run, repeat -> suppressed
        let other = alert(6, Some("0xtx2"), None);
        assert!(b.is_new(&other));
        assert_eq!(b.len(), 2);

        // The file persisted both fingerprints (one per line).
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().filter(|l| !l.trim().is_empty()).count(), 2);

        // A fresh load over the same file suppresses the previously seen alert.
        let mut b2 = AlertBaseline::load(Some(path.clone()));
        assert_eq!(b2.len(), 2);
        assert!(!b2.is_new(&a));
        assert!(!b2.is_new(&other));
        // A genuinely new alert still passes and is appended.
        let fresh = alert(7, Some("0xtx3"), None);
        assert!(b2.is_new(&fresh));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
    }

    #[test]
    fn seen_is_a_non_mutating_peek_record_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("seen.fp");
        let mut b = AlertBaseline::load(Some(path.clone()));
        let a = alert(9, Some("0xtx"), Some("0ximpl"));
        // Peeking many times must NOT record it (the throttle-safety property).
        assert!(!b.seen(&a));
        assert!(!b.seen(&a));
        assert!(b.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap_or_default().lines().count(), 0);
        // Recording commits it; thereafter seen() is true and the file has 1 line.
        b.record(&a);
        assert!(b.seen(&a));
        assert_eq!(b.len(), 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        // record() is idempotent (no duplicate line).
        b.record(&a);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        // Disabled baseline: seen() always false, record() a no-op.
        let mut d = AlertBaseline::load(None);
        assert!(!d.seen(&a));
        d.record(&a);
        assert!(d.is_empty());
    }

    #[test]
    fn load_ignores_comments_and_blank_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("seen.fp");
        std::fs::write(&path, "# a comment\n\n  \nabc123def4567890\n").unwrap();
        let b = AlertBaseline::load(Some(path));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does_not_exist.fp");
        let b = AlertBaseline::load(Some(path));
        assert!(b.is_empty());
    }

    #[test]
    fn unreadable_path_degrades_to_empty() {
        // A directory path can't be read as a file -> warn + empty (no panic).
        // Install a subscriber so the warn!'s lazy args actually evaluate.
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let tmp = tempfile::tempdir().unwrap();
        let b = AlertBaseline::load(Some(tmp.path().to_path_buf()));
        assert!(b.is_empty());
        assert!(b.enabled());
    }

    #[test]
    fn write_failure_is_swallowed() {
        // Path whose parent dir doesn't exist -> append fails -> warn, still "new".
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let mut b = AlertBaseline::load(Some(PathBuf::from("no_such_dir/sub/seen.fp")));
        assert!(b.is_new(&alert(1, Some("0xtx"), None)));
        // The in-memory set still recorded it, so the repeat is suppressed.
        assert!(!b.is_new(&alert(1, Some("0xtx"), None)));
    }
}
