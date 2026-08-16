//! Alert grouping (`--group`): collapse high-frequency same-`(chain, contract, kind)`
//! alerts into a single end-of-run **digest**, instead of [`crate::throttle`]'s hard
//! drop. Opt-in; the digest carries the count and the block span it covers.

use std::collections::BTreeMap;

use crate::model::Alert;

/// Accumulates alerts per `(chain, contract, event)` and emits one digest each.
/// Keyed on `event` (not the coarser `kind`) so distinct event types that share a
/// kind — e.g. `Upgraded` and `BeaconUpgraded` (both `proxy-upgrade`) — stay separate.
#[derive(Default)]
pub struct Grouper {
    enabled: bool,
    // BTreeMap so drained digests come out in a deterministic order (testable).
    groups: BTreeMap<(u64, String, String), Agg>,
}

struct Agg {
    count: u64,
    first_block: u64,
    last_block: u64,
    /// The folded events' kind (preserved for the digest; constant within a group).
    kind: String,
    /// Highest risk score seen (for risky-deployment groups) and its grade.
    max_risk: Option<u8>,
    grade: Option<String>,
}

impl Grouper {
    pub fn new(enabled: bool) -> Self {
        Self { enabled, groups: BTreeMap::new() }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Fold one alert into its `(chain, contract, event)` group (count, block span,
    /// and — for risky deployments — the worst risk score + its grade).
    pub fn add(&mut self, alert: &Alert) {
        let key = (alert.chain_id, alert.contract.clone(), alert.event.clone());
        let agg = self.groups.entry(key).or_insert(Agg {
            count: 0,
            first_block: alert.block,
            last_block: alert.block,
            kind: alert.kind.clone(),
            max_risk: None,
            grade: None,
        });
        agg.count += 1;
        agg.first_block = agg.first_block.min(alert.block);
        agg.last_block = agg.last_block.max(alert.block);
        // Keep the highest risk score (and its grade) so a digest of risky
        // deployments still conveys severity instead of dropping it.
        if let Some(risk) = alert.risk_score {
            if agg.max_risk.is_none_or(|m| risk > m) {
                agg.max_risk = Some(risk);
                agg.grade = alert.grade.clone();
            }
        }
    }

    /// Produce one digest [`Alert`] per group (sorted by key) and clear the state.
    /// A digest is a derived summary (`event: "Grouped"`), not an on-chain event, so
    /// it carries no `tx_hash` / `log_index` and is not itself de-duplicated.
    pub fn drain(&mut self) -> Vec<Alert> {
        std::mem::take(&mut self.groups)
            .into_iter()
            .map(|((chain_id, contract, event), agg)| Alert {
                block: agg.last_block,
                chain_id,
                contract,
                new_value: Some(format!("{} {event} event(s)", agg.count)),
                previous: Some(format!("blocks {}..{}", agg.first_block, agg.last_block)),
                event: "Grouped".to_string(),
                kind: agg.kind,
                tx_hash: None,
                log_index: None,
                amount: Some(agg.count.to_string()),
                risk_score: agg.max_risk,
                grade: agg.grade,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // event defaults to the kind so distinct kinds form distinct groups (the
    // grouper keys on event); individual tests override `event` where needed.
    fn alert(chain: u64, contract: &str, kind: &str, block: u64) -> Alert {
        Alert {
            block,
            chain_id: chain,
            contract: contract.into(),
            event: kind.into(),
            kind: kind.into(),
            new_value: None,
            previous: None,
            tx_hash: None,
            log_index: None,
            amount: None,
            risk_score: None,
            grade: None,
        }
    }

    #[test]
    fn disabled_grouper_is_inert() {
        let mut g = Grouper::new(false);
        assert!(!g.enabled());
        // add still works mechanically, but callers only use it when enabled().
        assert!(g.is_empty());
        assert!(g.drain().is_empty());
    }

    #[test]
    fn folds_count_and_block_span_per_key() {
        let mut g = Grouper::new(true);
        assert!(g.enabled());
        g.add(&alert(1, "0xabc", "large-transfer", 100));
        g.add(&alert(1, "0xabc", "large-transfer", 105));
        g.add(&alert(1, "0xabc", "large-transfer", 102));
        // Different kind on same contract -> its own group.
        g.add(&alert(1, "0xabc", "paused", 101));
        // Different contract.
        g.add(&alert(1, "0xdef", "large-transfer", 200));
        // Different chain, same contract+kind -> separate.
        g.add(&alert(10, "0xabc", "large-transfer", 100));
        assert_eq!(g.len(), 4);

        let digests = g.drain();
        assert_eq!(digests.len(), 4);
        assert!(g.is_empty()); // drained

        // The 0xabc/large-transfer/chain1 digest: 3 events over blocks 100..105.
        let d = digests
            .iter()
            .find(|d| d.chain_id == 1 && d.contract == "0xabc" && d.kind == "large-transfer")
            .unwrap();
        assert_eq!(d.event, "Grouped");
        assert_eq!(d.amount.as_deref(), Some("3"));
        assert_eq!(d.block, 105); // last block
        assert_eq!(d.new_value.as_deref(), Some("3 large-transfer event(s)"));
        assert_eq!(d.previous.as_deref(), Some("blocks 100..105"));
        assert!(d.tx_hash.is_none() && d.log_index.is_none());
    }

    #[test]
    fn distinct_events_with_same_kind_stay_separate() {
        // Regression (review MED): Upgraded and BeaconUpgraded share kind
        // "proxy-upgrade" but must NOT collapse into one digest.
        let mut g = Grouper::new(true);
        let mk = |event: &str| {
            let mut a = alert(1, "0xabc", "proxy-upgrade", 10);
            a.event = event.into();
            a
        };
        g.add(&mk("Upgraded"));
        g.add(&mk("Upgraded"));
        g.add(&mk("BeaconUpgraded"));
        let digests = g.drain();
        assert_eq!(digests.len(), 2, "distinct events must not collapse: {digests:?}");
        assert!(digests.iter().all(|d| d.kind == "proxy-upgrade"));
        assert!(digests.iter().any(|d| d.new_value.as_deref() == Some("2 Upgraded event(s)")));
        assert!(digests.iter().any(|d| d.new_value.as_deref() == Some("1 BeaconUpgraded event(s)")));
    }

    #[test]
    fn risky_deployment_digest_keeps_max_risk_and_grade() {
        // Regression (review LOW): folding risky deployments must retain severity.
        let mut g = Grouper::new(true);
        let mk = |risk: u8, grade: &str, block: u64| {
            let mut a = alert(1, "0xabc", "risky-deployment", block);
            a.event = "RiskyDeployment".into();
            a.risk_score = Some(risk);
            a.grade = Some(grade.into());
            a
        };
        g.add(&mk(30, "C", 1));
        g.add(&mk(70, "F", 2)); // worst
        g.add(&mk(50, "D", 3));
        let d = g.drain();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].amount.as_deref(), Some("3"));
        assert_eq!(d[0].risk_score, Some(70));
        assert_eq!(d[0].grade.as_deref(), Some("F"));
    }

    #[test]
    fn single_event_group_spans_one_block() {
        let mut g = Grouper::new(true);
        g.add(&alert(1, "0xabc", "paused", 42));
        let d = g.drain();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].amount.as_deref(), Some("1"));
        assert_eq!(d[0].previous.as_deref(), Some("blocks 42..42"));
    }
}
