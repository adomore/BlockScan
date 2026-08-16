//! In-run alert throttling: cap how many alerts a single `(contract, kind)` pair
//! may emit, so one noisy contract can't flood the sinks. Distinct from the
//! cross-run [`crate::baseline`] de-dup (which suppresses *exact repeats*); throttle
//! caps a *burst of distinct* same-kind alerts within one run.

use std::collections::HashMap;

/// Per-`(chain, contract, kind)` emission counter with an optional cap. The chain
/// id is part of the key so the same address active on two chains gets independent
/// budgets (mirroring the chain-aware [`crate::baseline`] fingerprint).
#[derive(Default)]
pub struct Throttle {
    /// Max alerts per (chain, contract, kind) this run; `None` disables throttling.
    cap: Option<usize>,
    counts: HashMap<(u64, String, String), usize>,
}

impl Throttle {
    /// `cap == Some(0)` is treated as disabled (a 0 cap would suppress everything,
    /// which is almost certainly a misconfiguration, not an intent).
    pub fn new(cap: Option<usize>) -> Self {
        Self {
            cap: cap.filter(|&n| n > 0),
            counts: HashMap::new(),
        }
    }

    /// Whether throttling is active.
    pub fn enabled(&self) -> bool {
        self.cap.is_some()
    }

    /// Returns `true` if an alert for `(chain, contract, kind)` is still under the
    /// cap (and counts it); `false` once the cap is reached. With no cap, always
    /// `true` and nothing is tracked.
    pub fn allow(&mut self, chain: u64, contract: &str, kind: &str) -> bool {
        let Some(cap) = self.cap else { return true };
        let c = self.counts.entry((chain, contract.to_string(), kind.to_string())).or_insert(0);
        if *c >= cap {
            return false;
        }
        *c += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_allows_everything() {
        let mut t = Throttle::new(None);
        assert!(!t.enabled());
        for _ in 0..1000 {
            assert!(t.allow(1, "0xabc", "paused"));
        }
        // A 0 cap is treated as disabled, not "suppress all".
        let mut z = Throttle::new(Some(0));
        assert!(!z.enabled());
        assert!(z.allow(1, "0xabc", "paused"));
    }

    #[test]
    fn caps_per_chain_contract_kind() {
        let mut t = Throttle::new(Some(2));
        assert!(t.enabled());
        assert!(t.allow(1, "0xabc", "large-transfer")); // 1
        assert!(t.allow(1, "0xabc", "large-transfer")); // 2
        assert!(!t.allow(1, "0xabc", "large-transfer")); // 3 -> capped
        assert!(!t.allow(1, "0xabc", "large-transfer")); // still capped
    }

    #[test]
    fn keys_are_independent() {
        let mut t = Throttle::new(Some(1));
        assert!(t.allow(1, "0xabc", "paused"));
        assert!(!t.allow(1, "0xabc", "paused")); // same key capped
        // Different kind on same contract -> own budget.
        assert!(t.allow(1, "0xabc", "role-granted"));
        // Different contract, same kind -> own budget.
        assert!(t.allow(1, "0xdef", "paused"));
        assert!(!t.allow(1, "0xdef", "paused"));
        // Same contract+kind on a DIFFERENT chain -> own budget.
        assert!(t.allow(10, "0xabc", "paused"));
        assert!(!t.allow(10, "0xabc", "paused"));
    }
}
