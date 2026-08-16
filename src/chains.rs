//! Chain id → explorer base + name mapping for multichain scanning.
//!
//! Etherscan V2 needs no per-chain host (it routes by `chainid`); only Blockscout
//! enrichment/search uses a per-chain base.

/// Blockscout v2 API base for a chain id, if known.
pub fn blockscout_base(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        1 => "https://eth.blockscout.com/api/v2",
        10 => "https://explorer.optimism.io/api/v2",
        8453 => "https://base.blockscout.com/api/v2",
        42161 => "https://arbitrum.blockscout.com/api/v2",
        137 => "https://polygon.blockscout.com/api/v2",
        _ => return None,
    })
}

/// Short human name for a chain id (used for output subdirectories).
pub fn chain_name(chain_id: u64) -> String {
    match chain_id {
        1 => "ethereum".into(),
        10 => "optimism".into(),
        8453 => "base".into(),
        42161 => "arbitrum".into(),
        137 => "polygon".into(),
        other => format!("chain-{other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_known_chains_map() {
        for id in [1, 10, 8453, 42161, 137] {
            assert!(blockscout_base(id).unwrap().starts_with("https://"));
            assert!(!chain_name(id).is_empty());
        }
        assert_eq!(blockscout_base(10), Some("https://explorer.optimism.io/api/v2"));
        assert_eq!(blockscout_base(137), Some("https://polygon.blockscout.com/api/v2"));
        assert_eq!(chain_name(1), "ethereum");
        assert_eq!(chain_name(10), "optimism");
        assert_eq!(chain_name(8453), "base");
        assert_eq!(chain_name(137), "polygon");
    }

    #[test]
    fn unknown_chain() {
        assert_eq!(blockscout_base(999999), None);
        assert_eq!(chain_name(999999), "chain-999999");
    }
}
