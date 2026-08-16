//! Security-event topic registry and decoder. Pure: turns an `eth_getLogs`
//! [`LogHit`] into a structured [`Alert`] for proxy-upgrade / ownership / admin
//! changes. No network.

use alloy::primitives::{b256, Address, B256};

use crate::model::Alert;
use crate::rpc::LogHit;

// topic0 = keccak256 of the event signature.
const UPGRADED: B256 = b256!("bc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b");
const BEACON_UPGRADED: B256 =
    b256!("1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e");
const OWNERSHIP_TRANSFERRED: B256 =
    b256!("8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0");
const ADMIN_CHANGED: B256 =
    b256!("7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f");
// OpenZeppelin AccessControl: role(indexed), account(indexed), sender(indexed).
const ROLE_GRANTED: B256 =
    b256!("2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d");
const ROLE_REVOKED: B256 =
    b256!("f6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b");
// OpenZeppelin Pausable: account is NOT indexed (data word 0).
const PAUSED: B256 = b256!("62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258");
const UNPAUSED: B256 = b256!("5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa");
// ERC-20/721 Transfer: from(indexed), to(indexed), value/tokenId. For ERC-20 the
// value is a non-indexed data word; for ERC-721 tokenId is indexed (data empty).
const TRANSFER: B256 = b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// The default set of security-relevant topics `monitor` scans for (proxy upgrade,
/// ownership/admin, access-control role grant/revoke, pause/unpause). `Transfer`
/// is intentionally excluded (high-volume) — added only when `--min-transfer` is set.
pub fn default_alert_topics() -> Vec<B256> {
    vec![
        UPGRADED,
        BEACON_UPGRADED,
        OWNERSHIP_TRANSFERRED,
        ADMIN_CHANGED,
        ROLE_GRANTED,
        ROLE_REVOKED,
        PAUSED,
        UNPAUSED,
    ]
}

/// topic0 of ERC-20 `Transfer` — opt-in (large-transfer monitoring via `--min-transfer`).
pub fn transfer_topic() -> B256 {
    TRANSFER
}

/// Decode a log into an [`Alert`] when its topic0 is a recognised security event.
/// Returns `None` for logs whose topic0 isn't in the registry (so custom
/// `--alert-topic`s without a decoder fall through to [`unknown_alert`]).
pub fn parse_alert(log: &LogHit) -> Option<Alert> {
    let t0 = *log.topics.first()?;
    if t0 == UPGRADED || t0 == BEACON_UPGRADED {
        let event = if t0 == UPGRADED { "Upgraded" } else { "BeaconUpgraded" };
        Some(base(log, event, "proxy-upgrade", topic_addr(log, 1), None))
    } else if t0 == OWNERSHIP_TRANSFERRED {
        Some(base(
            log,
            "OwnershipTransferred",
            "ownership",
            topic_addr(log, 2), // new owner (indexed)
            topic_addr(log, 1), // previous owner (indexed)
        ))
    } else if t0 == ADMIN_CHANGED {
        Some(base(
            log,
            "AdminChanged",
            "admin",
            data_word_addr(log, 1), // new admin (non-indexed)
            data_word_addr(log, 0), // previous admin (non-indexed)
        ))
    } else if t0 == ROLE_GRANTED || t0 == ROLE_REVOKED {
        let (event, kind) = if t0 == ROLE_GRANTED {
            ("RoleGranted", "role-granted")
        } else {
            ("RoleRevoked", "role-revoked")
        };
        Some(base(
            log,
            event,
            kind,
            topic_addr(log, 2), // account (indexed) — who gained/lost the role
            topic_addr(log, 3), // sender (indexed) — who made the change
        ))
    } else if t0 == PAUSED || t0 == UNPAUSED {
        let (event, kind) = if t0 == PAUSED { ("Paused", "paused") } else { ("Unpaused", "unpaused") };
        Some(base(log, event, kind, data_word_addr(log, 0), None)) // account (non-indexed)
    } else if t0 == TRANSFER {
        // ERC-20 value is the non-indexed data word 0; ERC-721 (tokenId indexed,
        // data empty) yields None so a `--min-transfer` threshold filters it out.
        let mut a = base(
            log,
            "Transfer",
            "large-transfer",
            topic_addr(log, 2), // to (indexed)
            topic_addr(log, 1), // from (indexed)
        );
        a.amount = data_word_u256(log, 0).map(|v| v.to_string());
        Some(a)
    } else {
        None
    }
}

/// Build an [`Alert`] for a topic the user explicitly asked to watch
/// (`--alert-topic`) but that has no dedicated decoder.
pub fn unknown_alert(log: &LogHit) -> Alert {
    base(log, "unknown", "unknown", None, None)
}

fn base(
    log: &LogHit,
    event: &str,
    kind: &str,
    new_value: Option<String>,
    previous: Option<String>,
) -> Alert {
    Alert {
        block: log.block,
        chain_id: 0, // set by the caller (run_monitor) per chain
        contract: fmt_addr(log.address),
        event: event.to_string(),
        kind: kind.to_string(),
        new_value,
        previous,
        tx_hash: log.tx_hash.map(|h| format!("{h:#x}")),
        log_index: log.log_index,
        amount: None,
        risk_score: None,
        grade: None,
    }
}

/// Address from an indexed topic (low 20 bytes of the 32-byte word).
fn topic_addr(log: &LogHit, i: usize) -> Option<String> {
    let t = log.topics.get(i)?;
    Some(fmt_addr(Address::from_word(*t)))
}

/// Address from a non-indexed 32-byte data word at index `i`.
fn data_word_addr(log: &LogHit, i: usize) -> Option<String> {
    let start = i * 32;
    let word = log.data.get(start..start + 32)?;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(word);
    Some(fmt_addr(Address::from_word(buf.into())))
}

/// `U256` from a non-indexed 32-byte data word at index `i` (None if data too short,
/// e.g. an ERC-721 Transfer whose tokenId is indexed and data is empty).
fn data_word_u256(log: &LogHit, i: usize) -> Option<alloy::primitives::U256> {
    let start = i * 32;
    let word = log.data.get(start..start + 32)?;
    Some(alloy::primitives::U256::from_be_slice(word))
}

fn fmt_addr(a: Address) -> String {
    format!("{a:#x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Bytes;

    fn word_addr(byte: u8) -> B256 {
        // 32-byte word whose low 20 bytes encode an address of repeated `byte`.
        let mut w = [0u8; 32];
        for b in w.iter_mut().skip(12) {
            *b = byte;
        }
        B256::from(w)
    }

    fn log(topics: Vec<B256>, data: Vec<u8>) -> LogHit {
        LogHit {
            block: 42,
            address: Address::repeat_byte(0xab),
            topics,
            data: Bytes::from(data),
            tx_hash: Some(B256::repeat_byte(0xcd)),
            log_index: Some(0),
        }
    }

    #[test]
    fn default_topics_are_eight_and_exclude_transfer() {
        let topics = default_alert_topics();
        assert_eq!(topics.len(), 8);
        // Transfer is opt-in (high volume), never in the default set.
        assert!(!topics.contains(&TRANSFER));
        assert_eq!(transfer_topic(), TRANSFER);
    }

    #[test]
    fn topic0_hashes_match_signatures() {
        use alloy::primitives::keccak256;
        // Self-verify every topic0 against keccak256(signature) — a wrong literal
        // fails here and prints the correct value.
        assert_eq!(UPGRADED, keccak256(b"Upgraded(address)"));
        assert_eq!(BEACON_UPGRADED, keccak256(b"BeaconUpgraded(address)"));
        assert_eq!(OWNERSHIP_TRANSFERRED, keccak256(b"OwnershipTransferred(address,address)"));
        assert_eq!(ADMIN_CHANGED, keccak256(b"AdminChanged(address,address)"));
        assert_eq!(ROLE_GRANTED, keccak256(b"RoleGranted(bytes32,address,address)"));
        assert_eq!(ROLE_REVOKED, keccak256(b"RoleRevoked(bytes32,address,address)"));
        assert_eq!(PAUSED, keccak256(b"Paused(address)"));
        assert_eq!(UNPAUSED, keccak256(b"Unpaused(address)"));
        assert_eq!(TRANSFER, keccak256(b"Transfer(address,address,uint256)"));
    }

    #[test]
    fn decodes_role_granted_and_revoked() {
        let role = B256::repeat_byte(0x01);
        let g = parse_alert(&log(vec![ROLE_GRANTED, role, word_addr(0xaa), word_addr(0xbb)], vec![])).unwrap();
        assert_eq!(g.event, "RoleGranted");
        assert_eq!(g.kind, "role-granted");
        assert_eq!(g.new_value.as_deref(), Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // account
        assert_eq!(g.previous.as_deref(), Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")); // sender
        let r = parse_alert(&log(vec![ROLE_REVOKED, role, word_addr(0xaa), word_addr(0xbb)], vec![])).unwrap();
        assert_eq!(r.event, "RoleRevoked");
        assert_eq!(r.kind, "role-revoked");
    }

    #[test]
    fn decodes_paused_and_unpaused_from_data() {
        // account is non-indexed -> data word 0.
        let mut data = vec![0u8; 32];
        for b in data[12..32].iter_mut() {
            *b = 0x55;
        }
        let p = parse_alert(&log(vec![PAUSED], data.clone())).unwrap();
        assert_eq!(p.event, "Paused");
        assert_eq!(p.kind, "paused");
        assert_eq!(p.new_value.as_deref(), Some("0x5555555555555555555555555555555555555555"));
        let u = parse_alert(&log(vec![UNPAUSED], data)).unwrap();
        assert_eq!(u.event, "Unpaused");
        assert_eq!(u.kind, "unpaused");
    }

    #[test]
    fn decodes_erc20_transfer_value_and_skips_erc721() {
        // ERC-20: from/to indexed, value = data word 0 = 1000.
        let mut data = vec![0u8; 32];
        data[31] = 0xe8;
        data[30] = 0x03; // 0x03e8 = 1000
        let t = parse_alert(&log(vec![TRANSFER, word_addr(0xaa), word_addr(0xbb)], data)).unwrap();
        assert_eq!(t.event, "Transfer");
        assert_eq!(t.kind, "large-transfer");
        assert_eq!(t.previous.as_deref(), Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // from
        assert_eq!(t.new_value.as_deref(), Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")); // to
        assert_eq!(t.amount.as_deref(), Some("1000"));
        // ERC-721: tokenId indexed (4 topics), data empty -> amount None.
        let nft = parse_alert(&log(vec![TRANSFER, word_addr(0xaa), word_addr(0xbb), B256::repeat_byte(0x07)], vec![])).unwrap();
        assert!(nft.amount.is_none());
    }

    #[test]
    fn decodes_upgraded() {
        let a = parse_alert(&log(vec![UPGRADED, word_addr(0x11)], vec![])).unwrap();
        assert_eq!(a.event, "Upgraded");
        assert_eq!(a.kind, "proxy-upgrade");
        assert_eq!(a.new_value.as_deref(), Some("0x1111111111111111111111111111111111111111"));
        assert!(a.previous.is_none());
        assert_eq!(a.contract, "0xabababababababababababababababababababab");
        assert!(a.tx_hash.is_some());
        assert_eq!(a.block, 42);
    }

    #[test]
    fn decodes_beacon_upgraded() {
        let a = parse_alert(&log(vec![BEACON_UPGRADED, word_addr(0x22)], vec![])).unwrap();
        assert_eq!(a.event, "BeaconUpgraded");
        assert_eq!(a.new_value.as_deref(), Some("0x2222222222222222222222222222222222222222"));
    }

    #[test]
    fn decodes_ownership_transferred() {
        let a = parse_alert(&log(
            vec![OWNERSHIP_TRANSFERRED, word_addr(0xaa), word_addr(0xbb)],
            vec![],
        ))
        .unwrap();
        assert_eq!(a.event, "OwnershipTransferred");
        assert_eq!(a.kind, "ownership");
        assert_eq!(a.previous.as_deref(), Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(a.new_value.as_deref(), Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    }

    #[test]
    fn decodes_admin_changed_from_data() {
        // Non-indexed: data = prevAdmin(32) ++ newAdmin(32).
        let mut data = vec![0u8; 64];
        for b in data[12..32].iter_mut() {
            *b = 0x33;
        }
        for b in data[44..64].iter_mut() {
            *b = 0x44;
        }
        let a = parse_alert(&log(vec![ADMIN_CHANGED], data)).unwrap();
        assert_eq!(a.event, "AdminChanged");
        assert_eq!(a.kind, "admin");
        assert_eq!(a.previous.as_deref(), Some("0x3333333333333333333333333333333333333333"));
        assert_eq!(a.new_value.as_deref(), Some("0x4444444444444444444444444444444444444444"));
    }

    #[test]
    fn unknown_topic_is_none_but_unknown_alert_works() {
        let other = B256::repeat_byte(0x99);
        assert!(parse_alert(&log(vec![other], vec![])).is_none());
        // Empty topics -> None (no topic0).
        assert!(parse_alert(&log(vec![], vec![])).is_none());
        // Explicit unknown alert still produces a record.
        let u = unknown_alert(&log(vec![other], vec![]));
        assert_eq!(u.event, "unknown");
        assert!(u.new_value.is_none());
    }

    #[test]
    fn missing_indexed_or_data_fields_degrade_to_none() {
        // Upgraded without the implementation topic -> new_value None, still an alert.
        let a = parse_alert(&log(vec![UPGRADED], vec![])).unwrap();
        assert!(a.new_value.is_none());
        // AdminChanged with short data -> fields None.
        let a = parse_alert(&log(vec![ADMIN_CHANGED], vec![0u8; 10])).unwrap();
        assert!(a.new_value.is_none() && a.previous.is_none());
    }
}
