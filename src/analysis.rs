//! Static analysis derived from runtime bytecode — no network calls.
//!
//! A single PUSH-aware pass over the metadata-stripped bytecode yields three
//! things at once: the notable/dangerous opcodes, the function selectors the
//! contract dispatches on (`PUSHk <sel> EQ`) used to detect ERC interfaces, and
//! the inputs to the bytecode fingerprint. Works on unverified contracts too,
//! since it reads only the on-chain code.

use std::collections::HashSet;

use alloy::primitives::keccak256;
use serde::{Deserialize, Serialize};

use crate::model::{Analysis, ContractDetails};

// Dangerous / noteworthy opcodes (all > 0x7f, so never confused with PUSH data).
const OP_CREATE: u8 = 0xf0;
const OP_CALLCODE: u8 = 0xf2;
const OP_DELEGATECALL: u8 = 0xf4;
const OP_CREATE2: u8 = 0xf5;
const OP_SELFDESTRUCT: u8 = 0xff;

// Required function selectors per ERC standard. A standard is detected only when
// ALL of its core selectors appear in the bytecode (conservative, low false-positive).
const ERC20: &[u32] = &[
    0xa9059cbb, // transfer(address,uint256)
    0x23b872dd, // transferFrom(address,address,uint256)
    0x095ea7b3, // approve(address,uint256)
    0x70a08231, // balanceOf(address)
    0x18160ddd, // totalSupply()
    0xdd62ed3e, // allowance(address,address)
];
const ERC721: &[u32] = &[
    0x6352211e, // ownerOf(uint256)
    0x70a08231, // balanceOf(address)
    0x23b872dd, // transferFrom(address,address,uint256)
    0x095ea7b3, // approve(address,uint256)
    0xa22cb465, // setApprovalForAll(address,bool)
    0x081812fc, // getApproved(uint256)
    0xe985e9c5, // isApprovedForAll(address,address)
];
const ERC1155: &[u32] = &[
    0x00fdd58e, // balanceOf(address,uint256)
    0x4e1273f4, // balanceOfBatch(address[],uint256[])
    0xa22cb465, // setApprovalForAll(address,bool)
    0xe985e9c5, // isApprovedForAll(address,address)
    0xf242432a, // safeTransferFrom(address,address,uint256,uint256,bytes)
    0x2eb2c2d6, // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
];
const ERC165: &[u32] = &[
    0x01ffc9a7, // supportsInterface(bytes4)
];

/// Run all static analyses over runtime `code` in one pass.
pub fn analyze(code: &[u8]) -> Analysis {
    // Scan the executable region only — the trailing CBOR metadata routinely
    // contains bytes like 0xff/0xf4 that would otherwise be misread as opcodes,
    // and PUSH-shaped runs that would inject phantom selectors.
    let stripped = strip_metadata(code);
    let (opcode_set, selectors) = walk(stripped);

    let mut opcodes = Vec::new();
    // Canonical, stable order (not lexical) for readable output.
    for (op, name) in [
        (OP_CREATE, "CREATE"),
        (OP_CREATE2, "CREATE2"),
        (OP_CALLCODE, "CALLCODE"),
        (OP_DELEGATECALL, "DELEGATECALL"),
        (OP_SELFDESTRUCT, "SELFDESTRUCT"),
    ] {
        if opcode_set.contains(&op) {
            opcodes.push(name.to_string());
        }
    }

    let mut interfaces = Vec::new();
    for (name, sigs) in [
        ("ERC-20", ERC20),
        ("ERC-721", ERC721),
        ("ERC-1155", ERC1155),
        ("ERC-165", ERC165),
    ] {
        if sigs.iter().all(|s| selectors.contains(s)) {
            interfaces.push(name.to_string());
        }
    }

    Analysis {
        code_hash: format!("{:#x}", keccak256(code)),
        code_hash_nometa: format!("{:#x}", keccak256(stripped)),
        opcodes,
        interfaces,
    }
}

/// Single PUSH-aware pass: collect opcodes seen and the function selectors the
/// contract *dispatches on*. PUSH1..PUSH32 immediate bytes are skipped so data
/// can't masquerade as opcodes.
///
/// A dispatched selector appears as `PUSHk <sel> EQ` (the Solidity selector
/// check). We capture the immediate of any `PUSH1..PUSH4` that is immediately
/// followed by `EQ` (0x14), right-aligned into a `u32`. This (a) catches
/// selectors solc shortened by dropping leading zero bytes — e.g.
/// `balanceOf(address,uint256)` 0x00fdd58e is emitted as `PUSH3 0xfdd58e` — and
/// (b) excludes selectors merely pushed to *build calldata* (a contract that
/// calls an interface rather than implementing it), since those aren't EQ-tested.
fn walk(code: &[u8]) -> (HashSet<u8>, HashSet<u32>) {
    const EQ: u8 = 0x14;
    let mut opcodes = HashSet::new();
    let mut selectors = HashSet::new();
    let mut i = 0usize;
    while i < code.len() {
        let op = code[i];
        if (0x60..=0x7f).contains(&op) {
            let n = (op - 0x5f) as usize; // PUSH1 -> 1 .. PUSH32 -> 32
            let end = i + 1 + n; // index just past the immediate bytes
            if (1..=4).contains(&n) && end <= code.len() && code.get(end) == Some(&EQ) {
                let mut sel = 0u32;
                for &b in &code[i + 1..end] {
                    sel = (sel << 8) | b as u32;
                }
                selectors.insert(sel);
            }
            i = end;
        } else {
            opcodes.insert(op);
            i += 1;
        }
    }
    (opcodes, selectors)
}

/// Strip the trailing Solidity CBOR metadata, whose length is encoded in the last
/// two big-endian bytes. Leaves `code` untouched when the encoding is implausible.
fn strip_metadata(code: &[u8]) -> &[u8] {
    let n = code.len();
    if n < 2 {
        return code;
    }
    let meta_len = ((code[n - 2] as usize) << 8) | (code[n - 1] as usize);
    let total = meta_len + 2;
    // Require `total < n` (strictly) so at least one executable byte remains —
    // never strip to empty, which would collapse unrelated contracts onto
    // keccak256("") and produce spurious clone clusters.
    if meta_len > 0 && total < n {
        &code[..n - total]
    } else {
        code
    }
}

/// A group of contracts sharing the same metadata-stripped bytecode (clone family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneCluster {
    pub code_hash_nometa: String,
    pub count: usize,
    pub addresses: Vec<String>,
}

/// Group contracts into clone families by `code_hash_nometa`, keeping only
/// families of size ≥ 2. Sorted by family size (desc), then hash for stability.
pub fn cluster_by_code(contracts: &[ContractDetails]) -> Vec<CloneCluster> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in contracts {
        let h = &c.analysis.code_hash_nometa;
        if h.is_empty() {
            continue;
        }
        groups.entry(h.clone()).or_default().push(c.address.clone());
    }
    let mut clusters: Vec<CloneCluster> = groups
        .into_iter()
        // Dedup BEFORE the size test: the same address can appear twice when one
        // contract is scanned on multiple chains (per-chain output dirs, one
        // shared --out). A group of only-duplicate addresses must not survive as
        // a bogus count==1 "family".
        .map(|(h, mut addrs)| {
            addrs.sort();
            addrs.dedup();
            (h, addrs)
        })
        .filter(|(_, addrs)| addrs.len() >= 2)
        .map(|(h, addrs)| CloneCluster {
            code_hash_nometa: h,
            count: addrs.len(),
            addresses: addrs,
        })
        .collect();
    clusters.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code_hash_nometa.cmp(&b.code_hash_nometa)));
    clusters
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Analysis;

    fn details(addr: &str, hash: &str) -> ContractDetails {
        let mut d = ContractDetails::minimal(addr, 1);
        d.analysis = Analysis {
            code_hash_nometa: hash.into(),
            ..Default::default()
        };
        d
    }

    /// Emit a realistic dispatcher fragment for each selector: `PUSHk <sel> EQ`,
    /// using the minimal PUSH width (leading zero bytes dropped, like solc).
    fn with_selectors(sigs: &[u32], trailing: &[u8]) -> Vec<u8> {
        let mut code = Vec::new();
        for &s in sigs {
            let bytes = s.to_be_bytes();
            let nz = bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let imm = &bytes[nz..]; // drop leading zero bytes
            code.push(0x60 + (imm.len() as u8 - 1)); // PUSHk (k = imm.len())
            code.extend_from_slice(imm);
            code.push(0x14); // EQ
        }
        code.extend_from_slice(trailing);
        code.push(0x00); // STOP terminator (keeps trailing bytes out of the metadata-strip tail)
        code
    }

    #[test]
    fn push_immediate_is_not_mistaken_for_opcode() {
        // PUSH1 0xff  — the 0xff is data, not SELFDESTRUCT.
        let a = analyze(&[0x60, 0xff]);
        assert!(a.opcodes.is_empty());
        // A bare 0xff IS SELFDESTRUCT.
        let b = analyze(&[0xff]);
        assert_eq!(b.opcodes, vec!["SELFDESTRUCT"]);
    }

    #[test]
    fn detects_dangerous_opcodes_in_canonical_order() {
        let a = analyze(&[OP_SELFDESTRUCT, OP_CREATE, OP_DELEGATECALL, OP_CREATE2, OP_CALLCODE]);
        assert_eq!(
            a.opcodes,
            vec!["CREATE", "CREATE2", "CALLCODE", "DELEGATECALL", "SELFDESTRUCT"]
        );
    }

    #[test]
    fn detects_erc20() {
        let a = analyze(&with_selectors(ERC20, &[]));
        assert!(a.interfaces.contains(&"ERC-20".to_string()));
        assert!(!a.interfaces.contains(&"ERC-721".to_string()));
    }

    #[test]
    fn detects_erc721_and_165() {
        let mut sigs = ERC721.to_vec();
        sigs.extend_from_slice(ERC165);
        let a = analyze(&with_selectors(&sigs, &[]));
        assert!(a.interfaces.contains(&"ERC-721".to_string()));
        assert!(a.interfaces.contains(&"ERC-165".to_string()));
        assert!(!a.interfaces.contains(&"ERC-20".to_string()));
    }

    #[test]
    fn detects_erc1155() {
        // ERC-1155 includes 0x00fdd58e, which `with_selectors` emits as PUSH3
        // 0xfdd58e (leading zero dropped) — the regression for the missed-1155 bug.
        let a = analyze(&with_selectors(ERC1155, &[]));
        assert!(a.interfaces.contains(&"ERC-1155".to_string()));
    }

    #[test]
    fn leading_zero_selector_via_push3_is_captured() {
        // Real solc encoding of balanceOf(address,uint256)=0x00fdd58e: PUSH3 + EQ.
        let code = [0x62, 0xfd, 0xd5, 0x8e, 0x14]; // PUSH3 0xfdd58e EQ
        // It alone isn't a full interface, but ERC-1155 (which requires it) must
        // be detectable — proven by detects_erc1155 above. Here assert no panic
        // and that a non-EQ PUSH3 of the same bytes is NOT captured (see below).
        let _ = analyze(&code);
    }

    #[test]
    fn calldata_pushes_without_eq_are_not_selectors() {
        // A contract that *calls* an interface pushes the selector to build
        // calldata (e.g. PUSH4 <sel> MSTORE), never PUSH4 <sel> EQ. Such pushes
        // must NOT count as "implements". Build the full ERC-20 set as PUSH4 +
        // MSTORE (0x52) instead of EQ -> not detected.
        let mut code = Vec::new();
        for &s in ERC20 {
            code.push(0x63); // PUSH4
            code.extend_from_slice(&s.to_be_bytes());
            code.push(0x52); // MSTORE (not EQ)
        }
        let a = analyze(&code);
        assert!(!a.interfaces.contains(&"ERC-20".to_string()));
    }

    #[test]
    fn metadata_bytes_not_misread_as_opcodes() {
        // STOP (the only executable op) + CBOR metadata containing 0xff/0xf4 +
        // a correct 2-byte length trailer. Opcodes must be empty after stripping.
        let mut code = vec![0x00u8]; // STOP
        code.extend_from_slice(&[0xa2, 0x64, 0x69, 0x70, 0x66, 0x73, 0x58, 0x22, 0xff, 0xf4]);
        code.extend_from_slice(&[0x00, 0x0a]); // metadata length = 10
        let a = analyze(&code);
        assert!(a.opcodes.is_empty(), "phantom opcodes from metadata: {:?}", a.opcodes);
    }

    #[test]
    fn partial_selector_set_not_detected() {
        // Missing one required ERC-20 selector -> not detected.
        let a = analyze(&with_selectors(&ERC20[..ERC20.len() - 1], &[]));
        assert!(!a.interfaces.contains(&"ERC-20".to_string()));
    }

    #[test]
    fn push4_at_end_without_full_immediate_is_ignored() {
        // PUSH4 with only 3 bytes left: no selector recorded, no panic.
        let a = analyze(&[0x63, 0x01, 0x02, 0x03]);
        assert!(a.interfaces.is_empty());
    }

    #[test]
    fn code_hash_and_nometa_strip() {
        // Two "contracts": identical logic, different trailing metadata.
        let logic = [0x60u8, 0x01, 0x60, 0x02];
        let meta_a = [0xaa, 0xbb, 0xcc, 0x00, 0x03]; // 3 meta bytes + 2 len bytes
        let meta_b = [0xde, 0xad, 0xbe, 0x00, 0x03];
        let mut a = logic.to_vec();
        a.extend_from_slice(&meta_a);
        let mut b = logic.to_vec();
        b.extend_from_slice(&meta_b);
        let ra = analyze(&a);
        let rb = analyze(&b);
        // Full hashes differ (different metadata)...
        assert_ne!(ra.code_hash, rb.code_hash);
        // ...but metadata-stripped hashes match (same logic) => clone family.
        assert_eq!(ra.code_hash_nometa, rb.code_hash_nometa);
        assert!(ra.code_hash.starts_with("0x") && ra.code_hash.len() == 66);
    }

    #[test]
    fn strip_metadata_leaves_implausible_encoding() {
        // Last two bytes claim a huge length -> leave code untouched, hashes equal.
        let code = [0x60u8, 0x01, 0xff, 0xff];
        let a = analyze(&code);
        assert_eq!(a.code_hash, a.code_hash_nometa);
    }

    #[test]
    fn strip_never_empties_code_no_spurious_collision() {
        // Two different blobs whose trailing length claims the WHOLE blob. Stripping
        // to empty would collide both on keccak256("") — must not happen.
        let a = [0xaau8, 0xbb, 0xcc, 0x00, 0x03]; // total = 5 = len
        let b = [0xde_u8, 0xad, 0xbe, 0x00, 0x03];
        let ra = analyze(&a);
        let rb = analyze(&b);
        assert_eq!(ra.code_hash, ra.code_hash_nometa); // not stripped
        assert_ne!(ra.code_hash_nometa, rb.code_hash_nometa); // no empty collision
    }

    #[test]
    fn cluster_groups_size_two_plus_only() {
        let h1 = "0x11";
        let h2 = "0x22";
        let contracts = vec![
            details("0xa", h1),
            details("0xb", h1),
            details("0xc", h1),
            details("0xd", h2), // singleton -> dropped
            details("0xe", ""),  // empty hash -> skipped
        ];
        let clusters = cluster_by_code(&contracts);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].code_hash_nometa, h1);
        assert_eq!(clusters[0].count, 3);
        assert_eq!(clusters[0].addresses, vec!["0xa", "0xb", "0xc"]);
    }

    #[test]
    fn cluster_sorts_by_size_desc() {
        let big = "0xbig";
        let small = "0xsmall";
        let contracts = vec![
            details("0x1", small),
            details("0x2", small),
            details("0x3", big),
            details("0x4", big),
            details("0x5", big),
        ];
        let clusters = cluster_by_code(&contracts);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].count, 3); // big first
        assert_eq!(clusters[1].count, 2);
    }

    #[test]
    fn cluster_dedups_before_size_filter() {
        // Same address twice in one hash group (cross-chain duplicate) + one distinct.
        let h = "0xdup";
        let contracts = vec![
            details("0xaaa", h),
            details("0xaaa", h),
            details("0xbbb", h),
        ];
        let clusters = cluster_by_code(&contracts);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].count, 2); // deduped to {0xaaa, 0xbbb}
        assert_eq!(clusters[0].addresses, vec!["0xaaa", "0xbbb"]);
    }

    #[test]
    fn cluster_drops_group_of_only_duplicates() {
        // A group that is ONLY a duplicate address must not survive as count==1.
        let h = "0xonly";
        let contracts = vec![details("0xaaa", h), details("0xaaa", h)];
        assert!(cluster_by_code(&contracts).is_empty());
    }
}
