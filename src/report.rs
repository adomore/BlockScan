//! Human-readable, normalized table output for contract details.

use crate::enrich::Enrichment;
use crate::model::{Audit, ContractDetails};

const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;

/// Format a wei amount (decimal string) as ETH with 6 decimals and thousands
/// separators, e.g. `"51272692007008651583944"` -> `"51,272.692007 ETH"`.
/// Falls back to raw wei if the value doesn't fit in `u128`.
pub fn format_eth(wei: &str) -> String {
    match wei.parse::<u128>() {
        Ok(w) => {
            let whole = w / WEI_PER_ETH;
            let micro = (w % WEI_PER_ETH) / 1_000_000_000_000; // 6 decimal places
            format!("{}.{:06} ETH", group_thousands(whole), micro)
        }
        Err(_) => format!("{wei} wei"),
    }
}

/// Insert commas as thousands separators into a non-negative integer.
fn group_thousands(n: u128) -> String {
    let digits = n.to_string();
    let len = digits.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Render a single contract's details as an aligned table with Chinese labels.
///
/// Alignment is computed by *display width* (CJK characters count as 2 columns)
/// so the right border stays straight regardless of Chinese labels/values.
pub fn render_contract_table(d: &ContractDetails, enrich: &Enrichment) -> String {
    let dash = || "-".to_string();
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(dash);
    let proxy = if d.is_proxy {
        let kind = d.proxy_kind.as_deref().unwrap_or("proxy");
        match &d.implementation {
            Some(impl_addr) => format!("是 [{kind}] -> {impl_addr}"),
            None => format!("是 [{kind}]"),
        }
    } else {
        "否".to_string()
    };

    let rows: Vec<(&str, String)> = vec![
        ("地址", d.address.clone()),
        (
            "合约名",
            d.contract_name.clone().unwrap_or_else(|| "（未验证）".into()),
        ),
        ("名称标签", opt(&enrich.name_tag)),
        ("项目URL", opt(&enrich.project_url)),
        ("已验证", yes_no(d.is_verified)),
        ("验证来源", opt(&d.verified_via)),
        ("编译器", d.compiler_version.clone().unwrap_or_else(dash)),
        ("EVM 版本", d.evm_version.clone().unwrap_or_else(dash)),
        ("许可证", d.license_type.clone().unwrap_or_else(dash)),
        ("代理", proxy),
        ("余额", format_eth(&d.balance_wei)),
        ("代币持仓", opt(&enrich.holdings)),
        ("创建者", d.creator.clone().unwrap_or_else(dash)),
        ("创建交易", d.creation_tx_hash.clone().unwrap_or_else(dash)),
        ("字节码大小", format!("{} 字节", d.bytecode_size)),
        ("ABI", yes_no(d.has_abi)),
        ("源码文件数", d.source_file_count.to_string()),
        ("接口", join_or_dash(&d.analysis.interfaces)),
        ("风险操作码", join_or_dash(&d.analysis.opcodes)),
        ("代码哈希", short_hash(&d.analysis.code_hash_nometa)),
        ("安全评分", audit_score_cell(&d.audit)),
        ("漏洞", audit_findings_cell(&d.audit)),
        ("链 ID", d.chain_id.to_string()),
    ];

    let key_w = rows.iter().map(|(k, _)| display_width(k)).max().unwrap_or(0);
    let val_w = rows.iter().map(|(_, v)| display_width(v)).max().unwrap_or(0);
    let sep = format!("+-{}-+-{}-+", "-".repeat(key_w), "-".repeat(val_w));

    let mut out = String::new();
    out.push_str(&sep);
    out.push('\n');
    for (k, v) in &rows {
        out.push_str(&format!("| {} | {} |\n", pad(k, key_w), pad(v, val_w)));
    }
    out.push_str(&sep);
    out
}

fn yes_no(b: bool) -> String {
    if b {
        "是".to_string()
    } else {
        "否".to_string()
    }
}

/// Join a list with `, `, or a dash when empty.
fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

/// Risk cell: `D 45/100 (High)`, or a dash when the audit didn't run.
fn audit_score_cell(a: &Option<Audit>) -> String {
    match a {
        Some(a) => format!("{} {}/100 ({})", a.grade, a.risk_score, a.risk_level),
        None => "-".to_string(),
    }
}

/// Findings cell: severity tally like `high×2, medium×1`, or `无` / `-`.
fn audit_findings_cell(a: &Option<Audit>) -> String {
    let Some(a) = a else { return "-".to_string() };
    if a.findings.is_empty() {
        return "无".to_string();
    }
    let mut parts = Vec::new();
    for sev in ["critical", "high", "medium", "low", "info"] {
        // Engine severities are capitalized (`High`); compare case-insensitively
        // so the tally isn't silently empty for real findings.
        let n = a.findings.iter().filter(|f| f.severity.eq_ignore_ascii_case(sev)).count();
        if n > 0 {
            parts.push(format!("{sev}×{n}"));
        }
    }
    parts.join(", ")
}

/// Abbreviate a `0x…`-hash to its first 10 hex chars + ellipsis; dash when empty.
fn short_hash(h: &str) -> String {
    if h.is_empty() {
        "-".to_string()
    } else if h.len() > 12 {
        format!("{}…", &h[..12])
    } else {
        h.to_string()
    }
}

/// Display width of one char: CJK/fullwidth characters occupy 2 terminal columns.
fn char_width(c: char) -> usize {
    let u = c as u32;
    let wide = (0x1100..=0x115F).contains(&u)      // Hangul Jamo
        || (0x2E80..=0xA4CF).contains(&u)          // CJK radicals .. Yi
        || (0xAC00..=0xD7A3).contains(&u)          // Hangul syllables
        || (0xF900..=0xFAFF).contains(&u)          // CJK compatibility ideographs
        || (0xFE30..=0xFE4F).contains(&u)          // CJK compatibility forms
        || (0xFF00..=0xFF60).contains(&u)          // fullwidth forms
        || (0xFFE0..=0xFFE6).contains(&u);
    if wide {
        2
    } else {
        1
    }
}

fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Left-align `s` to display width `w` by appending spaces.
fn pad(s: &str, w: usize) -> String {
    let mut out = s.to_string();
    out.push_str(&" ".repeat(w.saturating_sub(display_width(s))));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details() -> ContractDetails {
        ContractDetails {
            address: "0x000000000004444c5dc75cb358380d2e3de08a90".into(),
            chain_id: 1,
            bytecode: "0x60".into(),
            bytecode_size: 24009,
            balance_wei: "51272692007008651583944".into(),
            is_verified: true,
            contract_name: Some("PoolManager".into()),
            compiler_version: Some("v0.8.26+commit.8a97fa7a".into()),
            optimization_used: Some("1".into()),
            optimization_runs: Some("200".into()),
            evm_version: Some("cancun".into()),
            license_type: Some("MIT".into()),
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: Some("etherscan".into()),
            creator: Some("0x6b93e3bb9c0780c0f9042346ffc379530a5882c1".into()),
            creation_tx_hash: Some("0x747e".into()),
            has_abi: true,
            source_file_count: 44,
            analysis: crate::model::Analysis {
                code_hash: "0x1234567890abcdef".into(),
                code_hash_nometa: "0x1234567890abcdef".into(),
                opcodes: vec!["DELEGATECALL".into(), "CREATE2".into()],
                interfaces: vec!["ERC-20".into()],
            },
            audit: Some(Audit {
                risk_score: 35,
                grade: "D".into(),
                risk_level: "Medium".into(),
                findings: vec![crate::model::SecurityFinding {
                    rule_id: "TX_ORIGIN_AUTH".into(),
                    title: "Use of tx.origin".into(),
                    category: "SC01:Access Control".into(),
                    swc: Some("SWC-115".into()),
                    scwe: None,
                    ethtrust: None,
                    severity: "High".into(), // production-shaped (capitalized)
                    confidence: "Medium".into(),
                    impact_score: 7,
                    likelihood_score: 5,
                    exploitability: "Moderate".into(),
                    asset_at_risk: "funds".into(),
                    blast_radius: "user-funds".into(),
                    risk: 26,
                    priority: "P1".into(),
                    detection: "source".into(),
                    affected_contract: "0x..".into(),
                    locations: vec!["C.sol:3".into()],
                    evidence: "tx.origin".into(),
                    exploit_scenario: "s".into(),
                    recommendation: "r".into(),
                    references: vec![],
                    false_positive_notes: "".into(),
                }],
                summary: Default::default(),
            }),
        }
    }

    #[test]
    fn format_eth_normal() {
        assert_eq!(format_eth("51272692007008651583944"), "51,272.692007 ETH");
        assert_eq!(format_eth("0"), "0.000000 ETH");
        assert_eq!(format_eth("1000000000000000000"), "1.000000 ETH");
    }

    #[test]
    fn format_eth_overflow_falls_back_to_wei() {
        let huge = "9".repeat(40); // exceeds u128
        assert!(format_eth(&huge).ends_with(" wei"));
    }

    #[test]
    fn group_thousands_inserts_commas() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1234567), "1,234,567");
    }

    #[test]
    fn render_table_verified_contains_fields() {
        let enrich = Enrichment {
            name_tag: Some("Uniswap V4: PoolManager".into()),
            project_url: Some("https://uniswap.org".into()),
            holdings: Some("WBTC(~$32.3M)".into()),
        };
        let t = render_contract_table(&details(), &enrich);
        assert!(t.contains("PoolManager"));
        assert!(t.contains("51,272.692007 ETH"));
        assert!(t.contains("源码文件数"));
        assert!(t.contains("24009 字节"));
        assert!(t.contains("| 代理"));
        assert!(t.contains("名称标签") && t.contains("Uniswap V4: PoolManager"));
        assert!(t.contains("项目URL") && t.contains("https://uniswap.org"));
        assert!(t.contains("代币持仓") && t.contains("WBTC(~$32.3M)"));
        // Analysis rows.
        assert!(t.contains("接口") && t.contains("ERC-20"));
        assert!(t.contains("风险操作码") && t.contains("DELEGATECALL"));
        assert!(t.contains("代码哈希") && t.contains("0x1234567890"));
        // Audit rows.
        assert!(t.contains("安全评分") && t.contains("D 35/100 (Medium)"));
        assert!(t.contains("漏洞") && t.contains("high×1"));
        // Well-formed box: first and last lines are identical separators.
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.first(), lines.last());
        assert!(lines[0].starts_with('+'));
        // Every data row's right border aligns at the same display column.
        let widths: Vec<usize> = lines.iter().map(|l| display_width(l)).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "rows misaligned: {widths:?}");
    }

    #[test]
    fn render_table_unverified_and_proxy() {
        let mut d = details();
        d.is_verified = false;
        d.contract_name = None;
        d.compiler_version = None;
        d.is_proxy = true;
        d.implementation = Some("0ximpl".into());
        d.has_abi = false;
        let t = render_contract_table(&d, &Enrichment::default());
        assert!(t.contains("（未验证）"));
        assert!(t.contains("0ximpl") && t.contains("是 ["));
        // Enrichment empty -> placeholders.
        assert!(t.contains("名称标签") && t.contains("项目URL") && t.contains("代币持仓"));
    }

    #[test]
    fn render_table_proxy_without_impl() {
        let mut d = details();
        d.is_proxy = true;
        d.implementation = None;
        let t = render_contract_table(&d, &Enrichment::default());
        // "是" with no arrow when implementation is unknown.
        assert!(t
            .lines()
            .any(|l| l.contains("代理") && l.contains("是") && !l.contains("->")));
    }

    #[test]
    fn analysis_cell_helpers() {
        assert_eq!(join_or_dash(&[]), "-");
        assert_eq!(join_or_dash(&["a".to_string(), "b".to_string()]), "a, b");
        assert_eq!(short_hash(""), "-");
        assert_eq!(short_hash("0x1234"), "0x1234");
        assert_eq!(short_hash("0x1234567890abcdef"), "0x1234567890…");
    }

    #[test]
    fn audit_cells_handle_none_and_empty() {
        assert_eq!(audit_score_cell(&None), "-");
        assert_eq!(audit_findings_cell(&None), "-");
        // Audit ran but found nothing -> "无".
        let clean = Audit::default();
        assert_eq!(audit_findings_cell(&Some(clean)), "无");
    }

    #[test]
    fn display_width_counts_cjk_as_two() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("源码文件数"), 10);
        assert_eq!(display_width("EVM 版本"), 4 + 4); // "EVM " = 4, "版本" = 4
    }
}
