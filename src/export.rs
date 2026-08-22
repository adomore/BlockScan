//! Summary manifest export of all saved contracts.
//!
//! Two audiences, two shapes. `.json` / `.csv` / `.ndjson` feed a pipeline;
//! `.md` and `.html` produce a document a person reads, forwards or files, and
//! carry the audit itself rather than a row per contract.

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{AppError, Result};
use crate::model::{Audit, ContractDetails, SecurityFinding};

/// Output shape, chosen by the manifest path's extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Csv,
    Markdown,
    Html,
    /// Named only to refuse it. See [`write_manifest`].
    Pdf,
}

fn format_for(path: &Path) -> Format {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        e if e.eq_ignore_ascii_case("csv") => Format::Csv,
        e if e.eq_ignore_ascii_case("md") || e.eq_ignore_ascii_case("markdown") => Format::Markdown,
        e if e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm") => Format::Html,
        e if e.eq_ignore_ascii_case("pdf") => Format::Pdf,
        _ => Format::Json,
    }
}

/// Write a manifest of `contracts` to `path`. Format is chosen by extension:
/// `.csv` → CSV, `.md` → Markdown report, `.html` / `.htm` → one
/// self-contained HTML report, anything else → pretty JSON.
///
/// `.pdf` is refused rather than silently written as JSON. This binary does not
/// produce PDF and will not grow a writer for it: a hand-rolled one is how a
/// report ends up rendering its own body as question marks. The Markdown and
/// the HTML are both inputs to an established pipeline, and the error says so.
pub fn write_manifest(path: &Path, contracts: &[ContractDetails]) -> Result<()> {
    let body = match format_for(path) {
        Format::Csv => render_csv(contracts),
        Format::Markdown => render_markdown(contracts),
        Format::Html => render_html(contracts),
        Format::Json => render_json(contracts)?,
        Format::Pdf => {
            return Err(AppError::Config(
                "PDF is not produced by this tool. Write the report as .md or .html and render \
                 that with an established pipeline (pandoc, or a browser's print-to-PDF on the \
                 self-contained HTML)."
                    .into(),
            ))
        }
    };
    std::fs::write(path, body)?;
    Ok(())
}

/// Pretty-printed JSON array of the contracts.
pub fn render_json(contracts: &[ContractDetails]) -> Result<String> {
    Ok(serde_json::to_string_pretty(contracts)?)
}

/// CSV with a fixed column set (one row per contract).
pub fn render_csv(contracts: &[ContractDetails]) -> String {
    let mut out = String::from(
        "address,chain_id,contract_name,is_verified,verified_via,compiler_version,\
is_proxy,proxy_kind,implementation,balance_wei,creator,creation_tx_hash,\
bytecode_size,has_abi,source_file_count,code_hash_nometa,interfaces,risk_opcodes,\
risk_score,risk_grade,risk_level,findings,top_severity,top_category,owasp\n",
    );
    for d in contracts {
        let cols = [
            d.address.clone(),
            d.chain_id.to_string(),
            d.contract_name.clone().unwrap_or_default(),
            d.is_verified.to_string(),
            d.verified_via.clone().unwrap_or_default(),
            d.compiler_version.clone().unwrap_or_default(),
            d.is_proxy.to_string(),
            d.proxy_kind.clone().unwrap_or_default(),
            d.implementation.clone().unwrap_or_default(),
            d.balance_wei.clone(),
            d.creator.clone().unwrap_or_default(),
            d.creation_tx_hash.clone().unwrap_or_default(),
            d.bytecode_size.to_string(),
            d.has_abi.to_string(),
            d.source_file_count.to_string(),
            d.analysis.code_hash_nometa.clone(),
            d.analysis.interfaces.join(";"),
            d.analysis.opcodes.join(";"),
            d.audit.as_ref().map(|a| a.risk_score.to_string()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.grade.clone()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.risk_level.clone()).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.findings.len().to_string()).unwrap_or_default(),
            d.audit.as_ref().map(top_severity).unwrap_or_default(),
            d.audit.as_ref().map(top_category).unwrap_or_default(),
            d.audit.as_ref().map(|a| a.summary.owasp_categories.join(";")).unwrap_or_default(),
        ];
        out.push_str(&cols.iter().map(|c| csv_escape(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Document report (T-14) — Markdown and self-contained HTML
// ---------------------------------------------------------------------------

/// Severities worst-first. Also the order findings are presented in, so the
/// first thing a reader meets is the worst thing found.
const SEVERITY_ORDER: [&str; 5] = ["Critical", "High", "Medium", "Low", "Info"];

/// What the document says before it says anything about an individual contract.
struct Overview {
    contracts: usize,
    verified: usize,
    proxies: usize,
    audited: usize,
    with_findings: usize,
    by_severity: BTreeMap<&'static str, usize>,
    by_grade: BTreeMap<String, usize>,
    /// The block every record was read at, when they agree on one. `None` means
    /// the records disagree or predate the pin, and the document says so rather
    /// than picking one.
    pinned: Option<(u64, Option<String>)>,
    /// Records carrying an unanswered lookup.
    incomplete: usize,
}

fn overview(contracts: &[ContractDetails]) -> Overview {
    let mut by_severity: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_grade: BTreeMap<String, usize> = BTreeMap::new();
    for sev in SEVERITY_ORDER {
        by_severity.insert(sev, 0);
    }
    for d in contracts {
        if let Some(a) = &d.audit {
            *by_grade.entry(a.grade.clone()).or_default() += 1;
            for f in &a.findings {
                if let Some(sev) = SEVERITY_ORDER.iter().find(|s| s.eq_ignore_ascii_case(&f.severity))
                {
                    // Occurrences, not findings: one finding covers every site
                    // it lists, and a report that counts findings understates
                    // how much code is affected.
                    *by_severity.entry(*sev).or_default() += f.locations.len().max(1);
                }
            }
        }
    }
    let blocks: Vec<u64> = contracts.iter().filter_map(|d| d.block_number).collect();
    let pinned = match blocks.first() {
        Some(first) if blocks.len() == contracts.len() && blocks.iter().all(|b| b == first) => {
            let hash = contracts.iter().find_map(|d| d.block_hash.clone());
            Some((*first, hash))
        }
        _ => None,
    };
    Overview {
        contracts: contracts.len(),
        verified: contracts.iter().filter(|d| d.is_verified).count(),
        proxies: contracts.iter().filter(|d| d.is_proxy).count(),
        audited: contracts.iter().filter(|d| d.audit.is_some()).count(),
        with_findings: contracts
            .iter()
            .filter(|d| d.audit.as_ref().is_some_and(|a| !a.findings.is_empty()))
            .count(),
        by_severity,
        by_grade,
        pinned,
        incomplete: contracts.iter().filter(|d| !d.incomplete.is_empty()).count(),
    }
}

/// A contract's findings, worst first, then by computed risk.
fn ordered_findings(a: &Audit) -> Vec<&SecurityFinding> {
    let rank = |f: &SecurityFinding| {
        SEVERITY_ORDER
            .iter()
            .position(|s| s.eq_ignore_ascii_case(&f.severity))
            .unwrap_or(SEVERITY_ORDER.len())
    };
    let mut v: Vec<&SecurityFinding> = a.findings.iter().collect();
    v.sort_by(|x, y| rank(x).cmp(&rank(y)).then(y.risk.cmp(&x.risk)).then(x.rule_id.cmp(&y.rule_id)));
    v
}

fn display_name(d: &ContractDetails) -> &str {
    d.contract_name.as_deref().filter(|n| !n.is_empty()).unwrap_or("(unverified)")
}

// ---- escaping -------------------------------------------------------------
//
// Everything a contract contributes to this document is text somebody else
// chose: the name is whatever the deployer typed, the evidence is a line of
// their source, the locations are their file paths. A report is a thing people
// forward, so none of it may be emitted raw.

/// Render `s` as a Markdown code span, whatever it contains.
///
/// A code span neutralises every Markdown construct at once, which is the point
/// — escaping them one by one means being wrong about one of them. The fence is
/// widened past the longest backtick run inside so the span cannot be closed
/// early, and a span that starts or ends with a backtick gets the pad space
/// CommonMark then strips back off.
fn md_code(s: &str) -> String {
    let flat = s.replace(['\n', '\r'], " ");
    let longest = flat
        .as_bytes()
        .split(|b| *b != b'`')
        .map(<[u8]>::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if flat.starts_with('`') || flat.ends_with('`') { " " } else { "" };
    format!("{fence}{pad}{flat}{pad}{fence}")
}

/// A Markdown table cell: `|` ends the cell and a newline ends the row, so both
/// have to go before untrusted text can sit in a table.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Escape for HTML text and quoted attribute content. No exceptions and no
/// allow-list: this document is generated from a hostile corpus by definition.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

// ---- Markdown -------------------------------------------------------------

/// A Markdown audit report: overview, then one section per contract, findings
/// worst-first with their locations, evidence and remediation.
pub fn render_markdown(contracts: &[ContractDetails]) -> String {
    let o = overview(contracts);
    let mut m = String::new();

    m.push_str("# BlockScan audit report\n\n");
    m.push_str(&format!(
        "Produced by blockscan {}. Heuristic static analysis, not a formal proof — \
         every finding needs a human to confirm it.\n\n",
        env!("CARGO_PKG_VERSION")
    ));

    m.push_str("## Scope\n\n");
    m.push_str("| | |\n|---|---|\n");
    m.push_str(&format!("| Contracts | {} |\n", o.contracts));
    m.push_str(&format!("| With verified source | {} |\n", o.verified));
    m.push_str(&format!("| Proxies | {} |\n", o.proxies));
    m.push_str(&format!("| Audited | {} |\n", o.audited));
    m.push_str(&format!("| With at least one finding | {} |\n", o.with_findings));
    match &o.pinned {
        Some((n, Some(h))) => {
            m.push_str(&format!("| Chain state | block {n} ({}) |\n", md_code(h)));
        }
        Some((n, None)) => m.push_str(&format!("| Chain state | block {n} |\n")),
        None => m.push_str(
            "| Chain state | not a single block — these records were not all read at one pin |\n",
        ),
    }
    if o.incomplete > 0 {
        m.push_str(&format!(
            "| Incomplete records | {} — a lookup went unanswered; see each contract |\n",
            o.incomplete
        ));
    }
    m.push('\n');

    m.push_str("## Findings by severity\n\n");
    m.push_str("Occurrences, not findings: one finding covers every site it lists.\n\n");
    m.push_str("| Severity | Occurrences |\n|---|---:|\n");
    for sev in SEVERITY_ORDER {
        m.push_str(&format!("| {sev} | {} |\n", o.by_severity.get(sev).copied().unwrap_or(0)));
    }
    if !o.by_grade.is_empty() {
        m.push_str("\n| Grade | Contracts |\n|---|---:|\n");
        for (g, n) in &o.by_grade {
            m.push_str(&format!("| {} | {n} |\n", md_cell(g)));
        }
    }
    m.push('\n');

    m.push_str("## Contracts\n\n");
    for d in contracts {
        let grade = d
            .audit
            .as_ref()
            .map(|a| format!(" — grade {} ({}/100, {})", a.grade, a.risk_score, a.risk_level))
            .unwrap_or_default();
        m.push_str(&format!(
            "### {} {}{}\n\n",
            md_code(&d.address),
            md_cell(display_name(d)),
            md_cell(&grade)
        ));

        m.push_str("| | |\n|---|---|\n");
        m.push_str(&format!("| Chain | {} |\n", d.chain_id));
        m.push_str(&format!(
            "| Verified | {} |\n",
            match (d.is_verified, d.verified_via.as_deref()) {
                (true, Some(via)) => format!("yes, via {}", md_cell(via)),
                (true, None) => "yes".to_string(),
                (false, _) => "no — bytecode-level signals only".to_string(),
            }
        ));
        if let Some(v) = &d.compiler_version {
            m.push_str(&format!("| Compiler | {} |\n", md_code(v)));
        }
        if d.is_proxy {
            m.push_str(&format!(
                "| Proxy | {} → {} |\n",
                md_cell(d.proxy_kind.as_deref().unwrap_or("?")),
                md_code(d.implementation.as_deref().unwrap_or("?"))
            ));
        }
        m.push_str(&format!(
            "| Balance | {} |\n",
            md_cell(&crate::report::format_eth(&d.balance_wei))
        ));
        if let Some(c) = &d.creator {
            m.push_str(&format!("| Creator | {} |\n", md_code(c)));
        }
        if let Some(n) = d.block_number {
            m.push_str(&format!("| Read at block | {n} |\n"));
        }
        if !d.incomplete.is_empty() {
            m.push_str(&format!(
                "| Unanswered lookups | {} |\n",
                md_cell(&d.incomplete.join(", "))
            ));
        }
        m.push('\n');

        match d.audit.as_ref().filter(|a| !a.findings.is_empty()) {
            None => m.push_str("No findings.\n\n"),
            Some(a) => {
                for f in ordered_findings(a) {
                    let mut tags = vec![f.rule_id.clone(), f.category.clone()];
                    tags.extend(f.swc.clone());
                    tags.extend(f.scwe.clone());
                    m.push_str(&format!(
                        "#### [{}] {}\n\n",
                        md_cell(&f.severity),
                        md_cell(&f.title)
                    ));
                    m.push_str(&format!(
                        "{} · confidence {} · priority {} · risk {}/100\n\n",
                        tags.iter().map(|t| md_code(t)).collect::<Vec<_>>().join(" · "),
                        md_cell(&f.confidence),
                        md_cell(&f.priority),
                        f.risk
                    ));
                    if !f.locations.is_empty() {
                        m.push_str("Locations:\n\n");
                        for l in &f.locations {
                            m.push_str(&format!("- {}\n", md_code(l)));
                        }
                        m.push('\n');
                    }
                    if !f.evidence.is_empty() {
                        m.push_str(&format!("Evidence: {}\n\n", md_code(&f.evidence)));
                    }
                    if !f.exploit_scenario.is_empty() {
                        m.push_str(&format!("{}\n\n", md_cell(&f.exploit_scenario)));
                    }
                    if !f.recommendation.is_empty() {
                        m.push_str(&format!("**Fix:** {}\n\n", md_cell(&f.recommendation)));
                    }
                }
            }
        }
    }
    m
}

// ---- HTML -----------------------------------------------------------------

/// Inlined because the file has to work from a mail attachment, off a share, or
/// out of a ticket — places where a stylesheet URL resolves to nothing.
const REPORT_CSS: &str = "\
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e2e2e2;--card:#fafafa}\
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e8e8e8;--mut:#9aa0a6;--line:#2c3036;--card:#1d2025}}\
*{box-sizing:border-box}\
body{margin:0;padding:2rem 1.25rem;background:var(--bg);color:var(--fg);\
font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,'Noto Sans',sans-serif}\
main{max-width:60rem;margin:0 auto}\
h1{font-size:1.7rem;margin:0 0 .25rem}h2{font-size:1.25rem;margin:2.5rem 0 .75rem;\
padding-bottom:.3rem;border-bottom:1px solid var(--line)}\
h3{font-size:1.05rem;margin:2rem 0 .5rem;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}\
h4{font-size:.95rem;margin:1.5rem 0 .4rem}\
p{margin:.5rem 0}.mut{color:var(--mut)}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.87em;\
background:var(--card);border:1px solid var(--line);border-radius:3px;padding:.05em .35em;word-break:break-all}\
.wrap{overflow-x:auto}\
table{border-collapse:collapse;width:100%;margin:.5rem 0}\
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}\
th{font-weight:600;color:var(--mut);font-size:.85rem}td.n{text-align:right;font-variant-numeric:tabular-nums}\
.chip{display:inline-block;padding:.1em .5em;border-radius:999px;font-size:.75rem;font-weight:600;\
border:1px solid currentColor}\
.Critical{color:#b3261e}.High{color:#c25a00}.Medium{color:#8a6d00}.Low{color:#3a6ea5}.Info{color:var(--mut)}\
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:.75rem 1rem;margin:.75rem 0}\
ul{margin:.4rem 0;padding-left:1.2rem}\
@media print{body{padding:0;background:#fff;color:#000}h2,h3{break-after:avoid}.card{break-inside:avoid}}\
";

/// A single self-contained HTML file: styles inlined, no scripts, no external
/// requests of any kind. Same facts as the Markdown, escaped rather than fenced.
pub fn render_html(contracts: &[ContractDetails]) -> String {
    let o = overview(contracts);
    let mut h = String::new();
    let code = |s: &str| format!("<code>{}</code>", html_escape(s));

    h.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    h.push_str("<title>BlockScan audit report</title>\n<style>");
    h.push_str(REPORT_CSS);
    h.push_str("</style>\n</head>\n<body>\n<main>\n");

    h.push_str("<h1>BlockScan audit report</h1>\n");
    h.push_str(&format!(
        "<p class=\"mut\">Produced by blockscan {}. Heuristic static analysis, not a formal \
         proof — every finding needs a human to confirm it.</p>\n",
        env!("CARGO_PKG_VERSION")
    ));

    h.push_str("<h2>Scope</h2>\n<div class=\"wrap\"><table>\n");
    let row = |k: &str, v: String| format!("<tr><th>{k}</th><td>{v}</td></tr>\n");
    h.push_str(&row("Contracts", o.contracts.to_string()));
    h.push_str(&row("With verified source", o.verified.to_string()));
    h.push_str(&row("Proxies", o.proxies.to_string()));
    h.push_str(&row("Audited", o.audited.to_string()));
    h.push_str(&row("With at least one finding", o.with_findings.to_string()));
    h.push_str(&row(
        "Chain state",
        match &o.pinned {
            Some((n, Some(hash))) => format!("block {n} ({})", code(hash)),
            Some((n, None)) => format!("block {n}"),
            None => "not a single block — these records were not all read at one pin".into(),
        },
    ));
    if o.incomplete > 0 {
        h.push_str(&row(
            "Incomplete records",
            format!("{} — a lookup went unanswered; see each contract", o.incomplete),
        ));
    }
    h.push_str("</table></div>\n");

    h.push_str("<h2>Findings by severity</h2>\n");
    h.push_str("<p class=\"mut\">Occurrences, not findings: one finding covers every site it lists.</p>\n");
    h.push_str("<div class=\"wrap\"><table>\n<tr><th>Severity</th><th>Occurrences</th></tr>\n");
    for sev in SEVERITY_ORDER {
        h.push_str(&format!(
            "<tr><td><span class=\"chip {sev}\">{sev}</span></td><td class=\"n\">{}</td></tr>\n",
            o.by_severity.get(sev).copied().unwrap_or(0)
        ));
    }
    h.push_str("</table></div>\n");
    if !o.by_grade.is_empty() {
        h.push_str("<div class=\"wrap\"><table>\n<tr><th>Grade</th><th>Contracts</th></tr>\n");
        for (g, n) in &o.by_grade {
            h.push_str(&format!(
                "<tr><td>{}</td><td class=\"n\">{n}</td></tr>\n",
                html_escape(g)
            ));
        }
        h.push_str("</table></div>\n");
    }

    h.push_str("<h2>Contracts</h2>\n");
    for d in contracts {
        h.push_str(&format!(
            "<h3>{} <span class=\"mut\">{}</span></h3>\n",
            html_escape(&d.address),
            html_escape(display_name(d))
        ));
        if let Some(a) = &d.audit {
            h.push_str(&format!(
                "<p>Grade <strong>{}</strong> · {}/100 · {}</p>\n",
                html_escape(&a.grade),
                a.risk_score,
                html_escape(&a.risk_level)
            ));
        }

        h.push_str("<div class=\"wrap\"><table>\n");
        h.push_str(&row("Chain", d.chain_id.to_string()));
        h.push_str(&row(
            "Verified",
            match (d.is_verified, d.verified_via.as_deref()) {
                (true, Some(via)) => format!("yes, via {}", html_escape(via)),
                (true, None) => "yes".to_string(),
                (false, _) => "no — bytecode-level signals only".to_string(),
            },
        ));
        if let Some(v) = &d.compiler_version {
            h.push_str(&row("Compiler", code(v)));
        }
        if d.is_proxy {
            h.push_str(&row(
                "Proxy",
                format!(
                    "{} → {}",
                    html_escape(d.proxy_kind.as_deref().unwrap_or("?")),
                    code(d.implementation.as_deref().unwrap_or("?"))
                ),
            ));
        }
        h.push_str(&row("Balance", html_escape(&crate::report::format_eth(&d.balance_wei))));
        if let Some(c) = &d.creator {
            h.push_str(&row("Creator", code(c)));
        }
        if let Some(n) = d.block_number {
            h.push_str(&row("Read at block", n.to_string()));
        }
        if !d.incomplete.is_empty() {
            h.push_str(&row("Unanswered lookups", html_escape(&d.incomplete.join(", "))));
        }
        h.push_str("</table></div>\n");

        match d.audit.as_ref().filter(|a| !a.findings.is_empty()) {
            None => h.push_str("<p class=\"mut\">No findings.</p>\n"),
            Some(a) => {
                for f in ordered_findings(a) {
                    h.push_str("<div class=\"card\">\n");
                    h.push_str(&format!(
                        "<h4><span class=\"chip {}\">{}</span> {}</h4>\n",
                        html_escape(&f.severity),
                        html_escape(&f.severity),
                        html_escape(&f.title)
                    ));
                    let mut tags = vec![f.rule_id.clone(), f.category.clone()];
                    tags.extend(f.swc.clone());
                    tags.extend(f.scwe.clone());
                    h.push_str(&format!(
                        "<p class=\"mut\">{} · confidence {} · priority {} · risk {}/100</p>\n",
                        tags.iter().map(|t| code(t)).collect::<Vec<_>>().join(" · "),
                        html_escape(&f.confidence),
                        html_escape(&f.priority),
                        f.risk
                    ));
                    if !f.locations.is_empty() {
                        h.push_str("<ul>\n");
                        for l in &f.locations {
                            h.push_str(&format!("<li>{}</li>\n", code(l)));
                        }
                        h.push_str("</ul>\n");
                    }
                    if !f.evidence.is_empty() {
                        h.push_str(&format!("<p>Evidence: {}</p>\n", code(&f.evidence)));
                    }
                    if !f.exploit_scenario.is_empty() {
                        h.push_str(&format!("<p>{}</p>\n", html_escape(&f.exploit_scenario)));
                    }
                    if !f.recommendation.is_empty() {
                        h.push_str(&format!(
                            "<p><strong>Fix:</strong> {}</p>\n",
                            html_escape(&f.recommendation)
                        ));
                    }
                    h.push_str("</div>\n");
                }
            }
        }
    }

    h.push_str("</main>\n</body>\n</html>\n");
    h
}

/// Highest-severity finding present, in descending order; empty when none.
fn top_severity(a: &crate::model::Audit) -> String {
    for sev in ["Critical", "High", "Medium", "Low", "Info"] {
        if a.findings.iter().any(|f| f.severity.eq_ignore_ascii_case(sev)) {
            return sev.to_string();
        }
    }
    String::new()
}

/// OWASP category of the highest-risk finding; empty when none.
fn top_category(a: &crate::model::Audit) -> String {
    a.findings
        .iter()
        .max_by_key(|f| f.risk)
        .map(|f| f.category.clone())
        .unwrap_or_default()
}

/// Escape a CSV field: neutralize spreadsheet formula injection (fields whose
/// first char is `= + - @` / tab / CR get a leading `'`), then quote when the
/// field contains a comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(addr: &str, name: Option<&str>) -> ContractDetails {
        ContractDetails {
            address: addr.into(),
            chain_id: 1,
            block_number: None,
            block_hash: None,
            incomplete: Vec::new(),
            bytecode: "0x60".into(),
            bytecode_size: 2,
            balance_wei: "100".into(),
            is_verified: name.is_some(),
            contract_name: name.map(|s| s.into()),
            compiler_version: Some("v0.8.0".into()),
            optimization_used: None,
            optimization_runs: None,
            evm_version: None,
            license_type: None,
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: name.map(|_| "etherscan".into()),
            creator: None,
            creation_tx_hash: None,
            has_abi: name.is_some(),
            source_file_count: if name.is_some() { 1 } else { 0 },
            analysis: Default::default(),
            // Verified row carries an audit; unverified row has none (covers both CSV branches).
            audit: name.map(|_| crate::model::Audit {
                risk_score: 30,
                grade: "C".into(),
                risk_level: "Medium".into(),
                findings: vec![crate::model::SecurityFinding {
                    rule_id: "TX_ORIGIN_AUTH".into(),
                    title: "t".into(),
                    category: "SC01:Access Control".into(),
                    swc: Some("SWC-115".into()),
                    scwe: None,
                    ethtrust: None,
                    severity: "High".into(),
                    confidence: "Medium".into(),
                    impact_score: 7,
                    likelihood_score: 5,
                    exploitability: "Moderate".into(),
                    asset_at_risk: "x".into(),
                    blast_radius: "user-funds".into(),
                    risk: 26,
                    priority: "P1".into(),
                    detection: "source".into(),
                    affected_contract: "0xa".into(),
                    locations: vec![],
                    evidence: "e".into(),
                    exploit_scenario: "s".into(),
                    recommendation: "r".into(),
                    references: vec![],
                    false_positive_notes: "".into(),
                }],
                summary: crate::model::AuditSummary {
                    owasp_categories: vec!["SC01:Access Control".into()],
                    ..Default::default()
                },
            }),
        }
    }

    #[test]
    fn json_round_trips() {
        let json = render_json(&[d("0xa", Some("Foo"))]).unwrap();
        let back: Vec<ContractDetails> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].contract_name.as_deref(), Some("Foo"));
    }

    #[test]
    fn top_helpers_handle_empty_audit() {
        let empty = crate::model::Audit::default();
        assert_eq!(top_severity(&empty), "");
        assert_eq!(top_category(&empty), "");
    }

    #[test]
    fn csv_has_header_and_rows() {
        let csv = render_csv(&[d("0xa", Some("Foo")), d("0xb", None)]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("address,chain_id,"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].contains("0xa") && lines[1].contains("Foo"));
    }

    #[test]
    fn csv_escapes_commas_and_quotes() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("he\"llo"), "\"he\"\"llo\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn csv_neutralizes_formula_injection() {
        // Leading formula triggers get a `'` prefix so spreadsheets treat them as text.
        assert_eq!(csv_escape("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_escape("+1"), "'+1");
        assert_eq!(csv_escape("-1"), "'-1");
        assert_eq!(csv_escape("@cmd"), "'@cmd");
        // A normal name is untouched.
        assert_eq!(csv_escape("PoolManager"), "PoolManager");
    }

    // ---- T-14: the document formats ----

    /// A contract whose every text field is chosen by whoever deployed it.
    /// Etherscan hands these back verbatim, and a report is a thing people
    /// forward, so this is the shape that matters.
    fn hostile() -> ContractDetails {
        let mut d = ContractDetails::minimal("0x00000000000000000000000000000000000000ff", 1);
        d.contract_name = Some("<script>alert(1)</script>".into());
        d.is_verified = true;
        d.verified_via = Some("etherscan".into());
        d.compiler_version = Some("v0.8.20 | \"quoted\" & <b>".into());
        d.incomplete = vec!["creation".into()];
        let mut f = crate::model::SecurityFinding {
            rule_id: "TX_ORIGIN_AUTH".into(),
            title: "tx.origin used for authorization".into(),
            category: "SC01:Access Control".into(),
            swc: Some("SWC-115".into()),
            scwe: None,
            ethtrust: None,
            severity: "High".into(),
            confidence: "Medium".into(),
            impact_score: 7,
            likelihood_score: 5,
            exploitability: "Moderate".into(),
            asset_at_risk: "x".into(),
            blast_radius: "protocol".into(),
            risk: 34,
            priority: "P1".into(),
            detection: "source".into(),
            affected_contract: "0xff".into(),
            locations: vec!["src/<img src=x onerror=alert(1)>.sol:12".into()],
            evidence: "require(tx.origin == owner) && a | b `x` <b>".into(),
            exploit_scenario: "s".into(),
            recommendation: "r".into(),
            references: vec![],
            false_positive_notes: String::new(),
        };
        f.locations.push("src/A``B.sol:1".into());
        d.audit = Some(crate::model::Audit {
            risk_score: 34,
            grade: "C".into(),
            risk_level: "Medium".into(),
            findings: vec![f],
            summary: Default::default(),
        });
        d
    }

    #[test]
    fn markdown_and_html_are_selected_by_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let c = [hostile()];

        let md = tmp.path().join("r.md");
        write_manifest(&md, &c).unwrap();
        let body = std::fs::read_to_string(&md).unwrap();
        assert!(body.starts_with("# BlockScan audit report"), "{body}");

        for name in ["r.html", "r.htm", "R.HTML"] {
            let path = tmp.path().join(name);
            write_manifest(&path, &c).unwrap();
            let body = std::fs::read_to_string(&path).unwrap();
            assert!(body.starts_with("<!doctype html>"), "{name}: {}", &body[..40.min(body.len())]);
        }

        // The pipeline formats are untouched.
        let json = tmp.path().join("r.json");
        write_manifest(&json, &c).unwrap();
        assert!(std::fs::read_to_string(&json).unwrap().starts_with('['));
        let csv = tmp.path().join("r.csv");
        write_manifest(&csv, &c).unwrap();
        assert!(std::fs::read_to_string(&csv).unwrap().starts_with("address,chain_id"));
    }

    /// The task forbids a PDF writer. Falling through to JSON would put JSON in
    /// a file called report.pdf, so the extension is refused with a pointer at
    /// the pipeline that should do it instead.
    #[test]
    fn pdf_is_refused_and_says_what_to_use() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("r.pdf");
        let err = write_manifest(&path, &[hostile()]).unwrap_err().to_string();
        assert!(err.contains("PDF is not produced"), "{err}");
        assert!(err.contains("pandoc") || err.contains("print-to-PDF"), "{err}");
        assert!(!path.exists(), "nothing may be written under a refused extension");
    }

    #[test]
    fn html_escapes_every_attacker_chosen_string() {
        let h = render_html(&[hostile()]);
        assert!(!h.contains("<script>alert(1)"), "contract name reached the page as markup");
        assert!(h.contains("&lt;script&gt;alert(1)"), "and it must still be readable");
        assert!(!h.contains("onerror=alert(1)>"), "a source path reached the page as markup");
        assert!(h.contains("onerror=alert(1)&gt;"));
        assert!(!h.contains("v0.8.20 | \"quoted\""), "an unescaped quote can break out of an attribute");
        assert!(h.contains("&quot;quoted&quot;"));
        // The only `<` that may open a tag are ones this module wrote.
        assert_eq!(h.matches("<script").count(), 0, "no scripts, written or injected");
    }

    /// Self-contained means nothing in the file can fetch anything.
    ///
    /// Substring probes are the wrong test: `src=` appears in this document as
    /// escaped *text*, because the fixture's source path contains it. Since
    /// every untrusted string is escaped, only markup this module wrote can
    /// open a connection — so the property to check is which tags exist at all.
    #[test]
    fn html_makes_no_external_request() {
        let h = render_html(&[hostile()]);

        // Every tag name present, opening and closing.
        let mut tags: std::collections::BTreeSet<String> = Default::default();
        let b = h.as_bytes();
        for (i, _) in h.match_indices('<') {
            let mut j = i + 1;
            if b.get(j) == Some(&b'/') {
                j += 1;
            }
            let start = j;
            while b.get(j).is_some_and(|c| c.is_ascii_alphanumeric()) {
                j += 1;
            }
            if j > start {
                tags.insert(h[start..j].to_ascii_lowercase());
            }
        }
        const ALLOWED: [&str; 20] = [
            "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "h3", "h4", "p",
            "table", "tr", "th", "td", "div", "span", "code", "strong",
        ];
        // `ul`/`li` only appear when a finding has locations; the fixture has two.
        let extra = ["ul", "li"];
        for t in &tags {
            assert!(
                ALLOWED.contains(&t.as_str()) || extra.contains(&t.as_str()),
                "unexpected tag <{t}> — none of the allowed tags can fetch anything, this might"
            );
        }
        assert!(tags.contains("style"), "the styles have to be in the file");

        // And the stylesheet itself pulls nothing in.
        for probe in ["@import", "url(", "http:", "https:"] {
            assert!(!REPORT_CSS.contains(probe), "the inlined CSS must not contain {probe}");
        }
    }

    #[test]
    fn markdown_neutralises_its_own_metacharacters() {
        let md = render_markdown(&[hostile()]);
        // A `|` in a value would otherwise open a new table cell.
        assert!(!md.contains("| Compiler | v0.8.20 | "), "a raw pipe split the row");
        // A path containing backticks must not close the span that holds it.
        let line = md
            .lines()
            .find(|l| l.contains("A``B.sol"))
            .expect("the backticked path is in the document");
        assert!(line.starts_with("- ```") , "the fence must widen past the content: {line}");
        assert!(line.ends_with("```"), "{line}");
        // Markup in a name is inert in Markdown, but it must survive readable.
        assert!(md.contains("<script>alert(1)</script>"));
    }

    /// The two renderers are separate code paths over one set of records, so
    /// what stops them drifting is a test that names the facts both must carry.
    #[test]
    fn both_documents_carry_the_same_facts() {
        let c = [hostile()];
        let md = render_markdown(&c);
        let html = render_html(&c);
        for fact in [
            "0x00000000000000000000000000000000000000ff",
            "TX_ORIGIN_AUTH",
            "tx.origin used for authorization",
            "SWC-115",
            "SC01:Access Control",
            "creation", // the unanswered lookup from T-05
        ] {
            assert!(md.contains(fact), "markdown is missing {fact}");
            assert!(html.contains(fact), "html is missing {fact}");
        }
    }

    /// The severity table counts sites, not findings — one finding here lists
    /// two locations.
    #[test]
    fn the_severity_tally_counts_occurrences() {
        let md = render_markdown(&[hostile()]);
        assert!(md.contains("| High | 2 |"), "{md}");
        assert!(md.contains("| Critical | 0 |"));
    }

    /// A corpus read at one pinned block says so; a mixed one refuses to name a
    /// block rather than picking whichever record came first.
    #[test]
    fn the_document_states_the_chain_state_it_describes() {
        let mut a = hostile();
        let mut b = hostile();
        a.block_number = Some(19_000_000);
        a.block_hash = Some("0xabc".into());
        b.block_number = Some(19_000_000);
        b.block_hash = Some("0xabc".into());
        assert!(render_markdown(&[a.clone(), b.clone()]).contains("block 19000000"));

        b.block_number = Some(19_000_001);
        let mixed = render_markdown(&[a.clone(), b.clone()]);
        assert!(mixed.contains("not a single block"), "{mixed}");

        // Records written before the pin existed carry no block at all.
        let c = hostile();
        assert!(render_markdown(&[c]).contains("not a single block"));
    }

    #[test]
    fn write_manifest_picks_format_by_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("index.json");
        let csv_path = tmp.path().join("index.csv");
        write_manifest(&json_path, &[d("0xa", Some("Foo"))]).unwrap();
        write_manifest(&csv_path, &[d("0xa", Some("Foo"))]).unwrap();
        assert!(std::fs::read_to_string(&json_path).unwrap().contains("\"address\""));
        assert!(std::fs::read_to_string(&csv_path).unwrap().starts_with("address,"));
    }
}
