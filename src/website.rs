//! Website/docs discovery: fetch a project's site, harvest contract addresses
//! from the page text (and explorer `/address/0x…` links), and shallow-crawl
//! same-domain links that look like they lead to deployment/docs pages.
//!
//! Best-effort and bounded: a page cap and a crawl depth keep it polite.

use std::collections::HashSet;
use std::time::Duration;

use crate::github::valid_address;

/// Substrings (in a URL) that hint a page lists deployed contracts.
const INTERESTING: [&str; 8] = [
    "contract",
    "deploy",
    "address",
    "docs",
    "developer",
    "reference",
    "resources",
    "technical",
];

/// Crawler for a project's website/docs.
#[derive(Clone)]
pub struct WebsiteScraper {
    http: reqwest::Client,
    /// Hard cap on pages fetched per `discover` call.
    max_pages: usize,
}

impl WebsiteScraper {
    pub fn new(max_pages: usize) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap_or_default();
        Self {
            http,
            max_pages: max_pages.max(1),
        }
    }

    async fn fetch(&self, url: &str) -> Option<String> {
        let resp = self.http.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.text().await.ok()
    }

    /// Crawl from `start` up to `depth` hops along interesting same-domain links,
    /// returning all unique contract addresses found (lowercased).
    pub async fn discover(&self, start: &str, depth: usize) -> Vec<String> {
        let mut seen_pages: HashSet<String> = HashSet::new();
        let mut addrs: HashSet<String> = HashSet::new();
        let mut frontier = vec![start.to_string()];

        for hop in 0..=depth {
            if frontier.is_empty() || seen_pages.len() >= self.max_pages {
                break;
            }
            let mut next = Vec::new();
            for url in std::mem::take(&mut frontier) {
                if seen_pages.len() >= self.max_pages {
                    break;
                }
                if !seen_pages.insert(url.clone()) {
                    continue;
                }
                let Some(html) = self.fetch(&url).await else {
                    continue;
                };
                for a in extract_addresses(&html) {
                    addrs.insert(a);
                }
                if hop < depth {
                    for link in extract_links(&html, &url) {
                        if is_interesting(&link) && !seen_pages.contains(&link) {
                            next.push(link);
                        }
                    }
                }
            }
            frontier = next;
        }

        let mut out: Vec<String> = addrs.into_iter().collect();
        out.sort();
        out
    }
}

/// Extract contract addresses from page text. An address is a maximal hex run of
/// exactly 40 digits after `0x` (so 64-digit tx hashes are skipped). Case-folded.
pub fn extract_addresses(html: &str) -> Vec<String> {
    let s = html.to_ascii_lowercase();
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= b.len() {
        if b[i] == b'0' && b[i + 1] == b'x' {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - (i + 2) == 40 {
                if let Some(a) = valid_address(&s[i..i + 42]) {
                    out.push(a);
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Extract same-domain absolute links from `href="…"` attributes, resolving
/// relative/root-relative URLs against `page_url` and dropping fragments.
pub fn extract_links(html: &str, page_url: &str) -> Vec<String> {
    let Ok(base) = reqwest::Url::parse(page_url) else {
        return Vec::new();
    };
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("href=") {
        let q = search + rel + 5;
        if q >= html.len() {
            break;
        }
        let quote = html.as_bytes()[q];
        if quote != b'"' && quote != b'\'' {
            search = q;
            continue;
        }
        let val_start = q + 1;
        let Some(end_rel) = html[val_start..].find(quote as char) else {
            break;
        };
        let val = &html[val_start..val_start + end_rel];
        if let Ok(mut abs) = base.join(val) {
            abs.set_fragment(None);
            if matches!(abs.scheme(), "http" | "https") && abs.host_str() == base.host_str() {
                out.push(abs.as_str().to_string());
            }
        }
        search = val_start + end_rel + 1;
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a URL looks like a page that may list deployed contracts.
pub fn is_interesting(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    INTERESTING.iter().any(|k| u.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_inline_and_link_addresses_skips_tx() {
        let html = r#"
            Pool: 0x000000000004444c5dc75cB358380D2e3dE08A90 and
            <a href="https://etherscan.io/address/0x1111111111111111111111111111111111111111">x</a>
            tx 0xabc1230000000000000000000000000000000000000000000000000000000000000000 (64-hex, skip)
            zero 0x0000000000000000000000000000000000000000
        "#;
        let got = extract_addresses(html);
        assert!(got.contains(&"0x000000000004444c5dc75cb358380d2e3de08a90".to_string()));
        assert!(got.contains(&"0x1111111111111111111111111111111111111111".to_string()));
        assert_eq!(got.len(), 2); // tx hash + zero address excluded
    }

    #[test]
    fn extract_links_same_domain_only_resolved() {
        let html = r#"
            <a href="/docs/contracts">a</a>
            <a href="https://example.com/developers">b</a>
            <a href="https://other.com/contracts">c</a>
            <a href='deploy/list#section'>d</a>
        "#;
        let links = extract_links(html, "https://example.com/start");
        assert!(links.contains(&"https://example.com/docs/contracts".to_string()));
        assert!(links.contains(&"https://example.com/developers".to_string()));
        assert!(links.contains(&"https://example.com/deploy/list".to_string())); // fragment dropped
        assert!(!links.iter().any(|l| l.contains("other.com"))); // cross-domain excluded
    }

    #[test]
    fn interesting_link_detection() {
        assert!(is_interesting("https://x.com/docs/deployments"));
        assert!(is_interesting("https://x.com/developer/addresses"));
        assert!(!is_interesting("https://x.com/blog/2024/hello"));
    }

    #[tokio::test]
    async fn discover_dead_endpoint_is_empty() {
        let s = WebsiteScraper::new(5);
        assert!(s.discover("http://127.0.0.1:1", 1).await.is_empty());
    }
}
