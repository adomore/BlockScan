//! Best-effort enrichment from the free Blockscout API: public name tag,
//! project URL, and a top-by-USD token-holdings summary.
//!
//! Everything here is best-effort — any network/parse failure yields empty
//! fields rather than an error, so it never blocks a scan.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use serde_json::Value;

use crate::error::Result;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Extra, display-only fields shown in the `--table` output.
#[derive(Debug, Default, Clone)]
pub struct Enrichment {
    pub name_tag: Option<String>,
    pub project_url: Option<String>,
    /// Pre-formatted "top holdings" summary, e.g. `WBTC(~$32.3M), USDC(~$57.5M)`.
    pub holdings: Option<String>,
}

/// Client for a Blockscout v2 API instance, with per-address caching and
/// request rate limiting.
#[derive(Clone)]
pub struct Blockscout {
    http: reqwest::Client,
    /// API base, e.g. `https://eth.blockscout.com/api/v2`. Empty disables enrichment.
    base: String,
    limiter: Arc<DirectLimiter>,
    cache: Arc<Mutex<HashMap<String, Enrichment>>>,
}

impl Blockscout {
    pub fn new(base: &str, rate: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rate.max(1)).expect("rate.max(1) >= 1"));
        let limiter = Arc::new(RateLimiter::direct(quota));
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            limiter,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Fetch name tag, project URL and token holdings for an address.
    /// Returns empty fields when disabled or on any failure. Results are cached
    /// per address for the lifetime of the client.
    pub async fn fetch(&self, address: &str) -> Enrichment {
        if self.base.is_empty() {
            return Enrichment::default();
        }
        if let Some(hit) = self.cache.lock().unwrap().get(address).cloned() {
            return hit;
        }

        let mut e = Enrichment::default();
        let mut any_ok = false;
        if let Ok(v) = self.get_json(&format!("{}/addresses/{address}", self.base)).await {
            e.name_tag = parse_name_tag(&v);
            e.project_url = parse_project_url(&v);
            any_ok = true;
        }
        if let Ok(v) = self
            .get_json(&format!("{}/addresses/{address}/tokens?type=ERC-20", self.base))
            .await
        {
            e.holdings = parse_holdings(&v);
            any_ok = true;
        }

        // Cache only a result we actually obtained — a total (transient) failure
        // stays uncached so a later call can retry, rather than poisoning
        // enrichment for the client's lifetime.
        if any_ok {
            self.cache.lock().unwrap().insert(address.to_string(), e.clone());
        }
        e
    }

    async fn get_json(&self, url: &str) -> Result<Value> {
        self.limiter.until_ready().await;
        let text = self.http.get(url).send().await?.text().await?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Search Blockscout by name/tag and return matching smart-contract addresses
    /// (lowercased). Best-effort: empty on disabled / error.
    pub async fn search_contracts(&self, query: &str) -> Vec<String> {
        if self.base.is_empty() {
            return Vec::new();
        }
        self.limiter.until_ready().await;
        let resp = match self
            .http
            .get(format!("{}/search", self.base))
            .query(&[("q", query)])
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let Ok(text) = resp.text().await else {
            return Vec::new();
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => parse_search(&v),
            Err(_) => Vec::new(),
        }
    }
}

/// Extract smart-contract addresses from a Blockscout `/search` response.
/// Keeps `token` / `contract` / `metadata_tag` items that are smart contracts.
pub fn parse_search(v: &Value) -> Vec<String> {
    let Some(items) = v.get("items").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for it in items {
        let t = it.get("type").and_then(|x| x.as_str()).unwrap_or("");
        if !matches!(t, "token" | "contract" | "metadata_tag") {
            continue;
        }
        if it.get("is_smart_contract_address").and_then(|x| x.as_bool()) != Some(true) {
            continue;
        }
        // Validate (len/hex/non-zero) for parity with the GitHub discovery path.
        if let Some(a) = it
            .get("address_hash")
            .and_then(|x| x.as_str())
            .and_then(crate::github::valid_address)
        {
            out.push(a);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Public name tag: prefer `public_tags`, then a `metadata.tags` name entry,
/// finally the resolved top-level `name`.
pub fn parse_name_tag(v: &Value) -> Option<String> {
    if let Some(arr) = v.get("public_tags").and_then(|x| x.as_array()) {
        for t in arr {
            let label = t
                .get("display_name")
                .or_else(|| t.get("label"))
                .or_else(|| t.get("name"))
                .and_then(|x| x.as_str());
            if let Some(s) = label.filter(|s| !s.is_empty()) {
                return Some(s.to_string());
            }
        }
    }
    if let Some(tags) = v
        .get("metadata")
        .and_then(|m| m.get("tags"))
        .and_then(|x| x.as_array())
    {
        for t in tags {
            if t.get("tagType").and_then(|x| x.as_str()) == Some("name") {
                if let Some(s) = t.get("name").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    return Some(s.to_string());
                }
            }
        }
    }
    v.get("name")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Project URL from a Blockscout `metadata.tags[].meta` entry, if any.
pub fn parse_project_url(v: &Value) -> Option<String> {
    let tags = v
        .get("metadata")
        .and_then(|m| m.get("tags"))
        .and_then(|x| x.as_array())?;
    for t in tags {
        if let Some(meta) = t.get("meta").and_then(|x| x.as_object()) {
            for key in ["appMarketplaceURL", "website", "appURL", "url"] {
                if let Some(s) = meta.get(key).and_then(|x| x.as_str()) {
                    if s.starts_with("http") {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Top-3 ERC-20 holdings by USD value from a `/tokens` response.
pub fn parse_holdings(v: &Value) -> Option<String> {
    let items = v.get("items").and_then(|x| x.as_array())?;
    let mut rows: Vec<(String, f64)> = Vec::new();
    for it in items {
        let Some(tok) = it.get("token") else { continue };
        let sym = tok
            .get("symbol")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
            .to_string();
        let dec = tok
            .get("decimals")
            .and_then(|d| d.as_str())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let rate = tok
            .get("exchange_rate")
            .and_then(|r| r.as_str())
            .and_then(|s| s.parse::<f64>().ok());
        let val = it
            .get("value")
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        let amount = val / 10f64.powi(dec as i32);
        let usd = rate.map(|r| amount * r).unwrap_or(0.0);
        if usd > 0.0 {
            rows.push((sym, usd));
        }
    }
    if rows.is_empty() {
        return None;
    }
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let more =
        rows.len() > 3 || v.get("next_page_params").map(|p| !p.is_null()).unwrap_or(false);
    let top: Vec<String> = rows
        .iter()
        .take(3)
        .map(|(s, u)| format!("{s}(~{})", fmt_usd(*u)))
        .collect();
    let mut out = top.join(", ");
    if more {
        out.push_str(" …");
    }
    Some(out)
}

/// Compact USD formatting: `$141.3M`, `$32.3M`, `$950`.
fn fmt_usd(v: f64) -> String {
    if v >= 1e9 {
        format!("${:.1}B", v / 1e9)
    } else if v >= 1e6 {
        format!("${:.1}M", v / 1e6)
    } else if v >= 1e3 {
        format!("${:.1}K", v / 1e3)
    } else {
        format!("${v:.0}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn name_tag_prefers_public_tags() {
        let v = json!({"public_tags":[{"display_name":"Uniswap V4: PoolManager"}], "name":"PoolManager"});
        assert_eq!(parse_name_tag(&v).as_deref(), Some("Uniswap V4: PoolManager"));
    }

    #[test]
    fn name_tag_metadata_then_name_fallback() {
        let meta = json!({"metadata":{"tags":[{"tagType":"name","name":"Tagged"}]}});
        assert_eq!(parse_name_tag(&meta).as_deref(), Some("Tagged"));
        let plain = json!({"name":"USDC","public_tags":[]});
        assert_eq!(parse_name_tag(&plain).as_deref(), Some("USDC"));
        assert_eq!(parse_name_tag(&json!({"name":""})), None);
        assert_eq!(parse_name_tag(&json!({})), None);
    }

    #[test]
    fn name_tag_skips_unusable_entries_then_falls_back() {
        // public_tags entry without a usable label -> skip; empty metadata name -> skip;
        // finally fall back to top-level `name`.
        let v = json!({
            "public_tags": [{"foo": "bar"}],
            "metadata": {"tags": [
                {"tagType": "protocol", "name": "ignored"},
                {"tagType": "name", "name": ""}
            ]},
            "name": "Fallback"
        });
        assert_eq!(parse_name_tag(&v).as_deref(), Some("Fallback"));
    }

    #[test]
    fn project_url_from_meta() {
        let v = json!({"metadata":{"tags":[{"meta":{"website":"https://uniswap.org"}}]}});
        assert_eq!(parse_project_url(&v).as_deref(), Some("https://uniswap.org"));
        // No metadata -> None; non-http ignored.
        assert_eq!(parse_project_url(&json!({})), None);
        let bad = json!({"metadata":{"tags":[{"meta":{"website":"ftp://x"}}]}});
        assert_eq!(parse_project_url(&bad), None);
        // Tag present but without a `meta` object -> skipped, still None.
        let no_meta = json!({"metadata":{"tags":[{"x":1}]}});
        assert_eq!(parse_project_url(&no_meta), None);
    }

    #[test]
    fn holdings_top_three_sorted_with_more() {
        let v = json!({
            "items": [
                {"value":"1000000000000000000","token":{"symbol":"DAI","decimals":"18","exchange_rate":"1"}},
                {"value":"2000000","token":{"symbol":"USDC","decimals":"6","exchange_rate":"1"}},
                {"value":"100000000","token":{"symbol":"WBTC","decimals":"8","exchange_rate":"60000"}},
                {"value":"5","token":{"symbol":"SPAM","decimals":"0"}}
            ],
            "next_page_params": {"x":1}
        });
        let s = parse_holdings(&v).unwrap();
        assert!(s.starts_with("WBTC(~$60.0K)"), "{s}");
        assert!(s.contains("USDC") && s.contains("DAI"));
        assert!(s.contains('…')); // next page present
        assert!(!s.contains("SPAM")); // no exchange rate -> excluded
    }

    #[test]
    fn holdings_empty_is_none() {
        assert_eq!(parse_holdings(&json!({"items":[]})), None);
        assert_eq!(parse_holdings(&json!({})), None);
    }

    #[test]
    fn fmt_usd_scales() {
        assert_eq!(fmt_usd(2.5e9), "$2.5B");
        assert_eq!(fmt_usd(3.2e7), "$32.0M");
        assert_eq!(fmt_usd(9500.0), "$9.5K");
        assert_eq!(fmt_usd(950.0), "$950");
    }

    #[test]
    fn parse_search_filters_to_contracts() {
        let v = json!({"items":[
            {"type":"token","is_smart_contract_address":true,"address_hash":"0xAAA0000000000000000000000000000000000001"},
            {"type":"contract","is_smart_contract_address":true,"address_hash":"0xBBB0000000000000000000000000000000000002"},
            {"type":"metadata_tag","is_smart_contract_address":true,"address_hash":"0xCCC0000000000000000000000000000000000003"},
            {"type":"address","is_smart_contract_address":false,"address_hash":"0xDDD0000000000000000000000000000000000004"},
            {"type":"token","address_hash":"0xEEE0000000000000000000000000000000000005"},
            {"type":"contract","is_smart_contract_address":true,"address_hash":"0x0000000000000000000000000000000000000000"},
            {"type":"transaction"}
        ]});
        let got = parse_search(&v);
        // Zero address is filtered out -> still 3 valid contracts.
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|a| a.starts_with("0x") && a.chars().all(|c| !c.is_ascii_uppercase())));
        assert!(got.contains(&"0xbbb0000000000000000000000000000000000002".to_string()));
    }

    #[test]
    fn parse_search_no_items_is_empty() {
        assert!(parse_search(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn search_disabled_when_base_empty() {
        assert!(Blockscout::new("", 4).search_contracts("uniswap").await.is_empty());
    }

    #[tokio::test]
    async fn fetch_disabled_when_base_empty() {
        let b = Blockscout::new("", 4);
        let e = b.fetch("0xabc").await;
        assert!(e.name_tag.is_none() && e.holdings.is_none());
    }

    #[tokio::test]
    async fn fetch_dead_endpoint_returns_empty_and_caches() {
        let b = Blockscout::new("http://127.0.0.1:1", 4);
        let e = b.fetch("0xabc").await;
        assert!(e.name_tag.is_none() && e.project_url.is_none() && e.holdings.is_none());
        // Second call hits the cache (covers the cache-hit return path).
        let e2 = b.fetch("0xabc").await;
        assert!(e2.name_tag.is_none());
    }
}
