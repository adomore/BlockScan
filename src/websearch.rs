//! Optional web-search discovery via the Google Programmable Search (Custom
//! Search JSON) API. Given a project name, search the web and harvest contract
//! addresses from explorer `/address/0x…` links in the results.
//!
//! Requires two credentials (both must be set, else this source is disabled):
//!
//! - `GOOGLE_API_KEY` — a Google Cloud API key with "Custom Search API" enabled
//! - `GOOGLE_CSE_ID` — a Programmable Search Engine id (`cx`) set to search the whole web
//!
//! Free tier: 100 queries/day.

use std::time::Duration;

use serde_json::Value;

use crate::github::valid_address;

const DEFAULT_BASE: &str = "https://www.googleapis.com/customsearch/v1";

/// Client for the Google Custom Search JSON API.
#[derive(Clone)]
pub struct Google {
    http: reqwest::Client,
    base: String,
    api_key: String,
    cse_id: String,
    enabled: bool,
}

impl Google {
    pub fn new(api_key: &str, cse_id: &str) -> Self {
        Self::with_base(DEFAULT_BASE, api_key, cse_id)
    }

    /// Construct with an explicit endpoint base (for testing).
    pub fn with_base(base: &str, api_key: &str, cse_id: &str) -> Self {
        let enabled = !api_key.trim().is_empty() && !cse_id.trim().is_empty();
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base: base.to_string(),
            api_key: api_key.to_string(),
            cse_id: cse_id.to_string(),
            enabled,
        }
    }

    /// Search the web for `query` and return contract addresses found in result
    /// links. Best-effort: empty when disabled (missing creds) or on any error.
    pub async fn search_addresses(&self, query: &str) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let resp = match self
            .http
            .get(&self.base)
            .query(&[
                ("key", self.api_key.as_str()),
                ("cx", self.cse_id.as_str()),
                ("q", query),
            ])
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
            Ok(v) => parse_google_addresses(&v),
            Err(_) => Vec::new(),
        }
    }
}

/// Extract contract addresses from a Custom Search response (`items[].link`).
pub fn parse_google_addresses(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
        for it in items {
            if let Some(link) = it.get("link").and_then(|l| l.as_str()) {
                if let Some(a) = extract_address_from_url(link) {
                    out.push(a);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Pull a `/address/0x<40 hex>` contract address out of an explorer URL.
/// Rejects an over-long hex run (e.g. a 32-byte hash in the path) so it is not
/// silently truncated into a bogus 20-byte address.
fn extract_address_from_url(url: &str) -> Option<String> {
    let idx = url.find("/address/0x")?;
    let rest = &url[idx + "/address/".len()..];
    // If char 42 is another hex digit the run is longer than an address → reject.
    if rest.as_bytes().get(42).is_some_and(u8::is_ascii_hexdigit) {
        return None;
    }
    let candidate: String = rest.chars().take(42).collect();
    valid_address(&candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_from_etherscan_links() {
        assert_eq!(
            extract_address_from_url(
                "https://etherscan.io/address/0x000000000004444c5dc75cB358380D2e3dE08A90#code"
            )
            .as_deref(),
            Some("0x000000000004444c5dc75cb358380d2e3de08a90")
        );
        // Non-address explorer URLs and malformed addresses yield nothing.
        assert!(extract_address_from_url("https://etherscan.io/tx/0xabc").is_none());
        assert!(extract_address_from_url("https://example.org/").is_none());
        assert!(extract_address_from_url("https://etherscan.io/address/0xZZ").is_none());
        // An over-long hex run (e.g. a 32-byte hash in /address/) must NOT be
        // silently truncated into a bogus 20-byte address.
        let long = format!("https://x/address/0x{}", "a".repeat(64));
        assert!(extract_address_from_url(&long).is_none());
        // A clean address followed by a non-hex delimiter is still accepted.
        let clean = format!("https://x/address/0x{}/code", "a".repeat(40));
        assert_eq!(extract_address_from_url(&clean).as_deref(), Some(&*format!("0x{}", "a".repeat(40))));
    }

    #[test]
    fn parse_collects_and_dedups() {
        let v = json!({"items":[
            {"link":"https://etherscan.io/address/0x000000000004444c5dc75cB358380D2e3dE08A90"},
            {"link":"https://etherscan.io/address/0x000000000004444c5dc75cB358380D2e3dE08A90#code"},
            {"link":"https://docs.uniswap.org/"},
            {"link":"https://basescan.org/address/0x1111111111111111111111111111111111111111"}
        ]});
        let got = parse_google_addresses(&v);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&"0x1111111111111111111111111111111111111111".to_string()));
    }

    #[test]
    fn parse_no_items_is_empty() {
        assert!(parse_google_addresses(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn disabled_without_credentials() {
        assert!(Google::new("", "").search_addresses("uniswap").await.is_empty());
        assert!(Google::new("key", "").search_addresses("uniswap").await.is_empty());
    }

    #[tokio::test]
    async fn dead_endpoint_is_empty() {
        let g = Google::with_base("http://127.0.0.1:1", "k", "c");
        assert!(g.search_addresses("uniswap").await.is_empty());
    }

    #[tokio::test]
    async fn search_addresses_parses_results() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [
                    {"link":"https://etherscan.io/address/0x000000000004444c5dc75cB358380D2e3dE08A90"}
                ]
            })))
            .mount(&server)
            .await;
        let g = Google::with_base(&server.uri(), "key", "cse");
        let got = g.search_addresses("uniswap v4").await;
        assert_eq!(got, vec!["0x000000000004444c5dc75cb358380d2e3de08a90"]);
    }
}
