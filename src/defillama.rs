//! DefiLlama discovery: a protocol's main token/governance contract via the free
//! `/protocol/{slug}` API (the `address` field). One anchor address per slug —
//! not the protocol's full contract set, but a clean, free starting point.

use std::time::Duration;

use serde_json::Value;

use crate::github::valid_address;

const DEFAULT_BASE: &str = "https://api.llama.fi";

/// Client for the DefiLlama API.
#[derive(Clone)]
pub struct Defillama {
    http: reqwest::Client,
    base: String,
}

impl Default for Defillama {
    fn default() -> Self {
        Self::new()
    }
}

impl Defillama {
    pub fn new() -> Self {
        Self::with_base(DEFAULT_BASE)
    }

    /// Construct with an explicit base (for testing).
    pub fn with_base(base: &str) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
        }
    }

    /// Fetch a protocol's anchor contract address(es) by DefiLlama slug.
    /// Best-effort: empty on error (non-2xx / parse failures are logged).
    pub async fn fetch_addresses(&self, slug: &str) -> Vec<String> {
        let url = format!("{}/protocol/{}", self.base, encode_slug(slug));
        let Ok(resp) = self.http.get(&url).send().await else {
            return Vec::new();
        };
        let status = resp.status();
        let Ok(text) = resp.text().await else {
            return Vec::new();
        };
        if !status.is_success() {
            tracing::warn!("defillama {slug}: HTTP {status}");
            return Vec::new();
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => parse_protocol_addresses(&v),
            Err(e) => {
                tracing::warn!("defillama {slug}: invalid JSON: {e}");
                Vec::new()
            }
        }
    }
}

/// Percent-encode a slug as a URL path segment (only unreserved chars pass through),
/// so reserved characters (`/ ? # ..` etc.) can't alter the request path.
fn encode_slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Extract EVM contract addresses from a DefiLlama `/protocol/{slug}` response.
/// The `address` field is the protocol's main token/governance contract; it may
/// be plain `0x…` or chain-prefixed like `ethereum:0x…` (non-EVM ones are dropped).
pub fn parse_protocol_addresses(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = v.get("address").and_then(|x| x.as_str()) {
        if let Some(a) = extract_evm_address(s) {
            out.push(a);
        }
    }
    out
}

/// Pull a `0x{40}` EVM address out of a possibly chain-prefixed string.
/// Requires a clean trailing boundary so a longer hex run (e.g. a 32-byte hash)
/// isn't silently truncated into a bogus 20-byte address.
fn extract_evm_address(s: &str) -> Option<String> {
    let idx = s.find("0x")?;
    let rest = &s[idx..];
    // The 42 chars are 0x + 40 ASCII hex; reject if char 42 is another hex digit.
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
    fn parses_plain_and_chain_prefixed() {
        assert_eq!(
            parse_protocol_addresses(&json!({"address":"0x5a98fcbea516cf06857215779fd812ca3bef1b32"})),
            vec!["0x5a98fcbea516cf06857215779fd812ca3bef1b32"]
        );
        assert_eq!(
            parse_protocol_addresses(&json!({"address":"ethereum:0x000000000004444c5dc75cB358380D2e3dE08A90"})),
            vec!["0x000000000004444c5dc75cb358380d2e3de08a90"]
        );
    }

    #[test]
    fn rejects_longer_hex_runs() {
        // A 32-byte hash (0x + 64 hex) must NOT be truncated into a 20-byte address.
        let hash = format!("0x{}", "a".repeat(64));
        assert!(parse_protocol_addresses(&json!({ "address": hash })).is_empty());
        // Address glued to extra hex -> rejected.
        let glued = format!("0x{}deadbeef", "a".repeat(40));
        assert!(parse_protocol_addresses(&json!({ "address": glued })).is_empty());
        // Clean address followed by a non-hex delimiter -> accepted.
        let clean = format!("0x{} (LDO)", "a".repeat(40));
        assert_eq!(parse_protocol_addresses(&json!({ "address": clean })).len(), 1);
    }

    #[test]
    fn encode_slug_neutralizes_reserved() {
        assert_eq!(encode_slug("lido"), "lido");
        assert_eq!(encode_slug("uniswap-v3"), "uniswap-v3");
        assert_eq!(encode_slug("../config"), "..%2Fconfig");
        assert_eq!(encode_slug("foo?x=1"), "foo%3Fx%3D1");
    }

    #[test]
    fn drops_non_evm_and_missing() {
        // Solana-style / no 0x -> nothing.
        assert!(parse_protocol_addresses(&json!({"address":"solana:So11111111111111111111111111111111111111112"})).is_empty());
        assert!(parse_protocol_addresses(&json!({"address":"-"})).is_empty());
        assert!(parse_protocol_addresses(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn dead_endpoint_is_empty() {
        let c = Defillama::with_base("http://127.0.0.1:1");
        assert!(c.fetch_addresses("lido").await.is_empty());
    }

    #[test]
    fn new_and_default_build() {
        let _ = Defillama::new();
        let _ = Defillama::default();
    }

    #[tokio::test]
    async fn fetch_addresses_via_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/lido"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"address":"0x5a98fcbea516cf06857215779fd812ca3bef1b32"}),
            ))
            .mount(&s)
            .await;
        let got = Defillama::with_base(&s.uri()).fetch_addresses("lido").await;
        assert_eq!(got, vec!["0x5a98fcbea516cf06857215779fd812ca3bef1b32"]);
    }

    #[tokio::test]
    async fn http_error_and_invalid_json_are_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/bad"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad slug"))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/protocol/weird"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&s)
            .await;
        let c = Defillama::with_base(&s.uri());
        assert!(c.fetch_addresses("bad").await.is_empty());
        assert!(c.fetch_addresses("weird").await.is_empty());
    }
}
