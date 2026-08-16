//! CoinGecko discovery: a coin's on-chain contract address for the current chain
//! via the free `/api/v3/coins/{id}` API (the `platforms` map). One address per
//! `(coin, chain)` — a clean, free, key-less "coin → contract" anchor, mirroring
//! the `defillama` / `tokenlist` sources.

use std::time::Duration;

use serde_json::Value;

use crate::github::valid_address;

const DEFAULT_BASE: &str = "https://api.coingecko.com";

/// Client for the CoinGecko API.
#[derive(Clone)]
pub struct CoinGecko {
    http: reqwest::Client,
    base: String,
}

impl Default for CoinGecko {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinGecko {
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

    /// Fetch a coin's contract address on `chain_id` by CoinGecko coin `id`.
    /// Best-effort: empty on error (non-2xx / parse failures are logged), on an
    /// unsupported chain, or when the coin has no contract on that chain.
    pub async fn fetch_addresses(&self, id: &str, chain_id: u64) -> Vec<String> {
        let Some(platform) = coingecko_platform(chain_id) else {
            tracing::warn!("coingecko {id}: chain {chain_id} has no known CoinGecko platform key");
            return Vec::new();
        };
        let url = format!("{}/api/v3/coins/{}", self.base, encode_id(id));
        let Ok(resp) = self.http.get(&url).send().await else {
            return Vec::new();
        };
        let status = resp.status();
        let Ok(text) = resp.text().await else {
            return Vec::new();
        };
        if !status.is_success() {
            tracing::warn!("coingecko {id}: HTTP {status}");
            return Vec::new();
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => parse_platforms(&v, platform),
            Err(e) => {
                tracing::warn!("coingecko {id}: invalid JSON: {e}");
                Vec::new()
            }
        }
    }
}

/// Map an EVM chain id to its CoinGecko `platforms` key. Covers the chains this
/// tool supports; an unknown chain returns `None` (so we never guess a key).
pub fn coingecko_platform(chain_id: u64) -> Option<&'static str> {
    Some(match chain_id {
        1 => "ethereum",
        10 => "optimistic-ethereum",
        8453 => "base",
        42161 => "arbitrum-one",
        137 => "polygon-pos",
        _ => return None,
    })
}

/// Percent-encode a coin id as a single URL path segment (only unreserved chars
/// pass through), so reserved characters (`/ ? # ..` etc.) can't alter the path.
fn encode_id(s: &str) -> String {
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

/// Extract the contract address for `platform` from a `/coins/{id}` response's
/// `platforms` map. The value is a plain `0x…` string (or empty for the coin's
/// native chain); invalid / empty / zero addresses are dropped.
pub fn parse_platforms(v: &Value, platform: &str) -> Vec<String> {
    v.get("platforms")
        .and_then(|p| p.get(platform))
        .and_then(|a| a.as_str())
        .and_then(valid_address)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn platform_keys_map_supported_chains() {
        assert_eq!(coingecko_platform(1), Some("ethereum"));
        assert_eq!(coingecko_platform(10), Some("optimistic-ethereum"));
        assert_eq!(coingecko_platform(8453), Some("base"));
        assert_eq!(coingecko_platform(42161), Some("arbitrum-one"));
        assert_eq!(coingecko_platform(137), Some("polygon-pos"));
        assert_eq!(coingecko_platform(999999), None);
    }

    #[test]
    fn parses_address_for_the_requested_platform() {
        let body = json!({
            "platforms": {
                "ethereum": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                "polygon-pos": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063"
            }
        });
        assert_eq!(
            parse_platforms(&body, "ethereum"),
            vec!["0x6b175474e89094c44da98b954eedeac495271d0f"]
        );
        assert_eq!(
            parse_platforms(&body, "polygon-pos"),
            vec!["0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"]
        );
    }

    #[test]
    fn missing_platform_or_map_yields_empty() {
        let body = json!({ "platforms": { "ethereum": "0x6b175474e89094c44da98b954eedeac495271d0f" } });
        assert!(parse_platforms(&body, "base").is_empty()); // coin not on this chain
        assert!(parse_platforms(&json!({}), "ethereum").is_empty()); // no platforms map
    }

    #[test]
    fn empty_and_invalid_addresses_dropped() {
        // The native chain's entry is an empty string; junk and the zero address
        // must be rejected.
        assert!(parse_platforms(&json!({"platforms":{"ethereum":""}}), "ethereum").is_empty());
        assert!(parse_platforms(&json!({"platforms":{"ethereum":"not-an-address"}}), "ethereum").is_empty());
        let zero = format!("0x{}", "0".repeat(40));
        assert!(parse_platforms(&json!({ "platforms": { "ethereum": zero } }), "ethereum").is_empty());
        // A 32-byte hash is the wrong length and must be rejected.
        let hash = format!("0x{}", "a".repeat(64));
        assert!(parse_platforms(&json!({ "platforms": { "ethereum": hash } }), "ethereum").is_empty());
    }

    #[test]
    fn encode_id_neutralizes_reserved() {
        assert_eq!(encode_id("dai"), "dai");
        assert_eq!(encode_id("usd-coin"), "usd-coin");
        assert_eq!(encode_id("../config"), "..%2Fconfig");
        assert_eq!(encode_id("foo?x=1"), "foo%3Fx%3D1");
    }

    #[tokio::test]
    async fn unsupported_chain_is_empty_without_request() {
        // Even a live-looking base must not be hit for an unsupported chain.
        let c = CoinGecko::with_base("http://127.0.0.1:1");
        assert!(c.fetch_addresses("dai", 999999).await.is_empty());
    }

    #[tokio::test]
    async fn dead_endpoint_is_empty() {
        let c = CoinGecko::with_base("http://127.0.0.1:1");
        assert!(c.fetch_addresses("dai", 1).await.is_empty());
    }

    #[test]
    fn new_and_default_build() {
        let _ = CoinGecko::new();
        let _ = CoinGecko::default();
    }

    #[tokio::test]
    async fn fetch_addresses_via_mock() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/coins/dai"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "platforms": { "ethereum": "0x6b175474e89094c44da98b954eedeac495271d0f" }
            })))
            .mount(&s)
            .await;
        let got = CoinGecko::with_base(&s.uri()).fetch_addresses("dai", 1).await;
        assert_eq!(got, vec!["0x6b175474e89094c44da98b954eedeac495271d0f"]);
    }

    #[tokio::test]
    async fn http_error_and_invalid_json_are_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/coins/bad"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v3/coins/weird"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&s)
            .await;
        let c = CoinGecko::with_base(&s.uri());
        assert!(c.fetch_addresses("bad", 1).await.is_empty());
        assert!(c.fetch_addresses("weird", 1).await.is_empty());
    }
}
