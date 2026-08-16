//! Token List discovery: a standard Token List JSON (`tokens[]`) filtered by the
//! active chain id. Yields each token's `address` for the current chain.

use std::time::Duration;

use serde_json::Value;

use crate::github::valid_address;

/// Client for fetching a Token List by URL.
#[derive(Clone)]
pub struct TokenList {
    http: reqwest::Client,
}

impl Default for TokenList {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenList {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { http }
    }

    /// Fetch a Token List and return token addresses for `chain_id`.
    /// Best-effort: empty on error (non-2xx / parse failures are logged).
    pub async fn fetch(&self, url: &str, chain_id: u64) -> Vec<String> {
        let Ok(resp) = self.http.get(url).send().await else {
            return Vec::new();
        };
        let status = resp.status();
        let Ok(text) = resp.text().await else {
            return Vec::new();
        };
        if !status.is_success() {
            tracing::warn!("tokenlist {url}: HTTP {status}");
            return Vec::new();
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => parse_token_list(&v, chain_id),
            Err(e) => {
                tracing::warn!("tokenlist {url}: invalid JSON: {e}");
                Vec::new()
            }
        }
    }
}

/// Extract token addresses for `chain_id` from a Token List's `tokens[]`.
pub fn parse_token_list(v: &Value, chain_id: u64) -> Vec<String> {
    let Some(tokens) = v.get("tokens").and_then(|t| t.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for t in tokens {
        if t.get("chainId").and_then(|c| c.as_u64()) != Some(chain_id) {
            continue;
        }
        if let Some(a) = t.get("address").and_then(|a| a.as_str()).and_then(valid_address) {
            out.push(a);
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({"tokens":[
            {"chainId":1,"address":"0x000000000004444c5dc75cB358380D2e3dE08A90","symbol":"A"},
            {"chainId":1,"address":"0x5a98fcbea516cf06857215779fd812ca3bef1b32","symbol":"B"},
            {"chainId":10,"address":"0x1111111111111111111111111111111111111111","symbol":"C"},
            {"chainId":1,"address":"0xZZ","symbol":"BAD"}
        ]})
    }

    #[test]
    fn filters_by_chain_and_validates() {
        let m = parse_token_list(&sample(), 1);
        assert_eq!(m.len(), 2); // chain-10 and malformed excluded
        assert!(m.contains(&"0x000000000004444c5dc75cb358380d2e3de08a90".to_string()));
        assert_eq!(parse_token_list(&sample(), 10), vec!["0x1111111111111111111111111111111111111111"]);
        assert!(parse_token_list(&sample(), 999).is_empty());
    }

    #[test]
    fn no_tokens_field_is_empty() {
        assert!(parse_token_list(&json!({}), 1).is_empty());
    }

    #[test]
    fn new_and_default_build() {
        let _ = TokenList::new();
        let _ = TokenList::default();
    }

    #[tokio::test]
    async fn dead_endpoint_is_empty() {
        assert!(TokenList::new().fetch("http://127.0.0.1:1", 1).await.is_empty());
    }

    #[tokio::test]
    async fn fetch_via_mock() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample()))
            .mount(&s)
            .await;
        let got = TokenList::new().fetch(&s.uri(), 1).await;
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn http_error_is_empty() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        assert!(TokenList::new().fetch(&s.uri(), 1).await.is_empty());
    }

    #[tokio::test]
    async fn invalid_json_is_empty() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&s)
            .await;
        assert!(TokenList::new().fetch(&s.uri(), 1).await.is_empty());
    }
}
