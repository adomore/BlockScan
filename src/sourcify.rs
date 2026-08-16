//! Sourcify v2 source fallback — used when Etherscan has no verified source.
//!
//! API (verified live): `GET {base}/v2/contract/{chainId}/{address}?fields=sources`
//! returns `{ "sources": { "<relative path>": { "content": "..." } } }` when the
//! contract is verified (either `match` or `exact_match`); 404 / no `sources`
//! otherwise. We treat any returned sources as usable.

use std::time::Duration;

use serde_json::Value;

use crate::model::SourceFile;
use crate::storage;

/// Client for a Sourcify server.
#[derive(Clone)]
pub struct Sourcify {
    http: reqwest::Client,
    base: String,
    chain_id: u64,
    enabled: bool,
}

impl Sourcify {
    pub fn new(base: &str, chain_id: u64) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let enabled = !base.is_empty();
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            http,
            base,
            chain_id,
            enabled,
        }
    }

    /// Fetch verified source files from Sourcify. Returns empty on
    /// disabled / not-verified / any error (best-effort fallback).
    pub async fn fetch_sources(&self, address: &str) -> Vec<SourceFile> {
        if !self.enabled {
            return Vec::new();
        }
        let url = format!(
            "{}/v2/contract/{}/{}?fields=sources",
            self.base, self.chain_id, address
        );
        let Ok(resp) = self.http.get(&url).send().await else {
            return Vec::new();
        };
        let Ok(text) = resp.text().await else {
            return Vec::new();
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => parse_sourcify_sources(&v),
            Err(_) => Vec::new(),
        }
    }
}

/// Extract source files from a Sourcify v2 `?fields=sources` response.
/// The `sources` object maps a relative path to `{ "content": "..." }`.
pub fn parse_sourcify_sources(v: &Value) -> Vec<SourceFile> {
    let Some(map) = v.get("sources").and_then(|s| s.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, entry) in map {
        if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
            out.push(SourceFile {
                path: storage::sanitize_path(path),
                content: content.to_string(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_sources_map() {
        let v = json!({
            "match": "match",
            "sources": {
                "src/A.sol": { "content": "contract A {}" },
                "lib/B.sol": { "content": "contract B {}" }
            }
        });
        let mut files = parse_sourcify_sources(&v);
        files.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "lib/B.sol");
        assert_eq!(files[1].content, "contract A {}");
    }

    #[test]
    fn no_sources_field_is_empty() {
        assert!(parse_sourcify_sources(&json!({"match": null})).is_empty());
        assert!(parse_sourcify_sources(&json!({"sources": "oops"})).is_empty());
    }

    #[test]
    fn sanitizes_paths() {
        let v = json!({"sources": {"../../evil.sol": {"content":"x"}}});
        let files = parse_sourcify_sources(&v);
        assert!(!files[0].path.contains(".."));
    }

    #[tokio::test]
    async fn disabled_when_base_empty() {
        let s = Sourcify::new("", 1);
        assert!(s.fetch_sources("0xabc").await.is_empty());
    }

    #[tokio::test]
    async fn dead_endpoint_is_empty() {
        let s = Sourcify::new("http://127.0.0.1:1", 1);
        assert!(s.fetch_sources("0xabc").await.is_empty());
    }
}
