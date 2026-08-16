//! Discover deployed contract addresses from a GitHub repo's deployment
//! artifacts (hardhat-deploy + Foundry broadcasts), without code-search auth.
//!
//! Flow (2 API calls + N raw fetches): resolve default branch → list the file
//! tree (`git/trees?recursive=1`) → fetch matching artifacts from raw host.

use std::time::Duration;

use serde_json::Value;

const ZERO_ADDR: &str = "0x0000000000000000000000000000000000000000";

/// Which deployment-artifact convention a path matches.
#[derive(Debug, PartialEq, Eq)]
pub enum Artifact {
    /// `deployments/<network>/<Name>.json` (hardhat-deploy).
    Hardhat,
    /// `broadcast/<Script>/<chainId>/run-latest.json` (Foundry).
    Foundry,
    /// `README.md` / `*scope*.md` — audit-contest scope tables list addresses here.
    Markdown,
}

/// Classify a repo file path as a known deployment artifact, if any.
pub fn classify_path(path: &str) -> Option<Artifact> {
    let p = path.trim_start_matches("./");
    // Audit scope: README / scope markdown (e.g. Code4rena / Sherlock contest repos).
    // Skip vendored deps (a `lib` or `node_modules` path segment).
    let vendored = p
        .split('/')
        .any(|s| s.eq_ignore_ascii_case("lib") || s == "node_modules");
    if !vendored {
        let fname = p.rsplit('/').next().unwrap_or(p).to_ascii_lowercase();
        if fname == "readme.md" || (fname.ends_with(".md") && fname.contains("scope")) {
            return Some(Artifact::Markdown);
        }
    }
    // hardhat-deploy: deployments/<net>/<Name>.json, excluding solcInputs + dotfiles.
    if let Some(rest) = p.strip_prefix("deployments/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2
            && parts[1].ends_with(".json")
            && !parts[1].starts_with('.')
            && parts[0] != "solcInputs"
            && parts[1] != "solcInputs.json"
        {
            return Some(Artifact::Hardhat);
        }
    }
    // Foundry: broadcast/**/run-latest.json (skip dry-run/). Depth >= 3 keeps the
    // canonical broadcast/<Script>/<chainId>/run-latest.json plus nested layouts,
    // while still excluding a bare broadcast/run-latest.json.
    if p.starts_with("broadcast/")
        && !p.contains("/dry-run/")
        && p.ends_with("/run-latest.json")
        && p.matches('/').count() >= 3
    {
        return Some(Artifact::Foundry);
    }
    None
}

/// Normalize + validate a hex address; `None` if malformed or zero.
pub fn valid_address(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 42
        && s.starts_with("0x")
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
        && !s.eq_ignore_ascii_case(ZERO_ADDR)
    {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

/// Extract addresses from a hardhat-deploy artifact: the deployed `address` and,
/// for proxy artifacts, the `implementation` logic-contract address.
pub fn parse_hardhat(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["address", "implementation"] {
        if let Some(a) = v.get(key).and_then(|a| a.as_str()).and_then(valid_address) {
            out.push(a);
        }
    }
    out
}

/// Extract addresses from a Foundry `run-latest.json` broadcast.
pub fn parse_foundry(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: Option<&str>| {
        if let Some(a) = s.and_then(valid_address) {
            out.push(a);
        }
    };
    if let Some(txs) = v.get("transactions").and_then(|t| t.as_array()) {
        for tx in txs {
            let kind = tx.get("transactionType").and_then(|t| t.as_str()).unwrap_or("");
            if kind == "CREATE" || kind == "CREATE2" {
                push(tx.get("contractAddress").and_then(|a| a.as_str()));
            }
            if let Some(extra) = tx.get("additionalContracts").and_then(|a| a.as_array()) {
                for c in extra {
                    push(c.get("address").and_then(|a| a.as_str()));
                }
            }
        }
    }
    if let Some(rs) = v.get("receipts").and_then(|r| r.as_array()) {
        for r in rs {
            push(r.get("contractAddress").and_then(|a| a.as_str()));
        }
    }
    out
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("blockscan/0.1")
        .http1_only()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

/// Discover addresses from `owner/repo`. Best-effort: returns whatever it finds,
/// empty on error. `token` (may be empty) raises GitHub's rate limit.
pub async fn discover_repo(spec: &str, token: &str) -> Vec<String> {
    discover_repo_with(
        "https://api.github.com",
        "https://raw.githubusercontent.com",
        spec,
        token,
    )
    .await
}

/// Inner discovery with injectable API/raw bases (for testing).
pub async fn discover_repo_with(
    api_base: &str,
    raw_base: &str,
    spec: &str,
    token: &str,
) -> Vec<String> {
    let http = client();
    let Some((owner, repo)) = spec.split_once('/') else {
        tracing::warn!("invalid --github repo '{spec}', expected owner/repo");
        return Vec::new();
    };

    let get = |url: String| {
        let mut req = http.get(url).header("Accept", "application/vnd.github+json");
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req
    };

    // 1. default branch
    let branch = match get(format!("{api_base}/repos/{owner}/{repo}")).send().await {
        Ok(r) => r
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.get("default_branch").and_then(|b| b.as_str()).map(String::from))
            .unwrap_or_else(|| "main".into()),
        Err(e) => {
            tracing::warn!("github: failed to read {owner}/{repo}: {e}");
            return Vec::new();
        }
    };

    // 2. recursive tree
    let tree_url = format!("{api_base}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1");
    let tree: Value = match get(tree_url).send().await.and_then(|r| r.error_for_status()) {
        Ok(r) => r.json().await.unwrap_or(Value::Null),
        Err(e) => {
            tracing::warn!("github: failed to list tree for {owner}/{repo}: {e}");
            return Vec::new();
        }
    };
    if tree.get("truncated").and_then(|t| t.as_bool()).unwrap_or(false) {
        tracing::warn!("github: {owner}/{repo} tree truncated; some artifacts may be missed");
    }

    let paths: Vec<(String, Artifact)> = tree
        .get("tree")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("blob"))
                .filter_map(|e| e.get("path").and_then(|p| p.as_str()))
                .filter_map(|p| classify_path(p).map(|k| (p.to_string(), k)))
                .collect()
        })
        .unwrap_or_default();

    // 3. fetch + parse each artifact
    let mut out = Vec::new();
    for (path, kind) in paths {
        let raw_url = format!("{raw_base}/{owner}/{repo}/{branch}/{path}");
        let Ok(resp) = http.get(&raw_url).header("User-Agent", "blockscan/0.1").send().await else {
            continue;
        };
        // Skip non-2xx bodies (404 page, rate-limit notice) — never parse them as
        // an artifact (matches the status guard in defillama/tokenlist/coingecko).
        if !resp.status().is_success() {
            continue;
        }
        match kind {
            // Audit scope: extract addresses from markdown text (0x{40} + explorer links).
            Artifact::Markdown => {
                if let Ok(text) = resp.text().await {
                    out.extend(crate::website::extract_addresses(&text));
                }
            }
            Artifact::Hardhat => {
                if let Ok(v) = resp.json::<Value>().await {
                    out.extend(parse_hardhat(&v));
                }
            }
            Artifact::Foundry => {
                if let Ok(v) = resp.json::<Value>().await {
                    out.extend(parse_foundry(&v));
                }
            }
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

    #[test]
    fn classify_paths() {
        assert_eq!(classify_path("deployments/mainnet/Token.json"), Some(Artifact::Hardhat));
        assert_eq!(
            classify_path("broadcast/Deploy.s.sol/1/run-latest.json"),
            Some(Artifact::Foundry)
        );
        // Nested (depth >= 3) Foundry layouts also match.
        assert_eq!(
            classify_path("broadcast/Deploy.s.sol/1/extra/run-latest.json"),
            Some(Artifact::Foundry)
        );
        // Excluded / non-matching paths.
        assert_eq!(classify_path("deployments/mainnet/solcInputs/abc.json"), None);
        assert_eq!(classify_path("deployments/mainnet/.chainId"), None);
        assert_eq!(classify_path("broadcast/Deploy.s.sol/1/dry-run/run-latest.json"), None);
        assert_eq!(classify_path("broadcast/run-latest.json"), None); // too shallow
        assert_eq!(classify_path("src/Token.sol"), None);
        // Audit-scope markdown.
        assert_eq!(classify_path("README.md"), Some(Artifact::Markdown));
        assert_eq!(classify_path("audit/Scope.md"), Some(Artifact::Markdown));
        assert_eq!(classify_path("docs/guide.md"), None); // non-readme/non-scope md
        assert_eq!(classify_path("lib/dep/README.md"), None); // excluded under /lib/
    }

    #[test]
    fn valid_address_checks() {
        assert_eq!(
            valid_address("0x000000000000000000000000000000000000DeAd").as_deref(),
            Some("0x000000000000000000000000000000000000dead")
        );
        assert!(valid_address("0x123").is_none());
        assert!(valid_address(ZERO_ADDR).is_none());
        assert!(valid_address("0xzz00000000000000000000000000000000000000").is_none());
    }

    #[test]
    fn parse_hardhat_reads_address_and_implementation() {
        let v = json!({"address":"0x000000000000000000000000000000000000dEaD","abi":[]});
        assert_eq!(parse_hardhat(&v), vec!["0x000000000000000000000000000000000000dead"]);
        assert!(parse_hardhat(&json!({"abi":[]})).is_empty());
        // Proxy artifact: both the proxy address and the implementation are returned.
        let proxy = json!({
            "address":"0x1111111111111111111111111111111111111111",
            "implementation":"0x2222222222222222222222222222222222222222"
        });
        assert_eq!(
            parse_hardhat(&proxy),
            vec![
                "0x1111111111111111111111111111111111111111".to_string(),
                "0x2222222222222222222222222222222222222222".to_string(),
            ]
        );
    }

    #[test]
    fn parse_foundry_reads_creates_and_extras() {
        let v = json!({
            "transactions": [
                {"transactionType":"CREATE","contractAddress":"0x1111111111111111111111111111111111111111",
                 "additionalContracts":[{"address":"0x2222222222222222222222222222222222222222"}]},
                {"transactionType":"CALL","contractAddress":"0x3333333333333333333333333333333333333333"}
            ],
            "receipts": [{"contractAddress":"0x4444444444444444444444444444444444444444"}]
        });
        let mut got = parse_foundry(&v);
        got.sort();
        assert_eq!(
            got,
            vec![
                "0x1111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222",
                "0x4444444444444444444444444444444444444444",
            ]
        );
        // The CALL tx's contractAddress is excluded.
        assert!(!got.contains(&"0x3333333333333333333333333333333333333333".to_string()));
    }

    #[tokio::test]
    async fn discover_repo_invalid_spec() {
        assert!(discover_repo_with("http://x", "http://y", "noslash", "").await.is_empty());
    }

    #[tokio::test]
    async fn discover_repo_public_wrapper_invalid_spec() {
        // Exercises the public wrapper (real bases); invalid spec returns before any request.
        assert!(discover_repo("noslash", "").await.is_empty());
    }

    #[tokio::test]
    async fn discover_repo_dead_endpoint() {
        assert!(discover_repo_with("http://127.0.0.1:1", "http://127.0.0.1:1", "o/r", "")
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn discover_handles_truncation_and_bad_files() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let gh = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"default_branch":"main"})))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/trees/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "truncated": true,
                "tree": [
                    {"path":"deployments/m/Good.json","type":"blob"},
                    {"path":"deployments/m/Bad.json","type":"blob"}
                ]
            })))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/o/r/main/deployments/m/Good.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "address":"0x1111111111111111111111111111111111111111"
            })))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/o/r/main/deployments/m/Bad.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&gh)
            .await;

        // Non-empty token exercises the Bearer-auth header path.
        let got = discover_repo_with(&gh.uri(), &gh.uri(), "o/r", "tok123").await;
        assert_eq!(got, vec!["0x1111111111111111111111111111111111111111".to_string()]);
    }

    #[tokio::test]
    async fn discover_extracts_readme_scope_addresses() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let gh = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"default_branch":"main"})))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/trees/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "truncated": false,
                "tree": [{"path":"README.md","type":"blob"}]
            })))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/o/r/main/README.md"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "## Scope\n| Vault | 0x1111111111111111111111111111111111111111 |",
            ))
            .mount(&gh)
            .await;
        let got = discover_repo_with(&gh.uri(), &gh.uri(), "o/r", "").await;
        assert_eq!(got, vec!["0x1111111111111111111111111111111111111111".to_string()]);
    }

    #[tokio::test]
    async fn discover_tree_error_is_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let gh = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"default_branch":"main"})))
            .mount(&gh)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/o/r/git/trees/main"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&gh)
            .await;
        assert!(discover_repo_with(&gh.uri(), &gh.uri(), "o/r", "").await.is_empty());
    }
}
