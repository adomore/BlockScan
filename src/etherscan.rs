use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use serde::Deserialize;

use crate::error::{AppError, Result};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Client for the Etherscan V2 unified API.
#[derive(Clone)]
pub struct EtherscanClient {
    http: reqwest::Client,
    base: String,
    api_key: String,
    chain_id: u64,
    retries: u32,
    limiter: Arc<DirectLimiter>,
}

/// Standard Etherscan envelope. `result` shape varies per action.
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    status: String,
    message: String,
    result: T,
}

/// One entry from `getsourcecode`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SourceCodeResult {
    #[serde(rename = "SourceCode", default)]
    pub source_code: String,
    #[serde(rename = "ABI", default)]
    pub abi: String,
    pub contract_name: String,
    pub compiler_version: String,
    pub optimization_used: String,
    pub runs: String,
    #[serde(rename = "EVMVersion", default)]
    pub evm_version: String,
    pub constructor_arguments: String,
    pub license_type: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default)]
    pub implementation: String,
}

/// One entry from `getcontractcreation`.
#[derive(Debug, Deserialize)]
pub struct CreationResult {
    #[serde(rename = "contractCreator")]
    pub contract_creator: String,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
}

impl EtherscanClient {
    pub fn new(base: &str, api_key: &str, chain_id: u64, rate: u32, retries: u32) -> Result<Self> {
        let quota = Quota::per_second(
            NonZeroU32::new(rate).ok_or_else(|| AppError::Config("rate must be >= 1".into()))?,
        );
        let limiter = Arc::new(RateLimiter::direct(quota));
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            // Force HTTP/1.1: some networks/intermediaries break reqwest's HTTP/2
            // negotiation to api.etherscan.io even when curl (with fallback) works.
            .http1_only()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base: base.to_string(),
            api_key: api_key.to_string(),
            chain_id,
            retries: retries.max(1),
            limiter,
        })
    }

    async fn get_json(&self, params: &[(&str, &str)]) -> Result<String> {
        let chain = self.chain_id.to_string();
        let mut query: Vec<(&str, &str)> =
            vec![("chainid", chain.as_str()), ("apikey", self.api_key.as_str())];
        query.extend_from_slice(params);

        // Retry transient transport errors AND Etherscan rate-limit replies
        // (HTTP 200 with a "rate limit reached" body) with linear backoff.
        let max_attempts = self.retries;
        let mut last_err: Option<reqwest::Error> = None;
        for attempt in 1..=max_attempts {
            self.limiter.until_ready().await;
            match self.http.get(&self.base).query(&query).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().await?;
                    // Retry server-side failures (HTTP 5xx / 429) and Etherscan's
                    // 200-with-"rate limit reached" body, but never after the last
                    // attempt. A 2xx (incl. the unverified-contract body) returns.
                    let retryable =
                        status.is_server_error() || status.as_u16() == 429 || is_rate_limited(&text);
                    if retryable && attempt < max_attempts {
                        tracing::debug!(
                            "etherscan attempt {attempt}/{max_attempts}: HTTP {status} / rate-limited; backing off"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(600 * attempt as u64))
                            .await;
                        continue;
                    }
                    return Ok(text);
                }
                Err(e) => {
                    tracing::debug!("etherscan request attempt {attempt}/{max_attempts} failed: {e}");
                    last_err = Some(e);
                    if attempt < max_attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64))
                            .await;
                    }
                }
            }
        }
        Err(AppError::Http(last_err.expect("loop runs at least once")))
    }

    /// Fetch verified source + metadata.
    /// An unverified contract still returns a (mostly empty) `SourceCodeResult`.
    pub async fn get_source_code(&self, address: &str) -> Result<SourceCodeResult> {
        let text = self
            .get_json(&[
                ("module", "contract"),
                ("action", "getsourcecode"),
                ("address", address),
            ])
            .await?;
        parse_source_code(&text)
    }

    /// Fetch creator address + creation tx hash. Returns `None` if not found.
    pub async fn get_contract_creation(&self, address: &str) -> Result<Option<CreationResult>> {
        let text = self
            .get_json(&[
                ("module", "contract"),
                ("action", "getcontractcreation"),
                ("contractaddresses", address),
            ])
            .await?;
        parse_creation(&text)
    }
}

/// How much of a response body an error message may carry, in bytes.
///
/// Large enough that the diagnostic still works — an unexpected envelope is
/// legible well inside this — and small enough to be a bound.
const ERROR_BODY_BUDGET: usize = 512;

/// A response body rendered for an error message: clipped to
/// [`ERROR_BODY_BUDGET`] bytes with the cut stated, and control characters
/// escaped.
///
/// The verbosity is worth keeping. When an explorer returns a shape nothing
/// expects, the body is the only thing that says what it returned, and an error
/// that omits it sends someone to reproduce the request by hand. What is not
/// worth keeping is that the length and the bytes are the explorer's to choose
/// rather than this tool's: an error tends to reach a log, an unbounded one
/// fills it, and a body carrying a newline writes a second line into it that a
/// reader cannot tell from a real one.
///
/// The budget applies to what comes *out*, not to what goes in. Escaping
/// expands — a control byte becomes up to seven characters — so budgeting the
/// input would leave the message unbounded for exactly the input a hostile
/// responder would send. Iterating characters also means a multi-byte character
/// straddling the edge is dropped whole rather than split into invalid UTF-8.
fn clip_body(text: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(ERROR_BODY_BUDGET + 40);
    let mut consumed = 0usize;
    let mut esc = String::new();
    for c in text.chars() {
        esc.clear();
        match c {
            '\n' => esc.push_str("\\n"),
            '\r' => esc.push_str("\\r"),
            '\t' => esc.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(esc, "\\u{{{:x}}}", c as u32);
            }
            c => esc.push(c),
        }
        if out.len() + esc.len() > ERROR_BODY_BUDGET {
            break;
        }
        out.push_str(&esc);
        consumed += c.len_utf8();
    }
    if consumed < text.len() {
        // Stated, not implied: without this a reader concludes the explorer
        // sent exactly these bytes, which is the wrong thing to debug.
        let _ = write!(out, "…[truncated, {} bytes total]", text.len());
    }
    out
}

/// True if an Etherscan response body indicates a per-second rate limit.
pub fn is_rate_limited(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("rate limit") || t.contains("max calls per sec")
}

/// True when a non-success envelope means "the explorer has no such record"
/// rather than "the request did not succeed".
///
/// Both arrive as `status: "0"`; only the text tells them apart. Only the
/// absence side is enumerated, so an envelope this does not recognise -- a rate
/// limit, a rejected key, a message added next year -- is a failure.
/// Enumerating the failure side instead is what lets a new error string quietly
/// become an absence.
fn means_absent(message: &str, detail: &str) -> bool {
    const ABSENT: [&str; 2] = ["no data found", "no record found"];
    let m = message.to_ascii_lowercase();
    let d = detail.to_ascii_lowercase();
    ABSENT.iter().any(|p| m.contains(p) || d.contains(p))
}

/// Parse a `getsourcecode` response body into a [`SourceCodeResult`].
///
/// `result` is normally an array, but on error (invalid key, rate limit) it is a
/// plain string message — parse into a `Value` first to handle both shapes.
pub fn parse_source_code(text: &str) -> Result<SourceCodeResult> {
    let env: Envelope<serde_json::Value> = serde_json::from_str(text)
        .map_err(|e| {
            AppError::Etherscan(format!("getsourcecode parse failed: {e}; body={}", clip_body(text)))
        })?;

    if env.status != "1" {
        let detail = env.result.as_str().unwrap_or(env.message.as_str());
        return Err(AppError::Etherscan(format!("getsourcecode failed: {detail}")));
    }

    let arr = env
        .result
        .as_array()
        .ok_or_else(|| AppError::Etherscan("getsourcecode: unexpected result shape".into()))?;
    let first = arr
        .first()
        .ok_or_else(|| AppError::Etherscan("getsourcecode returned no entries".into()))?;
    let result: SourceCodeResult = serde_json::from_value(first.clone())?;
    Ok(result)
}

/// Parse a `getcontractcreation` response body.
///
/// Three outcomes, deliberately distinct: `Ok(Some)` the record exists,
/// `Ok(None)` the explorer answered and there is no record, `Err` the request
/// did not succeed. Folding the last two together -- which is what returning
/// `None` for every `status != "1"` did -- makes a rate-limited lookup
/// indistinguishable from a contract with no creation record, and the caller
/// then writes that absence to disk as fact.
pub fn parse_creation(text: &str) -> Result<Option<CreationResult>> {
    let env: Envelope<serde_json::Value> = serde_json::from_str(text)
        .map_err(|e| {
            AppError::Etherscan(format!(
                "getcontractcreation parse failed: {e}; body={}",
                clip_body(text)
            ))
        })?;

    if env.status != "1" {
        let detail = env.result.as_str().unwrap_or_default();
        if means_absent(&env.message, detail) {
            return Ok(None);
        }
        let shown = if detail.is_empty() { env.message.as_str() } else { detail };
        return Err(AppError::Etherscan(format!("getcontractcreation failed: {shown}")));
    }
    let arr = env.result.as_array().ok_or_else(|| {
        AppError::Etherscan(format!(
            "getcontractcreation: unexpected result shape; body={}",
            clip_body(text)
        ))
    })?;
    match arr.first() {
        Some(v) => Ok(Some(serde_json::from_value(v.clone())?)),
        // A success envelope with an empty array: answered, and empty. The one
        // shape where absence is unambiguous.
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_zero_rate() {
        assert!(matches!(
            EtherscanClient::new("http://x", "k", 1, 0, 3),
            Err(AppError::Config(_))
        ));
    }

    #[test]
    fn new_ok() {
        assert!(EtherscanClient::new("http://x", "k", 1, 5, 3).is_ok());
    }

    #[test]
    fn parse_source_code_ok() {
        let body = r#"{"status":"1","message":"OK","result":[{"SourceCode":"contract C {}","ABI":"[]","ContractName":"C","CompilerVersion":"v0.8.0","OptimizationUsed":"1","Runs":"200","EVMVersion":"london","ConstructorArguments":"","LicenseType":"MIT","Proxy":"0","Implementation":""}]}"#;
        let r = parse_source_code(body).unwrap();
        assert_eq!(r.contract_name, "C");
        assert_eq!(r.source_code, "contract C {}");
    }

    #[test]
    fn parse_source_code_status0_string_detail() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#;
        let err = parse_source_code(body).unwrap_err().to_string();
        assert!(err.contains("Invalid API Key"), "{err}");
    }

    #[test]
    fn parse_source_code_status0_message_fallback() {
        // result is not a string, so the message is used as detail.
        let body = r#"{"status":"0","message":"rate limited","result":null}"#;
        let err = parse_source_code(body).unwrap_err().to_string();
        assert!(err.contains("rate limited"), "{err}");
    }

    #[test]
    fn parse_source_code_result_not_array() {
        let body = r#"{"status":"1","message":"OK","result":{"x":1}}"#;
        let err = parse_source_code(body).unwrap_err().to_string();
        assert!(err.contains("unexpected result shape"), "{err}");
    }

    #[test]
    fn parse_source_code_empty_array() {
        let body = r#"{"status":"1","message":"OK","result":[]}"#;
        let err = parse_source_code(body).unwrap_err().to_string();
        assert!(err.contains("no entries"), "{err}");
    }

// ---- T-17: the response body embedded in a parse error ----

    /// A short body is passed through whole. The verbosity is the point of the
    /// message; the budget is only a ceiling.
    #[test]
    fn a_body_within_budget_is_not_touched() {
        let body = r#"{"unexpected":"shape"}"#;
        assert_eq!(clip_body(body), body);
        assert!(!clip_body(body).contains("truncated"));
    }

    /// Over budget: clipped, and the clip is stated with the real size, because
    /// a reader who thinks they are looking at the whole reply debugs the wrong
    /// thing.
    #[test]
    fn an_oversized_body_is_clipped_and_says_so() {
        let body = "x".repeat(20_000);
        let out = clip_body(&body);
        assert!(out.len() < ERROR_BODY_BUDGET + 64, "the result must be bounded: {}", out.len());
        assert!(out.starts_with(&"x".repeat(ERROR_BODY_BUDGET)));
        assert!(out.contains("truncated"), "{out}");
        assert!(out.contains("20000 bytes total"), "{out}");
    }

    /// The clip walks back to a character boundary. A naive byte slice here
    /// panics, and a panic inside error construction loses the error.
    #[test]
    fn clipping_never_splits_a_character() {
        // Multi-byte throughout, so the budget lands mid-character.
        let body = "\u{4e2d}".repeat(1000);
        let out = clip_body(&body);
        assert!(out.contains("truncated"));
        // Valid UTF-8 by construction (String), and no replacement characters.
        assert!(!out.contains('\u{fffd}'));
        let kept: String = out.chars().take_while(|c| *c == '\u{4e2d}').collect();
        assert!(kept.len() <= ERROR_BODY_BUDGET, "kept {} bytes", kept.len());
        assert!(kept.len() > ERROR_BODY_BUDGET - 3, "should fill the budget: {}", kept.len());
        assert_eq!(kept.len() % 3, 0, "a 3-byte character was split");
    }

    /// The length is not the only thing the explorer chooses. A body carrying a
    /// newline writes a second line into whatever log this reaches, and nothing
    /// downstream can tell it from a real one.
    #[test]
    fn control_characters_do_not_survive_into_the_message() {
        let out = clip_body("a\nb\r\nc\td\u{1b}[31me\u{0}f");
        for c in out.chars() {
            assert!(!c.is_control(), "a control character survived: {out:?}");
        }
        assert!(out.contains("a\\nb"), "{out}");
        assert!(out.contains("c\\td"), "{out}");
        assert!(out.contains("\\u{1b}"), "{out}");
    }

    /// The bound has to hold for the input that expands the most. A body of
    /// control bytes escapes to seven characters each, so budgeting the input
    /// rather than the output would leave the message unbounded for precisely
    /// the body somebody would send on purpose.
    #[test]
    fn the_bound_holds_for_a_body_that_is_all_escapes() {
        let out = clip_body(&"\u{1}".repeat(20_000));
        assert!(
            out.len() < ERROR_BODY_BUDGET + 64,
            "escaping blew the budget: {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"));
    }

    /// The requirement is about the messages, not the helper: every path that
    /// embeds a body has to be bounded, including the shape error T-05 added.
    #[test]
    fn every_error_that_embeds_a_body_is_bounded() {
        let huge = "y".repeat(50_000);
        let cases = [
            parse_source_code(&huge).unwrap_err(),
            parse_creation(&huge).unwrap_err(),
            parse_creation(&format!(r#"{{"status":"1","message":"OK","result":"{huge}"}}"#))
                .unwrap_err(),
        ];
        for e in cases {
            let msg = e.to_string();
            assert!(msg.len() < 2_048, "unbounded error message: {} bytes", msg.len());
            assert!(msg.contains("truncated"), "the cut must be visible: {msg}");
        }
    }

    #[test]
    fn parse_source_code_invalid_json() {
        let err = parse_source_code("not json").unwrap_err().to_string();
        assert!(err.contains("parse failed"), "{err}");
    }

    #[test]
    fn parse_creation_ok() {
        let body = r#"{"status":"1","message":"OK","result":[{"contractAddress":"0xabc","contractCreator":"0xcreator","txHash":"0xhash"}]}"#;
        let c = parse_creation(body).unwrap().unwrap();
        assert_eq!(c.contract_creator, "0xcreator");
        assert_eq!(c.tx_hash, "0xhash");
    }

    #[test]
    fn parse_creation_status0_is_none() {
        let body = r#"{"status":"0","message":"No data found","result":"No data found"}"#;
        assert!(parse_creation(body).unwrap().is_none());
    }

    /// T-05 inverted this. `parse_source_code` has always called the same
    /// envelope "unexpected result shape" and errored; reading it as an absence
    /// here was the asymmetry the task exists to remove.
    #[test]
    fn parse_creation_result_not_array_is_a_failure() {
        let body = r#"{"status":"1","message":"OK","result":"weird"}"#;
        let err = parse_creation(body).unwrap_err().to_string();
        assert!(err.contains("unexpected result shape"), "{err}");
    }

    /// The acceptance test: one body, both parsers, one classification.
    #[test]
    fn a_rate_limited_body_is_a_failure_in_both_parsers() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Max calls per sec rate limit reached (5/sec)"}"#;
        assert!(is_rate_limited(body), "the fixture must be a real rate-limit body");
        let src = parse_source_code(body).unwrap_err().to_string();
        let creation = parse_creation(body).unwrap_err().to_string();
        assert!(src.contains("rate limit"), "{src}");
        assert!(creation.contains("rate limit"), "{creation}");
    }

    /// Absence is a whitelist, so a message the explorer adds later cannot
    /// quietly become "this contract has no creation record".
    #[test]
    fn parse_creation_unknown_status0_message_is_a_failure() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#;
        let err = parse_creation(body).unwrap_err().to_string();
        assert!(err.contains("Invalid API Key"), "{err}");
    }

    #[test]
    fn parse_creation_empty_array_is_none() {
        let body = r#"{"status":"1","message":"OK","result":[]}"#;
        assert!(parse_creation(body).unwrap().is_none());
    }

    #[test]
    fn parse_creation_invalid_json() {
        assert!(parse_creation("nope").is_err());
    }

    #[test]
    fn detects_rate_limit_bodies() {
        assert!(is_rate_limited(
            r#"{"status":"0","message":"NOTOK","result":"Max calls per sec rate limit reached (3/sec)"}"#
        ));
        assert!(is_rate_limited(r#"{"result":"rate limit exceeded"}"#));
        assert!(!is_rate_limited(r#"{"status":"1","result":[]}"#));
    }
}
