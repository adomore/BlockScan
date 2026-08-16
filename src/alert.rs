//! Alert sinks for `monitor`: append-only JSONL file and/or best-effort webhook.
//! Every failure path degrades to a `warn!` — the monitor loop must never crash.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::model::Alert;

/// Where decoded alerts are delivered. Either/both sinks are optional.
#[derive(Clone)]
pub struct AlertSink {
    /// Append one JSON line per alert to this file (`alerts.jsonl`).
    path: Option<PathBuf>,
    /// POST each alert as JSON to this URL (best-effort).
    webhook: Option<String>,
    http: reqwest::Client,
}

impl AlertSink {
    pub fn new(path: Option<PathBuf>, webhook: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("blockscan/0.1")
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            path,
            webhook: webhook.filter(|w| !w.trim().is_empty()),
            http,
        }
    }

    /// Deliver one alert to all configured sinks. Best-effort: errors are logged,
    /// never propagated, so a bad file/endpoint can't stop monitoring.
    pub async fn emit(&self, alert: &Alert) {
        let line = match serde_json::to_string(alert) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("alert serialize failed: {e}");
                return;
            }
        };
        if let Some(path) = &self.path {
            if let Err(e) = append_line(path, &line) {
                tracing::warn!("alert file write failed ({}): {e}", path.display());
            }
        }
        if let Some(url) = &self.webhook {
            let res = self
                .http
                .post(url)
                .header("content-type", "application/json")
                .body(line)
                .send()
                .await;
            match res {
                Ok(r) if !r.status().is_success() => {
                    tracing::warn!("alert webhook {url}: HTTP {}", r.status());
                }
                Err(e) => tracing::warn!("alert webhook {url} failed: {e}"),
                _ => {}
            }
        }
    }
}

/// Append a single line (plus newline) to `path`, creating it if needed.
/// The line and its newline are written in one `write_all` call so concurrent
/// appenders can't interleave a line with another's newline.
fn append_line(path: &PathBuf, line: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(format!("{line}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(n: u64) -> Alert {
        Alert {
            block: n,
            chain_id: 1,
            contract: "0xabc".into(),
            event: "Upgraded".into(),
            kind: "proxy-upgrade".into(),
            new_value: Some("0ximpl".into()),
            previous: None,
            tx_hash: None,
            log_index: None,
            amount: None,
            risk_score: None,
            grade: None,
        }
    }

    #[tokio::test]
    async fn appends_jsonl_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("alerts.jsonl");
        let sink = AlertSink::new(Some(path.clone()), None);
        sink.emit(&alert(1)).await;
        sink.emit(&alert(2)).await;
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let a: Alert = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(a.block, 1);
        assert!(lines[1].contains("\"block\":2"));
    }

    #[tokio::test]
    async fn disabled_sink_does_nothing() {
        // No path, no webhook -> emit is a no-op and must not panic.
        AlertSink::new(None, Some("   ".into())).emit(&alert(1)).await;
    }

    #[tokio::test]
    async fn posts_to_webhook() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let sink = AlertSink::new(None, Some(format!("{}/hook", server.uri())));
        sink.emit(&alert(7)).await;
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let got: Alert = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(got.block, 7);
    }

    #[tokio::test]
    async fn webhook_error_is_swallowed() {
        // Dead endpoint + a file sink: file still written, no panic from webhook.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.jsonl");
        let sink = AlertSink::new(Some(path.clone()), Some("http://127.0.0.1:1/x".into()));
        sink.emit(&alert(3)).await;
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"block\":3"));
    }

    #[tokio::test]
    async fn non_2xx_webhook_is_swallowed() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        // Must not panic on a 5xx.
        AlertSink::new(None, Some(server.uri())).emit(&alert(1)).await;
    }

    #[tokio::test]
    async fn bad_file_path_is_swallowed() {
        // Path whose parent dir doesn't exist -> open fails -> warn, no panic.
        let sink = AlertSink::new(Some(PathBuf::from("no_such_dir/sub/a.jsonl")), None);
        sink.emit(&alert(1)).await;
    }
}
