//! Hardening spec for the MCP agent surface — tasks T-01, T-02, T-03.
//!
//! These tests are the acceptance criteria for the three findings that compound
//! into one reachable path: an unauthenticated caller (T-02) who chooses the
//! output directory (T-01) and the outbound endpoint (T-03). Closing any two
//! leaves the third open, so they ship as one spec.
//!
//! STATUS: failing specification. Every test here fails against v1.1.0 and must
//! pass after the three tasks land. Do not weaken a test to make it pass — if a
//! test looks wrong, argue it in the manifest before changing it.
//!
//! Placement: `tests/mcp_hardening.rs`, beside `tests/integration.rs`, because
//! two of the three need a real listener and a real TCP round trip. The
//! in-process listener pattern is the one already established in `mcp.rs` —
//! bind first, read the real port off the live listener, then inject it. Do not
//! probe-and-close for a free port: that is the bind→close→rebind window whose
//! flake the MCP design notes already record and fix.

use std::net::SocketAddr;

use blockscan::mcp;

/// Since T-02 the HTTP surface always has a credential, so a test about the
/// output directory or the outbound endpoint has to present one. Only the setup
/// moves; every assertion below is the one the specification shipped with.
const TOKEN: &str = "spec-token";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Bind a loopback listener and return it with its real port, so callers never
/// reopen a port they previously closed.
async fn live_listener() -> (tokio::net::TcpListener, SocketAddr) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let a = l.local_addr().expect("local addr");
    (l, a)
}

/// POST a JSON-RPC body to `/mcp` and return (status, body).
async fn post_mcp(addr: SocketAddr, token: Option<&str>, body: &str) -> (u16, String) {
    post_raw(addr, token, None, body).await
}

/// The one HTTP client these tests need. `Connection: close` is what makes
/// read-to-EOF terminate: hyper keeps the connection alive otherwise and the
/// read blocks until the timeout rather than returning the response.
async fn post_raw(
    addr: SocketAddr,
    token: Option<&str>,
    origin: Option<&str>,
    body: &str,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut req = String::new();
    req.push_str("POST /mcp HTTP/1.1\r\n");
    req.push_str("Host: localhost\r\n");
    req.push_str("Connection: close\r\n");
    req.push_str("Content-Type: application/json\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(o) = origin {
        req.push_str(&format!("Origin: {o}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    req.push_str(body);

    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    // Neither of these is checked, and both must not be. The body cap this file
    // asserts is enforced by `Limited`, which stops reading partway through an
    // oversized body: the server answers 413 and closes while the client still
    // has the rest queued, so the write fails and a following RST can fail the
    // read too — both are the guard working, not a transport fault. What
    // matters is whether a response came back, and the status-line parse below
    // still panics loudly when none did.
    let _ = stream.write_all(req.as_bytes()).await;
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp).await;
    let resp = String::from_utf8_lossy(&resp).into_owned();

    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in: {resp}"));
    let payload = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, payload)
}

fn tools_call(name: &str, arguments: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
    .to_string()
}

// ===========================================================================
// T-01 — the output directory must not be caller-controlled
// ===========================================================================

/// The guard next to this one already validates `address` by parsing it as a
/// real Address before building any path, and says why: traversal. That guard
/// is on the leaf of the path. This test is about the root.
#[tokio::test]
async fn out_argument_outside_the_server_base_is_rejected() {
    let base = tempfile::tempdir().expect("tempdir");
    let escape = tempfile::tempdir().expect("second tempdir");

    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), Some(TOKEN.to_string())));

    let (status, body) = post_mcp(
        addr,
        Some(TOKEN),
        &tools_call("list_contracts", serde_json::json!({ "out": escape.path() })),
    )
    .await;

    handle.abort();
    assert_eq!(status, 200, "JSON-RPC transports errors in the body, not the status");
    assert!(
        body.contains("error") || body.contains("isError"),
        "an out-of-base directory must be refused, got: {body}"
    );
}

/// The fix must not break the ordinary path: omitting `out` uses the server's
/// own directory and still works.
#[tokio::test]
async fn omitting_the_out_argument_still_uses_the_server_base() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), Some(TOKEN.to_string())));

    let (status, body) = post_mcp(addr, Some(TOKEN), &tools_call("list_contracts", serde_json::json!({}))).await;

    handle.abort();
    assert_eq!(status, 200);
    assert!(!body.contains("\"error\""), "the in-base case must still succeed: {body}");
}

/// Traversal through the argument, not just a sibling absolute path.
#[tokio::test]
async fn out_argument_with_parent_traversal_is_rejected() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), Some(TOKEN.to_string())));

    let escape = base.path().join("..").join("..");
    let (_, body) = post_mcp(
        addr,
        Some(TOKEN),
        &tools_call("list_contracts", serde_json::json!({ "out": escape })),
    )
    .await;

    handle.abort();
    assert!(
        body.contains("error") || body.contains("isError"),
        "parent traversal must be refused, got: {body}"
    );
}

// ===========================================================================
// T-02 — HTTP mode must not run unauthenticated
// ===========================================================================

/// The network boundary here is genuinely well built — loopback enforcement,
/// exact-host origin matching, a body cap, constant-time comparison. None of it
/// defends against another process on this machine, which is what the token is
/// for, and the token is the one control that is off by default.
#[tokio::test]
async fn http_mode_started_without_a_token_still_requires_one() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;

    // Started with None: the implementation must generate a credential rather
    // than disable the check.
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), None));

    let (status, _) = post_mcp(addr, None, &tools_call("list_contracts", serde_json::json!({}))).await;

    handle.abort();
    assert_eq!(status, 401, "an unauthenticated request must not reach a tool");
}

#[tokio::test]
async fn a_wrong_token_is_rejected() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(
        listener,
        base.path().to_path_buf(),
        Some("correct-horse".to_string()),
    ));

    let (status, _) = post_mcp(addr, Some("wrong"), &tools_call("list_contracts", serde_json::json!({}))).await;

    handle.abort();
    assert_eq!(status, 401);
}

#[tokio::test]
async fn the_configured_token_is_accepted() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(
        listener,
        base.path().to_path_buf(),
        Some("correct-horse".to_string()),
    ));

    let (status, _) = post_mcp(
        addr,
        Some("correct-horse"),
        &tools_call("list_contracts", serde_json::json!({})),
    )
    .await;

    handle.abort();
    assert_eq!(status, 200);
}

/// stdio has no network surface. Requiring a credential there would be a
/// regression in usability bought with no security.
#[test]
fn stdio_mode_does_not_gain_a_credential_requirement() {
    let base = tempfile::tempdir().expect("tempdir");
    let ctx = mcp::ServerCtx::new(base.path().to_path_buf());
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let resp = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(mcp::handle(&ctx, &req));
    let resp = resp.expect("tools/list must answer on stdio with no credential");
    assert!(resp.get("error").is_none(), "stdio must stay credential-free: {resp}");
}

// ===========================================================================
// T-03 — the outbound endpoint must not be caller-chosen
// ===========================================================================

/// An endpoint taken from a request argument lets any caller decide where this
/// process sends its next packet.
#[tokio::test]
async fn rpc_url_outside_the_allow_list_is_refused_before_any_socket_opens() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), Some(TOKEN.to_string())));

    let started = std::time::Instant::now();
    let (_, body) = post_mcp(
        addr,
        Some(TOKEN),
        &tools_call(
            "monitor_range",
            serde_json::json!({ "rpc_url": "http://169.254.169.254/latest/meta-data/", "from": 1, "to": 2 }),
        ),
    )
    .await;
    let elapsed = started.elapsed();

    handle.abort();
    assert!(body.contains("error") || body.contains("isError"), "got: {body}");
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "refusal must precede the connection attempt, not time out on it"
    );
}

/// Reachability is limited — a response must parse as JSON-RPC for the tool to
/// succeed — but failure is informative. Two different transport failures must
/// be indistinguishable in the tool result, or the tool is a port scanner.
#[tokio::test]
async fn transport_failures_are_indistinguishable_to_the_caller() {
    let base = tempfile::tempdir().expect("tempdir");

    // A closed port and a live socket that speaks the wrong protocol. Both are
    // created first, because both have to be on the allow-list: an endpoint that
    // is refused before the socket opens never exercises the transport, and the
    // comparison would pass while proving nothing.
    let (dead, dead_addr) = live_listener().await;
    drop(dead);
    let (alive, alive_addr) = live_listener().await;
    let alive_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = alive.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json").await;
        }
    });

    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on_with(
        listener,
        mcp::McpConfig {
            out: base.path().to_path_buf(),
            token: Some(TOKEN.to_string()),
            rpc_allow: vec![format!("http://{dead_addr}"), format!("http://{alive_addr}")],
        },
    ));

    let call = |url: String| {
        tools_call("monitor_range", serde_json::json!({ "rpc_url": url, "from": 1, "to": 2 }))
    };
    let (_, refused) = post_mcp(addr, Some(TOKEN), &call(format!("http://{dead_addr}"))).await;
    let (_, wrong_proto) = post_mcp(addr, Some(TOKEN), &call(format!("http://{alive_addr}"))).await;

    alive_task.abort();
    handle.abort();
    assert_eq!(
        refused, wrong_proto,
        "a closed port and a live wrong-protocol endpoint must be byte-identical to the caller"
    );
}

/// The allow-list is the mechanism; this asserts a permitted endpoint still
/// works, so the fix does not simply disable the tool.
#[tokio::test]
async fn an_allow_listed_rpc_url_is_accepted() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;

    // The allow-list is supplied at server launch, through McpConfig — the
    // constructor this test's original comment said to adjust. The endpoint is a
    // real listener so the tool is genuinely reached rather than short-circuited.
    let (endpoint, endpoint_addr) = live_listener().await;
    let endpoint_task = tokio::spawn(async move {
        while let Ok((mut s, _)) = endpoint.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json").await;
        }
    });
    let permitted = format!("http://{endpoint_addr}");

    let handle = tokio::spawn(mcp::serve_http_on_with(
        listener,
        mcp::McpConfig {
            out: base.path().to_path_buf(),
            token: Some(TOKEN.to_string()),
            rpc_allow: vec![permitted.clone()],
        },
    ));
    let (status, _) = post_mcp(
        addr,
        Some(TOKEN),
        &tools_call("monitor_range", serde_json::json!({ "rpc_url": permitted, "from": 1, "to": 2 })),
    )
    .await;
    endpoint_task.abort();

    handle.abort();
    assert_eq!(status, 200);
}

// ===========================================================================
// Regression guards — properties the fixes must not break
// ===========================================================================

/// The origin check, the body cap and the loopback refusal predate these tasks
/// and are correct. A fix that reorders the checks must not drop them.
#[tokio::test]
async fn existing_origin_and_body_guards_survive_the_hardening() {
    let base = tempfile::tempdir().expect("tempdir");
    let (listener, addr) = live_listener().await;
    let handle = tokio::spawn(mcp::serve_http_on(listener, base.path().to_path_buf(), Some(TOKEN.to_string())));

    // Host-suffix spoofing must still be refused.
    let (spoofed, _) = post_mcp_with_origin(addr, "http://localhost.evil.com", &tools_call("tools/list", serde_json::json!({}))).await;
    assert_eq!(spoofed, 403);

    // An oversized body must still be capped.
    let huge = "x".repeat(2 * 1024 * 1024);
    let (oversized, _) = post_mcp(addr, Some(TOKEN), &huge).await;
    assert_eq!(oversized, 413);

    handle.abort();
}

async fn post_mcp_with_origin(addr: SocketAddr, origin: &str, body: &str) -> (u16, String) {
    post_raw(addr, Some(TOKEN), Some(origin), body).await
}
