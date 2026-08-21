//! MCP (Model Context Protocol) stdio server — exposes BlockScan as agent-callable
//! tools over newline-delimited JSON-RPC 2.0 on stdin/stdout. Hand-rolled (no SDK)
//! to keep dependencies lean and the dispatch handler a pure, in-process-testable
//! function. See docs/MCP_DESIGN.md.
//!
//! INVARIANT: stdout carries ONLY MCP messages. All logs go to stderr (via
//! `init_tracing`'s stderr writer); this module never prints to stdout itself.

use alloy::primitives::{Address, Bytes as EvmBytes};
use serde_json::{json, Value};

use crate::cli::OutputFormat;
use crate::config::Config;
use crate::model::{ContractDetails, SourceFile};
use crate::suppress::Suppressions;
use crate::{analysis, audit, error, sarif, storage};

/// Protocol version used when the client doesn't send one. We otherwise echo the
/// client's requested version (the tools-only wire format is stable across versions),
/// so we never depend on asserting a specific "latest" string.
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "blockscan";
/// Max block span for the bounded `scan_block_range` / `monitor_range` tools, so a
/// single `tools/call` stays finite (the agent paginates larger ranges).
const MAX_RANGE: u64 = 500;

/// Server-wide context shared by every request: the corpus directory (`-o`/`--out`),
/// used as the default for the offline tools and as the source for `resources/*`.
pub struct ServerCtx {
    pub out: std::path::PathBuf,
}

impl ServerCtx {
    pub fn new(out: std::path::PathBuf) -> Self {
        Self { out }
    }
}

// JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// Run the stdio MCP server until stdin reaches EOF, with `out` as the corpus dir.
pub async fn serve_stdio(out: std::path::PathBuf) -> error::Result<()> {
    use tokio::io::BufReader;
    let ctx = ServerCtx::new(out);
    serve(&ctx, BufReader::new(tokio::io::stdin()), tokio::io::stdout()).await
}

/// The transport loop over any line reader + writer (generic so it's testable with
/// in-memory buffers). Each input line is one JSON-RPC message; each response is one
/// compact JSON line (flushed immediately). Blank lines are skipped; parse failures
/// yield a `-32700` error response.
pub async fn serve<R, W>(ctx: &ServerCtx, reader: R, mut writer: W) -> error::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut lines = reader.lines();
    tracing::info!("blockscan MCP server: JSON-RPC 2.0 over stdio (EOF to stop)");
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => handle(ctx, &req).await,
            Err(e) => Some(error_response(&Value::Null, PARSE_ERROR, &format!("parse error: {e}"))),
        };
        if let Some(response) = response {
            match serde_json::to_string(&response) {
                Ok(mut s) => {
                    s.push('\n');
                    writer.write_all(s.as_bytes()).await?;
                    writer.flush().await?;
                }
                // Fixed-shape envelopes can't realistically fail to serialize; if one
                // ever did, log to stderr so the missing reply is observable.
                Err(e) => tracing::error!("failed to serialize MCP response: {e}"),
            }
        }
    }
    Ok(())
}

// ---------------- HTTP transport (Streamable HTTP, tools-only) ----------------

/// Max request body for the HTTP transport (JSON-RPC messages are small).
const MAX_HTTP_BODY: usize = 1 << 20; // 1 MiB

/// Serve MCP over HTTP on a loopback address (Streamable HTTP, JSON-only, stateless).
/// Reuses the same `handle()` dispatch as stdio. Binds 127.0.0.1 only (never 0.0.0.0).
pub async fn serve_http(out: std::path::PathBuf, addr: &str, token: Option<String>) -> error::Result<()> {
    let socket = parse_loopback_addr(addr)?;
    let listener = tokio::net::TcpListener::bind(socket).await?;
    serve_http_on(listener, out, token).await
}

/// Accept loop for the HTTP transport, given an already-bound listener. Splitting
/// the bind out of the loop lets callers (notably the in-process test) obtain the
/// real bound port from a *live* listener before driving traffic — no
/// bind→close→rebind window where a concurrent process can steal the port, and the
/// socket is in LISTEN state (connections queue in the backlog) before any connect.
pub async fn serve_http_on(
    listener: tokio::net::TcpListener,
    out: std::path::PathBuf,
    token: Option<String>,
) -> error::Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;

    let socket = listener.local_addr()?;
    // T-02: this surface never runs unauthenticated. Loopback binding, exact
    // origin matching and the body cap all defend against another *host*; the
    // credential is the only one that defends against another *process on this
    // one*, and it used to be the single control that was off by default. A
    // caller that supplied no token gets one minted and printed once rather
    // than the check being skipped.
    let token = match token {
        Some(t) => t,
        None => {
            let t = mint_token()?;
            eprintln!(
                "blockscan MCP: no --http-token supplied; generated one for this run:
  {t}
                 pass it as `Authorization: Bearer <token>`. Set --http-token (or                  BLOCKSCAN_MCP_TOKEN) to choose your own."
            );
            t
        }
    };
    tracing::info!("blockscan MCP server: HTTP on http://{socket}/mcp (loopback only; Ctrl-C to stop)");
    let ctx = std::sync::Arc::new(ServerCtx::new(out));
    let token = std::sync::Arc::new(token);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => { tracing::warn!("accept failed: {e}"); continue; }
                };
                let io = TokioIo::new(stream);
                let ctx = ctx.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let ctx = ctx.clone();
                        let token = token.clone();
                        async move {
                            let resp = http_handle_conn(&ctx, &token, req).await;
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!("connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Parse an `--http` address into a SocketAddr, accepting `host:port`, bare port
/// (default host 127.0.0.1), or bare host (default port 8765). Rejects non-loopback.
fn parse_loopback_addr(addr: &str) -> error::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let candidate = if addr.parse::<u16>().is_ok() {
        format!("127.0.0.1:{addr}")
    } else if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:8765")
    };
    let sock = candidate
        .to_socket_addrs()
        .map_err(|e| error::AppError::Config(format!("invalid --http address '{addr}': {e}")))?
        .next()
        .ok_or_else(|| error::AppError::Config(format!("--http address '{addr}' resolved to nothing")))?;
    if !sock.ip().is_loopback() {
        return Err(error::AppError::Config(format!(
            "--http must bind a loopback address (got {}); refusing to expose MCP off-host",
            sock.ip()
        )));
    }
    Ok(sock)
}

/// Read the request body (bounded) then dispatch via the pure [`http_handle`].
async fn http_handle_conn(
    ctx: &ServerCtx,
    token: &str,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    use http_body_util::{BodyExt, Limited};
    let (parts, body) = req.into_parts();
    // Bound the read: Limited errors once the body exceeds the cap, so a giant POST
    // can't OOM us before any size check (the post-read len check would be too late).
    let bytes = match Limited::new(body, MAX_HTTP_BODY).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return text_response(413, "payload too large"),
    };
    http_handle(ctx, token, &parts.method, parts.uri.path(), &parts.headers, &bytes).await
}

/// Pure HTTP request handler (no socket / no spawn) — directly testable in memory.
/// A 256-bit bearer credential from the OS CSPRNG, hex-encoded.
///
/// `getrandom` is named as a direct dependency for exactly this: a credential
/// must not come from a clock, a pid or a hash of either, and every other source
/// reachable here is one of those.
fn mint_token() -> error::Result<String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| error::AppError::Config(format!("cannot generate an MCP credential: {e}")))?;
    Ok(raw.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    }))
}

/// Maps an already-read request to a response per the Streamable HTTP contract.
async fn http_handle(
    ctx: &ServerCtx,
    token: &str,
    method: &hyper::Method,
    path: &str,
    headers: &hyper::HeaderMap,
    body: &[u8],
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    if path != "/mcp" {
        return text_response(404, "not found");
    }
    if method != hyper::Method::POST {
        // GET/DELETE/etc: a tools-only server has no server-initiated stream.
        return text_response(405, "method not allowed");
    }
    let expected_header = format!("Bearer {token}");
    let authorized = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| ct_eq(h.as_bytes(), expected_header.as_bytes()));
    if !authorized {
        return text_response(401, "unauthorized");
    }
    if !origin_allowed(headers) {
        return text_response(403, "forbidden origin (loopback only)");
    }
    if body.len() > MAX_HTTP_BODY {
        return text_response(413, "payload too large");
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(req) => match handle(ctx, &req).await {
            Some(resp) => json_response(200, &resp),
            None => empty_response(202), // notification / no reply
        },
        Err(e) => json_response(200, &error_response(&Value::Null, PARSE_ERROR, &format!("parse error: {e}"))),
    }
}

/// Constant-time byte-slice equality (no early exit on the first mismatch), so a
/// bearer-token check can't be probed via response timing. The length check leaks
/// only the (fixed, known) expected length, which is acceptable.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Only same-host Origins are allowed (DNS-rebinding protection). A missing Origin
/// (typical non-browser MCP client) is allowed. The host is parsed and matched
/// EXACTLY — a prefix check would let `http://localhost.evil.com` through. An
/// opaque `Origin: null` is rejected (a legitimate local browser sends a real
/// loopback Origin; `null` would weaken the rebinding guard).
fn origin_allowed(headers: &hyper::HeaderMap) -> bool {
    let Some(o) = headers.get(hyper::header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // no Origin (non-browser client)
    };
    // Unparseable / non-http(s) / non-loopback host (incl. "null") -> reject.
    matches!(origin_host(o.trim()).as_deref(), Some("localhost") | Some("127.0.0.1") | Some("::1"))
}

/// Extract the bare host from an Origin like `http://host:port`, dropping scheme,
/// path, userinfo and port. `None` if it isn't an http(s) origin we can parse.
fn origin_host(origin: &str) -> Option<String> {
    let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority); // drop userinfo
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("") // [::1] / [::1]:port
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority) // host[:port]
    };
    Some(host.to_string())
}

fn json_response(status: u16, v: &Value) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    let body = serde_json::to_vec(v).unwrap_or_default();
    hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .expect("valid response")
}

fn text_response(status: u16, msg: &str) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(http_body_util::Full::new(bytes::Bytes::from(msg.to_string())))
        .expect("valid response")
}

fn empty_response(status: u16) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(status)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .expect("valid response")
}

/// Handle one decoded JSON-RPC message. Returns `Some(response)` for requests and
/// `None` for notifications (no `id`) — the core, side-effect-light dispatch that
/// tests drive directly. Tool calls may perform I/O (offline file reads / network).
pub async fn handle(ctx: &ServerCtx, req: &Value) -> Option<Value> {
    let method = req.get("method").and_then(Value::as_str);
    match (method, req.get("id")) {
        (None, _) => None,             // not a request we recognise
        (Some(_), None) => None,       // notification (notifications/initialized, …) -> no reply
        (Some(m), Some(id)) => Some(handle_request(ctx, m, id, req).await),
    }
}

async fn handle_request(ctx: &ServerCtx, method: &str, id: &Value, req: &Value) -> Value {
    match method {
        "initialize" => result_response(id, initialize_result(req)),
        "ping" => result_response(id, json!({})),
        "tools/list" => result_response(id, json!({ "tools": tool_list() })),
        "tools/call" => tools_call(ctx, id, req).await,
        "resources/list" => result_response(id, json!({ "resources": resources_list(ctx) })),
        "resources/read" => resources_read(ctx, id, req),
        other => error_response(id, METHOD_NOT_FOUND, &format!("unknown method: {other}")),
    }
}

/// `initialize` result: echo the client's protocol version, advertise tools.
fn initialize_result(req: &Value) -> Value {
    let version = req
        .pointer("/params/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {}, "resources": {} },
        "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
    })
}

// ---------------- JSON-RPC envelope helpers ----------------

fn result_response(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A successful `tools/call` result: human-readable text + (for object values)
/// machine-readable `structuredContent`.
fn ok_result(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut r = json!({ "content": [{ "type": "text", "text": text }], "isError": false });
    if value.is_object() {
        r["structuredContent"] = value;
    }
    r
}

/// A tool-level failure: surfaced as a successful JSON-RPC result with `isError`
/// set, so the model sees the message (vs. a protocol-level error).
fn err_result(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

// ---------------- tools/call dispatch ----------------

/// The outcome of invoking a tool by name.
enum ToolOutcome {
    /// Success — the tool's JSON result.
    Ok(Value),
    /// The tool ran but failed (e.g. contract not found) — `isError: true`.
    ToolError(String),
    /// Malformed/missing arguments — JSON-RPC `-32602`.
    BadArgs(String),
    /// No such tool — JSON-RPC `-32602`.
    UnknownTool,
}

async fn tools_call(ctx: &ServerCtx, id: &Value, req: &Value) -> Value {
    let name = match req.pointer("/params/name").and_then(Value::as_str) {
        Some(n) => n,
        None => return error_response(id, INVALID_PARAMS, "tools/call: missing params.name"),
    };
    let args = req.pointer("/params/arguments").cloned().unwrap_or_else(|| json!({}));
    match call_tool(ctx, name, &args).await {
        ToolOutcome::Ok(v) => result_response(id, ok_result(v)),
        ToolOutcome::ToolError(msg) => result_response(id, err_result(&msg)),
        ToolOutcome::BadArgs(msg) => error_response(id, INVALID_PARAMS, &msg),
        ToolOutcome::UnknownTool => error_response(id, INVALID_PARAMS, &format!("unknown tool: {name}")),
    }
}

async fn call_tool(ctx: &ServerCtx, name: &str, args: &Value) -> ToolOutcome {
    match name {
        "audit_source" => tool_audit_source(args),
        "audit_corpus" => tool_audit_corpus(ctx, args),
        "get_contract" => tool_get_contract(ctx, args),
        "list_contracts" => tool_list_contracts(ctx, args),
        "export_sarif" => tool_export_sarif(ctx, args),
        "cluster_corpus" => tool_cluster_corpus(ctx, args),
        "scan_addresses" => tool_scan_addresses(ctx, args).await,
        "scan_block_range" => tool_scan_block_range(ctx, args).await,
        "monitor_range" => tool_monitor_range(args).await,
        _ => ToolOutcome::UnknownTool,
    }
}

/// The MCP tool catalogue (returned by `tools/list`).
fn tool_list() -> Vec<Value> {
    vec![
        tool_def(
            "audit_source",
            "Audit Solidity source and/or runtime bytecode with the heuristic engine; returns the standardized Audit (risk score, grade, findings). Providing `sources` marks the contract as verified (source-level detectors run; this asserts source is present, NOT that it matches the bytecode).",
            json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Contract address (informational; default 0x0…0)" },
                    "chain_id": { "type": "integer", "description": "Chain id (default 1)" },
                    "sources": { "type": "array", "items": { "type": "object", "properties": {
                        "path": { "type": "string" }, "content": { "type": "string" } }, "required": ["path", "content"] },
                        "description": "Verified source files to audit" },
                    "bytecode": { "type": "string", "description": "0x-prefixed runtime bytecode (enables bytecode-level + analysis signals)" },
                    "compiler_version": { "type": "string" },
                    "is_proxy": { "type": "boolean" }
                }
            }),
        ),
        tool_def(
            "audit_corpus",
            "Re-audit every contract already saved under the output directory (offline); returns counts + audited contracts.",
            corpus_filter_schema(true),
        ),
        tool_def(
            "get_contract",
            "Load a saved contract's metadata (and optionally its source files) from the output directory.",
            json!({
                "type": "object",
                "properties": {
                    "out": { "type": "string", "description": "Output directory (default 'output')" },
                    "address": { "type": "string", "description": "Contract address (required)" },
                    "include_source": { "type": "boolean" }
                },
                "required": ["address"]
            }),
        ),
        tool_def(
            "list_contracts",
            "List saved contracts under the output directory (lightweight: address, name, risk score). Filters apply to the LAST-SAVED audit (no re-audit) — contracts saved with --no-audit are excluded by min_risk/only_vulnerable; use audit_corpus to re-audit and filter freshly.",
            corpus_filter_schema(false),
        ),
        tool_def(
            "export_sarif",
            "Re-audit the saved corpus and export findings as a SARIF 2.1.0 log (GitHub Code Scanning / CI).",
            corpus_filter_schema(false),
        ),
        tool_def(
            "cluster_corpus",
            "Group saved contracts into clone families by metadata-stripped bytecode hash.",
            json!({ "type": "object", "properties": { "out": { "type": "string" } } }),
        ),
        tool_def(
            "scan_addresses",
            "Scan contract addresses on-chain: fetch bytecode + verified source + details, audit, and persist. Requires rpc_url + etherscan_key.",
            json!({
                "type": "object",
                "properties": {
                    "addresses": { "type": "array", "items": { "type": "string" }, "description": "Contract addresses (required)" },
                    "rpc_url": { "type": "string", "description": "JSON-RPC endpoint (required)" },
                    "etherscan_key": { "type": "string", "description": "Etherscan V2 API key (required)" },
                    "etherscan_base": { "type": "string" },
                    "chain_id": { "type": "integer" },
                    "out": { "type": "string" },
                    "overwrite": { "type": "boolean" },
                    "audit": { "type": "boolean", "description": "Run the security audit (default true)" },
                    "only_verified": { "type": "boolean" },
                    "only_proxy": { "type": "boolean" },
                    "min_risk": { "type": "integer" },
                    "only_vulnerable": { "type": "boolean" }
                },
                "required": ["addresses", "rpc_url", "etherscan_key"]
            }),
        ),
        tool_def(
            "scan_block_range",
            "Scan all top-level contract deployments in a BOUNDED block range (≤500 blocks), audit + persist them. Requires rpc_url + etherscan_key; paginate larger ranges.",
            json!({
                "type": "object",
                "properties": {
                    "from": { "type": "integer", "description": "First block (inclusive)" },
                    "to": { "type": "integer", "description": "Last block (inclusive; to-from < 500)" },
                    "rpc_url": { "type": "string" }, "etherscan_key": { "type": "string" },
                    "etherscan_base": { "type": "string" }, "chain_id": { "type": "integer" },
                    "out": { "type": "string" }, "trace": { "type": "boolean", "description": "Also find factory (CREATE2) deployments via trace_block" },
                    "audit": { "type": "boolean" }
                },
                "required": ["from", "to", "rpc_url", "etherscan_key"]
            }),
        ),
        tool_def(
            "monitor_range",
            "Decode security events (proxy upgrade / ownership / admin / role / pause; large transfers via min_transfer) in a BOUNDED block range and RETURN the alerts. RPC-only (no Etherscan key).",
            json!({
                "type": "object",
                "properties": {
                    "from": { "type": "integer" }, "to": { "type": "integer", "description": "to-from < 500" },
                    "rpc_url": { "type": "string" }, "chain_id": { "type": "integer" },
                    "alert_topic": { "type": "array", "items": { "type": "string" }, "description": "Extra topic0 hashes" },
                    "min_transfer": { "type": "string", "description": "Include ERC-20 Transfer >= this (raw uint256)" },
                    "watchlist": { "type": "array", "items": { "type": "string" }, "description": "Only these contract addresses" }
                },
                "required": ["from", "to", "rpc_url"]
            }),
        ),
    ]
}

fn tool_def(name: &str, description: &str, input_schema: Value) -> Value {
    json!({ "name": name, "description": description, "inputSchema": input_schema })
}

/// Shared input schema for corpus tools (`out` + filters; `by_risk` only for audit).
fn corpus_filter_schema(with_by_risk: bool) -> Value {
    let mut props = json!({
        "out": { "type": "string", "description": "Output directory (default 'output')" },
        "min_risk": { "type": "integer", "description": "Keep contracts with risk >= this (0–100)" },
        "only_vulnerable": { "type": "boolean", "description": "Keep only high/critical findings" }
    });
    if with_by_risk {
        props["by_risk"] = json!({ "type": "boolean", "description": "Sort by risk score descending" });
    }
    json!({ "type": "object", "properties": props })
}

// ---------------- argument helpers ----------------

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn arg_bool(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The corpus directory for a call: explicit `out` argument, else the server's `-o`.
/// The corpus directory for this request, constrained to the server's own base.
///
/// The `address` argument beside this one is parsed as a real `Address` before
/// any path is built, and says why: traversal. That guard is on the leaf of the
/// path — this one is on the root. Without it a caller chooses where the server
/// reads and writes, which is the whole directory tree the process can reach.
///
/// Containment is decided after canonicalisation, so `..` segments and symlinks
/// resolve before the prefix test rather than after it. A path that cannot be
/// resolved at all is refused rather than guessed at.
fn arg_out(ctx: &ServerCtx, args: &Value) -> error::Result<std::path::PathBuf> {
    let Some(requested) = arg_str(args, "out") else {
        return Ok(ctx.out.clone());
    };
    let base = ctx.out.canonicalize().unwrap_or_else(|_| ctx.out.clone());
    let want = std::path::PathBuf::from(requested);
    let resolved = want.canonicalize().map_err(|e| {
        error::AppError::Config(format!("out: cannot resolve {}: {e}", want.display()))
    })?;
    if !resolved.starts_with(&base) {
        return Err(error::AppError::Config(format!(
            "out: {} is outside the server base {}",
            resolved.display(),
            base.display()
        )));
    }
    Ok(resolved)
}

/// [`arg_out`] mapped into the tool-result channel, so a refusal reaches the
/// caller as a JSON-RPC error instead of a panic or a silent fallback.
fn arg_out_or_err(ctx: &ServerCtx, args: &Value) -> Result<std::path::PathBuf, ToolOutcome> {
    arg_out(ctx, args).map_err(|e| ToolOutcome::BadArgs(e.to_string()))
}

fn arg_min_risk(args: &Value) -> u8 {
    args.get("min_risk").and_then(Value::as_u64).unwrap_or(0).min(100) as u8
}

fn parse_sources_arg(args: &Value) -> Vec<SourceFile> {
    args.get("sources")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    Some(SourceFile {
                        path: s.get("path").and_then(Value::as_str)?.to_string(),
                        content: s.get("content").and_then(Value::as_str)?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// JSON of a contract's source files (SourceFile isn't Serialize).
fn sources_to_json(sources: &[SourceFile]) -> Value {
    Value::Array(
        sources
            .iter()
            .map(|s| json!({ "path": s.path, "content": s.content }))
            .collect(),
    )
}

// ---------------- offline tools ----------------

fn tool_audit_source(args: &Value) -> ToolOutcome {
    let address = arg_str(args, "address").unwrap_or("0x0000000000000000000000000000000000000000");
    let chain_id = args.get("chain_id").and_then(Value::as_u64).unwrap_or(1);
    let mut d = ContractDetails::minimal(address, chain_id);
    d.is_proxy = arg_bool(args, "is_proxy");
    if let Some(cv) = arg_str(args, "compiler_version") {
        d.compiler_version = Some(cv.to_string());
    }
    if let Some(bc) = arg_str(args, "bytecode") {
        match bc.parse::<EvmBytes>() {
            Ok(bytes) => {
                d.bytecode = bytes.to_string();
                d.bytecode_size = bytes.len();
                d.analysis = analysis::analyze(bytes.as_ref());
            }
            Err(_) => return ToolOutcome::BadArgs("bytecode must be 0x-prefixed hex".into()),
        }
    }
    let sources = parse_sources_arg(args);
    if !sources.is_empty() {
        d.is_verified = true;
        d.source_file_count = sources.len();
    }
    let audit = audit::audit_with(&d, &sources, &Suppressions::default());
    ToolOutcome::Ok(serde_json::to_value(audit).unwrap_or(Value::Null))
}

fn tool_audit_corpus(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let out = match arg_out_or_err(ctx, args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let contracts = crate::audit_corpus(
        &out,
        arg_min_risk(args),
        arg_bool(args, "only_vulnerable"),
        arg_bool(args, "by_risk"),
        &Suppressions::default(),
    );
    let vulnerable = contracts
        .iter()
        .filter(|d| d.audit.as_ref().is_some_and(crate::has_high_or_critical))
        .count();
    ToolOutcome::Ok(json!({ "audited": contracts.len(), "vulnerable": vulnerable, "contracts": contracts }))
}

fn tool_get_contract(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let out = match arg_out_or_err(ctx, args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let Some(raw) = arg_str(args, "address") else {
        return ToolOutcome::BadArgs("get_contract: missing 'address'".into());
    };
    // Validate as a real address before building any path (prevents traversal).
    let address = match raw.parse::<Address>() {
        Ok(a) => format!("{a:#x}"),
        Err(_) => return ToolOutcome::BadArgs(format!("get_contract: invalid 'address': {raw}")),
    };
    match storage::load_metadata(&out, &address) {
        Ok(d) => {
            let mut result = json!({ "contract": d });
            if arg_bool(args, "include_source") {
                result["sources"] = sources_to_json(&storage::load_sources(&out, &address));
            }
            ToolOutcome::Ok(result)
        }
        Err(e) => ToolOutcome::ToolError(format!("contract {address} not found under {}: {e}", out.display())),
    }
}

fn tool_list_contracts(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let min_risk = arg_min_risk(args);
    let only_vulnerable = arg_bool(args, "only_vulnerable");
    let out = match arg_out_or_err(ctx, args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let contracts: Vec<Value> = storage::load_all_metadata(&out)
        .into_iter()
        .filter(|d| {
            // Filter on the saved audit (no re-audit): no audit can't meet min_risk.
            if min_risk > 0 && d.audit.as_ref().is_none_or(|a| a.risk_score < min_risk) {
                return false;
            }
            if only_vulnerable && !d.audit.as_ref().is_some_and(crate::has_high_or_critical) {
                return false;
            }
            true
        })
        .map(|d| {
            json!({
                "address": d.address,
                "chain_id": d.chain_id,
                "contract_name": d.contract_name,
                "is_verified": d.is_verified,
                "risk_score": d.audit.as_ref().map(|a| a.risk_score),
                "grade": d.audit.as_ref().map(|a| a.grade.clone()),
            })
        })
        .collect();
    ToolOutcome::Ok(json!({ "count": contracts.len(), "contracts": contracts }))
}

fn tool_export_sarif(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let out = match arg_out_or_err(ctx, args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let contracts = crate::audit_corpus(
        &out,
        arg_min_risk(args),
        arg_bool(args, "only_vulnerable"),
        false,
        &Suppressions::default(),
    );
    ToolOutcome::Ok(sarif::build_sarif(&contracts))
}

fn tool_cluster_corpus(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let out = match arg_out_or_err(ctx, args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let clusters = analysis::cluster_by_code(&storage::load_all_metadata(&out));
    ToolOutcome::Ok(json!({ "clusters": clusters }))
}

// ---------------- online tools ----------------

/// Build a Json-format scan [`Config`] from inline network args (shared by the
/// scan tools). `format = Json` so `process_addresses` materializes `contracts`
/// instead of streaming to stdout (which is the MCP channel).
fn build_scan_config(
    ctx: &ServerCtx,
    args: &Value,
    rpc_url: &str,
    etherscan_key: &str,
) -> error::Result<Config> {
    let out_dir = arg_out(ctx, args)?;
    Ok(Config {
        rpc_url: rpc_url.to_string(),
        etherscan_key: etherscan_key.to_string(),
        etherscan_base: arg_str(args, "etherscan_base")
            .unwrap_or("https://api.etherscan.io/v2/api")
            .to_string(),
        blockscout_base: String::new(),
        blockscout_rate: 4,
        chain_id: args.get("chain_id").and_then(Value::as_u64).unwrap_or(1),
        out_dir,
        concurrency: 5,
        rate: 5,
        retries: 5,
        overwrite: arg_bool(args, "overwrite"),
        trace: arg_bool(args, "trace"),
        table: false,
        sourcify: true,
        sourcify_base: "https://sourcify.dev/server".to_string(),
        only_verified: arg_bool(args, "only_verified"),
        min_balance_wei: 0,
        only_proxy: arg_bool(args, "only_proxy"),
        manifest: None,
        format: OutputFormat::Json,
        audit: args.get("audit").and_then(Value::as_bool).unwrap_or(true),
        min_risk: arg_min_risk(args),
        only_vulnerable: arg_bool(args, "only_vulnerable"),
        suppressions: Suppressions::default(),
    })
}

/// Parse a bounded `from`/`to` block range (≤ [`MAX_RANGE`]). `Err` is a BadArgs message.
fn bounded_range(args: &Value) -> Result<(u64, u64), String> {
    let (from, to) = match (args.get("from").and_then(Value::as_u64), args.get("to").and_then(Value::as_u64)) {
        (Some(f), Some(t)) => (f, t),
        _ => return Err("'from' and 'to' (block numbers) are required".into()),
    };
    if from > to {
        return Err("'from' must be <= 'to'".into());
    }
    // `to - from` is safe (from <= to); avoid `+1` which overflows at to == u64::MAX.
    // span = to-from+1 > MAX_RANGE  ⟺  to-from >= MAX_RANGE.
    if to - from >= MAX_RANGE {
        return Err(format!("range too large (> {MAX_RANGE} blocks) — paginate"));
    }
    Ok((from, to))
}

async fn tool_scan_addresses(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let Some(rpc_url) = arg_str(args, "rpc_url") else {
        return ToolOutcome::BadArgs("scan_addresses: missing 'rpc_url'".into());
    };
    let Some(etherscan_key) = arg_str(args, "etherscan_key") else {
        return ToolOutcome::BadArgs("scan_addresses: missing 'etherscan_key'".into());
    };
    let Some(raw) = args.get("addresses").and_then(Value::as_array) else {
        return ToolOutcome::BadArgs("scan_addresses: 'addresses' must be an array".into());
    };
    let addrs: Vec<Address> = raw
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|s| s.parse::<Address>().ok())
        .collect();
    if addrs.is_empty() {
        return ToolOutcome::BadArgs("scan_addresses: no valid addresses".into());
    }
    let cfg = match build_scan_config(ctx, args, rpc_url, etherscan_key) {
        Ok(c) => c,
        Err(e) => return ToolOutcome::BadArgs(e.to_string()),
    };
    if let Err(e) = cfg.validate() {
        return ToolOutcome::ToolError(e.to_string());
    }
    let (_rpc, scanner) = match crate::build_scanner(&cfg) {
        Ok(x) => x,
        Err(e) => return ToolOutcome::ToolError(e.to_string()),
    };
    let (stats, contracts) = scanner.process_addresses(addrs).await;
    ToolOutcome::Ok(json!({ "stats": stats, "contracts": contracts }))
}

async fn tool_scan_block_range(ctx: &ServerCtx, args: &Value) -> ToolOutcome {
    let Some(rpc_url) = arg_str(args, "rpc_url") else {
        return ToolOutcome::BadArgs("scan_block_range: missing 'rpc_url'".into());
    };
    let Some(etherscan_key) = arg_str(args, "etherscan_key") else {
        return ToolOutcome::BadArgs("scan_block_range: missing 'etherscan_key'".into());
    };
    let (from, to) = match bounded_range(args) {
        Ok(r) => r,
        Err(e) => return ToolOutcome::BadArgs(format!("scan_block_range: {e}")),
    };
    let cfg = match build_scan_config(ctx, args, rpc_url, etherscan_key) {
        Ok(c) => c,
        Err(e) => return ToolOutcome::BadArgs(e.to_string()),
    };
    if let Err(e) = cfg.validate() {
        return ToolOutcome::ToolError(e.to_string());
    }
    let (rpc, scanner) = match crate::build_scanner(&cfg) {
        Ok(x) => x,
        Err(e) => return ToolOutcome::ToolError(e.to_string()),
    };
    let mut stats = crate::scanner::RunStats::default();
    let mut contracts: Vec<ContractDetails> = Vec::new();
    for n in from..=to {
        if let Err(e) = crate::process_block(&rpc, &scanner, n, cfg.trace, &mut stats, &mut contracts).await {
            return ToolOutcome::ToolError(format!("block {n}: {e}"));
        }
    }
    ToolOutcome::Ok(json!({ "from": from, "to": to, "stats": stats, "contracts": contracts }))
}

/// Events-only monitor over a bounded range. COLLECTS alerts into the result —
/// it must NOT reuse `scan_events_range` (which writes to stdout, the MCP channel).
/// No Etherscan key needed (RPC `eth_getLogs` only).
async fn tool_monitor_range(args: &Value) -> ToolOutcome {
    let Some(rpc_url) = arg_str(args, "rpc_url") else {
        return ToolOutcome::BadArgs("monitor_range: missing 'rpc_url'".into());
    };
    let (from, to) = match bounded_range(args) {
        Ok(r) => r,
        Err(e) => return ToolOutcome::BadArgs(format!("monitor_range: {e}")),
    };
    let chain_id = args.get("chain_id").and_then(Value::as_u64).unwrap_or(1);

    let extra_topics: Vec<String> = args
        .get("alert_topic")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    let mut topics = crate::build_topics(&extra_topics);
    let min_transfer = crate::parse_min_transfer(arg_str(args, "min_transfer"));
    if min_transfer.is_some() {
        let t = crate::events::transfer_topic();
        if !topics.contains(&t) {
            topics.push(t);
        }
    }
    let watchlist: Option<std::collections::HashSet<Address>> = args
        .get("watchlist")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).filter_map(|s| s.parse::<Address>().ok()).collect());

    let rpc = match crate::rpc::RpcClient::new(rpc_url, 5) {
        Ok(r) => r,
        Err(e) => return ToolOutcome::ToolError(e.to_string()),
    };
    let (logs, failed) = match rpc.fetch_logs(from, to, topics, 2000, 4).await {
        Ok(x) => x,
        Err(e) => return ToolOutcome::ToolError(e.to_string()),
    };
    let mut alerts: Vec<crate::model::Alert> = Vec::new();
    for log in &logs {
        if let Some(wl) = &watchlist {
            if !wl.contains(&log.address) {
                continue;
            }
        }
        let mut a = crate::events::parse_alert(log).unwrap_or_else(|| crate::events::unknown_alert(log));
        a.chain_id = chain_id;
        if a.kind == "large-transfer" {
            let value = a.amount.as_deref().and_then(|s| s.parse::<alloy::primitives::U256>().ok());
            if !matches!((min_transfer, value), (Some(t), Some(v)) if v >= t) {
                continue;
            }
        }
        alerts.push(a);
    }
    ToolOutcome::Ok(json!({
        "from": from, "to": to,
        "counts": { "emitted": alerts.len(), "incomplete": failed > 0 },
        "alerts": alerts,
    }))
}

// ---------------- resources ----------------

/// One resource per saved contract: `blockscan://contract/<address>`.
fn resources_list(ctx: &ServerCtx) -> Vec<Value> {
    storage::load_all_metadata(&ctx.out)
        .into_iter()
        .map(|d| {
            let name = d.contract_name.clone().unwrap_or_else(|| d.address.clone());
            json!({
                "uri": format!("blockscan://contract/{}", d.address),
                "name": name,
                "mimeType": "application/json",
                "description": format!("chain {} contract {}", d.chain_id, d.address),
            })
        })
        .collect()
}

/// Read `blockscan://contract/<address>` → the contract's metadata JSON.
fn resources_read(ctx: &ServerCtx, id: &Value, req: &Value) -> Value {
    let Some(uri) = req.pointer("/params/uri").and_then(Value::as_str) else {
        return error_response(id, INVALID_PARAMS, "resources/read: missing params.uri");
    };
    let Some(raw) = uri.strip_prefix("blockscan://contract/") else {
        return error_response(id, INVALID_PARAMS, &format!("unsupported resource uri: {uri}"));
    };
    // Validate as a real address before touching the filesystem — a parsed Address
    // is canonical 20-byte hex, so it can't contain `/`, `\`, `..`, `:` or be
    // absolute (prevents path traversal out of the corpus directory).
    let address = match raw.parse::<Address>() {
        Ok(a) => format!("{a:#x}"),
        Err(_) => return error_response(id, INVALID_PARAMS, &format!("invalid contract address in uri: {uri}")),
    };
    match storage::load_metadata(&ctx.out, &address) {
        Ok(d) => {
            let text = serde_json::to_string_pretty(&d).unwrap_or_default();
            result_response(id, json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": text }] }))
        }
        Err(e) => error_response(id, INVALID_PARAMS, &format!("resource not found ({uri}): {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, id: Value, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    /// Default server context (corpus at "output"); corpus tools pass an explicit `out`.
    fn ctx() -> ServerCtx {
        ServerCtx::new(std::path::PathBuf::from("output"))
    }

    async fn call(tool: &str, args: Value) -> Value {
        let r = handle(&ctx(), &req("tools/call", json!(1), json!({ "name": tool, "arguments": args }))).await;
        r.expect("request gets a response")
    }

    /// Like [`call`], but with the server's own base set to `base`. Corpus tools
    /// take an `out` argument, and since T-01 that argument must resolve inside
    /// the server base — so a test driving one has to say what the base is
    /// rather than relying on the request to choose it.
    async fn call_at(base: &std::path::Path, tool: &str, args: Value) -> Value {
        let ctx = ServerCtx::new(base.to_path_buf());
        let r = handle(&ctx, &req("tools/call", json!(1), json!({ "name": tool, "arguments": args }))).await;
        r.expect("request gets a response")
    }

    // ---- T-01: the corpus directory is the server's, not the caller's ----

    #[tokio::test]
    async fn out_argument_outside_the_server_base_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let escape = tempfile::tempdir().unwrap();
        let r = call_at(base.path(), "list_contracts", json!({ "out": escape.path() })).await;
        assert!(r.get("error").is_some(), "a sibling directory must be refused: {r}");
    }

    #[tokio::test]
    async fn out_argument_with_parent_traversal_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let escape = base.path().join("..").join("..");
        let r = call_at(base.path(), "list_contracts", json!({ "out": escape })).await;
        assert!(r.get("error").is_some(), "parent traversal must be refused: {r}");
    }

    #[tokio::test]
    async fn an_in_base_out_argument_and_an_absent_one_both_work() {
        let base = tempfile::tempdir().unwrap();
        let inner = base.path().join("chain-1");
        std::fs::create_dir_all(&inner).unwrap();
        // A real subdirectory of the base resolves and is accepted.
        let r = call_at(base.path(), "list_contracts", json!({ "out": inner })).await;
        assert!(r.get("error").is_none(), "an in-base subdirectory must work: {r}");
        // Omitting the argument falls back to the server's own directory.
        let r = call_at(base.path(), "list_contracts", json!({})).await;
        assert!(r.get("error").is_none(), "the default path must work: {r}");
    }

    #[tokio::test]
    async fn an_unresolvable_out_argument_is_refused_rather_than_guessed() {
        let base = tempfile::tempdir().unwrap();
        let missing = base.path().join("does-not-exist");
        let r = call_at(base.path(), "list_contracts", json!({ "out": missing })).await;
        assert!(r.get("error").is_some(), "an unresolvable path must be refused: {r}");
    }

    #[tokio::test]
    async fn initialize_echoes_protocol_version_and_advertises_tools() {
        let r = handle(&ctx(), &req("initialize", json!(1), json!({ "protocolVersion": "2099-01-01" })))
            .await
            .unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2099-01-01"); // echoed
        assert_eq!(r["result"]["serverInfo"]["name"], "blockscan");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        // No version supplied -> default.
        let r = handle(&ctx(), &req("initialize", json!(2), json!({}))).await.unwrap();
        assert_eq!(r["result"]["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn notifications_get_no_reply() {
        assert!(handle(&ctx(), &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await.is_none());
        // No method at all -> ignored.
        assert!(handle(&ctx(), &json!({ "jsonrpc": "2.0", "id": 1 })).await.is_none());
    }

    #[tokio::test]
    async fn ping_and_unknown_method() {
        let r = handle(&ctx(), &req("ping", json!(7), json!({}))).await.unwrap();
        assert_eq!(r["result"], json!({}));
        assert_eq!(r["id"], 7);
        let r = handle(&ctx(), &req("frobnicate", json!(8), json!({}))).await.unwrap();
        assert_eq!(r["error"]["code"], METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn tools_list_shapes() {
        let r = handle(&ctx(), &req("tools/list", json!(1), json!({}))).await.unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 9);
        for t in tools {
            assert!(t["name"].is_string());
            assert!(t["description"].is_string());
            assert_eq!(t["inputSchema"]["type"], "object");
        }
        for name in ["audit_source", "scan_block_range", "monitor_range"] {
            assert!(tools.iter().any(|t| t["name"] == name), "missing tool {name}");
        }
    }

    #[tokio::test]
    async fn tools_call_argument_errors() {
        // Missing params.name.
        let r = handle(&ctx(), &req("tools/call", json!(1), json!({}))).await.unwrap();
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
        // Unknown tool.
        let r = call("nope", json!({})).await;
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
    }

    #[tokio::test]
    async fn audit_source_inline_detects_and_grades() {
        let r = call(
            "audit_source",
            json!({
                "address": "0xabc", "chain_id": 1, "compiler_version": "v0.8.20+commit", "is_proxy": false,
                "sources": [{ "path": "C.sol", "content": "contract C { function f() public { require(tx.origin == owner); } }" }]
            }),
        )
        .await;
        assert_eq!(r["result"]["isError"], false);
        let audit = &r["result"]["structuredContent"];
        assert!(audit["risk_score"].as_u64().unwrap() > 0);
        assert!(audit["findings"].as_array().unwrap().iter().any(|f| f["rule_id"] == "TX_ORIGIN_AUTH"));
        // Content text mirrors the structured value.
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("TX_ORIGIN_AUTH"));
    }

    #[tokio::test]
    async fn audit_source_bytecode_signal_and_bad_hex() {
        // A standalone SELFDESTRUCT opcode (0xff, not a PUSH immediate) -> a
        // bytecode-level finding, proving analysis feeds the bytecode detectors.
        let r = call("audit_source", json!({ "bytecode": "0xff" })).await;
        assert_eq!(r["result"]["isError"], false);
        let findings = r["result"]["structuredContent"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["rule_id"] == "BYTECODE_SELFDESTRUCT"),
            "expected a bytecode selfdestruct finding: {findings:?}"
        );
        // Bad hex -> protocol-level invalid params.
        let r = call("audit_source", json!({ "bytecode": "zzz" })).await;
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
    }

    fn save_vuln_corpus() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let mut d = ContractDetails::minimal("0x00000000000000000000000000000000000000aa", 1);
        d.is_verified = true;
        d.bytecode = "0x6001".into();
        let src = vec![SourceFile {
            path: "C.sol".into(),
            content: "contract C { function f() public { require(tx.origin == owner); } }".into(),
        }];
        storage::save_contract(out, &d, &src, None).unwrap();
        tmp
    }

    #[tokio::test]
    async fn audit_corpus_get_list_export_cluster() {
        let tmp = save_vuln_corpus();
        let out = tmp.path().to_str().unwrap();

        let r = call_at(tmp.path(),"audit_corpus", json!({ "out": out })).await;
        assert_eq!(r["result"]["structuredContent"]["audited"], 1);
        assert!(r["result"]["structuredContent"]["contracts"][0]["audit"]["risk_score"].as_u64().unwrap() > 0);

        let r = call_at(tmp.path(),"get_contract", json!({ "out": out, "address": "0x00000000000000000000000000000000000000aa", "include_source": true })).await;
        assert_eq!(r["result"]["structuredContent"]["contract"]["is_verified"], true);
        assert_eq!(r["result"]["structuredContent"]["sources"][0]["path"], "C.sol");

        let r = call_at(tmp.path(),"get_contract", json!({ "out": out, "address": "0x00000000000000000000000000000000000000ff" })).await;
        assert_eq!(r["result"]["isError"], true); // not found

        let r = call_at(tmp.path(),"list_contracts", json!({ "out": out })).await;
        assert_eq!(r["result"]["structuredContent"]["count"], 1);

        let r = call_at(tmp.path(),"export_sarif", json!({ "out": out })).await;
        assert_eq!(r["result"]["structuredContent"]["version"], "2.1.0");

        let r = call_at(tmp.path(),"cluster_corpus", json!({ "out": out })).await;
        assert!(r["result"]["structuredContent"]["clusters"].is_array());
    }

    #[tokio::test]
    async fn get_contract_missing_address_is_bad_args() {
        let r = call("get_contract", json!({ "out": "output" })).await;
        assert_eq!(r["error"]["code"], INVALID_PARAMS);
    }

    #[tokio::test]
    async fn scan_addresses_argument_validation() {
        // Missing rpc_url -> bad args (no network touched).
        assert_eq!(call("scan_addresses", json!({})).await["error"]["code"], INVALID_PARAMS);
        // rpc_url present, key missing -> bad args.
        assert_eq!(call("scan_addresses", json!({ "rpc_url": "http://x" })).await["error"]["code"], INVALID_PARAMS);
        // rpc_url + key present, addresses missing/not-array -> bad args.
        assert_eq!(call("scan_addresses", json!({ "rpc_url": "http://x", "etherscan_key": "k" })).await["error"]["code"], INVALID_PARAMS);
        // All addresses unparseable -> bad args.
        assert_eq!(
            call("scan_addresses", json!({ "rpc_url": "http://x", "etherscan_key": "k", "addresses": ["not-an-addr"] })).await["error"]["code"],
            INVALID_PARAMS
        );
        // Present-but-empty etherscan_key -> Config::validate fails -> tool error (not protocol).
        let r = call(
            "scan_addresses",
            json!({ "rpc_url": "http://x", "etherscan_key": "", "addresses": ["0x000000000000000000000000000000000000dEaD"] }),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
        // Unparseable rpc_url passes validate (non-empty) but fails client build -> tool error.
        let r = call(
            "scan_addresses",
            json!({ "rpc_url": "not a url", "etherscan_key": "k", "addresses": ["0x000000000000000000000000000000000000dEaD"] }),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
    }

    #[tokio::test]
    async fn list_contracts_filters_by_saved_audit() {
        use crate::model::{Audit, SecurityFinding};
        fn finding(sev: &str) -> SecurityFinding {
            SecurityFinding {
                rule_id: "X".into(), title: "t".into(), category: "SC01:Access Control".into(), swc: None,
                scwe: None, ethtrust: None,
                severity: sev.into(), confidence: "Medium".into(), impact_score: 5, likelihood_score: 5,
                exploitability: "Moderate".into(), asset_at_risk: "x".into(), blast_radius: "single-contract".into(),
                risk: 30, priority: "P1".into(), detection: "source".into(), affected_contract: "0xa".into(),
                locations: vec![], evidence: "e".into(), exploit_scenario: "s".into(), recommendation: "r".into(),
                references: vec![], false_positive_notes: String::new(),
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let save = |addr: &str, risk: u8, sev: &str| {
            let mut d = ContractDetails::minimal(addr, 1);
            d.is_verified = true;
            d.audit = Some(Audit {
                risk_score: risk, grade: "C".into(), risk_level: "Medium".into(),
                findings: vec![finding(sev)], summary: Default::default(),
            });
            storage::save_contract(out, &d, &[], None).unwrap();
        };
        save("0x00000000000000000000000000000000000000a1", 80, "High");
        save("0x00000000000000000000000000000000000000b2", 5, "Low");
        let out_s = out.to_str().unwrap();

        // No filter -> both.
        assert_eq!(call_at(out,"list_contracts", json!({ "out": out_s })).await["result"]["structuredContent"]["count"], 2);
        // min_risk drops the low-risk one.
        assert_eq!(call_at(out,"list_contracts", json!({ "out": out_s, "min_risk": 50 })).await["result"]["structuredContent"]["count"], 1);
        // only_vulnerable drops the Low-only one.
        assert_eq!(call_at(out,"list_contracts", json!({ "out": out_s, "only_vulnerable": true })).await["result"]["structuredContent"]["count"], 1);
    }

    #[tokio::test]
    async fn resources_list_and_read() {
        let tmp = save_vuln_corpus();
        let c = ServerCtx::new(tmp.path().to_path_buf());
        let addr = "0x00000000000000000000000000000000000000aa";
        // list -> one resource for the saved contract.
        let r = handle(&c, &req("resources/list", json!(1), json!({}))).await.unwrap();
        let res = r["result"]["resources"].as_array().unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0]["uri"], format!("blockscan://contract/{addr}"));
        assert_eq!(res[0]["mimeType"], "application/json");
        // read -> the contract metadata JSON.
        let r = handle(&c, &req("resources/read", json!(2), json!({ "uri": format!("blockscan://contract/{addr}") })))
            .await
            .unwrap();
        let contents = r["result"]["contents"].as_array().unwrap();
        assert_eq!(contents[0]["mimeType"], "application/json");
        assert!(contents[0]["text"].as_str().unwrap().contains(addr));
        // missing uri / unsupported scheme / not-found -> protocol errors.
        assert_eq!(handle(&c, &req("resources/read", json!(3), json!({}))).await.unwrap()["error"]["code"], INVALID_PARAMS);
        assert_eq!(handle(&c, &req("resources/read", json!(4), json!({ "uri": "http://x" }))).await.unwrap()["error"]["code"], INVALID_PARAMS);
        let missing = "blockscan://contract/0x00000000000000000000000000000000000000ff";
        assert_eq!(handle(&c, &req("resources/read", json!(5), json!({ "uri": missing }))).await.unwrap()["error"]["code"], INVALID_PARAMS);
        // Regression (review HIGH): traversal / absolute / non-address rejected, not joined.
        for evil in [
            "blockscan://contract/../../../../etc/passwd",
            "blockscan://contract/..\\..\\windows\\win.ini",
            "blockscan://contract/C:\\windows\\system32",
            "blockscan://contract/not-an-address",
        ] {
            let r = handle(&c, &req("resources/read", json!(9), json!({ "uri": evil }))).await.unwrap();
            assert_eq!(r["error"]["code"], INVALID_PARAMS, "must reject: {evil}");
        }
    }

    #[tokio::test]
    async fn get_contract_rejects_non_address() {
        // Regression (review HIGH): a traversal/absolute address arg is rejected.
        for evil in ["../../secret", "..\\..\\x", "C:\\windows", "nope"] {
            let r = call("get_contract", json!({ "out": "output", "address": evil })).await;
            assert_eq!(r["error"]["code"], INVALID_PARAMS, "must reject: {evil}");
        }
    }

    #[test]
    fn bounded_range_rejects_overflow_span() {
        // Regression (review MED): to-from+1 must not overflow at u64::MAX.
        assert!(bounded_range(&json!({ "from": 0u64, "to": u64::MAX })).is_err());
        // Boundary: span 500 ok, span 501 rejected; from>to rejected.
        assert!(bounded_range(&json!({ "from": 0u64, "to": 499u64 })).is_ok());
        assert!(bounded_range(&json!({ "from": 0u64, "to": 500u64 })).is_err());
        assert!(bounded_range(&json!({ "from": 10u64, "to": 5u64 })).is_err());
    }

    #[tokio::test]
    async fn corpus_tool_defaults_out_to_server_ctx() {
        // No `out` argument -> the tool uses the server's configured corpus dir.
        let tmp = save_vuln_corpus();
        let c = ServerCtx::new(tmp.path().to_path_buf());
        let r = handle(&c, &req("tools/call", json!(1), json!({ "name": "audit_corpus", "arguments": {} })))
            .await
            .unwrap();
        assert_eq!(r["result"]["structuredContent"]["audited"], 1);
    }

    #[tokio::test]
    async fn scan_block_range_bounded_validation() {
        assert_eq!(call("scan_block_range", json!({})).await["error"]["code"], INVALID_PARAMS); // no rpc_url
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "http://x" })).await["error"]["code"], INVALID_PARAMS); // no key
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "http://x", "etherscan_key": "k" })).await["error"]["code"], INVALID_PARAMS); // no from/to
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "http://x", "etherscan_key": "k", "from": 10, "to": 5 })).await["error"]["code"], INVALID_PARAMS); // from>to
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "http://x", "etherscan_key": "k", "from": 0, "to": 1000 })).await["error"]["code"], INVALID_PARAMS); // >MAX_RANGE
        // Empty key passes presence check but fails Config::validate -> tool error.
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "http://x", "etherscan_key": "", "from": 1, "to": 1 })).await["result"]["isError"], true);
        // Unparseable rpc_url -> client build fails -> tool error.
        assert_eq!(call("scan_block_range", json!({ "rpc_url": "not a url", "etherscan_key": "k", "from": 1, "to": 1 })).await["result"]["isError"], true);
    }

    #[tokio::test]
    async fn monitor_range_bounded_validation() {
        assert_eq!(call("monitor_range", json!({})).await["error"]["code"], INVALID_PARAMS); // no rpc_url
        assert_eq!(call("monitor_range", json!({ "rpc_url": "http://x" })).await["error"]["code"], INVALID_PARAMS); // no from/to
        assert_eq!(call("monitor_range", json!({ "rpc_url": "http://x", "from": 0, "to": 1000 })).await["error"]["code"], INVALID_PARAMS); // >MAX_RANGE
        // Unparseable rpc_url -> RpcClient build fails -> tool error.
        assert_eq!(call("monitor_range", json!({ "rpc_url": "not a url", "from": 1, "to": 1 })).await["result"]["isError"], true);
    }

    #[test]
    fn ok_result_omits_structured_for_non_objects() {
        // Object value -> structuredContent present.
        let r = ok_result(json!({ "a": 1 }));
        assert!(r["structuredContent"].is_object());
        assert_eq!(r["isError"], false);
        // Array value -> no structuredContent, but text still carries it.
        let r = ok_result(json!([1, 2, 3]));
        assert!(r.get("structuredContent").is_none());
        assert!(r["content"][0]["text"].as_str().unwrap().contains('1'));
    }

    #[tokio::test]
    async fn serve_loop_round_trips_over_buffers() {
        // Feed a blank line, an initialize, a notification (no reply), a bad line,
        // and a ping over in-memory buffers; assert one response line per request.
        let input = concat!(
            "\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "this is not json\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        );
        let mut out: Vec<u8> = Vec::new();
        serve(&ctx(), tokio::io::BufReader::new(input.as_bytes()), &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // initialize + parse-error + ping = 3 responses (blank + notification produce none).
        assert_eq!(lines.len(), 3, "responses: {text}");
        let init: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        let err: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(err["error"]["code"], PARSE_ERROR);
        assert_eq!(err["id"], Value::Null);
        let ping: Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(ping["id"], 2);
        assert_eq!(ping["result"], json!({}));
    }

    // ---- HTTP transport (Phase 20) ----

    fn hdr(origin: Option<&str>, auth: Option<&str>) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        if let Some(o) = origin {
            h.insert(hyper::header::ORIGIN, o.parse().unwrap());
        }
        if let Some(a) = auth {
            h.insert(hyper::header::AUTHORIZATION, a.parse().unwrap());
        }
        h
    }

    /// The credential these tests drive the server with. Since T-02 the HTTP
    /// surface always has one, so a test about method, path, origin or body size
    /// has to present it — that is setup, and the assertions are unchanged.
    const TOK: &str = "t0ken";
    const BEARER: &str = "Bearer t0ken";

    async fn http(token: &str, method: hyper::Method, path: &str, headers: hyper::HeaderMap, body: &[u8]) -> (u16, Vec<u8>) {
        use http_body_util::BodyExt;
        let resp = http_handle(&ctx(), token, &method, path, &headers, body).await;
        let status = resp.status().as_u16();
        let b = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, b)
    }

    #[tokio::test]
    async fn http_post_request_and_notification() {
        let init = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let (st, body) = http(TOK, hyper::Method::POST, "/mcp", hdr(Some("http://localhost"), Some(BEARER)), init).await;
        assert_eq!(st, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["result"]["serverInfo"]["name"], "blockscan");
        // Notification (no id) -> 202 empty body.
        let note = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let (st, body) = http(TOK, hyper::Method::POST, "/mcp", hdr(None, Some(BEARER)), note).await;
        assert_eq!(st, 202);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn http_tools_call_matches_stdio_and_bad_json() {
        // Same dispatch as stdio: an offline tool returns its result over HTTP.
        let call = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"audit_source","arguments":{"sources":[{"path":"C.sol","content":"contract C { function f() public { require(tx.origin == owner); } }"}]}}}"#;
        let (st, body) = http(TOK, hyper::Method::POST, "/mcp", hdr(None, Some(BEARER)), call).await;
        assert_eq!(st, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["result"]["isError"], false);
        assert!(v["result"]["structuredContent"]["risk_score"].as_u64().unwrap() > 0);
        // Bad JSON -> 200 + JSON-RPC parse error (NOT an HTTP 4xx).
        let (st, body) = http(TOK, hyper::Method::POST, "/mcp", hdr(None, Some(BEARER)), b"{not json").await;
        assert_eq!(st, 200);
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["code"], PARSE_ERROR);
    }

    #[tokio::test]
    async fn http_method_path_origin_size_auth_guards() {
        let ok = hdr(Some("http://localhost"), Some(BEARER));
        assert_eq!(http(TOK, hyper::Method::GET, "/mcp", ok.clone(), b"").await.0, 405);
        assert_eq!(http(TOK, hyper::Method::POST, "/nope", ok.clone(), b"{}").await.0, 404);
        assert_eq!(http(TOK, hyper::Method::POST, "/mcp", hdr(Some("http://evil.example"), Some(BEARER)), b"{}").await.0, 403);
        // Regression (review MED): host-suffix must NOT pass the loopback origin check.
        let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        // `null` (opaque origin) is rejected — a legitimate local browser sends a
        // real loopback Origin; allowing `null` would weaken the rebinding guard.
        for bad in ["http://localhost.evil.com", "http://127.0.0.1.evil.com", "http://127.0.0.1@evil.com", "ftp://localhost", "null"] {
            assert_eq!(http(TOK, hyper::Method::POST, "/mcp", hdr(Some(bad), Some(BEARER)), ping).await.0, 403, "must reject {bad}");
        }
        // Genuine loopback origins (incl. IPv6 + port + https) are allowed.
        for good in ["http://localhost", "http://127.0.0.1:8765", "https://localhost", "http://[::1]:9000"] {
            assert_eq!(http(TOK, hyper::Method::POST, "/mcp", hdr(Some(good), Some(BEARER)), ping).await.0, 200, "must allow {good}");
        }
        let big = vec![b'x'; MAX_HTTP_BODY + 1];
        assert_eq!(http(TOK, hyper::Method::POST, "/mcp", ok.clone(), &big).await.0, 413);
        // Token: missing/wrong -> 401; correct -> dispatched.
        assert_eq!(http("secret", hyper::Method::POST, "/mcp", ok.clone(), b"{}").await.0, 401);
        let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        assert_eq!(http("secret", hyper::Method::POST, "/mcp", hdr(Some("http://localhost"), Some("Bearer secret")), ping).await.0, 200);
        // No-Origin client is allowed (typical non-browser MCP client).
        assert_eq!(http(TOK, hyper::Method::POST, "/mcp", hdr(None, Some(BEARER)), ping).await.0, 200);
    }

    // ---- T-02: the HTTP surface never runs unauthenticated ----

    #[test]
    fn minted_credentials_are_random_and_full_width() {
        let a = mint_token().expect("OS CSPRNG");
        let b = mint_token().expect("OS CSPRNG");
        assert_eq!(a.len(), 64, "256 bits, hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two mints must not collide");
    }

    #[tokio::test]
    async fn a_minted_credential_is_still_required() {
        // The server that generates its own token must enforce it exactly as one
        // given a token does — generating it is not a way of turning the check off.
        let minted = mint_token().unwrap();
        let ping = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let none = hdr(Some("http://localhost"), None);
        assert_eq!(http(&minted, hyper::Method::POST, "/mcp", none, ping).await.0, 401);
        let wrong = hdr(Some("http://localhost"), Some("Bearer not-it"));
        assert_eq!(http(&minted, hyper::Method::POST, "/mcp", wrong, ping).await.0, 401);
        let right = hdr(Some("http://localhost"), Some(&format!("Bearer {minted}")));
        assert_eq!(http(&minted, hyper::Method::POST, "/mcp", right, ping).await.0, 200);
    }

    #[tokio::test]
    async fn stdio_does_not_gain_a_credential_requirement() {
        // stdio has no network surface, so a credential there would cost usability
        // and buy nothing.
        let tmp = tempfile::tempdir().unwrap();
        let c = ServerCtx::new(tmp.path().to_path_buf());
        let r = handle(&c, &req("tools/list", json!(1), json!({}))).await;
        let r = r.expect("tools/list answers on stdio with no credential");
        assert!(r.get("error").is_none(), "stdio must stay credential-free: {r}");
    }

    #[test]
    fn parse_loopback_addr_cases() {
        assert_eq!(parse_loopback_addr("8765").unwrap().to_string(), "127.0.0.1:8765");
        assert_eq!(parse_loopback_addr("127.0.0.1:9000").unwrap().to_string(), "127.0.0.1:9000");
        assert!(parse_loopback_addr("127.0.0.1").unwrap().ip().is_loopback());
        assert_eq!(parse_loopback_addr("127.0.0.1").unwrap().port(), 8765);
        // Non-loopback is refused (no off-host exposure).
        assert!(parse_loopback_addr("8.8.8.8:80").is_err());
        assert!(parse_loopback_addr("definitely not an address").is_err());
    }

    #[test]
    fn responses_are_single_line_json() {
        // Every serialized response must be one line (no bare newlines) for stdio framing.
        let r = result_response(&json!(1), json!({ "deep": { "nested": [1, 2] } }));
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains('\n'));
    }
}
