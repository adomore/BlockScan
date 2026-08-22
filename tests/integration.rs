//! End-to-end integration tests covering the networked code paths
//! (RPC + Etherscan clients, CLI dispatch, watch loop) against mock servers.

use std::path::Path;

use alloy::primitives::{Address, B256};
use clap::Parser;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use blockscan::cli::{Cli, OutputFormat, WatchArgs};
use blockscan::config::Config;
use blockscan::enrich::Blockscout;
use blockscan::etherscan::EtherscanClient;
use blockscan::rpc::RpcClient;
use blockscan::scanner::{RunStats, Scanner};
use blockscan::sourcify::Sourcify;
use blockscan::{poll_alert_tick, poll_tick, run, watch_alerts_with_shutdown, watch_with_shutdown, AlertCounts};

const CONTRACT_ADDR: &str = "0x000000000000000000000000000000000000c0de";
const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

/// A `WatchArgs` in download mode (no alert flags) — the original `watch` behaviour.
fn download_watch_args(confirmations: u64, poll_ms: u64) -> WatchArgs {
    WatchArgs {
        confirmations,
        poll_ms,
        alert_on_risk: false,
        alert_events: false,
        watchlist: None,
        alert_topic: Vec::new(),
        alerts: None,
        webhook_url: None,
        baseline: None,
        throttle: None,
        group: false,
        digest_interval: None,
        min_transfer: None,
    }
}

/// A `WatchArgs` in alert mode (events and/or risky deployments).
fn alert_watch_args(
    alert_events: bool,
    alert_on_risk: bool,
    alerts: Option<&Path>,
    baseline: Option<&Path>,
) -> WatchArgs {
    WatchArgs {
        confirmations: 0,
        poll_ms: 20,
        alert_on_risk,
        alert_events,
        watchlist: None,
        alert_topic: Vec::new(),
        alerts: alerts.map(Path::to_path_buf),
        webhook_url: None,
        baseline: baseline.map(Path::to_path_buf),
        throttle: None,
        group: false,
        digest_interval: None,
        min_transfer: None,
    }
}

/// Build an `AlertCtx` for direct `poll_alert_tick` tests (chain 1, no throttle/group/threshold).
#[allow(clippy::too_many_arguments)]
fn test_alert_ctx<'a>(
    sink: &'a blockscan::alert::AlertSink,
    base: &'a mut blockscan::baseline::AlertBaseline,
    throttle: &'a mut blockscan::throttle::Throttle,
    grouper: &'a mut blockscan::group::Grouper,
    watchlist: &'a Option<std::collections::HashSet<Address>>,
) -> blockscan::AlertCtx<'a> {
    blockscan::AlertCtx {
        sink,
        baseline: base,
        throttle,
        grouper,
        watchlist,
        chain: 1,
        min_transfer: None,
    }
}

// ---------- JSON-RPC mock that echoes the request id ----------

struct RpcResponder {
    result: Value,
}

impl Respond for RpcResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let id = body.get("id").cloned().unwrap_or(json!(1));
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": self.result,
        }))
    }
}

fn make_receipt(contract_address: Option<&str>) -> Value {
    let to = match contract_address {
        Some(_) => Value::Null,
        None => json!("0x0000000000000000000000000000000000001234"),
    };
    json!({
        "transactionHash": "0xe24234553f5e9f2a98b62570035ada317f7e13f18f762aab14846c758d57c276",
        "transactionIndex": "0x0",
        "blockHash": "0xbe0107d7669c9f1b62b8f5b6cae518744e7b3c44750f8e30273155b101e4363b",
        "blockNumber": "0x182e930",
        "from": "0x5875db54cd9ae2b2a875e09bb731772297ae9d92",
        "to": to,
        "cumulativeGasUsed": "0x8779",
        "gasUsed": "0x8779",
        "contractAddress": contract_address,
        "logs": [],
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "status": "0x1",
        "effectiveGasPrice": "0x9dd3251",
        "type": "0x2"
    })
}

fn make_log(address: &str, topic: &str) -> Value {
    json!({
        "address": address,
        "topics": [topic],
        "data": "0x",
        "blockHash": "0xbe0107d7669c9f1b62b8f5b6cae518744e7b3c44750f8e30273155b101e4363b",
        "blockNumber": "0x182e930",
        "transactionHash": "0xe24234553f5e9f2a98b62570035ada317f7e13f18f762aab14846c758d57c276",
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false
    })
}

async fn mount_rpc_method(server: &MockServer, rpc_method: &str, result: Value) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": rpc_method })))
        .respond_with(RpcResponder { result })
        .mount(server)
        .await;
}

/// Mount all RPC methods needed for a full scan. `code` is the getCode result.
async fn mount_rpc_full(server: &MockServer, code: &str) {
    mount_rpc_method(server, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(server, "eth_getBlockByNumber", block_body("0x64")).await;
    mount_rpc_method(server, "eth_getCode", json!(code)).await;
    mount_rpc_method(server, "eth_getBalance", json!("0x0")).await;
    mount_rpc_method(
        server,
        "eth_getBlockReceipts",
        json!([make_receipt(Some(CONTRACT_ADDR)), make_receipt(None)]),
    )
    .await;
    // Storage slots empty -> storage-proxy resolution returns None (fast path).
    mount_rpc_method(server, "eth_getStorageAt", json!(format!("0x{}", "0".repeat(64)))).await;
}

/// A 32-byte storage word holding a left-padded 20-byte address (`addr40` = 40 hex).
fn storage_word(addr40: &str) -> String {
    format!("0x{}{}", "0".repeat(24), addr40)
}

fn source_unverified_body() -> String {
    json!({
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": "",
            "ABI": "Contract source code not verified",
            "ContractName": "",
            "CompilerVersion": "",
            "OptimizationUsed": "",
            "Runs": "",
            "EVMVersion": "Default",
            "ConstructorArguments": "",
            "LicenseType": "Unknown",
            "Proxy": "0",
            "Implementation": ""
        }]
    })
    .to_string()
}

async fn mount_etherscan_unverified(server: &MockServer) {
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(source_unverified_body()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("action", "getcontractcreation"))
        .respond_with(ResponseTemplate::new(200).set_body_string(creation_ok_body()))
        .mount(server)
        .await;
}

// ---------- Etherscan mocks ----------

fn source_ok_body() -> String {
    json!({
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": "pragma solidity ^0.8.0; contract C {}",
            "ABI": "[{\"type\":\"function\",\"name\":\"foo\"}]",
            "ContractName": "C",
            "CompilerVersion": "v0.8.0+commit.abc",
            "OptimizationUsed": "1",
            "Runs": "200",
            "EVMVersion": "london",
            "ConstructorArguments": "",
            "LicenseType": "MIT",
            "Proxy": "0",
            "Implementation": ""
        }]
    })
    .to_string()
}

fn creation_ok_body() -> String {
    json!({
        "status": "1",
        "message": "OK",
        "result": [{
            "contractAddress": CONTRACT_ADDR,
            "contractCreator": "0xcreator0000000000000000000000000000beef",
            "txHash": "0xhash"
        }]
    })
    .to_string()
}

async fn mount_etherscan_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(source_ok_body()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("action", "getcontractcreation"))
        .respond_with(ResponseTemplate::new(200).set_body_string(creation_ok_body()))
        .mount(server)
        .await;
}

/// Source resolves, the creation lookup is rate limited. The contract is real
/// and must still be saved; what must not happen is `creator: null` written as
/// if the explorer had answered.
async fn mount_etherscan_creation_rate_limited(server: &MockServer) {
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(source_ok_body()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("action", "getcontractcreation"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"status":"0","message":"NOTOK","result":"Max calls per sec rate limit reached (5/sec)"}"#,
        ))
        .mount(server)
        .await;
}

/// T-05: a lookup that failed is recorded as unanswered, not as absent.
#[tokio::test]
async fn a_failed_creation_lookup_degrades_the_record() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_creation_rate_limited(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    run(
        addresses_cli(&rpc.uri(), &es.uri(), tmp.path().to_str().unwrap(), false),
        std::future::ready(()),
    )
    .await
    .unwrap();

    let v: Value = serde_json::from_str(&read_metadata(tmp.path())).unwrap();
    assert_eq!(v["incomplete"], json!(["creation"]), "the failure must be on the record");
    assert!(v["creator"].is_null(), "nothing was learned, so nothing is claimed");
}

/// The same field must stay off a record where every lookup was answered, or it
/// carries no information.
#[tokio::test]
async fn a_complete_scan_records_nothing_as_incomplete() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    run(
        addresses_cli(&rpc.uri(), &es.uri(), tmp.path().to_str().unwrap(), false),
        std::future::ready(()),
    )
    .await
    .unwrap();

    let raw = read_metadata(tmp.path());
    assert!(!raw.contains("incomplete"), "an unremarkable scan must not say so: {raw}");
}

/// Verified-source body whose Solidity uses `tx.origin` (a source-level finding).
fn source_txorigin_body() -> String {
    json!({
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": "pragma solidity ^0.8.0;\ncontract C {\n  function f() public view returns (bool) { return tx.origin == msg.sender; }\n}",
            "ABI": "[{\"type\":\"function\",\"name\":\"f\"}]",
            "ContractName": "C",
            "CompilerVersion": "v0.8.0+commit.abc",
            "OptimizationUsed": "1",
            "Runs": "200",
            "EVMVersion": "london",
            "ConstructorArguments": "",
            "LicenseType": "MIT",
            "Proxy": "0",
            "Implementation": ""
        }]
    })
    .to_string()
}

async fn mount_etherscan_txorigin(server: &MockServer) {
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(source_txorigin_body()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("action", "getcontractcreation"))
        .respond_with(ResponseTemplate::new(200).set_body_string(creation_ok_body()))
        .mount(server)
        .await;
}

async fn mount_etherscan_error(server: &MockServer) {
    let body = json!({"status":"0","message":"NOTOK","result":"Invalid API Key"}).to_string();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(server)
        .await;
}

// ---------- helpers to build app objects ----------

fn config(rpc: &str, es: &str, out: &Path, overwrite: bool) -> Config {
    Config {
        rpc_url: rpc.into(),
        etherscan_key: "k".into(),
        etherscan_base: es.into(),
        blockscout_base: String::new(),
        blockscout_rate: 4,
        chain_id: 1,
        pin_block: None,
        out_dir: out.to_path_buf(),
        concurrency: 4,
        rate: 1000,
        overwrite,
        retries: 2,
        trace: false,
        table: false,
        sourcify: false,
        sourcify_base: String::new(),
        only_verified: false,
        min_balance_wei: 0,
        only_proxy: false,
        manifest: None,
        format: Default::default(),
        audit: false,
        min_risk: 0,
        only_vulnerable: false,
        suppressions: Default::default(),
    }
}

fn scanner(cfg: Config) -> Scanner {
    let rpc = RpcClient::new(&cfg.rpc_url, 2).unwrap();
    let es = EtherscanClient::new(&cfg.etherscan_base, &cfg.etherscan_key, cfg.chain_id, cfg.rate, 2)
        .unwrap();
    let bs = Blockscout::new(&cfg.blockscout_base, 4);
    let sf = Sourcify::new(&cfg.sourcify_base, cfg.chain_id);
    Scanner::new(std::sync::Arc::new(cfg), rpc, es, bs, sf)
}

/// Mount a Blockscout mock (address metadata + token holdings) on any address path.
async fn mount_blockscout(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/addresses/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "TestName",
            "public_tags": [{"display_name": "Test: Tag"}],
            "metadata": {"tags": [{"meta": {"website": "https://example.org"}}]}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/addresses/.+/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"value": "100000000", "token": {"symbol": "WBTC", "decimals": "8", "exchange_rate": "60000"}}
            ],
            "next_page_params": null
        })))
        .mount(server)
        .await;
}

fn addr() -> Address {
    CONTRACT_ADDR.parse().unwrap()
}

// ============================ Etherscan client ============================

#[tokio::test]
async fn etherscan_client_happy_path() {
    let server = MockServer::start().await;
    mount_etherscan_ok(&server).await;
    let es = EtherscanClient::new(&server.uri(), "k", 1, 1000, 2).unwrap();

    let src = es.get_source_code(USDC).await.unwrap();
    assert_eq!(src.contract_name, "C");
    assert!(src.source_code.contains("contract C"));

    let creation = es.get_contract_creation(USDC).await.unwrap().unwrap();
    assert_eq!(creation.tx_hash, "0xhash");
}

#[tokio::test]
async fn etherscan_retries_on_rate_limit_then_succeeds() {
    let es = MockServer::start().await;
    // First getsourcecode reply is a rate-limit (consumed once, higher priority).
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"status":"0","message":"NOTOK","result":"Max calls per sec rate limit reached (3/sec)"}"#,
        ))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&es)
        .await;
    // The retry then gets a normal verified response.
    Mock::given(method("GET"))
        .and(query_param("action", "getsourcecode"))
        .respond_with(ResponseTemplate::new(200).set_body_string(source_ok_body()))
        .mount(&es)
        .await;

    let client = EtherscanClient::new(&es.uri(), "k", 1, 1000, 3).unwrap();
    let src = client.get_source_code(USDC).await.unwrap();
    assert_eq!(src.contract_name, "C");
}

#[tokio::test]
async fn etherscan_client_transport_error_retries_then_fails() {
    // Nothing listening -> get_json exhausts retries and returns Http error.
    let es = EtherscanClient::new("http://127.0.0.1:1", "k", 1, 1000, 2).unwrap();
    assert!(es.get_source_code(USDC).await.is_err());
}

// ============================ RPC client ============================

#[tokio::test]
async fn rpc_client_happy_path() {
    let server = MockServer::start().await;
    mount_rpc_full(&server, "0x6080604052").await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();

    assert_eq!(rpc.block_number().await.unwrap(), 100);
    assert!(!rpc.get_code(addr()).await.unwrap().is_empty());
    assert_eq!(rpc.get_balance(addr()).await.unwrap().to_string(), "0");

    let created = rpc.contract_creations_in_block(25_356_560).await.unwrap();
    assert_eq!(created.len(), 1);
    assert_eq!(format!("{:#x}", created[0]), CONTRACT_ADDR);
}

#[tokio::test]
async fn rpc_null_receipts_yields_empty() {
    let server = MockServer::start().await;
    mount_rpc_method(&server, "eth_getBlockReceipts", json!(null)).await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    assert!(rpc
        .contract_creations_in_block(1)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn rpc_client_all_methods_error_on_dead_endpoint() {
    let rpc = RpcClient::new("http://127.0.0.1:1", 2).unwrap();
    assert!(rpc.block_number().await.is_err());
    assert!(rpc.get_code(addr()).await.is_err());
    assert!(rpc.get_balance(addr()).await.is_err());
    assert!(rpc.contract_creations_in_block(1).await.is_err());
}

// ============================ run(): addresses ============================

fn addresses_cli(rpc: &str, es: &str, out: &str, overwrite: bool) -> Cli {
    let mut args = vec![
        "blockscan",
        "addresses",
        USDC,
        "--rpc-url",
        rpc,
        "--etherscan-key",
        "k",
        "--etherscan-base",
        es,
        "--rate",
        "1000",
        "-o",
        out,
    ];
    if overwrite {
        args.push("--overwrite");
    }
    Cli::parse_from(args)
}

// ---------------------------------------------------------------------------
// T-04 — every state read answers from one block
// ---------------------------------------------------------------------------

/// Hash the mock chain reports for whichever block is asked about.
const PIN_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
/// What a read at `latest` gets. Nothing in a pinned scan may ever see it.
const LATEST_SENTINEL: &str = "0xdeadbeef";

/// A chain that moves under the scan.
///
/// `eth_blockNumber` reports a new head on every call, and `eth_getCode` /
/// `eth_getBalance` answer differently per block, so a scan that reads at
/// `latest` records whichever moment each individual read happened to land on.
/// That is the condition T-04 removes, and it has to be present for a
/// reproducibility test to mean anything.
struct MovingChain {
    head: std::sync::atomic::AtomicU64,
}

impl MovingChain {
    fn from(head: u64) -> Self {
        Self { head: std::sync::atomic::AtomicU64::new(head) }
    }
}

/// A block body complete enough for alloy to deserialize a header from.
fn block_body(number_hex: &str) -> Value {
    let h32 = format!("0x{}", "0".repeat(64));
    json!({
        "hash": PIN_HASH,
        "parentHash": h32,
        "sha3Uncles": h32,
        "miner": format!("0x{}", "0".repeat(40)),
        "stateRoot": h32,
        "transactionsRoot": h32,
        "receiptsRoot": h32,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "difficulty": "0x0",
        "number": number_hex,
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "extraData": "0x",
        "mixHash": h32,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x0",
        "size": "0x0",
        "totalDifficulty": "0x0",
        "uncles": [],
        "transactions": []
    })
}

impl Respond for MovingChain {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        use std::sync::atomic::Ordering;
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let id = body.get("id").cloned().unwrap_or(json!(1));
        let m = body.get("method").and_then(Value::as_str).unwrap_or("");
        let params = body.get("params").and_then(Value::as_array).cloned().unwrap_or_default();
        // The block identifier on a state read is the trailing positional arg.
        let at = params.last().and_then(Value::as_str).unwrap_or("").to_string();
        let result = match m {
            "eth_blockNumber" => json!(format!("{:#x}", self.head.fetch_add(1, Ordering::SeqCst))),
            "eth_getBlockByNumber" => {
                block_body(params.first().and_then(Value::as_str).unwrap_or("0x0"))
            }
            "eth_getCode" | "eth_getBalance" if at == "latest" => json!(LATEST_SENTINEL),
            "eth_getCode" => json!(format!("0x6080{}", at.trim_start_matches("0x"))),
            "eth_getBalance" => json!(at),
            "eth_getStorageAt" => json!(format!("0x{}", "0".repeat(64))),
            "eth_getBlockReceipts" => json!([make_receipt(Some(CONTRACT_ADDR)), make_receipt(None)]),
            _ => Value::Null,
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": id, "result": result,
        }))
    }
}

/// `addresses` against a moving chain, optionally pinned with `--at-block`.
fn pinned_cli(rpc: &str, es: &str, out: &str, at: Option<&str>) -> Cli {
    let mut args = vec![
        "blockscan", "addresses", USDC,
        "--rpc-url", rpc,
        "--etherscan-key", "k",
        "--etherscan-base", es,
        "--rate", "1000",
        "-o", out,
    ];
    if let Some(block) = at {
        args.push("--at-block");
        args.push(block);
    }
    Cli::parse_from(args)
}

fn read_metadata(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(USDC.to_lowercase()).join("metadata.json"))
        .expect("metadata.json")
}

/// The acceptance criterion: two scans at the same pinned block agree byte for
/// byte. `ContractDetails` carries no timestamp, so the comparison is the whole
/// file with nothing excluded.
#[tokio::test]
async fn two_scans_at_the_same_pin_produce_identical_metadata() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    Mock::given(method("POST")).respond_with(MovingChain::from(100)).mount(&rpc).await;
    mount_etherscan_ok(&es).await;

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for dir in [a.path(), b.path()] {
        run(
            pinned_cli(&rpc.uri(), &es.uri(), dir.to_str().unwrap(), Some("4096")),
            std::future::ready(()),
        )
        .await
        .unwrap();
    }

    let first = read_metadata(a.path());
    assert_eq!(first, read_metadata(b.path()), "same pin, different bytes");

    let v: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(v["block_number"], json!(4096), "the pin must be recorded");
    assert_eq!(v["block_hash"], json!(PIN_HASH), "the height alone is not identifying");
    // 4096 == 0x1000, so a read routed through the pin returns 0x6080 + "1000".
    assert_eq!(v["bytecode"], json!("0x60801000"), "getCode did not use the pin");
    assert_eq!(v["balance_wei"], json!("4096"), "getBalance did not use the pin");
    assert!(
        !first.contains(LATEST_SENTINEL),
        "a state read fell through to `latest`: {first}"
    );
}

/// Without `--at-block` the head is resolved once, at scan start. The mock hands
/// out a new head on every `eth_blockNumber`, so a second resolution anywhere in
/// the run would show up as a different recorded block.
#[tokio::test]
async fn an_unpinned_scan_resolves_the_head_exactly_once() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    Mock::given(method("POST")).respond_with(MovingChain::from(0x2000)).mount(&rpc).await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    run(
        pinned_cli(&rpc.uri(), &es.uri(), tmp.path().to_str().unwrap(), None),
        std::future::ready(()),
    )
    .await
    .unwrap();

    let raw = read_metadata(tmp.path());
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["block_number"], json!(0x2000), "the head moved mid-scan");
    assert_eq!(v["bytecode"], json!("0x60802000"));
    assert!(!raw.contains(LATEST_SENTINEL), "an unpinned scan still read at `latest`");
}

#[tokio::test]
async fn run_addresses_saves_skips_and_overwrites() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let meta = tmp
        .path()
        .join(USDC.to_lowercase())
        .join("metadata.json");

    // First run: saves.
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, false),
        std::future::ready(()),
    )
    .await
    .unwrap();
    assert!(meta.exists());
    assert!(tmp
        .path()
        .join(USDC.to_lowercase())
        .join("source")
        .exists());

    // Second run: already saved -> skipped (no error).
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, false),
        std::future::ready(()),
    )
    .await
    .unwrap();

    // Third run: overwrite -> re-saves.
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, true),
        std::future::ready(()),
    )
    .await
    .unwrap();
    assert!(meta.exists());
}

#[tokio::test]
async fn run_addresses_with_table_output() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan",
        "addresses",
        USDC,
        "--table",
        "--blockscout-base",
        "",
        "--rpc-url",
        &rpc.uri(),
        "--etherscan-key",
        "k",
        "--etherscan-base",
        &es.uri(),
        "--rate",
        "1000",
        "-o",
        out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp
        .path()
        .join(USDC.to_lowercase())
        .join("metadata.json")
        .exists());
}

#[tokio::test]
async fn run_addresses_table_shows_on_skip() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let ru = rpc.uri();
    let eu = es.uri();
    let make = || {
        Cli::parse_from([
            "blockscan",
            "addresses",
            USDC,
            "--table",
            "--blockscout-base",
            "",
            "--rpc-url",
            ru.as_str(),
            "--etherscan-key",
            "k",
            "--etherscan-base",
            eu.as_str(),
            "--rate",
            "1000",
            "-o",
            out,
        ])
    };
    run(make(), std::future::ready(())).await.unwrap(); // first run saves
    run(make(), std::future::ready(())).await.unwrap(); // skipped -> loads metadata + prints table
    assert!(tmp
        .path()
        .join(USDC.to_lowercase())
        .join("metadata.json")
        .exists());
}

#[tokio::test]
async fn run_addresses_table_skip_with_unreadable_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // Pre-seed an existing but corrupt metadata.json: the skip path tries to load
    // it, fails, and falls back to Skipped(None) without crashing.
    let dir = tmp.path().join(USDC.to_lowercase());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("metadata.json"), "not json").unwrap();

    let cli = Cli::parse_from([
        "blockscan",
        "addresses",
        USDC,
        "--table",
        "--blockscout-base",
        "",
        "--rpc-url",
        "http://127.0.0.1:1",
        "--etherscan-key",
        "k",
        "-o",
        out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
}

#[tokio::test]
async fn run_addresses_table_enriched_via_blockscout() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let bs = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    mount_blockscout(&bs).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan",
        "addresses",
        USDC,
        "--table",
        "--blockscout-base",
        &bs.uri(),
        "--rpc-url",
        &rpc.uri(),
        "--etherscan-key",
        "k",
        "--etherscan-base",
        &es.uri(),
        "--rate",
        "1000",
        "-o",
        out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp
        .path()
        .join(USDC.to_lowercase())
        .join("metadata.json")
        .exists());
}

#[tokio::test]
async fn blockscout_fetch_parses_enrichment() {
    let bs = MockServer::start().await;
    mount_blockscout(&bs).await;
    let client = Blockscout::new(&bs.uri(), 100);
    let e = client.fetch(CONTRACT_ADDR).await;
    assert_eq!(e.name_tag.as_deref(), Some("Test: Tag"));
    assert_eq!(e.project_url.as_deref(), Some("https://example.org"));
    assert!(e.holdings.unwrap().contains("WBTC"));
}

#[tokio::test]
async fn blockscout_caches_per_address() {
    // Each mock answers at most once; a second fetch must come from the cache.
    let bs = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/addresses/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "Cached"})))
        .up_to_n_times(1)
        .mount(&bs)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/addresses/.+/tokens"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
        .up_to_n_times(1)
        .mount(&bs)
        .await;

    let client = Blockscout::new(&bs.uri(), 100);
    let first = client.fetch(CONTRACT_ADDR).await;
    assert_eq!(first.name_tag.as_deref(), Some("Cached"));
    // Mocks are exhausted; only the cache can satisfy this and keep the name tag.
    let second = client.fetch(CONTRACT_ADDR).await;
    assert_eq!(second.name_tag.as_deref(), Some("Cached"));
}

#[tokio::test]
async fn run_addresses_not_a_contract() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x").await; // empty code
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, false),
        std::future::ready(()),
    )
    .await
    .unwrap();
    assert!(!tmp.path().join(USDC.to_lowercase()).exists());
}

#[tokio::test]
async fn run_addresses_etherscan_failure_is_reported_not_fatal() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_error(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // Etherscan errors -> the address fails, but run() still completes Ok.
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, false),
        std::future::ready(()),
    )
    .await
    .unwrap();
    assert!(!tmp
        .path()
        .join(USDC.to_lowercase())
        .join("metadata.json")
        .exists());
}

// ============================ run(): range ============================

#[tokio::test]
async fn run_range_discovers_and_saves() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan",
        "range",
        "--from",
        "100",
        "--to",
        "100",
        "--rpc-url",
        &rpc.uri(),
        "--etherscan-key",
        "k",
        "--etherscan-base",
        &es.uri(),
        "--rate",
        "1000",
        "-o",
        out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp
        .path()
        .join(CONTRACT_ADDR)
        .join("metadata.json")
        .exists());
}

#[tokio::test]
async fn run_range_empty_block_saves_nothing() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc, "eth_getBlockReceipts", json!([])).await; // no creations
    // The scan pins state reads to a block, so the chain needs a head.
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getBlockByNumber", block_body("0x64")).await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan",
        "range",
        "--from",
        "100",
        "--to",
        "100",
        "--rpc-url",
        &rpc.uri(),
        "--etherscan-key",
        "k",
        "--etherscan-base",
        &es.uri(),
        "--rate",
        "1000",
        "-o",
        out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let count = std::fs::read_dir(tmp.path()).map(|d| d.count()).unwrap_or(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn run_addresses_save_error_is_reported() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    // Point output at a *file* so create_dir_all under it fails -> save error path.
    let out_file = tmp.path().join("not_a_dir");
    std::fs::write(&out_file, "x").unwrap();
    let out = out_file.to_str().unwrap();
    // Save fails per-address, but run() still completes Ok (reported as failed).
    run(
        addresses_cli(&rpc.uri(), &es.uri(), out, false),
        std::future::ready(()),
    )
    .await
    .unwrap();
    // The save genuinely failed: the output *file* is intact (nothing written over
    // it) and no per-contract dir/metadata was produced — i.e. the error path was
    // taken, not a silent success.
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "x");
    assert!(!tmp.path().join(USDC.to_lowercase()).join("metadata.json").exists());
}

// ============================ trace_block (factory discovery) ============================

const FACTORY_CHILD: &str = "0x0000000000000000000000000000000000facade";

fn range_trace_cli(rpc: &str, es: &str, out: &str) -> Cli {
    Cli::parse_from([
        "blockscan",
        "range",
        "--from",
        "100",
        "--to",
        "100",
        "--trace",
        "--rpc-url",
        rpc,
        "--etherscan-key",
        "k",
        "--etherscan-base",
        es,
        "--rate",
        "1000",
        "-o",
        out,
    ])
}

#[tokio::test]
async fn rpc_trace_creations_via_mock() {
    let server = MockServer::start().await;
    mount_rpc_method(
        &server,
        "trace_block",
        json!([
            { "type": "create", "result": { "address": CONTRACT_ADDR } },
            { "type": "call",   "result": { "address": FACTORY_CHILD } }
        ]),
    )
    .await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    let created = rpc.trace_creations_in_block(100).await.unwrap();
    assert_eq!(created.len(), 1); // only the "create" entry
}

#[tokio::test]
async fn run_range_with_trace_merges_and_dedups() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await; // receipts yield CONTRACT_ADDR
    // trace yields the same top-level contract (dup) plus a factory child.
    mount_rpc_method(
        &rpc,
        "trace_block",
        json!([
            { "type": "create", "result": { "address": CONTRACT_ADDR } },
            { "type": "create", "result": { "address": FACTORY_CHILD } }
        ]),
    )
    .await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    run(range_trace_cli(&rpc.uri(), &es.uri(), out), std::future::ready(()))
        .await
        .unwrap();

    // Both unique contracts saved exactly once (CONTRACT_ADDR deduped).
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
    assert!(tmp.path().join(FACTORY_CHILD).join("metadata.json").exists());
}

#[tokio::test]
async fn run_range_trace_failure_is_non_fatal() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    // trace_block unsupported / failing -> 500.
    Mock::given(method("POST"))
        .and(body_partial_json(json!({ "method": "trace_block" })))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rpc)
        .await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // Trace fails but receipt-based discovery still saves the top-level contract.
    run(range_trace_cli(&rpc.uri(), &es.uri(), out), std::future::ready(()))
        .await
        .unwrap();
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
}

// ============================ poll_tick / watch ============================

#[tokio::test]
async fn poll_tick_processes_confirmed_blocks() {
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc_server, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();

    let mut next = 100u64; // head=100, confirmations=0 -> process block 100
    let mut total = RunStats::default();
    poll_tick(&rpc, &s, &mut next, 0, false, &mut total, &mut Vec::new()).await;
    assert_eq!(next, 101);
    assert!(total.saved >= 1);
}

#[tokio::test]
async fn poll_tick_swallows_head_error() {
    let es = MockServer::start().await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config("http://127.0.0.1:1", &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new("http://127.0.0.1:1", 2).unwrap();

    let mut next = 5u64;
    let mut total = RunStats::default();
    poll_tick(&rpc, &s, &mut next, 0, false, &mut total, &mut Vec::new()).await;
    assert_eq!(next, 5); // unchanged: head fetch failed
}

#[tokio::test]
async fn poll_tick_breaks_on_block_error() {
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    // block_number ok, but receipts fail -> process_block errors -> break.
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"eth_getBlockReceipts"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rpc_server)
        .await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();

    let mut next = 100u64;
    let mut total = RunStats::default();
    poll_tick(&rpc, &s, &mut next, 0, false, &mut total, &mut Vec::new()).await;
    assert_eq!(next, 100); // did not advance: block processing failed
}

#[tokio::test]
async fn watch_runs_until_shutdown() {
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc_server, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();

    let args = download_watch_args(0, 30);
    let shutdown = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    };
    watch_with_shutdown(&rpc, &s, args, false, OutputFormat::Human, shutdown).await.unwrap();
}

#[tokio::test]
async fn run_watch_arm_stops_on_shutdown() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan",
        "watch",
        "--confirmations",
        "0",
        "--poll-ms",
        "20",
        "--rpc-url",
        &rpc.uri(),
        "--etherscan-key",
        "k",
        "--etherscan-base",
        &es.uri(),
        "--rate",
        "1000",
        "-o",
        out,
    ]);
    let shutdown = async {
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    };
    run(cli, shutdown).await.unwrap();
}

// ==================== watch alert mode (Phase 14) ====================

const UPGRADED_TOPIC: &str = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";

/// Build a scanner whose audit runs (needed for `--alert-on-risk`).
fn auditing_scanner(rpc: &str, es: &str, out: &Path) -> Scanner {
    let mut cfg = config(rpc, es, out, false);
    cfg.audit = true;
    scanner(cfg)
}

#[tokio::test]
async fn poll_alert_tick_emits_event_alert() {
    // --alert-events: a confirmed block with an Upgraded log -> one event alert.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await; // head=100
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([make_log(CONTRACT_ADDR, UPGRADED_TOPIC)])).await;

    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let args = alert_watch_args(true, false, None, None);
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(None);
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(false);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();
    let mut next = 100u64; // head=100, confirmations=0 -> process block 100

    let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 0, &mut next, 0, &mut total).await;
    assert_eq!(next, 101);
    assert_eq!(total.emitted, 1);
    assert_eq!(total.suppressed, 0);
}

#[tokio::test]
async fn poll_alert_tick_audits_risky_deployment() {
    // --alert-on-risk: a new deployment with a vulnerable source -> one risky alert.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc_server, "0x6080604052").await; // head=100, creation=CONTRACT_ADDR, getCode
    mount_etherscan_txorigin(&es).await; // source has tx.origin -> risk > 0
    let tmp = tempfile::tempdir().unwrap();
    let s = auditing_scanner(&rpc_server.uri(), &es.uri(), tmp.path());
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let args = alert_watch_args(false, true, None, None);
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(None);
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(false);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();
    let mut next = 100u64;

    let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 1, &mut next, 0, &mut total).await;
    assert_eq!(next, 101);
    assert_eq!(total.emitted, 1, "expected one risky-deployment alert");
}

#[tokio::test]
async fn poll_alert_tick_baseline_dedups_across_ticks() {
    // The same Upgraded log re-scanned on a later tick is suppressed by the baseline.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([make_log(CONTRACT_ADDR, UPGRADED_TOPIC)])).await;

    let tmp = tempfile::tempdir().unwrap();
    let base_path = tmp.path().join("seen.fp");
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let args = alert_watch_args(true, false, None, Some(&base_path));
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(args.baseline.clone());
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(false);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();

    let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
    let mut next = 100u64;
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 0, &mut next, 0, &mut total).await;
    assert_eq!(total.emitted, 1);
    // Re-scan the same block (reset next) -> baseline suppresses the duplicate.
    let mut next = 100u64;
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 0, &mut next, 0, &mut total).await;
    assert_eq!(total.emitted, 1, "no new alert on re-scan");
    assert_eq!(total.suppressed, 1);
}

#[tokio::test]
async fn watch_alerts_runs_until_shutdown() {
    // Drives the full alert-mode loop: static head means no NEW blocks, so it just
    // ticks and exits cleanly on shutdown (covers loop + summary + Ok path).
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc_server, "0x6080604052").await;
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([])).await;
    let tmp = tempfile::tempdir().unwrap();
    let s = auditing_scanner(&rpc_server.uri(), &es.uri(), tmp.path());
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let g = Cli::parse_from(["blockscan", "--rpc-url", &rpc_server.uri(), "--etherscan-key", "k", "watch"]).global;
    let args = alert_watch_args(true, true, None, None);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(80)).await; };
    let counts = watch_alerts_with_shutdown(&g, &rpc, Some(&s), args, 1, shutdown).await.unwrap();
    assert_eq!(counts.emitted, 0); // head static -> next starts past confirmed
}

#[tokio::test]
async fn run_watch_alert_events_with_min_transfer_adds_transfer_topic() {
    // watch --alert-events --min-transfer: setup must add the Transfer topic and run
    // cleanly to shutdown (covers the watch-side transfer-topic opt-in path).
    let rpc = MockServer::start().await;
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    let tmp = tempfile::tempdir().unwrap();
    std::env::remove_var("ETHERSCAN_API_KEY");
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-events", "--min-transfer", "1000",
        "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(60)).await; };
    run(cli, shutdown).await.unwrap();
}

#[tokio::test]
async fn run_watch_min_transfer_without_alert_events_warns_and_runs() {
    // --min-transfer needs --alert-events on watch; with only --alert-on-risk it's
    // ignored (warns) but the watch still runs cleanly to shutdown.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-on-risk", "--min-transfer", "1000",
        "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(60)).await; };
    run(cli, shutdown).await.unwrap();
}

#[tokio::test]
async fn run_watch_group_with_throttle_warns_and_runs() {
    // watch --alert-events --group --throttle: throttle ignored in group mode (warns),
    // still runs to shutdown (covers the watch-side group/throttle warn).
    let rpc = MockServer::start().await;
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    let tmp = tempfile::tempdir().unwrap();
    std::env::remove_var("ETHERSCAN_API_KEY");
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-events", "--group", "--throttle", "3",
        "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(60)).await; };
    run(cli, shutdown).await.unwrap();
}

#[tokio::test]
async fn run_watch_alert_arm_rejects_no_audit() {
    // watch --alert-on-risk + --no-audit is contradictory and must error.
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-on-risk", "--no-audit",
        "--rpc-url", "http://127.0.0.1:1", "--etherscan-key", "k",
    ]);
    assert!(run(cli, std::future::ready(())).await.is_err());
}

#[tokio::test]
async fn run_watch_alert_arm_stops_on_shutdown() {
    // run()'s watch arm dispatches to alert mode and exits on shutdown.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-events", "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(80)).await; };
    run(cli, shutdown).await.unwrap();
}

#[tokio::test]
async fn run_watch_alert_on_risk_stops_on_shutdown() {
    // run()'s watch arm dispatches the RISK branch (full scanner) and exits on shutdown.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-on-risk", "--min-risk", "50",
        "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(80)).await; };
    run(cli, shutdown).await.unwrap();
}

#[tokio::test]
async fn poll_alert_tick_risk_incomplete_on_receipts_failure() {
    // Regression: a failed eth_getBlockReceipts (creations lookup) must mark the tick
    // incomplete and NOT advance `next` — otherwise that block's deployments are lost.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"eth_getBlockReceipts"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rpc_server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let s = auditing_scanner(&rpc_server.uri(), &es.uri(), tmp.path());
    let rpc = RpcClient::new(&rpc_server.uri(), 1).unwrap();
    let args = alert_watch_args(false, true, None, None);
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(None);
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(false);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();
    let mut next = 100u64;

    let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 1, &mut next, 0, &mut total).await;
    assert_eq!(next, 100, "must not advance when a block's receipts failed");
    assert!(total.incomplete);
}

#[tokio::test]
async fn poll_alert_tick_does_not_advance_on_partial_log_fetch() {
    // Regression (review HIGH): a failing eth_getLogs window must NOT advance `next`
    // — otherwise that block's events are skipped forever. block_number succeeds but
    // getLogs always errors, so the range is left to retry.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await; // head=100
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"eth_getLogs"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rpc_server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 1).unwrap();
    let args = alert_watch_args(true, false, None, None);
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(None);
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(false);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();
    let mut next = 100u64;

    let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
    poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 0, &mut next, 0, &mut total).await;
    assert_eq!(next, 100, "must not advance past a partially-scanned range");
    assert_eq!(total.emitted, 0);
    assert!(total.incomplete);
}

#[tokio::test]
async fn watch_alert_events_needs_no_etherscan_key() {
    // Event-only watch (--alert-events, no --alert-on-risk) uses only eth_getLogs,
    // so it must run with NO Etherscan key (parity with `monitor`).
    let rpc = MockServer::start().await;
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    let tmp = tempfile::tempdir().unwrap();
    std::env::remove_var("ETHERSCAN_API_KEY");
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-events", "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc.uri(), "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(60)).await; };
    run(cli, shutdown).await.unwrap(); // no key -> still Ok
}

// ============================ MCP server (Phase 16) ============================

#[tokio::test]
async fn mcp_scan_addresses_tool_scans_over_wiremock() {
    // The online MCP tool wraps the scanner: feed a tools/call with wiremock RPC +
    // Etherscan and assert it returns the run-scoped {stats, contracts}.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "scan_addresses", "arguments": {
            "addresses": [USDC],
            "rpc_url": rpc.uri(),
            "etherscan_key": "k",
            "etherscan_base": es.uri(),
            "out": tmp.path().to_str().unwrap(),
        }}
    });
    let ctx = blockscan::mcp::ServerCtx::new(tmp.path().to_path_buf());
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["isError"], false, "resp: {r}");
    let sc = &r["result"]["structuredContent"];
    assert!(sc["stats"]["saved"].as_u64().unwrap() >= 1, "stats: {sc}");
    assert_eq!(sc["contracts"][0]["address"], USDC.to_lowercase());
    // The audited contract carries an audit block (default audit on).
    assert!(sc["contracts"][0]["audit"]["grade"].is_string());
}

#[tokio::test]
async fn mcp_scan_block_range_tool_over_wiremock() {
    // scan_block_range: bounded block-range scan returns {stats, contracts}.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await; // block has a creation (CONTRACT_ADDR)
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "scan_block_range", "arguments": {
            "from": 1, "to": 1, "rpc_url": rpc.uri(), "etherscan_key": "k",
            "etherscan_base": es.uri(), "out": tmp.path().to_str().unwrap(),
        }}
    });
    let ctx = blockscan::mcp::ServerCtx::new(tmp.path().to_path_buf());
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["isError"], false, "resp: {r}");
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["from"], 1);
    assert!(sc["stats"]["saved"].as_u64().unwrap() >= 1, "stats: {sc}");
}

#[tokio::test]
async fn mcp_monitor_range_tool_collects_alerts_over_wiremock() {
    // monitor_range: decode events in a bounded range and RETURN them (collected,
    // never streamed to stdout).
    let rpc = MockServer::start().await;
    let topic_own = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let own = json!({"address":"0x000000000000000000000000000000000000beef","topics":[topic_own, word("a"), word("b")],"data":"0x","blockHash":h32,"blockNumber":"0x2","transactionHash":h32,"transactionIndex":"0x0","logIndex":"0x0","removed":false});
    Mock::given(method("POST")).respond_with(LogsEcho(json!([own]))).mount(&rpc).await;
    let tmp = tempfile::tempdir().unwrap();
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "monitor_range", "arguments": {
            "from": 1, "to": 2, "rpc_url": rpc.uri(),
        }}
    });
    let ctx = blockscan::mcp::ServerCtx {
        out: tmp.path().to_path_buf(),
        // T-03: the endpoint is permitted at launch, not chosen per request.
        rpc_allow: vec![rpc.uri()],
    };
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["isError"], false, "resp: {r}");
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["counts"]["emitted"], 1);
    assert_eq!(sc["alerts"][0]["event"], "OwnershipTransferred");
    assert_eq!(sc["alerts"][0]["kind"], "ownership");
}

#[tokio::test]
async fn mcp_scan_block_range_reports_block_error() {
    // A failing eth_getBlockReceipts during the range scan -> tool error (isError).
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"eth_getBlockReceipts"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&rpc)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let call = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "scan_block_range", "arguments": {
            "from": 1, "to": 1, "rpc_url": rpc.uri(), "etherscan_key": "k", "etherscan_base": es.uri(),
            "out": tmp.path().to_str().unwrap(),
        }}
    });
    let ctx = blockscan::mcp::ServerCtx::new(tmp.path().to_path_buf());
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["isError"], true, "resp: {r}");
}

#[tokio::test]
async fn mcp_monitor_range_min_transfer_and_watchlist() {
    // monitor_range with --min-transfer adds the Transfer topic and filters by value;
    // a non-matching watchlist drops everything.
    let rpc = MockServer::start().await;
    let transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let beef = "0x000000000000000000000000000000000000beef";
    let tx = |value: u64| json!({
        "address": beef, "topics": [transfer, word("a"), word("b")],
        "data": format!("0x{value:064x}"), "blockHash": h32, "blockNumber": "0x1",
        "transactionHash": h32, "transactionIndex": "0x0", "logIndex": "0x0", "removed": false
    });
    Mock::given(method("POST")).respond_with(LogsEcho(json!([tx(500), tx(2000)]))).mount(&rpc).await;
    let tmp = tempfile::tempdir().unwrap();
    let ctx = blockscan::mcp::ServerCtx {
        out: tmp.path().to_path_buf(),
        // T-03: the endpoint is permitted at launch, not chosen per request.
        rpc_allow: vec![rpc.uri()],
    };

    // min_transfer 1000 -> only the 2000-value transfer survives.
    let call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"monitor_range","arguments":{
        "from":1,"to":1,"rpc_url":rpc.uri(),"min_transfer":"1000"}}});
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["counts"]["emitted"], 1, "resp: {r}");
    assert_eq!(sc["alerts"][0]["kind"], "large-transfer");
    assert_eq!(sc["alerts"][0]["amount"], "2000");

    // A watchlist that DOES include 0x..beef -> the large transfer is kept.
    let call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"monitor_range","arguments":{
        "from":1,"to":1,"rpc_url":rpc.uri(),"min_transfer":"1000","watchlist":[beef]}}});
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["structuredContent"]["counts"]["emitted"], 1);

    // A watchlist that does NOT include 0x..beef -> nothing.
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"monitor_range","arguments":{
        "from":1,"to":1,"rpc_url":rpc.uri(),"min_transfer":"1000",
        "watchlist":["0x000000000000000000000000000000000000dead"]}}});
    let r = blockscan::mcp::handle(&ctx, &call).await.unwrap();
    assert_eq!(r["result"]["structuredContent"]["counts"]["emitted"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_mcp_http_serves_over_loopback() {
    // Drive the real binary's `mcp --http` over a loopback socket: POST an initialize
    // and assert a 200 JSON-RPC response (proves bind/accept/dispatch end-to-end).
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let tmp = tempfile::tempdir().unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
        .args([
            "mcp",
            "--http",
            &format!("127.0.0.1:{port}"),
            "--http-token",
            "bin-token",
            "-o",
            tmp.path().to_str().unwrap(),
        ])
        .env_remove("ETHERSCAN_API_KEY")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let addr = format!("127.0.0.1:{port}");
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::TcpStream::connect(&addr).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    let result: Result<serde_json::Value, String> = async {
        let mut stream = stream.ok_or("server never bound")?;
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bin-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.map_err(|e| e.to_string())?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected status: {resp}"));
        }
        let start = resp.find("\r\n\r\n").ok_or("no body")? + 4;
        serde_json::from_str(resp[start..].trim()).map_err(|e| e.to_string())
    }
    .await;
    let _ = child.kill();
    let _ = child.wait();
    let v = result.unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "blockscan");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_http_in_process_dispatches_and_covers_accept_loop() {
    // Run the accept loop IN-PROCESS (tokio task) so coverage counts the accept/
    // dispatch path; abort the task when done (instead of Ctrl-C).
    //
    // Bind the listener HERE and read the real port from the *live* listener, then
    // hand the bound listener to the server. This removes the bind→close→rebind
    // window where a concurrent test could steal the ephemeral port (the old flake),
    // and the socket is already in LISTEN state before we connect — connections
    // queue in the accept backlog, so connect() succeeds regardless of whether the
    // accept loop has reached accept() yet.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_path_buf();
    let handle = tokio::spawn(async move {
        // Since T-02 the HTTP surface always has a credential; give it a known
        // one rather than letting it mint one this test cannot read off stderr.
        let _ = blockscan::mcp::serve_http_on(listener, out, Some("it-token".to_string())).await;
    });
    let addr = format!("127.0.0.1:{port}");
    // The listener is already bound+listening, so connect should succeed on the
    // first iteration; the short backoff is belt-and-suspenders for scheduler jitter.
    let mut stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::TcpStream::connect(&addr).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut stream = stream.expect("in-process server should accept");
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer it-token\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "resp: {resp}");
    assert!(resp.contains("\"result\":{}"), "ping result: {resp}");

    // Regression (review HIGH): an oversize streaming body is rejected with 413,
    // not buffered unbounded (Limited stops the read at the cap).
    let mut s2 = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let big = 2 * 1024 * 1024; // > MAX_HTTP_BODY (1 MiB)
    let head = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer it-token\r\nContent-Length: {big}\r\nConnection: close\r\n\r\n"
    );
    s2.write_all(head.as_bytes()).await.unwrap();
    let _ = s2.write_all(&vec![b'x'; big]).await; // server may close early -> ignore write error
    let mut resp2 = String::new();
    let _ = s2.read_to_string(&mut resp2).await;
    handle.abort();
    assert!(resp2.starts_with("HTTP/1.1 413"), "oversize body must be 413: {resp2:?}");
}

#[tokio::test]
async fn serve_http_wrapper_rejects_bad_and_busy_addrs() {
    // Covers serve_http's thin parse+bind wrapper in-process and deterministically
    // (no socket traffic, no timing). The accept/dispatch loop is covered by
    // serve_http_in_process_* via serve_http_on; serve_http's success delegation +
    // the full --http path are covered by the `mcp --http` subprocess e2e (llvm-cov
    // can't attribute subprocess coverage on this machine — see build-env notes).
    let tmp = tempfile::tempdir().unwrap();

    // (1) Non-loopback addr -> refused by parse_loopback_addr; never reaches bind.
    let r = blockscan::mcp::serve_http(tmp.path().to_path_buf(), "8.8.8.8:80", None, Vec::new()).await;
    assert!(r.is_err(), "non-loopback addr must be refused by serve_http");

    // (2) Loopback addr whose port is already held -> the bind() inside serve_http
    // errors out. Guarded by a timeout so the test can't hang even if some platform
    // allowed the re-bind; the asserted contract is only that it never returns Ok.
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let busy = format!("127.0.0.1:{}", occupied.local_addr().unwrap().port());
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        blockscan::mcp::serve_http(tmp.path().to_path_buf(), &busy, None, Vec::new()),
    )
    .await;
    assert!(!matches!(r, Ok(Ok(()))), "serve_http on an in-use port must not succeed: {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_mcp_subcommand_serves_initialize_over_stdio() {
    // Drive the real binary's `mcp` subcommand: pipe an initialize + tools/list on
    // stdin, assert clean JSON-RPC on stdout (proves stdout stays pure, EOF exits).
    use std::io::Write;
    use std::process::{Command, Stdio};
    let out = tokio::task::spawn_blocking(|| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.as_mut().unwrap();
        stdin
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n")
            .unwrap();
        // Dropping stdin closes it -> server sees EOF and exits.
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "stdout: {stdout}");
    let init: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "blockscan");
    let list: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert!(list["result"]["tools"].as_array().unwrap().len() >= 6);
}

// ============================ binary entrypoint ============================

#[test]
fn binary_reports_error_and_exits_nonzero() {
    // Drives main(): parse args, init tracing, run() -> validate error -> exit(1).
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
        .args(["addresses", "0xabc", "--rpc-url", "http://r"]) // missing etherscan key
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error:"), "{stderr}");
}

// In-process run() with the machine formats — exercises scanner's ndjson branch
// and lib's json emit path deterministically (independent of child-process
// coverage merge). stdout goes to the captured test harness.
#[tokio::test]
async fn run_addresses_ndjson_in_process() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "--format", "ndjson", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(USDC.to_lowercase()).join("metadata.json").exists());
}

#[tokio::test]
async fn run_addresses_json_in_process() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    // --table together with --format json: table is ignored (warned), json wins.
    let cli = Cli::parse_from([
        "blockscan", "--format", "json", "--table", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(USDC.to_lowercase()).join("metadata.json").exists());
}

// ============================ audit ============================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_audit_subcommand_reaudits_corpus_offline() {
    // Populate a corpus by scanning, then re-audit it OFFLINE via the `audit`
    // subcommand (no RPC/Etherscan key needed).
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();

    let out_s = out.to_str().unwrap().to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .env_remove("ETHERSCAN_API_KEY") // offline: no key required
            .args(["audit", "--format", "json", "--by-risk", "-o", &out_s])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    assert!(doc["audited"].as_u64().unwrap() >= 1);
    assert!(doc["vulnerable"].as_u64().is_some());
    assert!(doc["contracts"][0]["audit"]["grade"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_audit_sarif_output_is_valid() {
    // Re-audit a corpus and emit SARIF 2.1.0 (GitHub Code Scanning format).
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_txorigin(&es).await; // a finding-producing source (tx.origin)
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();

    let out_s = out.to_str().unwrap().to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .env_remove("ETHERSCAN_API_KEY")
            .args(["audit", "--format", "sarif", "-o", &out_s])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let s: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    assert_eq!(s["version"], "2.1.0");
    assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "blockscan");
    let rules = s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
    let results = s["runs"][0]["results"].as_array().unwrap();
    assert!(!rules.is_empty() && !results.is_empty());
    // The tx-origin finding should be present as an error-level result with a SWC tag.
    let txr = results.iter().find(|r| r["ruleId"] == "TX_ORIGIN_AUTH").unwrap();
    assert_eq!(txr["level"], "error");
    assert!(txr["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string());
    let txrule = rules.iter().find(|r| r["id"] == "TX_ORIGIN_AUTH").unwrap();
    assert!(txrule["helpUri"].as_str().unwrap().contains("SWC-115"));
    assert!(txrule["properties"]["security-severity"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_audit_suppress_drops_finding_and_lowers_score() {
    // Build a tx.origin corpus, then re-audit with --suppress hiding TX_ORIGIN_AUTH:
    // the finding disappears and the contract's risk score drops.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_txorigin(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();

    let out_s = out.to_str().unwrap().to_string();
    fn audit_json(out_s: &str, extra: &[&str]) -> serde_json::Value {
        let mut args = vec!["audit", "--format", "json", "-o", out_s];
        args.extend_from_slice(extra);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .env_remove("ETHERSCAN_API_KEY")
            .args(&args)
            .output()
            .unwrap();
        assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap()
    }

    // Baseline: tx.origin finding present, score > 0.
    let base_out = out_s.clone();
    let base = tokio::task::spawn_blocking(move || audit_json(&base_out, &[])).await.unwrap();
    let base_audit = &base["contracts"][0]["audit"];
    let base_score = base_audit["risk_score"].as_u64().unwrap();
    assert!(base_score > 0);
    assert!(base_audit["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule_id"] == "TX_ORIGIN_AUTH"));

    // With --suppress: the finding is gone and the score is lower.
    let supp = tmp.path().join("suppress.json");
    std::fs::write(&supp, r#"{"suppress":[{"rule":"TX_ORIGIN_AUTH","reason":"reviewed"}]}"#).unwrap();
    let supp_s = supp.to_str().unwrap().to_string();
    let filtered =
        tokio::task::spawn_blocking(move || audit_json(&out_s, &["--suppress", &supp_s])).await.unwrap();
    let f_audit = &filtered["contracts"][0]["audit"];
    assert!(!f_audit["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule_id"] == "TX_ORIGIN_AUTH"));
    assert!(f_audit["risk_score"].as_u64().unwrap() < base_score);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_audit_finds_source_issues_in_per_chain_subdir() {
    // Regression: scanning a non-mainnet chain writes the corpus to a per-chain
    // subdir (out/optimism/<addr>/). The offline `audit` subcommand must still
    // load each contract's source from its real directory and fire SOURCE-LEVEL
    // detectors (e.g. tx-origin) — not silently skip them and report a low score.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_txorigin(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    // Scan chain 10 (optimism) -> corpus lands in out/optimism/<addr>/.
    let cli = Cli::parse_from([
        "blockscan", "--chain-id", "10", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();

    // Source really was written under the per-chain subdir.
    let src_dir = out.join("optimism").join(USDC.to_lowercase()).join("source");
    assert!(src_dir.exists(), "expected source under {}", src_dir.display());

    // Re-audit offline against the base out dir.
    let out_s = out.to_str().unwrap().to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .env_remove("ETHERSCAN_API_KEY")
            .args(["audit", "--format", "json", "-o", &out_s])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();

    assert_eq!(doc["audited"].as_u64().unwrap(), 1);
    let findings = doc["contracts"][0]["audit"]["findings"].as_array().unwrap();
    // The source-level tx-origin detector must have fired (the bug skipped it).
    // The fixture's `tx.origin == msg.sender` parses cleanly, so the AST layer
    // (Phase 14) owns this finding and tags it `ast` rather than `source`.
    let tx_origin = findings
        .iter()
        .find(|f| f["rule_id"] == "TX_ORIGIN_AUTH")
        .unwrap_or_else(|| panic!("TX_ORIGIN_AUTH finding missing; findings={findings:?}"));
    assert_eq!(tx_origin["detection"], "ast");
    assert_eq!(tx_origin["category"], "SC01:Access Control");
    assert_eq!(tx_origin["swc"], "SWC-115");
}

// ============================ monitor ============================

struct LogsEcho(serde_json::Value);
impl wiremock::Respond for LogsEcho {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let b: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(json!({}));
        let id = b.get("id").cloned().unwrap_or(json!(1));
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc":"2.0","id":id,"result": self.0}))
    }
}

#[tokio::test]
async fn run_monitor_decodes_filters_and_sinks_alerts() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await; // constructed but never called by monitor
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let topic_own = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = json!({"address":"0x000000000000000000000000000000000000c0de","topics":[topic_up, word("1")],"data":"0x","blockHash":h32,"blockNumber":"0x1","transactionHash":h32,"transactionIndex":"0x0","logIndex":"0x0","removed":false});
    let own = json!({"address":"0x000000000000000000000000000000000000beef","topics":[topic_own, word("a"), word("b")],"data":"0x","blockHash":h32,"blockNumber":"0x2","transactionHash":h32,"transactionIndex":"0x1","logIndex":"0x0","removed":false});
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([up, own])))
        .mount(&rpc)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("o");
    // (1) No watchlist -> both events decoded, sorted by block.
    let alerts1 = tmp.path().join("a1.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "2",
        "--alerts", alerts1.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let lines: Vec<String> = std::fs::read_to_string(&alerts1).unwrap().lines().map(String::from).collect();
    assert_eq!(lines.len(), 2);
    let a0: blockscan::model::Alert = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(a0.event, "Upgraded");
    assert_eq!(a0.new_value.as_deref(), Some("0x1111111111111111111111111111111111111111"));
    let a1: blockscan::model::Alert = serde_json::from_str(&lines[1]).unwrap();
    assert_eq!(a1.event, "OwnershipTransferred");
    assert_eq!(a1.previous.as_deref(), Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert_eq!(a1.new_value.as_deref(), Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

    // (2) Watchlist restricts to the 0x..beef emitter -> only the ownership event.
    let wl = tmp.path().join("watch.txt");
    std::fs::write(&wl, "# only this one\n0x000000000000000000000000000000000000beef\n").unwrap();
    let alerts2 = tmp.path().join("a2.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "2",
        "--watchlist", wl.to_str().unwrap(),
        "--alerts", alerts2.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "-o", out.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let lines: Vec<String> = std::fs::read_to_string(&alerts2).unwrap().lines().map(String::from).collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("OwnershipTransferred"));
}

#[tokio::test]
async fn run_monitor_baseline_dedups_across_runs() {
    // Same logs over the same window, run twice with a shared --baseline file:
    // run 1 emits both alerts and records their fingerprints; run 2 suppresses
    // both (0 new), and the baseline file does not grow.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let topic_own = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = json!({"address":"0x000000000000000000000000000000000000c0de","topics":[topic_up, word("1")],"data":"0x","blockHash":h32,"blockNumber":"0x1","transactionHash":h32,"transactionIndex":"0x0","logIndex":"0x0","removed":false});
    let own = json!({"address":"0x000000000000000000000000000000000000beef","topics":[topic_own, word("a"), word("b")],"data":"0x","blockHash":h32,"blockNumber":"0x2","transactionHash":h32,"transactionIndex":"0x1","logIndex":"0x0","removed":false});
    Mock::given(method("POST")).respond_with(LogsEcho(json!([up, own]))).mount(&rpc).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("o");
    let base = tmp.path().join("seen.fp");
    let mk = |alerts: &std::path::Path| {
        Cli::parse_from([
            "blockscan", "monitor", "--from", "1", "--to", "2",
            "--baseline", base.to_str().unwrap(),
            "--alerts", alerts.to_str().unwrap(),
            "--rpc-url", &rpc.uri(), "--etherscan-key", "k",
            "-o", out.to_str().unwrap(),
        ])
    };

    // Run 1: both alerts emitted, baseline now holds 2 fingerprints.
    let alerts1 = tmp.path().join("a1.jsonl");
    run(mk(&alerts1), std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_to_string(&alerts1).unwrap().lines().count(), 2);
    let base_lines = std::fs::read_to_string(&base).unwrap().lines().count();
    assert_eq!(base_lines, 2);

    // Run 2: identical window -> all suppressed. No new alerts file, baseline unchanged.
    let alerts2 = tmp.path().join("a2.jsonl");
    run(mk(&alerts2), std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_to_string(&alerts2).unwrap_or_default().lines().count(), 0);
    assert_eq!(std::fs::read_to_string(&base).unwrap().lines().count(), 2);
}

#[tokio::test]
async fn run_monitor_throttle_caps_same_contract_kind() {
    // Three DISTINCT Upgraded events from the same contract (same kind) -> with
    // --throttle 2 only 2 are emitted, the 3rd is throttled.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = |impl_hex: &str, idx: &str| json!({
        "address":"0x000000000000000000000000000000000000c0de","topics":[topic_up, word(impl_hex)],
        "data":"0x","blockHash":h32,"blockNumber":"0x1","transactionHash":h32,
        "transactionIndex":"0x0","logIndex":idx,"removed":false
    });
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([up("1", "0x0"), up("2", "0x1"), up("3", "0x2")])))
        .mount(&rpc)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--throttle", "2",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k",
        "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    // 3 distinct alerts, capped at 2 for (contract, proxy-upgrade).
    assert_eq!(std::fs::read_to_string(&alerts).unwrap().lines().count(), 2);
}

#[tokio::test]
async fn run_monitor_throttled_alert_not_lost_across_runs() {
    // Regression (review MED): a throttled-but-NEW alert must NOT be recorded in the
    // baseline, so it can fire on a later run (fresh throttle budget) instead of
    // being permanently suppressed. --throttle 1 + shared --baseline.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = |impl_hex: &str, idx: &str| json!({
        "address":"0x000000000000000000000000000000000000c0de","topics":[topic_up, word(impl_hex)],
        "data":"0x","blockHash":h32,"blockNumber":"0x1","transactionHash":h32,
        "transactionIndex":"0x0","logIndex":idx,"removed":false
    });
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([up("1", "0x0"), up("2", "0x1")])))
        .mount(&rpc)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("seen.fp");
    let out = tmp.path().join("o");
    let mk = |alerts: &std::path::Path| {
        Cli::parse_from([
            "blockscan", "monitor", "--from", "1", "--to", "1",
            "--throttle", "1", "--baseline", base.to_str().unwrap(),
            "--alerts", alerts.to_str().unwrap(),
            "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "-o", out.to_str().unwrap(),
        ])
    };

    // Run 1: A emitted (throttle budget 1), B throttled. Only A's fingerprint recorded.
    let a1 = tmp.path().join("a1.jsonl");
    run(mk(&a1), std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_to_string(&a1).unwrap().lines().count(), 1);
    assert_eq!(std::fs::read_to_string(&base).unwrap().lines().count(), 1, "only the emitted alert recorded");

    // Run 2: A is seen -> suppressed; B (never recorded) gets a fresh throttle budget
    // and fires now. The throttled alert was NOT lost.
    let a2 = tmp.path().join("a2.jsonl");
    run(mk(&a2), std::future::ready(())).await.unwrap();
    let l2: Vec<String> = std::fs::read_to_string(&a2).unwrap().lines().map(String::from).collect();
    assert_eq!(l2.len(), 1, "the previously-throttled alert fires on the next run");
    assert!(l2[0].contains("0x2222222222222222222222222222222222222222"), "it's alert B: {l2:?}");
    assert_eq!(std::fs::read_to_string(&base).unwrap().lines().count(), 2);
}

#[tokio::test]
async fn run_monitor_group_collapses_into_digest() {
    // Three distinct Upgraded events from one contract + one from another, with
    // --group: each (contract, kind) collapses to a single end-of-run digest.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = |contract: &str, impl_hex: &str, block: &str, idx: &str| json!({
        "address": contract, "topics": [topic_up, word(impl_hex)], "data": "0x",
        "blockHash": h32, "blockNumber": block, "transactionHash": h32,
        "transactionIndex": "0x0", "logIndex": idx, "removed": false
    });
    let c0de = "0x000000000000000000000000000000000000c0de";
    let beef = "0x000000000000000000000000000000000000beef";
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([
            up(c0de, "1", "0x1", "0x0"), up(c0de, "2", "0x3", "0x1"), up(c0de, "3", "0x2", "0x2"),
            up(beef, "9", "0x5", "0x0"),
        ])))
        .mount(&rpc)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "5", "--group",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k",
        "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let digests: Vec<blockscan::model::Alert> = std::fs::read_to_string(&alerts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Two groups (one per contract) -> two digests.
    assert_eq!(digests.len(), 2, "digests: {digests:?}");
    assert!(digests.iter().all(|d| d.event == "Grouped" && d.kind == "proxy-upgrade"));
    let c0de_digest = digests.iter().find(|d| d.contract == c0de).unwrap();
    assert_eq!(c0de_digest.amount.as_deref(), Some("3")); // 3 events folded
    assert_eq!(c0de_digest.block, 3); // last (max) block of the span 1..3
    assert_eq!(c0de_digest.previous.as_deref(), Some("blocks 1..3"));
    let beef_digest = digests.iter().find(|d| d.contract == beef).unwrap();
    assert_eq!(beef_digest.amount.as_deref(), Some("1"));
}

#[tokio::test]
async fn run_monitor_group_baseline_dedups_across_runs() {
    // --group + --baseline: run 1 folds the events into a digest (recording each
    // fingerprint); run 2 sees them all as duplicates -> nothing folded, no digest.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = |impl_hex: &str, idx: &str| json!({
        "address": "0x000000000000000000000000000000000000c0de", "topics": [topic_up, word(impl_hex)],
        "data": "0x", "blockHash": h32, "blockNumber": "0x1", "transactionHash": h32,
        "transactionIndex": "0x0", "logIndex": idx, "removed": false
    });
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([up("1", "0x0"), up("2", "0x1"), up("3", "0x2")])))
        .mount(&rpc)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("seen.fp");
    let out = tmp.path().join("o");
    let mk = |alerts: &std::path::Path| {
        Cli::parse_from([
            "blockscan", "monitor", "--from", "1", "--to", "1", "--group",
            "--baseline", base.to_str().unwrap(), "--alerts", alerts.to_str().unwrap(),
            "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "-o", out.to_str().unwrap(),
        ])
    };
    // Run 1: one digest folding 3 events.
    let a1 = tmp.path().join("a1.jsonl");
    run(mk(&a1), std::future::ready(())).await.unwrap();
    let d1: Vec<blockscan::model::Alert> =
        std::fs::read_to_string(&a1).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(d1.len(), 1);
    assert_eq!(d1[0].amount.as_deref(), Some("3"));
    // Run 2: all 3 fingerprints already in the baseline -> suppressed, no digest.
    let a2 = tmp.path().join("a2.jsonl");
    run(mk(&a2), std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_to_string(&a2).unwrap_or_default().lines().count(), 0);
}

#[tokio::test]
async fn run_monitor_group_supersedes_throttle() {
    // --group + --throttle: throttle is ignored (warns); all events still fold into
    // one digest rather than being capped/dropped.
    let rpc = MockServer::start().await;
    let topic_up = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let up = |impl_hex: &str, idx: &str| json!({
        "address": "0x000000000000000000000000000000000000c0de", "topics": [topic_up, word(impl_hex)],
        "data": "0x", "blockHash": h32, "blockNumber": "0x1", "transactionHash": h32,
        "transactionIndex": "0x0", "logIndex": idx, "removed": false
    });
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([up("1", "0x0"), up("2", "0x1"), up("3", "0x2")])))
        .mount(&rpc)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--group", "--throttle", "1",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let d: Vec<blockscan::model::Alert> =
        std::fs::read_to_string(&alerts).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(d.len(), 1, "throttle must not cap group folding: {d:?}");
    assert_eq!(d[0].amount.as_deref(), Some("3"));
}

#[tokio::test]
async fn poll_alert_tick_group_folds_via_watch_path() {
    // The watch/poll path routes alerts into the grouper when --group is set.
    let rpc_server = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([make_log(CONTRACT_ADDR, UPGRADED_TOPIC), make_log(CONTRACT_ADDR, UPGRADED_TOPIC)])).await;
    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config(&rpc_server.uri(), &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let mut args = alert_watch_args(true, false, None, None);
    args.group = true;
    let topics = blockscan::events::default_alert_topics();
    let sink = blockscan::alert::AlertSink::new(None, None);
    let mut base = blockscan::baseline::AlertBaseline::load(None);
    let mut throttle = blockscan::throttle::Throttle::new(None);
    let mut grouper = blockscan::group::Grouper::new(true);
    let watchlist: Option<std::collections::HashSet<Address>> = None;
    let mut total = AlertCounts::default();
    let mut next = 100u64;
    {
        let mut ctx = test_alert_ctx(&sink, &mut base, &mut throttle, &mut grouper, &watchlist);
        poll_alert_tick(&rpc, Some(&s), &args, &topics, &mut ctx, 0, &mut next, 0, &mut total).await;
    }
    assert_eq!(next, 101);
    assert_eq!(total.emitted, 0, "group mode emits nothing per-tick");
    assert_eq!(total.grouped, 2, "both events folded");
    assert_eq!(grouper.len(), 1, "one (chain,contract,event) group");
}

#[tokio::test]
async fn run_monitor_min_transfer_filters_small_keeps_large() {
    // With --min-transfer 1000, a 500-value Transfer is dropped and a 2000-value one alerts.
    let rpc = MockServer::start().await;
    let transfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let tx = |value: u64, idx: &str| json!({
        "address":"0x000000000000000000000000000000000000beef",
        "topics":[transfer, word("a"), word("b")],
        "data": format!("0x{value:064x}"),
        "blockHash":h32,"blockNumber":"0x1","transactionHash":h32,
        "transactionIndex":"0x0","logIndex":idx,"removed":false
    });
    Mock::given(method("POST"))
        .respond_with(LogsEcho(json!([tx(500, "0x0"), tx(2000, "0x1")])))
        .mount(&rpc)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--min-transfer", "1000",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k",
        "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let lines: Vec<String> = std::fs::read_to_string(&alerts).unwrap().lines().map(String::from).collect();
    assert_eq!(lines.len(), 1, "only the >=1000 transfer should alert: {lines:?}");
    let a: blockscan::model::Alert = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(a.kind, "large-transfer");
    assert_eq!(a.amount.as_deref(), Some("2000"));
}

#[tokio::test]
async fn run_monitor_audit_deployments_alerts_on_risky() {
    // monitor --audit-deployments: a new deployment with a vulnerable source
    // (tx.origin) must produce a `risky-deployment` alert carrying risk_score/grade.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await; // block has a creation (CONTRACT_ADDR) + getCode
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await; // no events
    mount_etherscan_txorigin(&es).await; // source contains tx.origin -> risk > 0
    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--audit-deployments", "--min-risk", "1",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let lines: Vec<String> = std::fs::read_to_string(&alerts).unwrap().lines().map(String::from).collect();
    let risky: Vec<blockscan::model::Alert> = lines
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|a: &blockscan::model::Alert| a.kind == "risky-deployment")
        .collect();
    assert_eq!(risky.len(), 1, "expected one risky-deployment alert: {lines:?}");
    assert_eq!(risky[0].event, "RiskyDeployment");
    assert!(risky[0].risk_score.unwrap() > 0);
    assert!(risky[0].grade.is_some());
    assert_eq!(risky[0].contract, CONTRACT_ADDR.to_lowercase());
}

#[tokio::test]
async fn run_monitor_audit_deployments_respects_min_risk() {
    // With a min-risk above the contract's score, no risky-deployment alert fires.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([])).await;
    mount_etherscan_txorigin(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let alerts = tmp.path().join("a.jsonl");
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--audit-deployments", "--min-risk", "99",
        "--alerts", alerts.to_str().unwrap(),
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", tmp.path().join("o").to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    // No alerts file written (no alert emitted), or it exists but has no risky-deployment line.
    let risky = std::fs::read_to_string(&alerts)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("risky-deployment"))
        .count();
    assert_eq!(risky, 0);
}

#[tokio::test]
async fn run_monitor_audit_deployments_rejects_no_audit() {
    // --audit-deployments + --no-audit is contradictory and must error, not silently no-op.
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "1", "--to", "1", "--audit-deployments", "--no-audit",
        "--rpc-url", "http://127.0.0.1:1", "--etherscan-key", "k",
        "-o", tmp.path().to_str().unwrap(),
    ]);
    assert!(run(cli, std::future::ready(())).await.is_err());
}

#[tokio::test]
async fn run_monitor_inverted_range_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "monitor", "--from", "5", "--to", "1",
        "--rpc-url", "http://127.0.0.1:1", "--etherscan-key", "k",
        "-o", tmp.path().to_str().unwrap(),
    ]);
    assert!(run(cli, std::future::ready(())).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_monitor_needs_no_etherscan_key_and_tags_chain() {
    // monitor only uses eth_getLogs -> must run with NO Etherscan key. Also asserts
    // alerts carry chain_id. Drives the real binary with the env var removed.
    let rpc = MockServer::start().await;
    let topic_own = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0";
    let h32 = format!("0x{}", "2".repeat(64));
    let word = |hex: &str| format!("0x{}{}", "0".repeat(24), hex.repeat(40));
    let own = json!({"address":"0x000000000000000000000000000000000000beef","topics":[topic_own, word("a"), word("b")],"data":"0x","blockHash":h32,"blockNumber":"0x1","transactionHash":h32,"transactionIndex":"0x0","logIndex":"0x0","removed":false});
    Mock::given(method("POST")).respond_with(LogsEcho(json!([own]))).mount(&rpc).await;

    let tmp = tempfile::tempdir().unwrap();
    let out_s = tmp.path().join("o").to_str().unwrap().to_string();
    let rpc_uri = rpc.uri();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .env_remove("ETHERSCAN_API_KEY") // prove no key is required
            .args(["monitor", "--from", "1", "--to", "1", "--rpc-url", &rpc_uri, "-o", &out_s])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "stdout: {stdout}");
    let a: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(a["event"], "OwnershipTransferred");
    assert_eq!(a["chain_id"], 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_format_json_emits_clean_doc_on_stdout() {
    // Drives the real binary so we can assert stdout is PURE JSON (logs -> stderr).
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out_s = tmp.path().join("out").to_str().unwrap().to_string();
    let (rpc_uri, es_uri) = (rpc.uri(), es.uri());
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .args([
                "--format", "json", "-v", "addresses", USDC, "--no-sourcify",
                "--rpc-url", &rpc_uri, "--etherscan-key", "k", "--etherscan-base", &es_uri,
                "--rate", "1000", "-o", &out_s,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Pure JSON: even with -v logging, stdout's first char is '{' (logs went to stderr).
    assert!(stdout.trim_start().starts_with('{'), "stdout not pure JSON:\n{stdout}");
    let doc: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(doc["run"]["mode"], "addresses");
    assert!(doc["stats"]["saved"].as_u64().unwrap() >= 1);
    assert!(doc["contracts"][0]["analysis"]["code_hash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_format_ndjson_streams_one_object_per_line() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out_s = tmp.path().join("out").to_str().unwrap().to_string();
    let (rpc_uri, es_uri) = (rpc.uri(), es.uri());
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .args([
                "--format", "ndjson", "addresses", USDC, "--no-sourcify",
                "--rpc-url", &rpc_uri, "--etherscan-key", "k", "--etherscan-base", &es_uri,
                "--rate", "1000", "-o", &out_s,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "expected one NDJSON line, got: {stdout}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["address"].as_str().unwrap(), USDC.to_lowercase());
    assert!(v["analysis"]["code_hash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_ndjson_still_emits_skipped_contract_on_rerun() {
    // Regression: on a second run the contract is already saved (Skipped). ndjson
    // must still emit it (machine stdout must match the stderr summary).
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out_s = tmp.path().join("out").to_str().unwrap().to_string();
    let (rpc_uri, es_uri) = (rpc.uri(), es.uri());
    let args: Vec<String> = vec![
        "--format".into(), "ndjson".into(), "addresses".into(), USDC.into(), "--no-sourcify".into(),
        "--rpc-url".into(), rpc_uri, "--etherscan-key".into(), "k".into(), "--etherscan-base".into(), es_uri,
        "--rate".into(), "1000".into(), "-o".into(), out_s,
    ];
    let a1 = args.clone();
    let first = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan")).args(&a1).output().unwrap()
    }).await.unwrap();
    assert!(first.status.success());
    // Second run hits the resume/dedup (Skipped) path.
    let second = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan")).args(&args).output().unwrap()
    }).await.unwrap();
    assert!(second.status.success(), "stderr: {}", String::from_utf8_lossy(&second.stderr));
    let stdout = String::from_utf8(second.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "rerun ndjson must still emit the skipped contract:\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["address"].as_str().unwrap(), USDC.to_lowercase());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_json_contracts_are_run_scoped_not_whole_disk() {
    // Regression: json `contracts` must reflect THIS run, not the whole --out dir.
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    // Pre-populate the out dir with a FOREIGN contract from a hypothetical prior run.
    let foreign = out.join("0x000000000000000000000000000000000000beef");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(
        foreign.join("metadata.json"),
        r#"{"address":"0x000000000000000000000000000000000000beef","chain_id":1,"bytecode":"0x","bytecode_size":0,"balance_wei":"0","is_verified":false,"is_proxy":false,"has_abi":false,"source_file_count":0}"#,
    )
    .unwrap();
    let out_s = out.to_str().unwrap().to_string();
    let (rpc_uri, es_uri) = (rpc.uri(), es.uri());
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_blockscan"))
            .args([
                "--format", "json", "addresses", USDC, "--no-sourcify",
                "--rpc-url", &rpc_uri, "--etherscan-key", "k", "--etherscan-base", &es_uri,
                "--rate", "1000", "-o", &out_s,
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let doc: serde_json::Value =
        serde_json::from_str(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
    let contracts = doc["contracts"].as_array().unwrap();
    assert_eq!(contracts.len(), 1, "json contracts must be run-scoped: {contracts:?}");
    assert_eq!(contracts[0]["address"].as_str().unwrap(), USDC.to_lowercase());
}

#[tokio::test]
async fn watch_errors_when_initial_head_unavailable() {
    let es = MockServer::start().await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let s = scanner(config("http://127.0.0.1:1", &es.uri(), tmp.path(), false));
    let rpc = RpcClient::new("http://127.0.0.1:1", 2).unwrap();

    let args = download_watch_args(0, 30);
    let shutdown = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(watch_with_shutdown(&rpc, &s, args, false, OutputFormat::Human, shutdown)
        .await
        .is_err());
}

// ============================ proxy / sourcify / discover / export / multichain ============================

#[tokio::test]
async fn rpc_resolve_storage_proxy_eip1967() {
    let server = MockServer::start().await;
    let impl_hex = "00000000000000000000000000000000000000ad";
    mount_rpc_method(&server, "eth_getStorageAt", json!(storage_word(impl_hex))).await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    let p = rpc.resolve_storage_proxy(addr()).await.unwrap().unwrap();
    assert_eq!(p.kind, "EIP-1967");
    assert_eq!(format!("{:#x}", p.target), format!("0x{impl_hex}"));
}

const BEACON_TOPIC: &str = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e";

#[tokio::test]
async fn rpc_logs_addresses_via_mock() {
    let server = MockServer::start().await;
    mount_rpc_method(
        &server,
        "eth_getLogs",
        json!([
            make_log(CONTRACT_ADDR, BEACON_TOPIC),
            make_log("0x1111111111111111111111111111111111111111", BEACON_TOPIC)
        ]),
    )
    .await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    let topics = vec![BEACON_TOPIC.parse::<B256>().unwrap()];
    let got = rpc.logs_addresses(100, 100, topics, 2000, 2).await.unwrap();
    assert_eq!(got.len(), 2);
    assert!(got.iter().any(|a| format!("{a:#x}") == CONTRACT_ADDR));
}

#[tokio::test]
async fn rpc_logs_addresses_chunks_range() {
    // Range 0..=10 with chunk 4 -> 3 windows; each returns one log.
    let server = MockServer::start().await;
    mount_rpc_method(&server, "eth_getLogs", json!([make_log(CONTRACT_ADDR, BEACON_TOPIC)])).await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    let topics = vec![BEACON_TOPIC.parse::<B256>().unwrap()];
    let got = rpc.logs_addresses(0, 10, topics, 4, 3).await.unwrap();
    // Deduped across the 3 windows -> 1 unique address.
    assert_eq!(got.len(), 1);
}

#[tokio::test]
async fn defillama_fetch_via_mock() {
    use blockscan::defillama::Defillama;
    let ll = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/protocol/lido"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "Lido",
            "address": "0x5a98fcbea516cf06857215779fd812ca3bef1b32",
            "chains": ["Ethereum"]
        })))
        .mount(&ll)
        .await;
    let got = Defillama::with_base(&ll.uri()).fetch_addresses("lido").await;
    assert_eq!(got, vec!["0x5a98fcbea516cf06857215779fd812ca3bef1b32"]);
}

#[tokio::test]
async fn defillama_http_error_is_empty() {
    use blockscan::defillama::Defillama;
    let ll = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad slug"))
        .mount(&ll)
        .await;
    assert!(Defillama::with_base(&ll.uri()).fetch_addresses("nope").await.is_empty());
}

#[tokio::test]
async fn coingecko_fetch_via_mock() {
    use blockscan::coingecko::CoinGecko;
    let cg = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/coins/dai"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "dai",
            "platforms": {
                "ethereum": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "polygon-pos": "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"
            }
        })))
        .mount(&cg)
        .await;
    // chain 1 → ethereum platform key.
    let got = CoinGecko::with_base(&cg.uri()).fetch_addresses("dai", 1).await;
    assert_eq!(got, vec!["0x6b175474e89094c44da98b954eedeac495271d0f"]);
    // chain 137 → polygon-pos.
    let got = CoinGecko::with_base(&cg.uri()).fetch_addresses("dai", 137).await;
    assert_eq!(got, vec!["0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"]);
    // unsupported chain → empty.
    assert!(CoinGecko::with_base(&cg.uri()).fetch_addresses("dai", 999999).await.is_empty());
}

#[tokio::test]
async fn run_discover_topic_inverted_range_is_graceful() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // --from > --to -> log scan skipped with a warning, run still Ok, nothing saved.
    let cli = Cli::parse_from([
        "blockscan", "discover", "--topic", BEACON_TOPIC, "--from", "100", "--to", "50",
        "--no-sourcify", "--rpc-url", &rpc.uri(), "--etherscan-key", "k",
        "--etherscan-base", &es.uri(), "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_dir(out).map(|d| d.count()).unwrap_or(0), 0);
}

#[tokio::test]
async fn run_discover_by_topic() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_rpc_method(&rpc, "eth_getLogs", json!([make_log(CONTRACT_ADDR, BEACON_TOPIC)])).await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "discover", "--topic", BEACON_TOPIC, "--from", "100", "--to", "100",
        "--no-sourcify", "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
}

#[tokio::test]
async fn rpc_beacon_implementation_via_mock() {
    let server = MockServer::start().await;
    let impl_hex = "00000000000000000000000000000000000000ad";
    mount_rpc_method(&server, "eth_call", json!(storage_word(impl_hex))).await;
    let rpc = RpcClient::new(&server.uri(), 2).unwrap();
    let got = rpc.beacon_implementation(addr()).await.unwrap().unwrap();
    assert_eq!(format!("{:#x}", got), format!("0x{impl_hex}"));
}

#[tokio::test]
async fn sourcify_fetch_via_mock() {
    let sf = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/contract/1/.+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "match": "match",
            "sources": { "src/C.sol": { "content": "contract C {}" } }
        })))
        .mount(&sf)
        .await;
    let files = Sourcify::new(&sf.uri(), 1).fetch_sources(CONTRACT_ADDR).await;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "src/C.sol");
}

#[tokio::test]
async fn blockscout_search_via_mock() {
    let bs = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"type":"contract","is_smart_contract_address":true,"address_hash":CONTRACT_ADDR}
            ]
        })))
        .mount(&bs)
        .await;
    let got = Blockscout::new(&bs.uri(), 100).search_contracts("uniswap").await;
    assert_eq!(got, vec![CONTRACT_ADDR.to_ascii_lowercase()]);
}

#[tokio::test]
async fn google_search_via_mock() {
    use blockscan::websearch::Google;
    let g = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"link": format!("https://etherscan.io/address/{CONTRACT_ADDR}#code")},
                {"link": "https://docs.example.org/intro"}
            ]
        })))
        .mount(&g)
        .await;
    let client = Google::with_base(&g.uri(), "key", "cse");
    let got = client.search_addresses("uniswap").await;
    assert_eq!(got, vec![CONTRACT_ADDR.to_ascii_lowercase()]);
}

#[tokio::test]
async fn website_discover_crawls_same_domain() {
    use blockscan::website::WebsiteScraper;
    let site = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html>home {CONTRACT_ADDR} <a href="/docs/contracts">contracts</a></html>"#
        )))
        .mount(&site)
        .await;
    Mock::given(method("GET"))
        .and(path("/docs/contracts"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "Deployed at 0x1111111111111111111111111111111111111111",
        ))
        .mount(&site)
        .await;

    let scraper = WebsiteScraper::new(10);
    let got = scraper.discover(&format!("{}/", site.uri()), 1).await;
    assert!(got.contains(&CONTRACT_ADDR.to_ascii_lowercase()));
    assert!(got.contains(&"0x1111111111111111111111111111111111111111".to_string()));
}

#[tokio::test]
async fn run_discover_by_website() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let site = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html>contracts: {CONTRACT_ADDR}</html>"#
        )))
        .mount(&site)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "discover", "--website", &format!("{}/", site.uri()),
        "--no-sourcify", "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
}

#[tokio::test]
async fn github_discover_via_mock() {
    use blockscan::github;
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
            "tree": [
                {"path":"deployments/mainnet/Token.json","type":"blob"},
                {"path":"broadcast/Deploy.s.sol/1/run-latest.json","type":"blob"},
                {"path":"src/Token.sol","type":"blob"}
            ]
        })))
        .mount(&gh)
        .await;
    Mock::given(method("GET"))
        .and(path("/o/r/main/deployments/mainnet/Token.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "address": "0x1111111111111111111111111111111111111111"
        })))
        .mount(&gh)
        .await;
    Mock::given(method("GET"))
        .and(path("/o/r/main/broadcast/Deploy.s.sol/1/run-latest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "transactions": [
                {"transactionType":"CREATE","contractAddress":"0x2222222222222222222222222222222222222222"}
            ],
            "receipts": []
        })))
        .mount(&gh)
        .await;

    let mut got = github::discover_repo_with(&gh.uri(), &gh.uri(), "o/r", "").await;
    got.sort();
    assert_eq!(
        got,
        vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ]
    );
}

#[tokio::test]
async fn github_discover_reads_readme_scope() {
    use blockscan::github;
    let gh = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/o/contest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"default_branch":"main"})))
        .mount(&gh)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/o/contest/git/trees/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "truncated": false,
            "tree": [
                {"path":"README.md","type":"blob"},
                {"path":"src/Vault.sol","type":"blob"}
            ]
        })))
        .mount(&gh)
        .await;
    Mock::given(method("GET"))
        .and(path("/o/contest/main/README.md"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "## Scope\n\n| Contract | Address |\n|---|---|\n| Vault | 0x1111111111111111111111111111111111111111 |\nsee https://etherscan.io/address/0x2222222222222222222222222222222222222222",
        ))
        .mount(&gh)
        .await;

    let mut got = github::discover_repo_with(&gh.uri(), &gh.uri(), "o/contest", "").await;
    got.sort();
    assert_eq!(
        got,
        vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ]
    );
}

#[tokio::test]
async fn run_discover_by_tokenlist() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let tl = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tokens": [{"chainId": 1, "address": CONTRACT_ADDR, "symbol": "X"}]
        })))
        .mount(&tl)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "discover", "--tokenlist", &tl.uri(), "--no-sourcify", "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
}

fn proxy_cli(rpc: &str, es: &str, out: &str) -> Cli {
    Cli::parse_from([
        "blockscan", "addresses", USDC,
        "--no-sourcify", "--retries", "1",
        "--rpc-url", rpc, "--etherscan-key", "k", "--etherscan-base", es,
        "--rate", "1000", "-o", out,
    ])
}

#[tokio::test]
async fn run_addresses_detects_storage_proxy() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_method(&rpc, "eth_getCode", json!("0x6080604052")).await;
    // The scan pins state reads to a block, so the chain needs a head.
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getBlockByNumber", block_body("0x64")).await;
    mount_rpc_method(&rpc, "eth_getBalance", json!("0x0")).await;
    let impl_hex = "00000000000000000000000000000000000000ad";
    mount_rpc_method(&rpc, "eth_getStorageAt", json!(storage_word(impl_hex))).await;
    mount_etherscan_unverified(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    run(proxy_cli(&rpc.uri(), &es.uri(), out), std::future::ready(())).await.unwrap();

    let meta =
        std::fs::read_to_string(tmp.path().join(USDC.to_lowercase()).join("metadata.json")).unwrap();
    assert!(meta.contains("EIP-1967"), "{meta}");
    assert!(meta.contains(&format!("0x{impl_hex}")));
}

#[tokio::test]
async fn run_addresses_eip1167_skips_storage_lookup() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let impl_hex = "00000000000000000000000000000000000000ad";
    let clone = format!("0x363d3d373d3d3d363d73{impl_hex}5af43d82803e903d91602b57fd5bf3");
    mount_rpc_method(&rpc, "eth_getCode", json!(clone)).await;
    mount_rpc_method(&rpc, "eth_getBalance", json!("0x0")).await;
    // The scan pins state reads to a block, so the chain needs a head.
    mount_rpc_method(&rpc, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc, "eth_getBlockByNumber", block_body("0x64")).await;
    // No eth_getStorageAt mount: bytecode already yields the impl, so the
    // storage-slot lookup is skipped (covers the implementation-present branch).
    mount_etherscan_unverified(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    run(proxy_cli(&rpc.uri(), &es.uri(), out), std::future::ready(())).await.unwrap();
    let meta =
        std::fs::read_to_string(tmp.path().join(USDC.to_lowercase()).join("metadata.json")).unwrap();
    assert!(meta.contains("EIP-1167"), "{meta}");
}

#[tokio::test]
async fn run_addresses_sourcify_fallback() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let sf = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_unverified(&es).await;
    Mock::given(method("GET"))
        .and(path_regex(r"/v2/contract/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "match": "match",
            "sources": { "src/C.sol": { "content": "contract C {}" } }
        })))
        .mount(&sf)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--sourcify-base", &sf.uri(), "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();

    let dir = tmp.path().join(USDC.to_lowercase());
    let meta = std::fs::read_to_string(dir.join("metadata.json")).unwrap();
    assert!(meta.contains("sourcify"), "{meta}");
    assert!(dir.join("source/src/C.sol").exists());
}

#[tokio::test]
async fn run_addresses_only_verified_filters_out_unverified() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_unverified(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify", "--only-verified", "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(!tmp.path().join(USDC.to_lowercase()).exists());
}

#[tokio::test]
async fn run_addresses_writes_manifest() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let manifest = tmp.path().join("index.json");
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--rate", "1000", "-o", out.to_str().unwrap(),
        "--manifest", manifest.to_str().unwrap(),
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    let body = std::fs::read_to_string(&manifest).unwrap();
    assert!(body.contains(&USDC.to_lowercase()));
    assert!(body.trim_start().starts_with('['));
    // Static analysis flowed through the full pipeline into the manifest...
    assert!(body.contains("code_hash_nometa"));
    let meta = std::fs::read_to_string(out.join(USDC.to_lowercase()).join("metadata.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&meta).unwrap();
    assert!(v["analysis"]["code_hash"].as_str().unwrap().starts_with("0x"));
    // Security audit ran during the scan and is persisted.
    assert!(v["audit"]["grade"].as_str().is_some());
    assert!(v["audit"]["risk_score"].as_u64().is_some());
    // ...and a clusters.json sidecar is written next to the manifest.
    assert!(tmp.path().join("clusters.json").exists());
}

#[tokio::test]
async fn run_discover_by_name() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let bs = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"type":"contract","is_smart_contract_address":true,"address_hash":CONTRACT_ADDR}
            ]
        })))
        .mount(&bs)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "discover", "uniswap", "--no-sourcify", "--retries", "1",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--blockscout-base", &bs.uri(), "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join(CONTRACT_ADDR).join("metadata.json").exists());
}

#[tokio::test]
async fn run_discover_empty_is_ok() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let bs = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "items": [] })))
        .mount(&bs)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    let cli = Cli::parse_from([
        "blockscan", "discover", "nothing", "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--blockscout-base", &bs.uri(), "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_dir(out).map(|d| d.count()).unwrap_or(0), 0);
}

#[tokio::test]
async fn run_multichain_two_chains() {
    let rpc1 = MockServer::start().await;
    let rpc2 = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc1, "0x6080604052").await;
    mount_rpc_full(&rpc2, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    std::env::set_var("ETH_RPC_URL_8453", rpc2.uri());
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--chains", "1,8453",
        "--rpc-url", &rpc1.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--blockscout-base", "", "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    std::env::remove_var("ETH_RPC_URL_8453");

    assert!(tmp.path().join("ethereum").join(USDC.to_lowercase()).join("metadata.json").exists());
    assert!(tmp.path().join("base").join(USDC.to_lowercase()).join("metadata.json").exists());
}

#[tokio::test]
async fn run_watch_rejects_multichain() {
    // Download-mode watch (no alert flags) is single-chain; --chains must error.
    let cli = Cli::parse_from([
        "blockscan", "watch", "--chains", "1,10",
        "--rpc-url", "http://r", "--etherscan-key", "k",
    ]);
    assert!(run(cli, std::future::ready(())).await.is_err());
}

#[tokio::test]
async fn watch_alerts_periodic_digest_branch_fires() {
    // --group + --digest-interval enables the periodic-flush select branch (the
    // interval's immediate first tick flushes the (empty) grouper); runs to shutdown.
    let rpc_server = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([])).await;
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let g = Cli::parse_from(["blockscan", "--rpc-url", &rpc_server.uri(), "--etherscan-key", "k", "watch"]).global;
    let mut args = alert_watch_args(true, false, None, None);
    args.group = true;
    args.digest_interval = Some(1);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(80)).await; };
    let counts = blockscan::watch_alerts_with_shutdown(&g, &rpc, None, args, 1, shutdown).await.unwrap();
    assert_eq!(counts.emitted, 0); // static head -> nothing to fold/emit
}

#[tokio::test]
async fn watch_poll_not_starved_by_frequent_digest() {
    // Regression (review HIGH): with --digest-interval shorter than --poll-ms, the
    // poll branch must still run (persistent poll timer, not a restarting sleep).
    // Observe eth_blockNumber being called (poll_alert_tick ran at least once).
    let rpc_server = MockServer::start().await;
    mount_rpc_method(&rpc_server, "eth_blockNumber", json!("0x64")).await;
    mount_rpc_method(&rpc_server, "eth_getLogs", json!([])).await;
    let rpc = RpcClient::new(&rpc_server.uri(), 2).unwrap();
    let g = Cli::parse_from(["blockscan", "--rpc-url", &rpc_server.uri(), "--etherscan-key", "k", "watch"]).global;
    let mut args = alert_watch_args(true, false, None, None);
    args.group = true;
    args.poll_ms = 2000; // poll slower than digest (the dangerous ordering)
    args.digest_interval = Some(1); // 1000 ms < 2000 ms
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(300)).await; };
    blockscan::watch_alerts_with_shutdown(&g, &rpc, None, args, 1, shutdown).await.unwrap();
    let reqs = rpc_server.received_requests().await.unwrap();
    let block_number_calls = reqs
        .iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains("eth_blockNumber"))
        .count();
    assert!(block_number_calls >= 1, "poll must run despite frequent digest (starvation regression)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_alerts_multichain_runs_both_chains() {
    // Alert-mode watch supports --chains: two chains run in parallel, one shutdown
    // stops both, counts aggregate. Chain 10's RPC comes from ETH_RPC_URL_10.
    let rpc1 = MockServer::start().await;
    let rpc10 = MockServer::start().await;
    for s in [&rpc1, &rpc10] {
        mount_rpc_method(s, "eth_blockNumber", json!("0x64")).await;
        mount_rpc_method(s, "eth_getLogs", json!([])).await;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::env::remove_var("ETHERSCAN_API_KEY");
    std::env::set_var("ETH_RPC_URL_10", rpc10.uri());
    let cli = Cli::parse_from([
        "blockscan", "watch", "--alert-events", "--chains", "1,10",
        "--confirmations", "0", "--poll-ms", "20",
        "--rpc-url", &rpc1.uri(), "-o", tmp.path().to_str().unwrap(),
    ]);
    let shutdown = async { tokio::time::sleep(std::time::Duration::from_millis(100)).await; };
    let r = run(cli, shutdown).await;
    std::env::remove_var("ETH_RPC_URL_10");
    r.unwrap();
}

#[tokio::test]
async fn run_multichain_skips_chain_without_rpc() {
    let rpc1 = MockServer::start().await;
    let es = MockServer::start().await;
    mount_rpc_full(&rpc1, "0x6080604052").await;
    mount_etherscan_ok(&es).await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // Chain 137 has no ETH_RPC_URL_137 -> skipped with a warning.
    let cli = Cli::parse_from([
        "blockscan", "addresses", USDC, "--no-sourcify",
        "--chains", "1,137",
        "--rpc-url", &rpc1.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--blockscout-base", "", "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert!(tmp.path().join("ethereum").join(USDC.to_lowercase()).join("metadata.json").exists());
    assert!(!tmp.path().join("polygon").exists());
}

#[tokio::test]
async fn run_discover_invalid_github_is_graceful() {
    let rpc = MockServer::start().await;
    let es = MockServer::start().await;
    let bs = MockServer::start().await;
    mount_rpc_full(&rpc, "0x6080604052").await;
    mount_etherscan_ok(&es).await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "items": [] })))
        .mount(&bs)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().to_str().unwrap();
    // `noslash` is not owner/repo -> github discovery returns nothing (no network).
    let cli = Cli::parse_from([
        "blockscan", "discover", "someproject", "--github", "noslash", "--no-sourcify",
        "--rpc-url", &rpc.uri(), "--etherscan-key", "k", "--etherscan-base", &es.uri(),
        "--blockscout-base", &bs.uri(), "--rate", "1000", "-o", out,
    ]);
    run(cli, std::future::ready(())).await.unwrap();
    assert_eq!(std::fs::read_dir(out).map(|d| d.count()).unwrap_or(0), 0);
}
