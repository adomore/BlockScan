//! Performance probe for the on-chain log scan.
//! Usage: ETH_RPC_URL=<rpc> cargo run --release --example log_scan -- <from> <to> <topic> <chunk> <concurrency>

use std::str::FromStr;
use std::time::Instant;

use alloy::primitives::B256;
use blockscan::rpc::RpcClient;

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("ETH_RPC_URL").expect("set ETH_RPC_URL");
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 5 {
        eprintln!("usage: log_scan <from> <to> <topic> <chunk> <concurrency>");
        std::process::exit(2);
    }
    let from: u64 = a[0].parse().unwrap();
    let to: u64 = a[1].parse().unwrap();
    let topic = B256::from_str(&a[2]).unwrap();
    let chunk: u64 = a[3].parse().unwrap();
    let concurrency: usize = a[4].parse().unwrap();

    let rpc = RpcClient::new(&rpc_url, 3).expect("rpc");
    let t = Instant::now();
    let got = rpc
        .logs_addresses(from, to, vec![topic], chunk, concurrency)
        .await
        .expect("logs");
    let el = t.elapsed();
    println!(
        "range {from}..={to} ({} blocks) chunk={chunk} conc={concurrency} -> {} contracts in {:.2}s",
        to - from + 1,
        got.len(),
        el.as_secs_f64()
    );
}
