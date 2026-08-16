//! Real-chain probe for the storage-slot proxy resolver.
//! Usage: ETH_RPC_URL=<rpc> cargo run --example resolve_proxy -- <address>

use std::str::FromStr;

use alloy::primitives::Address;
use blockscan::rpc::RpcClient;

#[tokio::main]
async fn main() {
    let rpc_url = std::env::var("ETH_RPC_URL").expect("set ETH_RPC_URL");
    let arg = std::env::args().nth(1).expect("usage: resolve_proxy <address>");
    let addr = Address::from_str(&arg).expect("invalid address");
    let rpc = RpcClient::new(&rpc_url, 3).expect("rpc");
    match rpc.resolve_storage_proxy(addr).await {
        Ok(Some(p)) => println!("{addr:#x}: proxy kind={} target={:#x}", p.kind, p.target),
        Ok(None) => println!("{addr:#x}: not a storage-slot proxy"),
        Err(e) => println!("{addr:#x}: error: {e}"),
    }
}
