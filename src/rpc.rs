use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::{b256, Address, B256, Bytes, U256};
use alloy::primitives::TxKind;
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::client::ClientBuilder;
use alloy::rpc::types::{Filter, TransactionInput, TransactionRequest};
use alloy::transports::http::{Client, Http};
use futures::stream::{self, StreamExt};

use crate::error::{AppError, Result};

type EthProvider = RootProvider<Http<Client>>;

// Proxy storage slots (verified against EIP-1967 / EIP-1822).
const EIP1967_IMPL: B256 =
    b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
const EIP1967_BEACON: B256 =
    b256!("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50");
const EIP1822_PROXIABLE: B256 =
    b256!("c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7");
/// Pre-standard OpenZeppelin (zeppelinos) implementation slot: the plain
/// `keccak256("org.zeppelinos.proxy.implementation")`, without the "minus one"
/// step EIP-1967 later added. Proxies deployed before the standard existed use
/// it and are still live, so a scanner that reads only the three standard slots
/// reports them as ordinary contracts.
const ZEPPELINOS_IMPL: B256 =
    b256!("7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3");
/// `implementation()` selector (used to resolve a beacon's logic address).
const IMPLEMENTATION_SELECTOR: [u8; 4] = [0x5c, 0x60, 0xda, 0x1b];
/// `facetAddresses()` selector from the EIP-2535 diamond loupe.
const FACET_ADDRESSES_SELECTOR: [u8; 4] = [0x52, 0xef, 0x6b, 0x2c];

/// A proxy resolved from on-chain state.
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    /// `EIP-1967` / `EIP-1967-beacon` / `EIP-1822` / `zeppelinos-legacy` /
    /// `EIP-2535`.
    pub kind: &'static str,
    /// The address the proxy points to. For a beacon proxy this is the logic
    /// address the beacon names, not the beacon. For an `EIP-2535` diamond it is
    /// the *first* facet the loupe enumerates — a diamond has no single
    /// implementation, and `kind` is what says so.
    pub target: Address,
}

/// A single decoded `eth_getLogs` hit — the fields the alert parser needs,
/// decoupled from the alloy `Log` type so it's trivial to construct in tests.
#[derive(Debug, Clone)]
pub struct LogHit {
    pub block: u64,
    /// The contract that emitted the event.
    pub address: Address,
    pub topics: Vec<B256>,
    /// Non-indexed event data (ABI-encoded 32-byte words).
    pub data: Bytes,
    pub tx_hash: Option<B256>,
    /// Per-block log index — distinguishes multiple logs in the same transaction
    /// (without it, two same-signature events in one tx would dedupe to one alert).
    pub log_index: Option<u64>,
}

/// Thin wrapper over an Ethereum JSON-RPC endpoint.
#[derive(Clone)]
pub struct RpcClient {
    provider: EthProvider,
    retries: u32,
    /// The block every state read is answered at.
    ///
    /// `None` means the chain head, which is what these reads did before T-04:
    /// two scans of one address on different days could disagree, and nothing in
    /// the stored output said which chain state produced either answer. A scan
    /// resolves the head once at the start and pins to it, so the whole run sees
    /// one consistent chain.
    pinned: Option<u64>,
}

impl RpcClient {
    pub fn new(rpc_url: &str, retries: u32) -> Result<Self> {
        let url = rpc_url
            .parse()
            .map_err(|e| AppError::Rpc(format!("invalid RPC URL '{rpc_url}': {e}")))?;

        // Force HTTP/1.1 + a timeout: some networks break reqwest's HTTP/2
        // negotiation (large responses like block receipts fail to send).
        let client = reqwest::Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Rpc(e.to_string()))?;

        let transport = Http::with_client(client, url);
        let rpc_client = ClientBuilder::default().transport(transport, false);
        let provider = RootProvider::new(rpc_client);
        Ok(Self {
            provider,
            retries: retries.max(1),
            pinned: None,
        })
    }

    /// Latest block number.
    pub async fn block_number(&self) -> Result<u64> {
        with_retry(self.retries, || async {
            self.provider
                .get_block_number()
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await
    }

    /// Addresses of contracts created in the given block (top-level deployments).
    ///
    /// Uses block receipts: every receipt whose `contract_address` is set
    /// corresponds to a contract-creation transaction.
    pub async fn contract_creations_in_block(&self, number: u64) -> Result<Vec<Address>> {
        let block = BlockId::Number(BlockNumberOrTag::Number(number));
        let receipts = with_retry(self.retries, || async {
            self.provider
                .get_block_receipts(block)
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await?;

        let mut out = Vec::new();
        if let Some(receipts) = receipts {
            for r in receipts {
                if let Some(addr) = r.contract_address {
                    out.push(addr);
                }
            }
        }
        Ok(out)
    }

    /// Addresses of *all* contracts created in a block — including factory
    /// (CREATE/CREATE2) deployments — via the `trace_block` RPC method.
    ///
    /// Requires an RPC node with the `trace_` namespace enabled (Erigon, Reth,
    /// Nethermind, or an archive provider). Returns an error otherwise.
    pub async fn trace_creations_in_block(&self, number: u64) -> Result<Vec<Address>> {
        let params = (format!("0x{number:x}"),);
        let traces: serde_json::Value = self
            .provider
            .raw_request(Cow::Borrowed("trace_block"), params)
            .await
            .map_err(|e| AppError::Rpc(e.to_string()))?;
        Ok(parse_trace_creations(&traces))
    }

    /// A clone of this client whose state reads are answered at `block`.
    ///
    /// Cloning rather than mutating because the client is shared across the
    /// scan's concurrent tasks; the pin is decided once, before any of them run.
    pub fn pinned_at(&self, block: u64) -> Self {
        Self { pinned: Some(block), ..self.clone() }
    }

    /// The block this client pins state reads to, if any.
    pub fn pinned_block(&self) -> Option<u64> {
        self.pinned
    }

    /// The block identifier state reads use: the pin, or the head when unpinned.
    fn read_at(&self) -> BlockId {
        match self.pinned {
            Some(n) => BlockId::Number(BlockNumberOrTag::Number(n)),
            None => BlockId::Number(BlockNumberOrTag::Latest),
        }
    }

    /// Hash of a block, so a run can record *which* chain state it read, not
    /// only which height — heights are not unique across a reorg.
    pub async fn block_hash(&self, number: u64) -> Result<Option<B256>> {
        use alloy::rpc::types::BlockTransactionsKind;
        let block = with_retry(self.retries, || async {
            self.provider
                .get_block_by_number(BlockNumberOrTag::Number(number), BlockTransactionsKind::Hashes)
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await?;
        Ok(block.map(|b| b.header.hash))
    }

    /// Runtime bytecode at the pinned block (empty if not a contract / self-destructed).
    pub async fn get_code(&self, address: Address) -> Result<Bytes> {
        with_retry(self.retries, || async {
            self.provider
                .get_code_at(address)
                .block_id(self.read_at())
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await
    }

    /// Balance in wei at the pinned block.
    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        with_retry(self.retries, || async {
            self.provider
                .get_balance(address)
                .block_id(self.read_at())
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await
    }

    /// Read a storage slot at the pinned block and interpret the word as an address.
    pub async fn storage_address(&self, address: Address, slot: B256) -> Result<Option<Address>> {
        let key = U256::from_be_bytes(slot.0);
        let word = with_retry(self.retries, || async {
            self.provider
                .get_storage_at(address, key)
                .block_id(self.read_at())
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await?;
        Ok(slot_word_to_address(word))
    }

    /// Call `implementation()` (selector 0x5c60da1b) on a beacon contract and
    /// return the logic address it points to.
    pub async fn beacon_implementation(&self, beacon: Address) -> Result<Option<Address>> {
        let tx = TransactionRequest {
            to: Some(TxKind::Call(beacon)),
            input: TransactionInput::new(Bytes::from_static(&IMPLEMENTATION_SELECTOR)),
            ..Default::default()
        };
        let out = with_retry(self.retries, || async {
            self.provider
                .call(&tx)
                .await
                .map_err(|e| AppError::Rpc(e.to_string()))
        })
        .await?;
        if out.len() < 32 {
            return Ok(None);
        }
        let word = U256::from_be_slice(&out[out.len() - 32..]);
        Ok(slot_word_to_address(word))
    }

    /// Enumerate an EIP-2535 diamond's facets by calling `facetAddresses()`
    /// (selector 0x52ef6b2c) from the loupe interface.
    ///
    /// A diamond keeps no implementation slot, so unlike every other family here
    /// there is nothing to read: asking is the only way to recognise one. The
    /// reply is decoded strictly (see [`parse_facet_addresses`]) because this
    /// call lands on a contract not known to be a diamond, and a contract with a
    /// fallback answers *something*.
    ///
    /// A revert — what a contract without the function does — is not an error
    /// worth propagating: it is the negative answer. Same shape as the beacon
    /// dereference, which also falls back rather than failing the scan.
    pub async fn diamond_facets(&self, address: Address) -> Vec<Address> {
        let tx = TransactionRequest {
            to: Some(TxKind::Call(address)),
            input: TransactionInput::new(Bytes::from_static(&FACET_ADDRESSES_SELECTOR)),
            ..Default::default()
        };
        match self.provider.call(&tx).await {
            Ok(out) => parse_facet_addresses(&out),
            Err(_) => Vec::new(),
        }
    }

    /// `Some` when `address` answers the diamond loupe with at least one facet.
    ///
    /// Kept separate from [`RpcClient::resolve_storage_proxy`] because it costs
    /// an `eth_call` rather than a storage read, and the caller decides whether
    /// this contract is worth asking.
    pub async fn resolve_diamond(&self, address: Address) -> Option<ProxyInfo> {
        self.diamond_facets(address)
            .await
            .first()
            .map(|first| ProxyInfo { kind: "EIP-2535", target: *first })
    }

    /// Resolve a storage-slot proxy: EIP-1967 implementation, then EIP-1967
    /// beacon (resolved to the beacon's logic address via `implementation()`),
    /// then EIP-1822 (legacy UUPS), then the pre-standard zeppelinos slot.
    /// Returns the first slot that is set.
    ///
    /// The standard slots are read first on purpose: a proxy upgraded from the
    /// pre-standard layout can have both set, and the standard one is the live
    /// pointer.
    pub async fn resolve_storage_proxy(&self, address: Address) -> Result<Option<ProxyInfo>> {
        if let Some(target) = self.storage_address(address, EIP1967_IMPL).await? {
            return Ok(Some(ProxyInfo { kind: "EIP-1967", target }));
        }
        if let Some(beacon) = self.storage_address(address, EIP1967_BEACON).await? {
            // The beacon slot holds the beacon contract; its implementation() is
            // the real logic address. Fall back to the beacon address on failure.
            let target = match self.beacon_implementation(beacon).await {
                Ok(Some(impl_addr)) => impl_addr,
                _ => beacon,
            };
            return Ok(Some(ProxyInfo {
                kind: "EIP-1967-beacon",
                target,
            }));
        }
        if let Some(target) = self.storage_address(address, EIP1822_PROXIABLE).await? {
            return Ok(Some(ProxyInfo { kind: "EIP-1822", target }));
        }
        if let Some(target) = self.storage_address(address, ZEPPELINOS_IMPL).await? {
            return Ok(Some(ProxyInfo { kind: "zeppelinos-legacy", target }));
        }
        Ok(None)
    }
}

/// Scan one block window for logs matching `topics` on topic0, returning the
/// distinct emitting addresses plus the count of single-block windows that still
/// failed after retries. On a window failure, the window is bisected and the
/// halves retried (the standard way to survive provider result-size caps); only a
/// single-block failure is dropped (and counted).
async fn scan_log_window(
    provider: &EthProvider,
    topics: &[B256],
    retries: u32,
    from: u64,
    to: u64,
) -> (Vec<Address>, u64) {
    let mut stack = vec![(from, to)];
    let mut addrs = Vec::new();
    let mut failed = 0u64;
    while let Some((s, e)) = stack.pop() {
        let filter = Filter::new()
            .from_block(s)
            .to_block(e)
            .event_signature(topics.to_vec());
        let res = with_retry(retries, || async {
            provider
                .get_logs(&filter)
                .await
                .map_err(|err| AppError::Rpc(err.to_string()))
        })
        .await;
        match res {
            Ok(logs) => addrs.extend(logs.iter().map(|l| l.address())),
            Err(_) if s < e => {
                // Likely a range/result-size rejection: bisect and retry the halves.
                let mid = s + (e - s) / 2;
                stack.push((s, mid));
                stack.push((mid + 1, e));
            }
            Err(err) => {
                tracing::warn!("get_logs block {s} failed: {err}");
                failed += 1;
            }
        }
    }
    (addrs, failed)
}

/// Like [`scan_log_window`] but returns the full decoded logs ([`LogHit`]),
/// for alert decoding. Same bisect-on-failure behaviour.
async fn fetch_log_window(
    provider: &EthProvider,
    topics: &[B256],
    retries: u32,
    from: u64,
    to: u64,
) -> (Vec<LogHit>, u64) {
    let mut stack = vec![(from, to)];
    let mut hits = Vec::new();
    let mut failed = 0u64;
    while let Some((s, e)) = stack.pop() {
        let filter = Filter::new()
            .from_block(s)
            .to_block(e)
            .event_signature(topics.to_vec());
        let res = with_retry(retries, || async {
            provider
                .get_logs(&filter)
                .await
                .map_err(|err| AppError::Rpc(err.to_string()))
        })
        .await;
        match res {
            Ok(logs) => hits.extend(logs.into_iter().map(|l| LogHit {
                block: l.block_number.unwrap_or_default(),
                address: l.inner.address,
                topics: l.inner.data.topics().to_vec(),
                data: l.inner.data.data.clone(),
                tx_hash: l.transaction_hash,
                log_index: l.log_index,
            })),
            Err(_) if s < e => {
                let mid = s + (e - s) / 2;
                stack.push((s, mid));
                stack.push((mid + 1, e));
            }
            Err(err) => {
                tracing::warn!("get_logs block {s} failed: {err}");
                failed += 1;
            }
        }
    }
    (hits, failed)
}

impl RpcClient {
    /// Addresses of contracts that emitted any of `topics` (as topic0) within
    /// `[from, to]`, via `eth_getLogs`. The range is split into `chunk`-sized
    /// windows queried with up to `concurrency` in flight; a window that exceeds a
    /// provider cap is bisected. Incomplete results (blocks that still failed) are
    /// logged with a count so partial scans aren't mistaken for complete ones.
    pub async fn logs_addresses(
        &self,
        from: u64,
        to: u64,
        topics: Vec<B256>,
        chunk: u64,
        concurrency: usize,
    ) -> Result<Vec<Address>> {
        if topics.is_empty() {
            return Err(AppError::Rpc(
                "logs_addresses requires at least one topic (empty would match all logs)".into(),
            ));
        }
        if from > to {
            return Ok(Vec::new());
        }
        let chunk = chunk.max(1);
        let mut ranges = Vec::new();
        let mut start = from;
        while start <= to {
            let end = start.saturating_add(chunk - 1).min(to);
            ranges.push((start, end));
            if end == u64::MAX {
                break;
            }
            start = end + 1;
        }

        // Dedup incrementally into a HashSet to bound peak memory on busy topics.
        let (set, failed) = stream::iter(ranges.into_iter().map(|(s, e)| {
            let provider = self.provider.clone();
            let topics = topics.clone();
            let retries = self.retries;
            async move { scan_log_window(&provider, &topics, retries, s, e).await }
        }))
        .buffer_unordered(concurrency.max(1))
        .fold(
            (std::collections::HashSet::<Address>::new(), 0u64),
            |(mut set, mut f), (addrs, fw)| async move {
                set.extend(addrs);
                f += fw;
                (set, f)
            },
        )
        .await;

        if failed > 0 {
            tracing::warn!(
                "log scan {from}..={to} incomplete: {failed} block(s) failed after retry/bisection; results may be partial"
            );
        }
        let mut out: Vec<Address> = set.into_iter().collect();
        out.sort();
        Ok(out)
    }

    /// Full logs matching any of `topics` (as topic0) within `[from, to]`, via
    /// chunked + concurrent `eth_getLogs` (same bisect-on-cap behaviour as
    /// [`logs_addresses`]). Returns `(hits, failed_windows)`: one [`LogHit`] per
    /// matching log (sorted by block then address), plus the count of blocks that
    /// still failed after retry/bisection so callers can tell a partial scan from a
    /// complete one (real-time `watch` must not advance past a partial window).
    pub async fn fetch_logs(
        &self,
        from: u64,
        to: u64,
        topics: Vec<B256>,
        chunk: u64,
        concurrency: usize,
    ) -> Result<(Vec<LogHit>, u64)> {
        if topics.is_empty() {
            return Err(AppError::Rpc(
                "fetch_logs requires at least one topic (empty would match all logs)".into(),
            ));
        }
        if from > to {
            return Ok((Vec::new(), 0));
        }
        let chunk = chunk.max(1);
        let mut ranges = Vec::new();
        let mut start = from;
        while start <= to {
            let end = start.saturating_add(chunk - 1).min(to);
            ranges.push((start, end));
            if end == u64::MAX {
                break;
            }
            start = end + 1;
        }

        let (mut hits, failed) = stream::iter(ranges.into_iter().map(|(s, e)| {
            let provider = self.provider.clone();
            let topics = topics.clone();
            let retries = self.retries;
            async move { fetch_log_window(&provider, &topics, retries, s, e).await }
        }))
        .buffer_unordered(concurrency.max(1))
        .fold(
            (Vec::<LogHit>::new(), 0u64),
            |(mut acc, mut f), (hits, fw)| async move {
                acc.extend(hits);
                f += fw;
                (acc, f)
            },
        )
        .await;

        if failed > 0 {
            tracing::warn!(
                "log fetch {from}..={to} incomplete: {failed} block(s) failed after retry/bisection; results may be partial"
            );
        }
        hits.sort_by(|a, b| a.block.cmp(&b.block).then_with(|| a.address.cmp(&b.address)));
        Ok((hits, failed))
    }
}

/// Interpret a 32-byte storage word as a left-padded EVM address (last 20 bytes).
/// Returns `None` if the high 12 bytes are nonzero or the address is zero.
pub fn slot_word_to_address(word: U256) -> Option<Address> {
    let bytes = word.to_be_bytes::<32>();
    if bytes[..12].iter().any(|b| *b != 0) {
        return None;
    }
    let addr = Address::from_slice(&bytes[12..]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

/// Decode the ABI `address[]` a diamond's `facetAddresses()` returns.
///
/// Strict on purpose: the input is a reply from a contract that is *not* known
/// to be a diamond, so anything that is not exactly one dynamic array of
/// addresses decodes to nothing rather than to a guess. A wrong head offset, a
/// length that disagrees with the payload size, or a word with a dirty upper
/// half all mean "this is not a facet list", not "recover what you can".
pub fn parse_facet_addresses(out: &[u8]) -> Vec<Address> {
    if out.len() < 64 {
        return Vec::new();
    }
    // Head: the offset to the array data. A single dynamic return value encodes
    // this as 0x20 and nothing else.
    if U256::from_be_slice(&out[..32]) != U256::from(32u64) {
        return Vec::new();
    }
    let Ok(n) = usize::try_from(U256::from_be_slice(&out[32..64])) else {
        return Vec::new();
    };
    if n == 0 || out.len() != 64 + n * 32 {
        return Vec::new();
    }
    let mut facets = Vec::with_capacity(n);
    for word in out[64..].chunks_exact(32) {
        match slot_word_to_address(U256::from_be_slice(word)) {
            Some(a) => facets.push(a),
            // A zero or dirty word is not an address; the whole list is suspect.
            None => return Vec::new(),
        }
    }
    facets
}

/// Extract successfully-created contract addresses from a `trace_block` result.
///
/// Keeps entries of type `create` that have a `result.address` and no `error`
/// (reverted creations carry an `error` and no address).
pub fn parse_trace_creations(traces: &serde_json::Value) -> Vec<Address> {
    let mut out = Vec::new();
    let Some(arr) = traces.as_array() else {
        return out;
    };
    for t in arr {
        if t.get("type").and_then(|v| v.as_str()) != Some("create") {
            continue;
        }
        if t.get("error").is_some() {
            continue;
        }
        if let Some(addr) = t
            .get("result")
            .and_then(|r| r.get("address"))
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse::<Address>().ok())
        {
            out.push(addr);
        }
    }
    out
}

/// Retry a fallible async operation up to `attempts` times with linear backoff.
async fn with_retry<T, F, Fut>(attempts: u32, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let attempts = attempts.max(1);
    let mut last_err: Option<AppError> = None;
    for attempt in 1..=attempts {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                tracing::debug!("RPC attempt {attempt}/{attempts} failed: {e}");
                last_err = Some(e);
                // No backoff after the final attempt — it is guaranteed to fail.
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_millis(400 * attempt as u64)).await;
                }
            }
        }
    }
    Err(last_err.expect("loop runs at least once"))
}

#[cfg(test)]
mod tests {
    /// A JSON-RPC mock that echoes the request id and answers with one fixed
    /// result, whatever was asked.
    struct Echo(serde_json::Value);
    impl wiremock::Respond for Echo {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let b: serde_json::Value =
                serde_json::from_slice(&req.body).unwrap_or(serde_json::json!({}));
            let id = b.get("id").cloned().unwrap_or(serde_json::json!(1));
            wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"jsonrpc":"2.0","id":id,"result": self.0}),
            )
        }
    }

    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn new_rejects_invalid_url() {
        assert!(matches!(RpcClient::new("", 3), Err(AppError::Rpc(_))));
    }

    #[test]
    fn new_accepts_valid_url() {
        assert!(RpcClient::new("http://localhost:8545", 3).is_ok());
    }

    #[test]
    fn parse_trace_creations_filters_correctly() {
        let traces = serde_json::json!([
            { "type": "create", "result": { "address": "0x000000000000000000000000000000000000c0de" } },
            { "type": "call",   "result": { "address": "0x0000000000000000000000000000000000001111" } },
            { "type": "create", "error": "Reverted" },
            { "type": "create", "result": { "gasUsed": "0x1" } },
            { "type": "create", "result": { "address": "0x0000000000000000000000000000000000002222" } }
        ]);
        let out = parse_trace_creations(&traces);
        assert_eq!(out.len(), 2);
        assert_eq!(
            format!("{:#x}", out[0]),
            "0x000000000000000000000000000000000000c0de"
        );
        assert_eq!(
            format!("{:#x}", out[1]),
            "0x0000000000000000000000000000000000002222"
        );
    }

    #[test]
    fn parse_trace_creations_non_array_is_empty() {
        assert!(parse_trace_creations(&serde_json::json!({"x":1})).is_empty());
    }

    #[test]
    fn slot_word_to_address_extracts_left_padded() {
        // 12 zero bytes + 20-byte address.
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&[0xab; 20]);
        let word = U256::from_be_bytes(bytes);
        assert_eq!(
            slot_word_to_address(word).map(|a| format!("{a:#x}")),
            Some(format!("0x{}", "ab".repeat(20)))
        );
    }

    #[tokio::test]
    async fn logs_addresses_collects_distinct_chunked() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        struct Echo(serde_json::Value);
        impl Respond for Echo {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let b: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or(serde_json::json!({}));
                let id = b.get("id").cloned().unwrap_or(serde_json::json!(1));
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"jsonrpc":"2.0","id":id,"result": self.0}))
            }
        }
        let topic = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e";
        let h32 = format!("0x{}", "1".repeat(64));
        let log = |addr: &str| {
            serde_json::json!({
                "address": addr, "topics": [topic], "data": "0x",
                "blockHash": h32, "blockNumber": "0x1",
                "transactionHash": h32, "transactionIndex": "0x0",
                "logIndex": "0x0", "removed": false
            })
        };
        let server = MockServer::start().await;
        // Every getLogs window returns the same two logs -> deduped to 2.
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!([
                log("0x000000000000000000000000000000000000c0de"),
                log("0x1111111111111111111111111111111111111111")
            ])))
            .mount(&server)
            .await;

        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let topics = vec![topic.parse::<B256>().unwrap()];
        // 0..=9 with chunk 4 -> 3 windows, all same logs -> 2 distinct addresses.
        let got = rpc.logs_addresses(0, 9, topics, 4, 3).await.unwrap();
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn logs_addresses_rejects_empty_topics() {
        let rpc = RpcClient::new("http://localhost:1", 1).unwrap();
        // Empty topics would be a match-everything filter -> rejected, no request made.
        assert!(rpc.logs_addresses(0, 10, vec![], 100, 2).await.is_err());
    }

    #[tokio::test]
    async fn logs_addresses_inverted_range_is_empty() {
        let topic = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"
            .parse::<B256>()
            .unwrap();
        let rpc = RpcClient::new("http://localhost:1", 1).unwrap();
        // from > to -> no windows, no request, empty result.
        assert!(rpc.logs_addresses(100, 50, vec![topic], 100, 2).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn logs_addresses_bisects_to_single_blocks_on_failure() {
        let topic = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"
            .parse::<B256>()
            .unwrap();
        // Dead endpoint: window [0,3] fails -> bisects down to single blocks, all
        // fail -> Ok(empty) (exercises the bisection + single-block-drop path).
        let rpc = RpcClient::new("http://127.0.0.1:1", 1).unwrap();
        assert!(rpc.logs_addresses(0, 3, vec![topic], 4, 2).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_logs_returns_decoded_hits() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
        struct Echo(serde_json::Value);
        impl Respond for Echo {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let b: serde_json::Value =
                    serde_json::from_slice(&req.body).unwrap_or(serde_json::json!({}));
                let id = b.get("id").cloned().unwrap_or(serde_json::json!(1));
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"jsonrpc":"2.0","id":id,"result": self.0}))
            }
        }
        let topic = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
        let impl_word = format!("0x{}{}", "0".repeat(24), "1".repeat(40)); // low 20 bytes = 0x11..11
        let h32 = format!("0x{}", "2".repeat(64));
        let logj = serde_json::json!({
            "address": "0x000000000000000000000000000000000000c0de",
            "topics": [topic, impl_word], "data": "0x",
            "blockHash": h32, "blockNumber": "0x5",
            "transactionHash": h32, "transactionIndex": "0x0",
            "logIndex": "0x0", "removed": false
        });
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!([logj])))
            .mount(&server)
            .await;
        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let topics = vec![topic.parse::<B256>().unwrap()];
        let (hits, failed) = rpc.fetch_logs(5, 5, topics, 100, 1).await.unwrap();
        assert_eq!(failed, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].block, 5);
        assert_eq!(
            format!("{:#x}", hits[0].address),
            "0x000000000000000000000000000000000000c0de"
        );
        assert_eq!(hits[0].topics.len(), 2);
        assert!(hits[0].tx_hash.is_some());
        assert_eq!(hits[0].log_index, Some(0));
    }

    #[tokio::test]
    async fn fetch_logs_rejects_empty_topics_and_inverted_range() {
        let rpc = RpcClient::new("http://localhost:1", 1).unwrap();
        assert!(rpc.fetch_logs(0, 10, vec![], 100, 2).await.is_err());
        let topic = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
            .parse::<B256>()
            .unwrap();
        assert!(rpc.fetch_logs(100, 50, vec![topic], 100, 2).await.unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn fetch_logs_bisects_and_drops_on_failure() {
        let topic = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
            .parse::<B256>()
            .unwrap();
        // Dead endpoint: window [0,3] fails -> bisects to single blocks, all fail ->
        // Ok(empty) (exercises the bisection + single-block-drop + failed-count path).
        let rpc = RpcClient::new("http://127.0.0.1:1", 1).unwrap();
        let (hits, failed) = rpc.fetch_logs(0, 3, vec![topic], 4, 2).await.unwrap();
        assert!(hits.is_empty());
        assert!(failed > 0, "a partial scan must report failed blocks");
    }

    // ---- T-07: the two families that were missing ----

    /// Build an ABI `address[]` return body for `facetAddresses()`.
    fn facet_return(addrs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut word = |v: u64| {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&v.to_be_bytes());
            out.extend_from_slice(&w);
        };
        word(32); // head: offset to the array data
        word(addrs.len() as u64);
        for a in addrs {
            let addr: Address = a.parse().unwrap();
            out.extend_from_slice(&[0u8; 12]);
            out.extend_from_slice(addr.as_slice());
        }
        out
    }

    #[test]
    fn parse_facet_addresses_decodes_a_real_loupe_reply() {
        let body = facet_return(&[
            "0x00000000000000000000000000000000000000f1",
            "0x00000000000000000000000000000000000000f2",
        ]);
        let facets = parse_facet_addresses(&body);
        assert_eq!(facets.len(), 2);
        assert_eq!(format!("{:#x}", facets[0]), "0x00000000000000000000000000000000000000f1");
        assert_eq!(format!("{:#x}", facets[1]), "0x00000000000000000000000000000000000000f2");
    }

    /// The decoder is the whole defence against a fallback function answering
    /// this call with something that merely has the right length.
    #[test]
    fn parse_facet_addresses_rejects_everything_that_is_not_a_facet_list() {
        assert!(parse_facet_addresses(&[]).is_empty(), "empty");
        assert!(parse_facet_addresses(&[0u8; 32]).is_empty(), "one word");
        // A well-formed but empty array is not a diamond either.
        assert!(parse_facet_addresses(&facet_return(&[])).is_empty(), "zero facets");

        // Head offset is not 0x20.
        let mut wrong_head = facet_return(&["0x00000000000000000000000000000000000000f1"]);
        wrong_head[31] = 64;
        assert!(parse_facet_addresses(&wrong_head).is_empty(), "wrong head offset");

        // Length claims two facets, payload carries one.
        let mut short = facet_return(&["0x00000000000000000000000000000000000000f1"]);
        short[63] = 2;
        assert!(parse_facet_addresses(&short).is_empty(), "length disagrees with payload");

        // An address word with a dirty upper half.
        let mut dirty = facet_return(&["0x00000000000000000000000000000000000000f1"]);
        dirty[64] = 0xff;
        assert!(parse_facet_addresses(&dirty).is_empty(), "dirty upper bytes");

        // A zero address is not a facet.
        assert!(
            parse_facet_addresses(&facet_return(&["0x0000000000000000000000000000000000000000"]))
                .is_empty(),
            "zero facet"
        );
    }

    /// Positive: every standard slot is empty and the loupe answers.
    #[tokio::test]
    async fn resolve_diamond_recognises_a_loupe_reply() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer};

        let body = facet_return(&[
            "0x00000000000000000000000000000000000000f1",
            "0x00000000000000000000000000000000000000f2",
        ]);
        let hex = format!("0x{}", body.iter().map(|b| format!("{b:02x}")).collect::<String>());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!(hex)))
            .mount(&server)
            .await;

        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let addr: Address = "0x000000000000000000000000000000000000c0de".parse().unwrap();
        let p = rpc.resolve_diamond(addr).await.expect("a diamond");
        assert_eq!(p.kind, "EIP-2535");
        assert_eq!(format!("{:#x}", p.target), "0x00000000000000000000000000000000000000f1");
    }

    /// Negative: a contract with a fallback that returns a plausible-looking
    /// word is not a diamond, and neither is one that reverts.
    #[tokio::test]
    async fn resolve_diamond_refuses_a_non_loupe_reply() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!(format!("0x{}", "11".repeat(32)))))
            .mount(&server)
            .await;
        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let addr: Address = "0x000000000000000000000000000000000000c0de".parse().unwrap();
        assert!(rpc.resolve_diamond(addr).await.is_none(), "a stray word is not a facet list");

        // A dead endpoint stands in for a revert: both are "no answer", and
        // neither may fail the scan.
        let dead = RpcClient::new("http://127.0.0.1:1", 1).unwrap();
        assert!(dead.resolve_diamond(addr).await.is_none());
    }

    /// Positive: the three standard slots are empty, the pre-standard one is set.
    #[tokio::test]
    async fn resolve_storage_proxy_reads_the_pre_standard_slot() {
        use wiremock::matchers::{body_string_contains, method};
        use wiremock::{Mock, MockServer};

        let zero = format!("0x{}", "0".repeat(64));
        let legacy = format!("0x{}{}", "0".repeat(24), "00000000000000000000000000000000000000a1");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3",
            ))
            .respond_with(Echo(serde_json::json!(legacy)))
            .mount(&server)
            .await;
        // Everything else — the three standard slots — reads empty.
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!(zero)))
            .mount(&server)
            .await;

        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let addr: Address = "0x000000000000000000000000000000000000c0de".parse().unwrap();
        let p = rpc.resolve_storage_proxy(addr).await.unwrap().unwrap();
        assert_eq!(p.kind, "zeppelinos-legacy");
        assert_eq!(format!("{:#x}", p.target), "0x00000000000000000000000000000000000000a1");
    }

    /// Negative, and the reason the standard slots are read first: a proxy
    /// upgraded from the pre-standard layout can have both set, and the live
    /// pointer is the standard one.
    #[tokio::test]
    async fn the_standard_slot_wins_over_the_pre_standard_one() {
        use wiremock::matchers::{body_string_contains, method};
        use wiremock::{Mock, MockServer};

        let standard = format!("0x{}{}", "0".repeat(24), "00000000000000000000000000000000000000b2");
        let stale = format!("0x{}{}", "0".repeat(24), "00000000000000000000000000000000000000a1");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains(
                "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            ))
            .respond_with(Echo(serde_json::json!(standard)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(Echo(serde_json::json!(stale)))
            .mount(&server)
            .await;

        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let addr: Address = "0x000000000000000000000000000000000000c0de".parse().unwrap();
        let p = rpc.resolve_storage_proxy(addr).await.unwrap().unwrap();
        assert_eq!(p.kind, "EIP-1967");
        assert_eq!(format!("{:#x}", p.target), "0x00000000000000000000000000000000000000b2");
    }

    #[tokio::test]
    async fn resolve_storage_proxy_beacon_resolves_implementation() {
        use wiremock::matchers::{body_string_contains, method};
        use wiremock::{Mock, MockServer};

        let zero = format!("0x{}", "0".repeat(64));
        let beacon_word = format!("0x{}{}", "0".repeat(24), "00000000000000000000000000000000000000be");
        let impl_word = format!("0x{}{}", "0".repeat(24), "00000000000000000000000000000000000000ad");

        let server = MockServer::start().await;
        // EIP-1967 impl slot -> zero (forces the beacon branch).
        Mock::given(method("POST"))
            .and(body_string_contains(
                "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            ))
            .respond_with(Echo(serde_json::json!(zero)))
            .mount(&server)
            .await;
        // Beacon slot -> beacon contract address.
        Mock::given(method("POST"))
            .and(body_string_contains(
                "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
            ))
            .respond_with(Echo(serde_json::json!(beacon_word)))
            .mount(&server)
            .await;
        // beacon.implementation() eth_call -> the real logic address.
        Mock::given(method("POST"))
            .and(body_string_contains("eth_call"))
            .respond_with(Echo(serde_json::json!(impl_word)))
            .mount(&server)
            .await;

        let rpc = RpcClient::new(&server.uri(), 2).unwrap();
        let addr: Address = "0x000000000000000000000000000000000000c0de".parse().unwrap();
        let p = rpc.resolve_storage_proxy(addr).await.unwrap().unwrap();
        assert_eq!(p.kind, "EIP-1967-beacon");
        // Resolved through the beacon to the implementation, not the beacon addr.
        assert_eq!(
            format!("{:#x}", p.target),
            "0x00000000000000000000000000000000000000ad"
        );
    }

    #[test]
    fn slot_word_to_address_rejects_zero_and_dirty_high_bytes() {
        assert!(slot_word_to_address(U256::ZERO).is_none());
        // High byte set -> not an address word.
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[31] = 1;
        assert!(slot_word_to_address(U256::from_be_bytes(bytes)).is_none());
    }

    #[tokio::test]
    async fn with_retry_succeeds_first_try() {
        let calls = AtomicU32::new(0);
        let v = with_retry(3, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<_, AppError>(7)
        })
        .await
        .unwrap();
        assert_eq!(v, 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn with_retry_succeeds_after_failures() {
        let calls = AtomicU32::new(0);
        let v = with_retry(3, || async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(AppError::Rpc("transient".into()))
            } else {
                Ok(99)
            }
        })
        .await
        .unwrap();
        assert_eq!(v, 99);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn with_retry_exhausts_and_returns_last_error() {
        let calls = AtomicU32::new(0);
        let r: Result<u32> = with_retry(3, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Rpc("always".into()))
        })
        .await;
        assert!(r.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
