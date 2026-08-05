use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use alloy_primitives::{address, Address, Bytes, B256};
use alloy_sol_types::{sol, SolCall};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    BnsEvmError, BnsEvmResult, Eip1559FeeSuggestion, EthBlock, EthLog, EthRpcClient,
    EthTransaction, EthTransactionReceipt, RpcLogFilter,
};

sol! {
    interface Multicall3 {
        struct Call {
            address target;
            bytes callData;
        }

        function aggregate(Call[] calldata calls)
            external
            payable
            returns (uint256 blockNumber, bytes[] memory returnData);
    }
}

pub const MULTICALL3_ADDRESS: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");
const PENDING_TRANSACTION_TTL: Duration = Duration::from_secs(2);
const NOT_FOUND_TRANSACTION_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRead {
    pub target: Address,
    pub calldata: Bytes,
}

#[derive(Debug, Clone)]
pub enum TransactionLookup {
    Mined(EthTransactionReceipt),
    Pending,
    NotFound,
}

#[derive(Debug, Clone)]
struct CachedTransactionLookup {
    state: TransactionLookup,
    expires_at: Option<Instant>,
}

impl ContractRead {
    pub fn new<C>(target: Address, call: &C) -> Self
    where
        C: SolCall,
    {
        Self {
            target,
            calldata: call.abi_encode().into(),
        }
    }
}

pub fn decode_contract_return<C>(output: &[u8]) -> BnsEvmResult<C::Return>
where
    C: SolCall,
{
    C::abi_decode_returns(output).map_err(|err| BnsEvmError::Abi(err.to_string()))
}

/// Shared entry point for all long-lived BNS service access to an EVM chain.
///
/// The first implementation intentionally delegates one-for-one to the
/// existing transport. Later optimizations can therefore be contained here
/// without changing the indexer or server public APIs.
#[derive(Debug)]
pub struct BnsChainClient {
    rpc: EthRpcClient,
    expected_chain_id: Option<u64>,
    contract_address: Option<Address>,
    chain_id: OnceLock<u64>,
    latest_block: Mutex<Option<EthBlock>>,
    transaction_cache: Mutex<HashMap<B256, CachedTransactionLookup>>,
    transaction_locks: Mutex<HashMap<B256, Arc<tokio::sync::Mutex<()>>>>,
}

impl BnsChainClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            rpc: EthRpcClient::new(endpoint),
            expected_chain_id: None,
            contract_address: None,
            chain_id: OnceLock::new(),
            latest_block: Mutex::new(None),
            transaction_cache: Mutex::new(HashMap::new()),
            transaction_locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_with_chain_config(
        endpoint: impl Into<String>,
        contract_address: Address,
        chain_id: u64,
    ) -> Self {
        Self {
            rpc: EthRpcClient::new(endpoint),
            expected_chain_id: Some(chain_id),
            contract_address: Some(contract_address),
            chain_id: OnceLock::new(),
            latest_block: Mutex::new(None),
            transaction_cache: Mutex::new(HashMap::new()),
            transaction_locks: Mutex::new(HashMap::new()),
        }
    }

    pub fn endpoint(&self) -> &str {
        self.rpc.endpoint()
    }

    /// Compatibility access for callers that still need the raw transport.
    pub fn rpc(&self) -> &EthRpcClient {
        &self.rpc
    }

    pub fn configured_chain_id(&self) -> Option<u64> {
        self.expected_chain_id
    }

    pub fn contract_address(&self) -> Option<Address> {
        self.contract_address
    }

    pub async fn validate_chain(&self) -> BnsEvmResult<()> {
        self.chain_id().await.map(|_| ())
    }

    pub async fn chain_id(&self) -> BnsEvmResult<u64> {
        if let Some(chain_id) = self.chain_id.get() {
            return Ok(*chain_id);
        }
        let actual = self.rpc.chain_id().await?;
        if let Some(expected) = self.expected_chain_id {
            if actual != expected {
                return Err(BnsEvmError::Rpc(format!(
                    "BNS chain id mismatch: configured {expected}, RPC returned {actual}"
                )));
            }
        }
        let _ = self.chain_id.set(actual);
        Ok(actual)
    }

    pub async fn block_number(&self) -> BnsEvmResult<u64> {
        self.rpc.block_number().await
    }

    /// Return the latest header and whether it differs from the previously
    /// cached header. Backlog processing can pass `false` to reuse one head.
    pub async fn latest_block(&self, refresh: bool) -> BnsEvmResult<(EthBlock, bool)> {
        if !refresh {
            if let Some(block) = self.latest_block.lock().unwrap().clone() {
                return Ok((block, false));
            }
        }

        let block = self
            .rpc
            .latest_block()
            .await?
            .ok_or_else(|| BnsEvmError::Rpc("latest EVM block is missing".to_string()))?;
        let mut cached = self.latest_block.lock().unwrap();
        let reorg_from = cached
            .as_ref()
            .and_then(|previous| reorg_invalidation_start(previous, &block));
        let changed = cached.as_ref() != Some(&block);
        *cached = Some(block.clone());
        drop(cached);
        if let Some(block_number) = reorg_from {
            self.invalidate_mined_receipts_from(block_number);
        }
        Ok((block, changed))
    }

    pub fn cached_latest_block(&self) -> Option<EthBlock> {
        self.latest_block.lock().unwrap().clone()
    }

    pub async fn transaction_lookup(&self, tx_hash: B256) -> BnsEvmResult<TransactionLookup> {
        if let Some(state) = self.cached_transaction_lookup(tx_hash) {
            return Ok(state);
        }

        let lock = {
            let mut locks = self.transaction_locks.lock().unwrap();
            locks
                .entry(tx_hash)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = lock.lock().await;
        if let Some(state) = self.cached_transaction_lookup(tx_hash) {
            drop(guard);
            self.remove_unused_transaction_lock(tx_hash, &lock);
            return Ok(state);
        }

        let state = match self.rpc.transaction_receipt(tx_hash).await? {
            Some(receipt) => TransactionLookup::Mined(receipt),
            None => match self.rpc.transaction_by_hash(tx_hash).await? {
                Some(_) => TransactionLookup::Pending,
                None => TransactionLookup::NotFound,
            },
        };
        let expires_at = match state {
            TransactionLookup::Mined(_) => None,
            TransactionLookup::Pending => Some(Instant::now() + PENDING_TRANSACTION_TTL),
            TransactionLookup::NotFound => Some(Instant::now() + NOT_FOUND_TRANSACTION_TTL),
        };
        self.transaction_cache.lock().unwrap().insert(
            tx_hash,
            CachedTransactionLookup {
                state: state.clone(),
                expires_at,
            },
        );
        drop(guard);
        self.remove_unused_transaction_lock(tx_hash, &lock);
        Ok(state)
    }

    pub fn invalidate_mined_receipts_from(&self, block_number: u64) {
        self.transaction_cache
            .lock()
            .unwrap()
            .retain(|_, cached| match &cached.state {
                TransactionLookup::Mined(receipt) => receipt
                    .block_number
                    .is_none_or(|number| number < block_number),
                TransactionLookup::Pending | TransactionLookup::NotFound => true,
            });
    }

    fn cached_transaction_lookup(&self, tx_hash: B256) -> Option<TransactionLookup> {
        let now = Instant::now();
        let mut cache = self.transaction_cache.lock().unwrap();
        let expired = cache
            .get(&tx_hash)
            .and_then(|cached| cached.expires_at)
            .is_some_and(|expires_at| expires_at <= now);
        if expired {
            cache.remove(&tx_hash);
            return None;
        }
        cache.get(&tx_hash).map(|cached| cached.state.clone())
    }

    fn remove_unused_transaction_lock(&self, tx_hash: B256, lock: &Arc<tokio::sync::Mutex<()>>) {
        let mut locks = self.transaction_locks.lock().unwrap();
        if Arc::strong_count(lock) == 2 {
            locks.remove(&tx_hash);
        }
    }

    pub async fn transaction_count(&self, address: Address) -> BnsEvmResult<u64> {
        self.rpc.transaction_count(address).await
    }

    pub async fn gas_price(&self) -> BnsEvmResult<u128> {
        self.rpc.gas_price().await
    }

    pub async fn max_priority_fee_per_gas(&self) -> BnsEvmResult<u128> {
        self.rpc.max_priority_fee_per_gas().await
    }

    pub async fn suggest_eip1559_fees(&self) -> BnsEvmResult<Eip1559FeeSuggestion> {
        self.rpc.suggest_eip1559_fees().await
    }

    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        calldata: &[u8],
    ) -> BnsEvmResult<u64> {
        self.rpc.estimate_gas(from, to, calldata).await
    }

    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> BnsEvmResult<B256> {
        self.rpc.send_raw_transaction(raw_tx).await
    }

    pub async fn eth_call(&self, to: Address, calldata: &[u8]) -> BnsEvmResult<Bytes> {
        self.rpc.eth_call(to, calldata).await
    }

    pub async fn call_contract<C>(&self, to: Address, call: &C) -> BnsEvmResult<C::Return>
    where
        C: SolCall,
    {
        self.rpc.call_contract(to, call).await
    }

    /// Execute independent latest-state reads through Multicall3.
    ///
    /// A missing or incompatible Multicall3 deployment is transparent to
    /// callers: the original calls are replayed individually in order.
    pub async fn multicall(&self, calls: &[ContractRead]) -> BnsEvmResult<Vec<Bytes>> {
        if calls.len() <= 1 {
            return self.call_individually(calls).await;
        }

        let aggregate = Multicall3::aggregateCall {
            calls: calls
                .iter()
                .map(|call| Multicall3::Call {
                    target: call.target,
                    callData: call.calldata.clone(),
                })
                .collect(),
        };
        if let Ok(result) = self.rpc.call_contract(MULTICALL3_ADDRESS, &aggregate).await {
            if result.returnData.len() == calls.len() {
                return Ok(result.returnData);
            }
        }

        self.call_individually(calls).await
    }

    async fn call_individually(&self, calls: &[ContractRead]) -> BnsEvmResult<Vec<Bytes>> {
        let mut outputs = Vec::with_capacity(calls.len());
        for call in calls {
            outputs.push(self.rpc.eth_call(call.target, &call.calldata).await?);
        }
        Ok(outputs)
    }

    pub async fn get_logs(&self, filter: &RpcLogFilter) -> BnsEvmResult<Vec<EthLog>> {
        self.rpc.get_logs(filter).await
    }

    pub async fn block_by_number(&self, block_number: u64) -> BnsEvmResult<Option<EthBlock>> {
        self.rpc.block_by_number(block_number).await
    }

    pub async fn transaction_by_hash(&self, tx_hash: B256) -> BnsEvmResult<Option<EthTransaction>> {
        self.rpc.transaction_by_hash(tx_hash).await
    }

    pub async fn transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> BnsEvmResult<Option<EthTransactionReceipt>> {
        self.rpc.transaction_receipt(tx_hash).await
    }

    pub async fn call<R>(&self, method: &str, params: Value) -> BnsEvmResult<R>
    where
        R: DeserializeOwned,
    {
        self.rpc.call(method, params).await
    }

    pub async fn call_nullable<R>(&self, method: &str, params: Value) -> BnsEvmResult<Option<R>>
    where
        R: DeserializeOwned,
    {
        self.rpc.call_nullable(method, params).await
    }
}

fn reorg_invalidation_start(previous: &EthBlock, current: &EthBlock) -> Option<u64> {
    match (previous.number, current.number) {
        (Some(previous_number), Some(current_number)) if current_number < previous_number => {
            Some(current_number.saturating_add(1))
        }
        (Some(previous_number), Some(current_number))
            if current_number == previous_number && current.hash != previous.hash =>
        {
            Some(current_number)
        }
        (Some(previous_number), Some(current_number))
            if current_number == previous_number.saturating_add(1)
                && current.parent_hash != previous.hash =>
        {
            Some(0)
        }
        _ => None,
    }
}
