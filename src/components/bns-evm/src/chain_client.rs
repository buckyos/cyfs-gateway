use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolCall;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    BnsEvmResult, Eip1559FeeSuggestion, EthBlock, EthLog, EthRpcClient, EthTransaction,
    EthTransactionReceipt, RpcLogFilter,
};

/// Shared entry point for all long-lived BNS service access to an EVM chain.
///
/// The first implementation intentionally delegates one-for-one to the
/// existing transport. Later optimizations can therefore be contained here
/// without changing the indexer or server public APIs.
#[derive(Debug)]
pub struct BnsChainClient {
    rpc: EthRpcClient,
}

impl BnsChainClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            rpc: EthRpcClient::new(endpoint),
        }
    }

    pub fn endpoint(&self) -> &str {
        self.rpc.endpoint()
    }

    /// Compatibility access for callers that still need the raw transport.
    pub fn rpc(&self) -> &EthRpcClient {
        &self.rpc
    }

    pub async fn chain_id(&self) -> BnsEvmResult<u64> {
        self.rpc.chain_id().await
    }

    pub async fn block_number(&self) -> BnsEvmResult<u64> {
        self.rpc.block_number().await
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
