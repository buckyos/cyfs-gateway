use async_trait::async_trait;

use crate::{
    AliasState, BnsIndexerResult, ContractEventEnvelope, DocumentState, DocumentUpdate,
    IndexerCursor, NameState, PurchaseContext, RegisterOptions,
};

#[async_trait]
pub trait BnsContractView: Send + Sync {
    async fn query_name_state(&self, name: &str) -> BnsIndexerResult<Option<NameState>>;

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<Option<DocumentState>>;

    async fn get_alias(&self, _name: &str) -> BnsIndexerResult<Option<AliasState>> {
        Ok(None)
    }

    async fn get_purchase_context(
        &self,
        _content_name: &str,
        _doc_type: &str,
    ) -> BnsIndexerResult<Option<PurchaseContext>> {
        Ok(None)
    }
}

#[async_trait]
pub trait BnsContractWriter: BnsContractView {
    async fn register_name(
        &self,
        name: &str,
        asset_owner: &str,
        options: &RegisterOptions,
        initial_documents: &[DocumentUpdate],
    ) -> BnsIndexerResult<u64>;
}

#[async_trait]
pub trait BnsContractEventSource: Send + Sync {
    async fn fetch_events(
        &self,
        source: &str,
        cursor: Option<&IndexerCursor>,
        limit: usize,
    ) -> BnsIndexerResult<Vec<ContractEventEnvelope>>;
}
