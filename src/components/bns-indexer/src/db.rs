use crate::{
    AliasState, BnsIndexerResult, ContractEventEnvelope, DocumentKey, DocumentState, IndexerCursor,
    NameState, PurchaseContext, ValidationReport,
};

pub trait BnsDb: Send + Sync {
    fn put_name_state(&self, state: &NameState) -> BnsIndexerResult<()>;
    fn get_name_state(&self, name: &str) -> BnsIndexerResult<Option<NameState>>;
    fn list_names(&self) -> BnsIndexerResult<Vec<String>>;

    fn put_document_state(&self, state: &DocumentState) -> BnsIndexerResult<()>;
    fn get_document_state(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<Option<DocumentState>>;
    fn get_current_document_state(
        &self,
        name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<Option<DocumentState>>;
    fn list_document_keys(&self, name: Option<&str>) -> BnsIndexerResult<Vec<DocumentKey>>;

    fn put_alias_state(&self, state: &AliasState) -> BnsIndexerResult<()>;
    fn get_alias_state(&self, name: &str) -> BnsIndexerResult<Option<AliasState>>;

    fn put_purchase_context(&self, context: &PurchaseContext) -> BnsIndexerResult<()>;
    fn get_purchase_context(
        &self,
        content_name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<Option<PurchaseContext>>;

    fn record_contract_event(&self, event: &ContractEventEnvelope) -> BnsIndexerResult<()>;
    fn list_contract_events(
        &self,
        source: &str,
        from_block: u64,
        limit: usize,
    ) -> BnsIndexerResult<Vec<ContractEventEnvelope>>;

    fn get_indexer_cursor(&self, source: &str) -> BnsIndexerResult<Option<IndexerCursor>>;
    fn put_indexer_cursor(&self, cursor: &IndexerCursor) -> BnsIndexerResult<()>;

    fn put_validation_report(&self, report: &ValidationReport) -> BnsIndexerResult<()>;
    fn list_validation_reports(&self, limit: usize) -> BnsIndexerResult<Vec<ValidationReport>>;
}
