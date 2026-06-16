mod common;

use async_trait::async_trait;
use bns_indexer::{
    AliasState, BnsContractView, BnsDb, BnsIndexer, BnsIndexerResult, DocumentState, NameState,
    ReconciliationAction, SqliteBnsDb, ValidationStatus,
};
use common::{sample_alias_state, sample_document_state, sample_name_state};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
struct MockContract {
    names: HashMap<String, NameState>,
    documents: HashMap<(String, String, u64), DocumentState>,
    aliases: HashMap<String, AliasState>,
}

#[async_trait]
impl BnsContractView for MockContract {
    async fn query_name_state(&self, name: &str) -> BnsIndexerResult<Option<NameState>> {
        Ok(self.names.get(name).cloned())
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<Option<DocumentState>> {
        Ok(self
            .documents
            .get(&(name.to_string(), doc_type.to_string(), version))
            .cloned())
    }

    async fn get_alias(&self, name: &str) -> BnsIndexerResult<Option<AliasState>> {
        Ok(self.aliases.get(name).cloned())
    }
}

#[tokio::test]
async fn indexer_reports_contract_mismatch_without_changing_db_truth() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let db_name = sample_name_state("alice");
    db.put_name_state(&db_name).unwrap();
    db.put_document_state(&sample_document_state("alice", "owner", 1))
        .unwrap();

    let mut contract_name = db_name.clone();
    contract_name.asset_owner = "0x3333333333333333333333333333333333333333".to_string();

    let mut contract = MockContract::default();
    contract.names.insert("alice".to_string(), contract_name);
    contract.documents.insert(
        ("alice".to_string(), "owner".to_string(), 1),
        sample_document_state("alice", "owner", 1),
    );

    let indexer = BnsIndexer::new(db.clone(), Arc::new(contract));
    let report = indexer.validate_name_state("alice").await.unwrap();

    assert_eq!(report.status, ValidationStatus::Mismatch);
    assert_eq!(report.mismatches[0].path, "$.asset_owner");
    assert_eq!(
        indexer.reconciliation_plan(&report).action,
        ReconciliationAction::ManualReview
    );
    assert_eq!(db.list_validation_reports(10).unwrap().len(), 1);
}

#[tokio::test]
async fn indexer_validates_name_bundle_from_db() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let name = sample_name_state("alice");
    let document = sample_document_state("alice", "owner", 1);
    let alias = sample_alias_state("alice", "did:bns:alice2");
    db.put_name_state(&name).unwrap();
    db.put_document_state(&document).unwrap();
    db.put_alias_state(&alias).unwrap();

    let mut contract = MockContract::default();
    contract.names.insert("alice".to_string(), name);
    contract
        .documents
        .insert(("alice".to_string(), "owner".to_string(), 1), document);
    contract.aliases.insert("alice".to_string(), alias);

    let indexer = BnsIndexer::new(db.clone(), Arc::new(contract));
    let reports = indexer.validate_name_from_db("alice").await.unwrap();

    assert_eq!(reports.len(), 3);
    assert!(reports.iter().all(|report| report.is_consistent()));
}
