mod common;

use async_trait::async_trait;
use bns_indexer::{
    AliasState, BnsContractView, BnsDb, BnsIndexer, BnsIndexerResult, DocumentState,
    DocumentStatus, NameState, Principal, PurchaseContext, ReconciliationAction, SqliteBnsDb,
    ValidationStatus, ValidationTarget, ZERO_HASH,
};
use common::{sample_alias_state, sample_document_state, sample_name_state};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
struct MockContract {
    names: HashMap<String, NameState>,
    documents: HashMap<(String, String, u64), DocumentState>,
    aliases: HashMap<String, AliasState>,
    purchase_contexts: HashMap<(String, String), PurchaseContext>,
}

fn sample_purchase_context(
    content_name: &str,
    doc_type: &str,
    document_version: u64,
    beneficiary_name: &str,
) -> PurchaseContext {
    PurchaseContext {
        content_name: content_name.to_string(),
        doc_type: doc_type.to_string(),
        document_version,
        beneficiary: Principal::did(format!("did:bns:{}", beneficiary_name)),
        payment_target: "0x2222222222222222222222222222222222222222".to_string(),
        split_policy_hash: ZERO_HASH.to_string(),
        price_policy_hash: ZERO_HASH.to_string(),
        rights_policy_hash: ZERO_HASH.to_string(),
        status: DocumentStatus::Active,
        proof_root: ZERO_HASH.to_string(),
    }
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

    async fn get_purchase_context(
        &self,
        content_name: &str,
        doc_type: &str,
    ) -> BnsIndexerResult<Option<PurchaseContext>> {
        Ok(self
            .purchase_contexts
            .get(&(content_name.to_string(), doc_type.to_string()))
            .cloned())
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

#[tokio::test]
async fn indexer_uses_name_doc_type_version_as_document_key() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let name = sample_name_state("alice");
    db.put_name_state(&name).unwrap();

    let mut contract = MockContract::default();
    contract.names.insert("alice".to_string(), name);

    for doc_type in ["owner", "boot", "zone", "service"] {
        let document = sample_document_state("alice", doc_type, 1);
        db.put_document_state(&document).unwrap();
        contract
            .documents
            .insert(("alice".to_string(), doc_type.to_string(), 1), document);
    }

    let indexer = BnsIndexer::new(db, Arc::new(contract));
    let reports = indexer.validate_name_from_db("alice").await.unwrap();
    let document_types: Vec<&str> = reports
        .iter()
        .filter_map(|report| match &report.target {
            ValidationTarget::Document { doc_type, .. } => Some(doc_type.as_str()),
            _ => None,
        })
        .collect();

    assert_eq!(reports.len(), 5);
    assert_eq!(document_types, vec!["boot", "owner", "service", "zone"]);
    assert!(reports.iter().all(|report| report.is_consistent()));
}

#[tokio::test]
async fn indexer_validates_zone_and_gateway_device_documents_separately() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let alice = sample_name_state("alice");
    let gateway = sample_name_state("ood1.alice");
    db.put_name_state(&alice).unwrap();
    db.put_name_state(&gateway).unwrap();

    let mut contract = MockContract::default();
    contract.names.insert("alice".to_string(), alice);
    contract.names.insert("ood1.alice".to_string(), gateway);

    for (name, doc_type) in [
        ("alice", "boot"),
        ("alice", "zone"),
        ("ood1.alice", "doc"),
        ("ood1.alice", "info"),
    ] {
        let document = sample_document_state(name, doc_type, 1);
        db.put_document_state(&document).unwrap();
        contract
            .documents
            .insert((name.to_string(), doc_type.to_string(), 1), document);
    }

    let indexer = BnsIndexer::new(db, Arc::new(contract));

    for (name, doc_type) in [
        ("alice", "boot"),
        ("alice", "zone"),
        ("ood1.alice", "doc"),
        ("ood1.alice", "info"),
    ] {
        let report = indexer
            .validate_document_state(name, doc_type, 1)
            .await
            .unwrap();
        assert!(report.is_consistent(), "{name} {doc_type} should validate");
    }
}

#[tokio::test]
async fn indexer_detects_silent_purchase_context_rewrite_after_content_transfer() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let name = sample_name_state("book1.alice");
    let doc_v1 = sample_document_state("book1.alice", "content", 1);
    let doc_v2 = sample_document_state("book1.alice", "content", 2);
    let db_purchase = sample_purchase_context("book1.alice", "content", 1, "alice");

    db.put_name_state(&name).unwrap();
    db.put_document_state(&doc_v1).unwrap();
    db.put_document_state(&doc_v2).unwrap();
    db.put_purchase_context(&db_purchase).unwrap();

    let mut contract_purchase =
        sample_purchase_context("book1.alice", "content", 2, "publisher-team");
    contract_purchase.payment_target = "0x3333333333333333333333333333333333333333".to_string();

    let mut contract = MockContract::default();
    contract.names.insert("book1.alice".to_string(), name);
    contract.documents.insert(
        ("book1.alice".to_string(), "content".to_string(), 1),
        doc_v1,
    );
    contract.documents.insert(
        ("book1.alice".to_string(), "content".to_string(), 2),
        doc_v2,
    );
    contract.purchase_contexts.insert(
        ("book1.alice".to_string(), "content".to_string()),
        contract_purchase,
    );

    let indexer = BnsIndexer::new(db, Arc::new(contract));
    let report = indexer
        .validate_purchase_context("book1.alice", "content")
        .await
        .unwrap();
    let mismatch_paths: Vec<&str> = report
        .mismatches
        .iter()
        .map(|mismatch| mismatch.path.as_str())
        .collect();

    assert_eq!(report.status, ValidationStatus::Mismatch);
    assert!(mismatch_paths.contains(&"$.document_version"));
    assert!(mismatch_paths.contains(&"$.beneficiary.value"));
    assert_eq!(
        indexer.reconciliation_plan(&report).action,
        ReconciliationAction::ManualReview
    );
}

#[tokio::test]
async fn indexer_validates_migrated_alias_state() {
    let db = Arc::new(SqliteBnsDb::open_memory().unwrap());
    let alias = sample_alias_state("jarvis.alice", "did:bns:jarvis");
    db.put_alias_state(&alias).unwrap();

    let mut contract = MockContract::default();
    contract.aliases.insert("jarvis.alice".to_string(), alias);

    let indexer = BnsIndexer::new(db, Arc::new(contract));
    let report = indexer.validate_alias_state("jarvis.alice").await.unwrap();

    assert!(report.is_consistent());
    assert_eq!(
        report.target,
        ValidationTarget::Alias {
            name: "jarvis.alice".to_string()
        }
    );
}
