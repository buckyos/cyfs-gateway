mod common;

use bns_indexer::{
    now_timestamp, BnsDb, ContractEvent, ContractEventEnvelope, IndexerCursor, SqliteBnsDb,
};
use common::{sample_alias_state, sample_document_state, sample_name_state};

#[test]
fn sqlite_persists_bns_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bns.sqlite3");

    {
        let db = SqliteBnsDb::open(&path).unwrap();
        let name = sample_name_state("alice");
        db.put_name_state(&name).unwrap();

        let doc_v1 = sample_document_state("alice", "owner", 1);
        let doc_v2 = sample_document_state("alice", "owner", 2);
        db.put_document_state(&doc_v2).unwrap();
        db.put_document_state(&doc_v1).unwrap();

        let alias = sample_alias_state("alice", "did:bns:alice2");
        db.put_alias_state(&alias).unwrap();
    }

    let db = SqliteBnsDb::open(&path).unwrap();
    assert_eq!(
        db.get_name_state("alice").unwrap().unwrap().asset_owner,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        db.get_current_document_state("alice", "owner")
            .unwrap()
            .unwrap()
            .version,
        2
    );
    assert_eq!(db.list_document_keys(Some("alice")).unwrap().len(), 2);
    assert_eq!(
        db.get_alias_state("alice").unwrap().unwrap().target_did,
        "did:bns:alice2"
    );
}

#[test]
fn sqlite_rejects_non_canonical_names() {
    let db = SqliteBnsDb::open_memory().unwrap();
    let mut name = sample_name_state("Alice");
    assert!(db.put_name_state(&name).is_err());

    name.name = "did:bns:alice".to_string();
    assert!(db.put_name_state(&name).is_err());
}

#[test]
fn sqlite_records_contract_events_and_cursor() {
    let db = SqliteBnsDb::open_memory().unwrap();
    let event = ContractEventEnvelope {
        source: "bns-mainnet".to_string(),
        block_number: 42,
        block_hash: Some("0xabc".to_string()),
        tx_hash: "0xtx".to_string(),
        log_index: 7,
        observed_at: now_timestamp(),
        event: ContractEvent::NameRegistered {
            name: "alice".to_string(),
            asset_owner: "0x1111111111111111111111111111111111111111".to_string(),
            expire_at: 1_000,
            name_seq: 1,
        },
    };
    db.record_contract_event(&event).unwrap();

    let cursor = IndexerCursor {
        source: "bns-mainnet".to_string(),
        block_number: 42,
        block_hash: Some("0xabc".to_string()),
        log_index: 7,
        updated_at: now_timestamp(),
    };
    db.put_indexer_cursor(&cursor).unwrap();

    assert_eq!(
        db.list_contract_events("bns-mainnet", 0, 10).unwrap()[0].tx_hash,
        "0xtx"
    );
    assert_eq!(
        db.get_indexer_cursor("bns-mainnet")
            .unwrap()
            .unwrap()
            .log_index,
        7
    );
}
