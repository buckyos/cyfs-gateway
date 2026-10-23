//! SN-BNS transaction state persistence: a fully signed raw transaction is
//! inserted as Sending, then advanced with CAS to Pending and a receipt-backed
//! terminal state.

use bns_client::{
    BnsEvmPreparedTx, BnsWriteOperation, BnsWriteRequestState, MemorySnBnsWriteRequestStore,
    SnBnsControllerError, SnBnsTryBeginResult, SnBnsWriteRequestRecord, SnBnsWriteRequestStore,
    SqliteSnBnsWriteRequestStore, EVM_TX_RECOVERY_DATA_INVALID,
};
use rusqlite::Connection;
use serde_json::json;
use std::sync::{Arc, Barrier};

fn prepared_record(request_id: &str, created_at: u64) -> SnBnsWriteRequestRecord {
    SnBnsWriteRequestRecord {
        request_id: request_id.to_string(),
        operation: BnsWriteOperation::PublishDocument,
        name: "alice".to_string(),
        doc_type: Some("dns_txt".to_string()),
        payload_hash: "0xabc".to_string(),
        state: BnsWriteRequestState::Sending,
        result_json: Some(json!({ "name_seq": 3 })),
        error_code: None,
        error_message: None,
        lease_owner: None,
        lease_expires_at: None,
        evm_chain_id: Some(31_337),
        evm_nonce: Some(7),
        evm_tx_hash: Some("0xdeadbeef".to_string()),
        evm_raw_tx: Some("0x02f8raw".to_string()),
        created_at,
        updated_at: created_at,
    }
}

#[test]
fn sending_pending_and_terminal_states_round_trip() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();
    let mut record = prepared_record("req-1", 100);
    assert!(matches!(
        store.try_begin(record.clone()).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));

    let inflight = store.list_inflight().unwrap();
    assert_eq!(inflight.len(), 1);
    assert_eq!(inflight[0].state, BnsWriteRequestState::Sending);

    record.state = BnsWriteRequestState::Pending;
    record.updated_at = 110;
    assert!(store.update_inflight(record.clone()).unwrap());
    assert_eq!(
        store.get("req-1").unwrap().unwrap().state,
        BnsWriteRequestState::Pending
    );

    record.state = BnsWriteRequestState::Succeeded;
    record.updated_at = 120;
    assert!(store.update_inflight(record).unwrap());

    let stored = store.get("req-1").unwrap().expect("record persisted");
    assert_eq!(stored.state, BnsWriteRequestState::Succeeded);
    assert_eq!(stored.evm_chain_id, Some(31_337));
    assert_eq!(stored.evm_nonce, Some(7));
    assert_eq!(stored.evm_tx_hash.as_deref(), Some("0xdeadbeef"));
    assert_eq!(stored.evm_raw_tx.as_deref(), Some("0x02f8raw"));
    assert_eq!(stored.result_json, Some(json!({ "name_seq": 3 })));
    assert_eq!(stored.created_at, 100);
    assert!(store.list_inflight().unwrap().is_empty());
}

#[test]
fn same_request_id_has_one_raw_transaction_and_cas_transitions() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();
    let record = prepared_record("req-dup", 100);
    assert!(matches!(
        store.try_begin(record.clone()).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));

    let mut contender = prepared_record("req-dup", 999);
    contender.payload_hash = "0xdifferent".to_string();
    match store.try_begin(contender).unwrap() {
        SnBnsTryBeginResult::Existing(existing) => {
            assert_eq!(existing.payload_hash, "0xabc");
            assert_eq!(existing.created_at, 100);
        }
        SnBnsTryBeginResult::Acquired => panic!("duplicate request acquired execution"),
    }

    let mut stale = record.clone();
    stale.evm_tx_hash = Some("0xother".to_string());
    stale.state = BnsWriteRequestState::Pending;
    assert!(!store.update_inflight(stale).unwrap());

    let mut stale = record.clone();
    stale.evm_raw_tx = Some("0x02different".to_string());
    stale.state = BnsWriteRequestState::Pending;
    assert!(!store.update_inflight(stale).unwrap());

    let mut pending = record;
    pending.state = BnsWriteRequestState::Pending;
    pending.updated_at = 1_000;
    assert!(store.update_inflight(pending.clone()).unwrap());
    pending.state = BnsWriteRequestState::Reverted;
    pending.error_code = Some("EVM_TX_REVERTED".to_string());
    assert!(store.update_inflight(pending).unwrap());

    let stored = store.get("req-dup").unwrap().unwrap();
    assert_eq!(stored.state, BnsWriteRequestState::Reverted);
    assert_eq!(stored.created_at, 100);
}

#[test]
fn memory_try_begin_is_atomic_under_concurrency() {
    let store: Arc<dyn SnBnsWriteRequestStore> = Arc::new(MemorySnBnsWriteRequestStore::new());
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            matches!(
                store
                    .try_begin(prepared_record("req-concurrent-memory", 1))
                    .unwrap(),
                SnBnsTryBeginResult::Acquired
            )
        }));
    }
    barrier.wait();
    let acquired = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|acquired| *acquired)
        .count();
    assert_eq!(acquired, 1);
}

#[test]
fn sqlite_try_begin_is_atomic_across_connections() {
    let path = std::env::temp_dir().join(format!(
        "cyfs-gateway-sn-bns-idempotency-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let stores = (0..8)
        .map(|_| SqliteSnBnsWriteRequestStore::open(&path).unwrap())
        .collect::<Vec<_>>();
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for store in stores {
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            matches!(
                store
                    .try_begin(prepared_record("req-concurrent-sqlite", 1))
                    .unwrap(),
                SnBnsTryBeginResult::Acquired
            )
        }));
    }
    barrier.wait();
    let acquired = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|acquired| *acquired)
        .count();
    assert_eq!(acquired, 1);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
}

fn temp_store_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "cyfs-gateway-sn-bns-{}-{}-{}.sqlite",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn remove_store_files(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
}

fn request_rows(path: &std::path::Path) -> Vec<(String, String)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT request_id, state FROM sn_bns_write_requests ORDER BY request_id")
        .unwrap();
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

#[test]
fn sqlite_rejects_store_without_current_tx_state_model() {
    let path = temp_store_path("no-state-model");
    drop(SqliteSnBnsWriteRequestStore::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
        DELETE FROM sn_bns_write_store_meta;
        INSERT INTO sn_bns_write_requests
            (request_id, operation, name, payload_hash, state,
             evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
             created_at, updated_at)
        VALUES
            ('old-accepted', 'publish_document', 'alice', '0x1', 'succeeded',
             31337, 1, '0xaccepted', '0x02accepted', 1, 1),
            ('old-unprepared', 'publish_document', 'alice', '0x3', 'pending',
             NULL, NULL, NULL, NULL, 3, 3);
        "#,
    )
    .unwrap();
    drop(conn);

    let error = SqliteSnBnsWriteRequestStore::open(&path)
        .err()
        .expect("store without tx_state_model must be rejected");
    assert!(matches!(error, SnBnsControllerError::Store(_)));
    assert_eq!(
        request_rows(&path),
        [
            ("old-accepted".to_string(), "succeeded".to_string()),
            ("old-unprepared".to_string(), "pending".to_string()),
        ]
    );
    let meta_rows: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM sn_bns_write_store_meta", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(meta_rows, 0);
    remove_store_files(&path);
}

#[test]
fn sqlite_rejects_store_with_missing_columns() {
    let path = temp_store_path("missing-columns");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE sn_bns_write_requests (
            request_id TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            name TEXT NOT NULL,
            doc_type TEXT NULL,
            payload_hash TEXT NOT NULL,
            state TEXT NOT NULL,
            result_json TEXT NULL,
            error_code TEXT NULL,
            error_message TEXT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE sn_bns_write_store_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO sn_bns_write_store_meta (key, value) VALUES ('tx_state_model', '2');
        INSERT INTO sn_bns_write_requests
            (request_id, operation, name, payload_hash, state, created_at, updated_at)
        VALUES ('old-request', 'publish_document', 'alice', '0x1', 'pending', 1, 1);
        "#,
    )
    .unwrap();
    drop(conn);

    let error = SqliteSnBnsWriteRequestStore::open(&path)
        .err()
        .expect("store with missing columns must be rejected");
    assert!(matches!(error, SnBnsControllerError::Store(_)));
    assert_eq!(
        request_rows(&path),
        [("old-request".to_string(), "pending".to_string())]
    );
    let column_count: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sn_bns_write_requests')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(column_count, 11);
    remove_store_files(&path);
}

#[test]
fn sqlite_repairs_metadata_and_resolves_or_removes_recovery_quarantine() {
    let path = std::env::temp_dir().join(format!(
        "cyfs-gateway-sn-bns-recovery-repair-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let prepared = BnsEvmPreparedTx {
        tx_hash: "0xdeadbeef".to_string(),
        raw_tx: "0x02f8raw".to_string(),
        from: "0x0000000000000000000000000000000000000001".to_string(),
        nonce: 7,
        chain_id: 31_337,
    };
    let store = SqliteSnBnsWriteRequestStore::open(&path).unwrap();
    assert!(matches!(
        store.try_begin(prepared_record("repair", 1)).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));
    assert!(matches!(
        store.try_begin(prepared_record("remove", 2)).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));
    drop(store);

    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE sn_bns_write_requests
            SET evm_chain_id = NULL, evm_nonce = NULL, evm_tx_hash = NULL
          WHERE request_id = 'repair'",
        [],
    )
    .unwrap();
    drop(conn);

    let store = SqliteSnBnsWriteRequestStore::open(&path).unwrap();
    assert!(store
        .repair_prepared_metadata("repair", "0xabc", "0x02f8raw", None, &prepared, 10)
        .unwrap());
    let repaired = store.get("repair").unwrap().unwrap();
    assert_eq!(repaired.evm_chain_id, Some(31_337));
    assert_eq!(repaired.evm_nonce, Some(7));
    assert_eq!(repaired.evm_tx_hash.as_deref(), Some("0xdeadbeef"));

    let mut quarantined = repaired;
    quarantined.state = BnsWriteRequestState::Failed;
    quarantined.error_code = Some(EVM_TX_RECOVERY_DATA_INVALID.to_string());
    quarantined.error_message = Some("corrupt".to_string());
    assert!(store.update_inflight(quarantined.clone()).unwrap());
    quarantined.state = BnsWriteRequestState::Succeeded;
    quarantined.error_code = None;
    quarantined.error_message = None;
    assert!(store.resolve_recovery_failed(quarantined).unwrap());
    assert_eq!(
        store.get("repair").unwrap().unwrap().state,
        BnsWriteRequestState::Succeeded
    );

    let mut removable = store.get("remove").unwrap().unwrap();
    removable.state = BnsWriteRequestState::Failed;
    removable.error_code = Some(EVM_TX_RECOVERY_DATA_INVALID.to_string());
    removable.error_message = Some("corrupt".to_string());
    assert!(store.update_inflight(removable.clone()).unwrap());
    assert!(store
        .remove_recovery_failed(
            "remove",
            "0xabc",
            removable.evm_tx_hash.as_deref(),
            removable.evm_raw_tx.as_deref(),
        )
        .unwrap());
    assert!(store.get("remove").unwrap().is_none());
    drop(store);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
}
