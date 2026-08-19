//! §2.4 幂等元数据：`SnBnsWriteRequestStore` 对 `evm_chain_id`/`evm_nonce`/`evm_tx_hash`/
//! `evm_raw_tx` 的原子写入、执行权抢占与受约束状态转换。
//!
//! 用进程内 SQLite（`:memory:`），无活节点。

use bns_client::{
    BnsWriteOperation, BnsWriteRequestState, MemorySnBnsWriteRequestStore, SnBnsTryBeginResult,
    SnBnsWriteRequestRecord, SnBnsWriteRequestStore, SqliteSnBnsWriteRequestStore,
};
use serde_json::json;
use std::sync::{Arc, Barrier};

fn record(
    request_id: &str,
    state: BnsWriteRequestState,
    created_at: u64,
) -> SnBnsWriteRequestRecord {
    SnBnsWriteRequestRecord {
        request_id: request_id.to_string(),
        operation: BnsWriteOperation::PublishDocument,
        name: "alice".to_string(),
        doc_type: Some("dns_txt".to_string()),
        payload_hash: "0xabc".to_string(),
        state,
        result_json: None,
        error_code: None,
        error_message: None,
        lease_owner: Some("test-owner".to_string()),
        lease_expires_at: Some(created_at + 300),
        evm_chain_id: None,
        evm_nonce: None,
        evm_tx_hash: None,
        evm_raw_tx: None,
        created_at,
        updated_at: created_at,
    }
}

#[test]
fn evm_metadata_round_trips_through_store() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();

    let rec = record("req-1", BnsWriteRequestState::Pending, 100);
    assert!(matches!(
        store.try_begin(rec).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));

    let mut rec = record("req-1", BnsWriteRequestState::Pending, 100);
    rec.evm_chain_id = Some(31_337);
    rec.evm_nonce = Some(7);
    rec.evm_tx_hash = Some("0xdeadbeef".to_string());
    rec.evm_raw_tx = Some("0x02f8...raw".to_string());
    rec.result_json = Some(json!({ "name_seq": 3 }));
    assert!(store.save_prepared(rec.clone()).unwrap());
    rec.state = BnsWriteRequestState::Succeeded;
    assert!(store.finish(rec).unwrap());

    let got = store.get("req-1").unwrap().expect("record persisted");
    assert_eq!(got.evm_chain_id, Some(31_337));
    assert_eq!(got.evm_nonce, Some(7));
    assert_eq!(got.evm_tx_hash.as_deref(), Some("0xdeadbeef"));
    assert_eq!(got.evm_raw_tx.as_deref(), Some("0x02f8...raw"));
    assert_eq!(got.state, BnsWriteRequestState::Succeeded);
    assert_eq!(got.result_json, Some(json!({ "name_seq": 3 })));

    assert!(store.get("missing").unwrap().is_none());
}

#[test]
fn same_request_id_has_one_executor_and_cas_transitions() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();

    // 首次：pending、无 evm 元数据、created_at=100。
    assert!(matches!(
        store
            .try_begin(record("req-dup", BnsWriteRequestState::Pending, 100))
            .unwrap(),
        SnBnsTryBeginResult::Acquired
    ));

    // 相同 request_id 只能观察既有记录，不能覆盖 payload 或取得第二份执行权。
    let mut contender = record("req-dup", BnsWriteRequestState::Pending, 999);
    contender.payload_hash = "0xdifferent".to_string();
    match store.try_begin(contender).unwrap() {
        SnBnsTryBeginResult::Existing(existing) => {
            assert_eq!(existing.payload_hash, "0xabc");
            assert_eq!(existing.created_at, 100);
        }
        SnBnsTryBeginResult::Acquired => panic!("duplicate request acquired execution"),
    }

    let mut second = record("req-dup", BnsWriteRequestState::Pending, 999);
    second.updated_at = 1_000;
    second.evm_chain_id = Some(31_337);
    second.evm_nonce = Some(42);
    second.evm_tx_hash = Some("0xfeed".to_string());
    second.evm_raw_tx = Some("0x02raw".to_string());
    second.result_json = Some(json!({"ok": true}));
    assert!(store.save_prepared(second.clone()).unwrap());
    // 已持久化交易后，旧执行者不能换成另一笔交易。
    let mut stale = second.clone();
    stale.evm_tx_hash = Some("0xother".to_string());
    assert!(!store.save_prepared(stale).unwrap());

    second.state = BnsWriteRequestState::Succeeded;
    assert!(store.finish(second).unwrap());

    let got = store.get("req-dup").unwrap().expect("record present");
    assert_eq!(got.state, BnsWriteRequestState::Succeeded);
    assert_eq!(got.evm_chain_id, Some(31_337));
    assert_eq!(got.evm_nonce, Some(42));
    assert_eq!(got.evm_tx_hash.as_deref(), Some("0xfeed"));
    assert_eq!(got.updated_at, 1_000);
    assert_eq!(
        got.created_at, 100,
        "created_at must be preserved across state transitions"
    );
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
                    .try_begin(record(
                        "req-concurrent-memory",
                        BnsWriteRequestState::Pending,
                        1
                    ))
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
                    .try_begin(record(
                        "req-concurrent-sqlite",
                        BnsWriteRequestState::Pending,
                        1
                    ))
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

#[test]
fn expired_lease_takeover_blocks_the_old_executor() {
    let store = SqliteSnBnsWriteRequestStore::open(":memory:").unwrap();
    let mut pending = record("req-takeover", BnsWriteRequestState::Pending, 10);
    pending.lease_expires_at = Some(20);
    assert!(matches!(
        store.try_begin(pending.clone()).unwrap(),
        SnBnsTryBeginResult::Acquired
    ));
    pending.result_json = Some(json!({"ok": true}));
    pending.evm_chain_id = Some(31_337);
    pending.evm_nonce = Some(9);
    pending.evm_tx_hash = Some("0xtakeover".to_string());
    pending.evm_raw_tx = Some("0x02takeover".to_string());
    assert!(store.save_prepared(pending.clone()).unwrap());

    let recovered = store
        .try_takeover("req-takeover", "0xabc", "recovery-owner", 400, 100)
        .unwrap()
        .expect("expired lease was acquired");
    assert_eq!(recovered.lease_owner.as_deref(), Some("recovery-owner"));

    let mut stale_finish = pending;
    stale_finish.state = BnsWriteRequestState::Succeeded;
    assert!(!store.finish(stale_finish).unwrap());

    let mut recovered_finish = recovered;
    recovered_finish.state = BnsWriteRequestState::Succeeded;
    assert!(store.finish(recovered_finish).unwrap());
}
