use std::sync::Arc;

use cyfs_sn::{
    AuthDbRoutedSnCompatibilityStore, SnAuthDbAddUserDnsRecordReq, SnAuthDbQueryUserDnsRecordReq,
    SnAuthDbRemoveUserDnsRecordReq, SnCompatibilityStore, SnErrorCode, SnResolver,
    SnResolverConfig, SnResolverErrorKind, SqliteSnAuthDB, SqliteSnCompatibilityStore,
    METHOD_ADD_USER_DNS_RECORD, METHOD_LIST_USER_DNS_RECORDS, METHOD_QUERY_USER_DNS_RECORD,
    METHOD_REMOVE_USER_DNS_RECORD,
};
use name_client::RecordType;

#[test]
fn user_dns_wire_contract_has_stable_methods_and_fields() {
    assert_eq!(METHOD_ADD_USER_DNS_RECORD, "sn_auth_db.add_user_dns_record");
    assert_eq!(
        METHOD_REMOVE_USER_DNS_RECORD,
        "sn_auth_db.remove_user_dns_record"
    );
    assert_eq!(
        METHOD_QUERY_USER_DNS_RECORD,
        "sn_auth_db.query_user_dns_record"
    );
    assert_eq!(
        METHOD_LIST_USER_DNS_RECORDS,
        "sn_auth_db.list_user_dns_records"
    );

    let add = serde_json::to_value(SnAuthDbAddUserDnsRecordReq::new(
        "alice",
        "_pkx.alice.web3.example",
        "TXT",
        "pkx-value",
        300,
    ))
    .unwrap();
    assert_eq!(
        add,
        serde_json::json!({
            "username": "alice",
            "domain": "_pkx.alice.web3.example",
            "record_type": "TXT",
            "record": "pkx-value",
            "ttl": 300
        })
    );

    let exact_remove = serde_json::to_value(SnAuthDbRemoveUserDnsRecordReq::new(
        "alice",
        "_acme-challenge.alice.web3.example",
        "TXT",
        Some("challenge-a"),
    ))
    .unwrap();
    assert_eq!(exact_remove["record"], "challenge-a");

    let rrset_remove = serde_json::to_value(SnAuthDbRemoveUserDnsRecordReq::new(
        "alice",
        "_acme-challenge.alice.web3.example",
        "TXT",
        None,
    ))
    .unwrap();
    assert!(rrset_remove["record"].is_null());

    let query = serde_json::to_value(SnAuthDbQueryUserDnsRecordReq::new(
        "_pkx.alice.web3.example",
        "TXT",
    ))
    .unwrap();
    assert_eq!(
        query,
        serde_json::json!({
            "domain": "_pkx.alice.web3.example",
            "record_type": "TXT"
        })
    );
}

#[tokio::test]
async fn remote_auth_route_fails_closed_instead_of_reading_local_sqlite() {
    let temp = tempfile::tempdir().unwrap();
    let auth_path = temp.path().join("auth.sqlite3");
    let compat_path = temp.path().join("compat.sqlite3");

    let auth = Arc::new(
        SqliteSnAuthDB::new_by_path(auth_path.to_string_lossy().as_ref())
            .await
            .unwrap(),
    );
    auth.initialize_database().await.unwrap();

    let local = Arc::new(
        SqliteSnCompatibilityStore::new_by_path(compat_path.to_string_lossy().as_ref())
            .await
            .unwrap(),
    );
    local.initialize_database().await.unwrap();
    local
        .add_user_domain("alice", "_pkx.alice.web3.example", "TXT", "local-only", 600)
        .await
        .unwrap();

    let routed = AuthDbRoutedSnCompatibilityStore::new(auth, local.clone());
    let error = routed
        .query_domain_record("_pkx.alice.web3.example", "TXT")
        .await
        .unwrap_err();

    assert_eq!(error.code(), SnErrorCode::Failed);
    assert_eq!(
        local
            .query_domain_record("_pkx.alice.web3.example", "TXT")
            .await
            .unwrap(),
        Some(("local-only".to_owned(), 600))
    );
}

#[tokio::test]
async fn sqlite_baseline_keeps_multivalue_order_min_ttl_and_delete_modes() {
    let temp = tempfile::tempdir().unwrap();
    let compat_path = temp.path().join("compat.sqlite3");
    let store = SqliteSnCompatibilityStore::new_by_path(compat_path.to_string_lossy().as_ref())
        .await
        .unwrap();
    store.initialize_database().await.unwrap();

    let name = "_acme-challenge.alice.web3.example";
    store
        .add_user_domain("alice", name, "TXT", "first", 600)
        .await
        .unwrap();
    store
        .add_user_domain("alice", name, "TXT", "second", 300)
        .await
        .unwrap();
    store
        .add_user_domain("alice", name, "TXT", "first", 120)
        .await
        .unwrap();

    assert_eq!(
        store.query_domain_record(name, "TXT").await.unwrap(),
        Some(("first,second".to_owned(), 120))
    );

    store
        .remove_user_domain("alice", name, "TXT", Some("first"))
        .await
        .unwrap();
    assert_eq!(
        store.query_domain_record(name, "TXT").await.unwrap(),
        Some(("second".to_owned(), 300))
    );

    store
        .remove_user_domain("alice", name, "TXT", None)
        .await
        .unwrap();
    assert_eq!(store.query_domain_record(name, "TXT").await.unwrap(), None);
}

#[tokio::test]
async fn absent_underscore_txt_record_does_not_fall_through_to_bns() {
    let resolver = SnResolver::new(
        SnResolverConfig::new(
            "buckyos.test",
            Some("192.0.2.10".parse().unwrap()),
            "",
            "",
            Vec::new(),
        ),
        Arc::new(cyfs_sn::EmptySnAuthReader),
    );

    for hostname in [
        "_acme-challenge.alice.web3.buckyos.test",
        "_pkx.alice.web3.buckyos.test",
    ] {
        let error = resolver
            .resolve_dns(hostname, RecordType::TXT)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SnResolverErrorKind::DocumentNotFound);
    }
}
