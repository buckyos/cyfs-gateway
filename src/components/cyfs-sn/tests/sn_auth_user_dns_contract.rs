use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use cyfs_sn::{
    SnAuthDB, SnAuthDbClient, SnAuthDbGetUserDnsRrsetReq, SnAuthDbListUserDnsChangesReq,
    SnAuthDbPutUserDnsValueReq, SnAuthDbRemoveUserDnsValueReq, SnAuthDbRpcEnvelope,
    SnAuthDbRpcHandler, SnAuthDbUserDnsRrsetReq, SnResolver, SnResolverConfig, SnResolverErrorKind,
    SqliteSnAuthDB, UserDnsLookup, UserDnsMutationResult, UserDnsRecordType,
    METHOD_DELETE_USER_DNS_RRSET, METHOD_GET_USER_DNS_RRSET, METHOD_LIST_USER_DNS_CHANGES,
    METHOD_LIST_USER_DNS_RRSETS, METHOD_PUT_USER_DNS_VALUE, METHOD_REMOVE_USER_DNS_VALUE,
};
use kRPC::{RPCHandler, RPCRequest, RPCResult};
use name_client::RecordType;
use serde::de::DeserializeOwned;

#[test]
fn user_dns_wire_contract_is_structured_and_has_distinct_mutations() {
    assert_eq!(METHOD_PUT_USER_DNS_VALUE, "sn_auth_db.put_user_dns_value");
    assert_eq!(
        METHOD_REMOVE_USER_DNS_VALUE,
        "sn_auth_db.remove_user_dns_value"
    );
    assert_eq!(
        METHOD_DELETE_USER_DNS_RRSET,
        "sn_auth_db.delete_user_dns_rrset"
    );
    assert_eq!(METHOD_GET_USER_DNS_RRSET, "sn_auth_db.get_user_dns_rrset");
    assert_eq!(
        METHOD_LIST_USER_DNS_RRSETS,
        "sn_auth_db.list_user_dns_rrsets"
    );
    assert_eq!(
        METHOD_LIST_USER_DNS_CHANGES,
        "sn_auth_db.list_user_dns_changes"
    );

    let put = serde_json::to_value(SnAuthDbPutUserDnsValueReq::new(
        "alice",
        "_pkx.alice.web3.example",
        UserDnsRecordType::Txt,
        "value,with,commas",
        300,
    ))
    .unwrap();
    assert_eq!(
        put,
        serde_json::json!({
            "owner": "alice",
            "name": "_pkx.alice.web3.example",
            "record_type": "TXT",
            "value": "value,with,commas",
            "ttl": 300
        })
    );

    let exact = serde_json::to_value(SnAuthDbRemoveUserDnsValueReq::new(
        "alice",
        "_pkx.alice.web3.example",
        UserDnsRecordType::Txt,
        "value,with,commas",
    ))
    .unwrap();
    assert_eq!(exact["value"], "value,with,commas");
    let rrset = serde_json::to_value(SnAuthDbUserDnsRrsetReq::new(
        "alice",
        "_pkx.alice.web3.example",
        UserDnsRecordType::Txt,
    ))
    .unwrap();
    assert!(rrset.get("value").is_none());
}

async fn new_db() -> (tempfile::TempDir, Arc<SqliteSnAuthDB>) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("auth.sqlite3");
    let db = Arc::new(
        SqliteSnAuthDB::new_by_path(path.to_string_lossy().as_ref())
            .await
            .unwrap(),
    );
    db.initialize_database().await.unwrap();
    db.insert_activation_code("dns-contract").await.unwrap();
    assert!(db
        .register_user(
            "dns-contract",
            "alice",
            "alice@example.com",
            "hash",
            "salt",
            "pbkdf2",
        )
        .await
        .unwrap());
    (temp, db)
}

async fn exercise_contract(db: &dyn SnAuthDB) {
    let name = "_acme-challenge.alice.web3.example";
    let first = db
        .put_user_dns_value("alice", name, UserDnsRecordType::Txt, "root,order", 600)
        .await
        .unwrap();
    assert!(first.changed);
    let second = db
        .put_user_dns_value("alice", name, UserDnsRecordType::Txt, "wildcard-order", 300)
        .await
        .unwrap();
    assert!(second.revision > first.revision);
    let duplicate = db
        .put_user_dns_value("alice", name, UserDnsRecordType::Txt, "root,order", 600)
        .await
        .unwrap();
    assert!(!duplicate.changed);
    assert_eq!(duplicate.revision, second.revision);

    let lookup = db
        .get_user_dns_rrset(name, UserDnsRecordType::Txt)
        .await
        .unwrap();
    let rrset = lookup.rrset.unwrap();
    assert_eq!(rrset.ttl, 300);
    assert_eq!(rrset.values, vec!["root,order", "wildcard-order"]);

    let lowered = db
        .put_user_dns_value("alice", name, UserDnsRecordType::Txt, "root,order", 120)
        .await
        .unwrap();
    assert!(lowered.changed);
    assert_eq!(lowered.rrset.unwrap().ttl, 120);

    let removed = db
        .remove_user_dns_value("alice", name, UserDnsRecordType::Txt, "root,order")
        .await
        .unwrap();
    assert_eq!(removed.rrset.unwrap().values, vec!["wildcard-order"]);
    let deleted = db
        .delete_user_dns_rrset("alice", name, UserDnsRecordType::Txt)
        .await
        .unwrap();
    assert!(deleted.changed);
    assert!(db
        .get_user_dns_rrset(name, UserDnsRecordType::Txt)
        .await
        .unwrap()
        .rrset
        .is_none());
}

#[tokio::test]
async fn sqlite_and_in_process_provider_share_the_same_contract() {
    let (_temp, db) = new_db().await;
    exercise_contract(db.as_ref()).await;

    let (_temp, db) = new_db().await;
    let provider = SnAuthDbClient::new_in_process(db);
    exercise_contract(&provider).await;
}

async fn dispatch<T: DeserializeOwned>(
    handler: &SnAuthDbRpcHandler<SnAuthDbClient>,
    method: &str,
    params: serde_json::Value,
) -> T {
    let response = handler
        .handle_rpc_call(
            RPCRequest::new(method, params),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .await
        .unwrap();
    let value = match response.result {
        RPCResult::Success(value) => value,
        RPCResult::Failed(error) => panic!("RPC failed: {error}"),
    };
    serde_json::from_value::<SnAuthDbRpcEnvelope<T>>(value)
        .unwrap()
        .into_result()
        .unwrap()
}

#[tokio::test]
async fn remote_rpc_provider_preserves_structured_values_and_revision() {
    let (_temp, db) = new_db().await;
    let handler = SnAuthDbRpcHandler::new(SnAuthDbClient::new_in_process(db));
    let mutation: UserDnsMutationResult = dispatch(
        &handler,
        METHOD_PUT_USER_DNS_VALUE,
        serde_json::to_value(SnAuthDbPutUserDnsValueReq::new(
            "alice",
            "_pkx.alice.web3.example",
            UserDnsRecordType::Txt,
            "a,b,c",
            300,
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(mutation.revision, 1);

    let lookup: UserDnsLookup = dispatch(
        &handler,
        METHOD_GET_USER_DNS_RRSET,
        serde_json::to_value(SnAuthDbGetUserDnsRrsetReq::new(
            "_pkx.alice.web3.example",
            UserDnsRecordType::Txt,
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(lookup.rrset.unwrap().values, vec!["a,b,c"]);

    let page: cyfs_sn::UserDnsChangePage = dispatch(
        &handler,
        METHOD_LIST_USER_DNS_CHANGES,
        serde_json::to_value(SnAuthDbListUserDnsChangesReq::new(0, 10)).unwrap(),
    )
    .await;
    assert_eq!(page.current_revision, 1);
    assert_eq!(page.changes.len(), 1);
}

#[tokio::test]
async fn shared_provider_invalidates_positive_and_negative_resolver_caches() {
    let (_temp, db) = new_db().await;
    let auth: Arc<dyn SnAuthDB> = db.clone();
    let resolver_a = SnResolver::new(
        SnResolverConfig::new(
            "example",
            Some("192.0.2.10".parse().unwrap()),
            None,
            None,
            Vec::new(),
        ),
        Arc::new(cyfs_sn::SnAuthResolverReader::new(auth.clone())),
    );
    let resolver_b = SnResolver::new(
        SnResolverConfig::new(
            "example",
            Some("192.0.2.10".parse().unwrap()),
            None,
            None,
            Vec::new(),
        ),
        Arc::new(cyfs_sn::SnAuthResolverReader::new(auth)),
    );
    let name = "_acme-challenge.alice.web3.example";

    let missing = resolver_b
        .resolve_dns_cached(name, RecordType::TXT)
        .await
        .unwrap_err();
    assert_eq!(missing.kind(), SnResolverErrorKind::DocumentNotFound);

    db.put_user_dns_value("alice", name, UserDnsRecordType::Txt, "challenge", 60)
        .await
        .unwrap();
    let visible = resolver_b
        .resolve_dns_cached(name, RecordType::TXT)
        .await
        .unwrap();
    assert_eq!(visible.txt, vec!["challenge"]);

    // The other replica also observes the shared change feed, not a local
    // mutation callback.
    let visible = resolver_a
        .resolve_dns_cached(name, RecordType::TXT)
        .await
        .unwrap();
    assert_eq!(visible.txt, vec!["challenge"]);
}
