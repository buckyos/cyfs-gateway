use ::kRPC::{RPCHandler, RPCRequest, RPCResult};
use bns_client::{
    BnsIndexerApi, BnsIndexerClient, BnsIndexerRpcHandler, BnsRegisterNameReq, BnsRegisterNameResp,
    BnsRpcEnvelope, BootstrapNameParams, CentralizedBnsIndexerHandler, DnsTxtUpdate,
    MemorySnBnsWriteRequestStore, SnBnsController, SnBnsControllerConfig, SnBnsControllerError,
    UpsertDnsTxtParams, METHOD_REGISTER_NAME,
};
use bns_indexer::dns_document::{self, DNS_TXT_DOC_TYPE};
use bns_indexer::{
    controller_rule, policy_hash_from_rules, CallAuthority, CentralizedBnsRegistry, MutationGuard,
    Principal, RegisterOptions, SqliteBnsRegistryStore, PERMISSION_PUBLISH_DOCUMENT,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SN_CONTROLLER: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

fn registry() -> Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>> {
    Arc::new(CentralizedBnsRegistry::new(
        SqliteBnsRegistryStore::open_memory().unwrap(),
    ))
}

fn guard(seq: u64) -> MutationGuard {
    MutationGuard {
        expected_name_seq: seq,
        expected_parent_name_seq: 0,
    }
}

fn owner_authority() -> CallAuthority {
    CallAuthority::owner(Principal::chain_account(OWNER), "")
}

fn sn_controller_authority() -> CallAuthority {
    CallAuthority::controller(Principal::chain_account(SN_CONTROLLER), "")
}

#[tokio::test]
async fn rpc_handler_wraps_registry_result_in_envelope() {
    let handler = BnsIndexerRpcHandler::new(CentralizedBnsIndexerHandler::new(registry()));
    let req = BnsRegisterNameReq {
        name: "alice".to_string(),
        asset_owner: OWNER.to_string(),
        options: RegisterOptions::default(),
        initial_documents: vec![],
        authority: CallAuthority::public(),
        guard: MutationGuard::default(),
    };
    let rpc_req = RPCRequest::new(METHOD_REGISTER_NAME, serde_json::to_value(req).unwrap());

    let response = handler
        .handle_rpc_call(rpc_req, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await
        .unwrap();
    let value = match response.result {
        RPCResult::Success(value) => value,
        RPCResult::Failed(error) => panic!("unexpected rpc failure: {error}"),
    };
    let envelope: BnsRpcEnvelope<BnsRegisterNameResp> = serde_json::from_value(value).unwrap();

    assert!(envelope.ok);
    assert_eq!(envelope.into_result().unwrap().name_seq, 1);
}

#[tokio::test]
async fn sn_controller_bootstrap_name_installs_controller_policy() {
    let registry = registry();
    let handler: Arc<dyn BnsIndexerApi> =
        Arc::new(CentralizedBnsIndexerHandler::new(registry.clone()));
    let client = Arc::new(BnsIndexerClient::new_in_process(handler));
    let store = Arc::new(MemorySnBnsWriteRequestStore::new());
    let controller = SnBnsController::new(
        client,
        store,
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
    )
    .unwrap();

    let output = controller
        .bootstrap_name(BootstrapNameParams {
            request_id: "bootstrap-1".to_string(),
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            register_options: RegisterOptions::default(),
            owner_config: json!({"id":"did:bns:alice"}),
            owner_authority_keys: vec![],
            semantic_owner_after_authority: None,
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await
        .unwrap();
    assert_eq!(output.receipt.name_seq, 2);
    assert_eq!(output.initial_documents.len(), 1);
    assert_eq!(output.initial_documents[0].doc_type, "owner");

    let receipt = controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "bootstrap-dns".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Add {
                ttl: 60,
                value: "_acme-challenge=bootstrapped".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(receipt.document_version, Some(1));
}

#[tokio::test]
async fn sn_controller_upserts_dns_txt_with_idempotency() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let rules = vec![controller_rule(
        Principal::chain_account(SN_CONTROLLER),
        DNS_TXT_DOC_TYPE,
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    registry
        .set_controller_policy("alice", rules, &policy_hash, owner_authority(), guard(1))
        .unwrap();

    let handler: Arc<dyn BnsIndexerApi> =
        Arc::new(CentralizedBnsIndexerHandler::new(registry.clone()));
    let client = Arc::new(BnsIndexerClient::new_in_process(handler));
    let store = Arc::new(MemorySnBnsWriteRequestStore::new());
    let controller = SnBnsController::new(
        client,
        store,
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
    )
    .unwrap();

    let add = UpsertDnsTxtParams {
        request_id: "dns-1".to_string(),
        name: "alice".to_string(),
        update: DnsTxtUpdate::Add {
            ttl: 60,
            value: "_acme-challenge=token-a".to_string(),
        },
        authority: sn_controller_authority(),
    };
    let receipt = controller.upsert_dns_txt(add.clone()).await.unwrap();
    assert_eq!(receipt.document_version, Some(1));
    assert!(!receipt.created_or_reused);

    let replay = controller.upsert_dns_txt(add).await.unwrap();
    assert_eq!(replay.document_version, Some(1));
    assert!(replay.created_or_reused);

    let resolved = registry
        .resolve_document("alice", DNS_TXT_DOC_TYPE)
        .unwrap();
    let records = dns_document::txt_records_from_document(&resolved.document_state).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].value, "_acme-challenge=token-a");

    let conflict = controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "dns-1".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Add {
                ttl: 60,
                value: "_acme-challenge=token-b".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        conflict,
        SnBnsControllerError::IdempotencyConflict { .. }
    ));
}

#[tokio::test]
async fn sn_controller_removes_last_dns_txt_record_by_publishing_empty_rrset() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    let rules = vec![controller_rule(
        Principal::chain_account(SN_CONTROLLER),
        DNS_TXT_DOC_TYPE,
        PERMISSION_PUBLISH_DOCUMENT,
    )];
    let policy_hash = policy_hash_from_rules(&rules).unwrap();
    registry
        .set_controller_policy("alice", rules, &policy_hash, owner_authority(), guard(1))
        .unwrap();

    let handler: Arc<dyn BnsIndexerApi> =
        Arc::new(CentralizedBnsIndexerHandler::new(registry.clone()));
    let client = Arc::new(BnsIndexerClient::new_in_process(handler));
    let store = Arc::new(MemorySnBnsWriteRequestStore::new());
    let controller = SnBnsController::new(
        client,
        store,
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
    )
    .unwrap();

    controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "dns-add".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Add {
                ttl: 60,
                value: "google-site-verification=abc".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();

    let remove = controller
        .upsert_dns_txt(UpsertDnsTxtParams {
            request_id: "dns-remove".to_string(),
            name: "alice".to_string(),
            update: DnsTxtUpdate::Remove {
                value: "google-site-verification=abc".to_string(),
            },
            authority: sn_controller_authority(),
        })
        .await
        .unwrap();
    assert_eq!(remove.document_version, Some(2));

    let resolved = registry
        .resolve_document("alice", DNS_TXT_DOC_TYPE)
        .unwrap();
    assert_eq!(resolved.document_state.document.inline_document, b"[]");
    let records = dns_document::txt_records_from_document(&resolved.document_state).unwrap();
    assert!(records.is_empty());
}
