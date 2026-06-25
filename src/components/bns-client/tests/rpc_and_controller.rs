use ::kRPC::{RPCHandler, RPCRequest, RPCResult};
use bns_client::{
    BnsClientError, BnsIndexerApi, BnsIndexerClient, BnsIndexerRpcHandler, BnsPublishDocumentReq,
    BnsRegisterNameReq, BnsRegisterNameResp, BnsRpcEnvelope, BootstrapNameParams,
    CentralizedBnsIndexerHandler, DnsTxtUpdate, MemorySnBnsWriteRequestStore,
    PublishDeviceMiniDocParams, PublishRelayAssignmentParams, SnBnsController,
    SnBnsControllerConfig, SnBnsControllerError, UpsertDnsTxtParams, DEVICE_MINI_DOC_TYPE,
    METHOD_REGISTER_NAME, RELAY_ASSIGNMENT_DOC_TYPE,
};
use bns_indexer::dns_document::{self, DNS_TXT_DOC_TYPE};
use bns_indexer::{
    controller_rule, default_document_update, policy_hash_from_rules, CallAuthority,
    CentralizedBnsRegistry, DocumentRef, MutationGuard, Principal, RegisterOptions,
    SqliteBnsRegistryStore, PERMISSION_PUBLISH_DOCUMENT,
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

fn in_process_client(
    registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>,
) -> Arc<BnsIndexerClient> {
    let handler: Arc<dyn BnsIndexerApi> = Arc::new(CentralizedBnsIndexerHandler::new(registry));
    Arc::new(BnsIndexerClient::new_in_process(handler))
}

fn sn_controller(registry: Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>) -> SnBnsController {
    SnBnsController::new(
        in_process_client(registry),
        Arc::new(MemorySnBnsWriteRequestStore::new()),
        SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), ""),
    )
    .unwrap()
}

fn inline_update(doc_type: &str, expected_version: u64, body: &str) -> bns_indexer::DocumentUpdate {
    default_document_update(
        doc_type,
        expected_version,
        DocumentRef::inline(body.as_bytes()),
    )
    .unwrap()
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

#[test]
fn sn_controller_config_rejects_high_risk_doc_type_scope() {
    let mut config = SnBnsControllerConfig::new(Principal::chain_account(SN_CONTROLLER), "");
    config.allowed_controller_doc_types = vec![DEVICE_MINI_DOC_TYPE.to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(error.code(), "INVALID_INPUT");
    assert!(error.to_string().contains("high-risk doc_type"));
}

#[tokio::test]
async fn sn_controller_bootstrap_name_installs_controller_policy() {
    let registry = registry();
    let controller = sn_controller(registry.clone());

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

    let controller = sn_controller(registry.clone());

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
async fn sn_controller_cannot_publish_owner_scoped_device_doc() {
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
    let controller = sn_controller(registry.clone());

    let error = controller
        .publish_device_mini_doc(PublishDeviceMiniDocParams {
            request_id: "device-controller-denied".to_string(),
            name: "alice".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:ood1".to_string(),
            device_mini_doc: json!({"did":"did:dev:ood1"}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), "INVALID_INPUT");
    assert!(error.to_string().contains("requires owner authority"));
    assert!(registry
        .resolve_document("alice", DEVICE_MINI_DOC_TYPE)
        .is_err());
}

#[tokio::test]
async fn sn_controller_maps_registry_doc_type_scope_denial() {
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
    let controller = sn_controller(registry.clone());

    let error = controller
        .publish_relay_assignment(PublishRelayAssignmentParams {
            request_id: "relay-denied".to_string(),
            name: "alice".to_string(),
            relay_assignment: json!({"relay":"relay-a"}),
            authority: sn_controller_authority(),
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), "CONTROLLER_SCOPE_DENIED");
    match error {
        SnBnsControllerError::Bns(BnsClientError::Registry(info)) => {
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.doc_type.as_deref(), Some(RELAY_ASSIGNMENT_DOC_TYPE));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(registry
        .resolve_document("alice", RELAY_ASSIGNMENT_DOC_TYPE)
        .is_err());
}

#[tokio::test]
async fn bns_client_preserves_stale_guard_error_codes() {
    let registry = registry();
    let client = in_process_client(registry);
    client
        .register_name(BnsRegisterNameReq {
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            options: RegisterOptions::default(),
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await
        .unwrap();

    let stale_name_seq = client
        .publish_document(BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: inline_update("zone", 0, r#"{"version":1}"#),
            authority: owner_authority(),
            guard: guard(0),
        })
        .await
        .unwrap_err();
    assert_eq!(stale_name_seq.code(), "STALE_NAME_SEQ");
    match stale_name_seq {
        BnsClientError::Registry(info) => {
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.expected, Some(0));
            assert_eq!(info.actual, Some(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let published = client
        .publish_document(BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: inline_update("zone", 0, r#"{"version":1}"#),
            authority: owner_authority(),
            guard: guard(1),
        })
        .await
        .unwrap();
    assert_eq!(published.document_version, 1);

    let stale_document_version = client
        .publish_document(BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: inline_update("zone", 0, r#"{"version":2}"#),
            authority: owner_authority(),
            guard: guard(2),
        })
        .await
        .unwrap_err();
    assert_eq!(stale_document_version.code(), "STALE_DOCUMENT_VERSION");
    match stale_document_version {
        BnsClientError::Registry(info) => {
            assert_eq!(info.name.as_deref(), Some("alice"));
            assert_eq!(info.doc_type.as_deref(), Some("zone"));
            assert_eq!(info.expected, Some(0));
            assert_eq!(info.actual, Some(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }
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

    let controller = sn_controller(registry.clone());

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
