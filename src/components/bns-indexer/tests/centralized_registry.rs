use bns_indexer::{
    controller_rule, default_document_update, sha256_hex, AliasKind, AuthorityKey,
    AuthorityKeyUpdate, BnsRegistryError, CallAuthority, CentralizedBnsRegistry, DocumentRef,
    DocumentStatus, MutationGuard, OwnerSource, Principal, PrincipalKind, RegisterOptions,
    SqliteBnsRegistryStore, PERMISSION_PUBLISH_DOCUMENT, PERMISSION_SET_ALIAS, ZERO_HASH,
};

const OWNER_A: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OWNER_B: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONTROLLER: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

fn registry() -> CentralizedBnsRegistry<SqliteBnsRegistryStore> {
    CentralizedBnsRegistry::new(SqliteBnsRegistryStore::open_memory().unwrap())
}

fn guard(seq: u64) -> MutationGuard {
    MutationGuard {
        expected_name_seq: seq,
        expected_parent_name_seq: 0,
    }
}

fn chain_owner(seq: u64, account: &str) -> (CallAuthority, MutationGuard) {
    (
        CallAuthority::owner(Principal::chain_account(account), ""),
        guard(seq),
    )
}

fn bns_owner(seq: u64, name: &str, kid: &str) -> (CallAuthority, MutationGuard) {
    (
        CallAuthority::owner(Principal::bns_name(name).unwrap(), kid),
        guard(seq),
    )
}

fn key(kid_seed: &[u8]) -> AuthorityKey {
    AuthorityKey::authentication_key(sha256_hex(kid_seed), kid_seed.to_vec())
}

fn doc_update(doc_type: &str, expected_version: u64, body: &str) -> bns_indexer::DocumentUpdate {
    default_document_update(
        doc_type,
        expected_version,
        DocumentRef::inline(body.as_bytes()),
    )
    .unwrap()
}

#[test]
fn root_name_uses_asset_owner_until_semantic_owner_is_set() {
    let registry = registry();
    let seq = registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    assert_eq!(seq, 1);

    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.owner_source, OwnerSource::AssetOwnerFallback);
    assert_eq!(state.effective_owner, Principal::chain_account(OWNER_A));
    assert!(state.standard_transfer_enabled);

    let seq = registry.standard_transfer_name("alice", OWNER_B).unwrap();
    assert_eq!(seq, 2);

    let alice_key = key(b"alice-key");
    registry
        .update_authority_keys(
            "alice",
            vec![AuthorityKeyUpdate {
                key: alice_key.clone(),
                active: true,
            }],
            chain_owner(2, OWNER_B).0,
            chain_owner(2, OWNER_B).1,
        )
        .unwrap();

    let seq = registry
        .set_name_owner(
            "alice",
            Principal::bns_name("alice").unwrap(),
            chain_owner(2, OWNER_B).0,
            chain_owner(2, OWNER_B).1,
        )
        .unwrap();
    assert_eq!(seq, 3);

    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.owner_source, OwnerSource::ExplicitSemanticOwner);
    assert_eq!(state.effective_owner, Principal::bns_name("alice").unwrap());
    assert!(!state.standard_transfer_enabled);
    assert!(matches!(
        registry.standard_transfer_name("alice", OWNER_A),
        Err(BnsRegistryError::StandardTransferDisabled { .. })
    ));

    let update = doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#);
    assert!(matches!(
        registry.publish_document(
            "alice",
            update.clone(),
            chain_owner(3, OWNER_B).0,
            chain_owner(3, OWNER_B).1,
        ),
        Err(BnsRegistryError::NotEffectiveOwner { .. })
    ));

    let version = registry
        .publish_document(
            "alice",
            update,
            bns_owner(3, "alice", &alice_key.kid).0,
            bns_owner(3, "alice", &alice_key.kid).1,
        )
        .unwrap();
    assert_eq!(version, 1);
}

#[test]
fn controller_policy_scopes_document_operations() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    registry
        .publish_document(
            "alice",
            doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();

    let service_rule = controller_rule(
        Principal::chain_account(CONTROLLER),
        "service",
        PERMISSION_PUBLISH_DOCUMENT,
    );
    let alias_rule = controller_rule(
        Principal::chain_account(CONTROLLER),
        "",
        PERMISSION_SET_ALIAS,
    );
    registry
        .set_controller_policy(
            "alice",
            vec![service_rule, alias_rule],
            ZERO_HASH,
            chain_owner(2, OWNER_A).0,
            chain_owner(2, OWNER_A).1,
        )
        .unwrap();

    let version = registry
        .publish_document(
            "alice",
            doc_update("service", 0, r#"{"service":[]}"#),
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(3),
        )
        .unwrap();
    assert_eq!(version, 1);

    assert!(matches!(
        registry.revoke_document(
            "alice",
            "owner",
            1,
            1,
            ZERO_HASH,
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(4),
        ),
        Err(BnsRegistryError::ControllerScopeDenied { .. })
    ));

    let seq = registry
        .set_did_alias(
            "alice",
            "did:bns:alice2",
            AliasKind::Alias,
            ZERO_HASH,
            CallAuthority::controller(Principal::chain_account(CONTROLLER), ""),
            guard(4),
        )
        .unwrap();
    assert_eq!(seq, 5);
}

#[test]
fn revoke_current_document_keeps_current_pointer_revoked() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .publish_document(
            "alice",
            doc_update("owner", 0, r#"{"version":1}"#),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();
    registry
        .publish_document(
            "alice",
            doc_update("owner", 1, r#"{"version":2}"#),
            chain_owner(2, OWNER_A).0,
            chain_owner(2, OWNER_A).1,
        )
        .unwrap();

    registry
        .revoke_document(
            "alice",
            "owner",
            2,
            2,
            ZERO_HASH,
            chain_owner(3, OWNER_A).0,
            chain_owner(3, OWNER_A).1,
        )
        .unwrap();

    let resolved = registry.resolve_document("alice", "owner").unwrap();
    assert_eq!(resolved.document_state.version, 2);
    assert_eq!(resolved.status, DocumentStatus::Revoked);
}

#[test]
fn semantic_owner_requires_active_authority_set() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "bob",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    assert!(matches!(
        registry.set_name_owner(
            "bob",
            Principal::bns_name("alice").unwrap(),
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        ),
        Err(BnsRegistryError::NoConcreteSigner)
    ));
}

#[test]
fn semantic_owner_graph_rejects_cross_name_cycle() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
    registry
        .register_name(
            "bob",
            OWNER_B,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let alice_key = key(b"alice-key");
    let bob_key = key(b"bob-key");
    registry
        .update_authority_keys(
            "alice",
            vec![AuthorityKeyUpdate {
                key: alice_key,
                active: true,
            }],
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();
    registry
        .update_authority_keys(
            "bob",
            vec![AuthorityKeyUpdate {
                key: bob_key,
                active: true,
            }],
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        )
        .unwrap();

    registry
        .set_name_owner(
            "alice",
            Principal::bns_name("bob").unwrap(),
            chain_owner(1, OWNER_A).0,
            chain_owner(1, OWNER_A).1,
        )
        .unwrap();

    assert!(matches!(
        registry.set_name_owner(
            "bob",
            Principal::bns_name("alice").unwrap(),
            chain_owner(1, OWNER_B).0,
            chain_owner(1, OWNER_B).1,
        ),
        Err(BnsRegistryError::OwnerGraphCycle)
    ));
}

#[test]
fn checkpoint_covers_published_log_prefix() {
    let registry = registry();
    registry
        .register_name(
            "alice",
            OWNER_A,
            RegisterOptions::default(),
            vec![],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();

    let checkpoint = registry
        .publish_log_checkpoint(Principal::chain_account(OWNER_A), ZERO_HASH)
        .unwrap();
    assert_eq!(checkpoint.last_seq, 1);
    assert_ne!(checkpoint.log_root, ZERO_HASH);

    let events = registry.list_events(1, 10).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_type, "log_checkpoint_published");
    assert_eq!(
        registry.latest_checkpoint().unwrap().unwrap().last_seq,
        checkpoint.last_seq
    );
}

#[test]
fn sqlite_backend_persists_registry_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bns.sqlite3");
    {
        let registry = CentralizedBnsRegistry::new(SqliteBnsRegistryStore::open(&path).unwrap());
        registry
            .register_name(
                "alice",
                OWNER_A,
                RegisterOptions::default(),
                vec![doc_update("owner", 0, r#"{"id":"did:bns:alice"}"#)],
                CallAuthority::public(),
                MutationGuard::default(),
            )
            .unwrap();
    }

    let registry = CentralizedBnsRegistry::new(SqliteBnsRegistryStore::open(&path).unwrap());
    let state = registry.query_name_state("alice").unwrap().unwrap();
    assert_eq!(state.effective_owner.kind, PrincipalKind::ChainAccount);
    assert_eq!(
        registry
            .resolve_document("alice", "owner")
            .unwrap()
            .document_state
            .version,
        1
    );
}
