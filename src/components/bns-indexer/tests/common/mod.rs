use bns_indexer::{
    AliasKind, AliasState, DocumentRef, DocumentState, DocumentStatus, NameState, NameStatus,
    Principal, ZERO_HASH,
};

pub fn sample_name_state(name: &str) -> NameState {
    NameState {
        name: name.to_string(),
        asset_owner: "0x1111111111111111111111111111111111111111".to_string(),
        status: NameStatus::Active,
        registered_at: 10,
        expire_at: 1_000,
        grace_until: 1_100,
        updated_at: 20,
        name_seq: 1,
        owner_document_version: 1,
        namespace_policy_hash: ZERO_HASH.to_string(),
        payment_policy_hash: ZERO_HASH.to_string(),
        alias_state_hash: ZERO_HASH.to_string(),
    }
}

pub fn sample_document_state(name: &str, doc_type: &str, version: u64) -> DocumentState {
    DocumentState {
        name: name.to_string(),
        doc_type: doc_type.to_string(),
        version,
        previous_version: version.saturating_sub(1),
        status: DocumentStatus::Active,
        document: DocumentRef::inline(format!("{{\"id\":\"did:bns:{}\"}}", name)),
        controller: Principal::did(format!("did:bns:{}", name)),
        beneficiary: Principal::did(format!("did:bns:{}", name)),
        payment_target: "0x2222222222222222222222222222222222222222".to_string(),
        valid_from: 20 + version,
        expire_at: 1_000,
        revoked_at: 0,
        controller_policy_hash: ZERO_HASH.to_string(),
        split_policy_hash: ZERO_HASH.to_string(),
        document_state_hash: ZERO_HASH.to_string(),
    }
}

pub fn sample_alias_state(name: &str, target: &str) -> AliasState {
    AliasState {
        name: name.to_string(),
        kind: AliasKind::MigratedTo,
        target_did: target.to_string(),
        proof_hash: ZERO_HASH.to_string(),
        set_at: 30,
        name_seq: 2,
    }
}
