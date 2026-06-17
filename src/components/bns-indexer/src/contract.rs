use async_trait::async_trait;

use crate::{
    AliasKind, AliasState, AuthProof, BnsIndexerError, BnsIndexerResult, ContractEventEnvelope,
    ControllerRule, DocumentRef, DocumentState, DocumentUpdate, IndexerCursor, NameState,
    PaymentTargetResolution, Principal, PurchaseContext, RegisterOptions, ReleaseMode,
    ResolveResult,
};

#[async_trait]
pub trait BnsContractView: Send + Sync {
    async fn query_name_state(&self, name: &str) -> BnsIndexerResult<Option<NameState>>;

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsIndexerResult<Option<DocumentState>>;

    async fn resolve_did(
        &self,
        _did: &str,
        _doc_type: &str,
    ) -> BnsIndexerResult<Option<ResolveResult>> {
        Ok(None)
    }

    async fn get_alias(&self, _name: &str) -> BnsIndexerResult<Option<AliasState>> {
        Ok(None)
    }

    async fn get_purchase_context(
        &self,
        _content_name: &str,
        _doc_type: &str,
    ) -> BnsIndexerResult<Option<PurchaseContext>> {
        Ok(None)
    }

    async fn resolve_payment_target(
        &self,
        _name: &str,
        _doc_type: &str,
        _version: u64,
    ) -> BnsIndexerResult<Option<PaymentTargetResolution>> {
        Ok(None)
    }
}

#[async_trait]
pub trait BnsContractWriter: BnsContractView {
    async fn register_name(
        &self,
        name: &str,
        asset_owner: &str,
        options: &RegisterOptions,
        initial_documents: &[DocumentUpdate],
    ) -> BnsIndexerResult<u64> {
        let _ = (name, asset_owner, options, initial_documents);
        not_implemented("register_name")
    }

    async fn renew_name(&self, name: &str, duration: u64) -> BnsIndexerResult<u64> {
        let _ = (name, duration);
        not_implemented("renew_name")
    }

    async fn transfer_name(
        &self,
        name: &str,
        new_asset_owner: &str,
        atomic_document_updates: &[DocumentUpdate],
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, new_asset_owner, atomic_document_updates, proof);
        not_implemented("transfer_name")
    }

    async fn release_name(
        &self,
        name: &str,
        mode: ReleaseMode,
        reason_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, mode, reason_hash, proof);
        not_implemented("release_name")
    }

    async fn set_namespace_policy(
        &self,
        name: &str,
        allow_delegated_subnames: bool,
        namespace_policy_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, allow_delegated_subnames, namespace_policy_hash, proof);
        not_implemented("set_namespace_policy")
    }

    async fn publish_document(
        &self,
        name: &str,
        doc_type: &str,
        document: &DocumentRef,
        controller: &Principal,
        beneficiary: &Principal,
        payment_target: &str,
        expire_at: u64,
        controller_policy_hash: &str,
        split_policy_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (
            name,
            doc_type,
            document,
            controller,
            beneficiary,
            payment_target,
            expire_at,
            controller_policy_hash,
            split_policy_hash,
            proof,
        );
        not_implemented("publish_document")
    }

    async fn revoke_document(
        &self,
        name: &str,
        doc_type: &str,
        from_version: u64,
        to_version: u64,
        reason_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, doc_type, from_version, to_version, reason_hash, proof);
        not_implemented("revoke_document")
    }

    async fn set_controller_policy(
        &self,
        name: &str,
        rules: &[ControllerRule],
        policy_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, rules, policy_hash, proof);
        not_implemented("set_controller_policy")
    }

    async fn change_owner_key(
        &self,
        name: &str,
        new_owner_document: &DocumentRef,
        new_controller_rules: &[ControllerRule],
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, new_owner_document, new_controller_rules, proof);
        not_implemented("change_owner_key")
    }

    async fn set_did_alias(
        &self,
        name: &str,
        target_did: &str,
        kind: AliasKind,
        proof_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (name, target_did, kind, proof_hash, proof);
        not_implemented("set_did_alias")
    }

    async fn set_payment_target(
        &self,
        name: &str,
        doc_type: &str,
        payment_target: &str,
        beneficiary: &Principal,
        payment_policy_hash: &str,
        proof: &AuthProof,
    ) -> BnsIndexerResult<u64> {
        let _ = (
            name,
            doc_type,
            payment_target,
            beneficiary,
            payment_policy_hash,
            proof,
        );
        not_implemented("set_payment_target")
    }
}

#[async_trait]
pub trait BnsContractEventSource: Send + Sync {
    async fn fetch_events(
        &self,
        source: &str,
        cursor: Option<&IndexerCursor>,
        limit: usize,
    ) -> BnsIndexerResult<Vec<ContractEventEnvelope>>;
}

fn not_implemented<T>(method: &'static str) -> BnsIndexerResult<T> {
    Err(BnsIndexerError::contract(format!(
        "contract writer method `{method}` is not implemented"
    )))
}
