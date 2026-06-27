use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bns_evm::{
    build_eip1559_contract_tx, sign_eip1559_tx, signer_from_private_key, Address,
    AuthorityKey as EvmAuthorityKey, AuthorityKeyStatus as EvmAuthorityKeyStatus,
    AuthorityKeyUpdate as EvmAuthorityKeyUpdate, AuthorityRole as EvmAuthorityRole, Bns,
    BnsEvmError, Bytes, CallAuthority as EvmCallAuthority, ControllerRule as EvmControllerRule,
    DocumentRef as EvmDocumentRef, DocumentUpdate as EvmDocumentUpdate, Eip1559TxParams,
    EthRpcClient, MutationGuard as EvmMutationGuard, Principal as EvmPrincipal,
    PrincipalKind as EvmPrincipalKind, PrivateKeySigner, RegisterOptions as EvmRegisterOptions,
    SolCall, TxEip1559, B256, U256,
};
use bns_indexer::{
    AuthorityKey, AuthorityKeyStatus, AuthorityKeyUpdate, AuthorityRole, CallAuthority,
    ControllerRule, DocumentRef, DocumentUpdate, MutationGuard, Principal, PrincipalKind,
    RegisterOptions,
};
use serde::{Deserialize, Serialize};

use crate::{
    BnsBootstrapNameReq, BnsClientError, BnsClientResult, BnsPublishDocumentReq,
    BnsRegisterNameReq, BnsRevokeDocumentReq, BnsSetControllerPolicyReq, BnsUpdateAuthorityKeysReq,
};

impl From<BnsEvmError> for BnsClientError {
    fn from(value: BnsEvmError) -> Self {
        match value {
            BnsEvmError::Rpc(message) => Self::Transport(message),
            BnsEvmError::Abi(message)
            | BnsEvmError::Signer(message)
            | BnsEvmError::Transaction(message)
            | BnsEvmError::Parse(message) => Self::Serialization(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmClientConfig {
    pub rpc_endpoint: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

impl BnsEvmClientConfig {
    pub fn anvil(
        rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        chain_id: u64,
    ) -> Self {
        Self {
            rpc_endpoint: rpc_endpoint.into(),
            chain_id,
            contract_address: contract_address.into(),
            gas_limit: 3_000_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        }
    }

    fn contract(&self) -> BnsClientResult<Address> {
        parse_address(&self.contract_address, "contract_address")
    }

    fn tx_params(&self, nonce: u64) -> BnsClientResult<Eip1559TxParams> {
        Ok(Eip1559TxParams {
            chain_id: self.chain_id,
            nonce,
            to: self.contract()?,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: U256::ZERO,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmTxSubmission {
    pub tx_hash: String,
    pub raw_tx: String,
    pub from: String,
    pub nonce: u64,
    pub chain_id: u64,
}

#[derive(Clone)]
pub struct BnsEvmStandardClient {
    rpc: Arc<EthRpcClient>,
    config: BnsEvmClientConfig,
}

impl BnsEvmStandardClient {
    pub fn new(config: BnsEvmClientConfig) -> Self {
        Self {
            rpc: Arc::new(EthRpcClient::new(config.rpc_endpoint.clone())),
            config,
        }
    }

    pub fn rpc(&self) -> &EthRpcClient {
        &self.rpc
    }

    pub fn config(&self) -> &BnsEvmClientConfig {
        &self.config
    }

    pub async fn submit_raw_tx(&self, raw_tx: &[u8]) -> BnsClientResult<String> {
        self.rpc
            .send_raw_transaction(raw_tx)
            .await
            .map(|hash| format!("{hash:#x}"))
            .map_err(Into::into)
    }

    pub fn build_calldata<C: SolCall>(&self, call: &C) -> Bytes {
        bns_evm::encode_call(call)
    }

    pub fn build_unsigned_tx<C: SolCall>(
        &self,
        call: &C,
        nonce: u64,
    ) -> BnsClientResult<TxEip1559> {
        Ok(build_eip1559_contract_tx(
            call,
            self.config.tx_params(nonce)?,
        ))
    }
}

pub struct BnsEvmControllerClient {
    standard: BnsEvmStandardClient,
    signer: PrivateKeySigner,
    next_nonce: Mutex<Option<u64>>,
}

impl BnsEvmControllerClient {
    pub fn new(config: BnsEvmClientConfig, private_key: &str) -> BnsClientResult<Self> {
        Ok(Self {
            standard: BnsEvmStandardClient::new(config),
            signer: signer_from_private_key(private_key).map_err(BnsClientError::from)?,
            next_nonce: Mutex::new(None),
        })
    }

    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    pub fn standard(&self) -> &BnsEvmStandardClient {
        &self.standard
    }

    pub async fn sign_and_submit<C: SolCall>(
        &self,
        call: &C,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let nonce = self.next_nonce().await?;
        let tx = self.standard.build_unsigned_tx(call, nonce)?;
        let signed = sign_eip1559_tx(tx, &self.signer).map_err(BnsClientError::from)?;
        match self.standard.rpc.send_raw_transaction(&signed.raw_tx).await {
            Ok(tx_hash) => Ok(BnsEvmTxSubmission {
                tx_hash: format!("{tx_hash:#x}"),
                raw_tx: format!("0x{}", hex::encode(&signed.raw_tx)),
                from: format!("{:#x}", signed.signer),
                nonce: signed.nonce,
                chain_id: signed.chain_id,
            }),
            Err(error) => {
                self.reset_nonce();
                Err(error.into())
            }
        }
    }

    pub async fn register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&register_name_call(req)?).await
    }

    pub async fn bootstrap_name(
        &self,
        req: &BnsBootstrapNameReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&bootstrap_name_call(req)?).await
    }

    pub async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&publish_document_call(req)?).await
    }

    pub async fn revoke_document(
        &self,
        req: &BnsRevokeDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&revoke_document_call(req)?).await
    }

    pub async fn set_controller_policy(
        &self,
        req: &BnsSetControllerPolicyReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&set_controller_policy_call(req)?)
            .await
    }

    pub async fn update_authority_keys(
        &self,
        req: &BnsUpdateAuthorityKeysReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        self.sign_and_submit(&update_authority_keys_call(req)?)
            .await
    }

    async fn next_nonce(&self) -> BnsClientResult<u64> {
        {
            let mut cached = self.next_nonce.lock().map_err(|_| {
                BnsClientError::Transport("BNS EVM nonce lock poisoned".to_string())
            })?;
            if let Some(nonce) = *cached {
                *cached = Some(nonce + 1);
                return Ok(nonce);
            }
        }

        let chain_nonce = self
            .standard
            .rpc
            .transaction_count(self.signer.address())
            .await
            .map_err(BnsClientError::from)?;
        let mut cached = self
            .next_nonce
            .lock()
            .map_err(|_| BnsClientError::Transport("BNS EVM nonce lock poisoned".to_string()))?;
        let nonce = cached.unwrap_or(chain_nonce);
        *cached = Some(nonce + 1);
        Ok(nonce)
    }

    fn reset_nonce(&self) {
        if let Ok(mut cached) = self.next_nonce.lock() {
            *cached = None;
        }
    }
}

pub fn register_name_call(req: &BnsRegisterNameReq) -> BnsClientResult<Bns::registerNameCall> {
    Ok(Bns::registerNameCall {
        name: req.name.clone(),
        assetOwner: parse_address(&req.asset_owner, "asset_owner")?,
        options: register_options_to_evm(&req.options)?,
        initialDocuments: document_updates_to_evm(&req.initial_documents)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn bootstrap_name_call(req: &BnsBootstrapNameReq) -> BnsClientResult<Bns::bootstrapNameCall> {
    Ok(Bns::bootstrapNameCall {
        name: req.name.clone(),
        assetOwner: parse_address(&req.asset_owner, "asset_owner")?,
        options: register_options_to_evm(&req.options)?,
        initialDocuments: document_updates_to_evm(&req.initial_documents)?,
        authorityUpdates: authority_key_updates_to_evm(&req.authority_key_updates)?,
        semanticOwnerAfterAuthority: req
            .semantic_owner_after_authority
            .as_ref()
            .map(principal_to_evm)
            .transpose()?
            .unwrap_or_else(unset_principal),
        controllerPolicy: controller_rules_to_evm(&req.controller_policy)?,
        controllerPolicyHash: parse_b256_or_zero(
            &req.controller_policy_hash,
            "controller_policy_hash",
        )?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn publish_document_call(
    req: &BnsPublishDocumentReq,
) -> BnsClientResult<Bns::publishDocumentCall> {
    Ok(Bns::publishDocumentCall {
        name: req.name.clone(),
        docType: req.update.doc_type.clone(),
        expectedVersion: req.update.expected_version,
        document: document_ref_to_evm(&req.update.document)?,
        controller: principal_to_evm(&req.update.controller)?,
        beneficiary: principal_to_evm(&req.update.beneficiary)?,
        paymentTarget: parse_address_or_zero(&req.update.payment_target, "payment_target")?,
        expireAt: req.update.expire_at,
        controllerPolicyHash: parse_b256_or_zero(
            &req.update.controller_policy_hash,
            "controller_policy_hash",
        )?,
        paymentPolicyHash: parse_b256_or_zero(
            &req.update.payment_policy_hash,
            "payment_policy_hash",
        )?,
        splitPolicyHash: parse_b256_or_zero(&req.update.split_policy_hash, "split_policy_hash")?,
        pricePolicyHash: parse_b256_or_zero(&req.update.price_policy_hash, "price_policy_hash")?,
        rightsPolicyHash: parse_b256_or_zero(&req.update.rights_policy_hash, "rights_policy_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn revoke_document_call(
    req: &BnsRevokeDocumentReq,
) -> BnsClientResult<Bns::revokeDocumentCall> {
    Ok(Bns::revokeDocumentCall {
        name: req.name.clone(),
        docType: req.doc_type.clone(),
        fromVersion: req.from_version,
        toVersion: req.to_version,
        reasonHash: parse_b256_or_zero(&req.reason_hash, "reason_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn set_controller_policy_call(
    req: &BnsSetControllerPolicyReq,
) -> BnsClientResult<Bns::setControllerPolicyCall> {
    Ok(Bns::setControllerPolicyCall {
        name: req.name.clone(),
        rules: controller_rules_to_evm(&req.rules)?,
        policyHash: parse_b256_or_zero(&req.policy_hash, "policy_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn update_authority_keys_call(
    req: &BnsUpdateAuthorityKeysReq,
) -> BnsClientResult<Bns::updateAuthorityKeysCall> {
    Ok(Bns::updateAuthorityKeysCall {
        name: req.name.clone(),
        updates: authority_key_updates_to_evm(&req.updates)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

fn register_options_to_evm(options: &RegisterOptions) -> BnsClientResult<EvmRegisterOptions> {
    Ok(EvmRegisterOptions {
        duration: options.duration,
        gracePeriod: options.grace_period,
        renewable: options.renewable,
        transferable: options.transferable,
        initialSemanticOwner: principal_to_evm(&options.initial_semantic_owner)?,
        allowDelegatedSubnames: options.allow_delegated_subnames,
        initialPaymentTarget: parse_address_or_zero(
            &options.initial_payment_target,
            "initial_payment_target",
        )?,
        initialPaymentPolicyHash: parse_b256_or_zero(
            &options.initial_payment_policy_hash,
            "initial_payment_policy_hash",
        )?,
        initialNamespacePolicyHash: parse_b256_or_zero(
            &options.initial_namespace_policy_hash,
            "initial_namespace_policy_hash",
        )?,
    })
}

fn document_updates_to_evm(updates: &[DocumentUpdate]) -> BnsClientResult<Vec<EvmDocumentUpdate>> {
    updates.iter().map(document_update_to_evm).collect()
}

fn document_update_to_evm(update: &DocumentUpdate) -> BnsClientResult<EvmDocumentUpdate> {
    Ok(EvmDocumentUpdate {
        docType: update.doc_type.clone(),
        expectedVersion: update.expected_version,
        document: document_ref_to_evm(&update.document)?,
        controller: principal_to_evm(&update.controller)?,
        beneficiary: principal_to_evm(&update.beneficiary)?,
        paymentTarget: parse_address_or_zero(&update.payment_target, "payment_target")?,
        expireAt: update.expire_at,
        controllerPolicyHash: parse_b256_or_zero(
            &update.controller_policy_hash,
            "controller_policy_hash",
        )?,
        paymentPolicyHash: parse_b256_or_zero(&update.payment_policy_hash, "payment_policy_hash")?,
        splitPolicyHash: parse_b256_or_zero(&update.split_policy_hash, "split_policy_hash")?,
        pricePolicyHash: parse_b256_or_zero(&update.price_policy_hash, "price_policy_hash")?,
        rightsPolicyHash: parse_b256_or_zero(&update.rights_policy_hash, "rights_policy_hash")?,
    })
}

fn document_ref_to_evm(document: &DocumentRef) -> BnsClientResult<EvmDocumentRef> {
    Ok(EvmDocumentRef {
        storageType: bytes32_label_or_hash(&document.storage_type, "storage_type")?,
        uri: document.uri.clone(),
        inlineDocument: Bytes::from(document.inline_document.clone()),
        contentHash: parse_b256_or_zero(&document.content_hash, "content_hash")?,
        schema: parse_b256_or_zero(&document.schema, "schema")?,
        codec: parse_b256_or_zero(&document.codec, "codec")?,
        extraHash: parse_b256_or_zero(&document.extra_hash, "extra_hash")?,
    })
}

fn controller_rules_to_evm(rules: &[ControllerRule]) -> BnsClientResult<Vec<EvmControllerRule>> {
    rules.iter().map(controller_rule_to_evm).collect()
}

fn controller_rule_to_evm(rule: &ControllerRule) -> BnsClientResult<EvmControllerRule> {
    Ok(EvmControllerRule {
        controller: principal_to_evm(&rule.controller)?,
        docType: rule.doc_type.clone(),
        permissions: rule.permissions,
        namespaceScopeHash: parse_b256_or_zero(&rule.namespace_scope_hash, "namespace_scope_hash")?,
        validFrom: rule.valid_from,
        validUntil: rule.valid_until,
        constraintHash: parse_b256_or_zero(&rule.constraint_hash, "constraint_hash")?,
    })
}

fn authority_key_updates_to_evm(
    updates: &[AuthorityKeyUpdate],
) -> BnsClientResult<Vec<EvmAuthorityKeyUpdate>> {
    updates.iter().map(authority_key_update_to_evm).collect()
}

fn authority_key_update_to_evm(
    update: &AuthorityKeyUpdate,
) -> BnsClientResult<EvmAuthorityKeyUpdate> {
    Ok(EvmAuthorityKeyUpdate {
        key: authority_key_to_evm(&update.key)?,
        active: update.active,
    })
}

fn authority_key_to_evm(key: &AuthorityKey) -> BnsClientResult<EvmAuthorityKey> {
    Ok(EvmAuthorityKey {
        kid: parse_b256_or_zero(&key.kid, "kid")?,
        verificationMethod: bytes32_label_or_hash(&key.verification_method, "verification_method")?,
        keyData: Bytes::from(key.key_data.clone()),
        purposes: key.purposes,
        validFrom: key.valid_from,
        validUntil: key.valid_until,
        status: authority_key_status_to_evm(key.status),
        metadataHash: parse_b256_or_zero(&key.metadata_hash, "metadata_hash")?,
    })
}

fn call_authority_to_evm(authority: &CallAuthority) -> BnsClientResult<EvmCallAuthority> {
    Ok(EvmCallAuthority {
        role: authority_role_to_evm(authority.role),
        actor: principal_to_evm(&authority.actor)?,
        kid: parse_b256_or_zero(&authority.kid, "kid")?,
    })
}

fn principal_to_evm(principal: &Principal) -> BnsClientResult<EvmPrincipal> {
    let value = match principal.kind {
        PrincipalKind::Unset => {
            if !principal.value.is_empty() {
                return Err(BnsClientError::Serialization(
                    "unset principal must have empty value".to_string(),
                ));
            }
            Bytes::new()
        }
        PrincipalKind::ChainAccount => {
            let address = parse_address(&principal.value, "chain_account")?;
            Bytes::copy_from_slice(address.as_slice())
        }
        PrincipalKind::BnsName => Bytes::from(principal.value.as_bytes().to_vec()),
    };

    Ok(EvmPrincipal {
        kind: principal_kind_to_evm(principal.kind),
        value,
    })
}

fn unset_principal() -> EvmPrincipal {
    EvmPrincipal {
        kind: principal_kind_to_evm(PrincipalKind::Unset),
        value: Bytes::new(),
    }
}

fn mutation_guard_to_evm(guard: MutationGuard) -> EvmMutationGuard {
    EvmMutationGuard {
        expectedNameSeq: guard.expected_name_seq,
        expectedParentNameSeq: guard.expected_parent_name_seq,
    }
}

fn principal_kind_to_evm(kind: PrincipalKind) -> EvmPrincipalKind {
    match kind {
        PrincipalKind::Unset => EvmPrincipalKind::Unset,
        PrincipalKind::ChainAccount => EvmPrincipalKind::ChainAccount,
        PrincipalKind::BnsName => EvmPrincipalKind::BnsName,
    }
}

fn authority_role_to_evm(role: AuthorityRole) -> EvmAuthorityRole {
    match role {
        AuthorityRole::None => EvmAuthorityRole::None,
        AuthorityRole::Owner => EvmAuthorityRole::Owner,
        AuthorityRole::Controller => EvmAuthorityRole::Controller,
    }
}

fn authority_key_status_to_evm(status: AuthorityKeyStatus) -> EvmAuthorityKeyStatus {
    match status {
        AuthorityKeyStatus::Missing => EvmAuthorityKeyStatus::Missing,
        AuthorityKeyStatus::Active => EvmAuthorityKeyStatus::Active,
        AuthorityKeyStatus::Revoked => EvmAuthorityKeyStatus::Revoked,
        AuthorityKeyStatus::Expired => EvmAuthorityKeyStatus::Expired,
    }
}

fn parse_address(value: &str, field: &str) -> BnsClientResult<Address> {
    Address::from_str(value).map_err(|err| {
        BnsClientError::Serialization(format!("invalid {field} address `{value}`: {err}"))
    })
}

fn parse_address_or_zero(value: &str, field: &str) -> BnsClientResult<Address> {
    if value.is_empty() {
        Ok(Address::ZERO)
    } else {
        parse_address(value, field)
    }
}

fn parse_b256_or_zero(value: &str, field: &str) -> BnsClientResult<B256> {
    if value.is_empty() {
        return Ok(B256::ZERO);
    }
    B256::from_str(value).map_err(|err| {
        BnsClientError::Serialization(format!("invalid {field} bytes32 `{value}`: {err}"))
    })
}

fn bytes32_label_or_hash(value: &str, field: &str) -> BnsClientResult<B256> {
    if value.is_empty() {
        return Ok(B256::ZERO);
    }
    if value.starts_with("0x") {
        return parse_b256_or_zero(value, field);
    }
    let bytes = value.as_bytes();
    if bytes.len() > 32 {
        return Err(BnsClientError::Serialization(format!(
            "{field} `{value}` is longer than 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(B256::from(out))
}
