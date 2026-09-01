use crate::dns_document::{self, DnsTxtRecord, DNS_TXT_DOC_TYPE};
use crate::{
    canonical_bns_name, canonical_doc_type, canonical_json_sha256, controller_rule,
    default_document_update, hash_json, policy_hash_from_rules, validate_did, AuthorityKeyUpdate,
    AuthorityRole, AuthoritySetState, BnsRegistryError, CallAuthority, DocumentRef, DocumentState,
    DocumentStatus, DocumentUpdate, MutationGuard, NameState, OwnerPolicyUpdate, Principal,
    PrincipalKind, RegisterOptions, PERMISSION_PUBLISH_DOCUMENT, ZERO_HASH,
};
use crate::{
    BnsApplyMutationsReq, BnsClientError, BnsDocumentVersion, BnsEvmControllerClient,
    BnsEvmPreparedTx, BnsEvmReceiptWaitConfig, BnsEvmTxReceipt, BnsEvmTxSubmission, BnsIndexerApi,
    BnsPublishDocumentReq, BnsRegisterNameReq, BnsRpcErrorInfo, BnsTxExecutionState, BnsTxState,
};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const OWNER_DOC_TYPE: &str = "owner";
pub const ZONE_DOC_TYPE: &str = "zone";
pub const BOOT_DOC_TYPE: &str = "boot";
pub const DEVICE_MINI_DOC_TYPE: &str = "device_mini_doc";
pub const RELAY_ASSIGNMENT_DOC_TYPE: &str = "relay_assignment";
pub const EVM_TX_RECOVERY_DATA_INVALID: &str = "EVM_TX_RECOVERY_DATA_INVALID";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteOperation {
    RegisterName,
    BootstrapName,
    PublishDocument,
    RevokeDocument,
    SetControllerPolicy,
    UpdateAuthorityKeys,
    BindZoneDocuments,
    RemoveBoundZone,
    PublishDeviceMiniDoc,
    UpsertDnsTxt,
    PublishRelayAssignment,
}

impl BnsWriteOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterName => "register_name",
            Self::BootstrapName => "bootstrap_name",
            Self::PublishDocument => "publish_document",
            Self::RevokeDocument => "revoke_document",
            Self::SetControllerPolicy => "set_controller_policy",
            Self::UpdateAuthorityKeys => "update_authority_keys",
            Self::BindZoneDocuments => "bind_zone_documents",
            Self::RemoveBoundZone => "remove_bound_zone",
            Self::PublishDeviceMiniDoc => "publish_device_mini_doc",
            Self::UpsertDnsTxt => "upsert_dns_txt",
            Self::PublishRelayAssignment => "publish_relay_assignment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteReceiptStatus {
    Submitted,
}

impl Default for BnsWriteReceiptStatus {
    fn default() -> Self {
        Self::Submitted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsWriteReceipt {
    pub request_id: String,
    pub name: String,
    pub operation: BnsWriteOperation,
    #[serde(default)]
    pub status: BnsWriteReceiptStatus,
    pub name_seq: u64,
    pub doc_type: Option<String>,
    pub document_version: Option<u64>,
    pub content_hash: Option<String>,
    pub document_state_hash: Option<String>,
    pub authority_seq: u64,
    pub authority_root: String,
    pub controller_policy_hash: Option<String>,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub created_or_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsMultiWriteReceipt {
    pub request_id: String,
    pub name: String,
    pub operation: BnsWriteOperation,
    #[serde(default)]
    pub status: BnsWriteReceiptStatus,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub receipts: Vec<BnsWriteReceipt>,
    pub created_or_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNameOutput {
    pub receipt: BnsWriteReceipt,
    pub initial_documents: Vec<BnsDocumentVersion>,
}

pub type BootstrapNameOutput = RegisterNameOutput;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerDocumentSnapshot {
    pub document: Value,
    pub version: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveBoundZoneOutput {
    pub receipt: BnsWriteReceipt,
    pub source_owner_hash: String,
    pub result_owner_hash: String,
    pub source_version: u64,
    pub target_version: u64,
}

trait MarkIdempotentReuse {
    fn mark_reused(&mut self);
}

impl MarkIdempotentReuse for BnsWriteReceipt {
    fn mark_reused(&mut self) {
        self.created_or_reused = true;
    }
}

impl MarkIdempotentReuse for BnsMultiWriteReceipt {
    fn mark_reused(&mut self) {
        self.created_or_reused = true;
        for receipt in &mut self.receipts {
            receipt.mark_reused();
        }
    }
}

impl MarkIdempotentReuse for RegisterNameOutput {
    fn mark_reused(&mut self) {
        self.receipt.mark_reused();
    }
}

impl MarkIdempotentReuse for RemoveBoundZoneOutput {
    fn mark_reused(&mut self) {
        self.receipt.mark_reused();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsWriteRequestState {
    Sending,
    Pending,
    Succeeded,
    Reverted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnBnsWriteRequestRecord {
    pub request_id: String,
    pub operation: BnsWriteOperation,
    pub name: String,
    pub doc_type: Option<String>,
    pub payload_hash: String,
    pub state: BnsWriteRequestState,
    pub result_json: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    #[serde(default)]
    pub lease_owner: Option<String>,
    #[serde(default)]
    pub lease_expires_at: Option<u64>,
    #[serde(default)]
    pub evm_chain_id: Option<u64>,
    #[serde(default)]
    pub evm_nonce: Option<u64>,
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    #[serde(default)]
    pub evm_raw_tx: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnBnsRecoveryFailure {
    pub request_id: String,
    pub name: String,
    pub tx_hash: Option<String>,
    pub error_code: String,
    pub error_message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnBnsRecoveryReport {
    pub scanned: usize,
    pub recovered: usize,
    pub failures: Vec<SnBnsRecoveryFailure>,
}

#[derive(Debug, Error)]
pub enum SnBnsControllerError {
    #[error("BNS client error: {0}")]
    Bns(#[from] BnsClientError),

    #[error("invalid SN-BNS controller input: {0}")]
    InvalidInput(String),

    #[error("idempotency conflict for request `{request_id}`")]
    IdempotencyConflict { request_id: String },

    #[error("request `{request_id}` is still pending")]
    IdempotencyPending { request_id: String },

    #[error("request `{request_id}` failed previously: {message}")]
    IdempotencyPreviousFailure { request_id: String, message: String },

    #[error("idempotency store error: {0}")]
    Store(String),

    #[error("owner document hash conflict: expected {expected}, actual {actual}")]
    OwnerDocumentHashConflict { expected: String, actual: String },

    #[error("owner document is not bound to zone `{zone_did}`")]
    ZoneNotBound { zone_did: String },

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl SnBnsControllerError {
    pub fn code(&self) -> &str {
        match self {
            Self::Bns(error) => error.code(),
            Self::InvalidInput(_) => "INVALID_INPUT",
            Self::IdempotencyConflict { .. } => "IDEMPOTENCY_CONFLICT",
            Self::IdempotencyPending { .. } => "IDEMPOTENCY_PENDING",
            Self::IdempotencyPreviousFailure { .. } => "IDEMPOTENCY_PREVIOUS_FAILURE",
            Self::Store(_) => "IDEMPOTENCY_STORE_ERROR",
            Self::OwnerDocumentHashConflict { .. } => "OWNER_DOCUMENT_HASH_CONFLICT",
            Self::ZoneNotBound { .. } => "ZONE_NOT_BOUND",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
        }
    }

    fn is_stale_guard(&self) -> bool {
        matches!(
            self,
            Self::Bns(error)
                if error.is_registry_code("STALE_DOCUMENT_VERSION")
                    || error.is_registry_code("STALE_NAME_SEQ")
        )
    }
}

impl From<BnsRegistryError> for SnBnsControllerError {
    fn from(value: BnsRegistryError) -> Self {
        Self::Bns(BnsClientError::from(value))
    }
}

impl From<serde_json::Error> for SnBnsControllerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type SnBnsControllerResult<T> = Result<T, SnBnsControllerError>;

#[derive(Debug, Clone)]
pub enum SnBnsTryBeginResult {
    Acquired,
    Existing(SnBnsWriteRequestRecord),
}

pub trait SnBnsWriteRequestStore: Send + Sync {
    /// Serialize the prepare -> persist -> broadcast boundary for every
    /// controller sharing this store. This prevents a losing request-id race
    /// from reserving an EVM nonce that will never be broadcast.
    fn execution_lock(&self) -> &tokio::sync::Mutex<()>;

    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>>;

    /// Atomically insert a fully signed Sending record. Exactly one caller may
    /// receive [`SnBnsTryBeginResult::Acquired`] for a request id. Nothing is
    /// persisted before the raw transaction is available.
    fn try_begin(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<SnBnsTryBeginResult>;

    /// Return all records that still need startup or request-triggered recovery.
    fn list_inflight(&self) -> SnBnsControllerResult<Vec<SnBnsWriteRequestRecord>>;

    /// Compare-and-set a Sending/Pending record to its next chain-derived
    /// state. The payload hash and prepared transaction must still match.
    fn update_inflight(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<bool>;

    /// Repair metadata from a successfully decoded signed raw transaction.
    /// A conflicting stored hash may only be replaced after the caller has
    /// established that the old hash is not known by the chain.
    fn repair_prepared_metadata(
        &self,
        request_id: &str,
        payload_hash: &str,
        expected_raw_tx: &str,
        expected_tx_hash: Option<&str>,
        prepared: &BnsEvmPreparedTx,
        updated_at: u64,
    ) -> SnBnsControllerResult<bool>;

    /// Resolve a quarantined recovery failure from a later authoritative chain
    /// lookup without discarding its audit record.
    fn resolve_recovery_failed(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<bool>;

    /// Delete only a quarantined recovery failure after a later chain lookup
    /// again confirms that its transaction hash is not known.
    fn remove_recovery_failed(
        &self,
        request_id: &str,
        payload_hash: &str,
        tx_hash: Option<&str>,
        raw_tx: Option<&str>,
    ) -> SnBnsControllerResult<bool>;

    /// Remove a legacy pre-broadcast row that has no signed transaction. Such
    /// rows are safe to retry because the old workflow could not have reached
    /// its persist-before-broadcast boundary.
    fn remove_unprepared(
        &self,
        request_id: &str,
        payload_hash: &str,
    ) -> SnBnsControllerResult<bool>;
}

#[derive(Default)]
pub struct MemorySnBnsWriteRequestStore {
    records: Mutex<HashMap<String, SnBnsWriteRequestRecord>>,
    execution_lock: tokio::sync::Mutex<()>,
}

impl MemorySnBnsWriteRequestStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SnBnsWriteRequestStore for MemorySnBnsWriteRequestStore {
    fn execution_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.execution_lock
    }

    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>> {
        let records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        Ok(records.get(request_id).cloned())
    }

    fn try_begin(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<SnBnsTryBeginResult> {
        use std::collections::hash_map::Entry;

        if record.state != BnsWriteRequestState::Sending
            || record.result_json.is_none()
            || record.evm_chain_id.is_none()
            || record.evm_nonce.is_none()
            || record.evm_tx_hash.is_none()
            || record.evm_raw_tx.is_none()
        {
            return Err(SnBnsControllerError::Store(
                "try_begin requires a fully prepared sending record".to_string(),
            ));
        }

        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        match records.entry(record.request_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(record);
                Ok(SnBnsTryBeginResult::Acquired)
            }
            Entry::Occupied(entry) => Ok(SnBnsTryBeginResult::Existing(entry.get().clone())),
        }
    }

    fn list_inflight(&self) -> SnBnsControllerResult<Vec<SnBnsWriteRequestRecord>> {
        let records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        Ok(records
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    BnsWriteRequestState::Sending | BnsWriteRequestState::Pending
                )
            })
            .cloned()
            .collect())
    }

    fn update_inflight(&self, mut record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<bool> {
        if record.state == BnsWriteRequestState::Sending {
            return Err(SnBnsControllerError::Store(
                "update_inflight cannot transition back to sending".to_string(),
            ));
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        let Some(current) = records.get_mut(&record.request_id) else {
            return Ok(false);
        };
        if !matches!(
            current.state,
            BnsWriteRequestState::Sending | BnsWriteRequestState::Pending
        ) || current.payload_hash != record.payload_hash
            || current.evm_tx_hash != record.evm_tx_hash
            || current.evm_raw_tx != record.evm_raw_tx
        {
            return Ok(false);
        }
        record.created_at = current.created_at;
        *current = record;
        Ok(true)
    }

    fn repair_prepared_metadata(
        &self,
        request_id: &str,
        payload_hash: &str,
        expected_raw_tx: &str,
        expected_tx_hash: Option<&str>,
        prepared: &BnsEvmPreparedTx,
        updated_at: u64,
    ) -> SnBnsControllerResult<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        let Some(record) = records.get_mut(request_id) else {
            return Ok(false);
        };
        if !matches!(
            record.state,
            BnsWriteRequestState::Sending | BnsWriteRequestState::Pending
        ) || record.payload_hash != payload_hash
            || record.evm_raw_tx.as_deref() != Some(expected_raw_tx)
            || record.evm_tx_hash.as_deref() != expected_tx_hash
        {
            return Ok(false);
        }
        record.evm_tx_hash = Some(prepared.tx_hash.clone());
        record.evm_raw_tx = Some(prepared.raw_tx.clone());
        record.evm_chain_id = Some(prepared.chain_id);
        record.evm_nonce = Some(prepared.nonce);
        record.updated_at = updated_at;
        Ok(true)
    }

    fn resolve_recovery_failed(
        &self,
        mut record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<bool> {
        if !matches!(
            record.state,
            BnsWriteRequestState::Pending
                | BnsWriteRequestState::Succeeded
                | BnsWriteRequestState::Reverted
        ) {
            return Err(SnBnsControllerError::Store(
                "resolve_recovery_failed requires a chain-derived state".to_string(),
            ));
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        let Some(current) = records.get_mut(&record.request_id) else {
            return Ok(false);
        };
        if current.state != BnsWriteRequestState::Failed
            || current.error_code.as_deref() != Some(EVM_TX_RECOVERY_DATA_INVALID)
            || current.payload_hash != record.payload_hash
            || current.evm_tx_hash != record.evm_tx_hash
            || current.evm_raw_tx != record.evm_raw_tx
        {
            return Ok(false);
        }
        record.created_at = current.created_at;
        *current = record;
        Ok(true)
    }

    fn remove_recovery_failed(
        &self,
        request_id: &str,
        payload_hash: &str,
        tx_hash: Option<&str>,
        raw_tx: Option<&str>,
    ) -> SnBnsControllerResult<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        let removable = records.get(request_id).is_some_and(|record| {
            record.state == BnsWriteRequestState::Failed
                && record.error_code.as_deref() == Some(EVM_TX_RECOVERY_DATA_INVALID)
                && record.payload_hash == payload_hash
                && record.evm_tx_hash.as_deref() == tx_hash
                && record.evm_raw_tx.as_deref() == raw_tx
        });
        if removable {
            records.remove(request_id);
        }
        Ok(removable)
    }

    fn remove_unprepared(
        &self,
        request_id: &str,
        payload_hash: &str,
    ) -> SnBnsControllerResult<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SnBnsControllerError::Store("memory store lock poisoned".to_string()))?;
        let removable = records.get(request_id).is_some_and(|record| {
            record.payload_hash == payload_hash
                && matches!(
                    record.state,
                    BnsWriteRequestState::Sending | BnsWriteRequestState::Pending
                )
                && record.evm_tx_hash.is_none()
                && record.evm_raw_tx.is_none()
        });
        if removable {
            records.remove(request_id);
        }
        Ok(removable)
    }
}

#[derive(Debug, Clone)]
pub struct SnBnsControllerConfig {
    pub sn_controller_principal: Principal,
    pub sn_controller_kid: String,
    pub allowed_controller_doc_types: Vec<String>,
    pub max_inline_document_size: usize,
    pub write_retry_limit: usize,
}

impl SnBnsControllerConfig {
    pub fn new(sn_controller_principal: Principal, sn_controller_kid: impl Into<String>) -> Self {
        Self {
            sn_controller_principal,
            sn_controller_kid: sn_controller_kid.into(),
            // SN proxy 的应用层入口会继续隔离 owner / relay_assignment；链上
            // policy 使用 doc_type 通配，才能支持注册后补发 zone、boot、
            // device_mini_doc 以及未来的自定义内容文档。
            allowed_controller_doc_types: vec![String::new()],
            max_inline_document_size: crate::MAX_INLINE_DOCUMENT,
            write_retry_limit: 2,
        }
    }

    pub fn validate(&self) -> SnBnsControllerResult<()> {
        self.sn_controller_principal
            .validate()
            .map_err(SnBnsControllerError::from)?;
        if self.sn_controller_principal.kind == PrincipalKind::Unset {
            return Err(SnBnsControllerError::InvalidInput(
                "SN controller principal cannot be unset".to_string(),
            ));
        }

        for doc_type in &self.allowed_controller_doc_types {
            if doc_type.is_empty() {
                continue;
            }
            canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
            if doc_type == OWNER_DOC_TYPE {
                return Err(SnBnsControllerError::InvalidInput(format!(
                    "SN controller cannot be explicitly allowed to write owner doc_type `{}`",
                    doc_type
                )));
            }
        }

        Ok(())
    }

    pub fn sn_controller_authority(&self) -> CallAuthority {
        CallAuthority::controller(
            self.sn_controller_principal.clone(),
            self.sn_controller_kid.clone(),
        )
    }

    pub fn sn_managed_owner_authority(&self) -> CallAuthority {
        CallAuthority::owner(
            self.sn_controller_principal.clone(),
            self.sn_controller_kid.clone(),
        )
    }

    pub fn sn_controller_policy(&self) -> SnBnsControllerResult<Vec<crate::ControllerRule>> {
        self.validate()?;
        Ok(self
            .allowed_controller_doc_types
            .iter()
            .map(|doc_type| {
                controller_rule(
                    self.sn_controller_principal.clone(),
                    doc_type.clone(),
                    PERMISSION_PUBLISH_DOCUMENT,
                )
            })
            .collect())
    }
}

#[async_trait]
pub trait SnBnsEvmSubmitter: Send + Sync {
    async fn prepare_register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx>;

    async fn prepare_apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx>;

    async fn prepare_publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx>;

    async fn submit_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission>;

    /// Release any process-local nonce reservation when a prepared
    /// transaction could not be persisted and therefore must not be sent.
    fn abandon_prepared(&self, _prepared: &BnsEvmPreparedTx) {}

    async fn query_tx_state(&self, tx_hash: &str) -> crate::BnsClientResult<BnsTxState> {
        let _ = tx_hash;
        Err(BnsClientError::unsupported(
            "EVM transaction lookup is not supported by this submitter",
        ))
    }

    async fn recover_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        self.submit_prepared(prepared).await
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> crate::BnsClientResult<BnsEvmTxReceipt> {
        let _ = (tx_hash, config);
        Err(BnsClientError::Transport(
            "EVM receipt waiting is not supported by this submitter".to_string(),
        ))
    }
}

#[async_trait]
impl SnBnsEvmSubmitter for BnsEvmControllerClient {
    async fn prepare_register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx> {
        BnsEvmControllerClient::prepare_register_name(self, req).await
    }

    async fn prepare_apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx> {
        BnsEvmControllerClient::prepare_apply_mutations(self, req).await
    }

    async fn prepare_publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> crate::BnsClientResult<BnsEvmPreparedTx> {
        BnsEvmControllerClient::prepare_publish_document(self, req).await
    }

    async fn submit_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        BnsEvmControllerClient::submit_prepared_tx(self, prepared).await
    }

    fn abandon_prepared(&self, prepared: &BnsEvmPreparedTx) {
        BnsEvmControllerClient::abandon_prepared_tx(self, prepared)
    }

    async fn query_tx_state(&self, tx_hash: &str) -> crate::BnsClientResult<BnsTxState> {
        BnsEvmControllerClient::query_prepared_tx_state(self, tx_hash).await
    }

    async fn recover_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> crate::BnsClientResult<BnsEvmTxSubmission> {
        BnsEvmControllerClient::recover_prepared_tx(self, prepared).await
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> crate::BnsClientResult<BnsEvmTxReceipt> {
        BnsEvmControllerClient::wait_for_receipt(self, tx_hash, config).await
    }
}

#[async_trait]
trait SnBnsWriteBackend: Send + Sync {
    async fn prepare_register_name(
        &self,
        req: BnsRegisterNameReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx>;

    async fn prepare_apply_mutations(
        &self,
        req: BnsApplyMutationsReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx>;

    async fn prepare_publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx>;

    async fn submit_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission>;

    fn abandon_prepared(&self, prepared: &BnsEvmPreparedTx);

    async fn query_tx_state(&self, tx_hash: &str) -> SnBnsControllerResult<BnsTxState>;

    async fn recover_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission>;

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt>;
}

struct EvmSnBnsWriteBackend {
    submitter: Arc<dyn SnBnsEvmSubmitter>,
}

impl EvmSnBnsWriteBackend {
    fn new(submitter: Arc<dyn SnBnsEvmSubmitter>) -> Self {
        Self { submitter }
    }
}

#[async_trait]
impl SnBnsWriteBackend for EvmSnBnsWriteBackend {
    async fn prepare_register_name(
        &self,
        req: BnsRegisterNameReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx> {
        self.submitter
            .prepare_register_name(&req)
            .await
            .map_err(Into::into)
    }

    async fn prepare_apply_mutations(
        &self,
        req: BnsApplyMutationsReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx> {
        self.submitter
            .prepare_apply_mutations(&req)
            .await
            .map_err(Into::into)
    }

    async fn prepare_publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> SnBnsControllerResult<BnsEvmPreparedTx> {
        self.submitter
            .prepare_publish_document(&req)
            .await
            .map_err(Into::into)
    }

    async fn submit_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        self.submitter
            .submit_prepared(prepared)
            .await
            .map_err(Into::into)
    }

    fn abandon_prepared(&self, prepared: &BnsEvmPreparedTx) {
        self.submitter.abandon_prepared(prepared)
    }

    async fn query_tx_state(&self, tx_hash: &str) -> SnBnsControllerResult<BnsTxState> {
        self.submitter
            .query_tx_state(tx_hash)
            .await
            .map_err(Into::into)
    }

    async fn recover_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        self.submitter
            .recover_prepared(prepared)
            .await
            .map_err(Into::into)
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt> {
        self.submitter
            .wait_for_receipt(tx_hash, config)
            .await
            .map_err(Into::into)
    }
}

#[derive(Clone)]
struct SnBnsIdempotentExecution {
    store: Arc<dyn SnBnsWriteRequestStore>,
    backend: Arc<dyn SnBnsWriteBackend>,
    base_record: SnBnsWriteRequestRecord,
    prepared: Arc<AtomicBool>,
}

enum SnBnsExistingAction<T> {
    Return(T),
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnBnsRecoveryMode {
    Startup,
    RequestReplay,
}

enum SnBnsReconcileAction {
    Record(SnBnsWriteRequestRecord),
    Execute,
}

impl SnBnsIdempotentExecution {
    fn new(
        store: Arc<dyn SnBnsWriteRequestStore>,
        backend: Arc<dyn SnBnsWriteBackend>,
        base_record: SnBnsWriteRequestRecord,
    ) -> Self {
        Self {
            store,
            backend,
            base_record,
            prepared: Arc::new(AtomicBool::new(false)),
        }
    }

    fn is_prepared(&self) -> bool {
        self.prepared.load(Ordering::Acquire)
    }

    async fn persist_and_submit<T: Serialize + ?Sized>(
        &self,
        prepared: &BnsEvmPreparedTx,
        provisional_result: &T,
    ) -> SnBnsControllerResult<BnsEvmTxSubmission> {
        let mut record = self.base_record.clone();
        record.state = BnsWriteRequestState::Sending;
        record.result_json = Some(match serde_json::to_value(provisional_result) {
            Ok(result) => result,
            Err(error) => {
                self.backend.abandon_prepared(prepared);
                return Err(error.into());
            }
        });
        record.evm_chain_id = Some(prepared.chain_id);
        record.evm_nonce = Some(prepared.nonce);
        record.evm_tx_hash = Some(prepared.tx_hash.clone());
        record.evm_raw_tx = Some(prepared.raw_tx.clone());
        record.updated_at = crate::now_timestamp();
        let begin = match self.store.try_begin(record.clone()) {
            Ok(begin) => begin,
            Err(error) => {
                self.backend.abandon_prepared(prepared);
                return Err(error);
            }
        };
        match begin {
            SnBnsTryBeginResult::Acquired => {}
            SnBnsTryBeginResult::Existing(existing) => {
                self.backend.abandon_prepared(prepared);
                if existing.payload_hash != record.payload_hash {
                    return Err(SnBnsControllerError::IdempotencyConflict {
                        request_id: record.request_id,
                    });
                }
                return Err(SnBnsControllerError::IdempotencyPending {
                    request_id: record.request_id,
                });
            }
        }
        self.prepared.store(true, Ordering::Release);
        match self.backend.submit_prepared(prepared).await {
            Ok(submission) => {
                record.state = submission_state(&submission);
                record.error_code = None;
                record.error_message = None;
                record.updated_at = crate::now_timestamp();
                if !self.store.update_inflight(record.clone())? {
                    return Err(SnBnsControllerError::Store(format!(
                        "request `{}` lost its post-broadcast state transition",
                        record.request_id
                    )));
                }
                if record.state == BnsWriteRequestState::Reverted {
                    return Err(SnBnsControllerError::Bns(BnsClientError::registry(
                        "EVM_TX_REVERTED",
                        format!("BNS EVM tx {} reverted", prepared.tx_hash),
                    )));
                }
                Ok(submission)
            }
            Err(error) => {
                if error.code() == "EVM_TX_REVERTED" {
                    record.state = BnsWriteRequestState::Reverted;
                    record.error_code = Some(error.code().to_string());
                    record.error_message = Some(error.to_string());
                    record.updated_at = crate::now_timestamp();
                    if !self.store.update_inflight(record.clone())? {
                        let latest =
                            self.store.get(record.request_id.as_str())?.ok_or_else(|| {
                                SnBnsControllerError::Store(format!(
                                    "request `{}` disappeared after transaction revert",
                                    record.request_id
                                ))
                            })?;
                        if latest.state != BnsWriteRequestState::Reverted
                            || latest.payload_hash != record.payload_hash
                            || latest.evm_tx_hash != record.evm_tx_hash
                        {
                            return Err(SnBnsControllerError::Store(format!(
                                "request `{}` lost its reverted state transition",
                                record.request_id
                            )));
                        }
                    }
                }
                Err(error)
            }
        }
    }
}

fn submission_state(submission: &BnsEvmTxSubmission) -> BnsWriteRequestState {
    match submission.receipt_status {
        Some(0) => BnsWriteRequestState::Reverted,
        Some(_) => BnsWriteRequestState::Succeeded,
        None => BnsWriteRequestState::Pending,
    }
}

pub struct SnBnsController {
    client: Arc<dyn BnsIndexerApi>,
    write_backend: Arc<dyn SnBnsWriteBackend>,
    idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
    config: SnBnsControllerConfig,
}

impl SnBnsController {
    pub fn new_evm(
        client: Arc<dyn BnsIndexerApi>,
        idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
        config: SnBnsControllerConfig,
        evm_controller: Arc<BnsEvmControllerClient>,
    ) -> SnBnsControllerResult<Self> {
        let submitter: Arc<dyn SnBnsEvmSubmitter> = evm_controller;
        Self::new_with_evm_submitter(client, idempotency_store, config, submitter)
    }

    pub fn new_with_evm_submitter(
        client: Arc<dyn BnsIndexerApi>,
        idempotency_store: Arc<dyn SnBnsWriteRequestStore>,
        config: SnBnsControllerConfig,
        evm_submitter: Arc<dyn SnBnsEvmSubmitter>,
    ) -> SnBnsControllerResult<Self> {
        config.validate()?;
        Ok(Self {
            client,
            write_backend: Arc::new(EvmSnBnsWriteBackend::new(evm_submitter)),
            idempotency_store,
            config,
        })
    }

    pub fn config(&self) -> &SnBnsControllerConfig {
        &self.config
    }

    pub fn sn_controller_authority(&self) -> CallAuthority {
        self.config.sn_controller_authority()
    }

    pub fn sn_controller_policy(&self) -> SnBnsControllerResult<Vec<crate::ControllerRule>> {
        self.config.sn_controller_policy()
    }

    pub async fn wait_for_evm_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> SnBnsControllerResult<BnsEvmTxReceipt> {
        let result = self.write_backend.wait_for_receipt(tx_hash, config).await;
        let next_state = match &result {
            Ok(receipt) if receipt.status == Some(0) => Some(BnsWriteRequestState::Reverted),
            Ok(_) => Some(BnsWriteRequestState::Succeeded),
            Err(error) if error.code() == "EVM_TX_REVERTED" => Some(BnsWriteRequestState::Reverted),
            Err(_) => None,
        };
        if let Some(next_state) = next_state {
            if let Some(mut record) = self
                .idempotency_store
                .list_inflight()?
                .into_iter()
                .find(|record| record.evm_tx_hash.as_deref() == Some(tx_hash))
            {
                record.state = next_state;
                record.updated_at = crate::now_timestamp();
                if next_state == BnsWriteRequestState::Reverted {
                    record.error_code = Some("EVM_TX_REVERTED".to_string());
                    record.error_message = Some(format!("BNS EVM tx {tx_hash} reverted"));
                } else {
                    record.error_code = None;
                    record.error_message = None;
                }
                if !self.idempotency_store.update_inflight(record.clone())? {
                    let latest = self
                        .idempotency_store
                        .get(record.request_id.as_str())?
                        .ok_or_else(|| {
                            SnBnsControllerError::Store(format!(
                                "request `{}` disappeared after receipt",
                                record.request_id
                            ))
                        })?;
                    if latest.state != next_state
                        || latest.payload_hash != record.payload_hash
                        || latest.evm_tx_hash != record.evm_tx_hash
                    {
                        return Err(SnBnsControllerError::Store(format!(
                            "request `{}` lost its receipt state transition",
                            record.request_id
                        )));
                    }
                }
            }
        }
        result
    }

    pub async fn bootstrap_name(
        &self,
        params: RegisterNameParams,
    ) -> SnBnsControllerResult<RegisterNameOutput> {
        self.register_name(params).await
    }

    pub async fn register_name(
        &self,
        params: RegisterNameParams,
    ) -> SnBnsControllerResult<RegisterNameOutput> {
        self.ensure_owner_authority_or_public_registration(&params.authority)?;
        let controller_policy = self.sn_controller_policy()?;
        let controller_policy_hash =
            policy_hash_from_rules(&controller_policy).map_err(SnBnsControllerError::from)?;

        let mut initial_documents = Vec::with_capacity(params.initial_documents.len() + 1);
        if params
            .initial_documents
            .iter()
            .any(|update| update.doc_type == OWNER_DOC_TYPE)
        {
            return Err(SnBnsControllerError::InvalidInput(
                "initial_documents must not contain owner; pass owner_config instead".to_string(),
            ));
        }
        initial_documents.push(self.inline_json_update(OWNER_DOC_TYPE, 0, &params.owner_config)?);
        initial_documents.extend(params.initial_documents.clone());

        let req = BnsRegisterNameReq {
            name: canonical_bns_name(&params.name).map_err(SnBnsControllerError::from)?,
            asset_owner: params.asset_owner.clone(),
            options: params.register_options.clone(),
            authority_key_updates: params.owner_authority_keys.clone(),
            semantic_owner_after_authority: params.semantic_owner_after_authority.clone(),
            controller_policy,
            controller_policy_hash: controller_policy_hash.clone(),
            initial_documents,
            authority: params.authority.clone(),
            guard: params.guard,
        };

        let request_id = params.request_id.clone();
        let name = params.name.clone();
        let payload = req.clone();
        let response_request_id = request_id.clone();
        let response_name = name.clone();
        self.run_idempotent(
            &request_id,
            BnsWriteOperation::RegisterName,
            &name,
            None,
            &payload,
            |execution| async move {
                let prepared = self.write_backend.prepare_register_name(req).await?;
                let output = self.register_output_from_submission(
                    &response_request_id,
                    &response_name,
                    &controller_policy_hash,
                    prepared.submission(),
                );
                execution.persist_and_submit(&prepared, &output).await?;
                Ok(output)
            },
        )
        .await
    }

    pub async fn publish_owner_document(
        &self,
        params: PublishOwnerDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, OWNER_DOC_TYPE)?;
        let execute_params = params.clone();
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(OWNER_DOC_TYPE),
            &params,
            |execution| async move {
                self.publish_json_document_once(
                    &execution,
                    &execute_params.request_id,
                    BnsWriteOperation::PublishDocument,
                    &execute_params.name,
                    OWNER_DOC_TYPE,
                    &execute_params.owner_config,
                    execute_params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    pub async fn publish_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, &params.doc_type)?;
        let execute_params = params.clone();
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(&params.doc_type),
            &params,
            |execution| async move {
                self.publish_json_document_once(
                    &execution,
                    &execute_params.request_id,
                    BnsWriteOperation::PublishDocument,
                    &execute_params.name,
                    &execute_params.doc_type,
                    &execute_params.document,
                    execute_params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    /// 以 controller authority 发布普通内容文档。
    ///
    /// `owner` 必须走 [`Self::publish_guarded_owner_document`]，
    /// `relay_assignment` 必须走 [`Self::publish_relay_assignment`]；把保留类型
    /// 在这一层硬编码排除，避免其它调用方绕过上层 RPC 的产品边界。
    pub async fn publish_content_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        if params.doc_type == OWNER_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(
                "owner document must use guarded owner publishing".to_string(),
            ));
        }
        if params.doc_type == RELAY_ASSIGNMENT_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(
                "relay_assignment must use publish_relay_assignment".to_string(),
            ));
        }
        if !params.document.is_object()
            && !params
                .document
                .as_str()
                .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(SnBnsControllerError::InvalidInput(
                "document must be a JSON object or non-empty text string".to_string(),
            ));
        }
        self.ensure_authority_can_publish(&params.authority, &params.doc_type)?;
        let execute_params = params.clone();

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(&params.doc_type),
            &params,
            |execution| async move {
                let mut attempt = 0;
                loop {
                    let result = self
                        .publish_inline_document_once(
                            &execution,
                            &execute_params.request_id,
                            BnsWriteOperation::PublishDocument,
                            &execute_params.name,
                            &execute_params.doc_type,
                            &execute_params.document,
                            execute_params.authority.clone(),
                        )
                        .await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && !execution.is_prepared()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    /// 以 controller authority 更新 owner 文档，同时锁定已经存在的身份字段。
    /// 缺失的身份字段可以首次补齐；一旦存在就不能删除或改值。
    pub async fn publish_guarded_owner_document(
        &self,
        params: PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        if params.doc_type != OWNER_DOC_TYPE {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "guarded owner publishing requires doc_type `{OWNER_DOC_TYPE}`"
            )));
        }
        if !params.document.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "owner document must be a JSON object".to_string(),
            ));
        }
        self.ensure_authority_can_publish(&params.authority, OWNER_DOC_TYPE)?;
        let execute_params = params.clone();

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            Some(OWNER_DOC_TYPE),
            &params,
            |execution| async move {
                let mut attempt = 0;
                loop {
                    let result = self
                        .publish_guarded_owner_document_once(&execution, &execute_params)
                        .await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && !execution.is_prepared()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    pub async fn resolve_owner_document_snapshot(
        &self,
        name: &str,
    ) -> SnBnsControllerResult<OwnerDocumentSnapshot> {
        let state = self
            .current_document_state(name, OWNER_DOC_TYPE)
            .await?
            .ok_or_else(|| {
                SnBnsControllerError::InvalidInput(format!(
                    "owner document for `{name}` does not exist"
                ))
            })?;
        let document = self.parse_inline_document::<Value>(&state)?;
        let hash = canonical_json_sha256(&document).map_err(SnBnsControllerError::from)?;
        Ok(OwnerDocumentSnapshot {
            document,
            version: state.version,
            hash,
        })
    }

    /// Remove exactly one Zone DID from the latest OwnerDocument and submit a
    /// single compare-and-set update. A stale source hash or document version
    /// is never retried against a newer document.
    pub async fn remove_bound_zone(
        &self,
        params: RemoveBoundZoneParams,
    ) -> SnBnsControllerResult<RemoveBoundZoneOutput> {
        self.ensure_authority_can_publish(&params.authority, OWNER_DOC_TYPE)?;
        validate_did(&params.zone_did).map_err(SnBnsControllerError::from)?;
        validate_owner_document_hash(&params.expected_owner_hash)?;

        let execute_params = params.clone();
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::RemoveBoundZone,
            &params.name,
            Some(OWNER_DOC_TYPE),
            &params,
            |execution| async move {
                let current = self
                    .current_document_state(&execute_params.name, OWNER_DOC_TYPE)
                    .await?
                    .ok_or_else(|| {
                        SnBnsControllerError::InvalidInput(format!(
                            "owner document for `{}` does not exist",
                            execute_params.name
                        ))
                    })?;
                let source_document = self.parse_inline_document::<Value>(&current)?;
                let source_owner_hash =
                    canonical_json_sha256(&source_document).map_err(SnBnsControllerError::from)?;
                if source_owner_hash != execute_params.expected_owner_hash {
                    return Err(SnBnsControllerError::OwnerDocumentHashConflict {
                        expected: execute_params.expected_owner_hash.clone(),
                        actual: source_owner_hash,
                    });
                }

                let mut result_document = source_document;
                remove_owner_bound_zone(
                    &mut result_document,
                    &execute_params.name,
                    &execute_params.zone_did,
                )?;
                let result_owner_hash =
                    canonical_json_sha256(&result_document).map_err(SnBnsControllerError::from)?;
                let update =
                    self.inline_json_update(OWNER_DOC_TYPE, current.version, &result_document)?;
                let name_state = self.required_name_state(&execute_params.name).await?;
                let guard = MutationGuard {
                    expected_name_seq: name_state.name_seq,
                    expected_parent_name_seq: 0,
                };
                let authority_set = self.client.get_authority_set(&execute_params.name).await?;
                let prepared = self
                    .write_backend
                    .prepare_publish_document(BnsPublishDocumentReq {
                        name: execute_params.name.clone(),
                        update: update.clone(),
                        authority: execute_params.authority.clone(),
                        guard,
                    })
                    .await?;
                let receipt = receipt_from_submitted_document(
                    &execute_params.request_id,
                    BnsWriteOperation::RemoveBoundZone,
                    &name_state,
                    &update,
                    &authority_set,
                    prepared.submission(),
                );
                let output = RemoveBoundZoneOutput {
                    source_owner_hash: execute_params.expected_owner_hash.clone(),
                    result_owner_hash,
                    source_version: current.version,
                    target_version: receipt
                        .document_version
                        .unwrap_or(current.version.saturating_add(1)),
                    receipt,
                };
                execution.persist_and_submit(&prepared, &output).await?;
                Ok(output)
            },
        )
        .await
    }

    pub async fn bind_zone_documents(
        &self,
        params: BindZoneDocumentsParams,
    ) -> SnBnsControllerResult<BnsMultiWriteReceipt> {
        self.ensure_owner_authority(&params.authority, ZONE_DOC_TYPE)?;
        if !params.zone_config.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "zone_config must be a JSON object".to_string(),
            ));
        }
        if !params.boot_config.is_null() && !params.boot_config.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "boot_config must be a JSON object when present".to_string(),
            ));
        }
        let execute_params = params.clone();
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::BindZoneDocuments,
            &params.name,
            Some(ZONE_DOC_TYPE),
            &params,
            |execution| async move {
                let name_state = self.required_name_state(&execute_params.name).await?;
                let zone_current = self
                    .current_document_state(&execute_params.name, ZONE_DOC_TYPE)
                    .await?;
                let zone_expected = zone_current.as_ref().map_or(0, |state| state.version);
                let mut updates = vec![self.inline_json_update(
                    ZONE_DOC_TYPE,
                    zone_expected,
                    &execute_params.zone_config,
                )?];
                if !execute_params.boot_config.is_null() {
                    let boot_current = self
                        .current_document_state(&execute_params.name, BOOT_DOC_TYPE)
                        .await?;
                    let boot_expected = boot_current.as_ref().map_or(0, |state| state.version);
                    updates.push(self.inline_json_update(
                        BOOT_DOC_TYPE,
                        boot_expected,
                        &execute_params.boot_config,
                    )?);
                }
                let guard = MutationGuard {
                    expected_name_seq: name_state.name_seq,
                    expected_parent_name_seq: 0,
                };
                let authority_set = self.client.get_authority_set(&execute_params.name).await?;
                let prepared = self
                    .write_backend
                    .prepare_apply_mutations(BnsApplyMutationsReq {
                        name: execute_params.name.clone(),
                        authority_key_updates: Vec::new(),
                        documents: updates.clone(),
                        owner_policy: OwnerPolicyUpdate::none(),
                        authority: execute_params.authority.clone(),
                        guard,
                    })
                    .await?;
                let submission = prepared.submission();
                let receipts = updates
                    .iter()
                    .map(|update| {
                        receipt_from_submitted_document(
                            &execute_params.request_id,
                            BnsWriteOperation::BindZoneDocuments,
                            &name_state,
                            update,
                            &authority_set,
                            submission.clone(),
                        )
                    })
                    .collect();
                let output = BnsMultiWriteReceipt {
                    request_id: execute_params.request_id.clone(),
                    name: execute_params.name.clone(),
                    operation: BnsWriteOperation::BindZoneDocuments,
                    status: BnsWriteReceiptStatus::Submitted,
                    evm_chain_id: Some(submission.chain_id),
                    evm_nonce: Some(submission.nonce),
                    evm_tx_hash: Some(submission.tx_hash),
                    evm_raw_tx: Some(submission.raw_tx),
                    receipts,
                    created_or_reused: false,
                };
                execution.persist_and_submit(&prepared, &output).await?;
                Ok(output)
            },
        )
        .await
    }

    pub async fn publish_device_mini_doc(
        &self,
        params: PublishDeviceMiniDocParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_owner_authority(&params.authority, DEVICE_MINI_DOC_TYPE)?;
        self.validate_device_name(&params.device_name)?;
        crate::validate_did(&params.did).map_err(SnBnsControllerError::from)?;
        let execute_params = params.clone();

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishDeviceMiniDoc,
            &params.name,
            Some(DEVICE_MINI_DOC_TYPE),
            &params,
            |execution| async move {
                let current = self
                    .current_document_state(&execute_params.name, DEVICE_MINI_DOC_TYPE)
                    .await?;
                let expected_version = current.as_ref().map_or(0, |state| state.version);
                let mut collection = match current.as_ref() {
                    Some(state) => self.parse_inline_document::<DeviceMiniDocCollection>(state)?,
                    None => DeviceMiniDocCollection::default(),
                };

                let entry = normalize_device_mini_doc_entry(
                    &execute_params.did,
                    execute_params.device_mini_doc.clone(),
                )?;
                collection
                    .devices
                    .insert(execute_params.device_name.clone(), entry);
                let document = serde_json::to_value(collection)?;

                self.publish_json_document_with_expected_once(
                    &execution,
                    &execute_params.request_id,
                    BnsWriteOperation::PublishDeviceMiniDoc,
                    &execute_params.name,
                    DEVICE_MINI_DOC_TYPE,
                    expected_version,
                    &document,
                    execute_params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    pub async fn upsert_dns_txt(
        &self,
        params: UpsertDnsTxtParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_authority_can_publish(&params.authority, DNS_TXT_DOC_TYPE)?;
        let execute_params = params.clone();
        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::UpsertDnsTxt,
            &params.name,
            Some(DNS_TXT_DOC_TYPE),
            &params,
            |execution| async move {
                let mut attempt = 0;
                loop {
                    let result = self.upsert_dns_txt_once(&execution, &execute_params).await;
                    match result {
                        Ok(receipt) => return Ok(receipt),
                        Err(error)
                            if error.is_stale_guard()
                                && !execution.is_prepared()
                                && attempt < self.config.write_retry_limit =>
                        {
                            attempt += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .await
    }

    pub async fn publish_relay_assignment(
        &self,
        params: PublishRelayAssignmentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        self.ensure_authority_can_publish(&params.authority, RELAY_ASSIGNMENT_DOC_TYPE)?;
        if !params.relay_assignment.is_object() {
            return Err(SnBnsControllerError::InvalidInput(
                "relay_assignment must be a JSON object".to_string(),
            ));
        }
        let execute_params = params.clone();

        self.run_idempotent(
            &params.request_id,
            BnsWriteOperation::PublishRelayAssignment,
            &params.name,
            Some(RELAY_ASSIGNMENT_DOC_TYPE),
            &params,
            |execution| async move {
                self.publish_inline_document_once(
                    &execution,
                    &execute_params.request_id,
                    BnsWriteOperation::PublishRelayAssignment,
                    &execute_params.name,
                    RELAY_ASSIGNMENT_DOC_TYPE,
                    &execute_params.relay_assignment,
                    execute_params.authority.clone(),
                )
                .await
            },
        )
        .await
    }

    async fn upsert_dns_txt_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        params: &UpsertDnsTxtParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self
            .current_document_state(&params.name, DNS_TXT_DOC_TYPE)
            .await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        let mut records = match current.as_ref() {
            Some(state) => dns_document::txt_records_from_document(state)
                .map_err(SnBnsControllerError::from)?,
            None => Vec::new(),
        };

        match &params.update {
            DnsTxtUpdate::Add { ttl, value } => {
                DnsTxtRecord::new(*ttl, value.clone()).map_err(SnBnsControllerError::from)?;
                if !records.iter().any(|record| record.value == *value) {
                    records.push(DnsTxtRecord {
                        ttl: *ttl,
                        value: value.clone(),
                    });
                }
            }
            DnsTxtUpdate::Remove { value } => {
                records.retain(|record| record.value != *value);
            }
            DnsTxtUpdate::Replace { records: next } => {
                for record in next {
                    DnsTxtRecord::new(record.ttl, record.value.clone())
                        .map_err(SnBnsControllerError::from)?;
                }
                records = next.clone();
            }
        }

        let update = self.dns_txt_update(expected_version, &records)?;
        self.publish_document_update_once(
            execution,
            &params.request_id,
            BnsWriteOperation::UpsertDnsTxt,
            &params.name,
            update,
            params.authority.clone(),
        )
        .await
    }

    async fn publish_json_document_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self.current_document_state(name, doc_type).await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        self.publish_json_document_with_expected_once(
            execution,
            request_id,
            operation,
            name,
            doc_type,
            expected_version,
            document,
            authority,
        )
        .await
    }

    async fn publish_inline_document_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self.current_document_state(name, doc_type).await?;
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        let update = self.inline_content_update(doc_type, expected_version, document)?;
        self.publish_document_update_once(execution, request_id, operation, name, update, authority)
            .await
    }

    async fn publish_guarded_owner_document_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        params: &PublishDocumentParams,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let current = self
            .current_document_state(&params.name, OWNER_DOC_TYPE)
            .await?;
        if let Some(state) = current.as_ref() {
            let current_document = self.parse_inline_document::<Value>(state)?;
            ensure_owner_identity_fields_unchanged(&current_document, &params.document)?;
        }
        let expected_version = current.as_ref().map_or(0, |state| state.version);
        self.publish_json_document_with_expected_once(
            execution,
            &params.request_id,
            BnsWriteOperation::PublishDocument,
            &params.name,
            OWNER_DOC_TYPE,
            expected_version,
            &params.document,
            params.authority.clone(),
        )
        .await
    }

    async fn publish_json_document_with_expected_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let update = self.inline_json_update(doc_type, expected_version, document)?;
        self.publish_document_update_once(execution, request_id, operation, name, update, authority)
            .await
    }

    async fn publish_document_update_once(
        &self,
        execution: &SnBnsIdempotentExecution,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        update: DocumentUpdate,
        authority: CallAuthority,
    ) -> SnBnsControllerResult<BnsWriteReceipt> {
        let name_state = self.required_name_state(name).await?;
        let guard = MutationGuard {
            expected_name_seq: name_state.name_seq,
            expected_parent_name_seq: 0,
        };
        let authority_set = self.client.get_authority_set(name).await?;
        let prepared = self
            .write_backend
            .prepare_publish_document(BnsPublishDocumentReq {
                name: name.to_string(),
                update: update.clone(),
                authority,
                guard,
            })
            .await?;
        let output = receipt_from_submitted_document(
            request_id,
            operation,
            &name_state,
            &update,
            &authority_set,
            prepared.submission(),
        );
        execution.persist_and_submit(&prepared, &output).await?;
        Ok(output)
    }

    async fn current_document_state(
        &self,
        name: &str,
        doc_type: &str,
    ) -> SnBnsControllerResult<Option<DocumentState>> {
        match self.client.resolve_document(name, doc_type).await {
            Ok(result) if result.status == DocumentStatus::Missing => Ok(None),
            Ok(result) => Ok(Some(result.document_state)),
            Err(error) if error.is_registry_code("DOCUMENT_NOT_FOUND") => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn required_name_state(&self, name: &str) -> SnBnsControllerResult<NameState> {
        self.client
            .query_name_state(name)
            .await?
            .ok_or_else(|| {
                BnsClientError::Registry(BnsRpcErrorInfo {
                    code: "NAME_NOT_FOUND".to_string(),
                    message: format!("name `{}` was not found", name),
                    name: Some(name.to_string()),
                    doc_type: None,
                    expected: None,
                    actual: None,
                })
            })
            .map_err(SnBnsControllerError::from)
    }

    fn inline_json_update(
        &self,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
    ) -> SnBnsControllerResult<DocumentUpdate> {
        canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        let bytes = serde_json::to_vec(document)?;
        if bytes.is_empty() || bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "inline document `{}` is {} bytes, max {}",
                doc_type,
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(doc_type, expected_version, DocumentRef::inline(bytes))
            .map_err(SnBnsControllerError::from)
    }

    fn inline_content_update(
        &self,
        doc_type: &str,
        expected_version: u64,
        document: &Value,
    ) -> SnBnsControllerResult<DocumentUpdate> {
        canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        let bytes = match document {
            Value::Object(_) => serde_json::to_vec(document)?,
            Value::String(text) if !text.trim().is_empty() => text.as_bytes().to_vec(),
            _ => {
                return Err(SnBnsControllerError::InvalidInput(
                    "document must be a JSON object or non-empty text string".to_string(),
                ));
            }
        };
        if bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "inline document `{}` is {} bytes, max {}",
                doc_type,
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(doc_type, expected_version, DocumentRef::inline(bytes))
            .map_err(SnBnsControllerError::from)
    }

    fn dns_txt_update(
        &self,
        expected_version: u64,
        records: &[DnsTxtRecord],
    ) -> SnBnsControllerResult<DocumentUpdate> {
        let bytes = serde_json::to_vec(records)?;
        if bytes.len() > self.config.max_inline_document_size {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "dns_txt inline document is {} bytes, max {}",
                bytes.len(),
                self.config.max_inline_document_size
            )));
        }
        default_document_update(
            DNS_TXT_DOC_TYPE,
            expected_version,
            DocumentRef::inline(bytes),
        )
        .map_err(SnBnsControllerError::from)
    }

    fn parse_inline_document<T: DeserializeOwned>(
        &self,
        state: &DocumentState,
    ) -> SnBnsControllerResult<T> {
        if state.document.storage_type != crate::STORAGE_TYPE_INLINE {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "document `{}/{}` is not inline",
                state.name, state.doc_type
            )));
        }
        serde_json::from_slice(&state.document.inline_document).map_err(Into::into)
    }

    fn ensure_owner_authority(
        &self,
        authority: &CallAuthority,
        doc_type: &str,
    ) -> SnBnsControllerResult<()> {
        if authority.role == AuthorityRole::Owner {
            Ok(())
        } else {
            Err(SnBnsControllerError::InvalidInput(format!(
                "doc_type `{}` requires owner authority",
                doc_type
            )))
        }
    }

    fn ensure_owner_authority_or_public_registration(
        &self,
        authority: &CallAuthority,
    ) -> SnBnsControllerResult<()> {
        if matches!(authority.role, AuthorityRole::Owner | AuthorityRole::None) {
            Ok(())
        } else {
            Err(SnBnsControllerError::InvalidInput(
                "register_name requires owner authority for subnames or public authority for root registration"
                    .to_string(),
            ))
        }
    }

    fn ensure_authority_can_publish(
        &self,
        authority: &CallAuthority,
        doc_type: &str,
    ) -> SnBnsControllerResult<()> {
        match authority.role {
            AuthorityRole::Owner => Ok(()),
            AuthorityRole::Controller => {
                if !self
                    .config
                    .allowed_controller_doc_types
                    .iter()
                    .any(|allowed| allowed.is_empty() || allowed == doc_type)
                {
                    return Err(SnBnsControllerError::InvalidInput(format!(
                        "SN controller is not allowed to publish doc_type `{}`",
                        doc_type
                    )));
                }
                if authority.actor != self.config.sn_controller_principal {
                    return Err(SnBnsControllerError::InvalidInput(
                        "controller authority actor does not match configured SN controller"
                            .to_string(),
                    ));
                }
                if authority.actor.kind == PrincipalKind::BnsName
                    && authority.kid != self.config.sn_controller_kid
                {
                    return Err(SnBnsControllerError::InvalidInput(
                        "controller authority kid does not match configured SN controller key"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            AuthorityRole::None => Err(SnBnsControllerError::InvalidInput(format!(
                "doc_type `{}` requires owner or controller authority",
                doc_type
            ))),
        }
    }

    fn validate_device_name(&self, device_name: &str) -> SnBnsControllerResult<()> {
        if device_name.is_empty() || device_name.len() > 64 {
            return Err(SnBnsControllerError::InvalidInput(
                "device_name must be 1..64 bytes".to_string(),
            ));
        }
        if !device_name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(SnBnsControllerError::InvalidInput(
                "device_name only supports lower-case ASCII letters, digits, '-' and '_'"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn register_output_from_submission(
        &self,
        request_id: &str,
        name: &str,
        controller_policy_hash: &str,
        submission: BnsEvmTxSubmission,
    ) -> RegisterNameOutput {
        RegisterNameOutput {
            receipt: BnsWriteReceipt {
                request_id: request_id.to_string(),
                name: name.to_string(),
                operation: BnsWriteOperation::RegisterName,
                status: BnsWriteReceiptStatus::Submitted,
                name_seq: 0,
                doc_type: None,
                document_version: None,
                content_hash: None,
                document_state_hash: None,
                authority_seq: 0,
                authority_root: ZERO_HASH.to_string(),
                controller_policy_hash: Some(controller_policy_hash.to_string()),
                evm_chain_id: Some(submission.chain_id),
                evm_nonce: Some(submission.nonce),
                evm_tx_hash: Some(submission.tx_hash),
                evm_raw_tx: Some(submission.raw_tx),
                created_or_reused: false,
            },
            initial_documents: Vec::new(),
        }
    }

    async fn transition_from_chain_state(
        &self,
        mut record: SnBnsWriteRequestRecord,
        state: BnsTxExecutionState,
        from_recovery_failure: bool,
    ) -> SnBnsControllerResult<SnBnsWriteRequestRecord> {
        record.state = match state {
            BnsTxExecutionState::Pending => BnsWriteRequestState::Pending,
            BnsTxExecutionState::Succeeded => BnsWriteRequestState::Succeeded,
            BnsTxExecutionState::Reverted => BnsWriteRequestState::Reverted,
            BnsTxExecutionState::NotFound => {
                return Err(SnBnsControllerError::Store(
                    "cannot transition a request from a NotFound chain state".to_string(),
                ));
            }
        };
        if record.state == BnsWriteRequestState::Reverted {
            record.error_code = Some("EVM_TX_REVERTED".to_string());
            record.error_message = Some(format!(
                "BNS EVM tx {} reverted",
                record.evm_tx_hash.as_deref().unwrap_or("<unknown>")
            ));
        } else {
            record.error_code = None;
            record.error_message = None;
        }
        record.updated_at = crate::now_timestamp();
        let updated = if from_recovery_failure {
            self.idempotency_store
                .resolve_recovery_failed(record.clone())?
        } else {
            self.idempotency_store.update_inflight(record.clone())?
        };
        if updated {
            return Ok(record);
        }
        let latest = self
            .idempotency_store
            .get(record.request_id.as_str())?
            .ok_or_else(|| {
                SnBnsControllerError::Store(format!(
                    "request `{}` disappeared during chain-state recovery",
                    record.request_id
                ))
            })?;
        if latest.state != record.state
            || latest.payload_hash != record.payload_hash
            || latest.evm_tx_hash != record.evm_tx_hash
            || latest.evm_raw_tx != record.evm_raw_tx
        {
            return Err(SnBnsControllerError::Store(format!(
                "request `{}` lost its chain-state recovery transition",
                record.request_id
            )));
        }
        Ok(latest)
    }

    fn quarantine_invalid_recovery_record(
        &self,
        mut record: SnBnsWriteRequestRecord,
        reason: &str,
    ) -> SnBnsControllerResult<SnBnsWriteRequestRecord> {
        record.state = BnsWriteRequestState::Failed;
        record.error_code = Some(EVM_TX_RECOVERY_DATA_INVALID.to_string());
        record.error_message = Some(reason.to_string());
        record.updated_at = crate::now_timestamp();
        if self.idempotency_store.update_inflight(record.clone())? {
            return Ok(record);
        }
        let latest = self
            .idempotency_store
            .get(record.request_id.as_str())?
            .ok_or_else(|| {
                SnBnsControllerError::Store(format!(
                    "request `{}` disappeared while quarantining invalid recovery data",
                    record.request_id
                ))
            })?;
        if latest.state != BnsWriteRequestState::Failed
            || latest.error_code.as_deref() != Some(EVM_TX_RECOVERY_DATA_INVALID)
            || latest.payload_hash != record.payload_hash
            || latest.evm_tx_hash != record.evm_tx_hash
            || latest.evm_raw_tx != record.evm_raw_tx
        {
            return Err(SnBnsControllerError::Store(format!(
                "request `{}` lost its recovery quarantine transition",
                record.request_id
            )));
        }
        Ok(latest)
    }

    fn recovery_data_error(
        record: &SnBnsWriteRequestRecord,
        reason: impl Into<String>,
    ) -> SnBnsControllerError {
        SnBnsControllerError::Bns(BnsClientError::registry(
            EVM_TX_RECOVERY_DATA_INVALID,
            format!(
                "request `{}` cannot recover its stored EVM transaction: {}",
                record.request_id,
                reason.into()
            ),
        ))
    }

    async fn reconcile_invalid_record(
        &self,
        record: SnBnsWriteRequestRecord,
        reason: String,
        mode: SnBnsRecoveryMode,
    ) -> SnBnsControllerResult<SnBnsReconcileAction> {
        if let Some(tx_hash) = record.evm_tx_hash.as_deref() {
            match self.write_backend.query_tx_state(tx_hash).await? {
                BnsTxState {
                    state: BnsTxExecutionState::NotFound,
                    ..
                } => {
                    let quarantined = self.quarantine_invalid_recovery_record(record, &reason)?;
                    if mode == SnBnsRecoveryMode::RequestReplay {
                        let removed = self.idempotency_store.remove_recovery_failed(
                            quarantined.request_id.as_str(),
                            quarantined.payload_hash.as_str(),
                            quarantined.evm_tx_hash.as_deref(),
                            quarantined.evm_raw_tx.as_deref(),
                        )?;
                        if removed {
                            return Ok(SnBnsReconcileAction::Execute);
                        }
                    }
                    return Err(Self::recovery_data_error(&quarantined, reason));
                }
                state => {
                    let record = self
                        .transition_from_chain_state(record, state.state, false)
                        .await?;
                    return Ok(SnBnsReconcileAction::Record(record));
                }
            }
        }

        let quarantined = self.quarantine_invalid_recovery_record(record, &reason)?;
        Err(Self::recovery_data_error(&quarantined, reason))
    }

    async fn reconcile_inflight_record(
        &self,
        mut record: SnBnsWriteRequestRecord,
        mode: SnBnsRecoveryMode,
    ) -> SnBnsControllerResult<SnBnsReconcileAction> {
        if record.evm_tx_hash.is_none() && record.evm_raw_tx.is_none() {
            if self
                .idempotency_store
                .remove_unprepared(record.request_id.as_str(), record.payload_hash.as_str())?
            {
                return Ok(SnBnsReconcileAction::Execute);
            }
            return Err(SnBnsControllerError::Store(format!(
                "request `{}` could not remove its legacy pre-broadcast record",
                record.request_id
            )));
        }

        let Some(stored_raw_tx) = record.evm_raw_tx.clone() else {
            return self
                .reconcile_invalid_record(
                    record,
                    "stored transaction hash has no raw transaction".to_string(),
                    mode,
                )
                .await;
        };

        if let (Some(tx_hash), Some(nonce), Some(chain_id)) = (
            record.evm_tx_hash.clone(),
            record.evm_nonce,
            record.evm_chain_id,
        ) {
            let prepared = BnsEvmPreparedTx {
                tx_hash,
                raw_tx: stored_raw_tx,
                from: String::new(),
                nonce,
                chain_id,
            };
            return self.recover_prepared_record(record, prepared, mode).await;
        }

        let decoded = match BnsEvmPreparedTx::from_raw_tx(stored_raw_tx.clone()) {
            Ok(decoded) => decoded,
            Err(error) => {
                return self
                    .reconcile_invalid_record(
                        record,
                        format!("decode stored raw transaction failed: {error}"),
                        mode,
                    )
                    .await;
            }
        };

        let stored_hash = record.evm_tx_hash.clone();
        if let Some(stored_hash) = stored_hash.as_deref() {
            if !stored_hash.eq_ignore_ascii_case(decoded.tx_hash.as_str()) {
                let state = self.write_backend.query_tx_state(stored_hash).await?;
                if state.state != BnsTxExecutionState::NotFound {
                    let record = self
                        .transition_from_chain_state(record, state.state, false)
                        .await?;
                    return Ok(SnBnsReconcileAction::Record(record));
                }
            }
        }

        let metadata_needs_repair = record.evm_tx_hash.as_deref() != Some(decoded.tx_hash.as_str())
            || record.evm_raw_tx.as_deref() != Some(decoded.raw_tx.as_str())
            || record.evm_chain_id != Some(decoded.chain_id)
            || record.evm_nonce != Some(decoded.nonce);
        if metadata_needs_repair {
            if !self.idempotency_store.repair_prepared_metadata(
                record.request_id.as_str(),
                record.payload_hash.as_str(),
                stored_raw_tx.as_str(),
                stored_hash.as_deref(),
                &decoded,
                crate::now_timestamp(),
            )? {
                return Err(SnBnsControllerError::Store(format!(
                    "request `{}` could not repair its prepared transaction metadata",
                    record.request_id
                )));
            }
            record.evm_chain_id = Some(decoded.chain_id);
            record.evm_nonce = Some(decoded.nonce);
            record.evm_tx_hash = Some(decoded.tx_hash.clone());
            record.evm_raw_tx = Some(decoded.raw_tx.clone());
        }

        self.recover_prepared_record(record, decoded, mode).await
    }

    async fn recover_prepared_record(
        &self,
        record: SnBnsWriteRequestRecord,
        prepared: BnsEvmPreparedTx,
        mode: SnBnsRecoveryMode,
    ) -> SnBnsControllerResult<SnBnsReconcileAction> {
        match self.write_backend.recover_prepared(&prepared).await {
            Ok(submission) => {
                let state = submission_state(&submission);
                let state = match state {
                    BnsWriteRequestState::Pending => BnsTxExecutionState::Pending,
                    BnsWriteRequestState::Succeeded => BnsTxExecutionState::Succeeded,
                    BnsWriteRequestState::Reverted => BnsTxExecutionState::Reverted,
                    BnsWriteRequestState::Sending | BnsWriteRequestState::Failed => {
                        return Err(SnBnsControllerError::Store(
                            "recovered submission returned an invalid state".to_string(),
                        ));
                    }
                };
                let record = self
                    .transition_from_chain_state(record, state, false)
                    .await?;
                Ok(SnBnsReconcileAction::Record(record))
            }
            Err(error) if error.code() == "EVM_TX_REVERTED" => {
                let record = self
                    .transition_from_chain_state(record, BnsTxExecutionState::Reverted, false)
                    .await?;
                Ok(SnBnsReconcileAction::Record(record))
            }
            Err(error) if error.code() == "SERIALIZATION_ERROR" => {
                self.reconcile_invalid_record(record, error.to_string(), mode)
                    .await
            }
            Err(error) => Err(error),
        }
    }

    async fn retry_recovery_failed_record(
        &self,
        record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<SnBnsReconcileAction> {
        let Some(tx_hash) = record.evm_tx_hash.as_deref() else {
            if self.idempotency_store.remove_recovery_failed(
                record.request_id.as_str(),
                record.payload_hash.as_str(),
                None,
                record.evm_raw_tx.as_deref(),
            )? {
                return Ok(SnBnsReconcileAction::Execute);
            }
            return Err(SnBnsControllerError::Store(format!(
                "request `{}` could not remove its unqueryable recovery failure",
                record.request_id
            )));
        };
        let state = self.write_backend.query_tx_state(tx_hash).await?;
        if state.state == BnsTxExecutionState::NotFound {
            if self.idempotency_store.remove_recovery_failed(
                record.request_id.as_str(),
                record.payload_hash.as_str(),
                record.evm_tx_hash.as_deref(),
                record.evm_raw_tx.as_deref(),
            )? {
                return Ok(SnBnsReconcileAction::Execute);
            }
            return Err(SnBnsControllerError::Store(format!(
                "request `{}` could not remove its retryable recovery failure",
                record.request_id
            )));
        }
        let record = self
            .transition_from_chain_state(record, state.state, true)
            .await?;
        Ok(SnBnsReconcileAction::Record(record))
    }

    async fn handle_existing<T>(
        &self,
        mut record: SnBnsWriteRequestRecord,
    ) -> SnBnsControllerResult<SnBnsExistingAction<T>>
    where
        T: DeserializeOwned + MarkIdempotentReuse,
    {
        if record.state == BnsWriteRequestState::Failed
            && record.error_code.as_deref() == Some(EVM_TX_RECOVERY_DATA_INVALID)
        {
            match self.retry_recovery_failed_record(record).await? {
                SnBnsReconcileAction::Record(next) => record = next,
                SnBnsReconcileAction::Execute => return Ok(SnBnsExistingAction::Execute),
            }
        }

        if matches!(
            record.state,
            BnsWriteRequestState::Sending | BnsWriteRequestState::Pending
        ) {
            match self
                .reconcile_inflight_record(record, SnBnsRecoveryMode::RequestReplay)
                .await?
            {
                SnBnsReconcileAction::Record(next) => record = next,
                SnBnsReconcileAction::Execute => return Ok(SnBnsExistingAction::Execute),
            }
        }

        match record.state {
            BnsWriteRequestState::Pending | BnsWriteRequestState::Succeeded => {
                let value = record.result_json.ok_or_else(|| {
                    SnBnsControllerError::Store(format!(
                        "request `{}` has no provisional result",
                        record.request_id
                    ))
                })?;
                let mut result: T = serde_json::from_value(value)?;
                result.mark_reused();
                Ok(SnBnsExistingAction::Return(result))
            }
            BnsWriteRequestState::Reverted | BnsWriteRequestState::Failed => {
                Err(SnBnsControllerError::IdempotencyPreviousFailure {
                    request_id: record.request_id,
                    message: record
                        .error_message
                        .unwrap_or_else(|| "previous request failed".to_string()),
                })
            }
            BnsWriteRequestState::Sending => Err(SnBnsControllerError::IdempotencyPending {
                request_id: record.request_id,
            }),
        }
    }

    pub async fn recover_inflight_requests(&self) -> SnBnsControllerResult<SnBnsRecoveryReport> {
        let _write_guard = self.idempotency_store.execution_lock().lock().await;
        let records = self.idempotency_store.list_inflight()?;
        let mut report = SnBnsRecoveryReport {
            scanned: records.len(),
            ..Default::default()
        };
        for record in records {
            let request_id = record.request_id.clone();
            let name = record.name.clone();
            let tx_hash = record.evm_tx_hash.clone();
            match self
                .reconcile_inflight_record(record, SnBnsRecoveryMode::Startup)
                .await
            {
                Ok(_) => report.recovered += 1,
                Err(error) => report.failures.push(SnBnsRecoveryFailure {
                    request_id,
                    name,
                    tx_hash,
                    error_code: error.code().to_string(),
                    error_message: error.to_string(),
                }),
            }
        }
        Ok(report)
    }

    async fn run_idempotent<T, P, F, Fut>(
        &self,
        request_id: &str,
        operation: BnsWriteOperation,
        name: &str,
        doc_type: Option<&str>,
        payload: &P,
        execute: F,
    ) -> SnBnsControllerResult<T>
    where
        T: Serialize + DeserializeOwned + MarkIdempotentReuse,
        P: Serialize + ?Sized,
        F: FnOnce(SnBnsIdempotentExecution) -> Fut,
        Fut: Future<Output = SnBnsControllerResult<T>>,
    {
        let _write_guard = self.idempotency_store.execution_lock().lock().await;
        if request_id.is_empty() {
            return Err(SnBnsControllerError::InvalidInput(
                "request_id is required".to_string(),
            ));
        }
        canonical_bns_name(name).map_err(SnBnsControllerError::from)?;
        if let Some(doc_type) = doc_type {
            canonical_doc_type(doc_type).map_err(SnBnsControllerError::from)?;
        }

        let payload_hash = hash_json(payload).map_err(SnBnsControllerError::from)?;
        if let Some(record) = self.idempotency_store.get(request_id)? {
            if record.payload_hash != payload_hash {
                return Err(SnBnsControllerError::IdempotencyConflict {
                    request_id: request_id.to_string(),
                });
            }
            match self.handle_existing(record).await? {
                SnBnsExistingAction::Return(value) => return Ok(value),
                SnBnsExistingAction::Execute => {}
            }
        }

        let now = crate::now_timestamp();
        let base_record = SnBnsWriteRequestRecord {
            request_id: request_id.to_string(),
            operation,
            name: name.to_string(),
            doc_type: doc_type.map(str::to_string),
            payload_hash: payload_hash.clone(),
            state: BnsWriteRequestState::Sending,
            result_json: None,
            error_code: None,
            error_message: None,
            lease_owner: None,
            lease_expires_at: None,
            evm_chain_id: None,
            evm_nonce: None,
            evm_tx_hash: None,
            evm_raw_tx: None,
            created_at: now,
            updated_at: now,
        };

        let execution = SnBnsIdempotentExecution::new(
            self.idempotency_store.clone(),
            self.write_backend.clone(),
            base_record,
        );
        let result = execute(execution.clone()).await;
        match result {
            Ok(value) => Ok(value),
            Err(error) if execution.is_prepared() => {
                // The network may have accepted the transaction even though
                // the submit call failed. Preserve Sending + raw_tx so startup
                // or a request-id replay can query/rebroadcast the exact bytes.
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterNameParams {
    pub request_id: String,
    pub name: String,
    pub asset_owner: String,
    pub register_options: RegisterOptions,
    pub owner_config: Value,
    pub owner_authority_keys: Vec<AuthorityKeyUpdate>,
    pub semantic_owner_after_authority: Option<Principal>,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

pub type BootstrapNameParams = RegisterNameParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishOwnerDocumentParams {
    pub request_id: String,
    pub name: String,
    pub owner_config: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDocumentParams {
    pub request_id: String,
    pub name: String,
    pub doc_type: String,
    pub document: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveBoundZoneParams {
    pub request_id: String,
    pub name: String,
    pub zone_did: String,
    pub expected_owner_hash: String,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindZoneDocumentsParams {
    pub request_id: String,
    pub name: String,
    pub zone_config: Value,
    pub boot_config: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDeviceMiniDocParams {
    pub request_id: String,
    pub name: String,
    pub device_name: String,
    pub did: String,
    pub device_mini_doc: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DnsTxtUpdate {
    Add { ttl: u32, value: String },
    Remove { value: String },
    Replace { records: Vec<DnsTxtRecord> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertDnsTxtParams {
    pub request_id: String,
    pub name: String,
    pub update: DnsTxtUpdate,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRelayAssignmentParams {
    pub request_id: String,
    pub name: String,
    pub relay_assignment: Value,
    pub authority: CallAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceMiniDocCollection {
    version: u32,
    devices: BTreeMap<String, Value>,
}

impl Default for DeviceMiniDocCollection {
    fn default() -> Self {
        Self {
            version: 1,
            devices: BTreeMap::new(),
        }
    }
}

const ZONE_BINDING_MODEL_VERSION: u64 = 2;

fn validate_owner_document_hash(value: &str) -> SnBnsControllerResult<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SnBnsControllerError::InvalidInput(
            "expected_owner_hash must use the sha256:<64 lowercase hex> format".to_string(),
        ));
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(SnBnsControllerError::InvalidInput(
            "expected_owner_hash must use the sha256:<64 lowercase hex> format".to_string(),
        ));
    }
    Ok(())
}

fn zone_did_hostname(zone_did: &str) -> SnBnsControllerResult<String> {
    let mut parts = zone_did.splitn(3, ':');
    if parts.next() != Some("did") {
        return Err(SnBnsControllerError::InvalidInput(format!(
            "invalid zone DID `{zone_did}`"
        )));
    }
    let method = parts.next().unwrap_or_default();
    let id = parts.next().unwrap_or_default();
    let hostname = id.split(':').next().unwrap_or_default();
    if method.is_empty() || hostname.is_empty() {
        return Err(SnBnsControllerError::InvalidInput(format!(
            "invalid zone DID `{zone_did}`"
        )));
    }
    if method == "web" {
        Ok(hostname.to_string())
    } else {
        Ok(format!("{hostname}.{method}.did"))
    }
}

fn remove_owner_bound_zone(
    document: &mut Value,
    name: &str,
    zone_did: &str,
) -> SnBnsControllerResult<()> {
    let object = document.as_object_mut().ok_or_else(|| {
        SnBnsControllerError::InvalidInput("owner document must be a JSON object".to_string())
    })?;
    let expected_owner_did = format!("did:bns:{name}");
    if object.get("id").and_then(Value::as_str) != Some(expected_owner_did.as_str()) {
        return Err(SnBnsControllerError::InvalidInput(format!(
            "owner document id must be `{expected_owner_did}`"
        )));
    }

    if let Some(value) = object.get("zone_binding_model_version") {
        match value.as_u64() {
            Some(ZONE_BINDING_MODEL_VERSION) => {}
            Some(version) => {
                return Err(SnBnsControllerError::InvalidInput(format!(
                    "unsupported zone_binding_model_version `{version}`"
                )));
            }
            None => {
                return Err(SnBnsControllerError::InvalidInput(
                    "zone_binding_model_version must be an unsigned integer".to_string(),
                ));
            }
        }
    }

    let mut zones = match object.remove("binded_zone_list") {
        None => Vec::new(),
        Some(Value::Array(zones)) => zones,
        Some(_) => {
            return Err(SnBnsControllerError::InvalidInput(
                "binded_zone_list must be an array".to_string(),
            ));
        }
    };
    if zones.iter().any(|zone| !zone.is_string()) {
        return Err(SnBnsControllerError::InvalidInput(
            "binded_zone_list entries must be DID strings".to_string(),
        ));
    }
    let previous_len = zones.len();
    zones.retain(|zone| zone.as_str() != Some(zone_did));
    if zones.len() == previous_len {
        return Err(SnBnsControllerError::ZoneNotBound {
            zone_did: zone_did.to_string(),
        });
    }

    object.insert(
        "zone_binding_model_version".to_string(),
        Value::from(ZONE_BINDING_MODEL_VERSION),
    );
    if !zones.is_empty() {
        object.insert("binded_zone_list".to_string(), Value::Array(zones.clone()));
    }

    let last_doc_id = format!("{expected_owner_did}#lastDoc");
    let mut services = match object.remove("service") {
        None => Vec::new(),
        Some(Value::Array(services)) => services,
        Some(_) => {
            return Err(SnBnsControllerError::InvalidInput(
                "owner document service must be an array".to_string(),
            ));
        }
    };
    services
        .retain(|service| service.get("id").and_then(Value::as_str) != Some(last_doc_id.as_str()));
    if let Some(default_zone_did) = zones.first().and_then(Value::as_str) {
        let hostname = zone_did_hostname(default_zone_did)?;
        services.push(serde_json::json!({
            "id": last_doc_id,
            "type": "DIDDoc",
            "serviceEndpoint": format!("https://{hostname}/resolve/{expected_owner_did}"),
        }));
    }
    if !services.is_empty() {
        object.insert("service".to_string(), Value::Array(services));
    }
    Ok(())
}

const OWNER_IDENTITY_PATHS: [(&str, &[&str]); 5] = [
    ("public_key", &["public_key"]),
    ("owner_key", &["owner_key"]),
    ("default_key", &["default_key"]),
    ("key", &["key"]),
    (
        "verificationMethod[0].publicKeyJwk",
        &["verificationMethod", "0", "publicKeyJwk"],
    ),
];

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        if let Ok(index) = segment.parse::<usize>() {
            current = current.as_array()?.get(index)?;
        } else {
            current = current.get(*segment)?;
        }
    }
    Some(current)
}

fn ensure_owner_identity_fields_unchanged(
    current: &Value,
    next: &Value,
) -> SnBnsControllerResult<()> {
    for (label, path) in OWNER_IDENTITY_PATHS {
        let Some(existing) = value_at_path(current, path) else {
            continue;
        };
        if value_at_path(next, path) != Some(existing) {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "owner identity field `{label}` cannot be changed or removed"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod owner_identity_field_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_identity_fields_can_be_filled_for_the_first_time() {
        ensure_owner_identity_fields_unchanged(
            &json!({"name":"alice","created_by":"cyfs-sn"}),
            &json!({
                "name":"alice",
                "public_key":{"kty":"OKP","crv":"Ed25519","x":"alice-key"}
            }),
        )
        .unwrap();
    }

    #[test]
    fn nested_verification_method_identity_cannot_change_or_disappear() {
        let current = json!({
            "verificationMethod":[{
                "id":"did:bns:alice#default",
                "publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"alice-key"}
            }]
        });
        let changed = json!({
            "verificationMethod":[{
                "id":"did:bns:alice#default",
                "publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"other-key"}
            }]
        });
        let error = ensure_owner_identity_fields_unchanged(&current, &changed).unwrap_err();
        assert!(error
            .to_string()
            .contains("verificationMethod[0].publicKeyJwk"));

        let removed = json!({"verificationMethod":[{"id":"did:bns:alice#default"}]});
        assert!(ensure_owner_identity_fields_unchanged(&current, &removed).is_err());
    }
}

#[cfg(test)]
mod owner_zone_binding_tests {
    use super::*;
    use serde_json::json;

    fn owner_document() -> Value {
        json!({
            "id": "did:bns:alice",
            "zone_binding_model_version": 2,
            "binded_zone_list": ["did:web:zone-a.example", "did:web:zone-b.example"],
            "service": [
                {
                    "id": "did:bns:alice#profile",
                    "type": "Profile",
                    "serviceEndpoint": "https://alice.example/profile"
                },
                {
                    "id": "did:bns:alice#lastDoc",
                    "type": "DIDDoc",
                    "serviceEndpoint": "https://zone-a.example/resolve/did:bns:alice"
                }
            ]
        })
    }

    #[test]
    fn canonical_owner_hash_ignores_object_insertion_order() {
        let left = json!({"id":"did:bns:alice","nested":{"b":2,"a":1}});
        let right = json!({"nested":{"a":1,"b":2},"id":"did:bns:alice"});
        assert_eq!(
            canonical_json_sha256(&left).unwrap(),
            canonical_json_sha256(&right).unwrap()
        );
    }

    #[test]
    fn removing_default_zone_promotes_next_zone_and_preserves_other_services() {
        let mut document = owner_document();
        remove_owner_bound_zone(&mut document, "alice", "did:web:zone-a.example").unwrap();

        assert_eq!(document["zone_binding_model_version"], json!(2));
        assert_eq!(
            document["binded_zone_list"],
            json!(["did:web:zone-b.example"])
        );
        let services = document["service"].as_array().unwrap();
        assert!(services.iter().any(|service| {
            service["id"] == "did:bns:alice#profile"
                && service["serviceEndpoint"] == "https://alice.example/profile"
        }));
        assert!(services.iter().any(|service| {
            service["id"] == "did:bns:alice#lastDoc"
                && service["serviceEndpoint"] == "https://zone-b.example/resolve/did:bns:alice"
        }));
    }

    #[test]
    fn removing_non_default_zone_keeps_default_last_doc() {
        let mut document = owner_document();
        remove_owner_bound_zone(&mut document, "alice", "did:web:zone-b.example").unwrap();

        assert_eq!(
            document["binded_zone_list"],
            json!(["did:web:zone-a.example"])
        );
        let last_doc = document["service"]
            .as_array()
            .unwrap()
            .iter()
            .find(|service| service["id"] == "did:bns:alice#lastDoc")
            .unwrap();
        assert_eq!(
            last_doc["serviceEndpoint"],
            "https://zone-a.example/resolve/did:bns:alice"
        );
    }

    #[test]
    fn removing_last_zone_records_v2_unbound_state() {
        let mut document = json!({
            "id": "did:bns:alice",
            "binded_zone_list": ["did:web:zone-a.example"],
            "service": [
                {"id":"did:bns:alice#lastDoc","type":"DIDDoc","serviceEndpoint":"old"},
                {"id":"did:bns:alice#profile","type":"Profile","serviceEndpoint":"keep"}
            ]
        });
        remove_owner_bound_zone(&mut document, "alice", "did:web:zone-a.example").unwrap();

        assert_eq!(document["zone_binding_model_version"], json!(2));
        assert!(document.get("binded_zone_list").is_none());
        assert_eq!(
            document["service"],
            json!([{"id":"did:bns:alice#profile","type":"Profile","serviceEndpoint":"keep"}])
        );
    }

    #[test]
    fn removal_is_exact_and_rejects_unsupported_or_unbound_state() {
        let mut document = owner_document();
        let error =
            remove_owner_bound_zone(&mut document, "alice", "did:web:zone.example").unwrap_err();
        assert!(matches!(error, SnBnsControllerError::ZoneNotBound { .. }));

        document["zone_binding_model_version"] = json!(3);
        let error =
            remove_owner_bound_zone(&mut document, "alice", "did:web:zone-a.example").unwrap_err();
        assert!(matches!(error, SnBnsControllerError::InvalidInput(_)));
        assert!(error
            .to_string()
            .contains("unsupported zone_binding_model_version"));

        document["zone_binding_model_version"] = json!("2");
        let error =
            remove_owner_bound_zone(&mut document, "alice", "did:web:zone-a.example").unwrap_err();
        assert!(error.to_string().contains("must be an unsigned integer"));
    }

    #[test]
    fn owner_hash_requires_lowercase_sha256_format() {
        assert!(validate_owner_document_hash(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
        assert!(validate_owner_document_hash(
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_err());
        assert!(validate_owner_document_hash("0123").is_err());
    }
}

fn normalize_device_mini_doc_entry(
    did: &str,
    device_mini_doc: Value,
) -> SnBnsControllerResult<Value> {
    let mut object = match device_mini_doc {
        Value::Object(object) => object,
        _ => {
            return Err(SnBnsControllerError::InvalidInput(
                "device_mini_doc must be a JSON object".to_string(),
            ));
        }
    };

    match object.get("did") {
        Some(Value::String(existing)) if existing == did => {}
        Some(Value::String(existing)) => {
            return Err(SnBnsControllerError::InvalidInput(format!(
                "device_mini_doc did `{}` does not match `{}`",
                existing, did
            )));
        }
        Some(_) => {
            return Err(SnBnsControllerError::InvalidInput(
                "device_mini_doc did must be a string".to_string(),
            ));
        }
        None => {
            object.insert("did".to_string(), Value::String(did.to_string()));
        }
    }

    Ok(Value::Object(object))
}

fn receipt_from_submitted_document(
    request_id: &str,
    operation: BnsWriteOperation,
    name_state: &NameState,
    update: &DocumentUpdate,
    authority_set: &AuthoritySetState,
    submission: BnsEvmTxSubmission,
) -> BnsWriteReceipt {
    BnsWriteReceipt {
        request_id: request_id.to_string(),
        name: name_state.name.clone(),
        operation,
        status: BnsWriteReceiptStatus::Submitted,
        name_seq: name_state.name_seq,
        doc_type: Some(update.doc_type.clone()),
        document_version: Some(update.expected_version + 1),
        content_hash: Some(update.document.content_hash.clone()),
        document_state_hash: None,
        authority_seq: authority_set.authority_seq,
        authority_root: authority_set.authority_root.clone(),
        controller_policy_hash: Some(update.controller_policy_hash.clone()),
        evm_chain_id: Some(submission.chain_id),
        evm_nonce: Some(submission.nonce),
        evm_tx_hash: Some(submission.tx_hash),
        evm_raw_tx: Some(submission.raw_tx),
        created_or_reused: false,
    }
}
