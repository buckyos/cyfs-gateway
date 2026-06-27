use ::kRPC::{kRPC, RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use async_trait::async_trait;
use bns_indexer::{
    AuthorityKey, AuthorityKeyUpdate, AuthoritySetState, BnsRegistryError, BnsRegistryResult,
    BnsRegistryStore, CallAuthority, CentralizedBnsRegistry, ControllerRule, DocumentState,
    DocumentUpdate, EventLogRecord, LogCheckpoint, MutationGuard, NameState, OwnerResolution,
    RegisterOptions, ResolveResult,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;

pub const BNS_INDEXER_RPC_PATH: &str = "/kapi/bns-indexer";
pub const BNS_SERVER_RPC_PATH: &str = "/kapi/bns";

pub const METHOD_QUERY_NAME_STATE: &str = "name.query_state";
pub const METHOD_RESOLVE_OWNER: &str = "name.resolve_owner";
pub const METHOD_GET_AUTHORITY_SET: &str = "authority.get_set";
pub const METHOD_GET_AUTHORITY_KEY: &str = "authority.get_key";
pub const METHOD_RESOLVE_DOCUMENT: &str = "document.resolve";
pub const METHOD_GET_DOCUMENT_VERSION: &str = "document.get_version";
pub const METHOD_SUBMIT_RAW_TX: &str = "tx.submit_raw";
pub const METHOD_REGISTER_NAME: &str = "name.register";
pub const METHOD_BOOTSTRAP_NAME: &str = "name.bootstrap";
pub const METHOD_PUBLISH_DOCUMENT: &str = "document.publish";
pub const METHOD_REVOKE_DOCUMENT: &str = "document.revoke";
pub const METHOD_SET_CONTROLLER_POLICY: &str = "controller.set_policy";
pub const METHOD_UPDATE_AUTHORITY_KEYS: &str = "authority.update_keys";
pub const METHOD_LIST_EVENTS: &str = "events.list";
pub const METHOD_LATEST_CHECKPOINT: &str = "checkpoint.latest";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsRpcErrorInfo {
    pub code: String,
    pub message: String,
    pub name: Option<String>,
    pub doc_type: Option<String>,
    pub expected: Option<u64>,
    pub actual: Option<u64>,
}

impl BnsRpcErrorInfo {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            name: None,
            doc_type: None,
            expected: None,
            actual: None,
        }
    }

    pub fn from_registry_error(error: &BnsRegistryError) -> Self {
        let mut info = Self::new(error.code(), error.to_string());
        match error {
            BnsRegistryError::InvalidName { name, .. }
            | BnsRegistryError::NameAlreadyExists { name }
            | BnsRegistryError::NameNotFound { name }
            | BnsRegistryError::NotEffectiveOwner { name }
            | BnsRegistryError::StandardTransferDisabled { name } => {
                info.name = Some(name.clone());
            }
            BnsRegistryError::InvalidDocType { doc_type, .. } => {
                info.doc_type = Some(doc_type.clone());
            }
            BnsRegistryError::DocumentNotFound { name, doc_type }
            | BnsRegistryError::ControllerScopeDenied { name, doc_type, .. } => {
                info.name = Some(name.clone());
                info.doc_type = Some(doc_type.clone());
            }
            BnsRegistryError::StaleNameSeq {
                name,
                expected,
                actual,
            }
            | BnsRegistryError::StaleParentNameSeq {
                name,
                expected,
                actual,
            } => {
                info.name = Some(name.clone());
                info.expected = Some(*expected);
                info.actual = Some(*actual);
            }
            BnsRegistryError::StaleDocumentVersion {
                name,
                doc_type,
                expected,
                actual,
            } => {
                info.name = Some(name.clone());
                info.doc_type = Some(doc_type.clone());
                info.expected = Some(*expected);
                info.actual = Some(*actual);
            }
            _ => {}
        }
        info
    }
}

#[derive(Debug, Error)]
pub enum BnsClientError {
    #[error("BNS registry error: {0:?}")]
    Registry(BnsRpcErrorInfo),

    #[error("BNS RPC transport error: {0}")]
    Transport(String),

    #[error("BNS RPC serialization error: {0}")]
    Serialization(String),

    #[error("BNS RPC response error: {0}")]
    InvalidResponse(String),
}

impl BnsClientError {
    pub fn registry(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Registry(BnsRpcErrorInfo::new(code, message))
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::registry("UNSUPPORTED_OPERATION", message)
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Registry(info) => &info.code,
            Self::Transport(_) => "RPC_TRANSPORT_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
            Self::InvalidResponse(_) => "INVALID_RESPONSE",
        }
    }

    pub fn is_registry_code(&self, code: &str) -> bool {
        matches!(self, Self::Registry(info) if info.code == code)
    }
}

impl From<BnsRegistryError> for BnsClientError {
    fn from(value: BnsRegistryError) -> Self {
        Self::Registry(BnsRpcErrorInfo::from_registry_error(&value))
    }
}

impl From<serde_json::Error> for BnsClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type BnsClientResult<T> = Result<T, BnsClientError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRpcEnvelope<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<BnsRpcErrorInfo>,
}

impl<T> BnsRpcEnvelope<T> {
    pub fn success(result: T) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(error: BnsClientError) -> Self {
        let error = match error {
            BnsClientError::Registry(info) => info,
            other => BnsRpcErrorInfo::new(other.code(), other.to_string()),
        };
        Self {
            ok: false,
            result: None,
            error: Some(error),
        }
    }

    pub fn into_result(self) -> BnsClientResult<T> {
        if self.ok {
            self.result.ok_or_else(|| {
                BnsClientError::InvalidResponse("BNS RPC envelope missing result".to_string())
            })
        } else {
            Err(BnsClientError::Registry(self.error.unwrap_or_else(|| {
                BnsRpcErrorInfo::new("UNKNOWN_BNS_ERROR", "BNS RPC envelope missing error")
            })))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsNameReq {
    pub name: String,
}

impl BnsNameReq {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsAuthorityKeyReq {
    pub name: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentReq {
    pub name: String,
    pub doc_type: String,
}

impl BnsDocumentReq {
    pub fn new(name: impl Into<String>, doc_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentVersionReq {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsSubmitRawTxReq {
    pub raw_tx: String,
}

impl BnsSubmitRawTxReq {
    pub fn from_hex(raw_tx: impl Into<String>) -> Self {
        Self {
            raw_tx: raw_tx.into(),
        }
    }

    pub fn from_bytes(raw_tx: &[u8]) -> Self {
        Self {
            raw_tx: format!("0x{}", hex::encode(raw_tx)),
        }
    }

    pub fn raw_tx_bytes(&self) -> BnsClientResult<Vec<u8>> {
        let raw = self.raw_tx.trim();
        if raw.is_empty() {
            return Err(BnsClientError::Serialization(
                "raw_tx must not be empty".to_string(),
            ));
        }
        let hex = raw.strip_prefix("0x").unwrap_or(raw);
        if hex.is_empty() || hex.len() % 2 != 0 {
            return Err(BnsClientError::Serialization(format!(
                "raw_tx must be even-length hex, got `{}`",
                self.raw_tx
            )));
        }
        hex::decode(hex).map_err(|e| {
            BnsClientError::Serialization(format!("invalid raw_tx hex `{}`: {}", self.raw_tx, e))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsSubmitRawTxResp {
    pub tx_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegisterNameReq {
    pub name: String,
    pub asset_owner: String,
    pub options: RegisterOptions,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRegisterNameResp {
    pub name_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsDocumentVersion {
    pub doc_type: String,
    pub version: u64,
    pub content_hash: String,
    pub document_state_hash: String,
}

impl From<&DocumentState> for BnsDocumentVersion {
    fn from(value: &DocumentState) -> Self {
        Self {
            doc_type: value.doc_type.clone(),
            version: value.version,
            content_hash: value.document.content_hash.clone(),
            document_state_hash: value.document_state_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsBootstrapNameReq {
    pub request_id: String,
    pub name: String,
    pub asset_owner: String,
    pub options: RegisterOptions,
    pub initial_documents: Vec<DocumentUpdate>,
    pub authority_key_updates: Vec<AuthorityKeyUpdate>,
    pub semantic_owner_after_authority: Option<bns_indexer::Principal>,
    pub controller_policy: Vec<ControllerRule>,
    pub controller_policy_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsBootstrapNameResp {
    pub name_seq: u64,
    pub initial_documents: Vec<BnsDocumentVersion>,
    pub authority_set: AuthoritySetState,
    pub controller_policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsPublishDocumentReq {
    pub name: String,
    pub update: DocumentUpdate,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsPublishDocumentResp {
    pub document_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRevokeDocumentReq {
    pub name: String,
    pub doc_type: String,
    pub from_version: u64,
    pub to_version: u64,
    pub reason_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsRevokeDocumentResp {
    pub name_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsSetControllerPolicyReq {
    pub name: String,
    pub rules: Vec<ControllerRule>,
    pub policy_hash: String,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsSetControllerPolicyResp {
    pub name_seq: u64,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsUpdateAuthorityKeysReq {
    pub name: String,
    pub updates: Vec<AuthorityKeyUpdate>,
    pub authority: CallAuthority,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsUpdateAuthorityKeysResp {
    pub authority_set: AuthoritySetState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnsListEventsReq {
    pub from_seq: u64,
    pub limit: usize,
}

#[async_trait]
pub trait BnsIndexerApi: Send + Sync {
    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>>;

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution>;

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState>;

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>>;

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult>;

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>>;

    async fn submit_raw_tx(&self, _req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        Err(BnsClientError::unsupported(
            "BNS raw TX submission is not configured",
        ))
    }

    async fn register_name(&self, req: BnsRegisterNameReq) -> BnsClientResult<BnsRegisterNameResp>;

    async fn bootstrap_name(
        &self,
        _req: BnsBootstrapNameReq,
    ) -> BnsClientResult<BnsBootstrapNameResp> {
        Err(BnsClientError::unsupported(
            "bns-indexer bootstrap_name handler is not configured",
        ))
    }

    async fn publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsPublishDocumentResp>;

    async fn revoke_document(
        &self,
        req: BnsRevokeDocumentReq,
    ) -> BnsClientResult<BnsRevokeDocumentResp>;

    async fn set_controller_policy(
        &self,
        req: BnsSetControllerPolicyReq,
    ) -> BnsClientResult<BnsSetControllerPolicyResp>;

    async fn update_authority_keys(
        &self,
        req: BnsUpdateAuthorityKeysReq,
    ) -> BnsClientResult<BnsUpdateAuthorityKeysResp>;

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>>;

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>>;
}

#[derive(Clone)]
pub enum BnsIndexerClient {
    InProcess(Arc<dyn BnsIndexerApi>),
    KRPC(Arc<kRPC>),
}

impl BnsIndexerClient {
    pub fn new_in_process(handler: Arc<dyn BnsIndexerApi>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(client: Arc<kRPC>) -> Self {
        Self::KRPC(client)
    }

    pub fn new_krpc_url(indexer_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_bns_indexer_url(indexer_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    pub fn new_bns_server_url(server_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_bns_server_url(server_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    async fn call<Req, Resp>(&self, method: &str, req: &Req) -> BnsClientResult<Resp>
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        match self {
            Self::InProcess(_) => Err(BnsClientError::unsupported(
                "generic call is only available for KRPC clients",
            )),
            Self::KRPC(client) => {
                let req_json = serde_json::to_value(req)
                    .map_err(|e| BnsClientError::Serialization(e.to_string()))?;
                let result = client
                    .call(method, req_json)
                    .await
                    .map_err(|e| BnsClientError::Transport(e.to_string()))?;
                let envelope: BnsRpcEnvelope<Resp> = serde_json::from_value(result)
                    .map_err(|e| BnsClientError::InvalidResponse(e.to_string()))?;
                envelope.into_result()
            }
        }
    }
}

#[async_trait]
impl BnsIndexerApi for BnsIndexerClient {
    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        match self {
            Self::InProcess(handler) => handler.query_name_state(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_QUERY_NAME_STATE, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        match self {
            Self::InProcess(handler) => handler.resolve_owner(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_RESOLVE_OWNER, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        match self {
            Self::InProcess(handler) => handler.get_authority_set(name).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_AUTHORITY_SET, &BnsNameReq::new(name))
                    .await
            }
        }
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        match self {
            Self::InProcess(handler) => handler.get_authority_key(name, kid).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_AUTHORITY_KEY,
                    &BnsAuthorityKeyReq {
                        name: name.to_string(),
                        kid: kid.to_string(),
                    },
                )
                .await
            }
        }
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        match self {
            Self::InProcess(handler) => handler.resolve_document(name, doc_type).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_RESOLVE_DOCUMENT,
                    &BnsDocumentReq::new(name, doc_type),
                )
                .await
            }
        }
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        match self {
            Self::InProcess(handler) => handler.get_document_version(name, doc_type, version).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_DOCUMENT_VERSION,
                    &BnsDocumentVersionReq {
                        name: name.to_string(),
                        doc_type: doc_type.to_string(),
                        version,
                    },
                )
                .await
            }
        }
    }

    async fn submit_raw_tx(&self, req: BnsSubmitRawTxReq) -> BnsClientResult<BnsSubmitRawTxResp> {
        match self {
            Self::InProcess(handler) => handler.submit_raw_tx(req).await,
            Self::KRPC(_) => self.call(METHOD_SUBMIT_RAW_TX, &req).await,
        }
    }

    async fn register_name(&self, req: BnsRegisterNameReq) -> BnsClientResult<BnsRegisterNameResp> {
        match self {
            Self::InProcess(handler) => handler.register_name(req).await,
            Self::KRPC(_) => self.call(METHOD_REGISTER_NAME, &req).await,
        }
    }

    async fn bootstrap_name(
        &self,
        req: BnsBootstrapNameReq,
    ) -> BnsClientResult<BnsBootstrapNameResp> {
        match self {
            Self::InProcess(handler) => handler.bootstrap_name(req).await,
            Self::KRPC(_) => self.call(METHOD_BOOTSTRAP_NAME, &req).await,
        }
    }

    async fn publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsPublishDocumentResp> {
        match self {
            Self::InProcess(handler) => handler.publish_document(req).await,
            Self::KRPC(_) => self.call(METHOD_PUBLISH_DOCUMENT, &req).await,
        }
    }

    async fn revoke_document(
        &self,
        req: BnsRevokeDocumentReq,
    ) -> BnsClientResult<BnsRevokeDocumentResp> {
        match self {
            Self::InProcess(handler) => handler.revoke_document(req).await,
            Self::KRPC(_) => self.call(METHOD_REVOKE_DOCUMENT, &req).await,
        }
    }

    async fn set_controller_policy(
        &self,
        req: BnsSetControllerPolicyReq,
    ) -> BnsClientResult<BnsSetControllerPolicyResp> {
        match self {
            Self::InProcess(handler) => handler.set_controller_policy(req).await,
            Self::KRPC(_) => self.call(METHOD_SET_CONTROLLER_POLICY, &req).await,
        }
    }

    async fn update_authority_keys(
        &self,
        req: BnsUpdateAuthorityKeysReq,
    ) -> BnsClientResult<BnsUpdateAuthorityKeysResp> {
        match self {
            Self::InProcess(handler) => handler.update_authority_keys(req).await,
            Self::KRPC(_) => self.call(METHOD_UPDATE_AUTHORITY_KEYS, &req).await,
        }
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        match self {
            Self::InProcess(handler) => handler.list_events(from_seq, limit).await,
            Self::KRPC(_) => {
                self.call(METHOD_LIST_EVENTS, &BnsListEventsReq { from_seq, limit })
                    .await
            }
        }
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        match self {
            Self::InProcess(handler) => handler.latest_checkpoint().await,
            Self::KRPC(_) => self.call(METHOD_LATEST_CHECKPOINT, &json!({})).await,
        }
    }
}

pub struct CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore,
{
    registry: Arc<CentralizedBnsRegistry<S>>,
}

impl<S> CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore,
{
    pub fn new(registry: Arc<CentralizedBnsRegistry<S>>) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &CentralizedBnsRegistry<S> {
        &self.registry
    }
}

#[async_trait]
impl<S> BnsIndexerApi for CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore + 'static,
{
    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        self.registry.query_name_state(name).map_err(Into::into)
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        self.registry.resolve_owner(name).map_err(Into::into)
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        self.registry.get_authority_set(name).map_err(Into::into)
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        self.registry
            .get_authority_key(name, kid)
            .map_err(Into::into)
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        self.registry
            .resolve_document(name, doc_type)
            .map_err(Into::into)
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        self.registry
            .get_document_version(name, doc_type, version)
            .map_err(Into::into)
    }

    async fn register_name(&self, req: BnsRegisterNameReq) -> BnsClientResult<BnsRegisterNameResp> {
        let name_seq = self
            .registry
            .register_name(
                &req.name,
                &req.asset_owner,
                req.options,
                req.initial_documents,
                req.authority,
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(BnsRegisterNameResp { name_seq })
    }

    async fn bootstrap_name(
        &self,
        req: BnsBootstrapNameReq,
    ) -> BnsClientResult<BnsBootstrapNameResp> {
        let result = self
            .registry
            .bootstrap_name(
                &req.name,
                &req.asset_owner,
                req.options,
                req.initial_documents,
                req.authority_key_updates,
                req.semantic_owner_after_authority,
                req.controller_policy,
                &req.controller_policy_hash,
                req.authority,
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(BnsBootstrapNameResp {
            name_seq: result.name_seq,
            initial_documents: result
                .initial_documents
                .into_iter()
                .map(|document| BnsDocumentVersion {
                    doc_type: document.doc_type,
                    version: document.version,
                    content_hash: document.content_hash,
                    document_state_hash: document.document_state_hash,
                })
                .collect(),
            authority_set: result.authority_set,
            controller_policy_hash: result.controller_policy_hash,
        })
    }

    async fn publish_document(
        &self,
        req: BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsPublishDocumentResp> {
        let document_version = self
            .registry
            .publish_document(&req.name, req.update, req.authority, req.guard)
            .map_err(BnsClientError::from)?;
        Ok(BnsPublishDocumentResp { document_version })
    }

    async fn revoke_document(
        &self,
        req: BnsRevokeDocumentReq,
    ) -> BnsClientResult<BnsRevokeDocumentResp> {
        let name_seq = self
            .registry
            .revoke_document(
                &req.name,
                &req.doc_type,
                req.from_version,
                req.to_version,
                &req.reason_hash,
                req.authority,
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(BnsRevokeDocumentResp { name_seq })
    }

    async fn set_controller_policy(
        &self,
        req: BnsSetControllerPolicyReq,
    ) -> BnsClientResult<BnsSetControllerPolicyResp> {
        let name_seq = self
            .registry
            .set_controller_policy(
                &req.name,
                req.rules,
                &req.policy_hash,
                req.authority,
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(BnsSetControllerPolicyResp {
            name_seq,
            policy_hash: req.policy_hash,
        })
    }

    async fn update_authority_keys(
        &self,
        req: BnsUpdateAuthorityKeysReq,
    ) -> BnsClientResult<BnsUpdateAuthorityKeysResp> {
        let authority_set = self
            .registry
            .update_authority_keys(&req.name, req.updates, req.authority, req.guard)
            .map_err(BnsClientError::from)?;
        Ok(BnsUpdateAuthorityKeysResp { authority_set })
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        self.registry
            .list_events(from_seq, limit)
            .map_err(Into::into)
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        self.registry.latest_checkpoint().map_err(Into::into)
    }
}

pub struct BnsIndexerRpcHandler<T: BnsIndexerApi>(pub T);

impl<T: BnsIndexerApi> BnsIndexerRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for BnsIndexerRpcHandler<T>
where
    T: BnsIndexerApi,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        match req.method.as_str() {
            METHOD_QUERY_NAME_STATE | "query_name_state" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.query_name_state(&parsed.name).await, &req)
            }
            METHOD_RESOLVE_OWNER | "resolve_owner" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.resolve_owner(&parsed.name).await, &req)
            }
            METHOD_GET_AUTHORITY_SET | "get_authority_set" => {
                let parsed: BnsNameReq = parse_req(req.params.clone(), "BnsNameReq")?;
                rpc_envelope_response(self.0.get_authority_set(&parsed.name).await, &req)
            }
            METHOD_GET_AUTHORITY_KEY | "get_authority_key" => {
                let parsed: BnsAuthorityKeyReq =
                    parse_req(req.params.clone(), "BnsAuthorityKeyReq")?;
                rpc_envelope_response(
                    self.0.get_authority_key(&parsed.name, &parsed.kid).await,
                    &req,
                )
            }
            METHOD_RESOLVE_DOCUMENT | "resolve_document" => {
                let parsed: BnsDocumentReq = parse_req(req.params.clone(), "BnsDocumentReq")?;
                rpc_envelope_response(
                    self.0
                        .resolve_document(&parsed.name, &parsed.doc_type)
                        .await,
                    &req,
                )
            }
            METHOD_GET_DOCUMENT_VERSION | "get_document_version" => {
                let parsed: BnsDocumentVersionReq =
                    parse_req(req.params.clone(), "BnsDocumentVersionReq")?;
                rpc_envelope_response(
                    self.0
                        .get_document_version(&parsed.name, &parsed.doc_type, parsed.version)
                        .await,
                    &req,
                )
            }
            METHOD_SUBMIT_RAW_TX | "submit_raw_tx" => {
                let parsed: BnsSubmitRawTxReq = parse_req(req.params.clone(), "BnsSubmitRawTxReq")?;
                rpc_envelope_response(self.0.submit_raw_tx(parsed).await, &req)
            }
            METHOD_REGISTER_NAME | "register_name" => {
                let parsed: BnsRegisterNameReq =
                    parse_req(req.params.clone(), "BnsRegisterNameReq")?;
                rpc_envelope_response(self.0.register_name(parsed).await, &req)
            }
            METHOD_BOOTSTRAP_NAME | "bootstrap_name" => {
                let parsed: BnsBootstrapNameReq =
                    parse_req(req.params.clone(), "BnsBootstrapNameReq")?;
                rpc_envelope_response(self.0.bootstrap_name(parsed).await, &req)
            }
            METHOD_PUBLISH_DOCUMENT | "publish_document" => {
                let parsed: BnsPublishDocumentReq =
                    parse_req(req.params.clone(), "BnsPublishDocumentReq")?;
                rpc_envelope_response(self.0.publish_document(parsed).await, &req)
            }
            METHOD_REVOKE_DOCUMENT | "revoke_document" => {
                let parsed: BnsRevokeDocumentReq =
                    parse_req(req.params.clone(), "BnsRevokeDocumentReq")?;
                rpc_envelope_response(self.0.revoke_document(parsed).await, &req)
            }
            METHOD_SET_CONTROLLER_POLICY | "set_controller_policy" => {
                let parsed: BnsSetControllerPolicyReq =
                    parse_req(req.params.clone(), "BnsSetControllerPolicyReq")?;
                rpc_envelope_response(self.0.set_controller_policy(parsed).await, &req)
            }
            METHOD_UPDATE_AUTHORITY_KEYS | "update_authority_keys" => {
                let parsed: BnsUpdateAuthorityKeysReq =
                    parse_req(req.params.clone(), "BnsUpdateAuthorityKeysReq")?;
                rpc_envelope_response(self.0.update_authority_keys(parsed).await, &req)
            }
            METHOD_LIST_EVENTS | "list_events" => {
                let parsed: BnsListEventsReq = parse_req(req.params.clone(), "BnsListEventsReq")?;
                rpc_envelope_response(
                    self.0.list_events(parsed.from_seq, parsed.limit).await,
                    &req,
                )
            }
            METHOD_LATEST_CHECKPOINT | "latest_checkpoint" => {
                rpc_envelope_response(self.0.latest_checkpoint().await, &req)
            }
            _ => Err(RPCErrors::UnknownMethod(req.method.clone())),
        }
    }
}

pub fn normalize_bns_indexer_url(indexer_url: &str) -> String {
    let trimmed = indexer_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix(BNS_INDEXER_RPC_PATH) {
        return format!("{}{}", base, BNS_INDEXER_RPC_PATH);
    }
    format!("{}{}", trimmed, BNS_INDEXER_RPC_PATH)
}

pub fn normalize_bns_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix(BNS_SERVER_RPC_PATH) {
        return format!("{}{}", base, BNS_SERVER_RPC_PATH);
    }
    format!("{}{}", trimmed, BNS_SERVER_RPC_PATH)
}

fn parse_req<T: DeserializeOwned>(value: Value, type_name: &str) -> Result<T, RPCErrors> {
    serde_json::from_value(value)
        .map_err(|e| RPCErrors::ParseRequestError(format!("Failed to parse {}: {}", type_name, e)))
}

fn rpc_envelope_response<T: Serialize>(
    result: BnsClientResult<T>,
    req: &RPCRequest,
) -> Result<RPCResponse, RPCErrors> {
    let envelope = match result {
        Ok(value) => BnsRpcEnvelope::success(value),
        Err(error) => BnsRpcEnvelope::failure(error),
    };
    let value = serde_json::to_value(envelope).map_err(|e| {
        RPCErrors::ParserResponseError(format!("Failed to serialize BNS RPC envelope: {}", e))
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

pub fn registry_result<T>(result: BnsRegistryResult<T>) -> BnsClientResult<T> {
    result.map_err(BnsClientError::from)
}
