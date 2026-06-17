use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{BnsIndexerError, BnsIndexerResult};

pub const DID_BNS_PREFIX: &str = "did:bns:";
pub const STORAGE_TYPE_INLINE: &str = "inline";
pub const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

pub const STANDARD_DOC_TYPES: &[&str] = &[
    "owner", "boot", "zone", "doc", "device", "service", "agent", "app", "content", "payment",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthSource {
    BnsDb,
    Contract,
}

impl Default for TruthSource {
    fn default() -> Self {
        TruthSource::BnsDb
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned,
}

impl NameStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Released => "released",
            Self::Tombstoned => "tombstoned",
        }
    }
}

impl fmt::Display for NameStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NameStatus {
    type Err = BnsIndexerError;

    fn from_str(value: &str) -> BnsIndexerResult<Self> {
        match value {
            "available" => Ok(Self::Available),
            "active" => Ok(Self::Active),
            "expired" => Ok(Self::Expired),
            "released" => Ok(Self::Released),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(BnsIndexerError::invalid_name(value, "unknown name status")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned,
}

impl DocumentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Migrated => "migrated",
            Self::Tombstoned => "tombstoned",
        }
    }
}

impl fmt::Display for DocumentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DocumentStatus {
    type Err = BnsIndexerError;

    fn from_str(value: &str) -> BnsIndexerResult<Self> {
        match value {
            "missing" => Ok(Self::Missing),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            "migrated" => Ok(Self::Migrated),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(BnsIndexerError::invalid_doc_type(
                value,
                "unknown document status",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    Alias,
    MigratedTo,
    Canonical,
}

impl AliasKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alias => "alias",
            Self::MigratedTo => "migrated_to",
            Self::Canonical => "canonical",
        }
    }
}

impl fmt::Display for AliasKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AliasKind {
    type Err = BnsIndexerError;

    fn from_str(value: &str) -> BnsIndexerResult<Self> {
        match value {
            "alias" => Ok(Self::Alias),
            "migrated_to" => Ok(Self::MigratedTo),
            "canonical" => Ok(Self::Canonical),
            _ => Err(BnsIndexerError::invalid_name(value, "unknown alias kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    ChainAddress,
    Did,
    PublicKey,
    Contract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub value: String,
}

impl Principal {
    pub fn new(kind: PrincipalKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    pub fn chain_address(value: impl Into<String>) -> Self {
        Self::new(PrincipalKind::ChainAddress, value)
    }

    pub fn did(value: impl Into<String>) -> Self {
        Self::new(PrincipalKind::Did, value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRef {
    pub storage_type: String,
    pub uri: String,
    pub inline_document: Vec<u8>,
    pub content_hash: String,
    pub schema: String,
    pub codec: String,
    pub extra_hash: String,
}

impl DocumentRef {
    pub fn new(
        storage_type: impl Into<String>,
        uri: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            storage_type: storage_type.into(),
            uri: uri.into(),
            inline_document: Vec::new(),
            content_hash: normalize_hash_or_zero(content_hash.into()),
            schema: ZERO_HASH.to_string(),
            codec: ZERO_HASH.to_string(),
            extra_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn inline(inline_document: impl Into<Vec<u8>>) -> Self {
        let inline_document = inline_document.into();
        let content_hash = sha256_hex(&inline_document);
        Self {
            storage_type: STORAGE_TYPE_INLINE.to_string(),
            uri: String::new(),
            inline_document,
            content_hash,
            schema: ZERO_HASH.to_string(),
            codec: ZERO_HASH.to_string(),
            extra_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn validate_shape(&self) -> BnsIndexerResult<()> {
        validate_hash(&self.content_hash)?;
        validate_hash(&self.schema)?;
        validate_hash(&self.codec)?;
        validate_hash(&self.extra_hash)?;

        if self.storage_type == STORAGE_TYPE_INLINE {
            if self.inline_document.is_empty() {
                return Err(BnsIndexerError::invalid_doc_type(
                    self.storage_type.clone(),
                    "inline document must not be empty",
                ));
            }
        } else if !self.inline_document.is_empty() {
            return Err(BnsIndexerError::invalid_doc_type(
                self.storage_type.clone(),
                "inline_document must be empty for non-inline storage",
            ));
        }

        Ok(())
    }

    pub fn matches_sha256_content_hash(&self) -> bool {
        sha256_hex(&self.inline_document) == self.content_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameState {
    pub name: String,
    pub asset_owner: String,
    pub status: NameStatus,
    pub registered_at: u64,
    pub expire_at: u64,
    pub grace_until: u64,
    pub updated_at: u64,
    pub name_seq: u64,
    pub owner_document_version: u64,
    pub namespace_policy_hash: String,
    pub payment_policy_hash: String,
    pub alias_state_hash: String,
}

impl NameState {
    pub fn validate(&self) -> BnsIndexerResult<()> {
        canonical_bns_name(&self.name)?;
        validate_hash(&self.namespace_policy_hash)?;
        validate_hash(&self.payment_policy_hash)?;
        validate_hash(&self.alias_state_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentState {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
    pub previous_version: u64,
    pub status: DocumentStatus,
    pub document: DocumentRef,
    pub controller: Principal,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub valid_from: u64,
    pub expire_at: u64,
    pub revoked_at: u64,
    pub controller_policy_hash: String,
    pub split_policy_hash: String,
    pub document_state_hash: String,
}

impl DocumentState {
    pub fn key(&self) -> DocumentKey {
        DocumentKey {
            name: self.name.clone(),
            doc_type: self.doc_type.clone(),
            version: self.version,
        }
    }

    pub fn validate(&self) -> BnsIndexerResult<()> {
        canonical_bns_name(&self.name)?;
        canonical_doc_type(&self.doc_type)?;
        self.document.validate_shape()?;
        validate_hash(&self.controller_policy_hash)?;
        validate_hash(&self.split_policy_hash)?;
        validate_hash(&self.document_state_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasState {
    pub name: String,
    pub kind: AliasKind,
    pub target_did: String,
    pub proof_hash: String,
    pub set_at: u64,
    pub name_seq: u64,
}

impl AliasState {
    pub fn validate(&self) -> BnsIndexerResult<()> {
        canonical_bns_name(&self.name)?;
        validate_did(&self.target_did)?;
        validate_hash(&self.proof_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseContext {
    pub content_name: String,
    pub doc_type: String,
    pub document_version: u64,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub split_policy_hash: String,
    pub price_policy_hash: String,
    pub rights_policy_hash: String,
    pub status: DocumentStatus,
    pub proof_root: String,
}

impl PurchaseContext {
    pub fn validate(&self) -> BnsIndexerResult<()> {
        canonical_bns_name(&self.content_name)?;
        canonical_doc_type(&self.doc_type)?;
        validate_hash(&self.split_policy_hash)?;
        validate_hash(&self.price_policy_hash)?;
        validate_hash(&self.rights_policy_hash)?;
        validate_hash(&self.proof_root)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentTargetResolution {
    pub beneficiary: Principal,
    pub payment_target: String,
    pub split_policy_hash: String,
    pub proof_root: String,
}

impl PaymentTargetResolution {
    pub fn validate(&self) -> BnsIndexerResult<()> {
        validate_hash(&self.split_policy_hash)?;
        validate_hash(&self.proof_root)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentUpdate {
    pub doc_type: String,
    pub document: DocumentRef,
    pub controller: Principal,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub expire_at: u64,
    pub controller_policy_hash: String,
    pub split_policy_hash: String,
}

impl DocumentUpdate {
    pub fn validate(&self) -> BnsIndexerResult<()> {
        canonical_doc_type(&self.doc_type)?;
        self.document.validate_shape()?;
        validate_hash(&self.controller_policy_hash)?;
        validate_hash(&self.split_policy_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResult {
    pub name_state: NameState,
    pub document_state: DocumentState,
    pub verified_owner: Principal,
    pub controller: Principal,
    pub trust_root: String,
    pub status: DocumentStatus,
    pub alias_kind: AliasKind,
    pub alias_target_did: String,
    pub proof_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentKey {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProof {
    pub signer: Principal,
    pub signature: String,
    pub nonce: u64,
    pub deadline: u64,
    pub expected_name_seq: u64,
    pub expected_document_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterOptions {
    pub duration: u64,
    pub grace_period: u64,
    pub renewable: bool,
    pub transferable: bool,
    pub allow_delegated_subnames: bool,
    pub initial_payment_target: String,
    pub initial_payment_policy_hash: String,
    pub initial_namespace_policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerRule {
    pub controller: Principal,
    pub doc_type: String,
    pub permissions: u32,
    pub namespace_scope_hash: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub constraint_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ContractEvent {
    NameRegistered {
        name: String,
        asset_owner: String,
        expire_at: u64,
        name_seq: u64,
    },
    NameRenewed {
        name: String,
        expire_at: u64,
        name_seq: u64,
    },
    NameTransferred {
        name: String,
        old_asset_owner: String,
        new_asset_owner: String,
        name_seq: u64,
    },
    NameReleased {
        name: String,
        mode: ReleaseMode,
        reason_hash: String,
        name_seq: u64,
    },
    DocumentPublished {
        name: String,
        doc_type: String,
        version: u64,
        content_hash: String,
        document_state_hash: String,
    },
    DocumentRevoked {
        name: String,
        doc_type: String,
        from_version: u64,
        to_version: u64,
        reason_hash: String,
    },
    ControllerPolicyUpdated {
        name: String,
        policy_hash: String,
        name_seq: u64,
    },
    NamespacePolicyUpdated {
        name: String,
        allow_delegated_subnames: bool,
        namespace_policy_hash: String,
        name_seq: u64,
    },
    OwnerKeyChanged {
        name: String,
        owner_document_version: u64,
        owner_document_hash: String,
    },
    DidAliasSet {
        name: String,
        target_did: String,
        kind: AliasKind,
        proof_hash: String,
        name_seq: u64,
    },
    PaymentTargetUpdated {
        name: String,
        doc_type: String,
        payment_target: String,
        payment_policy_hash: String,
        version: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEventEnvelope {
    pub source: String,
    pub block_number: u64,
    pub block_hash: Option<String>,
    pub tx_hash: String,
    pub log_index: u64,
    pub observed_at: u64,
    pub event: ContractEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerCursor {
    pub source: String,
    pub block_number: u64,
    pub block_hash: Option<String>,
    pub log_index: u64,
    pub updated_at: u64,
}

pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn canonical_bns_name(name: &str) -> BnsIndexerResult<String> {
    if name.is_empty() {
        return Err(BnsIndexerError::invalid_name(name, "name is empty"));
    }

    if name.trim() != name {
        return Err(BnsIndexerError::invalid_name(
            name,
            "name must not contain leading or trailing whitespace",
        ));
    }

    if name.starts_with(DID_BNS_PREFIX) {
        return Err(BnsIndexerError::invalid_name(
            name,
            "contract names must not include did:bns: prefix",
        ));
    }

    if name.len() > 253 {
        return Err(BnsIndexerError::invalid_name(
            name,
            "name must be at most 253 bytes",
        ));
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(BnsIndexerError::invalid_name(name, "empty label"));
        }

        if label.len() > 63 {
            return Err(BnsIndexerError::invalid_name(
                name,
                "label must be at most 63 bytes",
            ));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(BnsIndexerError::invalid_name(
                name,
                "label must not start or end with '-'",
            ));
        }

        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(BnsIndexerError::invalid_name(
                name,
                "only lower-case ASCII letters, digits, '-' and '.' are supported",
            ));
        }
    }

    Ok(name.to_string())
}

pub fn canonical_doc_type(doc_type: &str) -> BnsIndexerResult<String> {
    if doc_type.is_empty() {
        return Err(BnsIndexerError::invalid_doc_type(
            doc_type,
            "doc_type is empty",
        ));
    }

    if doc_type.len() > 32 {
        return Err(BnsIndexerError::invalid_doc_type(
            doc_type,
            "doc_type must be at most 32 bytes",
        ));
    }

    if !doc_type
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(BnsIndexerError::invalid_doc_type(
            doc_type,
            "only lower-case ASCII letters, digits, '-' and '_' are supported",
        ));
    }

    Ok(doc_type.to_string())
}

pub fn name_from_did_bns(did: &str) -> BnsIndexerResult<String> {
    let name = did
        .strip_prefix(DID_BNS_PREFIX)
        .ok_or_else(|| BnsIndexerError::invalid_name(did, "DID must start with did:bns:"))?;
    canonical_bns_name(name)
}

pub fn did_bns_from_name(name: &str) -> BnsIndexerResult<String> {
    Ok(format!("{}{}", DID_BNS_PREFIX, canonical_bns_name(name)?))
}

pub fn validate_did(did: &str) -> BnsIndexerResult<()> {
    if did.starts_with(DID_BNS_PREFIX) {
        name_from_did_bns(did)?;
        return Ok(());
    }

    if did.starts_with("did:") && did.len() > 4 {
        return Ok(());
    }

    Err(BnsIndexerError::invalid_name(did, "invalid DID"))
}

pub fn normalize_hash_or_zero(value: String) -> String {
    if value.is_empty() {
        ZERO_HASH.to_string()
    } else {
        value
    }
}

pub fn validate_hash(value: &str) -> BnsIndexerResult<()> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() != 64 {
        return Err(BnsIndexerError::invalid_hash(
            value,
            "bytes32 hash must contain 64 hex chars",
        ));
    }

    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BnsIndexerError::invalid_hash(
            value,
            "bytes32 hash must be hex encoded",
        ));
    }

    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("0x{}", hex::encode(digest))
}
