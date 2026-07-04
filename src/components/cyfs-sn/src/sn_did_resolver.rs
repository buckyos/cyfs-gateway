use crate::sn_resolver::SnResolverResult;
use async_trait::async_trait;
use name_lib::{EncodedDocument, DID};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

pub const SN_DID_RESOLVER_ROUTE_PREFIX: &str = "/1.0/identifiers/";

pub type SnDidResolverRef = Arc<dyn SnDidResolver>;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidResolverProfile {
    PublicSupplement,
    InternalZoneResolver,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidDocumentStatus {
    Active,
    Missing,
    Revoked,
    Tombstoned,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidDocumentSource {
    BnsDocument,
    DeviceMiniDocument,
    DeviceOnlineInfo,
    LegacyCompatibilityStore,
    SynthesizedOwnerDocument,
    InternalCache,
}

#[derive(Debug, Clone)]
pub struct SnDidResolveRequest {
    pub did: DID,
    pub doc_type: Option<String>,
    pub from_ip: Option<IpAddr>,
    pub profile: SnDidResolverProfile,
    pub accept: Option<String>,
    pub iat: Option<String>,
}

impl SnDidResolveRequest {
    pub fn new(
        did: DID,
        doc_type: Option<String>,
        from_ip: Option<IpAddr>,
        profile: SnDidResolverProfile,
    ) -> Self {
        Self {
            did,
            doc_type: normalize_sn_did_doc_type(doc_type.as_deref()),
            from_ip,
            profile,
            accept: None,
            iat: None,
        }
    }

    pub fn doc_type(&self) -> Option<&str> {
        self.doc_type.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDidResolveResponse {
    pub did: String,
    pub doc_type: String,
    pub document: EncodedDocument,
    pub source: SnDidDocumentSource,
    pub profile: SnDidResolverProfile,
    pub document_status: Option<SnDidDocumentStatus>,
    pub metadata: Value,
}

impl SnDidResolveResponse {
    pub fn content_type(&self) -> &'static str {
        match self.document {
            EncodedDocument::JsonLd(_) => "application/json",
            EncodedDocument::Jwt(_) => "application/jwt",
        }
    }

    pub fn body(&self) -> String {
        self.document.to_string()
    }
}

#[async_trait]
pub trait SnDidResolver: Send + Sync + 'static {
    async fn resolve(&self, request: SnDidResolveRequest)
        -> SnResolverResult<SnDidResolveResponse>;
}

pub fn normalize_sn_did_doc_type(doc_type: Option<&str>) -> Option<String> {
    doc_type.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}
