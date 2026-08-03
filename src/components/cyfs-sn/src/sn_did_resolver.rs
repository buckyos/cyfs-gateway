use crate::sn_resolver::{
    SnAuthReaderRef, SnResolverError, SnResolverErrorKind, SnResolverRef, SnResolverResult,
    ZoneResolution, ZoneResolutionSource, BNS_DOC_ZONE, DEFAULT_SN_RESOLVER_TTL_SECS,
};
use crate::{SNUserInfo, UserState};
use async_trait::async_trait;
use http::StatusCode;
use jsonwebtoken::{jwk::Jwk, DecodingKey};
use name_client::{document_content_hash, document_iat};
use name_lib::{create_jwt_by_x, EncodedDocument, OwnerDocument, DID};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SN_DID_RESOLVER_ROUTE_PREFIX: &str = "/1.0/identifiers/";
pub const DID_RESOLUTION_CONTENT_TYPE: &str = "application/did-resolution+json";

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
    AuthDbProjection,
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
        let doc_type = normalize_sn_did_doc_type(doc_type.as_deref()).map(|doc_type| {
            if profile == SnDidResolverProfile::InternalZoneResolver && doc_type == "doc" {
                "device".to_string()
            } else {
                doc_type
            }
        });
        Self {
            did,
            doc_type,
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
    fn uses_resolution_envelope(&self, accept: Option<&str>) -> bool {
        self.profile == SnDidResolverProfile::InternalZoneResolver || accepts_did_resolution(accept)
    }

    pub fn content_type(&self) -> &'static str {
        match self.document {
            EncodedDocument::JsonLd(_) => "application/json",
            EncodedDocument::Jwt(_) => "application/jwt",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self.document_status {
            Some(SnDidDocumentStatus::Missing) => StatusCode::NOT_FOUND,
            Some(SnDidDocumentStatus::Revoked | SnDidDocumentStatus::Tombstoned) => {
                StatusCode::GONE
            }
            _ => StatusCode::OK,
        }
    }

    pub fn body(&self) -> String {
        self.document.to_string()
    }

    pub fn content_type_for_accept(&self, accept: Option<&str>) -> &'static str {
        if self.uses_resolution_envelope(accept) {
            DID_RESOLUTION_CONTENT_TYPE
        } else {
            self.content_type()
        }
    }

    pub fn body_for_accept(&self, accept: Option<&str>) -> String {
        if self.uses_resolution_envelope(accept) {
            self.did_resolution_body()
        } else {
            self.body()
        }
    }

    fn did_resolution_body(&self) -> String {
        // Preserve compact JWT artifacts verbatim. Decoding a JWT payload into
        // JSON here would discard its signature and make docHash describe a
        // different body than the one consumed by name-client.
        let did_document = match &self.document {
            EncodedDocument::JsonLd(value) => value.clone(),
            EncodedDocument::Jwt(jwt) => Value::String(jwt.clone()),
        };
        let mut buckyos = self
            .metadata
            .get("buckyos")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(status) = self.document_status {
            if let Some(obj) = buckyos.as_object_mut() {
                obj.insert("documentStatus".to_string(), json!(status));
            }
        }

        serde_json::to_string(&json!({
            "didResolutionMetadata": {
                "contentType": self.content_type(),
            },
            "didDocument": did_document,
            "didDocumentMetadata": {
                "buckyos": buckyos,
            }
        }))
        .unwrap()
    }
}

#[async_trait]
pub trait SnDidResolver: Send + Sync + 'static {
    async fn resolve(&self, request: SnDidResolveRequest)
        -> SnResolverResult<SnDidResolveResponse>;
}

pub struct SnResolverBackedDidResolver {
    resolver: SnResolverRef,
    auth: SnAuthReaderRef,
    server_host: String,
}

impl SnResolverBackedDidResolver {
    pub fn new(
        resolver: SnResolverRef,
        auth: SnAuthReaderRef,
        server_host: impl Into<String>,
    ) -> Self {
        Self {
            resolver,
            auth,
            server_host: normalize_host_lossy(server_host.into().as_str()),
        }
    }

    pub fn new_ref(
        resolver: SnResolverRef,
        auth: SnAuthReaderRef,
        server_host: impl Into<String>,
    ) -> SnDidResolverRef {
        Arc::new(Self::new(resolver, auth, server_host))
    }

    async fn resolve_request(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        if request.iat.is_some() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                "historical DID resolution by iat is not supported",
            ));
        }

        match request.did.method.as_str() {
            "web" => self.resolve_web_did(request).await,
            "bns" => self.resolve_bns_did(request).await,
            "dev" => self.resolve_passthrough(request).await,
            other => Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedDidMethod,
                format!("unsupported did method {}", other),
            )),
        }
    }

    async fn resolve_passthrough(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let mut response = self
            .resolver
            .resolve_did(&request.did, request.doc_type(), request.from_ip)
            .await?;
        self.apply_profile(request, &mut response, None);
        Ok(response)
    }

    async fn resolve_bns_did(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = effective_bns_doc_type(&request.did, request.doc_type());
        if request.profile == SnDidResolverProfile::InternalZoneResolver
            && is_root_bns_did(&request.did)
        {
            if let Some(user) = self.auth.get_user_info(request.did.id.as_str()).await? {
                if let Some(status) = owner_status_for_user_state(&user.state) {
                    return Ok(self.negative_response(
                        request,
                        doc_type.as_str(),
                        status,
                        SnDidDocumentSource::AuthDbProjection,
                        format!(
                            "AuthDB user {} is {}",
                            request.did.id,
                            user.state.to_string()
                        ),
                    ));
                }
            }
        }
        if request.profile == SnDidResolverProfile::InternalZoneResolver
            && doc_type == "device"
            && !is_root_bns_did(&request.did)
        {
            if let Some((_, zone_name)) = request.did.id.split_once('.') {
                if !zone_name.contains('.') {
                    if let Some(user) = self.auth.get_user_info(zone_name).await? {
                        if let Some(status) = owner_status_for_user_state(&user.state) {
                            return Ok(self.negative_response(
                                request,
                                "device",
                                status,
                                SnDidDocumentSource::AuthDbProjection,
                                format!("AuthDB owner {} is {}", zone_name, user.state.to_string()),
                            ));
                        }
                    }
                }
            }
        }
        if is_root_bns_did(&request.did) && doc_type == "owner" {
            let user = if request.profile == SnDidResolverProfile::InternalZoneResolver {
                self.auth.get_user_info(request.did.id.as_str()).await?
            } else {
                None
            };
            if let Some((status, state)) = user.as_ref().and_then(|user| {
                owner_status_for_user_state(&user.state)
                    .map(|status| (status, user.state.to_string()))
            }) {
                return Ok(self.negative_response(
                    request,
                    "owner",
                    status,
                    SnDidDocumentSource::AuthDbProjection,
                    format!("AuthDB user {} is {}", request.did.id, state),
                ));
            }

            match self.resolve_passthrough(request).await {
                Ok(response) => return Ok(response),
                Err(error)
                    if matches!(
                        error.kind(),
                        SnResolverErrorKind::DocumentNotFound
                            | SnResolverErrorKind::DeviceNotFound
                            | SnResolverErrorKind::NameNotFound
                    ) => {}
                Err(error) => return Err(error),
            }

            let zone = match self
                .resolver
                .resolve_zone_by_bns_name(
                    request.did.id.as_str(),
                    request.did.id.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await
            {
                Ok(zone) => zone,
                Err(error)
                    if request.profile == SnDidResolverProfile::InternalZoneResolver
                        && matches!(
                            error.kind(),
                            SnResolverErrorKind::DocumentNotFound
                                | SnResolverErrorKind::NameNotFound
                        ) =>
                {
                    return Ok(self.negative_response(
                        request,
                        "owner",
                        SnDidDocumentStatus::Missing,
                        SnDidDocumentSource::BnsDocument,
                        error.to_string(),
                    ));
                }
                Err(error) => return Err(error),
            };
            let owner_did = request.did.to_string();
            let mut response = match self.synthesize_owner_response(&owner_did, &zone, "owner") {
                Ok(response) => response,
                Err(error)
                    if request.profile == SnDidResolverProfile::InternalZoneResolver
                        && error.kind() == SnResolverErrorKind::DocumentNotFound =>
                {
                    return Ok(self.negative_response(
                        request,
                        "owner",
                        SnDidDocumentStatus::Missing,
                        if zone.owner_from_auth_db {
                            SnDidDocumentSource::AuthDbProjection
                        } else {
                            SnDidDocumentSource::BnsDocument
                        },
                        "owner has no valid key material",
                    ));
                }
                Err(error) => return Err(error),
            };
            if let Some(user) = user
                .as_ref()
                .filter(|user| owner_uses_auth_db_key(&zone, user))
            {
                mark_auth_db_projection(&mut response, user);
            }
            self.apply_profile(
                request,
                &mut response,
                Some(json!({
                    "canonicalZone": format!("did:bns:{}", zone.canonical_name),
                    "effectiveOwner": owner_did,
                })),
            );
            return Ok(response);
        }

        self.resolve_passthrough(request).await
    }

    async fn resolve_web_did(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = normalize_host_lossy(request.did.id.as_str());
        if id.is_empty() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                "did:web id is empty",
            ));
        }

        if request.profile == SnDidResolverProfile::InternalZoneResolver
            && request.doc_type().unwrap_or(BNS_DOC_ZONE) == "owner"
        {
            if let Some(username) = self.managed_owner_username(id.as_str()) {
                return self
                    .resolve_managed_web_owner(request, username.as_str())
                    .await;
            }
        }

        let Some(binding) = self.find_user_domain_binding(id.as_str()).await? else {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NotManaged,
                format!("did:web:{} is not managed by this SN", id),
            ));
        };

        if binding.device_name.is_none() && request.doc_type().unwrap_or(BNS_DOC_ZONE) == "owner" {
            let owner_did = request.did.to_string();
            let mut response =
                self.synthesize_owner_response(&owner_did, &binding.zone, "owner")?;
            self.apply_profile(
                request,
                &mut response,
                Some(json!({
                    "canonicalZone": binding.canonical_zone_did(),
                    "userDomain": binding.user_domain,
                    "effectiveOwner": owner_did,
                })),
            );
            return Ok(response);
        }

        let mapped = binding.mapped_bns_did(request.doc_type())?;
        let mapped_doc_type = request.doc_type().or_else(|| {
            if binding.device_name.is_some() {
                Some("doc")
            } else {
                Some(BNS_DOC_ZONE)
            }
        });
        let mut response = self
            .resolver
            .resolve_did(&mapped, mapped_doc_type, request.from_ip)
            .await?;

        let owner_did = format!("did:web:{}", binding.user_domain);
        rewrite_web_document_identity(
            &mut response.document,
            request.did.to_string().as_str(),
            owner_did.as_str(),
            binding.canonical_zone_did().as_str(),
            binding.device_name.as_deref(),
        );

        response.did = request.did.to_string();
        let metadata = json!({
            "canonicalZone": binding.canonical_zone_did(),
            "userDomain": binding.user_domain,
            "mappedDid": mapped.to_string(),
            "effectiveOwner": owner_did,
        });
        self.apply_profile(request, &mut response, Some(metadata));
        Ok(response)
    }

    fn managed_owner_username(&self, host: &str) -> Option<String> {
        let suffix = format!(".{}", self.server_host);
        let username = host.strip_suffix(suffix.as_str())?;
        if username.is_empty() || username.contains('.') {
            return None;
        }
        Some(username.to_string())
    }

    async fn resolve_managed_web_owner(
        &self,
        request: &SnDidResolveRequest,
        username: &str,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let Some(user) = self.auth.get_user_info(username).await? else {
            return Ok(self.negative_response(
                request,
                "owner",
                SnDidDocumentStatus::Missing,
                SnDidDocumentSource::AuthDbProjection,
                format!("AuthDB user {} is not registered", username),
            ));
        };
        if let Some(status) = owner_status_for_user_state(&user.state) {
            return Ok(self.negative_response(
                request,
                "owner",
                status,
                SnDidDocumentSource::AuthDbProjection,
                format!("AuthDB user {} is {}", username, user.state.to_string()),
            ));
        }

        let zone = match self
            .resolver
            .resolve_zone_by_bns_name(
                username,
                request.did.id.as_str(),
                ZoneResolutionSource::UserDomain,
                Some(request.did.id.clone()),
            )
            .await
        {
            Ok(zone) => zone,
            Err(error)
                if matches!(
                    error.kind(),
                    SnResolverErrorKind::DocumentNotFound | SnResolverErrorKind::NameNotFound
                ) =>
            {
                return Ok(self.negative_response(
                    request,
                    "owner",
                    SnDidDocumentStatus::Missing,
                    SnDidDocumentSource::BnsDocument,
                    error.to_string(),
                ));
            }
            Err(error) => return Err(error),
        };
        let owner_did = request.did.to_string();
        let mut response = match self.synthesize_owner_response(&owner_did, &zone, "owner") {
            Ok(response) => response,
            Err(error) if error.kind() == SnResolverErrorKind::DocumentNotFound => {
                return Ok(self.negative_response(
                    request,
                    "owner",
                    SnDidDocumentStatus::Missing,
                    if zone.owner_from_auth_db {
                        SnDidDocumentSource::AuthDbProjection
                    } else {
                        SnDidDocumentSource::BnsDocument
                    },
                    "owner has no valid key material",
                ));
            }
            Err(error) => return Err(error),
        };
        if owner_uses_auth_db_key(&zone, &user) {
            mark_auth_db_projection(&mut response, &user);
        }
        self.apply_profile(
            request,
            &mut response,
            Some(json!({
                "canonicalZone": format!("did:bns:{}", zone.canonical_name),
                "managedHostSuffix": self.server_host,
                "effectiveOwner": owner_did,
            })),
        );
        Ok(response)
    }

    async fn find_user_domain_binding(
        &self,
        host: &str,
    ) -> SnResolverResult<Option<WebDomainBinding>> {
        let Some(user) = self.auth.get_user_by_domain(host).await? else {
            return Ok(None);
        };
        let Some(username) = user.username.clone() else {
            return Err(SnResolverError::not_found(format!(
                "user_domain {} has no username",
                host
            )));
        };
        let Some(user_domain) = user.user_domain.as_deref().map(normalize_host_lossy) else {
            return Ok(None);
        };
        if user_domain.is_empty() {
            return Ok(None);
        }

        let device_name = if host == user_domain {
            None
        } else {
            let suffix = format!(".{}", user_domain);
            host.strip_suffix(suffix.as_str())
                .filter(|name| !name.is_empty() && !name.contains('.'))
                .map(ToOwned::to_owned)
        };

        if host != user_domain && device_name.is_none() {
            return Ok(None);
        }

        let zone = self
            .resolver
            .resolve_zone_by_bns_name(
                username.as_str(),
                user_domain.as_str(),
                ZoneResolutionSource::UserDomain,
                Some(user_domain.clone()),
            )
            .await?;

        Ok(Some(WebDomainBinding {
            username,
            user_domain,
            device_name,
            zone,
        }))
    }

    fn synthesize_owner_response(
        &self,
        owner_did: &str,
        zone: &ZoneResolution,
        doc_type: &str,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let canonical_zone = format!("did:bns:{}", zone.canonical_name);
        let (document, key_source) = synthesize_owner_document(owner_did, &canonical_zone, zone)?;
        Ok(SnDidResolveResponse {
            did: owner_did.to_string(),
            doc_type: doc_type.to_string(),
            document: EncodedDocument::JsonLd(document),
            source: SnDidDocumentSource::SynthesizedOwnerDocument,
            profile: SnDidResolverProfile::PublicSupplement,
            document_status: None,
            metadata: json!({
                "buckyos": {
                    "docType": doc_type,
                    "source": SnDidDocumentSource::SynthesizedOwnerDocument,
                    "ownerKeySource": key_source,
                    "canonicalZone": canonical_zone,
                    "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
                }
            }),
        })
    }

    fn negative_response(
        &self,
        request: &SnDidResolveRequest,
        doc_type: &str,
        status: SnDidDocumentStatus,
        source: SnDidDocumentSource,
        reason: impl Into<String>,
    ) -> SnDidResolveResponse {
        let mut response = SnDidResolveResponse {
            did: request.did.to_string(),
            doc_type: doc_type.to_string(),
            document: EncodedDocument::JsonLd(Value::Null),
            source,
            profile: request.profile,
            document_status: Some(status),
            metadata: json!({
                "buckyos": {
                    "docType": doc_type,
                    "source": source,
                    "resolverRole": "zone_resolver",
                    "profile": request.profile,
                    "reason": reason.into(),
                }
            }),
        };
        self.apply_profile(request, &mut response, None);
        response
    }

    fn apply_profile(
        &self,
        request: &SnDidResolveRequest,
        response: &mut SnDidResolveResponse,
        extra_buckyos: Option<Value>,
    ) {
        response.profile = request.profile;
        response.document_status = match request.profile {
            SnDidResolverProfile::PublicSupplement => None,
            SnDidResolverProfile::InternalZoneResolver => response
                .document_status
                .or(Some(SnDidDocumentStatus::Active)),
        };

        let mut buckyos = response
            .metadata
            .get("buckyos")
            .and_then(|value| value.as_object())
            .cloned()
            .unwrap_or_default();

        buckyos.insert(
            "docType".to_string(),
            Value::String(response.doc_type.clone()),
        );
        buckyos.insert("source".to_string(), json!(response.source));
        buckyos.insert(
            "resolverRole".to_string(),
            Value::String(
                match request.profile {
                    SnDidResolverProfile::PublicSupplement => "supplement",
                    SnDidResolverProfile::InternalZoneResolver => "zone_resolver",
                }
                .to_string(),
            ),
        );
        buckyos.insert("profile".to_string(), json!(request.profile));

        if let Some(Value::Object(extra)) = extra_buckyos {
            for (key, value) in extra {
                buckyos.insert(key, value);
            }
        }

        if request.profile == SnDidResolverProfile::InternalZoneResolver {
            let now = unix_timestamp();
            buckyos.insert("checkedAt".to_string(), Value::from(now));
            buckyos.insert(
                "validUntil".to_string(),
                Value::from(now.saturating_add(DEFAULT_SN_RESOLVER_TTL_SECS as u64)),
            );
        }

        if response.document_status == Some(SnDidDocumentStatus::Active) {
            buckyos.insert(
                "documentVersion".to_string(),
                document_iat(&response.document)
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            );
            buckyos.insert(
                "docHash".to_string(),
                Value::String(document_content_hash(&response.document)),
            );
            if !buckyos.contains_key("effectiveOwner") {
                if let Some(owner) = expected_owner_for_request(request, &response.document) {
                    buckyos.insert("effectiveOwner".to_string(), Value::String(owner));
                }
            }
        } else {
            for key in ["documentVersion", "docHash", "effectiveOwner"] {
                buckyos.remove(key);
            }
        }

        if let Some(status) = response.document_status {
            buckyos.insert("documentStatus".to_string(), json!(status));
        } else {
            buckyos.remove("documentStatus");
        }

        response.metadata = json!({ "buckyos": buckyos });
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn owner_status_for_user_state(state: &UserState) -> Option<SnDidDocumentStatus> {
    match state {
        UserState::Active => None,
        UserState::Suspended | UserState::Banned => Some(SnDidDocumentStatus::Revoked),
        UserState::Deleted => Some(SnDidDocumentStatus::Tombstoned),
    }
}

fn owner_uses_auth_db_key(zone: &ZoneResolution, user: &SNUserInfo) -> bool {
    zone.owner_from_auth_db && key_like_string_to_jwk(user.public_key.as_str()).is_some()
}

fn mark_auth_db_projection(response: &mut SnDidResolveResponse, user: &SNUserInfo) {
    response.source = SnDidDocumentSource::AuthDbProjection;
    if let EncodedDocument::JsonLd(Value::Object(document)) = &mut response.document {
        let revision = user.updated_at.max(1);
        document.insert("iat".to_string(), Value::from(revision));
        // The Zone snapshot's checkedAt/validUntil controls freshness. Keep the
        // synthesized document stable between reads of the same AuthDB
        // revision instead of regenerating exp/hash on every request.
        document.insert("exp".to_string(), Value::from(253_402_300_799_u64));
        merge_buckyos_object(
            document,
            json!({
                "source": "sn-auth-db-control-plane",
                "ownerKeySource": "sn-auth-db",
                "authDbRevision": revision,
            }),
        );
    }
    if let Some(buckyos) = response
        .metadata
        .get_mut("buckyos")
        .and_then(Value::as_object_mut)
    {
        buckyos.insert(
            "source".to_string(),
            json!(SnDidDocumentSource::AuthDbProjection),
        );
        buckyos.insert(
            "ownerKeySource".to_string(),
            Value::String("sn-auth-db".to_string()),
        );
        buckyos.insert(
            "authoritySeq".to_string(),
            Value::from(user.updated_at.max(1)),
        );
    }
}

fn expected_owner_for_request(
    request: &SnDidResolveRequest,
    document: &EncodedDocument,
) -> Option<String> {
    if request.doc_type() == Some("owner") {
        return Some(request.did.to_string());
    }
    if let Some(owner) = document_declared_owner(document) {
        return Some(owner);
    }
    if request.did.method == "bns" {
        let (_, owner) = request.did.id.split_once('.')?;
        if owner.contains('.') {
            return None;
        }
        return Some(format!("did:bns:{}", owner));
    }
    None
}

#[async_trait]
impl SnDidResolver for SnResolverBackedDidResolver {
    async fn resolve(
        &self,
        request: SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        match self.resolve_request(&request).await {
            Ok(response) => Ok(response),
            Err(error)
                if request.profile == SnDidResolverProfile::InternalZoneResolver
                    && request.did.method == "bns"
                    && matches!(
                        error.kind(),
                        SnResolverErrorKind::NameNotFound
                            | SnResolverErrorKind::DocumentNotFound
                            | SnResolverErrorKind::DeviceNotFound
                    ) =>
            {
                let doc_type = effective_bns_doc_type(&request.did, request.doc_type());
                Ok(self.negative_response(
                    &request,
                    doc_type.as_str(),
                    SnDidDocumentStatus::Missing,
                    SnDidDocumentSource::BnsDocument,
                    error.to_string(),
                ))
            }
            Err(error) => Err(error),
        }
    }
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

struct WebDomainBinding {
    username: String,
    user_domain: String,
    device_name: Option<String>,
    zone: ZoneResolution,
}

impl WebDomainBinding {
    fn canonical_zone_did(&self) -> String {
        format!("did:bns:{}", self.zone.canonical_name)
    }

    fn mapped_bns_did(&self, doc_type: Option<&str>) -> SnResolverResult<DID> {
        let did = if let Some(device_name) = self.device_name.as_deref() {
            format!("did:bns:{}.{}", device_name, self.username)
        } else {
            format!("did:bns:{}", self.username)
        };
        DID::from_str(did.as_str()).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                format!(
                    "invalid mapped BNS DID for doc_type {}: {}",
                    doc_type.unwrap_or(""),
                    e
                ),
            )
        })
    }
}

fn effective_bns_doc_type(did: &DID, doc_type: Option<&str>) -> String {
    doc_type.map(ToOwned::to_owned).unwrap_or_else(|| {
        if is_root_bns_did(did) {
            BNS_DOC_ZONE
        } else {
            "doc"
        }
        .to_string()
    })
}

fn is_root_bns_did(did: &DID) -> bool {
    did.method == "bns" && !did.id.contains('.')
}

fn normalize_host_lossy(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn accepts_did_resolution(accept: Option<&str>) -> bool {
    accept
        .unwrap_or_default()
        .split(',')
        .map(|item| item.split(';').next().unwrap_or_default().trim())
        .any(|item| {
            item.eq_ignore_ascii_case("application/did-resolution")
                || item.eq_ignore_ascii_case(DID_RESOLUTION_CONTENT_TYPE)
        })
}

fn synthesize_owner_document(
    owner_did: &str,
    canonical_zone: &str,
    zone: &ZoneResolution,
) -> SnResolverResult<(Value, &'static str)> {
    if let Some(owner_config) = zone.owner.owner_config.as_ref() {
        if owner_config.get("verificationMethod").is_some() {
            let mut document = normalize_owner_config_document(
                owner_config.clone(),
                owner_did,
                canonical_zone,
                "bns-owner-config",
            );
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "bns-owner-config",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            stabilize_bns_owner_document(&mut document, owner_config);
            return Ok((document, "bns-owner-config"));
        }

        if let Some(jwk) = owner_key_from_config(owner_config) {
            let mut document =
                build_owner_document_from_jwk(owner_did, canonical_zone, jwk, "bns-owner-config")?;
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "bns-owner-config",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            stabilize_bns_owner_document(&mut document, owner_config);
            return Ok((document, "bns-owner-config"));
        }
    }

    if let Some(effective_owner) = zone.owner.effective_owner.as_deref() {
        if let Some(jwk) = key_like_string_to_jwk(effective_owner) {
            let mut document =
                build_owner_document_from_jwk(owner_did, canonical_zone, jwk, "effective-owner")?;
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "effective-owner",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            return Ok((document, "effective-owner"));
        }
    }

    Err(SnResolverError::new(
        SnResolverErrorKind::DocumentNotFound,
        format!("owner key not found for {}", canonical_zone),
    ))
}

fn stabilize_bns_owner_document(document: &mut Value, owner_config: &Value) {
    let Some(document) = document.as_object_mut() else {
        return;
    };
    document.remove("_snBnsUpdatedAt");
    document.remove("_snBnsDocumentVersion");
    let revision = owner_config
        .get("iat")
        .and_then(Value::as_u64)
        .or_else(|| owner_config.get("_snBnsUpdatedAt").and_then(Value::as_u64))
        .or_else(|| {
            owner_config
                .get("_snBnsDocumentVersion")
                .and_then(Value::as_u64)
        })
        .unwrap_or(1)
        .max(1);
    document
        .entry("iat".to_string())
        .or_insert_with(|| Value::from(revision));
    document
        .entry("exp".to_string())
        .or_insert_with(|| Value::from(253_402_300_799_u64));
}

fn build_owner_document_from_jwk(
    owner_did: &str,
    canonical_zone: &str,
    jwk: Jwk,
    source: &'static str,
) -> SnResolverResult<Value> {
    let owner = DID::from_str(owner_did).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("invalid owner DID {}: {}", owner_did, e),
        )
    })?;
    let zone = DID::from_str(canonical_zone).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("invalid canonical zone DID {}: {}", canonical_zone, e),
        )
    })?;

    let mut config = OwnerDocument::new(
        owner.clone(),
        owner.id.clone(),
        format!("{}@{}", owner.id, owner_did),
        jwk,
    );
    config.set_default_zone_did(zone);
    config.extra_info.insert(
        "buckyos".to_string(),
        json!({
            "canonicalZone": canonical_zone,
            "source": source,
            "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
        }),
    );

    serde_json::to_value(config).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::BackendUnavailable,
            format!("encode synthesized owner document failed: {}", e),
        )
    })
}

fn normalize_owner_config_document(
    mut document: Value,
    owner_did: &str,
    canonical_zone: &str,
    source: &'static str,
) -> Value {
    if let Some(obj) = document.as_object_mut() {
        obj.insert("id".to_string(), Value::String(owner_did.to_string()));
        obj.entry("name".to_string())
            .or_insert_with(|| Value::String(owner_did.to_string()));
        obj.entry("full_name".to_string())
            .or_insert_with(|| Value::String(format!("{}@{}", owner_did, owner_did)));
        obj.entry("display_name".to_string())
            .or_insert_with(|| Value::String(format!("{}@{}", owner_did, owner_did)));
        obj.insert(
            "default_zone_did".to_string(),
            Value::String(canonical_zone.to_string()),
        );
        obj.insert(
            "binded_zone_list".to_string(),
            Value::Array(vec![Value::String(canonical_zone.to_string())]),
        );

        if let Some(methods) = obj
            .get_mut("verificationMethod")
            .and_then(Value::as_array_mut)
        {
            for method in methods {
                if let Some(method) = method.as_object_mut() {
                    method.insert(
                        "controller".to_string(),
                        Value::String(owner_did.to_string()),
                    );
                }
            }
        }

        merge_buckyos_object(
            obj,
            json!({
                "canonicalZone": canonical_zone,
                "source": source,
                "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
            }),
        );
    }
    document
}

fn insert_document_provenance(
    document: &mut Value,
    canonical_zone: &str,
    source: &'static str,
    ttl: u32,
) {
    if let Some(obj) = document.as_object_mut() {
        merge_buckyos_object(
            obj,
            json!({
                "canonicalZone": canonical_zone,
                "source": source,
                "ttl": ttl,
            }),
        );
    }
}

fn merge_buckyos_object(obj: &mut Map<String, Value>, value: Value) {
    let Some(extra) = value.as_object() else {
        return;
    };
    let buckyos = obj
        .entry("buckyos".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(buckyos) = buckyos.as_object_mut() {
        for (key, value) in extra {
            buckyos.insert(key.clone(), value.clone());
        }
    }
}

pub(crate) fn owner_key_from_config(value: &Value) -> Option<Jwk> {
    first_jwk_path(
        value,
        &[
            &["public_key"][..],
            &["owner_key"][..],
            &["default_key"][..],
            &["key"][..],
            &["verificationMethod", "0", "publicKeyJwk"][..],
        ],
    )
}

fn first_jwk_path(value: &Value, paths: &[&[&str]]) -> Option<Jwk> {
    for path in paths {
        if let Some(value) = value_path(value, path) {
            if let Some(jwk) = value_to_jwk(value) {
                return Some(jwk);
            }
        }
    }
    None
}

fn value_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        if let Ok(index) = key.parse::<usize>() {
            current = current.as_array()?.get(index)?;
        } else {
            current = current.get(*key)?;
        }
    }
    Some(current)
}

fn value_to_jwk(value: &Value) -> Option<Jwk> {
    match value {
        Value::Object(_) => serde_json::from_value(value.clone()).ok(),
        Value::String(value) => key_like_string_to_jwk(value.as_str()),
        _ => None,
    }
}

pub(crate) fn key_like_string_to_jwk(value: &str) -> Option<Jwk> {
    let value = value.trim().trim_end_matches(';');
    if value.is_empty() {
        return None;
    }

    if let Ok(jwk) = serde_json::from_str::<Jwk>(value) {
        return DecodingKey::from_jwk(&jwk).ok().map(|_| jwk);
    }

    let value = value.strip_prefix("PKX=").unwrap_or(value);
    let x = value.split(':').next().unwrap_or(value);
    let jwk = create_jwt_by_x(x).ok()?;
    DecodingKey::from_jwk(&jwk).ok().map(|_| jwk)
}

fn rewrite_web_document_identity(
    document: &mut EncodedDocument,
    request_did: &str,
    owner_did: &str,
    canonical_zone: &str,
    device_name: Option<&str>,
) {
    let EncodedDocument::JsonLd(value) = document else {
        return;
    };

    let Some(obj) = value.as_object_mut() else {
        return;
    };

    // New node environments already publish a full DeviceDocument whose
    // semantic did:web identity matches the request. Keep it byte-for-byte
    // equivalent to the JWT payload supplied in RTCP Hello so authority
    // membership can compare the two documents exactly.
    if obj.get("id").and_then(Value::as_str) == Some(request_did) {
        return;
    }

    if let Some(existing_id) = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| *id != request_did)
        .map(ToOwned::to_owned)
    {
        obj.entry("did".to_string())
            .or_insert_with(|| Value::String(existing_id.clone()));
        obj.entry("canonical_did".to_string())
            .or_insert_with(|| Value::String(existing_id));
    }

    obj.insert("id".to_string(), Value::String(request_did.to_string()));
    obj.insert("owner".to_string(), Value::String(owner_did.to_string()));
    obj.insert(
        "canonical_zone".to_string(),
        Value::String(canonical_zone.to_string()),
    );

    if let Some(device_name) = device_name {
        obj.entry("device_name".to_string())
            .or_insert_with(|| Value::String(device_name.to_string()));
        obj.entry("name".to_string())
            .or_insert_with(|| Value::String(device_name.to_string()));
    }

    for key in ["zone_did", "zone"] {
        if obj
            .get(key)
            .and_then(Value::as_str)
            .map(|value| value.starts_with("did:bns:") || value == canonical_zone)
            .unwrap_or(false)
        {
            obj.insert(key.to_string(), Value::String(owner_did.to_string()));
        }
    }

    merge_buckyos_object(
        obj,
        json!({
            "canonicalZone": canonical_zone,
            "ownerConstraint": owner_did,
        }),
    );
}

fn document_declared_owner(document: &EncodedDocument) -> Option<String> {
    let value = document.clone().to_json_value().ok()?;
    let owner = value.get("owner")?.as_str()?;
    DID::from_str(owner).ok().map(|did| did.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn_resolver::{
        BnsDocument, BnsDocumentReader, BnsOwner, BootDocument, SnAuthReader, SnResolver,
        SnResolverConfig, ZoneDocument,
    };
    use crate::ZoneInfo;
    use std::collections::HashMap;

    const OWNER_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";

    fn compact_test_jwt(payload: &Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap())
        )
    }

    #[derive(Default)]
    struct StaticAuthReader {
        users: HashMap<String, SNUserInfo>,
        fail: bool,
    }

    #[async_trait]
    impl SnAuthReader for StaticAuthReader {
        async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
            if self.fail {
                return Err(SnResolverError::backend("AuthDB unavailable (test)"));
            }
            Ok(self.users.get(username).cloned())
        }

        async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
            if self.fail {
                return Err(SnResolverError::backend("AuthDB unavailable (test)"));
            }
            Ok(self
                .users
                .values()
                .filter(|user| {
                    user.user_domain.as_deref().is_some_and(|user_domain| {
                        domain == user_domain
                            || domain.ends_with(format!(".{}", user_domain).as_str())
                    })
                })
                .max_by_key(|user| {
                    user.user_domain
                        .as_deref()
                        .map(str::len)
                        .unwrap_or_default()
                })
                .cloned())
        }

        async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
            if self.fail {
                return Err(SnResolverError::backend("AuthDB unavailable (test)"));
            }
            Ok(Some(ZoneInfo::default_for(username)))
        }
    }

    #[derive(Default)]
    struct StaticBnsReader {
        owners: HashMap<String, BnsOwner>,
        documents: HashMap<(String, String), BnsDocument>,
    }

    #[async_trait]
    impl BnsDocumentReader for StaticBnsReader {
        async fn resolve_owner(&self, name: &str) -> SnResolverResult<Option<BnsOwner>> {
            Ok(self.owners.get(name).cloned())
        }

        async fn get_document(
            &self,
            name: &str,
            doc_type: &str,
        ) -> SnResolverResult<Option<BnsDocument>> {
            Ok(self
                .documents
                .get(&(name.to_string(), doc_type.to_string()))
                .cloned())
        }
    }

    fn auth_user(username: &str, state: UserState, public_key: &str) -> SNUserInfo {
        SNUserInfo {
            username: Some(username.to_string()),
            email: None,
            state,
            public_key: public_key.to_string(),
            activation_code: None,
            zone_config: String::new(),
            self_cert: false,
            user_domain: None,
            sn_ips: None,
            updated_at: 7,
            relay: None,
        }
    }

    fn auth_db_owner_key() -> String {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": OWNER_X,
        })
        .to_string()
    }

    fn resolver_with_users(users: Vec<SNUserInfo>) -> SnResolverBackedDidResolver {
        resolver_with_users_and_bns(users, StaticBnsReader::default())
    }

    fn resolver_with_users_and_bns(
        users: Vec<SNUserInfo>,
        bns: StaticBnsReader,
    ) -> SnResolverBackedDidResolver {
        let auth = Arc::new(StaticAuthReader {
            users: users
                .into_iter()
                .map(|user| (user.username.clone().unwrap(), user))
                .collect(),
            fail: false,
        });
        let resolver = Arc::new(SnResolver::new_with_bns(
            SnResolverConfig::new("sn.test", None, None, None, Vec::new()),
            auth.clone(),
            Arc::new(bns),
        ));
        SnResolverBackedDidResolver::new(resolver, auth, "sn.test")
    }

    fn empty_zone_document() -> ZoneDocument {
        ZoneDocument {
            raw: None,
            jwt: None,
            boot_jwt: None,
            devices: HashMap::new(),
            mini_device_jwts: HashMap::new(),
            gateway_device_name: None,
            gateway_ips: Vec::new(),
            ttl: None,
            version: None,
        }
    }

    fn empty_boot_document() -> BootDocument {
        BootDocument {
            raw: None,
            jwt: None,
            gateway_device_name: None,
            ttl: None,
            version: None,
        }
    }

    #[test]
    fn rewrites_web_device_document_identity_and_keeps_canonical_device_did() {
        let mut document = EncodedDocument::JsonLd(json!({
            "id": "did:dev:abc",
            "zone_did": "did:bns:alice",
            "name": "ood1"
        }));

        rewrite_web_document_identity(
            &mut document,
            "did:web:ood1.example.com",
            "did:web:example.com",
            "did:bns:alice",
            Some("ood1"),
        );

        let value = document.to_json_value().unwrap();
        assert_eq!(value["id"], "did:web:ood1.example.com");
        assert_eq!(value["did"], "did:dev:abc");
        assert_eq!(value["canonical_did"], "did:dev:abc");
        assert_eq!(value["owner"], "did:web:example.com");
        assert_eq!(value["zone_did"], "did:web:example.com");
        assert_eq!(value["buckyos"]["canonicalZone"], "did:bns:alice");
    }

    #[test]
    fn preserves_matching_web_device_document_for_authority_membership() {
        let expected = json!({
            "id": "did:web:ood1.example.com",
            "owner": "did:bns:alice",
            "device_type": "ood",
            "name": "ood1",
            "verificationMethod": [{
                "id": "#main_key",
                "controller": "did:web:ood1.example.com",
                "type": "Ed25519VerificationKey2020",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "abc"
                }
            }]
        });
        let mut document = EncodedDocument::JsonLd(expected.clone());

        rewrite_web_document_identity(
            &mut document,
            "did:web:ood1.example.com",
            "did:web:example.com",
            "did:bns:alice",
            Some("ood1"),
        );

        assert_eq!(document.clone().to_json_value().unwrap(), expected);
        assert_eq!(
            document_declared_owner(&document).as_deref(),
            Some("did:bns:alice")
        );
    }

    #[test]
    fn synthesizes_owner_document_from_effective_owner_key() {
        let zone = ZoneResolution {
            input: "example.com".to_string(),
            canonical_name: "alice".to_string(),
            zone_name: "alice".to_string(),
            owner: BnsOwner {
                name: "alice".to_string(),
                effective_owner: Some("T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8".to_string()),
                owner_config: None,
            },
            owner_from_auth_db: false,
            zone_doc: empty_zone_document(),
            boot_doc: empty_boot_document(),
            user_domain: Some("example.com".to_string()),
            self_cert: true,
            relay_sn: None,
            source: ZoneResolutionSource::UserDomain,
        };

        let (document, source) =
            synthesize_owner_document("did:web:example.com", "did:bns:alice", &zone).unwrap();

        assert_eq!(source, "effective-owner");
        assert_eq!(document["id"], "did:web:example.com");
        assert_eq!(document["binded_zone_list"][0], "did:bns:alice");
        assert_eq!(
            document["verificationMethod"][0]["controller"],
            "did:web:example.com"
        );
        assert_eq!(document["buckyos"]["canonicalZone"], "did:bns:alice");
    }

    #[test]
    fn parses_pkx_style_owner_key_strings() {
        let jwk =
            key_like_string_to_jwk("PKX=T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8:bns:alice;")
                .unwrap();
        let value = serde_json::to_value(jwk).unwrap();

        assert_eq!(value["x"], "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8");
    }

    #[test]
    fn emits_did_resolution_envelope_when_requested() {
        let response = SnDidResolveResponse {
            did: "did:web:example.com".to_string(),
            doc_type: "owner".to_string(),
            document: EncodedDocument::JsonLd(json!({ "id": "did:web:example.com" })),
            source: SnDidDocumentSource::SynthesizedOwnerDocument,
            profile: SnDidResolverProfile::InternalZoneResolver,
            document_status: Some(SnDidDocumentStatus::Active),
            metadata: json!({
                "buckyos": {
                    "resolverRole": "zone_resolver",
                    "canonicalZone": "did:bns:alice",
                }
            }),
        };

        assert_eq!(
            response.content_type_for_accept(Some("application/did-resolution")),
            DID_RESOLUTION_CONTENT_TYPE
        );
        let body: Value = serde_json::from_str(
            response
                .body_for_accept(Some("application/did-resolution"))
                .as_str(),
        )
        .unwrap();

        assert_eq!(body["didDocument"]["id"], "did:web:example.com");
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "active"
        );
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["canonicalZone"],
            "did:bns:alice"
        );
    }

    #[tokio::test]
    async fn internal_zone_resolver_projects_active_auth_db_owner_with_revision_metadata() {
        let resolver = resolver_with_users(vec![auth_user(
            "alice",
            UserState::Active,
            auth_db_owner_key().as_str(),
        )]);
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:alice").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();

        assert_eq!(response.document_status, Some(SnDidDocumentStatus::Active));
        assert_eq!(response.source, SnDidDocumentSource::AuthDbProjection);
        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(response.doc_type, "owner");
        let body: Value = serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
        let metadata = &body["didDocumentMetadata"]["buckyos"];
        assert_eq!(body["didDocument"]["id"], "did:bns:alice");
        assert_eq!(metadata["documentStatus"], "active");
        assert_eq!(metadata["effectiveOwner"], "did:bns:alice");
        assert_eq!(metadata["ownerKeySource"], "sn-auth-db");
        assert!(metadata["documentVersion"].as_u64().is_some());
        assert_eq!(metadata["docHash"].as_str().unwrap().len(), 64);
        assert!(
            metadata["validUntil"].as_u64().unwrap() >= metadata["checkedAt"].as_u64().unwrap()
        );
        let first_hash = metadata["docHash"].clone();

        let repeated = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:alice").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        let repeated_body: Value =
            serde_json::from_str(repeated.body_for_accept(None).as_str()).unwrap();
        assert_eq!(
            repeated_body["didDocumentMetadata"]["buckyos"]["docHash"], first_hash,
            "the same AuthDB revision must not regenerate a different OwnerDocument"
        );
    }

    #[tokio::test]
    async fn internal_zone_resolver_maps_auth_db_negative_owner_states() {
        for (state, expected_status, expected_http) in [
            (
                UserState::Suspended,
                SnDidDocumentStatus::Revoked,
                StatusCode::GONE,
            ),
            (
                UserState::Banned,
                SnDidDocumentStatus::Revoked,
                StatusCode::GONE,
            ),
            (
                UserState::Deleted,
                SnDidDocumentStatus::Tombstoned,
                StatusCode::GONE,
            ),
        ] {
            let resolver = resolver_with_users(vec![auth_user(
                "alice",
                state,
                auth_db_owner_key().as_str(),
            )]);
            let response = resolver
                .resolve(SnDidResolveRequest::new(
                    DID::from_str("did:bns:alice").unwrap(),
                    Some("owner".to_string()),
                    None,
                    SnDidResolverProfile::InternalZoneResolver,
                ))
                .await
                .unwrap();
            assert_eq!(response.document_status, Some(expected_status));
            assert_eq!(response.status_code(), expected_http);
            let body: Value =
                serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
            assert!(body["didDocument"].is_null());
            assert_eq!(
                body["didDocumentMetadata"]["buckyos"]["documentStatus"],
                json!(expected_status)
            );
        }
    }

    #[tokio::test]
    async fn internal_zone_resolver_does_not_promote_active_user_without_owner_key() {
        let resolver = resolver_with_users(vec![auth_user("alice", UserState::Active, "")]);
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:alice").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        assert_eq!(response.document_status, Some(SnDidDocumentStatus::Missing));
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        assert!(response
            .body_for_accept(None)
            .contains("\"documentStatus\":\"missing\""));
    }

    #[tokio::test]
    async fn internal_zone_resolver_maps_only_the_managed_web_owner_suffix() {
        let resolver = resolver_with_users(vec![auth_user(
            "alice",
            UserState::Active,
            auth_db_owner_key().as_str(),
        )]);
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:web:alice.sn.test").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
        assert_eq!(body["didDocument"]["id"], "did:web:alice.sn.test");
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["effectiveOwner"],
            "did:web:alice.sn.test"
        );

        let error = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:web:alice.unmanaged.test").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SnResolverErrorKind::NotManaged);
    }

    #[tokio::test]
    async fn internal_zone_resolver_returns_complete_device_with_stable_revision_metadata() {
        let document = json!({
            "id": "did:bns:ood1.alice",
            "owner": "did:bns:alice",
            "iat": 42,
            "exp": 253_402_300_799_u64,
            "verificationMethod": [{
                "id": "did:bns:ood1.alice#main_key",
                "type": "JsonWebKey2020",
                "controller": "did:bns:ood1.alice",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": OWNER_X,
                }
            }],
            "authentication": ["did:bns:ood1.alice#main_key"],
        });
        let device_jwt = compact_test_jwt(&document);
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("alice".to_string(), "ood1".to_string()),
            BnsDocument::jwt("alice", "ood1", device_jwt.clone()),
        );
        let resolver = resolver_with_users_and_bns(
            vec![auth_user(
                "alice",
                UserState::Active,
                auth_db_owner_key().as_str(),
            )],
            bns,
        );
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:ood1.alice").unwrap(),
                Some("device".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        let encoded = EncodedDocument::Jwt(device_jwt.clone());
        let body: Value = serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
        let metadata = &body["didDocumentMetadata"]["buckyos"];

        assert_eq!(body["didDocument"], device_jwt);
        assert_eq!(metadata["docType"], "device");
        assert_eq!(metadata["documentStatus"], "active");
        assert_eq!(metadata["effectiveOwner"], "did:bns:alice");
        assert_eq!(metadata["source"], "bns_document");
        assert_eq!(metadata["documentVersion"], 42);
        assert_eq!(
            metadata["docHash"],
            Value::String(document_content_hash(&encoded))
        );
    }

    #[tokio::test]
    async fn internal_zone_resolver_preserves_bns_owner_key_provenance_over_auth_db() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: Some(OWNER_X.to_string()),
                owner_config: None,
            },
        );
        let resolver = resolver_with_users_and_bns(
            vec![auth_user(
                "alice",
                UserState::Active,
                auth_db_owner_key().as_str(),
            )],
            bns,
        );
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:alice").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
        let metadata = &body["didDocumentMetadata"]["buckyos"];

        assert_eq!(
            response.source,
            SnDidDocumentSource::SynthesizedOwnerDocument
        );
        assert_eq!(metadata["ownerKeySource"], "effective-owner");
        assert!(metadata.get("authDbRevision").is_none());
    }

    #[tokio::test]
    async fn internal_zone_resolver_keeps_web_device_identity_and_owner_metadata() {
        let document = json!({
            "id": "did:web:ood1.example.com",
            "owner": "did:web:example.com",
            "iat": 42,
            "exp": 253_402_300_799_u64,
            "verificationMethod": [{
                "id": "did:web:ood1.example.com#main_key",
                "type": "JsonWebKey2020",
                "controller": "did:web:ood1.example.com",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": OWNER_X,
                }
            }],
            "authentication": ["did:web:ood1.example.com#main_key"],
        });
        let device_jwt = compact_test_jwt(&document);
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("alice".to_string(), "ood1".to_string()),
            BnsDocument::jwt("alice", "ood1", device_jwt.clone()),
        );
        let mut user = auth_user("alice", UserState::Active, auth_db_owner_key().as_str());
        user.user_domain = Some("example.com".to_string());
        let resolver = resolver_with_users_and_bns(vec![user], bns);
        let response = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:web:ood1.example.com").unwrap(),
                Some("device".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(response.body_for_accept(None).as_str()).unwrap();
        let metadata = &body["didDocumentMetadata"]["buckyos"];

        assert_eq!(body["didDocument"], device_jwt);
        assert_eq!(metadata["effectiveOwner"], "did:web:example.com");
        assert_eq!(metadata["canonicalZone"], "did:bns:alice");
        assert_eq!(metadata["source"], "bns_document");
    }

    #[tokio::test]
    async fn internal_zone_resolver_does_not_turn_auth_db_failure_into_missing() {
        let auth = Arc::new(StaticAuthReader {
            users: HashMap::new(),
            fail: true,
        });
        let resolver = Arc::new(SnResolver::new(
            SnResolverConfig::new("sn.test", None, None, None, Vec::new()),
            auth.clone(),
        ));
        let resolver = SnResolverBackedDidResolver::new(resolver, auth, "sn.test");
        let error = resolver
            .resolve(SnDidResolveRequest::new(
                DID::from_str("did:bns:alice").unwrap(),
                Some("owner".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), SnResolverErrorKind::BackendUnavailable);
    }

    #[test]
    fn internal_zone_resolver_canonicalizes_legacy_doc_type_and_defaults_to_envelope() {
        let request = SnDidResolveRequest::new(
            DID::from_str("did:bns:ood1.alice").unwrap(),
            Some("doc".to_string()),
            None,
            SnDidResolverProfile::InternalZoneResolver,
        );
        assert_eq!(request.doc_type(), Some("device"));

        let response = SnDidResolveResponse {
            did: request.did.to_string(),
            doc_type: "device".to_string(),
            document: EncodedDocument::JsonLd(json!({
                "id": "did:bns:ood1.alice",
                "iat": 7,
            })),
            source: SnDidDocumentSource::DeviceMiniDocument,
            profile: SnDidResolverProfile::InternalZoneResolver,
            document_status: Some(SnDidDocumentStatus::Active),
            metadata: json!({"buckyos": {"docType": "device"}}),
        };
        assert_eq!(
            response.content_type_for_accept(None),
            DID_RESOLUTION_CONTENT_TYPE
        );
        assert!(
            serde_json::from_str::<Value>(response.body_for_accept(None).as_str())
                .unwrap()
                .get("didDocument")
                .is_some()
        );

        let jwt_response = SnDidResolveResponse {
            document: EncodedDocument::Jwt("header.payload.signature".to_string()),
            ..response
        };
        let jwt_body: Value =
            serde_json::from_str(jwt_response.body_for_accept(None).as_str()).unwrap();
        assert_eq!(
            jwt_body["didDocument"],
            Value::String("header.payload.signature".to_string())
        );
    }
}
