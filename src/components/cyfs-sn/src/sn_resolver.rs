use crate::sn_did_resolver::{
    key_like_string_to_jwk, owner_key_from_config, SnDidDocumentSource, SnDidResolveResponse,
    SnDidResolverProfile,
};
use crate::{
    RelayAssignment, RelayAssignmentState, RelayNodeIpMapReq, RelayNodeIpMapSnapshot, SNUserInfo,
    SnAuthDBRef, SnDeviceInfoDBRef, SnDeviceStateView, UserDnsChangePage, UserDnsLookup,
    UserDnsRecordType, UserDnsRrset, UserState, ZoneInfo,
};
use async_trait::async_trait;
use bns_client::canonical_bns_name;
use cyfs_gateway_lib::{server_err, DnsAuthority, ServerError, ServerErrorCode};
use jsonwebtoken::{
    jwk::{AlgorithmParameters, Jwk},
    DecodingKey,
};
use log::{debug, warn};
use name_client::{NameInfo, RecordType};
use name_lib::{EncodedDocument, DID};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const DEFAULT_SN_RESOLVER_TTL_SECS: u32 = 60;
pub const DEFAULT_LEGACY_GATEWAY_DEVICE: &str = "ood1";
pub const BNS_DOC_ZONE: &str = "zone";
pub const BNS_DOC_BOOT: &str = "boot";
pub const BNS_DOC_DEVICE_MINI: &str = "device_mini_doc";
pub const BNS_DOC_DNS_TXT: &str = "dns_txt";
pub const UNASSIGNED_RELAY_SN: &str = "unassigned";
pub const DEFAULT_AUTH_SOA_SERIAL: u32 = 1;
pub const DEFAULT_AUTH_SOA_REFRESH: i32 = 300;
pub const DEFAULT_AUTH_SOA_RETRY: i32 = 60;
pub const DEFAULT_AUTH_SOA_EXPIRE: i32 = 86_400;
pub const DEFAULT_AUTH_SOA_MINIMUM: u32 = 60;
pub const SN_SERVER_IP_NOT_CONFIGURED: &str = "SN server ip is not configured";

pub type SnResolverRef = Arc<SnResolver>;
pub type SnResolverResult<T> = std::result::Result<T, SnResolverError>;
pub type SnAuthReaderRef = Arc<dyn SnAuthReader>;
pub type BnsDocumentReaderRef = Arc<dyn BnsDocumentReader>;
pub type DeviceOnlineReaderRef = Arc<dyn DeviceOnlineReader>;
pub type RelayAssignmentReaderRef = Arc<dyn RelayAssignmentReader>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnResolverErrorKind {
    NotManaged,
    NameNotFound,
    DocumentNotFound,
    DeviceNotFound,
    UnsupportedRecordType,
    UnsupportedDidMethod,
    InvalidHostname,
    InvalidDid,
    BackendUnavailable,
}

#[derive(Debug, Clone)]
pub struct SnResolverError {
    kind: SnResolverErrorKind,
    message: String,
}

impl SnResolverError {
    pub fn new(kind: SnResolverErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> SnResolverErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(SnResolverErrorKind::NameNotFound, message)
    }

    pub fn backend(message: impl Into<String>) -> Self {
        Self::new(SnResolverErrorKind::BackendUnavailable, message)
    }

    pub fn to_server_error(&self) -> ServerError {
        let code = match self.kind {
            SnResolverErrorKind::InvalidHostname
            | SnResolverErrorKind::InvalidDid
            | SnResolverErrorKind::UnsupportedRecordType
            | SnResolverErrorKind::UnsupportedDidMethod => ServerErrorCode::InvalidParam,
            SnResolverErrorKind::NotManaged
            | SnResolverErrorKind::NameNotFound
            | SnResolverErrorKind::DocumentNotFound
            | SnResolverErrorKind::DeviceNotFound => ServerErrorCode::NotFound,
            SnResolverErrorKind::BackendUnavailable => ServerErrorCode::ProcessChainError,
        };

        server_err!(code, "{}", self.message)
    }
}

impl fmt::Display for SnResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SnResolverError {}

#[derive(Debug, Clone)]
pub struct SnResolverConfig {
    pub server_host: String,
    pub server_ip: Option<IpAddr>,
    pub aliases: Vec<String>,
    pub boot_jwt: Option<String>,
    pub owner_pkx: Option<String>,
    pub device_jwts: Vec<String>,
    pub default_ttl: u32,
    pub legacy_gateway_device_name: String,
    pub soa_serial: u32,
    pub soa_refresh: i32,
    pub soa_retry: i32,
    pub soa_expire: i32,
    pub soa_minimum: u32,
}

impl SnResolverConfig {
    pub fn new(
        server_host: impl Into<String>,
        server_ip: Option<IpAddr>,
        boot_jwt: Option<String>,
        owner_pkx: Option<String>,
        device_jwts: Vec<String>,
    ) -> Self {
        Self {
            server_host: normalize_host_lossy(server_host.into().as_str()),
            server_ip,
            aliases: Vec::new(),
            boot_jwt: boot_jwt.filter(|value| !value.trim().is_empty()),
            owner_pkx: owner_pkx.filter(|value| !value.trim().is_empty()),
            device_jwts: device_jwts
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect(),
            default_ttl: DEFAULT_SN_RESOLVER_TTL_SECS,
            legacy_gateway_device_name: DEFAULT_LEGACY_GATEWAY_DEVICE.to_string(),
            soa_serial: DEFAULT_AUTH_SOA_SERIAL,
            soa_refresh: DEFAULT_AUTH_SOA_REFRESH,
            soa_retry: DEFAULT_AUTH_SOA_RETRY,
            soa_expire: DEFAULT_AUTH_SOA_EXPIRE,
            soa_minimum: DEFAULT_AUTH_SOA_MINIMUM,
        }
    }

    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases
            .into_iter()
            .map(|alias| normalize_host_lossy(alias.as_str()))
            .filter(|alias| !alias.is_empty())
            .collect();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ZoneResolutionSource {
    BnsName,
    UserDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum DnsResolutionSource {
    ExplicitRecord,
    BnsDocument,
    DeviceOnlineInfo,
    SnSelf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum RelayState {
    Healthy,
    Draining,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RelayMigrationHint {
    pub migrated_from: Option<String>,
    pub migration_deadline: Option<u64>,
    pub generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BnsOwner {
    pub name: String,
    pub effective_owner: Option<String>,
    pub owner_config: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct BnsDocumentMeta {
    pub version: Option<u64>,
    pub name_seq: Option<u64>,
    pub updated_at: Option<u64>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BnsDocumentContent {
    Json(Value),
    Jwt(String),
    Text(String),
}

impl BnsDocumentContent {
    fn to_encoded_document(&self) -> EncodedDocument {
        match self {
            Self::Json(value) => EncodedDocument::JsonLd(value.clone()),
            Self::Jwt(jwt) => EncodedDocument::Jwt(jwt.clone()),
            Self::Text(text) => EncodedDocument::Jwt(text.clone()),
        }
    }

    fn to_json_value(&self) -> Option<Value> {
        match self {
            Self::Json(value) => Some(value.clone()),
            Self::Jwt(jwt) | Self::Text(jwt) => {
                EncodedDocument::Jwt(jwt.clone()).to_json_value().ok()
            }
        }
    }

    fn as_jwt(&self) -> Option<String> {
        match self {
            Self::Jwt(jwt) => Some(jwt.clone()),
            Self::Text(text) if !text.trim_start().starts_with('{') => Some(text.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BnsDocument {
    pub name: String,
    pub doc_type: String,
    pub content: BnsDocumentContent,
    pub meta: BnsDocumentMeta,
}

impl BnsDocument {
    pub fn json(name: impl Into<String>, doc_type: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
            content: BnsDocumentContent::Json(value),
            meta: BnsDocumentMeta::default(),
        }
    }

    pub fn jwt(
        name: impl Into<String>,
        doc_type: impl Into<String>,
        jwt: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
            content: BnsDocumentContent::Jwt(jwt.into()),
            meta: BnsDocumentMeta::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneDocument {
    pub raw: Option<Value>,
    pub jwt: Option<String>,
    pub boot_jwt: Option<String>,
    pub devices: HashMap<String, Value>,
    pub mini_device_jwts: HashMap<String, String>,
    pub gateway_device_name: Option<String>,
    pub gateway_ips: Vec<IpAddr>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

impl ZoneDocument {
    fn empty() -> Self {
        Self {
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

    fn from_bns_document(document: &BnsDocument) -> Self {
        let raw = document.content.to_json_value();
        let jwt = document.content.as_jwt();
        let boot_jwt = raw.as_ref().and_then(find_boot_jwt);
        let devices = raw.as_ref().map(find_device_map).unwrap_or_default();
        let mini_device_jwts = raw.as_ref().map(find_mini_device_jwts).unwrap_or_default();
        let gateway_device_name = raw.as_ref().and_then(find_gateway_device_name);
        let gateway_ips = raw.as_ref().map(find_gateway_ips).unwrap_or_default();
        let ttl = raw.as_ref().and_then(find_ttl).or(document.meta.ttl);
        Self {
            raw,
            jwt,
            boot_jwt,
            devices,
            mini_device_jwts,
            gateway_device_name,
            gateway_ips,
            ttl,
            version: document.meta.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BootDocument {
    pub raw: Option<Value>,
    pub jwt: Option<String>,
    pub gateway_device_name: Option<String>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

impl BootDocument {
    fn empty() -> Self {
        Self {
            raw: None,
            jwt: None,
            gateway_device_name: None,
            ttl: None,
            version: None,
        }
    }

    fn from_bns_document(document: &BnsDocument) -> Self {
        let raw = document.content.to_json_value();
        let jwt = document.content.as_jwt();
        let gateway_device_name = raw.as_ref().and_then(find_gateway_device_name);
        let ttl = raw.as_ref().and_then(find_ttl).or(document.meta.ttl);
        Self {
            raw,
            jwt,
            gateway_device_name,
            ttl,
            version: document.meta.version,
        }
    }

    fn from_legacy_boot_jwt(jwt: &str) -> Self {
        let raw = EncodedDocument::Jwt(jwt.to_string()).to_json_value().ok();
        Self {
            gateway_device_name: raw.as_ref().and_then(find_gateway_device_name),
            ttl: raw.as_ref().and_then(find_ttl),
            raw,
            jwt: Some(jwt.to_string()),
            version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceMiniDocument {
    pub zone_name: String,
    pub device_name: String,
    pub did: String,
    pub mini_config_jwt: Option<String>,
    pub document: Option<Value>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneResolution {
    pub input: String,
    pub canonical_name: String,
    pub zone_name: String,
    pub owner: BnsOwner,
    #[serde(skip)]
    pub owner_from_auth_db: bool,
    pub zone_doc: ZoneDocument,
    pub boot_doc: BootDocument,
    pub user_domain: Option<String>,
    pub self_cert: bool,
    pub relay_sn: Option<String>,
    pub source: ZoneResolutionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayResolution {
    pub zone_name: String,
    pub hostname: String,
    pub gateway_device_name: String,
    pub gateway_did: String,
    pub device_doc: DeviceMiniDocument,
    pub online: Option<SnDeviceStateView>,
    pub addresses: Vec<IpAddr>,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsResolution {
    pub hostname: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub addresses: Vec<IpAddr>,
    pub txt: Vec<String>,
    pub source: DnsResolutionSource,
}

/// Resolver-level authoritative DNS outcome.  Zone ownership, owner-name
/// existence, RRset existence, and temporary failure remain distinct until
/// the DNS wire response is built.
#[derive(Debug, Clone)]
pub enum SnAuthoritativeDnsResult {
    NotManaged,
    AuthoritativeAnswer {
        authority: DnsAuthority,
        resolution: DnsResolution,
    },
    AuthoritativeNoData {
        authority: DnsAuthority,
    },
    AuthoritativeNxDomain {
        authority: DnsAuthority,
    },
    TemporaryFailure {
        cause: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RelayResolution {
    pub zone_name: String,
    pub relay_sn: String,
    pub relay_state: RelayState,
    pub migration_hint: Option<RelayMigrationHint>,
}

#[async_trait]
pub trait BnsDocumentReader: Send + Sync + 'static {
    async fn resolve_owner(&self, _name: &str) -> SnResolverResult<Option<BnsOwner>> {
        Ok(None)
    }

    async fn get_document(
        &self,
        _name: &str,
        _doc_type: &str,
    ) -> SnResolverResult<Option<BnsDocument>> {
        Ok(None)
    }
}

pub struct EmptyBnsDocumentReader;

#[async_trait]
impl BnsDocumentReader for EmptyBnsDocumentReader {}

#[async_trait]
pub trait SnAuthReader: Send + Sync + 'static {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>>;
    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>>;
    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>>;
    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResolverResult<UserDnsLookup> {
        let _ = (name, record_type);
        Ok(UserDnsLookup {
            rrset: None,
            observed_revision: 0,
        })
    }
    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResolverResult<UserDnsChangePage> {
        let _ = (after_revision, limit);
        Ok(UserDnsChangePage {
            changes: Vec::new(),
            current_revision: 0,
            earliest_available_revision: 1,
        })
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResolverResult<Vec<IpAddr>> {
        let Some(zone_info) = self.get_zone_info(username).await? else {
            return Ok(Vec::new());
        };
        Ok(parse_sn_ips(zone_info.sn_ips.as_deref(), username))
    }
}

pub struct EmptySnAuthReader;

#[async_trait]
impl SnAuthReader for EmptySnAuthReader {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
        let _ = username;
        Ok(None)
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
        let _ = domain;
        Ok(None)
    }

    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
        Ok(Some(ZoneInfo::default_for(username)))
    }
}

pub struct SnAuthResolverReader {
    db: SnAuthDBRef,
}

impl SnAuthResolverReader {
    pub fn new(db: SnAuthDBRef) -> Self {
        Self { db }
    }
}

#[async_trait]
impl SnAuthReader for SnAuthResolverReader {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
        self.db
            .get_user_info(username)
            .await
            .map_err(|e| SnResolverError::backend(format!("query user {} failed: {}", username, e)))
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
        self.db.get_user_by_domain(domain).await.map_err(|e| {
            SnResolverError::backend(format!("query user by domain {} failed: {}", domain, e))
        })
    }

    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
        self.db.get_zone_info(username).await.map_err(|e| {
            SnResolverError::backend(format!("query zone_info {} failed: {}", username, e))
        })
    }

    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResolverResult<UserDnsLookup> {
        self.db
            .get_user_dns_rrset(name, record_type)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query user DNS RRset {} {} failed: {}",
                    name, record_type, e
                ))
            })
    }

    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResolverResult<UserDnsChangePage> {
        self.db
            .list_user_dns_changes(after_revision, limit)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "list user DNS changes after {} failed: {}",
                    after_revision, e
                ))
            })
    }
}

#[async_trait]
pub trait DeviceOnlineReader: Send + Sync + 'static {
    async fn get_device_state(&self, _did: &str) -> SnResolverResult<Option<SnDeviceStateView>> {
        Ok(None)
    }

    async fn get_device_state_by_name(
        &self,
        _zone: &str,
        _device_name: &str,
    ) -> SnResolverResult<Option<SnDeviceStateView>> {
        Ok(None)
    }
}

pub struct EmptyDeviceOnlineReader;

#[async_trait]
impl DeviceOnlineReader for EmptyDeviceOnlineReader {}

pub struct SnDeviceInfoResolverReader {
    db: SnDeviceInfoDBRef,
}

impl SnDeviceInfoResolverReader {
    pub fn new(db: SnDeviceInfoDBRef) -> Self {
        Self { db }
    }
}

#[async_trait]
impl DeviceOnlineReader for SnDeviceInfoResolverReader {
    async fn get_device_state(&self, did: &str) -> SnResolverResult<Option<SnDeviceStateView>> {
        self.db.get_device_state(did).await.map_err(|e| {
            SnResolverError::backend(format!("query device online state {} failed: {}", did, e))
        })
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResolverResult<Option<SnDeviceStateView>> {
        self.db
            .get_device_state_by_name(zone, device_name)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query device online state {}.{} failed: {}",
                    device_name, zone, e
                ))
            })
    }
}

#[async_trait]
pub trait RelayAssignmentReader: Send + Sync + 'static {
    async fn get_zone_relay(&self, _zone: &str) -> SnResolverResult<Option<RelayAssignment>> {
        Ok(None)
    }

    async fn get_relay_node_ips(&self, _relay_id: &str) -> SnResolverResult<Option<[IpAddr; 2]>> {
        Ok(None)
    }
}

pub struct EmptyRelayAssignmentReader;

#[async_trait]
impl RelayAssignmentReader for EmptyRelayAssignmentReader {}

#[derive(Debug)]
struct RelayNodeMapCache {
    snapshot: Option<RelayNodeIpMapSnapshot>,
    expires_at: Instant,
}

pub struct SnAuthDbRelayResolverReader {
    db: SnAuthDBRef,
    cache: RwLock<RelayNodeMapCache>,
    cache_ttl: Duration,
}

impl SnAuthDbRelayResolverReader {
    pub fn new(db: SnAuthDBRef) -> Self {
        Self {
            db,
            cache: RwLock::new(RelayNodeMapCache {
                snapshot: None,
                expires_at: Instant::now(),
            }),
            cache_ttl: Duration::from_secs(DEFAULT_SN_RESOLVER_TTL_SECS as u64),
        }
    }

    pub fn with_cache_ttl(mut self, cache_ttl: Duration) -> Self {
        self.cache_ttl = cache_ttl;
        self
    }

    fn cached_ip_pair(&self, relay_id: &str) -> (Option<[IpAddr; 2]>, bool) {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let value = cache.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .nodes
                .iter()
                .find(|node| node.relay_id == relay_id)
                .map(|node| node.ips)
        });
        (value, cache.expires_at > Instant::now())
    }

    async fn refresh(&self, force_full: bool) -> SnResolverResult<()> {
        let if_revision = if force_full {
            None
        } else {
            self.cache
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.revision)
        };
        let snapshot = self
            .db
            .get_relay_nodes_ip_map(RelayNodeIpMapReq { if_revision })
            .await
            .map_err(|e| {
                SnResolverError::backend(format!("refresh relay node IP map failed: {}", e))
            })?;
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if let Some(snapshot) = snapshot {
            cache.snapshot = Some(snapshot);
        } else if cache.snapshot.is_none() {
            return Err(SnResolverError::backend(
                "AuthDB returned not-modified without a cached relay node map",
            ));
        }
        cache.expires_at = Instant::now() + self.cache_ttl;
        Ok(())
    }
}

#[async_trait]
impl RelayAssignmentReader for SnAuthDbRelayResolverReader {
    async fn get_zone_relay(&self, zone: &str) -> SnResolverResult<Option<RelayAssignment>> {
        self.db.get_zone_relay(zone).await.map_err(|e| {
            SnResolverError::backend(format!("query relay assignment {} failed: {}", zone, e))
        })
    }

    async fn get_relay_node_ips(&self, relay_id: &str) -> SnResolverResult<Option<[IpAddr; 2]>> {
        let (cached, fresh) = self.cached_ip_pair(relay_id);
        if cached.is_some() {
            if fresh {
                return Ok(cached);
            }
        } else if fresh {
            self.refresh(true).await?;
            return Ok(self.cached_ip_pair(relay_id).0);
        }

        self.refresh(false).await?;
        let refreshed = self.cached_ip_pair(relay_id).0;
        if refreshed.is_some() {
            return Ok(refreshed);
        }
        self.refresh(true).await?;
        Ok(self.cached_ip_pair(relay_id).0)
    }
}

#[derive(Debug)]
pub struct SnResolverCache {
    dns: RwLock<HashMap<DnsCacheKey, DnsCacheEntry>>,
    authoritative_dns: RwLock<HashMap<AuthoritativeDnsCacheKey, AuthoritativeDnsCacheEntry>>,
    min_ttl: Duration,
}

impl Default for SnResolverCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SnResolverCache {
    pub fn new() -> Self {
        Self {
            dns: RwLock::new(HashMap::new()),
            authoritative_dns: RwLock::new(HashMap::new()),
            min_ttl: Duration::from_secs(DEFAULT_SN_RESOLVER_TTL_SECS as u64),
        }
    }

    pub fn query_dns(&self, hostname: &str, record_type: RecordType) -> Option<DnsCacheValue> {
        let key = DnsCacheKey::new(hostname, record_type);
        let now = Instant::now();
        {
            let items = self.dns.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = items.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.value.clone());
                }
            }
        }

        let mut items = self.dns.write().unwrap_or_else(|e| e.into_inner());
        if items
            .get(&key)
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false)
        {
            items.remove(&key);
        }
        None
    }

    pub fn insert_dns(
        &self,
        hostname: &str,
        record_type: RecordType,
        value: DnsCacheValue,
        ttl: Option<u32>,
    ) {
        let requested = Duration::from_secs(ttl.unwrap_or(DEFAULT_SN_RESOLVER_TTL_SECS) as u64);
        let entry = DnsCacheEntry {
            value,
            expires_at: Instant::now() + requested.max(self.min_ttl),
        };
        self.dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(DnsCacheKey::new(hostname, record_type), entry);
    }

    pub fn remove_dns(&self, hostname: &str, record_type: RecordType) -> bool {
        self.dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&DnsCacheKey::new(hostname, record_type))
            .is_some()
    }

    pub fn remove_dns_name(&self, hostname: &str) -> usize {
        let hostname = normalize_host_lossy(hostname);
        let mut removed = 0;
        {
            let mut items = self.dns.write().unwrap_or_else(|e| e.into_inner());
            let before = items.len();
            items.retain(|key, _| key.hostname != hostname);
            removed += before - items.len();
        }
        removed + self.remove_authoritative_name(hostname.as_str())
    }

    pub fn query_authoritative_dns(
        &self,
        hostname: &str,
        record_type: &str,
    ) -> Option<SnAuthoritativeDnsResult> {
        let key = AuthoritativeDnsCacheKey::new(hostname, record_type);
        let now = Instant::now();
        {
            let items = self
                .authoritative_dns
                .read()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = items.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.value.clone());
                }
            }
        }

        let mut items = self
            .authoritative_dns
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if items
            .get(&key)
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false)
        {
            items.remove(&key);
        }
        None
    }

    pub fn insert_authoritative_dns(
        &self,
        hostname: &str,
        record_type: &str,
        value: SnAuthoritativeDnsResult,
        ttl: u32,
    ) {
        let requested = Duration::from_secs(ttl as u64).max(self.min_ttl);
        let entry = AuthoritativeDnsCacheEntry {
            value,
            expires_at: Instant::now() + requested,
        };
        self.authoritative_dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(AuthoritativeDnsCacheKey::new(hostname, record_type), entry);
    }

    /// Invalidate every RR type for an owner name. Name existence is shared
    /// across RRsets, so adding/removing TXT can change an MX response between
    /// NXDOMAIN and NODATA as well.
    pub fn remove_authoritative_name(&self, hostname: &str) -> usize {
        let hostname = normalize_host_lossy(hostname);
        let mut items = self
            .authoritative_dns
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let before = items.len();
        items.retain(|key, _| key.hostname != hostname);
        before - items.len()
    }

    pub fn clear(&self) {
        self.dns.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.authoritative_dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[derive(Clone, Debug)]
pub enum DnsCacheValue {
    Hit(DnsResolution),
    Tombstone(SnResolverErrorKind),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    hostname: String,
    record_type: String,
}

impl DnsCacheKey {
    fn new(hostname: &str, record_type: RecordType) -> Self {
        Self {
            hostname: normalize_host_lossy(hostname),
            record_type: record_type.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    value: DnsCacheValue,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AuthoritativeDnsCacheKey {
    hostname: String,
    record_type: String,
}

impl AuthoritativeDnsCacheKey {
    fn new(hostname: &str, record_type: &str) -> Self {
        Self {
            hostname: normalize_host_lossy(hostname),
            record_type: record_type.trim().to_ascii_uppercase(),
        }
    }
}

#[derive(Clone, Debug)]
struct AuthoritativeDnsCacheEntry {
    value: SnAuthoritativeDnsResult,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ManagedDnsZoneKind {
    Web3,
    UserDomain,
}

#[derive(Debug, Clone)]
struct ManagedDnsZone {
    kind: ManagedDnsZoneKind,
    authority: DnsAuthority,
}

pub struct SnResolver {
    config: SnResolverConfig,
    auth: SnAuthReaderRef,
    bns: BnsDocumentReaderRef,
    device_online: DeviceOnlineReaderRef,
    relay_reader: RelayAssignmentReaderRef,
    cache: Arc<SnResolverCache>,
    user_dns_revision: tokio::sync::Mutex<u64>,
}

impl SnResolver {
    pub fn new(config: SnResolverConfig, auth: SnAuthReaderRef) -> Self {
        Self::new_with_bns(config, auth, Arc::new(EmptyBnsDocumentReader))
    }

    pub fn new_with_bns(
        config: SnResolverConfig,
        auth: SnAuthReaderRef,
        bns: BnsDocumentReaderRef,
    ) -> Self {
        Self {
            config,
            auth,
            bns,
            device_online: Arc::new(EmptyDeviceOnlineReader),
            relay_reader: Arc::new(EmptyRelayAssignmentReader),
            cache: Arc::new(SnResolverCache::new()),
            user_dns_revision: tokio::sync::Mutex::new(0),
        }
    }

    pub fn new_ref(config: SnResolverConfig, auth: SnAuthReaderRef) -> SnResolverRef {
        Arc::new(Self::new(config, auth))
    }

    pub fn with_bns_reader(mut self, reader: BnsDocumentReaderRef) -> Self {
        self.bns = reader;
        self
    }

    pub fn with_device_online_reader(mut self, reader: DeviceOnlineReaderRef) -> Self {
        self.device_online = reader;
        self
    }

    pub fn with_relay_reader(mut self, reader: RelayAssignmentReaderRef) -> Self {
        self.relay_reader = reader;
        self
    }

    pub fn cache(&self) -> Arc<SnResolverCache> {
        self.cache.clone()
    }

    pub fn config(&self) -> &SnResolverConfig {
        &self.config
    }

    pub fn parse_record_type(record_type: &str) -> Option<RecordType> {
        match record_type.trim().to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "TXT" => Some(RecordType::TXT),
            _ => None,
        }
    }

    pub fn normalize_hostname(hostname: &str) -> SnResolverResult<String> {
        let name = normalize_host_lossy(hostname);
        if name.is_empty() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                "hostname is empty",
            ));
        }
        if name.len() > 253 || name.contains(char::is_whitespace) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                format!("invalid hostname {}", hostname),
            ));
        }
        if name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                format!("invalid hostname label in {}", hostname),
            ));
        }
        Ok(name)
    }

    pub fn is_self_hostname(&self, hostname: &str) -> bool {
        let hostname = normalize_host_lossy(hostname);
        let sn_full_host = format!("sn.{}", self.config.server_host);
        hostname == sn_full_host
            || hostname == self.config.server_host
            || self.config.aliases.iter().any(|alias| alias == &hostname)
    }

    pub async fn synchronize_user_dns_changes(&self) -> SnResolverResult<u64> {
        let mut cursor = self.user_dns_revision.lock().await;
        loop {
            let page = self.auth.list_user_dns_changes(*cursor, 256).await?;
            if *cursor < page.current_revision
                && cursor.saturating_add(1) < page.earliest_available_revision
            {
                self.cache.clear();
                *cursor = page.current_revision;
                return Ok(*cursor);
            }
            if let Some(first) = page.changes.first() {
                if first.revision > cursor.saturating_add(1) {
                    self.cache.clear();
                    *cursor = page.current_revision;
                    return Ok(*cursor);
                }
            }
            for change in &page.changes {
                self.cache.remove_dns_name(change.name.as_str());
                *cursor = change.revision;
            }
            if *cursor >= page.current_revision || page.changes.is_empty() {
                *cursor = page.current_revision;
                return Ok(*cursor);
            }
        }
    }

    pub fn invalidate_user_dns_name(&self, name: &str) {
        self.cache.remove_dns_name(name);
    }

    pub async fn resolve_authoritative_dns_cached(
        &self,
        hostname: &str,
        record_type: &str,
    ) -> SnResolverResult<SnAuthoritativeDnsResult> {
        let hostname = Self::normalize_hostname(hostname)?;
        let record_type = record_type.trim().to_ascii_uppercase();
        if record_type.is_empty() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedRecordType,
                "record type is empty",
            ));
        }

        self.synchronize_user_dns_changes().await?;
        let bypass_cache = is_user_dns_control_name(hostname.as_str());
        if !bypass_cache {
            if let Some(result) = self
                .cache
                .query_authoritative_dns(hostname.as_str(), record_type.as_str())
            {
                debug!(
                    "sn_resolver authoritative dns cache hit: {} {}",
                    hostname, record_type
                );
                return Ok(result);
            }
        }

        let result = match self
            .resolve_authoritative_dns_uncached(hostname.as_str(), record_type.as_str())
            .await
        {
            Ok(result) => result,
            Err(error) if error.kind() == SnResolverErrorKind::BackendUnavailable => {
                SnAuthoritativeDnsResult::TemporaryFailure {
                    cause: error.to_string(),
                }
            }
            Err(error) => return Err(error),
        };

        let ttl = match &result {
            SnAuthoritativeDnsResult::AuthoritativeAnswer { resolution, .. } => {
                Some(resolution.ttl)
            }
            SnAuthoritativeDnsResult::AuthoritativeNoData { authority }
            | SnAuthoritativeDnsResult::AuthoritativeNxDomain { authority } => {
                Some(authority.soa_minimum)
            }
            SnAuthoritativeDnsResult::NotManaged
            | SnAuthoritativeDnsResult::TemporaryFailure { .. } => None,
        };
        if let Some(ttl) = ttl.filter(|_| !bypass_cache) {
            self.cache.insert_authoritative_dns(
                hostname.as_str(),
                record_type.as_str(),
                result.clone(),
                ttl,
            );
        }
        Ok(result)
    }

    async fn resolve_authoritative_dns_uncached(
        &self,
        hostname: &str,
        record_type: &str,
    ) -> SnResolverResult<SnAuthoritativeDnsResult> {
        let Some(zone) = self.managed_dns_zone(hostname).await? else {
            return Ok(SnAuthoritativeDnsResult::NotManaged);
        };

        let name_exists = self.authoritative_name_exists(hostname, &zone).await?;
        if !name_exists {
            return Ok(SnAuthoritativeDnsResult::AuthoritativeNxDomain {
                authority: zone.authority,
            });
        }

        let Some(record_type) = RecordType::from_str(record_type) else {
            return Ok(SnAuthoritativeDnsResult::AuthoritativeNoData {
                authority: zone.authority,
            });
        };
        if !is_supported_record_type(record_type) {
            return Ok(SnAuthoritativeDnsResult::AuthoritativeNoData {
                authority: zone.authority,
            });
        }

        match self.resolve_dns(hostname, record_type).await {
            Ok(resolution) if dns_resolution_has_rrset(&resolution) => {
                Ok(SnAuthoritativeDnsResult::AuthoritativeAnswer {
                    authority: zone.authority,
                    resolution,
                })
            }
            Ok(_) => Ok(SnAuthoritativeDnsResult::AuthoritativeNoData {
                authority: zone.authority,
            }),
            Err(error)
                if matches!(
                    error.kind(),
                    SnResolverErrorKind::NotManaged
                        | SnResolverErrorKind::NameNotFound
                        | SnResolverErrorKind::DocumentNotFound
                        | SnResolverErrorKind::DeviceNotFound
                        | SnResolverErrorKind::UnsupportedRecordType
                ) =>
            {
                Ok(SnAuthoritativeDnsResult::AuthoritativeNoData {
                    authority: zone.authority,
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn managed_dns_zone(&self, hostname: &str) -> SnResolverResult<Option<ManagedDnsZone>> {
        let web3_zone = format!("web3.{}", self.config.server_host);
        let mut candidates = Vec::new();
        if dns_name_in_zone(hostname, web3_zone.as_str()) {
            candidates.push((web3_zone, ManagedDnsZoneKind::Web3));
        }

        if let Some(user) = self.auth.get_user_by_domain(hostname).await? {
            if matches!(user.state, UserState::Active) {
                if let Some(user_domain) = user.user_domain.as_deref() {
                    let user_domain = normalize_host_lossy(user_domain);
                    if dns_name_in_zone(hostname, user_domain.as_str()) {
                        candidates.push((user_domain, ManagedDnsZoneKind::UserDomain));
                    }
                }
            }
        }

        let Some((zone_apex, kind)) = candidates
            .into_iter()
            .max_by_key(|(zone_apex, _)| zone_apex.split('.').count())
        else {
            return Ok(None);
        };
        Ok(Some(ManagedDnsZone {
            kind,
            authority: self.dns_authority(zone_apex),
        }))
    }

    fn dns_authority(&self, zone_apex: String) -> DnsAuthority {
        DnsAuthority {
            zone_apex,
            primary_ns: format!("dns.{}", self.config.server_host),
            responsible_mailbox: format!("hostmaster.{}", self.config.server_host),
            soa_serial: self.config.soa_serial,
            soa_refresh: self.config.soa_refresh,
            soa_retry: self.config.soa_retry,
            soa_expire: self.config.soa_expire,
            soa_minimum: self.config.soa_minimum,
            positive_ttl: self.config.default_ttl,
        }
    }

    async fn authoritative_name_exists(
        &self,
        hostname: &str,
        zone: &ManagedDnsZone,
    ) -> SnResolverResult<bool> {
        if hostname == zone.authority.zone_apex {
            return Ok(true);
        }

        for record_type in [
            UserDnsRecordType::A,
            UserDnsRecordType::Aaaa,
            UserDnsRecordType::Txt,
        ] {
            if self
                .auth
                .get_user_dns_rrset(hostname, record_type)
                .await?
                .rrset
                .is_some()
            {
                return Ok(true);
            }
        }

        // Control owners such as _acme-challenge exist only while at least one
        // explicit RRset exists. Removing the last TXT therefore restores
        // NXDOMAIN instead of leaving a permanent empty node.
        if hostname
            .split('.')
            .next()
            .map(|label| label.starts_with('_'))
            .unwrap_or(false)
        {
            return Ok(false);
        }

        match zone.kind {
            // Active user_domain bindings retain the existing wildcard gateway
            // model for ordinary descendants.
            ManagedDnsZoneKind::UserDomain => Ok(true),
            ManagedDnsZoneKind::Web3 => {
                let prefix = hostname
                    .strip_suffix(format!(".{}", zone.authority.zone_apex).as_str())
                    .unwrap_or_default();
                let Some(bns_name) = prefix.rsplit('.').next().filter(|name| !name.is_empty())
                else {
                    return Ok(false);
                };
                if self.bns.resolve_owner(bns_name).await?.is_some() {
                    return Ok(true);
                }
                Ok(self
                    .auth
                    .get_user_info(bns_name)
                    .await?
                    .map(|user| matches!(user.state, UserState::Active))
                    .unwrap_or(false))
            }
        }
    }

    pub async fn resolve_dns_cached(
        &self,
        hostname: &str,
        record_type: RecordType,
    ) -> SnResolverResult<DnsResolution> {
        let normalized = Self::normalize_hostname(hostname)?;
        if !is_supported_record_type(record_type) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedRecordType,
                format!("unsupported record type {}", record_type.to_string()),
            ));
        }

        self.synchronize_user_dns_changes().await?;
        let bypass_cache = is_user_dns_control_name(normalized.as_str());
        match (!bypass_cache)
            .then(|| self.cache.query_dns(normalized.as_str(), record_type))
            .flatten()
        {
            Some(DnsCacheValue::Hit(result)) => {
                debug!(
                    "sn_resolver dns cache hit: {} {}",
                    normalized,
                    record_type.to_string()
                );
                return Ok(result);
            }
            Some(DnsCacheValue::Tombstone(kind)) => {
                debug!(
                    "sn_resolver dns tombstone hit: {} {}",
                    normalized,
                    record_type.to_string()
                );
                return Err(SnResolverError::new(
                    kind,
                    format!("no dns result for {}", normalized),
                ));
            }
            None => {}
        }

        match self.resolve_dns(normalized.as_str(), record_type).await {
            Ok(result) => {
                if !bypass_cache {
                    self.cache.insert_dns(
                        normalized.as_str(),
                        record_type,
                        DnsCacheValue::Hit(result.clone()),
                        Some(result.ttl),
                    );
                }
                Ok(result)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    SnResolverErrorKind::NotManaged
                        | SnResolverErrorKind::NameNotFound
                        | SnResolverErrorKind::DocumentNotFound
                        | SnResolverErrorKind::DeviceNotFound
                ) =>
            {
                if !bypass_cache {
                    self.cache.insert_dns(
                        normalized.as_str(),
                        record_type,
                        DnsCacheValue::Tombstone(e.kind()),
                        Some(DEFAULT_SN_RESOLVER_TTL_SECS),
                    );
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn resolve_name_info(
        &self,
        query_name: &str,
        record_type: RecordType,
    ) -> SnResolverResult<NameInfo> {
        self.resolve_dns_cached(query_name, record_type)
            .await
            .map(|resolution| resolution.into_name_info(query_name))
    }

    pub async fn resolve_dns(
        &self,
        hostname: &str,
        record_type: RecordType,
    ) -> SnResolverResult<DnsResolution> {
        let hostname = Self::normalize_hostname(hostname)?;
        if !is_supported_record_type(record_type) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedRecordType,
                format!("unsupported record type {}", record_type.to_string()),
            ));
        }

        if self.is_self_hostname(hostname.as_str()) {
            return self.resolve_self_dns(hostname.as_str(), record_type);
        }

        let user_record_type = match record_type {
            RecordType::A => UserDnsRecordType::A,
            RecordType::AAAA => UserDnsRecordType::Aaaa,
            RecordType::TXT => UserDnsRecordType::Txt,
            _ => unreachable!("supported record type checked above"),
        };
        if let Some(rrset) = self
            .auth
            .get_user_dns_rrset(hostname.as_str(), user_record_type)
            .await?
            .rrset
        {
            return explicit_dns_rrset(hostname.as_str(), record_type, &rrset);
        }

        // Underscore-prefixed TXT names are control records such as ACME and
        // PKX. They only exist when explicitly stored; falling through would
        // either expose the zone's root TXT data or send an invalid BNS name.
        if is_explicit_only_dns_name(hostname.as_str(), record_type) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::DocumentNotFound,
                format!("explicit TXT record not found for {}", hostname),
            ));
        }

        let zone = self.resolve_zone_by_hostname(hostname.as_str()).await?;

        if record_type == RecordType::TXT {
            let mut txt = self.resolve_zone_txt(&zone).await?;
            if txt.is_empty() {
                return Err(SnResolverError::new(
                    SnResolverErrorKind::DocumentNotFound,
                    format!("TXT document not found for {}", hostname),
                ));
            }
            dedup_strings(&mut txt);
            return Ok(DnsResolution {
                hostname,
                record_type,
                ttl: effective_ttl(
                    &[zone.zone_doc.ttl, zone.boot_doc.ttl],
                    self.config.default_ttl,
                ),
                addresses: Vec::new(),
                txt,
                source: DnsResolutionSource::BnsDocument,
            });
        }

        if !zone.zone_doc.gateway_ips.is_empty() {
            let mut addresses = Vec::new();
            for ip in zone.zone_doc.gateway_ips.iter().copied() {
                push_dns_address(&mut addresses, ip, record_type);
            }
            return Ok(DnsResolution {
                hostname,
                record_type,
                ttl: zone.zone_doc.ttl.unwrap_or(self.config.default_ttl),
                addresses,
                txt: Vec::new(),
                source: DnsResolutionSource::BnsDocument,
            });
        }

        let gateway = self
            .resolve_gateway_for_zone(hostname.as_str(), &zone)
            .await?;
        let mut addresses = Vec::new();
        for ip in gateway.addresses.iter().copied() {
            // 设备来源的 IP 已在 resolve_gateway_addresses 内做过 zonegate
            // 过滤；SN 中继回退地址不再过滤（dev-local 下是 127.0.0.1）。
            push_dns_address_unfiltered(&mut addresses, ip, record_type);
        }

        Ok(DnsResolution {
            hostname,
            record_type,
            ttl: self.config.default_ttl,
            addresses,
            txt: Vec::new(),
            source: DnsResolutionSource::DeviceOnlineInfo,
        })
    }

    pub async fn resolve_gateway_by_hostname(
        &self,
        hostname: &str,
    ) -> SnResolverResult<GatewayResolution> {
        let hostname = Self::normalize_hostname(hostname)?;
        let zone = self.resolve_zone_by_hostname(hostname.as_str()).await?;
        self.resolve_gateway_for_zone(hostname.as_str(), &zone)
            .await
    }

    pub async fn resolve_zone_by_hostname(
        &self,
        hostname: &str,
    ) -> SnResolverResult<ZoneResolution> {
        let hostname = Self::normalize_hostname(hostname)?;

        if let Some(owner) = self.bns.resolve_owner(hostname.as_str()).await? {
            return self
                .resolve_zone_by_bns_owner(
                    hostname.as_str(),
                    hostname.as_str(),
                    owner,
                    false,
                    ZoneResolutionSource::BnsName,
                    None,
                    None,
                )
                .await;
        }

        if let Some(user) = self.auth.get_user_by_domain(hostname.as_str()).await? {
            let username = user.username.clone().ok_or_else(|| {
                SnResolverError::not_found(format!("user_domain {} has no username", hostname))
            })?;
            return self
                .resolve_zone_by_user(
                    hostname.as_str(),
                    username.as_str(),
                    user,
                    ZoneResolutionSource::UserDomain,
                )
                .await;
        }

        if !hostname.contains('.') {
            return self
                .resolve_zone_by_bns_name(
                    hostname.as_str(),
                    hostname.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await;
        }

        // BNS 兼容域名（SN-Resolver.md "BNS 兼容域名"）：
        //   alice.web3.<server_host>       -> BNS name alice
        //   home.alice.web3.<server_host>  -> BNS name alice（sub_host 只作
        //   relay 上下文，不决定 owner，这里取 web3 前缀的末级 label）。
        // 旧 URL 的 `www-alice` 连字符规则不在此实现（用户名可含 '-'，
        // 会误切；需要时由显式 dns record 覆盖）。
        if let Some(bns_name) = self.bns_compat_name_of(hostname.as_str()) {
            return self
                .resolve_zone_by_bns_name(
                    bns_name.as_str(),
                    hostname.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await;
        }

        Err(SnResolverError::new(
            SnResolverErrorKind::NotManaged,
            format!("hostname {} is not managed by this SN", hostname),
        ))
    }

    /// `<...>.<name>.web3.<server_host>` -> `<name>`；不匹配返回 None。
    fn bns_compat_name_of(&self, hostname: &str) -> Option<String> {
        bns_compat_name_for(self.config.server_host.as_str(), hostname)
    }

    pub async fn resolve_zone_by_bns_name(
        &self,
        bns_name: &str,
        input: &str,
        source: ZoneResolutionSource,
        user_domain: Option<String>,
    ) -> SnResolverResult<ZoneResolution> {
        let canonical_name = normalize_bns_name(bns_name)?;
        let bns_owner = self.bns.resolve_owner(canonical_name.as_str()).await?;
        let owner_from_auth_db = bns_owner.is_none();
        let user = self.auth.get_user_info(canonical_name.as_str()).await?;

        if bns_owner.is_none() && user.is_none() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NameNotFound,
                format!("BNS name {} not found", canonical_name),
            ));
        }

        let owner =
            bns_owner.unwrap_or_else(|| legacy_owner(canonical_name.as_str(), user.as_ref()));
        self.resolve_zone_by_bns_owner(
            input,
            canonical_name.as_str(),
            owner,
            owner_from_auth_db,
            source,
            user,
            user_domain,
        )
        .await
    }

    pub async fn resolve_relay_for_zone(
        &self,
        zone_name: &str,
    ) -> SnResolverResult<RelayResolution> {
        let zone_name = normalize_bns_name(zone_name)?;
        if let Some(assignment) = self.relay_reader.get_zone_relay(zone_name.as_str()).await? {
            return Ok(relay_resolution_from_assignment(
                zone_name.as_str(),
                assignment,
            ));
        }

        if let Some(zone_info) = self.auth.get_zone_info(zone_name.as_str()).await? {
            if let Some(relay_sn) = zone_info.relay_sn {
                if !relay_sn.trim().is_empty() {
                    return Ok(RelayResolution {
                        zone_name,
                        relay_sn,
                        relay_state: RelayState::Unknown,
                        migration_hint: None,
                    });
                }
            }
        }

        Ok(RelayResolution {
            zone_name,
            relay_sn: UNASSIGNED_RELAY_SN.to_string(),
            relay_state: RelayState::Unknown,
            migration_hint: None,
        })
    }

    pub async fn resolve_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = normalize_doc_type(doc_type);
        match did.method.as_str() {
            "web" => self.resolve_web_did(did, doc_type.as_deref()).await,
            "bns" => self.resolve_bns_did(did, doc_type.as_deref()).await,
            "dev" => self.resolve_dev_did(did, doc_type.as_deref()).await,
            other => Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedDidMethod,
                format!("unsupported did method {}", other),
            )),
        }
    }

    async fn resolve_zone_by_user(
        &self,
        input: &str,
        username: &str,
        user: SNUserInfo,
        source: ZoneResolutionSource,
    ) -> SnResolverResult<ZoneResolution> {
        let bns_owner = self.bns.resolve_owner(username).await?;
        let owner_from_auth_db = bns_owner.is_none();
        let owner = bns_owner.unwrap_or_else(|| legacy_owner(username, Some(&user)));
        let user_domain = user.user_domain.clone();

        self.resolve_zone_by_bns_owner(
            input,
            username,
            owner,
            owner_from_auth_db,
            source,
            Some(user),
            user_domain,
        )
        .await
    }

    async fn resolve_zone_by_bns_owner(
        &self,
        input: &str,
        zone_name: &str,
        owner: BnsOwner,
        owner_from_auth_db: bool,
        source: ZoneResolutionSource,
        user: Option<SNUserInfo>,
        user_domain: Option<String>,
    ) -> SnResolverResult<ZoneResolution> {
        let zone_doc = self
            .bns
            .get_document(zone_name, BNS_DOC_ZONE)
            .await?
            .as_ref()
            .map(ZoneDocument::from_bns_document)
            .unwrap_or_else(ZoneDocument::empty);

        let boot_doc =
            if let Some(document) = self.bns.get_document(zone_name, BNS_DOC_BOOT).await? {
                BootDocument::from_bns_document(&document)
            } else if let Some(boot_jwt) = zone_doc.boot_jwt.as_deref() {
                BootDocument::from_legacy_boot_jwt(boot_jwt)
            } else if let Some(user) = user.as_ref() {
                if user.zone_config.trim().is_empty() {
                    BootDocument::empty()
                } else {
                    BootDocument::from_legacy_boot_jwt(user.zone_config.as_str())
                }
            } else {
                BootDocument::empty()
            };

        let zone_info = self.auth.get_zone_info(zone_name).await?;
        let self_cert = zone_info
            .as_ref()
            .map(|info| info.self_cert)
            .or_else(|| user.as_ref().map(|u| u.self_cert))
            .unwrap_or(false);

        let relay_sn = self
            .relay_reader
            .get_zone_relay(zone_name)
            .await?
            .map(|assignment| assignment.relay_sn)
            .or_else(|| zone_info.and_then(|info| info.relay_sn));

        Ok(ZoneResolution {
            input: input.to_string(),
            canonical_name: zone_name.to_string(),
            zone_name: zone_name.to_string(),
            owner,
            owner_from_auth_db,
            zone_doc,
            boot_doc,
            user_domain,
            self_cert,
            relay_sn,
            source,
        })
    }

    async fn resolve_gateway_for_zone(
        &self,
        hostname: &str,
        zone: &ZoneResolution,
    ) -> SnResolverResult<GatewayResolution> {
        let gateway_device_name = zone
            .zone_doc
            .gateway_device_name
            .as_deref()
            .or(zone.boot_doc.gateway_device_name.as_deref())
            .unwrap_or(self.config.legacy_gateway_device_name.as_str())
            .to_string();

        let device_doc = self
            .resolve_device_mini_doc(
                zone.zone_name.as_str(),
                gateway_device_name.as_str(),
                Some(&zone.zone_doc),
            )
            .await?;

        let online = self
            .device_online
            .get_device_state_by_name(zone.zone_name.as_str(), gateway_device_name.as_str())
            .await?;

        let addresses = self
            .resolve_gateway_addresses(zone, &device_doc, online.as_ref())
            .await?;

        Ok(GatewayResolution {
            zone_name: zone.zone_name.clone(),
            hostname: hostname.to_string(),
            gateway_device_name,
            gateway_did: device_doc.did.clone(),
            device_doc,
            online,
            addresses,
            relay_sn: zone.relay_sn.clone(),
            self_cert: zone.self_cert,
        })
    }

    /// 按 (zone, device_name) 解析 zone 权威侧登记的设备身份文档，返回其中的
    /// 设备 DID（通常是 `did:dev:<x>`，公钥内嵌）。来源优先级与内部设备解析
    /// 一致：BNS `<device>.<zone>` 的 `device_mini_doc` 单文档 → zone 级
    /// `device_mini_doc` 聚合 → ZoneDocument `mini_device_jwts`。`sn_authority` 用它锚定设备
    /// token 的公钥，不存在时返回 `DeviceNotFound`。
    pub async fn resolve_zone_device_did(
        &self,
        zone_name: &str,
        device_name: &str,
    ) -> SnResolverResult<String> {
        let device_doc = self
            .resolve_device_mini_doc(zone_name, device_name, None)
            .await?;
        Ok(device_doc.did)
    }

    async fn resolve_device_document(
        &self,
        zone_name: &str,
        device_name: &str,
    ) -> SnResolverResult<EncodedDocument> {
        let document = self
            .bns
            .get_document(zone_name, device_name)
            .await?
            .ok_or_else(|| {
                SnResolverError::new(
                    SnResolverErrorKind::DocumentNotFound,
                    format!("BNS DeviceDocument {}/{} not found", zone_name, device_name),
                )
            })?;
        let jwt = document.content.as_jwt().ok_or_else(|| {
            SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                format!(
                    "BNS DeviceDocument {}/{} must be a compact JWT",
                    zone_name, device_name
                ),
            )
        })?;
        Ok(EncodedDocument::Jwt(jwt))
    }

    async fn resolve_device_mini_doc(
        &self,
        zone_name: &str,
        device_name: &str,
        zone_doc: Option<&ZoneDocument>,
    ) -> SnResolverResult<DeviceMiniDocument> {
        let child_name = format!("{}.{}", device_name, zone_name);
        if let Some(document) = self
            .bns
            .get_document(child_name.as_str(), BNS_DOC_DEVICE_MINI)
            .await?
        {
            if let Some(device_doc) =
                device_doc_from_single(zone_name, device_name, &document, Some(child_name.as_str()))
            {
                return Ok(device_doc);
            }
        }

        if let Some(document) = self
            .bns
            .get_document(zone_name, BNS_DOC_DEVICE_MINI)
            .await?
        {
            if let Some(device_doc) =
                device_mini_doc_from_aggregate(zone_name, device_name, &document)
            {
                return Ok(device_doc);
            }
        }

        if let Some(zone_doc) = zone_doc {
            if let Some(device_doc) = device_doc_from_mini_jwt_map(
                zone_name,
                device_name,
                &zone_doc.mini_device_jwts,
                zone_doc.ttl,
                zone_doc.version,
            ) {
                return Ok(device_doc);
            }
        } else if let Some(document) = self.bns.get_document(zone_name, BNS_DOC_ZONE).await? {
            let zone_doc = ZoneDocument::from_bns_document(&document);
            if let Some(device_doc) = device_doc_from_mini_jwt_map(
                zone_name,
                device_name,
                &zone_doc.mini_device_jwts,
                zone_doc.ttl,
                zone_doc.version,
            ) {
                return Ok(device_doc);
            }
        }

        Err(SnResolverError::new(
            SnResolverErrorKind::DeviceNotFound,
            format!(
                "BNS device document {}.{} not found",
                device_name, zone_name
            ),
        ))
    }

    async fn resolve_gateway_addresses(
        &self,
        zone: &ZoneResolution,
        device_doc: &DeviceMiniDocument,
        online: Option<&SnDeviceStateView>,
    ) -> SnResolverResult<Vec<IpAddr>> {
        let mut addresses = Vec::new();

        for ip in zone.zone_doc.gateway_ips.iter().copied() {
            push_exportable_ip(&mut addresses, ip);
        }

        // `net_id` is owner-signed topology information. Prefer it over the
        // online-state heuristic because a LAN/NAT device may report a global
        // address which is useful to local clients but is not a public gateway
        // address. Such zones must still publish their assigned relay IPs.
        let requires_relay = device_document_requires_sn_relay(device_doc)
            .or_else(|| online.map(|online| !online.is_wan_device))
            .unwrap_or(false);

        if let Some(online) = online {
            for value in online
                .public_ips
                .iter()
                .chain(online.private_ips.iter())
                .map(|s| s.as_str())
            {
                if let Some(ip) = parse_ip_or_socket_addr(value) {
                    push_exportable_ip(&mut addresses, ip);
                }
            }

            for endpoint in &online.active_endpoints {
                if let Some(ip) = parse_ip_or_socket_addr(endpoint.host.as_str()) {
                    push_exportable_ip(&mut addresses, ip);
                }
            }
        }

        if let Some(value) = device_doc.document.as_ref() {
            for key in ["ip", "ips", "all_ip", "addresses"] {
                collect_ips_from_value_path(value, &[key], &mut addresses);
            }
        }

        // Relay is required for LAN/NAT zones even when local/direct addresses
        // were collected above. It also remains the last-resort route for any
        // zone without a usable direct address.
        if requires_relay || addresses.is_empty() {
            let assignment = self
                .relay_reader
                .get_zone_relay(zone.zone_name.as_str())
                .await?
                .ok_or_else(|| {
                    SnResolverError::backend(format!(
                        "relay assignment is missing for {}",
                        zone.zone_name
                    ))
                })?;
            if assignment.state == RelayAssignmentState::Suspended {
                return Err(SnResolverError::backend(format!(
                    "relay assignment for {} is suspended",
                    zone.zone_name
                )));
            }
            let relay_ips = self
                .relay_reader
                .get_relay_node_ips(assignment.relay_id.as_str())
                .await?
                .ok_or_else(|| {
                    SnResolverError::backend(format!(
                        "relay assignment for {} points to unknown node {}",
                        zone.zone_name, assignment.relay_id
                    ))
                })?;
            for ip in relay_ips {
                if !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
        }

        Ok(addresses)
    }

    async fn resolve_zone_txt(&self, zone: &ZoneResolution) -> SnResolverResult<Vec<String>> {
        let mut txt = Vec::new();

        let legacy_user = self.auth.get_user_info(zone.zone_name.as_str()).await?;
        if let Some(x) = owner_pkx_from_owner_config(&zone.owner).or_else(|| {
            legacy_user
                .as_ref()
                .and_then(|user| pkx_from_public_key(user.public_key.as_str()))
        }) {
            txt.push(format!("PKX={};", x));
        }

        if let Some(jwt) = zone.boot_doc.jwt.as_ref() {
            txt.push(format!("BOOT={};", jwt));
        } else if let Some(raw) = zone.boot_doc.raw.as_ref() {
            txt.push(format!("BOOT={};", raw));
        }

        let mut device_jwt_source_found = false;
        if let Some(document) = self
            .bns
            .get_document(zone.zone_name.as_str(), BNS_DOC_DEVICE_MINI)
            .await?
        {
            device_jwt_source_found = true;
            for jwt in device_jwts_from_bns_document(&document) {
                txt.push(format!("DEV={};", jwt));
            }
        } else if !zone.zone_doc.mini_device_jwts.is_empty() {
            device_jwt_source_found = true;
            for jwt in zone.zone_doc.mini_device_jwts.values() {
                txt.push(format!("DEV={};", jwt));
            }
        }

        let _ = device_jwt_source_found;

        if let Some(dns_txt_doc) = self
            .bns
            .get_document(zone.zone_name.as_str(), BNS_DOC_DNS_TXT)
            .await?
        {
            txt.extend(txt_records_from_bns_document(&dns_txt_doc));
        }

        Ok(txt)
    }

    fn resolve_self_dns(
        &self,
        hostname: &str,
        record_type: RecordType,
    ) -> SnResolverResult<DnsResolution> {
        Ok(match record_type {
            RecordType::A | RecordType::AAAA => {
                let mut addresses = Vec::new();
                push_dns_address(&mut addresses, self.server_ip()?, record_type);
                DnsResolution {
                    hostname: hostname.to_string(),
                    record_type,
                    ttl: self.config.default_ttl,
                    addresses,
                    txt: Vec::new(),
                    source: DnsResolutionSource::SnSelf,
                }
            }
            RecordType::TXT => {
                let mut txt = Vec::new();
                if let Some(owner_pkx) = self.config.owner_pkx.as_deref() {
                    if let Some(x) = pkx_from_public_key(owner_pkx) {
                        txt.push(format!("PKX={};", x));
                    } else {
                        txt.push(format!("PKX={};", owner_pkx));
                    }
                }
                if let Some(boot_jwt) = self.config.boot_jwt.as_deref() {
                    txt.push(format!("BOOT={};", boot_jwt));
                }
                for jwt in &self.config.device_jwts {
                    txt.push(format!("DEV={};", jwt));
                }
                DnsResolution {
                    hostname: hostname.to_string(),
                    record_type,
                    ttl: self.config.default_ttl,
                    addresses: Vec::new(),
                    txt,
                    source: DnsResolutionSource::SnSelf,
                }
            }
            _ => DnsResolution {
                hostname: hostname.to_string(),
                record_type,
                ttl: self.config.default_ttl,
                addresses: Vec::new(),
                txt: Vec::new(),
                source: DnsResolutionSource::SnSelf,
            },
        })
    }

    fn server_ip(&self) -> SnResolverResult<IpAddr> {
        self.config
            .server_ip
            .ok_or_else(|| SnResolverError::backend(SN_SERVER_IP_NOT_CONFIGURED))
    }

    async fn resolve_web_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = normalize_host_lossy(did.id.as_str());
        let user = self.auth.get_user_by_domain(id.as_str()).await?;
        let Some(user) = user else {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NameNotFound,
                format!("user_domain {} not found", id),
            ));
        };

        let username = user.username.clone().ok_or_else(|| {
            SnResolverError::not_found(format!("user_domain {} has no username", id))
        })?;

        if let Some(domain) = user.user_domain.as_deref() {
            let domain = normalize_host_lossy(domain);
            if id != domain {
                let suffix = format!(".{}", domain);
                if let Some(device_name) = id.strip_suffix(suffix.as_str()) {
                    let mapped =
                        DID::from_str(format!("did:bns:{}.{}", device_name, username).as_str())
                            .map_err(|e| {
                                SnResolverError::new(
                                    SnResolverErrorKind::InvalidDid,
                                    format!("invalid mapped bns did: {}", e),
                                )
                            })?;
                    return self.resolve_bns_did(&mapped, doc_type).await;
                }
            }
        }

        let mapped = DID::from_str(format!("did:bns:{}", username).as_str()).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                format!("invalid mapped bns did: {}", e),
            )
        })?;
        self.resolve_bns_did(&mapped, doc_type).await
    }

    async fn resolve_bns_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = did.id.as_str();
        if let Some((obj_name, tail)) = id.split_once('.') {
            let zone_name = if tail.contains('.') {
                self.auth
                    .get_user_by_domain(tail)
                    .await?
                    .and_then(|user| user.username)
                    .ok_or_else(|| {
                        SnResolverError::new(
                            SnResolverErrorKind::NameNotFound,
                            format!("user_domain {} not found", tail),
                        )
                    })?
            } else {
                tail.to_string()
            };

            let doc_type = doc_type.unwrap_or("doc");
            return self
                .resolve_bns_object_doc(did, zone_name.as_str(), obj_name, doc_type)
                .await;
        }

        let zone_name = normalize_bns_name(id)?;
        let doc_type = doc_type.unwrap_or(BNS_DOC_ZONE);
        if let Some(document) = self.bns.get_document(zone_name.as_str(), doc_type).await? {
            return Ok(did_response(
                did,
                doc_type,
                document.content.to_encoded_document(),
                SnDidDocumentSource::BnsDocument,
            ));
        }

        match doc_type {
            BNS_DOC_ZONE | BNS_DOC_BOOT => {
                let user = self.auth.get_user_info(zone_name.as_str()).await?;
                if let Some(user) = user {
                    let document = if doc_type == BNS_DOC_ZONE {
                        build_auth_db_zone_projection(zone_name.as_str(), &user)
                    } else {
                        json!({ "boot": user.zone_config })
                    };
                    return Ok(did_response(
                        did,
                        doc_type,
                        EncodedDocument::JsonLd(document),
                        SnDidDocumentSource::AuthDbProjection,
                    ));
                }

                let kind = if self.bns.resolve_owner(zone_name.as_str()).await?.is_some() {
                    SnResolverErrorKind::DocumentNotFound
                } else {
                    SnResolverErrorKind::NameNotFound
                };
                Err(SnResolverError::new(
                    kind,
                    format!("BNS document {}/{} not found", zone_name, doc_type),
                ))
            }
            device_name => Err(SnResolverError::new(
                SnResolverErrorKind::DocumentNotFound,
                format!(
                    "BNS device document {}/{} not found",
                    zone_name, device_name
                ),
            )),
        }
    }

    async fn resolve_bns_object_doc(
        &self,
        did: &DID,
        zone_name: &str,
        obj_name: &str,
        doc_type: &str,
    ) -> SnResolverResult<SnDidResolveResponse> {
        match doc_type {
            "doc" | "device" => {
                let document = self.resolve_device_document(zone_name, obj_name).await?;
                Ok(did_response(
                    did,
                    doc_type,
                    document,
                    SnDidDocumentSource::BnsDocument,
                ))
            }
            BNS_DOC_DEVICE_MINI => {
                let device_doc = self
                    .resolve_device_mini_doc(zone_name, obj_name, None)
                    .await?;
                Ok(did_response(
                    did,
                    doc_type,
                    EncodedDocument::JsonLd(device_document(device_doc)),
                    SnDidDocumentSource::DeviceMiniDocument,
                ))
            }
            "info" => {
                if let Some(online) = self
                    .device_online
                    .get_device_state_by_name(zone_name, obj_name)
                    .await?
                {
                    return Ok(did_response(
                        did,
                        doc_type,
                        EncodedDocument::JsonLd(device_online_info_document(&online)),
                        SnDidDocumentSource::DeviceOnlineInfo,
                    ));
                }

                Err(SnResolverError::new(
                    SnResolverErrorKind::DeviceNotFound,
                    format!("online device {}.{} not found", obj_name, zone_name),
                ))
            }
            other => {
                let child_name = format!("{}.{}", obj_name, zone_name);
                if let Some(document) = self.bns.get_document(child_name.as_str(), other).await? {
                    return Ok(did_response(
                        did,
                        other,
                        document.content.to_encoded_document(),
                        SnDidDocumentSource::BnsDocument,
                    ));
                }
                Err(SnResolverError::new(
                    SnResolverErrorKind::DocumentNotFound,
                    format!("BNS document {}/{} not found", child_name, other),
                ))
            }
        }
    }

    async fn resolve_dev_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = doc_type.unwrap_or("doc");
        let did_str = did.to_string();
        let online = self
            .device_online
            .get_device_state(did_str.as_str())
            .await?;
        match (doc_type, online) {
            ("info", Some(online)) => Ok(did_response_str(
                did_str,
                doc_type,
                EncodedDocument::JsonLd(device_online_info_document(&online)),
                SnDidDocumentSource::DeviceOnlineInfo,
            )),
            ("doc", Some(online)) => {
                let device_doc = self
                    .resolve_device_mini_doc(
                        online.zone.as_str(),
                        online.device_name.as_str(),
                        None,
                    )
                    .await?;
                Ok(did_response_str(
                    did_str,
                    doc_type,
                    EncodedDocument::JsonLd(device_document(device_doc)),
                    SnDidDocumentSource::DeviceMiniDocument,
                ))
            }
            ("doc" | "info", None) => Err(SnResolverError::new(
                SnResolverErrorKind::DeviceNotFound,
                format!("online device {} not found", did_str),
            )),
            (other, _) => Err(SnResolverError::new(
                SnResolverErrorKind::DocumentNotFound,
                format!("unsupported doc_type {} for {}", other, did_str),
            )),
        }
    }
}

fn did_response(
    did: &DID,
    doc_type: impl Into<String>,
    document: EncodedDocument,
    source: SnDidDocumentSource,
) -> SnDidResolveResponse {
    did_response_str(did.to_string(), doc_type, document, source)
}

fn did_response_str(
    did: impl Into<String>,
    doc_type: impl Into<String>,
    document: EncodedDocument,
    source: SnDidDocumentSource,
) -> SnDidResolveResponse {
    SnDidResolveResponse {
        did: did.into(),
        doc_type: doc_type.into(),
        document,
        source,
        profile: SnDidResolverProfile::PublicSupplement,
        document_status: None,
        metadata: Value::Null,
    }
}

impl DnsResolution {
    pub fn into_name_info(self, query_name: &str) -> NameInfo {
        let mut name_info = NameInfo::new(query_name);
        name_info.ttl = Some(self.ttl);
        name_info.address = self.addresses;
        name_info.txt = self.txt;
        name_info
    }
}

fn is_supported_record_type(record_type: RecordType) -> bool {
    matches!(
        record_type,
        RecordType::A | RecordType::AAAA | RecordType::TXT
    )
}

fn dns_resolution_has_rrset(resolution: &DnsResolution) -> bool {
    match resolution.record_type {
        RecordType::A | RecordType::AAAA => !resolution.addresses.is_empty(),
        RecordType::TXT => !resolution.txt.is_empty(),
        _ => false,
    }
}

fn dns_name_in_zone(hostname: &str, zone_apex: &str) -> bool {
    hostname == zone_apex
        || hostname
            .strip_suffix(zone_apex)
            .map(|prefix| prefix.ends_with('.') && prefix.len() > 1)
            .unwrap_or(false)
}

fn is_explicit_only_dns_name(hostname: &str, record_type: RecordType) -> bool {
    record_type == RecordType::TXT
        && matches!(hostname.split('.').next(), Some(label) if label.starts_with('_'))
}

fn normalize_host_lossy(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_bns_name(name: &str) -> SnResolverResult<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    canonical_bns_name(name.as_str()).map_err(|_| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidHostname,
            format!("invalid BNS name {}", name),
        )
    })
}

fn normalize_doc_type(doc_type: Option<&str>) -> Option<String> {
    doc_type.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn legacy_owner(name: &str, user: Option<&SNUserInfo>) -> BnsOwner {
    BnsOwner {
        name: name.to_string(),
        effective_owner: user
            .and_then(|user| pkx_from_public_key(user.public_key.as_str()))
            .or_else(|| user.map(|user| user.public_key.clone())),
        owner_config: None,
    }
}

fn parse_sn_ips(sn_ips: Option<&str>, username: &str) -> Vec<IpAddr> {
    sn_ips
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|e| warn!("invalid sn_ip {} for {}: {}", value, username, e))
                .ok()
        })
        .collect()
}

fn relay_resolution_from_assignment(
    zone_name: &str,
    assignment: RelayAssignment,
) -> RelayResolution {
    let relay_state = match assignment.state {
        RelayAssignmentState::Active => RelayState::Healthy,
        RelayAssignmentState::Migrating | RelayAssignmentState::Draining => RelayState::Draining,
        RelayAssignmentState::Suspended => RelayState::Offline,
    };

    let migration_hint = if assignment.migrated_from.is_some()
        || assignment.migration_deadline.is_some()
        || assignment.state == RelayAssignmentState::Migrating
    {
        Some(RelayMigrationHint {
            migrated_from: assignment.migrated_from,
            migration_deadline: assignment.migration_deadline,
            generation: Some(assignment.generation),
        })
    } else {
        None
    };

    RelayResolution {
        zone_name: zone_name.to_string(),
        relay_sn: assignment.relay_sn,
        relay_state,
        migration_hint,
    }
}

fn effective_ttl(values: &[Option<u32>], default_ttl: u32) -> u32 {
    values
        .iter()
        .filter_map(|ttl| *ttl)
        .min()
        .unwrap_or(default_ttl)
}

fn explicit_dns_rrset(
    hostname: &str,
    record_type: RecordType,
    rrset: &UserDnsRrset,
) -> SnResolverResult<DnsResolution> {
    match record_type {
        RecordType::TXT => Ok(DnsResolution {
            hostname: hostname.to_string(),
            record_type,
            ttl: rrset.ttl,
            addresses: Vec::new(),
            txt: rrset.values.clone(),
            source: DnsResolutionSource::ExplicitRecord,
        }),
        RecordType::A | RecordType::AAAA => {
            let mut addresses = Vec::new();
            for value in &rrset.values {
                if let Some(ip) = parse_ip_or_socket_addr(value.as_str()) {
                    push_dns_address_unfiltered(&mut addresses, ip, record_type);
                }
            }
            Ok(DnsResolution {
                hostname: hostname.to_string(),
                record_type,
                ttl: rrset.ttl,
                addresses,
                txt: Vec::new(),
                source: DnsResolutionSource::ExplicitRecord,
            })
        }
        _ => Err(SnResolverError::new(
            SnResolverErrorKind::UnsupportedRecordType,
            format!("unsupported record type {}", record_type.to_string()),
        )),
    }
}

pub fn is_user_dns_control_name(name: &str) -> bool {
    matches!(
        normalize_host_lossy(name).split('.').next(),
        Some("_acme-challenge" | "_pkx")
    )
}

fn owner_pkx_from_owner_config(owner: &BnsOwner) -> Option<String> {
    let from_complete_document = owner
        .owner_config
        .as_ref()
        .and_then(owner_key_from_config)
        .and_then(|jwk| ed25519_jwk_x(&jwk));
    let from_legacy_config = owner
        .owner_config
        .as_ref()
        .and_then(|value| {
            find_string_path(value, &["public_key", "x"])
                .or_else(|| find_string_path(value, &["owner_key", "x"]))
                .or_else(|| find_string_path(value, &["default_key", "x"]))
                .or_else(|| find_string_path(value, &["x"]))
        })
        .and_then(|value| key_like_string_to_jwk(value.as_str()))
        .and_then(|jwk| ed25519_jwk_x(&jwk));
    let from_effective_owner = owner
        .effective_owner
        .as_deref()
        .and_then(key_like_string_to_jwk)
        .and_then(|jwk| ed25519_jwk_x(&jwk));

    from_complete_document
        .or(from_legacy_config)
        .or(from_effective_owner)
}

fn ed25519_jwk_x(jwk: &Jwk) -> Option<String> {
    DecodingKey::from_jwk(jwk).ok()?;
    match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(params) => Some(params.x.clone()),
        _ => None,
    }
}

fn pkx_from_public_key(public_key: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(public_key).ok()?;
    find_string_path(&value, &["x"])
}

fn device_document(device_doc: DeviceMiniDocument) -> Value {
    device_doc.document.unwrap_or_else(|| {
        json!({
            "id": device_doc.did,
            "name": device_doc.device_name,
            "zone": device_doc.zone_name,
            "mini_config_jwt": device_doc.mini_config_jwt,
        })
    })
}

fn device_online_info_document(online: &SnDeviceStateView) -> Value {
    let mut value = serde_json::to_value(online).unwrap_or_else(|_| json!({}));
    if let Some(obj) = value.as_object_mut() {
        obj.entry("owner".to_string())
            .or_insert_with(|| Value::String(online.zone.clone()));
        obj.entry("zone_name".to_string())
            .or_insert_with(|| Value::String(online.zone.clone()));

        let exportable_ips: Vec<Value> = online
            .public_ips
            .iter()
            .chain(online.private_ips.iter())
            .cloned()
            .map(Value::String)
            .collect();

        if let Some(first_ip) = exportable_ips.first().cloned() {
            obj.entry("ip".to_string()).or_insert(first_ip);
        }
        obj.entry("ips".to_string())
            .or_insert_with(|| Value::Array(exportable_ips.clone()));
        obj.entry("all_ip".to_string())
            .or_insert_with(|| Value::Array(exportable_ips));
    }

    value
}

fn find_gateway_device_name(value: &Value) -> Option<String> {
    for path in [
        &["gateway_device_name"][..],
        &["gateway_device"][..],
        &["default_gateway"][..],
        &["gateway", "device_name"][..],
        &["gateway", "name"][..],
        &["gateway", "device"][..],
        &["boot", "gateway_device_name"][..],
    ] {
        if let Some(name) = find_string_path(value, path) {
            return Some(name);
        }
    }

    for path in [&["gateway_devices"][..], &["oods"][..]] {
        if let Some(array) = find_array_path(value, path) {
            for item in array {
                if let Some(name) = item.as_str() {
                    return Some(short_device_name(name));
                }
                if let Some(name) = find_string_path(item, &["device_name"])
                    .or_else(|| find_string_path(item, &["name"]))
                {
                    return Some(short_device_name(name.as_str()));
                }
            }
        }
    }

    None
}

fn find_boot_jwt(value: &Value) -> Option<String> {
    // Shared with the SN controller's write side so the embedded boot_jwt is read
    // back through the exact same locations it was written through.
    bns_client::dns_document::extract_boot_jwt(value)
}

fn find_device_map(value: &Value) -> HashMap<String, Value> {
    value
        .get("devices")
        .and_then(Value::as_object)
        .map(|devices| {
            devices
                .iter()
                .map(|(name, device)| (name.clone(), device.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn find_mini_device_jwts(value: &Value) -> HashMap<String, String> {
    value
        .get("mini_device_jwts")
        .and_then(Value::as_object)
        .map(|jwts| {
            jwts.iter()
                .filter_map(|(name, jwt)| jwt.as_str().map(|jwt| (name.clone(), jwt.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn short_device_name(value: &str) -> String {
    value.split('.').next().unwrap_or(value).to_string()
}

fn find_gateway_ips(value: &Value) -> Vec<IpAddr> {
    let mut result = Vec::new();
    for path in [
        &["gateway_ips"][..],
        &["gateway", "ips"][..],
        &["gateway", "addresses"][..],
        &["addresses"][..],
    ] {
        collect_ips_from_value_path(value, path, &mut result);
    }
    result
}

fn find_ttl(value: &Value) -> Option<u32> {
    value
        .get("ttl")
        .and_then(|ttl| ttl.as_u64())
        .and_then(|ttl| u32::try_from(ttl).ok())
}

fn find_string_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn find_array_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Vec<Value>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_array()
}

fn collect_ips_from_value_path(value: &Value, path: &[&str], result: &mut Vec<IpAddr>) {
    let mut current = value;
    for key in path {
        let Some(next) = current.get(*key) else {
            return;
        };
        current = next;
    }

    if let Some(value) = current.as_str() {
        if let Some(ip) = parse_ip_or_socket_addr(value) {
            push_exportable_ip(result, ip);
        }
        return;
    }

    if let Some(values) = current.as_array() {
        for value in values {
            if let Some(value) = value.as_str() {
                if let Some(ip) = parse_ip_or_socket_addr(value) {
                    push_exportable_ip(result, ip);
                }
            }
        }
    }
}

fn device_jwts_from_bns_document(document: &BnsDocument) -> Vec<String> {
    let mut result = Vec::new();
    let Some(value) = document.content.to_json_value() else {
        if document.doc_type == BNS_DOC_DEVICE_MINI {
            if let Some(jwt) = document.content.as_jwt() {
                result.push(jwt);
            }
        }
        return result;
    };

    if document.doc_type == BNS_DOC_DEVICE_MINI {
        if let Some(devices) = value.get("devices").and_then(|v| v.as_object()) {
            for device in devices.values() {
                if let Some(jwt) = find_string_path(device, &["mini_config_jwt"]) {
                    result.push(jwt);
                }
            }
        }
    }

    if let Some(mini_device_jwts) = value.get("mini_device_jwts").and_then(Value::as_object) {
        result.extend(
            mini_device_jwts
                .values()
                .filter_map(Value::as_str)
                .map(ToString::to_string),
        );
    }

    if let Some(jwt) = find_string_path(&value, &["mini_config_jwt"]) {
        result.push(jwt);
    }

    result
}

fn txt_records_from_bns_document(document: &BnsDocument) -> Vec<String> {
    let Some(value) = document.content.to_json_value() else {
        return document
            .content
            .as_jwt()
            .map(|text| vec![text])
            .unwrap_or_default();
    };

    let mut result = Vec::new();
    if let Some(records) = value.as_array() {
        for record in records {
            if let Some(txt) = record.as_str() {
                result.push(txt.to_string());
            } else if let Some(txt) = record.get("value").and_then(|v| v.as_str()) {
                result.push(txt.to_string());
            } else if let Some(values) = record.get("values").and_then(|v| v.as_array()) {
                for value in values.iter().filter_map(|v| v.as_str()) {
                    result.push(value.to_string());
                }
            }
        }
    } else if let Some(records) = value.get("records").and_then(|v| v.as_array()) {
        for record in records {
            if let Some(txt) = record.as_str() {
                result.push(txt.to_string());
            } else if let Some(txt) = record.get("value").and_then(|v| v.as_str()) {
                result.push(txt.to_string());
            }
        }
    } else if let Some(txt) = value.get("txt").and_then(|v| v.as_str()) {
        result.push(txt.to_string());
    }

    result
}

fn device_doc_from_mini_jwt_map(
    zone_name: &str,
    device_name: &str,
    mini_device_jwts: &HashMap<String, String>,
    ttl: Option<u32>,
    version: Option<u64>,
) -> Option<DeviceMiniDocument> {
    let jwt = mini_device_jwts.get(device_name)?;
    let value = EncodedDocument::Jwt(jwt.clone()).to_json_value().ok()?;
    let mut result = device_doc_from_value(zone_name, device_name, &value, ttl, version)?;
    result.mini_config_jwt = Some(jwt.clone());
    Some(result)
}

fn device_mini_doc_from_aggregate(
    zone_name: &str,
    device_name: &str,
    document: &BnsDocument,
) -> Option<DeviceMiniDocument> {
    let value = document.content.to_json_value()?;
    let device_value = value
        .get("devices")
        .and_then(|v| v.as_object())
        .and_then(|devices| devices.get(device_name))
        .or_else(|| value.get(device_name))?;

    let mut result = device_doc_from_value(
        zone_name,
        device_name,
        device_value,
        document.meta.ttl,
        document.meta.version,
    )?;
    if result.mini_config_jwt.is_none() {
        result.mini_config_jwt = value
            .get("mini_device_jwts")
            .and_then(Value::as_object)
            .and_then(|jwts| jwts.get(device_name))
            .and_then(Value::as_str)
            .map(ToString::to_string);
    }
    Some(result)
}

fn device_doc_from_single(
    zone_name: &str,
    device_name: &str,
    document: &BnsDocument,
    child_name: Option<&str>,
) -> Option<DeviceMiniDocument> {
    let value = document.content.to_json_value()?;
    let inferred_name = child_name
        .and_then(|name| name.split('.').next())
        .unwrap_or(device_name);
    let mut result = device_doc_from_value(
        zone_name,
        inferred_name,
        &value,
        document.meta.ttl,
        document.meta.version,
    )?;
    if result.mini_config_jwt.is_none() {
        result.mini_config_jwt = document.content.as_jwt();
    }
    Some(result)
}

fn device_doc_from_value(
    zone_name: &str,
    fallback_device_name: &str,
    value: &Value,
    ttl: Option<u32>,
    version: Option<u64>,
) -> Option<DeviceMiniDocument> {
    let device_name = find_string_path(value, &["device_name"])
        .or_else(|| find_string_path(value, &["name"]))
        .or_else(|| find_string_path(value, &["n"]))
        .unwrap_or_else(|| fallback_device_name.to_string());
    let did = device_public_key_x(value)
        .map(|x| format!("did:dev:{}", x))
        .or_else(|| find_string_path(value, &["did"]))
        .or_else(|| find_string_path(value, &["id"]))
        .or_else(|| find_string_path(value, &["x"]).map(|x| format!("did:dev:{}", x)))?;
    let mini_config_jwt = find_string_path(value, &["mini_config_jwt"]);

    Some(DeviceMiniDocument {
        zone_name: zone_name.to_string(),
        device_name,
        did,
        mini_config_jwt,
        document: Some(value.clone()),
        ttl,
        version,
    })
}

fn device_document_requires_sn_relay(device_doc: &DeviceMiniDocument) -> Option<bool> {
    let net_id = device_doc
        .document
        .as_ref()?
        .get("net_id")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    if net_id.is_empty() {
        return None;
    }

    Some(!net_id.starts_with("wan"))
}

fn device_public_key_x(value: &Value) -> Option<String> {
    value
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find_map(|method| find_string_path(method, &["publicKeyJwk", "x"]))
        })
        .or_else(|| find_string_path(value, &["public_key", "x"]))
}

fn build_auth_db_zone_projection(username: &str, user: &SNUserInfo) -> Value {
    json!({
        "user_name": username,
        "public_key": user.public_key.clone(),
        "boot": user.zone_config.clone(),
        "self_cert": user.self_cert,
        "user_domain": user.user_domain.clone(),
        "sn_ips": user.sn_ips.clone(),
        "state": user.state.to_string(),
    })
}

fn parse_ip_or_socket_addr(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

/// BNS 兼容域名映射（SN-Resolver.md "BNS 兼容域名"）：
/// `<name>.web3.<server_host>` 及其子域 -> BNS name `<name>`。
fn bns_compat_name_for(server_host: &str, hostname: &str) -> Option<String> {
    let suffix = format!(".web3.{}", server_host);
    let prefix = hostname.strip_suffix(suffix.as_str())?;
    if prefix.is_empty() {
        return None;
    }
    let name = prefix.rsplit('.').next().unwrap_or(prefix);
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn push_dns_address(addresses: &mut Vec<IpAddr>, ip: IpAddr, record_type: RecordType) {
    match record_type {
        RecordType::A if ip.is_ipv4() => push_exportable_ip(addresses, ip),
        RecordType::AAAA if ip.is_ipv6() => push_exportable_ip(addresses, ip),
        _ => {}
    }
}

fn push_dns_address_unfiltered(addresses: &mut Vec<IpAddr>, ip: IpAddr, record_type: RecordType) {
    match record_type {
        RecordType::A if ip.is_ipv4() => {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        RecordType::AAAA if ip.is_ipv6() => {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        _ => {}
    }
}

fn push_exportable_ip(addresses: &mut Vec<IpAddr>, ip: IpAddr) {
    if is_filtered_zonegate_ip(ip) {
        return;
    }
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

fn is_filtered_zonegate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                return true;
            }
            is_docker_bridge_ipv4(&ipv4)
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn is_docker_bridge_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 172 && (16..=31).contains(&octets[1])
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

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
    struct StaticBnsReader {
        owners: HashMap<String, BnsOwner>,
        documents: HashMap<(String, String), BnsDocument>,
        unavailable: bool,
    }

    #[async_trait]
    impl BnsDocumentReader for StaticBnsReader {
        async fn resolve_owner(&self, name: &str) -> SnResolverResult<Option<BnsOwner>> {
            if self.unavailable {
                return Err(SnResolverError::backend("static BNS backend unavailable"));
            }
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

    #[derive(Default)]
    struct StaticAuthReader {
        users: HashMap<String, SNUserInfo>,
        bindings: Vec<(String, String)>,
        records: HashMap<(String, String), (String, u32)>,
    }

    #[async_trait]
    impl SnAuthReader for StaticAuthReader {
        async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
            Ok(self.users.get(username).cloned())
        }

        async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
            let domain = normalize_host_lossy(domain);
            let binding = self
                .bindings
                .iter()
                .filter(|(zone, _)| dns_name_in_zone(domain.as_str(), zone.as_str()))
                .max_by_key(|(zone, _)| zone.split('.').count());
            let Some((zone, username)) = binding else {
                return Ok(None);
            };
            let mut user = self.users.get(username).cloned();
            if let Some(user) = user.as_mut() {
                user.user_domain = Some(zone.clone());
            }
            Ok(user)
        }

        async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
            Ok(Some(ZoneInfo::default_for(username)))
        }

        async fn get_user_dns_rrset(
            &self,
            name: &str,
            record_type: UserDnsRecordType,
        ) -> SnResolverResult<UserDnsLookup> {
            let rrset = self
                .records
                .get(&(normalize_host_lossy(name), record_type.to_string()))
                .map(|(value, ttl)| UserDnsRrset {
                    name: normalize_host_lossy(name),
                    record_type,
                    ttl: *ttl,
                    values: vec![value.clone()],
                    revision: 1,
                });
            Ok(UserDnsLookup {
                rrset,
                observed_revision: u64::from(!self.records.is_empty()),
            })
        }

        async fn list_user_dns_changes(
            &self,
            _after_revision: u64,
            _limit: usize,
        ) -> SnResolverResult<UserDnsChangePage> {
            let current_revision = u64::from(!self.records.is_empty());
            Ok(UserDnsChangePage {
                changes: Vec::new(),
                current_revision,
                earliest_available_revision: current_revision.saturating_add(1),
            })
        }
    }

    struct StaticRelayReader {
        assignment: RelayAssignment,
        ips: Option<[IpAddr; 2]>,
    }

    #[async_trait]
    impl RelayAssignmentReader for StaticRelayReader {
        async fn get_zone_relay(&self, zone: &str) -> SnResolverResult<Option<RelayAssignment>> {
            Ok((zone == self.assignment.zone).then(|| self.assignment.clone()))
        }

        async fn get_relay_node_ips(
            &self,
            relay_id: &str,
        ) -> SnResolverResult<Option<[IpAddr; 2]>> {
            Ok((relay_id == self.assignment.relay_id)
                .then_some(self.ips)
                .flatten())
        }
    }

    fn test_relay_assignment(zone: &str) -> RelayAssignment {
        RelayAssignment {
            zone: zone.to_string(),
            relay_id: "relay-test".to_string(),
            relay_sn: "relay-test.example".to_string(),
            state: RelayAssignmentState::Active,
            source: crate::RelayAssignmentSource::Auto,
            reason: Some("test".to_string()),
            generation: 1,
            backup_relay_id: None,
            sticky_until: None,
            lease_expires_at: None,
            migrated_from: None,
            migration_deadline: None,
            source_version: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn relay_dns_test_resolver(ips: Option<[IpAddr; 2]>) -> SnResolver {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: None,
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("alice".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "alice",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:alice-ood",
                            "net_id": "nat"
                        }
                    }
                }),
            ),
        );
        SnResolver::new_with_bns(
            SnResolverConfig::new("buckyos.test", None, None, None, Vec::new()),
            Arc::new(StaticAuthReader::default()),
            Arc::new(bns),
        )
        .with_relay_reader(Arc::new(StaticRelayReader {
            assignment: test_relay_assignment("alice"),
            ips,
        }))
    }

    fn test_user(username: &str, state: UserState, user_domain: Option<&str>) -> SNUserInfo {
        SNUserInfo {
            username: Some(username.to_string()),
            email: None,
            state,
            public_key: "test-key".to_string(),
            activation_code: None,
            zone_config: String::new(),
            self_cert: false,
            user_domain: user_domain.map(ToOwned::to_owned),
            sn_ips: None,
            updated_at: 1,
            relay: None,
        }
    }

    fn test_resolver_with_bns(bns: StaticBnsReader) -> SnResolver {
        SnResolver::new(
            SnResolverConfig::new(
                "buckyos.test",
                Some("192.0.2.10".parse::<IpAddr>().unwrap()),
                None,
                None,
                Vec::new(),
            ),
            Arc::new(EmptySnAuthReader),
        )
        .with_bns_reader(Arc::new(bns))
    }

    fn authoritative_test_resolver(bns: StaticBnsReader, auth: StaticAuthReader) -> SnResolver {
        SnResolver::new_with_bns(
            SnResolverConfig::new(
                "BuckyOS.Test.",
                Some("192.0.2.10".parse::<IpAddr>().unwrap()),
                None,
                None,
                Vec::new(),
            ),
            Arc::new(auth),
            Arc::new(bns),
        )
    }

    fn resolver_without_server_ip() -> SnResolver {
        SnResolver::new(
            SnResolverConfig::new(
                "buckyos.test",
                None,
                Some("boot".to_string()),
                Some("owner".to_string()),
                Vec::new(),
            )
            .with_aliases(vec!["alias.buckyos.test".to_string()]),
            Arc::new(EmptySnAuthReader),
        )
    }

    #[tokio::test]
    async fn self_dns_bootstrap_fields_are_independent_and_empty_values_are_omitted() {
        let cases = [
            (None, None, Vec::new(), Vec::<String>::new()),
            (
                Some(String::new()),
                Some("  ".to_string()),
                vec![String::new(), "  ".to_string()],
                Vec::new(),
            ),
            (
                Some("boot".to_string()),
                None,
                Vec::new(),
                vec!["BOOT=boot;".to_string()],
            ),
            (
                None,
                Some("owner".to_string()),
                Vec::new(),
                vec!["PKX=owner;".to_string()],
            ),
            (
                None,
                None,
                vec!["device".to_string()],
                vec!["DEV=device;".to_string()],
            ),
        ];

        for (boot_jwt, owner_pkx, device_jwts, expected) in cases {
            let resolver = SnResolver::new(
                SnResolverConfig::new(
                    "buckyos.test",
                    Some("192.0.2.10".parse().unwrap()),
                    boot_jwt,
                    owner_pkx,
                    device_jwts,
                ),
                Arc::new(EmptySnAuthReader),
            );
            let resolution = resolver
                .resolve_dns("sn.buckyos.test", RecordType::TXT)
                .await
                .unwrap();
            assert_eq!(resolution.txt, expected);
        }
    }

    #[tokio::test]
    async fn bootstrap_absence_preserves_bns_and_user_domain_dns_sources() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                // The chain-level asset owner is an EVM address. A complete
                // OwnerDocument must win when constructing the PKX TXT record.
                effective_owner: Some("0x70997970c51812dc3a010c7d01b50e0d17dc79c8".to_string()),
                owner_config: Some(json!({
                    "id": "did:bns:alice",
                    "verificationMethod": [{
                        "id": "#main_key",
                        "controller": "did:bns:alice",
                        "publicKeyJwk": {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8"
                        }
                    }]
                })),
            },
        );
        bns.documents.insert(
            ("alice".to_string(), BNS_DOC_BOOT.to_string()),
            BnsDocument::jwt("alice", BNS_DOC_BOOT, "alice-boot"),
        );
        bns.documents.insert(
            ("alice".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "alice",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:alice-device",
                            "mini_config_jwt": "alice-device-jwt"
                        }
                    }
                }),
            ),
        );

        let mut auth = StaticAuthReader::default();
        auth.users.insert(
            "bob".to_string(),
            test_user("bob", UserState::Active, Some("bob.example")),
        );
        auth.bindings
            .push(("bob.example".to_string(), "bob".to_string()));

        auth.records.insert(
            ("www.bob.example".to_string(), "A".to_string()),
            ("198.51.100.20".to_string(), 90),
        );
        auth.records.insert(
            ("www.bob.example".to_string(), "TXT".to_string()),
            ("user-domain-record".to_string(), 90),
        );

        let resolver = authoritative_test_resolver(bns, auth);
        assert!(resolver.config().boot_jwt.is_none());
        assert!(resolver.config().owner_pkx.is_none());
        assert!(resolver.config().device_jwts.is_empty());

        let web3_txt = resolver
            .resolve_dns("alice.web3.buckyos.test", RecordType::TXT)
            .await
            .unwrap();
        assert!(web3_txt
            .txt
            .iter()
            .any(|value| { value == "PKX=T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8;" }));
        assert!(!web3_txt.txt.iter().any(|value| value.starts_with("PKX=0x")));
        assert!(web3_txt.txt.iter().any(|value| value == "BOOT=alice-boot;"));
        assert!(web3_txt
            .txt
            .iter()
            .any(|value| value == "DEV=alice-device-jwt;"));

        let user_domain_a = resolver
            .resolve_dns("www.bob.example", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            user_domain_a.addresses,
            vec!["198.51.100.20".parse::<IpAddr>().unwrap()]
        );
        let user_domain_txt = resolver
            .resolve_dns("www.bob.example", RecordType::TXT)
            .await
            .unwrap();
        assert_eq!(user_domain_txt.txt, vec!["user-domain-record".to_string()]);
    }

    #[tokio::test]
    async fn missing_server_ip_only_fails_ip_dependent_resolution() {
        let resolver = resolver_without_server_ip();

        let txt = resolver
            .resolve_dns("buckyos.test", RecordType::TXT)
            .await
            .unwrap();
        assert!(txt.txt.iter().any(|value| value == "BOOT=boot;"));

        for hostname in ["buckyos.test", "sn.buckyos.test", "alias.buckyos.test"] {
            for record_type in [RecordType::A, RecordType::AAAA] {
                let error = resolver
                    .resolve_dns(hostname, record_type)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), SnResolverErrorKind::BackendUnavailable);
                assert_eq!(error.message(), SN_SERVER_IP_NOT_CONFIGURED);
            }
        }
    }

    #[tokio::test]
    async fn missing_assignment_fails_without_server_ip_fallback() {
        let resolver = resolver_without_server_ip();
        let zone = ZoneResolution {
            input: "testuser".to_string(),
            canonical_name: "testuser".to_string(),
            zone_name: "testuser".to_string(),
            owner: BnsOwner {
                name: "testuser".to_string(),
                effective_owner: None,
                owner_config: None,
            },
            owner_from_auth_db: false,
            zone_doc: ZoneDocument::empty(),
            boot_doc: BootDocument::empty(),
            user_domain: None,
            self_cert: false,
            relay_sn: None,
            source: ZoneResolutionSource::BnsName,
        };

        for net_id in ["nat", "wan"] {
            let device_doc = DeviceMiniDocument {
                zone_name: "testuser".to_string(),
                device_name: "ood1".to_string(),
                did: "did:dev:test-device".to_string(),
                mini_config_jwt: None,
                document: Some(json!({ "net_id": net_id })),
                ttl: None,
                version: None,
            };
            let error = resolver
                .resolve_gateway_addresses(&zone, &device_doc, None)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), SnResolverErrorKind::BackendUnavailable);
            assert_eq!(error.message(), "relay assignment is missing for testuser");
        }
    }

    #[test]
    fn bns_compat_name_extraction() {
        // <name>.web3.<server_host> 与其子域都映射到末级 name。
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.web3.devtests.org").as_deref(),
            Some("alice")
        );
        assert_eq!(
            bns_compat_name_for("devtests.org", "home.alice.web3.devtests.org").as_deref(),
            Some("alice")
        );
        // web3.<server_host> 本体不是 BNS 兼容域名（属 SN 自身 hostname 域）。
        assert_eq!(
            bns_compat_name_for("devtests.org", "web3.devtests.org"),
            None
        );
        // 其他后缀不误判。
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.example.com"),
            None
        );
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.web3.other.org"),
            None
        );
    }

    #[tokio::test]
    async fn authoritative_dns_distinguishes_answer_nodata_nxdomain_and_not_managed() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: None,
                owner_config: None,
            },
        );
        let mut auth = StaticAuthReader::default();
        for (record_type, record) in [
            ("A", "192.0.2.11"),
            ("AAAA", "2001:db8::11"),
            ("TXT", "alice-txt"),
        ] {
            auth.records.insert(
                (
                    "alice.web3.buckyos.test".to_string(),
                    record_type.to_string(),
                ),
                (record.to_string(), 120),
            );
        }
        auth.records.insert(
            ("txt-only.web3.buckyos.test".to_string(), "TXT".to_string()),
            ("only-txt".to_string(), 120),
        );
        let resolver = authoritative_test_resolver(bns, auth);

        for record_type in ["A", "AAAA", "TXT"] {
            match resolver
                .resolve_authoritative_dns_cached("Alice.Web3.BuckyOS.Test.", record_type)
                .await
                .unwrap()
            {
                SnAuthoritativeDnsResult::AuthoritativeAnswer {
                    authority,
                    resolution,
                } => {
                    assert_eq!(authority.zone_apex, "web3.buckyos.test");
                    assert_eq!(authority.soa_serial, DEFAULT_AUTH_SOA_SERIAL);
                    assert!(dns_resolution_has_rrset(&resolution));
                }
                other => panic!("expected answer for {record_type}, got {other:?}"),
            }
        }

        for record_type in ["HTTPS", "SVCB", "CAA", "MX", "NS", "SOA"] {
            assert!(matches!(
                resolver
                    .resolve_authoritative_dns_cached("txt-only.web3.buckyos.test", record_type,)
                    .await
                    .unwrap(),
                SnAuthoritativeDnsResult::AuthoritativeNoData { .. }
            ));
        }
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("web3.buckyos.test", "A")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeNoData { .. }
        ));

        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("missing.web3.buckyos.test", "MX")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeNxDomain { .. }
        ));
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("alice.web3.other.test", "A")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::NotManaged
        ));
    }

    #[tokio::test]
    async fn authoritative_control_owner_exists_only_while_an_explicit_rrset_exists() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: None,
                owner_config: None,
            },
        );
        let resolver_without_record = authoritative_test_resolver(bns, StaticAuthReader::default());
        assert!(matches!(
            resolver_without_record
                .resolve_authoritative_dns_cached("_acme-challenge.alice.web3.buckyos.test", "MX",)
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeNxDomain { .. }
        ));

        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: None,
                owner_config: None,
            },
        );
        let mut auth = StaticAuthReader::default();
        auth.records.insert(
            (
                "_acme-challenge.alice.web3.buckyos.test".to_string(),
                "TXT".to_string(),
            ),
            ("challenge".to_string(), 60),
        );
        let resolver_with_record = authoritative_test_resolver(bns, auth);
        assert!(matches!(
            resolver_with_record
                .resolve_authoritative_dns_cached("_acme-challenge.alice.web3.buckyos.test", "MX",)
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeNoData { .. }
        ));
    }

    #[tokio::test]
    async fn authoritative_user_domain_uses_active_longest_suffix_binding() {
        let mut auth = StaticAuthReader::default();
        auth.users.insert(
            "alice".to_string(),
            test_user("alice", UserState::Active, Some("example.com")),
        );
        auth.users.insert(
            "bob".to_string(),
            test_user("bob", UserState::Active, Some("sub.example.com")),
        );
        auth.users.insert(
            "mallory".to_string(),
            test_user("mallory", UserState::Suspended, Some("suspended.test")),
        );
        auth.bindings = vec![
            ("example.com".to_string(), "alice".to_string()),
            ("sub.example.com".to_string(), "bob".to_string()),
            ("suspended.test".to_string(), "mallory".to_string()),
        ];
        let resolver = authoritative_test_resolver(StaticBnsReader::default(), auth);

        match resolver
            .resolve_authoritative_dns_cached("host.sub.example.com", "MX")
            .await
            .unwrap()
        {
            SnAuthoritativeDnsResult::AuthoritativeNoData { authority } => {
                assert_eq!(authority.zone_apex, "sub.example.com");
            }
            other => panic!("expected user-domain NODATA, got {other:?}"),
        }
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("host.suspended.test", "MX")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::NotManaged
        ));
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("notexample.com", "MX")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::NotManaged
        ));
    }

    #[tokio::test]
    async fn authoritative_backend_unavailable_is_not_negative_dns_data() {
        let resolver = authoritative_test_resolver(
            StaticBnsReader {
                unavailable: true,
                ..Default::default()
            },
            StaticAuthReader::default(),
        );
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("alice.web3.buckyos.test", "A")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::TemporaryFailure { .. }
        ));
    }

    #[test]
    fn dns_address_filter_removes_loopback_and_docker_bridge() {
        let mut addresses = Vec::new();
        push_dns_address(&mut addresses, "127.0.0.1".parse().unwrap(), RecordType::A);
        push_dns_address(&mut addresses, "172.17.0.1".parse().unwrap(), RecordType::A);
        push_dns_address(
            &mut addresses,
            "192.168.1.2".parse().unwrap(),
            RecordType::A,
        );
        push_dns_address(
            &mut addresses,
            "192.168.1.2".parse().unwrap(),
            RecordType::A,
        );
        push_dns_address(&mut addresses, "::1".parse().unwrap(), RecordType::AAAA);
        push_dns_address(
            &mut addresses,
            "2001:db8::1".parse().unwrap(),
            RecordType::AAAA,
        );

        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&"192.168.1.2".parse::<IpAddr>().unwrap()));
        assert!(addresses.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parses_gateway_device_from_zone_documents() {
        let value = json!({
            "gateway": { "device_name": "gw1", "ips": ["8.8.8.8", "172.18.0.1"] }
        });
        assert_eq!(find_gateway_device_name(&value).as_deref(), Some("gw1"));
        assert_eq!(
            find_gateway_ips(&value),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );

        let value = json!({ "oods": ["ood2.testuser"] });
        assert_eq!(find_gateway_device_name(&value).as_deref(), Some("ood2"));
    }

    #[test]
    fn signed_device_net_id_controls_sn_relay_requirement() {
        let device = |net_id: Option<&str>| DeviceMiniDocument {
            zone_name: "testuser".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:test-device".to_string(),
            mini_config_jwt: None,
            document: net_id.map(|net_id| json!({ "net_id": net_id })),
            ttl: None,
            version: None,
        };

        assert_eq!(
            device_document_requires_sn_relay(&device(Some("nat"))),
            Some(true)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("portmap"))),
            Some(true)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("wan"))),
            Some(false)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("wan_dyn"))),
            Some(false)
        );
        assert_eq!(device_document_requires_sn_relay(&device(None)), None);
    }

    #[tokio::test]
    async fn nat_device_includes_assigned_relay_even_when_online_state_looks_wan() {
        let resolver = test_resolver_with_bns(StaticBnsReader::default()).with_relay_reader(
            Arc::new(StaticRelayReader {
                assignment: test_relay_assignment("testuser"),
                ips: Some([
                    "192.0.2.10".parse::<IpAddr>().unwrap(),
                    "198.51.100.20".parse::<IpAddr>().unwrap(),
                ]),
            }),
        );
        let zone = ZoneResolution {
            input: "testuser.web3.buckyos.test".to_string(),
            canonical_name: "testuser".to_string(),
            zone_name: "testuser".to_string(),
            owner: BnsOwner {
                name: "testuser".to_string(),
                effective_owner: None,
                owner_config: None,
            },
            owner_from_auth_db: false,
            zone_doc: ZoneDocument::empty(),
            boot_doc: BootDocument::empty(),
            user_domain: None,
            self_cert: false,
            relay_sn: None,
            source: ZoneResolutionSource::BnsName,
        };
        let device_doc = DeviceMiniDocument {
            zone_name: "testuser".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:test-device".to_string(),
            mini_config_jwt: None,
            document: Some(json!({
                "net_id": "nat",
                "all_ip": ["2600:1700:1150:9440::49", "192.168.1.143"]
            })),
            ttl: None,
            version: None,
        };
        let online = SnDeviceStateView {
            did: device_doc.did.clone(),
            zone: zone.zone_name.clone(),
            device_name: device_doc.device_name.clone(),
            device_role: crate::SnDeviceRole::Ood,
            state: crate::SnDeviceState::Online,
            public_ips: vec!["2600:1700:1150:9440::49".to_string()],
            private_ips: vec!["192.168.1.143".to_string()],
            active_endpoints: Vec::new(),
            preferred_endpoint: None,
            nat_type: crate::SnNatType::Unknown,
            is_wan_device: true,
            last_seen_at: None,
            expires_at: None,
        };

        let addresses = resolver
            .resolve_gateway_addresses(&zone, &device_doc, Some(&online))
            .await
            .unwrap();

        assert!(addresses.contains(&"192.0.2.10".parse::<IpAddr>().unwrap()));
        assert!(addresses.contains(&"198.51.100.20".parse::<IpAddr>().unwrap()));
        assert!(addresses.contains(&"2600:1700:1150:9440::49".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn nat_zone_dns_returns_direct_addresses_before_assigned_relay_addresses() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "alice".to_string(),
            BnsOwner {
                name: "alice".to_string(),
                effective_owner: None,
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("alice".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "alice",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:alice-ood",
                            "net_id": "nat",
                            "all_ip": ["192.168.1.143"]
                        }
                    }
                }),
            ),
        );
        let resolver = SnResolver::new_with_bns(
            SnResolverConfig::new("buckyos.test", None, None, None, Vec::new()),
            Arc::new(StaticAuthReader::default()),
            Arc::new(bns),
        )
        .with_relay_reader(Arc::new(StaticRelayReader {
            assignment: test_relay_assignment("alice"),
            ips: Some([
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "198.51.100.20".parse::<IpAddr>().unwrap(),
            ]),
        }));

        let resolution = resolver
            .resolve_dns("alice.web3.buckyos.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(
            resolution.addresses,
            ["192.168.1.143", "192.0.2.10", "198.51.100.20"]
                .into_iter()
                .map(|ip| ip.parse::<IpAddr>().unwrap())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn wan_device_with_direct_address_does_not_require_relay_assignment() {
        let resolver = test_resolver_with_bns(StaticBnsReader::default());
        let zone = ZoneResolution {
            input: "testuser.web3.buckyos.test".to_string(),
            canonical_name: "testuser".to_string(),
            zone_name: "testuser".to_string(),
            owner: BnsOwner {
                name: "testuser".to_string(),
                effective_owner: None,
                owner_config: None,
            },
            owner_from_auth_db: false,
            zone_doc: ZoneDocument::empty(),
            boot_doc: BootDocument::empty(),
            user_domain: None,
            self_cert: false,
            relay_sn: None,
            source: ZoneResolutionSource::BnsName,
        };
        let device_doc = DeviceMiniDocument {
            zone_name: "testuser".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:test-device".to_string(),
            mini_config_jwt: None,
            document: Some(json!({
                "net_id": "wan",
                "all_ip": ["198.51.100.30"]
            })),
            ttl: None,
            version: None,
        };

        let addresses = resolver
            .resolve_gateway_addresses(&zone, &device_doc, None)
            .await
            .unwrap();

        assert_eq!(addresses, vec!["198.51.100.30".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn relay_dns_filters_two_typed_addresses_by_query_family() {
        let cases = [
            (
                [
                    "192.0.2.10".parse().unwrap(),
                    "198.51.100.20".parse().unwrap(),
                ],
                vec!["192.0.2.10", "198.51.100.20"],
                Vec::<&str>::new(),
            ),
            (
                [
                    "192.0.2.11".parse().unwrap(),
                    "2001:db8::11".parse().unwrap(),
                ],
                vec!["192.0.2.11"],
                vec!["2001:db8::11"],
            ),
            (
                [
                    "2001:db8::12".parse().unwrap(),
                    "2001:db8::13".parse().unwrap(),
                ],
                Vec::<&str>::new(),
                vec!["2001:db8::12", "2001:db8::13"],
            ),
        ];

        for (ips, expected_a, expected_aaaa) in cases {
            let resolver = relay_dns_test_resolver(Some(ips));
            let a = resolver
                .resolve_dns("alice.web3.buckyos.test", RecordType::A)
                .await
                .unwrap();
            let aaaa = resolver
                .resolve_dns("alice.web3.buckyos.test", RecordType::AAAA)
                .await
                .unwrap();
            assert_eq!(
                a.addresses,
                expected_a
                    .into_iter()
                    .map(|ip| ip.parse::<IpAddr>().unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                aaaa.addresses,
                expected_aaaa
                    .into_iter()
                    .map(|ip| ip.parse::<IpAddr>().unwrap())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[tokio::test]
    async fn relay_dns_unknown_node_is_backend_failure_without_fallback() {
        let resolver = relay_dns_test_resolver(None);
        let error = resolver
            .resolve_dns("alice.web3.buckyos.test", RecordType::A)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SnResolverErrorKind::BackendUnavailable);
        assert!(error.message().contains("unknown node relay-test"));
        assert!(!error.message().contains(SN_SERVER_IP_NOT_CONFIGURED));
    }

    #[tokio::test]
    async fn relay_dns_missing_family_is_authoritative_nodata() {
        let resolver = relay_dns_test_resolver(Some([
            "2001:db8::20".parse().unwrap(),
            "2001:db8::21".parse().unwrap(),
        ]));
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("alice.web3.buckyos.test", "A")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeNoData { .. }
        ));
        assert!(matches!(
            resolver
                .resolve_authoritative_dns_cached("alice.web3.buckyos.test", "AAAA")
                .await
                .unwrap(),
            SnAuthoritativeDnsResult::AuthoritativeAnswer { .. }
        ));
    }

    #[tokio::test]
    async fn relay_dns_keeps_ipv4_mapped_ipv6_in_aaaa_and_deduplicates() {
        let mapped: IpAddr = "::ffff:192.0.2.44".parse().unwrap();
        let resolver = relay_dns_test_resolver(Some([mapped, mapped]));
        let a = resolver
            .resolve_dns("alice.web3.buckyos.test", RecordType::A)
            .await
            .unwrap();
        let aaaa = resolver
            .resolve_dns("alice.web3.buckyos.test", RecordType::AAAA)
            .await
            .unwrap();
        assert!(a.addresses.is_empty());
        assert_eq!(aaaa.addresses, vec![mapped]);
    }

    #[tokio::test]
    async fn auth_db_relay_map_cache_refreshes_after_revision_change() {
        use crate::{RelayNodeAddressUpdate, RelayNodeRegistration, SnAuthDB, SqliteSnAuthDB};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(path.to_string_lossy().as_ref())
            .await
            .unwrap();
        db.initialize_database().await.unwrap();
        db.register_relay_node(RelayNodeRegistration {
            relay_id: "relay-a".to_string(),
            relay_sn: "relay-a.example".to_string(),
            ips: [
                "192.0.2.30".parse().unwrap(),
                "2001:db8::30".parse().unwrap(),
            ],
            public_host: "relay-a.example".to_string(),
            http_endpoint: None,
            rtcp_endpoint: None,
            region: None,
            isp: None,
            tags: Vec::new(),
            capabilities: Vec::new(),
            status: None,
            capacity_score: Some(100),
        })
        .await
        .unwrap();
        let db: SnAuthDBRef = Arc::new(db);
        let reader = SnAuthDbRelayResolverReader::new(db.clone()).with_cache_ttl(Duration::ZERO);
        assert_eq!(
            reader.get_relay_node_ips("relay-a").await.unwrap(),
            Some([
                "192.0.2.30".parse().unwrap(),
                "2001:db8::30".parse().unwrap()
            ])
        );

        let updated = [
            "198.51.100.31".parse().unwrap(),
            "2001:db8::31".parse().unwrap(),
        ];
        db.update_relay_node_addresses(RelayNodeAddressUpdate {
            relay_id: "relay-a".to_string(),
            ips: updated,
        })
        .await
        .unwrap();
        assert_eq!(
            reader.get_relay_node_ips("relay-a").await.unwrap(),
            Some(updated)
        );
    }

    #[test]
    fn parses_boot_jwt_from_zone_document() {
        let value = json!({ "boot_jwt": " inline-boot " });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("inline-boot"));

        let value = json!({ "boot": { "boot_config_jwt": "nested-boot" } });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("nested-boot"));

        let value = json!({ "zone_config_jwt": "wrapped-boot" });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("wrapped-boot"));

        let value = json!({ "boot": "legacy-boot" });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("legacy-boot"));
    }

    #[test]
    fn parses_device_mini_doc_from_aggregate() {
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_DEVICE_MINI,
            json!({
                "devices": {
                    "gw1": {
                        "did": "did:dev:abc",
                        "mini_config_jwt": "jwt"
                    }
                }
            }),
        );

        let device = device_mini_doc_from_aggregate("testuser", "gw1", &doc).unwrap();
        assert_eq!(device.device_name, "gw1");
        assert_eq!(device.did, "did:dev:abc");
        assert_eq!(device.mini_config_jwt.as_deref(), Some("jwt"));
    }

    #[test]
    fn parses_full_devices_and_mini_jwts_as_distinct_zone_fields() {
        let mini_jwt = compact_test_jwt(&json!({ "n": "gw1", "x": "abc" }));
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_ZONE,
            json!({
                "devices": {
                    "gw1": {
                        "id": "did:bns:gw1.testuser",
                        "name": "gw1"
                    }
                },
                "mini_device_jwts": {
                    "gw1": mini_jwt
                },
                "device_mini_doc": {
                    "devices": {
                        "mini-only": {
                            "x": "must-not-enter-full-device-map"
                        }
                    }
                }
            }),
        );

        let zone_doc = ZoneDocument::from_bns_document(&doc);
        assert_eq!(zone_doc.devices["gw1"]["id"], "did:bns:gw1.testuser");
        assert!(!zone_doc.devices.contains_key("mini-only"));
        let device = device_doc_from_mini_jwt_map(
            "testuser",
            "gw1",
            &zone_doc.mini_device_jwts,
            zone_doc.ttl,
            zone_doc.version,
        )
        .unwrap();

        assert_eq!(device.device_name, "gw1");
        assert_eq!(device.did, "did:dev:abc");
        assert_eq!(
            device.mini_config_jwt.as_deref(),
            zone_doc.mini_device_jwts.get("gw1").map(String::as_str)
        );
    }

    #[test]
    fn parses_canonical_zone_document_device_and_mini_jwt_fields() {
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_ZONE,
            json!({
                "devices": {
                    "ood1": {
                        "id": "did:dev:canonical",
                        "name": "ood1"
                    }
                },
                "mini_device_jwts": {
                    "ood1": "canonical-mini-jwt"
                }
            }),
        );

        let zone_doc = ZoneDocument::from_bns_document(&doc);
        assert_eq!(zone_doc.devices["ood1"]["id"], "did:dev:canonical");
        assert_eq!(
            zone_doc.mini_device_jwts.get("ood1").map(String::as_str),
            Some("canonical-mini-jwt"),
        );
        assert_eq!(
            device_jwts_from_bns_document(&doc),
            vec!["canonical-mini-jwt"]
        );
    }

    #[tokio::test]
    async fn resolves_device_key_did_from_canonical_zone_document_jwt() {
        let device_x = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
        let mini_jwt = compact_test_jwt(&json!({ "n": "ood1", "x": device_x }));
        let payload = json!({
            "boot_jwt": "canonical-boot-jwt",
            "oods": ["ood1"],
            "devices": {
                "ood1": {
                    "id": "did:bns:ood1.testuser",
                    "name": "ood1",
                    "verificationMethod": [{
                        "publicKeyJwk": {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": device_x
                        }
                    }]
                }
            },
            "mini_device_jwts": {
                "ood1": mini_jwt
            }
        });
        let zone_jwt = compact_test_jwt(&payload);
        let document = BnsDocument::jwt("testuser", BNS_DOC_ZONE, zone_jwt);
        let zone = ZoneDocument::from_bns_document(&document);
        assert_eq!(zone.boot_jwt.as_deref(), Some("canonical-boot-jwt"));
        assert_eq!(zone.gateway_device_name.as_deref(), Some("ood1"));
        assert_eq!(device_jwts_from_bns_document(&document), vec![mini_jwt]);

        let mut bns = StaticBnsReader::default();
        bns.documents
            .insert(("testuser".to_string(), BNS_DOC_ZONE.to_string()), document);
        let resolver = test_resolver_with_bns(bns);
        assert_eq!(
            resolver
                .resolve_zone_device_did("testuser", "ood1")
                .await
                .unwrap(),
            format!("did:dev:{}", device_x)
        );
    }

    #[tokio::test]
    async fn resolves_device_mini_doc_from_zone_mini_jwt_map() {
        let mini_jwt = compact_test_jwt(&json!({ "n": "ood1", "x": "embedded" }));
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "mini_device_jwts": {
                        "ood1": mini_jwt
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let device = resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert_eq!(device.device_name, "ood1");
        assert_eq!(device.did, "did:dev:embedded");
        assert_eq!(device.mini_config_jwt.as_deref(), Some(mini_jwt.as_str()));
    }

    #[tokio::test]
    async fn embedded_and_standalone_mini_documents_resolve_equivalently() {
        let mini_payload = json!({ "n": "ood1", "x": "abc" });
        let mini_jwt = compact_test_jwt(&mini_payload);

        let mut embedded_bns = StaticBnsReader::default();
        embedded_bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({ "mini_device_jwts": { "ood1": mini_jwt } }),
            ),
        );
        let embedded_resolver = test_resolver_with_bns(embedded_bns);

        let mut standalone_bns = StaticBnsReader::default();
        standalone_bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": mini_payload
                    },
                    "mini_device_jwts": {
                        "ood1": mini_jwt
                    }
                }),
            ),
        );
        let standalone_resolver = test_resolver_with_bns(standalone_bns);

        let embedded = embedded_resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();
        let standalone = standalone_resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert_eq!(embedded, standalone);
    }

    #[tokio::test]
    async fn child_device_mini_doc_overrides_aggregate() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:aggregate",
                            "source": "aggregate"
                        }
                    }
                }),
            ),
        );
        bns.documents.insert(
            ("ood1.testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "ood1.testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "x": "child",
                    "source": "child"
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let device = resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert_eq!(device.did, "did:dev:child");
        assert_eq!(
            device
                .document
                .as_ref()
                .and_then(|value| value["source"].as_str()),
            Some("child")
        );
    }

    #[tokio::test]
    async fn resolves_bns_zone_document_without_sn_user() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "gateway": { "device_name": "ood1" }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:testuser").unwrap();

        let resolved = resolver
            .resolve_did(&did, Some(BNS_DOC_ZONE), None)
            .await
            .unwrap();

        assert_eq!(resolved.source, SnDidDocumentSource::BnsDocument);
        assert_eq!(resolved.doc_type, BNS_DOC_ZONE);
    }

    #[tokio::test]
    async fn resolves_zone_with_embedded_boot_jwt_without_separate_boot_doc() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "gateway": { "device_name": "ood1" },
                    "boot_jwt": "embedded-boot"
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let resolved = resolver
            .resolve_zone_by_bns_owner(
                "testuser",
                "testuser",
                BnsOwner {
                    name: "testuser".to_string(),
                    effective_owner: Some("owner-key".to_string()),
                    owner_config: None,
                },
                false,
                ZoneResolutionSource::BnsName,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(resolved.zone_doc.boot_jwt.as_deref(), Some("embedded-boot"));
        assert_eq!(resolved.boot_doc.jwt.as_deref(), Some("embedded-boot"));
    }

    #[tokio::test]
    async fn separate_boot_doc_overrides_embedded_boot_jwt() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({ "boot_jwt": "embedded-boot" }),
            ),
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_BOOT.to_string()),
            BnsDocument::json("testuser", BNS_DOC_BOOT, json!({ "boot": "separate-boot" })),
        );
        let resolver = test_resolver_with_bns(bns);

        let resolved = resolver
            .resolve_zone_by_bns_owner(
                "testuser",
                "testuser",
                BnsOwner {
                    name: "testuser".to_string(),
                    effective_owner: Some("owner-key".to_string()),
                    owner_config: None,
                },
                false,
                ZoneResolutionSource::BnsName,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.boot_doc.raw,
            Some(json!({ "boot": "separate-boot" }))
        );
        assert_eq!(resolved.boot_doc.jwt, None);
    }

    #[tokio::test]
    async fn resolves_bns_device_document_without_sn_user() {
        let device_document = json!({
            "id": "did:bns:ood1.testuser",
            "owner": "did:bns:testuser",
            "iat": 42,
            "exp": 253_402_300_799_u64,
            "name": "ood1",
            "verificationMethod": [{
                "id": "#main_key",
                "controller": "did:bns:ood1.testuser",
                "type": "Ed25519VerificationKey2020",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "abc"
                }
            }]
        });
        let device_jwt = compact_test_jwt(&device_document);
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), "ood1".to_string()),
            BnsDocument::jwt("testuser", "ood1", device_jwt.clone()),
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "id": "did:bns:ood1.testuser",
                            "owner": "did:bns:testuser",
                            "device_type": "ood",
                            "name": "ood1",
                            "verificationMethod": [{
                                "id": "#main_key",
                                "controller": "did:bns:ood1.testuser",
                                "type": "Ed25519VerificationKey2020",
                                "publicKeyJwk": {
                                    "kty": "OKP",
                                    "crv": "Ed25519",
                                    "x": "abc"
                                }
                            }]
                        }
                    },
                    "mini_device_jwts": {
                        "ood1": "mini-jwt"
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:testuser").unwrap();

        let resolved = resolver
            .resolve_did(&did, Some("ood1"), None)
            .await
            .unwrap();

        assert_eq!(resolved.source, SnDidDocumentSource::BnsDocument);
        assert_eq!(resolved.doc_type, "ood1");
        assert_eq!(resolved.document, EncodedDocument::Jwt(device_jwt.clone()));

        let device_did = DID::from_str("did:bns:ood1.testuser").unwrap();
        let resolved = resolver
            .resolve_did(&device_did, Some("device"), None)
            .await
            .unwrap();
        assert_eq!(resolved.source, SnDidDocumentSource::BnsDocument);
        assert_eq!(resolved.doc_type, "device");
        assert_eq!(resolved.document, EncodedDocument::Jwt(device_jwt));
    }

    #[tokio::test]
    async fn device_document_resolution_never_falls_back_to_device_mini_document() {
        let mini_jwt = compact_test_jwt(&json!({ "n": "ood1", "x": "mini-key" }));
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({ "mini_device_jwts": { "ood1": mini_jwt } }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let root_did = DID::from_str("did:bns:testuser").unwrap();
        let root_error = resolver
            .resolve_did(&root_did, Some("ood1"), None)
            .await
            .unwrap_err();
        assert_eq!(root_error.kind(), SnResolverErrorKind::DocumentNotFound);

        let device_did = DID::from_str("did:bns:ood1.testuser").unwrap();
        let child_error = resolver
            .resolve_did(&device_did, Some("device"), None)
            .await
            .unwrap_err();
        assert_eq!(child_error.kind(), SnResolverErrorKind::DocumentNotFound);

        let mini = resolver
            .resolve_did(&device_did, Some(BNS_DOC_DEVICE_MINI), None)
            .await
            .unwrap();
        assert_eq!(mini.source, SnDidDocumentSource::DeviceMiniDocument);
    }

    #[tokio::test]
    async fn bns_static_device_document_does_not_impersonate_online_state() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:abc",
                            "mini_config_jwt": "jwt"
                        }
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:ood1.testuser").unwrap();

        let error = resolver
            .resolve_did(&did, Some("info"), None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SnResolverErrorKind::DeviceNotFound);
        assert!(error.to_string().contains("online device"));
    }
}
