use crate::api::{handle_auth, handle_device, handle_dns, handle_domain, handle_user};
use crate::name_info_cache::{NameInfoCache, NameInfoCacheQueryResult, NameInfoCacheRef};
use crate::sn_auth_manager::SnAuthManager;
use crate::sn_bns_reader::BnsIndexerDocumentReader;
use crate::sn_compat_store::{SNDeviceInfo, SnCompatibilityStoreRef, SqliteSnCompatibilityStore};
use crate::sn_did_resolver::{
    normalize_sn_did_doc_type, SnDidResolveRequest, SnDidResolveResponse, SnDidResolver,
    SnDidResolverProfile, SnDidResolverRef, SN_DID_RESOLVER_ROUTE_PREFIX,
};
use crate::sn_resolver::{
    device_config_from_mini_jwt, ResolverCompatibilityReader, ResolverDeviceDocument,
    ResolverDidDocument, SnAuthResolverReader, SnDeviceInfoResolverReader,
    SnRelayManagerResolverReader, SnResolver, SnResolverConfig, SnResolverError,
    SnResolverErrorKind, SnResolverRef, SnResolverResult,
};
use crate::{
    SnAuthDBRef, SnDeviceEndpointUpdate, SnDeviceInfoDBRef, SnDeviceRole, SnDeviceState,
    SnDeviceStateUpdate, SnEndpointProtocol, SnEndpointScope, SnEndpointSource, SnNatType,
    SnRelayManagerRef, SnResult, SqliteSnAuthDB, SqliteSnDeviceInfoDB, SqliteSnRelayManager,
};
use ::kRPC::*;
use async_trait::async_trait;
use bns_client::{
    canonical_bns_name, BnsEvmClientConfig, BnsEvmControllerClient, BnsIndexerApi,
    BnsIndexerClient, SnBnsController, SnBnsControllerConfig, SqliteSnBnsWriteRequestStore,
};
use bns_indexer::{Principal, PrincipalKind};
use buckyos_kit::{get_buckyos_service_data_dir, is_valid_name, NameType};
use cyfs_gateway_lib::server_err;
use cyfs_gateway_lib::{
    qa_json_to_rpc_request, HttpRequestProcessChainVars, HttpServer, NameServer, QAServer, Server,
    ServerConfig, ServerContextRef, ServerError, ServerErrorCode, ServerFactory, ServerResult,
    StreamInfo,
};
use http::{Method, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use log::*;
use name_client::*;
use name_lib::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::{
    net::{IpAddr, Ipv4Addr},
    result::Result,
};

const CLEAR_STATE_ACTIVE_CODE: &str = "zX6cV7bN8mK9lJ0hG1fD";
const RESERVED_USER_NAMES_FILE_ENV: &str = "BUCKYOS_SN_RESERVED_NAMES_FILE";
const RESERVED_USER_NAMES_FILE: &str = "reserved_user_names.txt";

fn is_filtered_zonegate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                return true;
            }

            let octets = ipv4.octets();
            octets[0] == 172 && (16..=31).contains(&octets[1])
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn push_exportable_device_ip(address_vec: &mut Vec<IpAddr>, ip: IpAddr) {
    if is_filtered_zonegate_ip(ip) {
        return;
    }

    if !address_vec.contains(&ip) {
        address_vec.push(ip);
    }
}

struct LegacyResolverCompatibilityReader {
    auth_db: SnAuthDBRef,
    device_info_db: SnDeviceInfoDBRef,
    compat_store: SnCompatibilityStoreRef,
}

impl LegacyResolverCompatibilityReader {
    fn new(
        auth_db: SnAuthDBRef,
        device_info_db: SnDeviceInfoDBRef,
        compat_store: SnCompatibilityStoreRef,
    ) -> Self {
        Self {
            auth_db,
            device_info_db,
            compat_store,
        }
    }

    fn convert_device_state(view: crate::SnDeviceStateView) -> ResolverDeviceDocument {
        let mut addresses = Vec::new();
        for value in view
            .public_ips
            .iter()
            .chain(view.private_ips.iter())
            .map(|s| s.as_str())
        {
            if let Some(ip) = parse_ip_or_socket_addr(value) {
                push_exportable_device_ip(&mut addresses, ip);
            }
        }
        for endpoint in &view.active_endpoints {
            if let Some(ip) = parse_ip_or_socket_addr(endpoint.host.as_str()) {
                push_exportable_device_ip(&mut addresses, ip);
            }
        }

        let document = serde_json::to_value(&view).ok();

        ResolverDeviceDocument {
            zone_name: view.zone,
            device_name: view.device_name,
            did: view.did,
            mini_config_jwt: None,
            document: document.clone(),
            info_document: document,
            addresses,
            ttl: None,
            version: None,
        }
    }

    async fn convert_device(
        &self,
        device: SNDeviceInfo,
    ) -> SnResolverResult<ResolverDeviceDocument> {
        let raw_document = serde_json::from_str::<Value>(device.description.as_str()).ok();
        let user_public_key = self
            .auth_db
            .get_user_info(device.owner.as_str())
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query owner {} for device {} failed: {}",
                    device.owner, device.device_name, e
                ))
            })?
            .map(|user| user.public_key);

        let document = if !device.mini_config_jwt.trim().is_empty() {
            if let Some(public_key) = user_public_key.as_deref() {
                match device_config_from_mini_jwt(
                    device.mini_config_jwt.as_str(),
                    public_key,
                    device.owner.as_str(),
                ) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        warn!(
                            "failed to build legacy device document for {}.{} from mini jwt: {}",
                            device.device_name, device.owner, e
                        );
                        raw_document.clone()
                    }
                }
            } else {
                raw_document.clone()
            }
        } else {
            raw_document.clone()
        };

        let mut addresses = Vec::new();
        if let Some(ip) = parse_ip_or_socket_addr(device.ip.as_str()) {
            push_exportable_device_ip(&mut addresses, ip);
        }
        collect_device_ips_from_legacy_document(raw_document.as_ref(), &mut addresses);

        Ok(ResolverDeviceDocument {
            zone_name: device.owner.clone(),
            device_name: device.device_name.clone(),
            did: device.did.clone(),
            mini_config_jwt: if device.mini_config_jwt.trim().is_empty() {
                None
            } else {
                Some(device.mini_config_jwt.clone())
            },
            document,
            info_document: Some(build_legacy_device_info_json(&device)),
            addresses,
            ttl: None,
            version: None,
        })
    }
}

#[async_trait]
impl ResolverCompatibilityReader for LegacyResolverCompatibilityReader {
    async fn query_domain_record(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> SnResolverResult<Option<(String, u32)>> {
        self.compat_store
            .query_domain_record(domain, record_type.to_string().as_str())
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query domain record {} {} failed: {}",
                    domain,
                    record_type.to_string(),
                    e
                ))
            })
    }

    async fn get_device_by_name(
        &self,
        zone_name: &str,
        device_name: &str,
    ) -> SnResolverResult<Option<ResolverDeviceDocument>> {
        let registered_device = self
            .device_info_db
            .get_device_state_by_name(zone_name, device_name)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query registered device {}.{} failed: {}",
                    device_name, zone_name, e
                ))
            })?
            .map(Self::convert_device_state);

        let Some(device) = self
            .compat_store
            .query_device_by_name(zone_name, device_name)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query device {}.{} failed: {}",
                    device_name, zone_name, e
                ))
            })?
        else {
            return Ok(registered_device);
        };

        self.convert_device(device).await.map(Some)
    }

    async fn get_device_by_did(
        &self,
        did: &str,
    ) -> SnResolverResult<Option<ResolverDeviceDocument>> {
        if let Some(view) = self
            .device_info_db
            .get_device_state(did)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!("query registered device {} failed: {}", did, e))
            })?
        {
            return Ok(Some(Self::convert_device_state(view)));
        }

        let Some(device) = self
            .compat_store
            .query_device_by_did(did)
            .await
            .map_err(|e| SnResolverError::backend(format!("query device {} failed: {}", did, e)))?
        else {
            return Ok(None);
        };

        self.convert_device(device).await.map(Some)
    }

    async fn query_user_did_document(
        &self,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResolverResult<Option<ResolverDidDocument>> {
        let Some((obj_id, document_json, stored_type)) = self
            .compat_store
            .query_user_did_document(owner_user, obj_name, doc_type)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query did document {}/{} failed: {}",
                    owner_user, obj_name, e
                ))
            })?
        else {
            return Ok(None);
        };

        Ok(Some(ResolverDidDocument {
            obj_id,
            document_json,
            doc_type: stored_type,
        }))
    }
}

fn collect_device_ips_from_legacy_document(value: Option<&Value>, result: &mut Vec<IpAddr>) {
    let Some(value) = value else {
        return;
    };

    for key in ["ip", "ips", "all_ip", "addresses"] {
        let Some(ip_values) = value.get(key) else {
            continue;
        };

        if let Some(ip_str) = ip_values.as_str() {
            if let Some(ip) = parse_ip_or_socket_addr(ip_str) {
                push_exportable_device_ip(result, ip);
            }
            continue;
        }

        if let Some(ip_values) = ip_values.as_array() {
            for ip_str in ip_values.iter().filter_map(|v| v.as_str()) {
                if let Some(ip) = parse_ip_or_socket_addr(ip_str) {
                    push_exportable_device_ip(result, ip);
                }
            }
        }
    }
}

fn build_legacy_device_info_json(device: &SNDeviceInfo) -> Value {
    let mut value = serde_json::from_str::<Value>(device.description.as_str())
        .unwrap_or_else(|_| json!({ "description": device.description }));

    if let Some(obj) = value.as_object_mut() {
        obj.insert("did".to_string(), Value::String(device.did.clone()));
        obj.insert("ip".to_string(), Value::String(device.ip.clone()));
        obj.insert("owner".to_string(), Value::String(device.owner.clone()));
        obj.insert(
            "device_name".to_string(),
            Value::String(device.device_name.clone()),
        );
        obj.insert(
            "created_at".to_string(),
            Value::Number(serde_json::Number::from(device.created_at)),
        );
        obj.insert(
            "updated_at".to_string(),
            Value::Number(serde_json::Number::from(device.updated_at)),
        );
        sanitize_device_info_json_for_export(obj);
    }

    value
}

fn sanitize_device_info_json_for_export(obj: &mut serde_json::Map<String, Value>) {
    let mut exportable_ips = Vec::new();

    if let Some(ip_str) = obj.get("ip").and_then(|v| v.as_str()) {
        if let Some(ip) = parse_ip_or_socket_addr(ip_str) {
            push_exportable_device_ip(&mut exportable_ips, ip);
        }
    }

    for key in ["ips", "all_ip"] {
        if let Some(ip_values) = obj.get(key).and_then(|v| v.as_array()) {
            for ip_str in ip_values.iter().filter_map(|v| v.as_str()) {
                if let Some(ip) = parse_ip_or_socket_addr(ip_str) {
                    push_exportable_device_ip(&mut exportable_ips, ip);
                }
            }
        }
    }

    if let Some(first_ip) = exportable_ips.first() {
        obj.insert("ip".to_string(), Value::String(first_ip.to_string()));
    } else {
        obj.remove("ip");
    }

    let exportable_ip_values: Vec<Value> = exportable_ips
        .iter()
        .map(|ip| Value::String(ip.to_string()))
        .collect();
    for key in ["ips", "all_ip"] {
        if obj.contains_key(key) {
            obj.insert(key.to_string(), Value::Array(exportable_ip_values.clone()));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnRpcPath {
    Root,
    Auth,
    DeviceInfo,
    InternalRoot,
}

fn parse_ip_or_socket_addr(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

fn get_request_client_ip(
    req: &http::Request<BoxBody<Bytes, ServerError>>,
    info: &StreamInfo,
) -> Option<IpAddr> {
    req.extensions()
        .get::<HttpRequestProcessChainVars>()
        .and_then(|vars| vars.req_real_remote_ip.as_deref())
        .and_then(parse_ip_or_socket_addr)
        .or_else(|| {
            info.real_src_addr
                .as_deref()
                .and_then(parse_ip_or_socket_addr)
        })
        .or_else(|| info.src_addr.as_deref().and_then(parse_ip_or_socket_addr))
}

impl SnRpcPath {
    fn parse(path: &str) -> Option<Self> {
        match path {
            "/" => Some(Self::InternalRoot),
            "/kapi/sn" => Some(Self::Root),
            "/kapi/sn/auth" => Some(Self::Auth),
            "/kapi/sn/deviceinfo" => Some(Self::DeviceInfo),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "/kapi/sn",
            Self::Auth => "/kapi/sn/auth",
            Self::DeviceInfo => "/kapi/sn/deviceinfo",
            Self::InternalRoot => "/",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OODInfo {
    //pub device_info: DeviceInfo,
    pub did_hostname: String,
    pub owner_id: String,
    pub self_cert: bool,
    pub state: String, //active,suspended,disabled,banned
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RegisteredDeviceKey {
    zone: String,
    device_name: String,
}

struct LegacySnDidResolver {
    resolver: SnResolverRef,
}

impl LegacySnDidResolver {
    fn new(resolver: SnResolverRef) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl SnDidResolver for LegacySnDidResolver {
    async fn resolve(
        &self,
        request: SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let mut resolution = self
            .resolver
            .resolve_did(&request.did, request.doc_type(), request.from_ip)
            .await?;
        resolution.profile = request.profile;
        resolution.document_status = match request.profile {
            SnDidResolverProfile::PublicSupplement => None,
            SnDidResolverProfile::InternalZoneResolver => {
                Some(crate::sn_did_resolver::SnDidDocumentStatus::Active)
            }
        };
        Ok(resolution)
    }
}

#[derive(Clone)]
pub struct SNServer {
    id: String,
    server_host: String,
    auth_db: SnAuthDBRef,
    device_info_db: SnDeviceInfoDBRef,
    compat_store: SnCompatibilityStoreRef,
    auth: Arc<SnAuthManager>,
    name_info_cache: NameInfoCacheRef,
    resolver: SnResolverRef,
    did_resolver: SnDidResolverRef,
    bns_controller: Option<Arc<SnBnsController>>,
}

impl SNServer {
    fn rewrite_rpc_method(mut req: RPCRequest, method: &str) -> RPCRequest {
        req.method = method.to_string();
        req
    }

    fn canonical_method_name(method: &str) -> String {
        method.to_string()
    }

    fn preferred_rpc_path(method: &str) -> SnRpcPath {
        match method {
            method if method.starts_with("auth.") => SnRpcPath::Auth,
            "user.get_profile"
            | "user.set_self_cert"
            | "user.add_dns_record"
            | "user.remove_dns_record"
            | "user.list_dns_records"
            | "domain.begin_verify"
            | "domain.create_pkx_binding"
            | "domain.verify"
            | "domain.verify_pkx_binding"
            | "domain.unbind" => SnRpcPath::Auth,
            "device.register"
            | "device.update"
            | "device.get"
            | "device.list"
            | "deviceinfo.resolve_ood_by_did"
            | "deviceinfo.resolve_ood_by_hostname" => SnRpcPath::DeviceInfo,
            "admin.clear_state_by_active_code" => SnRpcPath::InternalRoot,
            _ => SnRpcPath::Root,
        }
    }

    fn reserved_user_names_file() -> PathBuf {
        std::env::var_os(RESERVED_USER_NAMES_FILE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| get_buckyos_service_data_dir("sn").join(RESERVED_USER_NAMES_FILE))
    }

    fn load_reserved_user_names() -> HashSet<String> {
        let path = Self::reserved_user_names_file();
        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                if path.exists() {
                    warn!(
                        "failed to read reserved user names file {}: {}",
                        path.display(),
                        err
                    );
                } else {
                    debug!("reserved user names file not found: {}", path.display());
                }
                return HashSet::new();
            }
        };

        content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_lowercase())
            .collect()
    }

    pub(crate) fn validate_registration_username(
        username: &str,
    ) -> std::result::Result<(), String> {
        if username.is_empty() {
            return Err("username is empty".to_string());
        }
        if username.contains('.') {
            return Err("username does not meet naming rules".to_string());
        }
        if !is_valid_name(username, NameType::User) {
            return Err("username does not meet naming rules".to_string());
        }
        if canonical_bns_name(username).is_err() {
            return Err("username does not meet naming rules".to_string());
        }
        if Self::load_reserved_user_names().contains(username) {
            return Err("username is reserved by server".to_string());
        }
        Ok(())
    }

    fn is_method_allowed_on_path(method: &str, path: SnRpcPath) -> bool {
        match path {
            SnRpcPath::Auth | SnRpcPath::DeviceInfo | SnRpcPath::InternalRoot => {
                Self::preferred_rpc_path(method) == path
            }
            SnRpcPath::Root => false,
        }
    }

    fn extract_missing_field_name(err: &str) -> Option<String> {
        for marker in ["missing field `", "missing field '"] {
            if let Some(start) = err.find(marker) {
                let value_start = start + marker.len();
                let tail = &err[value_start..];
                if let Some(end) = tail.find(['`', '\'']) {
                    let field = tail[..end].trim();
                    if !field.is_empty() {
                        return Some(field.to_string());
                    }
                }
            }
        }

        None
    }

    pub async fn new(
        server_config: SNServerConfig,
        auth_db: SnAuthDBRef,
        device_info_db: SnDeviceInfoDBRef,
        compat_store: SnCompatibilityStoreRef,
        relay_manager: SnRelayManagerRef,
        bns_controller: Option<Arc<SnBnsController>>,
    ) -> Self {
        let bns_indexer_url = server_config.bns_indexer_url.clone();
        let bns_session_token = server_config.bns_session_token.clone();
        let server_host = server_config.host;
        let server_ip = IpAddr::from_str(server_config.ip.as_str()).unwrap();
        let server_aliases = server_config.aliases;
        let boot_jwt = server_config.boot_jwt;
        let owner_pkx = server_config.owner_pkx;
        let device_jwt = server_config.device_jwt;
        let auth = Arc::new(
            SnAuthManager::new(server_config.auth_data_dir.as_deref())
                .await
                .expect("init sn auth manager"),
        );
        let resolver_config = SnResolverConfig::new(
            server_host.clone(),
            server_ip,
            boot_jwt,
            owner_pkx,
            device_jwt,
        )
        .with_aliases(server_aliases);
        let mut resolver = SnResolver::new(
            resolver_config,
            Arc::new(SnAuthResolverReader::new(auth_db.clone())),
        )
        .with_device_online_reader(Arc::new(SnDeviceInfoResolverReader::new(
            device_info_db.clone(),
        )))
        .with_relay_reader(Arc::new(SnRelayManagerResolverReader::new(
            relay_manager.clone(),
        )))
        .with_compatibility_reader(Arc::new(LegacyResolverCompatibilityReader::new(
            auth_db.clone(),
            device_info_db.clone(),
            compat_store.clone(),
        )));
        if let Some(indexer_url) = bns_indexer_url.as_deref() {
            resolver = resolver.with_bns_reader(Arc::new(BnsIndexerDocumentReader::new(
                indexer_url,
                bns_session_token,
            )));
        } else {
            warn!(
                "bns_indexer_url is not configured; SN resolver will use legacy local cache only and cannot lazy-load BNS contract state"
            );
        }
        let resolver = Arc::new(resolver);
        let did_resolver = Arc::new(LegacySnDidResolver::new(resolver.clone()));

        SNServer {
            id: server_config.id,
            server_host,
            auth_db,
            device_info_db,
            compat_store,
            auth,
            name_info_cache: NameInfoCache::new_ref(),
            resolver,
            did_resolver,
            bns_controller,
        }
    }

    pub fn name_info_cache(&self) -> NameInfoCacheRef {
        self.name_info_cache.clone()
    }

    pub fn resolver(&self) -> SnResolverRef {
        self.resolver.clone()
    }

    pub fn did_resolver(&self) -> SnDidResolverRef {
        self.did_resolver.clone()
    }

    pub(crate) fn bns_controller(&self) -> Option<Arc<SnBnsController>> {
        self.bns_controller.clone()
    }

    pub fn add_name_info_cache(
        &self,
        name: &str,
        record_type: RecordType,
        name_info: NameInfo,
        cache_ttl_secs: Option<u32>,
    ) {
        self.name_info_cache
            .add(name, record_type, name_info, cache_ttl_secs);
    }

    pub fn add_name_info_tombstone_cache(
        &self,
        name: &str,
        record_type: RecordType,
        cache_ttl_secs: Option<u32>,
    ) {
        self.name_info_cache
            .add_tombstone(name, record_type, cache_ttl_secs);
    }

    pub fn remove_name_info_cache(&self, name: &str, record_type: RecordType) {
        self.name_info_cache.remove(name, record_type);
    }

    pub(crate) fn parse_name_record_type(record_type: &str) -> Option<RecordType> {
        match record_type.to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "TXT" => Some(RecordType::TXT),
            _ => None,
        }
    }

    fn collect_device_report_ips(ip: &str, description: &str) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(ip) = parse_ip_or_socket_addr(ip) {
            result.push(ip.to_string());
        }

        let value = serde_json::from_str::<Value>(description).ok();
        let mut candidates = Vec::new();
        collect_device_ips_from_legacy_document(value.as_ref(), &mut candidates);
        for ip in candidates {
            let value = ip.to_string();
            if !result.contains(&value) {
                result.push(value);
            }
        }

        result
    }

    pub(crate) async fn upsert_device_online_state(
        &self,
        username: &str,
        device_name: &str,
        did: &str,
        ip: &str,
        description: &str,
        from_ip: Option<IpAddr>,
        extra_endpoints: Vec<SnDeviceEndpointUpdate>,
        report_seq: Option<u64>,
        ttl: Option<u64>,
    ) -> SnResult<()> {
        let role = if device_name == "ood1" {
            SnDeviceRole::Ood
        } else {
            SnDeviceRole::Normal
        };
        self.device_info_db
            .upsert_device_index(did, username, device_name, role)
            .await?;

        let mut reported_ips = Self::collect_device_report_ips(ip, description);
        let reported_ip = reported_ips.first().cloned();
        if reported_ip.is_some() {
            reported_ips.remove(0);
        }

        let endpoint = reported_ip.as_ref().map(|host| SnDeviceEndpointUpdate {
            endpoint_id: "device_report".to_string(),
            protocol: SnEndpointProtocol::Tcp,
            host: host.clone(),
            port: None,
            scope: SnEndpointScope::Public,
            priority: 100,
            source: SnEndpointSource::DeviceReport,
            expires_at: None,
        });
        let mut endpoints = endpoint.into_iter().collect::<Vec<_>>();
        endpoints.extend(extra_endpoints);

        self.device_info_db
            .update_device_state(SnDeviceStateUpdate {
                did: did.to_string(),
                reported_ip,
                reported_ips,
                from_ip: from_ip.map(|ip| ip.to_string()),
                nat_type: SnNatType::Unknown,
                endpoints,
                report_seq,
                ttl: ttl.unwrap_or(300),
                raw_report: serde_json::from_str::<Value>(description)
                    .ok()
                    .map(|_| description.to_string()),
            })
            .await
    }

    fn normalize_query_name(name: &str) -> String {
        if name.ends_with(".") {
            name.trim_end_matches('.').to_string()
        } else {
            name.to_string()
        }
    }

    // 辅助函数：检测字符串是否包含特殊字符
    pub(crate) fn contains_special_chars(s: &str) -> bool {
        s.chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace() && c != '_' && c != '-' && c != '.')
    }

    pub async fn check_active_code(&self, req: RPCRequest) -> Result<RPCResponse, RPCErrors> {
        let active_code = req.params.get("active_code");
        if active_code.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, active_code is none".to_string(),
            ));
        }
        let active_code = active_code.unwrap().as_str();
        if active_code.is_none() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, active_code is none".to_string(),
            ));
        }
        let active_code = active_code.unwrap();
        let ret = self.auth_db.check_active_code(active_code).await;
        if ret.is_err() {
            return Err(RPCErrors::ReasonError(ret.err().unwrap().to_string()));
        }
        let valid = ret.unwrap();
        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "valid":valid
            })),
            &req,
        );
        return Ok(resp);
    }

    pub async fn clear_state_by_active_code(
        &self,
        req: RPCRequest,
    ) -> Result<RPCResponse, RPCErrors> {
        if req.params.get("active_code").is_some() {
            return Err(RPCErrors::ParseRequestError(
                "Invalid params, active_code is not allowed".to_string(),
            ));
        }

        let result = self
            .auth_db
            .clear_state_by_active_code(CLEAR_STATE_ACTIVE_CODE)
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                warn!(
                    "Failed to clear state for activation code {}: {}",
                    CLEAR_STATE_ACTIVE_CODE, err_str
                );
                RPCErrors::ReasonError(err_str)
            })?;

        let resp = RPCResponse::create_by_req(
            RPCResult::Success(json!({
                "code": 0,
                "deleted_users": result.deleted_users,
                "deleted_devices": result.deleted_devices,
                "deleted_domain_records": result.deleted_domain_records,
                "deleted_did_documents": result.deleted_did_documents,
                "activation_code_reset": result.activation_code_reset
            })),
            &req,
        );
        Ok(resp)
    }

    async fn get_device_info(
        &self,
        owner_id: &str,
        device_name: &str,
    ) -> ServerResult<Option<(DeviceInfo, IpAddr)>> {
        let key = format!("{}_{}", owner_id, device_name);
        let device_json = self
            .compat_store
            .query_device_by_name(owner_id, device_name)
            .await;
        if device_json.is_err() {
            warn!(
                "failed to query device info for {} from db: {:?}",
                key,
                device_json.err().unwrap()
            );
            return Ok(None);
        };
        let device_json = device_json.unwrap();
        if device_json.is_none() {
            warn!("device info not found for {} in db", key);
            return Ok(None);
        }
        let device_json = device_json.unwrap();
        let sn_ip = &device_json.ip;
        let sn_ip = IpAddr::from_str(sn_ip.as_str()).unwrap();
        let device_info_json: String = device_json.description.clone();
        //info!("device info json: {}",device_info_json);
        let device_info = serde_json::from_str::<DeviceInfo>(device_info_json.as_str());
        if device_info.is_err() {
            let parse_err = device_info.err().unwrap();
            let parse_err_str = parse_err.to_string();
            if let Some(field) = Self::extract_missing_field_name(parse_err_str.as_str()) {
                warn!(
                    "[schema_compat] failed to parse device info for {}: missing required field `{}`; raw_error={}; please refresh device registration",
                    key,
                    field,
                    parse_err_str
                );
            }
            warn!(
                "failed to parse device info from db for {}: {} (schema/version mismatch)",
                key, parse_err_str
            );
            return Err(server_err!(
                ServerErrorCode::InvalidData,
                "device info schema mismatch for {}: {}",
                key,
                parse_err_str
            ));
        }
        let device_info = device_info.unwrap();
        Ok(Some((device_info.clone(), sn_ip)))
    }
    //return (subhost,username)
    pub fn get_user_subhost_from_host(host: &str, server_host: &str) -> Option<(String, String)> {
        SnResolver::get_user_subhost_from_host(host, server_host)
            .map(|parts| (parts.sub_host, parts.username))
    }

    pub(crate) async fn handle_namespaced_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        info!("sn server handle rpc call: {}", req.method);
        match req.method.as_str() {
            "auth.check_active_code" => {
                handle_auth(self, Self::rewrite_rpc_method(req, "check_active_code")).await
            }
            "auth.check_username" => {
                handle_auth(self, Self::rewrite_rpc_method(req, "check_username")).await
            }
            "auth.register" | "auth.login" | "auth.refresh" | "auth.logout" | "auth.me" => {
                let bare_method = req
                    .method
                    .strip_prefix("auth.")
                    .unwrap_or(req.method.as_str())
                    .to_string();
                handle_auth(self, Self::rewrite_rpc_method(req, bare_method.as_str())).await
            }
            "user.get_profile" | "user.set_self_cert" => {
                let bare_method = req
                    .method
                    .strip_prefix("user.")
                    .unwrap_or(req.method.as_str())
                    .to_string();
                handle_user(self, Self::rewrite_rpc_method(req, bare_method.as_str())).await
            }
            "user.add_dns_record" => {
                handle_dns(self, Self::rewrite_rpc_method(req, "add_record")).await
            }
            "user.remove_dns_record" => {
                handle_dns(self, Self::rewrite_rpc_method(req, "remove_record")).await
            }
            "user.list_dns_records" => {
                handle_dns(self, Self::rewrite_rpc_method(req, "list_records")).await
            }
            "domain.begin_verify"
            | "domain.create_pkx_binding"
            | "domain.verify"
            | "domain.verify_pkx_binding"
            | "domain.unbind" => {
                let bare_method = req
                    .method
                    .strip_prefix("domain.")
                    .unwrap_or(req.method.as_str())
                    .to_string();
                handle_domain(self, Self::rewrite_rpc_method(req, bare_method.as_str())).await
            }
            "device.register" => {
                handle_device(self, Self::rewrite_rpc_method(req, "register"), ip_from).await
            }
            "device.update" => {
                handle_device(self, Self::rewrite_rpc_method(req, "update"), ip_from).await
            }
            "device.get" => {
                handle_device(self, Self::rewrite_rpc_method(req, "get"), ip_from).await
            }
            "device.list" => {
                handle_device(self, Self::rewrite_rpc_method(req, "list"), ip_from).await
            }
            "deviceinfo.resolve_ood_by_hostname" => {
                handle_device(
                    self,
                    Self::rewrite_rpc_method(req, "resolve_ood_by_hostname"),
                    ip_from,
                )
                .await
            }
            "deviceinfo.resolve_ood_by_did" => {
                handle_device(
                    self,
                    Self::rewrite_rpc_method(req, "resolve_ood_by_did"),
                    ip_from,
                )
                .await
            }
            "admin.clear_state_by_active_code" => {
                self.clear_state_by_active_code(Self::rewrite_rpc_method(
                    req,
                    "clear_state_by_active_code",
                ))
                .await
            }
            _ => Err(RPCErrors::UnknownMethod(req.method)),
        }
    }

    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        let canonical_method = Self::canonical_method_name(req.method.as_str());
        self.handle_namespaced_rpc_call(
            Self::rewrite_rpc_method(req, canonical_method.as_str()),
            ip_from,
        )
        .await
    }

    async fn handle_http_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
        path: SnRpcPath,
    ) -> Result<RPCResponse, RPCErrors> {
        let canonical_method = Self::canonical_method_name(req.method.as_str());
        if !Self::is_method_allowed_on_path(canonical_method.as_str(), path) {
            return Err(RPCErrors::UnknownMethod(format!(
                "{} is not available on {}",
                req.method,
                path.as_str()
            )));
        }

        let preferred_path = Self::preferred_rpc_path(canonical_method.as_str());
        if path == SnRpcPath::Root && preferred_path != SnRpcPath::Root {
            warn!(
                "sn rpc method {} hit compatibility path {}; prefer {}",
                canonical_method,
                path.as_str(),
                preferred_path.as_str()
            );
        }

        self.handle_namespaced_rpc_call(
            Self::rewrite_rpc_method(req, canonical_method.as_str()),
            ip_from,
        )
        .await
    }

    pub(crate) async fn resolve_ood_by_did(&self, did: &str) -> Result<OODInfo, RPCErrors> {
        if let Some(view) = self
            .device_info_db
            .get_device_state(did)
            .await
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
        {
            let registered_did = view.did.clone();
            return self
                .ood_info_from_device_state(registered_did.as_str(), view)
                .await;
        }

        if let Some(device_info) = self
            .compat_store
            .query_device_by_did(did)
            .await
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
        {
            let registered_did = device_info.did.clone();
            return self
                .ood_info_from_legacy_device(registered_did.as_str(), device_info)
                .await;
        }

        if let Some(key) = self.registered_device_key_from_did(did).await? {
            let canonical_did = self.canonical_device_did_from_scoped_did(did).await?;
            if let Some(view) = self
                .device_info_db
                .get_device_state_by_name(key.zone.as_str(), key.device_name.as_str())
                .await
                .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
            {
                if let Some(canonical_did) = canonical_did.as_deref() {
                    if canonical_did != view.did.as_str() {
                        return Err(RPCErrors::ParseRequestError(
                            Self::registered_device_did_mismatch(
                                did,
                                canonical_did,
                                view.did.as_str(),
                            ),
                        ));
                    }
                }
                let registered_did = view.did.clone();
                return self
                    .ood_info_from_device_state(registered_did.as_str(), view)
                    .await;
            }

            if let Some(device_info) = self
                .compat_store
                .query_device_by_name(key.zone.as_str(), key.device_name.as_str())
                .await
                .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
            {
                if let Some(canonical_did) = canonical_did.as_deref() {
                    if canonical_did != device_info.did.as_str() {
                        return Err(RPCErrors::ParseRequestError(
                            Self::registered_device_did_mismatch(
                                did,
                                canonical_did,
                                device_info.did.as_str(),
                            ),
                        ));
                    }
                }
                let registered_did = device_info.did.clone();
                return self
                    .ood_info_from_legacy_device(registered_did.as_str(), device_info)
                    .await;
            }
        }

        Err(RPCErrors::ParseRequestError(
            Self::registered_device_not_found(did),
        ))
    }

    async fn ood_info_from_device_state(
        &self,
        did_for_hostname: &str,
        view: crate::SnDeviceStateView,
    ) -> Result<OODInfo, RPCErrors> {
        let user = self
            .auth_db
            .get_user_info(view.zone.as_str())
            .await
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?;
        Ok(OODInfo {
            did_hostname: Self::did_hostname(did_for_hostname),
            owner_id: view.zone,
            self_cert: user.map(|u| u.self_cert).unwrap_or(false),
            state: Self::device_state_to_ood_state(view.state).to_string(),
        })
    }

    async fn ood_info_from_legacy_device(
        &self,
        did_for_hostname: &str,
        device_info: SNDeviceInfo,
    ) -> Result<OODInfo, RPCErrors> {
        let user = self
            .auth_db
            .get_user_info(device_info.owner.as_str())
            .await
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?;
        Ok(OODInfo {
            did_hostname: Self::did_hostname(did_for_hostname),
            owner_id: device_info.owner,
            self_cert: user.map(|u| u.self_cert).unwrap_or(false),
            state: "active".to_string(),
        })
    }

    async fn registered_device_key_from_did(
        &self,
        did: &str,
    ) -> Result<Option<RegisteredDeviceKey>, RPCErrors> {
        let did = match DID::from_str(did) {
            Ok(did) => did,
            Err(_) => return Ok(None),
        };

        match did.method.as_str() {
            "bns" => {
                self.registered_device_key_from_bns_id(did.id.as_str())
                    .await
            }
            "web" => {
                self.registered_device_key_from_web_id(did.id.as_str())
                    .await
            }
            _ => Ok(None),
        }
    }

    async fn registered_device_key_from_bns_id(
        &self,
        id: &str,
    ) -> Result<Option<RegisteredDeviceKey>, RPCErrors> {
        let id = Self::normalize_did_name(id);
        let Some((device_name, zone_ref)) = id.split_once('.') else {
            return Ok(None);
        };
        if device_name.is_empty() || zone_ref.is_empty() {
            return Ok(None);
        }

        let zone = if zone_ref.contains('.') {
            let Some(user) = self
                .auth_db
                .get_user_by_domain(zone_ref)
                .await
                .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
            else {
                return Ok(None);
            };
            let Some(username) = user.username else {
                return Ok(None);
            };
            username
        } else {
            zone_ref.to_string()
        };

        Ok(Self::registered_device_key(zone, device_name.to_string()))
    }

    async fn registered_device_key_from_web_id(
        &self,
        id: &str,
    ) -> Result<Option<RegisteredDeviceKey>, RPCErrors> {
        let id = Self::normalize_did_name(id);
        let Some(user) = self
            .auth_db
            .get_user_by_domain(id.as_str())
            .await
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
        else {
            return Ok(None);
        };
        let Some(zone) = user.username else {
            return Ok(None);
        };
        let Some(user_domain) = user.user_domain else {
            return Ok(None);
        };
        let user_domain = Self::normalize_did_name(user_domain.as_str());
        if id == user_domain {
            return Ok(None);
        }

        let suffix = format!(".{}", user_domain);
        let Some(device_name) = id.strip_suffix(suffix.as_str()) else {
            return Ok(None);
        };

        Ok(Self::registered_device_key(zone, device_name.to_string()))
    }

    fn registered_device_key(zone: String, device_name: String) -> Option<RegisteredDeviceKey> {
        if zone.trim().is_empty() || device_name.trim().is_empty() {
            return None;
        }

        Some(RegisteredDeviceKey { zone, device_name })
    }

    fn normalize_did_name(value: &str) -> String {
        value.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    async fn canonical_device_did_from_scoped_did(
        &self,
        did: &str,
    ) -> Result<Option<String>, RPCErrors> {
        let did = match DID::from_str(did) {
            Ok(did) => did,
            Err(_) => return Ok(None),
        };
        if did.method != "bns" && did.method != "web" {
            return Ok(None);
        }
        let did_string = did.to_string();

        let resolution = match self
            .did_resolver
            .resolve(SnDidResolveRequest::new(
                did,
                Some("doc".to_string()),
                None,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
        {
            Ok(resolution) => resolution,
            Err(e) => {
                debug!(
                    "skip canonical device DID check for {}: resolver failed: {}",
                    did_string, e
                );
                return Ok(None);
            }
        };

        let value = match resolution.document.to_json_value() {
            Ok(value) => value,
            Err(e) => {
                debug!(
                    "skip canonical device DID check for {}: document decode failed: {}",
                    did_string, e
                );
                return Ok(None);
            }
        };

        Ok(Self::device_did_from_document(&value))
    }

    fn device_did_from_document(value: &Value) -> Option<String> {
        for key in ["did", "id"] {
            if let Some(did) = value.get(key).and_then(|v| v.as_str()) {
                if !did.trim().is_empty() {
                    return Some(did.trim().to_string());
                }
            }
        }

        value
            .get("x")
            .and_then(|v| v.as_str())
            .filter(|x| !x.trim().is_empty())
            .map(|x| format!("did:dev:{}", x.trim()))
    }

    fn registered_device_not_found(did: &str) -> String {
        format!(
            "registered device not found for source_device_id={did}; \
             deviceinfo.resolve_ood_by_did checks the exact DID first, then for \
             did:bns:<device>.<zone> or did:web:<device>.<domain> checks the \
             registered device binding by zone and device_name. Prefer passing the \
             canonical did:dev device DID after registration; scoped BNS/Web device \
             DIDs are accepted as compatibility aliases. Verify the SN sqlite \
             devices/device_indexes tables contain a device registered for the same \
             public key, device name, and zone."
        )
    }

    fn registered_device_did_mismatch(
        query_did: &str,
        resolved_did: &str,
        registered_did: &str,
    ) -> String {
        format!(
            "registered device DID mismatch for source_device_id={query_did}; \
             scoped DID resolves to canonical device DID {resolved_did}, but the \
             registered device binding points to {registered_did}."
        )
    }

    fn did_hostname(did: &str) -> String {
        DID::from_str(did)
            .map(|did| did.to_host_name())
            .unwrap_or_else(|_| did.to_string())
    }

    fn device_state_to_ood_state(state: SnDeviceState) -> &'static str {
        match state {
            SnDeviceState::Online => "active",
            SnDeviceState::Offline | SnDeviceState::Stale => "suspended",
            SnDeviceState::Blocked => "banned",
        }
    }

    pub(crate) async fn query_device_by_hostname(&self, req_host: &str) -> Option<OODInfo> {
        match self.resolver.resolve_gateway_by_hostname(req_host).await {
            Ok(gateway) => {
                let did_hostname = DID::from_str(gateway.gateway_did.as_str())
                    .map(|did| did.to_host_name())
                    .unwrap_or_else(|_| gateway.gateway_did.clone());
                let state = gateway
                    .online
                    .as_ref()
                    .map(|online| Self::device_state_to_ood_state(online.state))
                    .unwrap_or("active");
                return Some(OODInfo {
                    did_hostname,
                    owner_id: gateway.zone_name,
                    self_cert: gateway.self_cert,
                    state: state.to_string(),
                });
            }
            Err(e) if e.kind() != SnResolverErrorKind::NotManaged => {
                warn!("sn_resolver hostname query failed for {}: {}", req_host, e);
            }
            Err(_) => {}
        }

        let get_result = SNServer::get_user_subhost_from_host(req_host, &self.server_host);
        if get_result.is_some() {
            let (_, username) = get_result.unwrap();
            let user_info = self.auth_db.get_user_info(username.as_str()).await;
            if user_info.is_err() {
                warn!("get user info error: {}", user_info.err().unwrap());
                return None;
            }
            let user_info = user_info.unwrap();
            if user_info.is_none() {
                warn!("user info not found for {}", username);
                return None;
            }
            let user_info = user_info.unwrap();

            let device_info = match self.get_device_info(username.as_str(), "ood1").await {
                Ok(info) => info,
                Err(e) => {
                    warn!("ood1 device info parse failed for {}: {}", username, e);
                    None
                }
            };
            if device_info.is_some() {
                info!("ood1 device info found for {} in sn server", username);
                //let device_did = device_info.unwrap().0.did;
                let (device_info, _) = device_info.unwrap();
                let did_hostname = device_info.id.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.clone(),
                    self_cert: user_info.self_cert,
                    state: "active".to_string(),
                };
                return Some(ood_info);
            } else {
                warn!("ood1 device info not found for {} in sn server", username);
            }
        } else {
            let user_info = self.auth_db.get_user_by_domain(req_host).await;
            if user_info.is_err() {
                info!(
                    "failed to get user info by domain: {}",
                    user_info.err().unwrap()
                );
                return None;
            }
            let user_info = user_info.unwrap();
            if user_info.is_none() {
                return None;
            }
            let user_info = user_info.unwrap();
            let username = user_info.username.as_ref().unwrap();
            let device_info = match self.get_device_info(username.as_str(), "ood1").await {
                Ok(info) => info,
                Err(e) => {
                    warn!("ood1 device info parse failed for {}: {}", username, e);
                    None
                }
            };
            if device_info.is_some() {
                //info!("ood1 device info found for {} in sn server",username);
                //let device_did = device_info.unwrap().0.did;
                let device_did = device_info.as_ref().unwrap().0.id.clone();
                let did_hostname = device_did.to_host_name();
                let ood_info = OODInfo {
                    did_hostname: did_hostname,
                    owner_id: username.to_string(),
                    self_cert: user_info.self_cert,
                    state: "active".to_string(),
                };
                //info!("select device {} for http upstream:{}",device_did.as_str(),result_str.as_str());
                return Some(ood_info);
            } else {
                warn!("ood1 device info not found for {} in sn server", username);
            }
        }

        return None;
    }

    pub fn create_name_info_from_zone_config(
        &self,
        zone_config: &str,
        public_key: &str,
        device_jwt: Option<&String>,
    ) -> NameInfo {
        let mut name_info = NameInfo::default();
        if public_key.starts_with("{") {
            let public_key_json = serde_json::from_str(public_key);
            if public_key_json.is_ok() {
                let public_key_json: Value = public_key_json.unwrap();
                let x = public_key_json.get("x");
                if x.is_some() {
                    let x = x.unwrap().as_str().unwrap();
                    name_info.txt.push(format!("PKX={};", x));
                }
            }
        } else {
            name_info.txt.push(format!("PKX={};", public_key));
        }
        name_info.txt.push(format!("BOOT={};", zone_config));
        if device_jwt.is_some() {
            name_info
                .txt
                .push(format!("DEV={};", device_jwt.as_ref().unwrap().as_str()));
        }
        return name_info;
    }

    fn builder_error_http_response(
        status: StatusCode,
        msg: String,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        Ok(Response::builder()
            .status(status)
            .header("Access-Control-Allow-Origin", "*")
            .body(BoxBody::new(
                Full::new(Bytes::from(msg))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .unwrap())
    }

    pub(crate) fn auth_db(&self) -> &SnAuthDBRef {
        &self.auth_db
    }

    pub(crate) fn compat_store(&self) -> &SnCompatibilityStoreRef {
        &self.compat_store
    }

    pub(crate) fn device_info_db(&self) -> &SnDeviceInfoDBRef {
        &self.device_info_db
    }

    pub(crate) fn auth(&self) -> Arc<SnAuthManager> {
        self.auth.clone()
    }
}

#[async_trait]
impl QAServer for SNServer {
    async fn serve_question(&self, req: &serde_json::Value) -> ServerResult<serde_json::Value> {
        let rpc_request = qa_json_to_rpc_request(req);
        if rpc_request.is_err() {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "invalid request"
            ));
        }
        let rpc_request = rpc_request.unwrap();
        let rpc_response = self
            .handle_rpc_call(rpc_request, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await;
        let rpc_response = match rpc_response {
            Ok(response) => response,
            Err(e) => {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "failed to handle rpc call: {}",
                    e
                ))
            }
        };
        match rpc_response.result {
            RPCResult::Success(result) => {
                return Ok(result);
            }
            RPCResult::Failed(error) => {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "failed to handle rpc call: {}",
                    error
                ));
            }
        }
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

#[async_trait]
impl NameServer for SNServer {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn query(
        &self,
        name: &str,
        record_type: Option<RecordType>,
        _from_ip: Option<IpAddr>,
    ) -> ServerResult<NameInfo> {
        info!(
            "sn server process name query: {} record_type: {:?}",
            name, record_type
        );
        let record_type = record_type.unwrap_or_default();
        let req_real_name = Self::normalize_query_name(name);

        match self
            .name_info_cache
            .query(req_real_name.as_str(), record_type)
        {
            Some(NameInfoCacheQueryResult::Hit(name_info)) => {
                info!(
                    "sn server name cache hit: {} record_type: {:?}",
                    req_real_name, record_type
                );
                return Ok(name_info);
            }
            Some(NameInfoCacheQueryResult::Tombstone) => {
                info!(
                    "sn server name cache tombstone hit: {} record_type: {:?}",
                    req_real_name, record_type
                );
                return Err(server_err!(
                    ServerErrorCode::NotFound,
                    "no address found for {}",
                    name.to_string()
                ));
            }
            None => {}
        }

        info!(
            "sn server name cache miss: {} record_type: {:?}",
            req_real_name, record_type
        );
        match self
            .resolver
            .resolve_dns(req_real_name.as_str(), record_type)
            .await
        {
            Ok(resolution) => {
                let name_info = resolution.into_name_info(name);
                let cache_ttl_secs = name_info.ttl;
                self.name_info_cache.add(
                    req_real_name.as_str(),
                    record_type,
                    name_info.clone(),
                    cache_ttl_secs,
                );
                Ok(name_info)
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
                self.name_info_cache
                    .add_tombstone(req_real_name.as_str(), record_type, None);
                Err(server_err!(
                    ServerErrorCode::NotFound,
                    "no address found for {}",
                    name.to_string()
                ))
            }
            Err(e) => Err(e.to_server_error()),
        }
    }

    async fn query_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        from_ip: Option<IpAddr>,
    ) -> ServerResult<EncodedDocument> {
        self.did_resolver
            .resolve(SnDidResolveRequest::new(
                did.clone(),
                normalize_sn_did_doc_type(doc_type),
                from_ip,
                SnDidResolverProfile::InternalZoneResolver,
            ))
            .await
            .map(|resolution| resolution.document)
            .map_err(|e| e.to_server_error())
    }
}

#[async_trait]
impl HttpServer for SNServer {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }

    async fn serve_request(
        &self,
        request: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        // Handle OPTIONS preflight request for CORS
        if request.method() == Method::OPTIONS {
            return Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                .header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                )
                .header("Access-Control-Max-Age", "86400")
                .body(BoxBody::new(
                    Full::new(Bytes::new()).map_err(|e| match e {}).boxed(),
                ))
                .unwrap());
        }

        let path = request.uri().path().to_string();
        if path.starts_with(SN_DID_RESOLVER_ROUTE_PREFIX) && request.method() == Method::GET {
            let did_str = path
                .trim_start_matches(SN_DID_RESOLVER_ROUTE_PREFIX)
                .to_string();
            if did_str.is_empty() {
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "invalid did in path"
                ));
            }

            let mut doc_type: Option<String> = None;
            let mut iat: Option<String> = None;
            if let Some(query) = request.uri().query() {
                for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                    match key.as_ref() {
                        "type" => {
                            doc_type = normalize_sn_did_doc_type(Some(value.as_ref()));
                        }
                        "iat" => {
                            let value = value.trim();
                            if !value.is_empty() {
                                iat = Some(value.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }

            let did = DID::from_str(did_str.as_str()).map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "invalid did '{}': {}",
                    did_str,
                    e
                )
            })?;

            let from_ip = get_request_client_ip(&request, &info);
            let accept = request
                .headers()
                .get(http::header::ACCEPT)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string());

            let mut resolve_request = SnDidResolveRequest::new(
                did,
                doc_type,
                from_ip,
                SnDidResolverProfile::PublicSupplement,
            );
            resolve_request.accept = accept;
            resolve_request.iat = iat;

            match self.did_resolver.resolve(resolve_request).await {
                Ok(resolution) => {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Content-Type", resolution.content_type())
                        .body(BoxBody::new(
                            Full::new(Bytes::from(resolution.body()))
                                .map_err(|never| match never {})
                                .boxed(),
                        ))
                        .unwrap());
                }
                Err(e) => {
                    let status = match e.kind() {
                        SnResolverErrorKind::NotManaged
                        | SnResolverErrorKind::NameNotFound
                        | SnResolverErrorKind::DocumentNotFound
                        | SnResolverErrorKind::DeviceNotFound => StatusCode::NOT_FOUND,
                        SnResolverErrorKind::InvalidHostname
                        | SnResolverErrorKind::InvalidDid
                        | SnResolverErrorKind::UnsupportedRecordType
                        | SnResolverErrorKind::UnsupportedDidMethod => StatusCode::BAD_REQUEST,
                        SnResolverErrorKind::BackendUnavailable => {
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    };
                    return Self::builder_error_http_response(status, e.to_string());
                }
            }
        }

        if request.method() != Method::POST {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Access-Control-Allow-Origin", "*")
                .body(BoxBody::new(
                    Full::new(Bytes::from_static(b"Method Not Allowed"))
                        .map_err(|e| match e {})
                        .boxed(),
                ))
                .unwrap());
        }

        let rpc_path = match SnRpcPath::parse(&path) {
            Some(rpc_path) => rpc_path,
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(BoxBody::new(
                        Full::new(Bytes::from_static(b"Not Found"))
                            .map_err(|e| match e {})
                            .boxed(),
                    ))
                    .unwrap());
            }
        };

        let client_ip = match get_request_client_ip(&request, &info) {
            Some(ip) => ip,
            None => {
                error!("Failed to get client ip");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from_static(b"Bad Request")))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap());
            }
        };

        let body_bytes = match request.collect().await {
            Ok(data) => data.to_bytes(),
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to read body: {:?}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        let body_str = match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to convert body to string: {}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        info!("|==>recv kRPC req: {}", body_str);

        let rpc_request: RPCRequest = match serde_json::from_str(body_str.as_str()) {
            Ok(rpc_request) => rpc_request,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header("Access-Control-Allow-Origin", "*")
                    .body(
                        BoxBody::new(Full::new(Bytes::from(format!(
                            "Failed to parse request body to RPCRequest: {}",
                            e
                        ))))
                        .map_err(|e| match e {})
                        .boxed(),
                    )
                    .unwrap());
            }
        };

        let canonical_method = Self::canonical_method_name(rpc_request.method.as_str());
        let prefer_rpc_failed = canonical_method.contains('.');
        let rpc_seq = rpc_request.seq;
        let rpc_trace_id = rpc_request.trace_id.clone();
        let resp = match self
            .handle_http_rpc_call(rpc_request, client_ip, rpc_path)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                if prefer_rpc_failed {
                    warn!("Failed to handle namespaced rpc call: {}", e);
                    RPCResponse {
                        result: RPCResult::Failed(e.to_string()),
                        seq: rpc_seq,
                        trace_id: rpc_trace_id,
                    }
                } else {
                    let msg = format!("Failed to handle rpc call: {}", e);
                    error!("{}", msg);
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("Access-Control-Allow-Origin", "*")
                        .body(
                            BoxBody::new(Full::new(Bytes::from(msg)))
                                .map_err(|e| match e {})
                                .boxed(),
                        )
                        .unwrap());
                }
            }
        };

        //parse resp to Response<Body>
        let response_builder = Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header(
                "Access-Control-Allow-Headers",
                "Content-Type, Authorization",
            )
            .header("Access-Control-Max-Age", "86400");

        Ok(response_builder
            .body(BoxBody::new(
                Full::new(Bytes::from(serde_json::to_string(&resp).unwrap()))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
            .unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNServerConfig {
    pub id: String,
    pub host: String,
    pub ip: String,
    pub boot_jwt: String,
    pub owner_pkx: String,
    pub device_jwt: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_indexer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_session_token: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_write_enabled: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn_controller_principal: Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn_controller_kid: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_controller_doc_types: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_evm: Option<SNBnsEvmConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_type: Option<String>,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNBnsEvmConfig {
    pub rpc_endpoint: String,
    pub chain_id: u64,
    pub contract_address: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_private_key_env: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_private_key_file: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller_private_key: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<u128>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<u128>,
}

impl ServerConfig for SNServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "sn".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

pub struct SnServerFactory;

impl SnServerFactory {
    pub fn new() -> Self {
        SnServerFactory
    }

    fn sqlite_db_path(config: &SNServerConfig) -> String {
        let configured = config.db_params.as_ref().and_then(|params| {
            params
                .get("db_path")
                .or_else(|| {
                    params
                        .get("db_params")
                        .and_then(|value| value.get("db_path"))
                })
                .and_then(Value::as_str)
        });

        configured.map(ToString::to_string).unwrap_or_else(|| {
            get_buckyos_service_data_dir("sn")
                .join("sn.sqlite3")
                .to_string_lossy()
                .to_string()
        })
    }

    fn parse_sn_controller_principal(config: &SNServerConfig) -> ServerResult<Principal> {
        let Some(value) = config.sn_controller_principal.as_ref() else {
            return Ok(Principal::chain_account(format!("sn:{}", config.id)));
        };

        if let Some(principal) = value.as_str() {
            return Ok(Principal::chain_account(principal));
        }

        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("chain_account");
        let principal_value = value
            .get("value")
            .and_then(Value::as_str)
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "sn_controller_principal.value is required"
            ))?;

        match kind {
            "chain_account" | "chain" | "account" | "eth" => {
                Ok(Principal::chain_account(principal_value))
            }
            "bns_name" | "bns" => Principal::bns_name(principal_value).map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid sn_controller_principal bns_name: {}",
                    e
                )
            }),
            "unset" => Ok(Principal {
                kind: PrincipalKind::Unset,
                value: String::new(),
            }),
            other => Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "unsupported sn_controller_principal.kind {}",
                other
            )),
        }
    }

    fn parse_bns_evm_client_config(
        config: &SNServerConfig,
    ) -> ServerResult<Option<BnsEvmClientConfig>> {
        let Some(evm) = config.bns_evm.as_ref() else {
            return Ok(None);
        };
        let mut client = BnsEvmClientConfig::anvil(
            evm.rpc_endpoint.clone(),
            evm.contract_address.clone(),
            evm.chain_id,
        );
        if let Some(gas_limit) = evm.gas_limit {
            client.gas_limit = gas_limit;
        }
        if let Some(max_fee_per_gas) = evm.max_fee_per_gas {
            client.max_fee_per_gas = max_fee_per_gas;
        }
        if let Some(max_priority_fee_per_gas) = evm.max_priority_fee_per_gas {
            client.max_priority_fee_per_gas = max_priority_fee_per_gas;
        }
        Ok(Some(client))
    }

    fn load_bns_evm_controller_private_key(
        config: &SNServerConfig,
    ) -> ServerResult<Option<String>> {
        let Some(evm) = config.bns_evm.as_ref() else {
            return Ok(None);
        };

        if let Some(env_name) = evm.controller_private_key_env.as_deref() {
            let value = std::env::var(env_name).map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "read bns_evm.controller_private_key_env {} failed: {}",
                    env_name,
                    e
                )
            })?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "bns_evm.controller_private_key_env {} is empty",
                    env_name
                ));
            }
            return Ok(Some(value));
        }

        if let Some(path) = evm.controller_private_key_file.as_deref() {
            let value = fs::read_to_string(path).map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "read bns_evm.controller_private_key_file {} failed: {}",
                    path,
                    e
                )
            })?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "bns_evm.controller_private_key_file {} is empty",
                    path
                ));
            }
            return Ok(Some(value));
        }

        Ok(evm
            .controller_private_key
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()))
    }

    fn build_bns_controller(
        config: &SNServerConfig,
        db_path: &str,
    ) -> ServerResult<Option<Arc<SnBnsController>>> {
        let write_enabled = config
            .bns_write_enabled
            .unwrap_or_else(|| config.bns_indexer_url.is_some());
        if !write_enabled {
            return Ok(None);
        }
        let evm_config = Self::parse_bns_evm_client_config(config)?;
        let evm_controller = if let Some(evm_config) = evm_config {
            let private_key = Self::load_bns_evm_controller_private_key(config)?.ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "bns_evm requires controller_private_key_env, controller_private_key_file or controller_private_key"
            ))?;
            Some(Arc::new(
                BnsEvmControllerClient::new(evm_config, private_key.as_str()).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "create bns evm controller failed: {}",
                        e
                    )
                })?,
            ))
        } else {
            None
        };

        let indexer_url = config.bns_indexer_url.as_deref().ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "bns_write_enabled requires bns_indexer_url"
        ))?;
        let principal = if config.sn_controller_principal.is_none() {
            evm_controller
                .as_ref()
                .and_then(|controller| controller.default_signer_address())
                .map(|address| Principal::chain_account(format!("{address:#x}")))
                .unwrap_or(Self::parse_sn_controller_principal(config)?)
        } else {
            Self::parse_sn_controller_principal(config)?
        };
        let mut controller_config = SnBnsControllerConfig::new(
            principal,
            config.sn_controller_kid.clone().unwrap_or_default(),
        );
        if let Some(doc_types) = config.allowed_controller_doc_types.clone() {
            controller_config.allowed_controller_doc_types = doc_types;
        }
        let client: Arc<dyn BnsIndexerApi> = Arc::new(BnsIndexerClient::new_krpc_url(
            indexer_url,
            config.bns_session_token.clone(),
        ));
        let store = Arc::new(SqliteSnBnsWriteRequestStore::open(db_path).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "open sn bns write request store failed: {}",
                e
            )
        })?);
        let evm_controller = evm_controller.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "bns_write_enabled requires bns_evm because SN BNS writes must go through the EVM contract"
        ))?;
        let controller = SnBnsController::new_evm(client, store, controller_config, evm_controller)
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "create sn bns controller failed: {}",
                    e
                )
            })?;
        Ok(Some(Arc::new(controller)))
    }
}

#[async_trait::async_trait]
impl ServerFactory for SnServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<SNServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid SNServer config {}",
                config.server_type()
            ))?;

        let db_type = config
            .db_type
            .clone()
            .unwrap_or_else(|| "sqlite".to_string());
        if db_type != "sqlite" {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid db type {}",
                db_type
            ));
        }

        let db_path = Self::sqlite_db_path(config);
        let auth_db = SqliteSnAuthDB::new_by_path(db_path.as_str())
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "open sn auth db failed: {}",
                    e
                )
            })?;
        auth_db.initialize_database().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "initialize sn auth db failed: {}",
                e
            )
        })?;
        let auth_db: SnAuthDBRef = Arc::new(auth_db);

        let device_info_db = SqliteSnDeviceInfoDB::new_by_path(db_path.as_str())
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "open sn device info db failed: {}",
                    e
                )
            })?;
        device_info_db.initialize_database().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "initialize sn device info db failed: {}",
                e
            )
        })?;
        let device_info_db: SnDeviceInfoDBRef = Arc::new(device_info_db);

        let compat_store = SqliteSnCompatibilityStore::new_by_path(db_path.as_str())
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "open sn compatibility store failed: {}",
                    e
                )
            })?;
        compat_store.initialize_database().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "initialize sn compatibility store failed: {}",
                e
            )
        })?;
        let compat_store: SnCompatibilityStoreRef = Arc::new(compat_store);

        let relay_manager = SqliteSnRelayManager::new_by_path(db_path.as_str())
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "open sn relay manager failed: {}",
                    e
                )
            })?
            .with_auth_db(auth_db.clone())
            .with_device_info_db(device_info_db.clone());
        relay_manager.initialize_database().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "initialize sn relay manager failed: {}",
                e
            )
        })?;
        let relay_manager: SnRelayManagerRef = Arc::new(relay_manager);
        let bns_controller = Self::build_bns_controller(config, db_path.as_str())?;

        let sn = Arc::new(
            SNServer::new(
                config.clone(),
                auth_db,
                device_info_db,
                compat_store,
                relay_manager,
                bns_controller,
            )
            .await,
        );
        Ok(vec![
            Server::NameServer(sn.clone()),
            Server::Http(sn.clone()),
            Server::QA(sn.clone()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SnAuthDB;
    use buckyos_kit::init_logging;
    use cyfs_gateway_lib::hyper_serve_http;
    use std::time::SystemTime;
    use tokio::net::{TcpListener, TcpStream};

    const TEST_USER: &str = "testuser";
    const TEST_ROOT_USER: &str = "testroot";
    const TEST_LEGACY_USER: &str = "testlegacy";
    const ANVIL_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

    async fn spawn_test_http_server(http_server: Arc<dyn HttpServer>) -> SocketAddr {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let http_server = http_server.clone();
                let stream_info = StreamInfo::new(addr.to_string());
                tokio::spawn(async move {
                    let ret = hyper_serve_http(Box::new(stream), http_server, stream_info).await;
                    if let Err(e) = ret {
                        warn!("hyper_serve_http returned error: {}", e);
                    }
                });
            }
        });

        wait_for_tcp(addr).await;
        addr
    }

    async fn wait_for_tcp(addr: SocketAddr) {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("test HTTP server did not become ready at {}", addr);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn test_split_host_name() {
        let req_host = "home.lzc.web3.buckyos.io".to_string();
        let server_host = "web3.buckyos.io".to_string();
        let end_string = format!(".{}", server_host.as_str());
        if req_host.ends_with(&end_string) {
            let sub_name = req_host[0..req_host.len() - end_string.len()].to_string();
            //split sub_name by "."
            let subs: Vec<&str> = sub_name.split(".").collect();
            let username = subs.last();
            if username.is_none() {
                warn!("invalid username for sn tunnel selector {}", req_host);
                return;
            }
            let username = username.unwrap().to_string();
            assert_eq!(username, "lzc".to_string());
            println!("username: {}", username);
        }
    }

    #[test]
    fn sn_config_accepts_bns_evm_settings() {
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_evm": {
                "rpc_endpoint": "http://127.0.0.1:8545",
                "chain_id": 31337,
                "contract_address": "0x2222222222222222222222222222222222222222",
                "controller_private_key": ANVIL_PRIVATE_KEY,
                "gas_limit": 1234567
            }
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let evm = SnServerFactory::parse_bns_evm_client_config(&config)
            .unwrap()
            .unwrap();

        assert_eq!(evm.rpc_endpoint, "http://127.0.0.1:8545");
        assert_eq!(evm.chain_id, 31337);
        assert_eq!(
            evm.contract_address,
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(evm.gas_limit, 1234567);
        assert_eq!(
            SnServerFactory::load_bns_evm_controller_private_key(&config)
                .unwrap()
                .as_deref(),
            Some(ANVIL_PRIVATE_KEY)
        );
    }

    #[test]
    fn sn_bns_controller_uses_evm_signer_as_default_principal() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_write_enabled": true,
            "bns_indexer_url": "http://127.0.0.1:18080",
            "bns_evm": {
                "rpc_endpoint": "http://127.0.0.1:8545",
                "chain_id": 31337,
                "contract_address": "0x2222222222222222222222222222222222222222",
                "controller_private_key": ANVIL_PRIVATE_KEY
            }
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let controller =
            SnServerFactory::build_bns_controller(&config, db.path().to_str().unwrap())
                .unwrap()
                .unwrap();

        assert_eq!(
            controller.config().sn_controller_principal,
            Principal::chain_account(ANVIL_ADDRESS)
        );
    }

    #[test]
    fn test_get_user_subhost_from_host() {
        let server_host = "buckyos.io".to_string();
        let req_host = "home.lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "home.lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "www-lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "www-lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let req_host = "buckyos-filebrowser-lzc.web3.buckyos.io".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "buckyos-filebrowser-lzc".to_string());
        assert_eq!(username, "lzc".to_string());

        let server_host = "devtests.org".to_string();
        let req_host = "alice.web3.devtests.org".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "alice".to_string());
        assert_eq!(username, "alice".to_string());

        let req_host = "public.alice.web3.devtests.org".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "public.alice".to_string());
        assert_eq!(username, "alice".to_string());

        let server_host = "sn.devtests.org".to_string();
        let req_host = "public.alice.web3.devtests.org".to_string();
        let (sub_host, username) =
            SNServer::get_user_subhost_from_host(&req_host, &server_host).unwrap();
        assert_eq!(sub_host, "public.alice".to_string());
        assert_eq!(username, "alice".to_string());
    }

    #[test]
    fn test_validate_registration_username() {
        for username in ["validuser", "my-device"] {
            assert!(
                SNServer::validate_registration_username(username).is_ok(),
                "expected valid username: {}",
                username
            );
            assert!(
                canonical_bns_name(username).is_ok(),
                "SN-valid username must also be a valid BNS name: {}",
                username
            );
        }

        for (username, expected_reason) in [
            ("", "username is empty"),
            ("short", "username does not meet naming rules"),
            ("waterflier", "username does not meet naming rules"),
            ("security", "username does not meet naming rules"),
            ("UserName", "username does not meet naming rules"),
            ("1starter", "username does not meet naming rules"),
            ("user-", "username does not meet naming rules"),
            ("user_name", "username does not meet naming rules"),
            ("sub.domain", "username does not meet naming rules"),
            ("sub.admin.domain", "username does not meet naming rules"),
            ("double..dot", "username does not meet naming rules"),
        ] {
            let err = SNServer::validate_registration_username(username).unwrap_err();
            assert_eq!(err, expected_reason, "unexpected reason for {}", username);
        }

        let tempdir = tempfile::tempdir().unwrap();
        let reserved_file = tempdir.path().join(RESERVED_USER_NAMES_FILE);
        std::fs::write(&reserved_file, "# comment\npremiumname\n").unwrap();
        std::env::set_var(
            RESERVED_USER_NAMES_FILE_ENV,
            reserved_file.to_string_lossy().to_string(),
        );
        let err = SNServer::validate_registration_username("premiumname").unwrap_err();
        assert_eq!(err, "username is reserved by server");
        std::env::remove_var(RESERVED_USER_NAMES_FILE_ENV);
    }

    #[test]
    fn test_zonegate_ip_filter_only_blocks_172_private_range() {
        assert!(is_filtered_zonegate_ip("172.17.0.1".parse().unwrap()));
        assert!(is_filtered_zonegate_ip("172.31.255.254".parse().unwrap()));

        assert!(!is_filtered_zonegate_ip("192.168.100.191".parse().unwrap()));
        assert!(!is_filtered_zonegate_ip("207.246.96.13".parse().unwrap()));
        assert!(!is_filtered_zonegate_ip(
            "240e:3b3:30c0:930::47f".parse().unwrap()
        ));
    }

    #[test]
    fn test_build_device_info_json_filters_172_from_exported_ip_fields() {
        let device = SNDeviceInfo {
            owner: "meteormeta".to_string(),
            device_name: "ood1".to_string(),
            mini_config_jwt: "mini-jwt".to_string(),
            did: "did:dev:test".to_string(),
            ip: "172.26.48.1".to_string(),
            description: json!({
                "ip": "172.17.0.1",
                "ips": ["172.20.1.2", "192.168.100.182", "240e:3b3:30c1:5380::997"],
                "all_ip": ["172.26.48.1", "192.168.100.182", "240e:3b3:30c1:5380::997"]
            })
            .to_string(),
            created_at: 1,
            updated_at: 2,
        };

        let exported = build_legacy_device_info_json(&device);
        assert_eq!(
            exported.get("ip").and_then(|v| v.as_str()),
            Some("192.168.100.182")
        );
        assert_eq!(
            exported.get("ips").and_then(|v| v.as_array()).cloned(),
            Some(vec![
                Value::String("192.168.100.182".to_string()),
                Value::String("240e:3b3:30c1:5380::997".to_string()),
            ])
        );
        assert_eq!(
            exported.get("all_ip").and_then(|v| v.as_array()).cloned(),
            Some(vec![
                Value::String("192.168.100.182".to_string()),
                Value::String("240e:3b3:30c1:5380::997".to_string()),
            ])
        );
    }

    #[test]
    fn test_build_device_info_json_removes_ip_when_only_filtered_values_exist() {
        let device = SNDeviceInfo {
            owner: "meteormeta".to_string(),
            device_name: "ood1".to_string(),
            mini_config_jwt: "mini-jwt".to_string(),
            did: "did:dev:test".to_string(),
            ip: "172.26.48.1".to_string(),
            description: json!({
                "ip": "172.17.0.1",
                "ips": ["172.20.1.2"],
                "all_ip": ["172.26.48.1"]
            })
            .to_string(),
            created_at: 1,
            updated_at: 2,
        };

        let exported = build_legacy_device_info_json(&device);
        assert!(exported.get("ip").is_none());
        assert_eq!(
            exported.get("ips").and_then(|v| v.as_array()).cloned(),
            Some(vec![])
        );
        assert_eq!(
            exported.get("all_ip").and_then(|v| v.as_array()).cloned(),
            Some(vec![])
        );
    }

    #[tokio::test]
    #[ignore = "legacy V1/root compatibility API removed by SN API refactor"]
    async fn test_sn_api() {
        init_logging("sn", false);
        let (user_signing_key, user_pkcs8_bytes) = generate_ed25519_key();
        let user_public_key = encode_ed25519_sk_to_pk_jwk(&user_signing_key);
        let user_encoding_key = jsonwebtoken::EncodingKey::from_ed_der(user_pkcs8_bytes.as_slice());

        let now = SystemTime::now();
        let zone_boot_config = json!({
            "oods": ["ood1"],
            "exp": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 3600,
            "iat": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        });
        let zone_boot_config: ZoneBootDocument = serde_json::from_value(zone_boot_config).unwrap();
        let zone_jwt = zone_boot_config
            .encode(Some(&user_encoding_key))
            .unwrap()
            .to_string();

        let (_user_token, mut user_session) = RPCSessionToken::generate_jwt_token(
            TEST_USER,
            "active_service",
            None,
            &user_encoding_key,
        )
        .unwrap();
        user_session.aud = Some("sn".to_string());
        let user_token = user_session
            .generate_jwt(None, &user_encoding_key)
            .unwrap()
            .to_string();
        let (signing_key, pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(jwk).unwrap());
        let mini_config_jwt = DeviceMiniDocument::new_by_device_document(&device_config);
        let mini_config_jwt = mini_config_jwt
            .to_jwt(&user_encoding_key)
            .unwrap()
            .to_string();
        let device_info = DeviceInfo::from_device_doc(&device_config);

        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_bytes.as_slice());
        // device signed token: userid is device_name (e.g. "ood1")
        let (_token, mut session) =
            RPCSessionToken::generate_jwt_token("ood1", "cyfs_gateway", None, &encoding_key)
                .unwrap();
        session.aud = Some("sn".to_string());
        let token = session
            .generate_jwt(None, &encoding_key)
            .unwrap()
            .to_string();

        // token and user_token are used by different flows below:
        // - token: used for cyfs_gateway (should NOT be allowed to register device)
        // - user_token: used for active_service (should be allowed to register device)

        let (signing_key2, pkcs8_bytes2) = generate_ed25519_key();
        let jwk2 = encode_ed25519_sk_to_pk_jwk(&signing_key2);
        let device_config2 =
            DeviceDocument::new_by_jwk("ood2", serde_json::from_value(jwk2).unwrap());

        let encoding_key2 = jsonwebtoken::EncodingKey::from_ed_der(pkcs8_bytes2.as_slice());
        let (_token2, mut session2) =
            RPCSessionToken::generate_jwt_token(TEST_USER, "cyfs_gateway", None, &encoding_key2)
                .unwrap();
        session2.aud = Some("sn".to_string());
        let token2 = session2
            .generate_jwt(None, &encoding_key2)
            .unwrap()
            .to_string();

        let sn_factory = SnServerFactory::new();

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();

        {
            let db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            db.initialize_database().await.unwrap();
            db.insert_activation_code(CLEAR_STATE_ACTIVE_CODE)
                .await
                .unwrap();
        }
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_type": "sqlite",
            "db_path": db.path().to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let servers = sn_factory.create(Arc::new(config), None).await.unwrap();
        let mut http_server = None;
        for server in servers.iter() {
            if let Server::Http(server) = server {
                http_server = Some(server.clone());
            }
        }
        let http_server = http_server.unwrap();

        let mut dns_server = None;
        for server in servers.iter() {
            if let Server::NameServer(server) = server {
                dns_server = Some(server.clone());
            }
        }
        let dns_server = dns_server.unwrap();

        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);

        let krpc = kRPC::new(base_url.as_str(), Some(token.clone()));
        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": TEST_USER
                }),
            )
            .await
            .unwrap();
        assert!(result
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_bool()
            .unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "ok");
        assert_eq!(result["normalized_name"].as_str().unwrap(), TEST_USER);

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": "short"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");
        assert_eq!(
            result["message"].as_str().unwrap(),
            "username does not meet naming rules"
        );

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": "user_name"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": "sub.domain"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let invalid_register_result = krpc
            .call(
                "register_user",
                json!({
                    "user_name": "sub.domain",
                    "public_key": user_public_key.to_string(),
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "zone_config": zone_jwt,
                    "user_domain": "sub.domain.buckyos.ai",
                }),
            )
            .await;
        assert!(invalid_register_result.is_err());
        let invalid_register_err = invalid_register_result.err().unwrap().to_string();
        assert!(invalid_register_err.contains("username does not meet naming rules"));

        let result = krpc
            .call(
                "register_user",
                json!({
                    "user_name": TEST_USER,
                    "public_key": user_public_key.to_string(),
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "zone_config": zone_jwt,
                    "user_domain": format!("{}.buckyos.ai", TEST_USER),
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            result
                .as_object()
                .unwrap()
                .get("code")
                .unwrap()
                .as_i64()
                .unwrap(),
            0
        );

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": TEST_USER
                }),
            )
            .await
            .unwrap();
        assert!(!result
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_bool()
            .unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "already_exists");
        assert!(result["message"]
            .as_str()
            .unwrap()
            .contains("already exists"));

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": "security"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let result = krpc
            .call(
                "register",
                json!({
                    "user_name": TEST_USER,
                    "device_name": "ood1",
                    "device_did": device_config.id.clone(),
                    "mini_config_jwt": mini_config_jwt.clone(),
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                }),
            )
            .await;
        assert!(result.is_err());

        let krpc = kRPC::new(base_url.as_str(), Some(user_token.clone()));
        let result = krpc
            .call(
                "register",
                json!({
                    "user_name": TEST_USER,
                    "device_name": "ood1",
                    "device_did": device_config.id.clone(),
                    "mini_config_jwt": mini_config_jwt.clone(),
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                }),
            )
            .await;
        assert!(result.is_ok());

        // --- DID resolve HTTP API ---
        let client = reqwest::Client::new();

        // did:bns:username type=boot
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:{}?type=boot",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("boot").is_some());

        // did:bns:username type=zone (default)
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:{}",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("user_name").unwrap().as_str().unwrap(), TEST_USER);
        assert!(v.get("boot").is_some());

        // did:web:domain -> routes to did:bns:username
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:web:{}.buckyos.ai",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("user_name").unwrap().as_str().unwrap(), TEST_USER);

        // did:bns:device.username type=doc
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:ood1.{}?type=doc",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());
        assert!(v.get("device_mini_config_jwt").is_some());

        // did:bns:device.domain -> routes domain -> username -> device
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:ood1.{}.buckyos.ai?type=doc",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());

        // did:bns:device.username type=info
        let resp = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:ood1.{}?type=info",
                base_url, TEST_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        //println!("v: {:?}", v);
        assert_eq!(v.get("device_name").unwrap().as_str().unwrap(), "ood1");
        assert_eq!(v.get("owner").unwrap().as_str().unwrap(), TEST_USER);
        //assert!(v.get("ip").is_some());

        // did:dev:public_key type=doc/info
        let did_dev = device_config.id.to_string();
        let resp = client
            .get(format!("{}/1.0/identifiers/{}?type=doc", base_url, did_dev))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v.get("id").is_some());

        let resp = client
            .get(format!(
                "{}/1.0/identifiers/{}?type=info",
                base_url, did_dev
            ))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v.get("device_name").unwrap().as_str().unwrap(), "ood1");
        //assert!(v.get("ip").is_some());

        let krpc = kRPC::new(base_url.as_str(), Some(token.clone()));
        let result = krpc
            .call(
                "get",
                json!({
                    "device_id": device_config.name,
                    "owner_id": TEST_USER
                }),
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ret = serde_json::from_value::<DeviceInfo>(result);
        assert!(ret.is_ok());

        let result = krpc
            .call(
                "get_by_pk",
                json!({
                    "public_key": user_public_key.to_string()
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc
            .call(
                "add_dns_record",
                json!({
                    "device_did": device_config2.id.to_string(),
                    "domain": format!("{}.buckyos.ai", TEST_USER),
                    "record_type": "A",
                    "record": "127.0.0.1",
                }),
            )
            .await;
        assert!(result.is_err());

        let result = krpc
            .call(
                "add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("test.{}.web3.buckyos.ai", TEST_USER),
                    "record_type": "A",
                    "record": "127.0.0.1",
                    "ttl": 600
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc
            .call(
                "add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("{}.buckyos.ai", TEST_USER),
                    "record_type": "A",
                    "record": "127.0.0.1",
                    "ttl": 600
                }),
            )
            .await;
        assert!(result.is_err());

        let result = krpc
            .call(
                "add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("_acme-challenge.{}.web3.buckyos.ai", TEST_USER),
                    "record_type": "TXT",
                    "record": "ERWSSDFERWERSD",
                    "ttl": 600
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = dns_server
            .query(
                &format!("_acme-challenge.{}.web3.buckyos.ai", TEST_USER),
                Some(RecordType::TXT),
                None,
            )
            .await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.txt.len(), 1);
        assert_eq!(name_info.txt[0], "ERWSSDFERWERSD");

        let result = dns_server
            .query(
                format!("test.{}.web3.buckyos.ai", TEST_USER).as_str(),
                Some(RecordType::A),
                None,
            )
            .await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.address.len(), 1);
        assert_eq!(name_info.address[0].to_string(), "127.0.0.1");

        let result = krpc
            .call(
                "query_by_hostname",
                json!({
                    "dest_host": format!("test.{}.web3.buckyos.ai", TEST_USER)
                }),
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(!ood_info.self_cert);

        let result = krpc
            .call(
                "remove_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("_acme-challenge.{}.web3.buckyos.ai", TEST_USER),
                    "record_type": "TXT",
                    "has_cert": true
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = dns_server
            .query(
                &format!("_acme-challenge.{}.web3.buckyos.ai", TEST_USER),
                Some(RecordType::TXT),
                None,
            )
            .await;
        assert!(result.is_ok());
        let name_info = result.unwrap();
        assert_eq!(name_info.txt.len(), 3);

        let krpc = kRPC::new(base_url.as_str(), Some(token2.clone()));
        let device_info2 = DeviceInfo::from_device_doc(&device_config2);
        let result = krpc
            .call(
                "update",
                json!({
                    "device_info": device_info2,
                    "owner_id": TEST_USER
                }),
            )
            .await;
        assert!(result.is_err());

        let krpc = kRPC::new(base_url.as_str(), Some(token.clone()));
        let mut device_info = DeviceInfo::from_device_doc(&device_config);
        device_info.cpu_info = Some("AMD".to_string());
        let result = krpc
            .call(
                "update",
                json!({
                    "device_info": device_info,
                    "owner_id": TEST_USER
                }),
            )
            .await;
        assert!(result.is_ok());

        let krpc = kRPC::new(base_url.as_str(), Some(token.clone()));
        let result = krpc
            .call(
                "get",
                json!({
                    "device_id": device_config.name,
                    "owner_id": TEST_USER
                }),
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ret = serde_json::from_value::<DeviceInfo>(result);
        assert!(ret.is_ok());
        let device_info = ret.unwrap();
        assert_eq!(device_info.cpu_info.unwrap(), "AMD");

        let result = krpc
            .call(
                "query_by_did",
                json!({
                    "source_device_id": device_config.id.to_string(),
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc
            .call(
                "query_by_hostname",
                json!({
                    "dest_host": format!("test.{}.web3.buckyos.ai", TEST_USER)
                }),
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(ood_info.self_cert);

        // --- set_user_self_cert (device-signed) ---
        let result = krpc
            .call(
                "set_user_self_cert",
                json!({
                    "name": TEST_USER,
                    "self_cert": false
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc
            .call(
                "query_by_hostname",
                json!({
                    "dest_host": format!("test.{}.web3.buckyos.ai", TEST_USER)
                }),
            )
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert!(!ood_info.self_cert);

        let result = krpc
            .call(
                "set_user_self_cert",
                json!({
                    "name": TEST_USER,
                    "self_cert": true
                }),
            )
            .await;
        assert!(result.is_ok());

        let result = krpc
            .call("clear_state_by_active_code", json!({}))
            .await
            .unwrap();
        assert_eq!(
            result
                .as_object()
                .unwrap()
                .get("code")
                .unwrap()
                .as_i64()
                .unwrap(),
            0
        );

        let result = krpc
            .call(
                "check_username",
                json!({
                    "username": TEST_USER
                }),
            )
            .await
            .unwrap();
        assert!(result
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_bool()
            .unwrap());

        let result = krpc
            .call(
                "check_active_code",
                json!({
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        assert!(result
            .as_object()
            .unwrap()
            .get("valid")
            .unwrap()
            .as_bool()
            .unwrap());

        let result = krpc
            .call(
                "register_user",
                json!({
                    "user_name": TEST_USER,
                    "public_key": user_public_key.to_string(),
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "zone_config": zone_jwt,
                    "user_domain": format!("{}.buckyos.ai", TEST_USER),
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            result
                .as_object()
                .unwrap()
                .get("code")
                .unwrap()
                .as_i64()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn test_sn_refactored_api_paths() {
        init_logging("sn", false);
        const REFACTOR_USER: &str = "refactoruser";

        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(jwk).unwrap());
        let device_info = DeviceInfo::from_device_doc(&device_config);

        let sn_factory = SnServerFactory::new();
        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();

        {
            let db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            db.initialize_database().await.unwrap();
            db.insert_activation_code(CLEAR_STATE_ACTIVE_CODE)
                .await
                .unwrap();
        }

        let config = json!({
            "id": "test-refactor",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_type": "sqlite",
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let servers = sn_factory.create(Arc::new(config), None).await.unwrap();
        let http_server = servers
            .iter()
            .find_map(|server| match server {
                Server::Http(server) => Some(server.clone()),
                _ => None,
            })
            .unwrap();

        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let root_url = format!("{}/kapi/sn", base_url);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let deviceinfo_url = format!("{}/kapi/sn/deviceinfo", base_url);

        let root_err = kRPC::new(root_url.as_str(), None)
            .call("auth.check_username", json!({ "name": REFACTOR_USER }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(root_err.contains("not available on /kapi/sn"));

        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let result = auth_krpc
            .call("auth.check_username", json!({ "name": REFACTOR_USER }))
            .await
            .unwrap();
        assert!(result["valid"].as_bool().unwrap());

        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": REFACTOR_USER,
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        let access_token = result["access_token"].as_str().unwrap().to_string();

        let auth_user_krpc = kRPC::new(auth_url.as_str(), Some(access_token.clone()));
        let removed_owner_key = auth_user_krpc
            .call("user.bind_owner_key", json!({ "public_key": {} }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(removed_owner_key.contains("not available on /kapi/sn/auth"));

        let device_krpc = kRPC::new(deviceinfo_url.as_str(), Some(access_token.clone()));
        let missing_device = "did:dev:missing-device";
        let missing_device_err = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": missing_device
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(missing_device_err.contains("registered device not found"));
        assert!(missing_device_err.contains(missing_device));
        assert!(missing_device_err.contains("registered device binding by zone and device_name"));

        let result = device_krpc
            .call(
                "device.register",
                json!({
                    "device_name": "ood1",
                    "device_did": device_config.id.to_string(),
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                    "ttl": 600
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), REFACTOR_USER);

        let result = device_krpc
            .call("device.get", json!({ "device_name": "ood1" }))
            .await
            .unwrap();
        assert_eq!(
            result["did"].as_str().unwrap(),
            device_config.id.to_string()
        );

        let result = device_krpc.call("device.list", json!({})).await.unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 1);

        let did_resp = reqwest::Client::new()
            .get(format!(
                "{}/1.0/identifiers/{}?type=info",
                base_url,
                device_config.id.to_string()
            ))
            .send()
            .await
            .unwrap();
        assert!(did_resp.status().is_success());
        let did_info: Value = did_resp.json().await.unwrap();
        assert_eq!(did_info["device_name"].as_str().unwrap(), "ood1");
        assert_eq!(
            did_info["did"].as_str().unwrap(),
            device_config.id.to_string()
        );

        let registered_did_hostname = device_config.id.to_host_name();
        let result = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": device_config.id.to_string()
                }),
            )
            .await
            .unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(ood_info.did_hostname, registered_did_hostname);
        assert_eq!(ood_info.owner_id, REFACTOR_USER);
        assert_eq!(ood_info.state, "active");
        assert!(!ood_info.self_cert);

        let bns_device_did = format!("did:bns:ood1.{}", REFACTOR_USER);
        let result = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": bns_device_did
                }),
            )
            .await
            .unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(ood_info.did_hostname, registered_did_hostname);
        assert_eq!(ood_info.owner_id, REFACTOR_USER);
        assert_eq!(ood_info.state, "active");
        assert!(!ood_info.self_cert);

        let nested_web3_host = format!("public.{}.web3.buckyos.ai", REFACTOR_USER);
        let result = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_hostname",
                json!({
                    "dest_host": nested_web3_host
                }),
            )
            .await
            .unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(ood_info.did_hostname, registered_did_hostname);
        assert_eq!(ood_info.owner_id, REFACTOR_USER);
        assert_eq!(ood_info.state, "active");
        assert!(!ood_info.self_cert);

        let result = auth_user_krpc
            .call(
                "user.set_self_cert",
                json!({
                    "self_cert": true,
                    "device_did": device_config.id.to_string()
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        let profile = auth_user_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert!(profile["self_cert"].as_bool().unwrap());

        let user_domain = format!("{}.buckyos.ai", REFACTOR_USER);
        let challenge = auth_user_krpc
            .call("domain.begin_verify", json!({ "domain": user_domain }))
            .await
            .unwrap();
        let pkx = challenge["pkx"].as_str().unwrap();
        auth_user_krpc
            .call(
                "domain.verify",
                json!({
                    "domain": user_domain,
                    "txt_records": [pkx]
                }),
            )
            .await
            .unwrap();

        let result = auth_user_krpc
            .call(
                "user.add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("home.{}", user_domain),
                    "record_type": "A",
                    "record": "127.0.0.1",
                    "ttl": 600
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["device_name"].as_str().unwrap(), "ood1");

        let result = auth_user_krpc
            .call("user.list_dns_records", json!({}))
            .await
            .unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 1);

        let admin_on_auth = auth_user_krpc
            .call("admin.clear_state_by_active_code", json!({}))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(admin_on_auth.contains("not available on /kapi/sn/auth"));

        let admin_krpc = kRPC::new(base_url.as_str(), Some(access_token));
        let result = admin_krpc
            .call("admin.clear_state_by_active_code", json!({}))
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
    }

    #[tokio::test]
    #[ignore = "legacy BNS-in-SN route coverage replaced by refactored path test"]
    async fn test_sn_account_api() {
        init_logging("sn", false);
        let (user_signing_key, user_pkcs8_bytes) = generate_ed25519_key();
        let user_public_key = encode_ed25519_sk_to_pk_jwk(&user_signing_key);
        let user_encoding_key = jsonwebtoken::EncodingKey::from_ed_der(user_pkcs8_bytes.as_slice());

        let now = SystemTime::now();
        let zone_boot_config = json!({
            "oods": ["ood1"],
            "exp": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 3600,
            "iat": now.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        });
        let zone_boot_config: ZoneBootDocument = serde_json::from_value(zone_boot_config).unwrap();
        let zone_jwt = zone_boot_config
            .encode(Some(&user_encoding_key))
            .unwrap()
            .to_string();

        let (signing_key, _pkcs8_bytes) = generate_ed25519_key();
        let jwk = encode_ed25519_sk_to_pk_jwk(&signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(jwk).unwrap());
        let mini_config_jwt = DeviceMiniDocument::new_by_device_document(&device_config)
            .to_jwt(&user_encoding_key)
            .unwrap()
            .to_string();
        let device_info = DeviceInfo::from_device_doc(&device_config);

        let sn_factory = SnServerFactory::new();

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();

        {
            let db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            db.initialize_database().await.unwrap();
            db.insert_activation_code(CLEAR_STATE_ACTIVE_CODE)
                .await
                .unwrap();
        }

        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_type": "sqlite",
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let servers = sn_factory.create(Arc::new(config), None).await.unwrap();
        let mut http_server = None;
        for server in servers.iter() {
            if let Server::Http(server) = server {
                http_server = Some(server.clone());
            }
        }
        let http_server = http_server.unwrap();

        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let sn_url = format!("{}/kapi/sn", base_url);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let bns_url = format!("{}/kapi/sn/bns", base_url);

        let root_krpc = kRPC::new(sn_url.as_str(), None);
        let result = root_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": TEST_ROOT_USER
                }),
            )
            .await
            .unwrap();
        assert!(result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "ok");
        assert_eq!(result["normalized_name"].as_str().unwrap(), TEST_ROOT_USER);

        let result = root_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": "short"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let result = root_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": "security"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let result = root_krpc
            .call(
                "check_username",
                json!({
                    "username": TEST_LEGACY_USER
                }),
            )
            .await
            .unwrap();
        assert!(result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "ok");

        let result = root_krpc
            .call(
                "check_username",
                json!({
                    "username": "1starter"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let result = auth_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": TEST_USER
                }),
            )
            .await
            .unwrap();
        assert!(result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "ok");

        let result = auth_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": "user_name"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let result = auth_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": "sub.domain"
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "invalid_username");

        let dotted_register_result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": "sub.domain",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await;
        assert!(dotted_register_result.is_err());
        let dotted_register_err = dotted_register_result.err().unwrap().to_string();
        assert!(dotted_register_err.contains("[SN:1001:invalid_username]"));

        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": TEST_USER,
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert!(result["need_bind_owner_key"].as_bool().unwrap());
        let access_token = result["access_token"].as_str().unwrap().to_string();
        let refresh_token = result["refresh_token"].as_str().unwrap().to_string();

        let result = auth_krpc
            .call(
                "auth.check_username",
                json!({
                    "name": TEST_USER
                }),
            )
            .await
            .unwrap();
        assert!(!result["valid"].as_bool().unwrap());
        assert_eq!(result["reason"].as_str().unwrap(), "already_exists");
        assert!(result["message"]
            .as_str()
            .unwrap()
            .contains("already exists"));

        let auth_me_krpc = kRPC::new(auth_url.as_str(), Some(access_token.clone()));
        let result = auth_me_krpc.call("auth.me", json!({})).await.unwrap();
        assert_eq!(result["name"].as_str().unwrap(), TEST_USER);
        assert!(!result["owner_key_bound"].as_bool().unwrap());

        let login_krpc = kRPC::new(auth_url.as_str(), None);
        let result = login_krpc
            .call(
                "auth.login",
                json!({
                    "name": TEST_USER,
                    "pwd_hash": "12345678"
                }),
            )
            .await
            .unwrap();
        let login_access_token = result["access_token"].as_str().unwrap().to_string();
        assert!(!login_access_token.is_empty());

        let login_with_legacy_active_code = login_krpc
            .call(
                "auth.login",
                json!({
                    "name": TEST_USER,
                    "pwd_hash": "12345678",
                    "active_code": "wrong-active-code"
                }),
            )
            .await;
        assert!(login_with_legacy_active_code.is_ok());

        let invalid_login_result = login_krpc
            .call(
                "auth.login",
                json!({
                    "name": TEST_USER,
                    "pwd_hash": "wrong-password"
                }),
            )
            .await;
        assert!(invalid_login_result.is_err());
        let invalid_login_err = invalid_login_result.err().unwrap().to_string();
        assert!(invalid_login_err.contains("[SN:1005:invalid_password]"));

        let invalid_register_result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": "short",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await;
        assert!(invalid_register_result.is_err());
        let invalid_register_err = invalid_register_result.err().unwrap().to_string();
        assert!(invalid_register_err.contains("[SN:1001:invalid_username]"));

        let refresh_krpc = kRPC::new(auth_url.as_str(), None);
        let result = refresh_krpc
            .call(
                "auth.refresh",
                json!({
                    "refresh_token": refresh_token.clone()
                }),
            )
            .await
            .unwrap();
        assert!(!result["access_token"].as_str().unwrap().is_empty());

        let logout_krpc = kRPC::new(auth_url.as_str(), Some(access_token.clone()));
        let result = logout_krpc
            .call(
                "auth.logout",
                json!({
                    "refresh_token": refresh_token
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        let revoked_access_result = auth_me_krpc.call("auth.me", json!({})).await;
        assert!(revoked_access_result.is_err());
        assert!(revoked_access_result
            .err()
            .unwrap()
            .to_string()
            .contains("[SN:1007:invalid_token]"));

        let user_krpc = kRPC::new(bns_url.as_str(), Some(login_access_token.clone()));
        let result = user_krpc
            .call(
                "user.bind_owner_key",
                json!({
                    "public_key": user_public_key.clone()
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let result = user_krpc
            .call("user.get_owner_key", json!({}))
            .await
            .unwrap();
        assert_eq!(
            result["public_key"]["x"].as_str().unwrap(),
            user_public_key["x"].as_str().unwrap()
        );

        let (_owner_token, mut owner_session) = RPCSessionToken::generate_jwt_token(
            TEST_USER,
            "active_service",
            None,
            &user_encoding_key,
        )
        .unwrap();
        owner_session.aud = Some("sn".to_string());
        let _owner_signed_token = owner_session
            .generate_jwt(None, &user_encoding_key)
            .unwrap()
            .to_string();

        let bns_user_krpc = kRPC::new(bns_url.as_str(), Some(login_access_token.clone()));
        let result = bns_user_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert_eq!(result["name"].as_str().unwrap(), TEST_USER);

        let user_domain = format!("{}.buckyos.ai", TEST_USER);
        let result = user_krpc
            .call(
                "domain.begin_verify",
                json!({
                    "domain": user_domain
                }),
            )
            .await
            .unwrap();
        let pkx = result["pkx"].as_str().unwrap().to_string();
        assert_eq!(
            result["pkx_record_name"].as_str().unwrap(),
            format!("_pkx.{}", user_domain)
        );
        let result = user_krpc
            .call(
                "domain.verify",
                json!({
                    "domain": user_domain,
                    "txt_records": [pkx]
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let zone_krpc = kRPC::new(bns_url.as_str(), Some(login_access_token.clone()));
        let result = zone_krpc
            .call(
                "zone.bind_config",
                json!({
                    "zone_config": zone_jwt,
                    "user_domain": user_domain
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let result = zone_krpc.call("zone.get", json!({})).await.unwrap();
        assert_eq!(result["user_name"].as_str().unwrap(), TEST_USER);
        assert_eq!(result["user_domain"].as_str().unwrap(), user_domain);

        let device_krpc = kRPC::new(bns_url.as_str(), Some(login_access_token.clone()));
        let result = device_krpc
            .call(
                "device.register",
                json!({
                    "device_name": "ood1",
                    "device_did": device_config.id.clone(),
                    "mini_config_jwt": mini_config_jwt.clone(),
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let result = device_krpc.call("device.list", json!({})).await.unwrap();
        assert_eq!(result["items"].as_array().unwrap().len(), 1);

        let dns_krpc = kRPC::new(sn_url.as_str(), Some(login_access_token.clone()));
        let result = dns_krpc
            .call(
                "dns.add_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("home.{}.buckyos.ai", TEST_USER),
                    "record_type": "A",
                    "record": "127.0.0.1",
                    "ttl": 600,
                    "has_cert": true
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let result = dns_krpc
            .call(
                "dns.remove_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": "home.other.buckyos.ai",
                    "record_type": "A"
                }),
            )
            .await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("[SN:1015:invalid_domain]"));

        let did_krpc = kRPC::new(sn_url.as_str(), Some(login_access_token.clone()));
        let result = did_krpc
            .call(
                "did.set_document",
                json!({
                    "obj_name": "profile",
                    "did_document": {
                        "name": TEST_USER,
                        "version": 2
                    },
                    "doc_type": "profile"
                }),
            )
            .await
            .unwrap();
        assert!(!result["obj_id"].as_str().unwrap().is_empty());

        let result = did_krpc
            .call(
                "did.get_document",
                json!({
                    "obj_name": "profile",
                    "doc_type": "profile"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["did_document"]["name"].as_str().unwrap(), TEST_USER);

        let query_krpc = kRPC::new(sn_url.as_str(), Some(login_access_token.clone()));
        let result = query_krpc
            .call(
                "query.resolve_hostname",
                json!({
                    "host": format!("home.{}.buckyos.ai", TEST_USER)
                }),
            )
            .await
            .unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(ood_info.owner_id, TEST_USER.to_string());
        assert!(ood_info.self_cert);

        let result = root_krpc
            .call(
                "query.by_hostname",
                json!({
                    "dest_host": format!("home.{}.buckyos.ai", TEST_USER)
                }),
            )
            .await
            .unwrap();
        let root_ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(root_ood_info.owner_id, TEST_USER.to_string());
        assert!(root_ood_info.self_cert);

        let result = query_krpc
            .call(
                "query.resolve_did",
                json!({
                    "did": format!("did:bns:{}", TEST_USER),
                    "type": "zone"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["document"]["user_name"].as_str().unwrap(), TEST_USER);

        let result = query_krpc
            .call(
                "query.resolve_device",
                json!({
                    "name": TEST_USER,
                    "device_name": "ood1"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["device_name"].as_str().unwrap(), "ood1");

        let result = dns_krpc
            .call(
                "dns.remove_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": format!("home.{}.buckyos.ai", TEST_USER),
                    "record_type": "A"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let bns_admin_krpc = kRPC::new(bns_url.as_str(), Some(login_access_token));
        let result = bns_admin_krpc
            .call("admin.clear_state_by_active_code", json!({}))
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);

        let result = auth_krpc
            .call(
                "auth.login",
                json!({
                    "name": TEST_USER,
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("[SN:1004:user_auth_not_found]"));
    }

    // §3.2/§3.3/§3.4 阶段二安全回归：token claims、冻结用户旧 token 立即失效、
    // 未经 PKX 校验的 user_domain 不能 bind、裸 access token 不能置 self_cert=true。
    #[tokio::test]
    #[ignore = "legacy /kapi/sn/bns zone binding coverage moved out of SN API"]
    async fn test_sn_phase_two_security_regressions() {
        use crate::UserState;

        const REG_USER: &str = "regressuser";

        let sn_factory = SnServerFactory::new();
        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        {
            let db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            db.initialize_database().await.unwrap();
            db.insert_activation_code(CLEAR_STATE_ACTIVE_CODE)
                .await
                .unwrap();
        }
        let config = json!({
            "id": "test-sec",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_type": "sqlite",
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let servers = sn_factory.create(Arc::new(config), None).await.unwrap();
        let http_server = servers
            .iter()
            .find_map(|server| match server {
                Server::Http(server) => Some(server.clone()),
                _ => None,
            })
            .unwrap();
        // 独立打开同一 SQLite 文件，用于直接驱动用户状态（服务端读同一份文件）。
        let auth_db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
            .await
            .unwrap();

        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let bns_url = format!("{}/kapi/sn/bns", base_url);

        // 注册 → 拿 access/refresh token。
        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": REG_USER,
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        let access_token = result["access_token"].as_str().unwrap().to_string();
        let refresh_token = result["refresh_token"].as_str().unwrap().to_string();

        // §3.2 token claims：access=sn/1h，refresh=sn-refresh/24h，sub=username，jti 存在。
        let access_session = RPCSessionToken::from_string(access_token.as_str()).unwrap();
        let refresh_session = RPCSessionToken::from_string(refresh_token.as_str()).unwrap();
        assert_eq!(access_session.sub.as_deref(), Some(REG_USER));
        assert_eq!(access_session.aud.as_deref(), Some("sn"));
        assert_eq!(refresh_session.aud.as_deref(), Some("sn-refresh"));
        assert!(access_session.jti.as_deref().is_some_and(|j| !j.is_empty()));
        assert!(refresh_session
            .jti
            .as_deref()
            .is_some_and(|j| !j.is_empty()));
        let access_exp = access_session.exp.unwrap();
        let refresh_exp = refresh_session.exp.unwrap();
        // 同批签发：refresh 比 access 多 23h（允许 ±2s 时钟抖动）。
        assert!(
            (82_798..=82_802).contains(&(refresh_exp - access_exp)),
            "refresh-access exp gap should be ~23h, got {}",
            refresh_exp - access_exp
        );

        // §3.4 裸 access token（无 device_did）不能开 self_cert。
        let bns_krpc = kRPC::new(bns_url.as_str(), Some(access_token.clone()));
        let self_cert_err = bns_krpc
            .call("user.set_self_cert", json!({ "self_cert": true }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            self_cert_err.contains("[SN:1013:device_permission_denied]"),
            "unexpected self_cert error: {self_cert_err}"
        );
        // 未开启 self_cert：zone.get 仍为 false。
        let zone = bns_krpc.call("zone.get", json!({})).await.unwrap();
        assert!(!zone["self_cert"].as_bool().unwrap());

        // §3.3 未经 PKX 校验的 user_domain 不能 bind（绕过风险已堵）。
        let bind_err = bns_krpc
            .call(
                "zone.bind_config",
                json!({
                    "zone_config": "{\"oods\":[\"ood1\"]}",
                    "user_domain": format!("{}.buckyos.ai", REG_USER)
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            bind_err.contains("[SN:1015:invalid_domain]"),
            "unexpected bind error: {bind_err}"
        );

        // §3.2 冻结用户 → 旧 access token 立即失效（会话被撤销）。
        auth_db
            .set_user_state(REG_USER, UserState::Suspended)
            .await
            .unwrap();
        let me_err = kRPC::new(auth_url.as_str(), Some(access_token.clone()))
            .call("auth.me", json!({}))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            me_err.contains("[SN:1007:invalid_token]"),
            "frozen user token should be rejected, got: {me_err}"
        );
    }
}
