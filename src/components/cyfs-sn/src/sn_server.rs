use crate::api::{
    handle_auth, handle_bns_proxy, handle_device, handle_dns, handle_domain, handle_user,
    handle_zone,
};
use crate::name_info_cache::{
    NameInfoCache, NameInfoCacheQueryResult, NameInfoCacheRef, MIN_NAME_INFO_CACHE_TTL_SECS,
};
use crate::sn_auth_manager::SnAuthManager;
use crate::sn_bns_proxy::{
    SNBnsProxyConfig, SnBnsControllerBindingStoreRef, SnBnsProxy, SnBnsProxyController,
    SqliteSnBnsControllerBindingStore,
};
use crate::sn_bns_reader::BnsRpcDocumentReader;
use crate::sn_bns_signer::{
    BoundControllerKeyManager, SnBnsControllerKeySpec, SnBnsProxyOperation, SnBnsTxSigner,
};
use crate::sn_did_resolver::{
    key_like_string_to_jwk, normalize_sn_did_doc_type, owner_key_from_config, SnDidResolveRequest,
    SnDidResolverProfile, SnDidResolverRef, SnResolverBackedDidResolver,
    SN_DID_RESOLVER_ROUTE_PREFIX,
};
use crate::sn_dns_proof::{DnsTxtResolverRef, DohDnsTxtResolver, DEFAULT_PKX_DOH_URL};
use crate::sn_resolver::{
    BnsDocumentReader, SnAuthDbRelayResolverReader, SnAuthResolverReader, SnAuthoritativeDnsResult,
    SnDeviceInfoResolverReader, SnResolver, SnResolverConfig, SnResolverErrorKind, SnResolverRef,
};
use crate::{
    AllocateZoneRelayReq, GeoIpResolverConfig, RelayAllocationConfig, RelayNodeRegistration,
    SnAuthDBRef, SnAuthDbClient, SnDeviceEndpointUpdate, SnDeviceInfoDBRef, SnDeviceInfoDbClient,
    SnDeviceRole, SnDeviceState, SnDeviceStateUpdate, SnEndpointProtocol, SnEndpointScope,
    SnEndpointSource, SnNatType, SnResult, SqliteSnAuthDB, SqliteSnDeviceInfoDB, XdbGeoIpResolver,
};
use ::kRPC::*;
use async_trait::async_trait;
use bns_client::{
    canonical_bns_name, BnsEvmClientConfig, BnsEvmControllerClient, BnsRpcApi, BnsRpcClient,
    BnsSystemInfo, Principal, SnBnsController, SnBnsControllerConfig, SqliteSnBnsWriteRequestStore,
};
use buckyos_kit::{get_buckyos_service_data_dir, is_valid_name, NameType};
pub use cyfs_gateway_api::SnOodInfo as OODInfo;
use cyfs_gateway_api::{SnCheckActiveCodeResp, SnOodState};
use cyfs_gateway_lib::server_err;
use cyfs_gateway_lib::{
    get_gateway_main_config_dir, qa_json_to_rpc_request, DnsQueryResult,
    HttpRequestProcessChainVars, HttpServer, NameServer, QAServer, Server, ServerConfig,
    ServerContextRef, ServerError, ServerErrorCode, ServerFactory, ServerResult, StreamInfo,
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
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::{
    net::{IpAddr, Ipv4Addr},
    result::Result,
};

const CLEAR_STATE_ACTIVE_CODE: &str = "zX6cV7bN8mK9lJ0hG1fD";
const RESERVED_USER_NAMES_FILE_ENV: &str = "BUCKYOS_SN_RESERVED_NAMES_FILE";
const RESERVED_USER_NAMES_FILE: &str = "reserved_user_names.txt";
const INTERNAL_ZONE_RESOLVER_ADDR: &str = "127.0.0.1:3180";

fn is_internal_zone_resolver_ingress(info: &StreamInfo) -> bool {
    info.dst_addr
        .as_deref()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .map(|addr| {
            addr == INTERNAL_ZONE_RESOLVER_ADDR
                .parse::<SocketAddr>()
                .expect("internal Zone Resolver address is a constant")
        })
        .unwrap_or(false)
}

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

fn collect_device_report_ips_from_json(value: Option<&Value>, result: &mut Vec<IpAddr>) {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnRpcPath {
    Root,
    Auth,
    DeviceInfo,
    BnsProxy,
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

fn is_internal_rpc_client_allowed(client_ip: IpAddr) -> bool {
    client_ip.is_loopback()
}

impl SnRpcPath {
    fn parse(path: &str) -> Option<Self> {
        match path {
            "/" => Some(Self::InternalRoot),
            "/kapi/sn" => Some(Self::Root),
            "/kapi/sn/auth" => Some(Self::Auth),
            "/kapi/sn/deviceinfo" => Some(Self::DeviceInfo),
            "/kapi/sn/bns-proxy" => Some(Self::BnsProxy),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "/kapi/sn",
            Self::Auth => "/kapi/sn/auth",
            Self::DeviceInfo => "/kapi/sn/deviceinfo",
            Self::BnsProxy => "/kapi/sn/bns-proxy",
            Self::InternalRoot => "/",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RegisteredDeviceKey {
    pub(crate) zone: String,
    pub(crate) device_name: String,
}

#[derive(Clone, Copy, Debug)]
struct BnsDnsCacheState {
    generation: u64,
    bypass_until: Instant,
}

#[derive(Clone, Debug)]
struct BnsDnsCacheQueryState {
    username: String,
    generation: u64,
    bypassed: bool,
}

#[derive(Clone)]
pub struct SNServer {
    id: String,
    auth_db: SnAuthDBRef,
    device_info_db: SnDeviceInfoDBRef,
    auth: Arc<SnAuthManager>,
    name_info_cache: NameInfoCacheRef,
    user_dns_cache_revision: Arc<AtomicU64>,
    bns_dns_cache_state: Arc<RwLock<HashMap<String, BnsDnsCacheState>>>,
    resolver: SnResolverRef,
    did_resolver: SnDidResolverRef,
    bns_proxy: Option<Arc<SnBnsProxy>>,
    /// user_domain PKX proof 专用的外部 DNS 查询（不走 SN 自身解析路径）。
    pkx_txt_resolver: DnsTxtResolverRef,
    /// `did:bns:<username>` owner document / authority key 读取（PKX 权威来源）。
    bns_owner_reader: Arc<BnsRpcDocumentReader>,
}

impl SNServer {
    fn parse_server_ip(ip: Option<&str>) -> ServerResult<Option<IpAddr>> {
        ip.map(|ip| {
            IpAddr::from_str(ip).map_err(|error| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "invalid SN server ip {}: {}",
                    ip,
                    error
                )
            })
        })
        .transpose()
    }

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
            | "zone.get_info"
            | "domain.bind"
            | "domain.unbind" => SnRpcPath::Auth,
            "device.register"
            | "device.update"
            | "device.get"
            | "device.list"
            | "deviceinfo.resolve_ood_by_did"
            | "deviceinfo.resolve_ood_by_hostname" => SnRpcPath::DeviceInfo,
            "bns.publish_dns_txt" | "bns.publish_document" => SnRpcPath::BnsProxy,
            // internal/admin only：不在外部 HTTP 路径开放（QA/loopback 通道可用）。
            "bns.publish_relay_assignment" | "bns.register_name_bootstrap" => {
                SnRpcPath::InternalRoot
            }
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
            SnRpcPath::Auth
            | SnRpcPath::DeviceInfo
            | SnRpcPath::BnsProxy
            | SnRpcPath::InternalRoot => Self::preferred_rpc_path(method) == path,
            SnRpcPath::Root => false,
        }
    }

    pub async fn new(
        server_config: SNServerConfig,
        auth_db: SnAuthDBRef,
        device_info_db: SnDeviceInfoDBRef,
        bns_client: BnsRpcClient,
        bns_proxy: Option<Arc<SnBnsProxy>>,
    ) -> ServerResult<Self> {
        let server_host = server_config.host;
        let server_ip = Self::parse_server_ip(server_config.ip.as_deref())?;
        let server_aliases = server_config.aliases;
        let boot_jwt = server_config.boot_jwt;
        let owner_pkx = server_config.owner_pkx;
        let device_jwt = server_config.device_jwt;
        let auth = Arc::new(
            SnAuthManager::new(server_config.auth_data_dir.as_deref())
                .await
                .map_err(|error| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "init sn auth manager failed: {}",
                        error
                    )
                })?,
        );
        let resolver_config = SnResolverConfig::new(
            server_host.clone(),
            server_ip,
            boot_jwt,
            owner_pkx,
            device_jwt,
        )
        .with_aliases(server_aliases);
        let auth_reader = Arc::new(SnAuthResolverReader::new(auth_db.clone()));
        let bns_owner_reader = Arc::new(BnsRpcDocumentReader::new(bns_client));
        let resolver = SnResolver::new_with_bns(
            resolver_config,
            auth_reader.clone(),
            bns_owner_reader.clone(),
        )
        .with_device_online_reader(Arc::new(SnDeviceInfoResolverReader::new(
            device_info_db.clone(),
        )))
        .with_relay_reader(Arc::new(SnAuthDbRelayResolverReader::new(auth_db.clone())));
        let resolver = Arc::new(resolver);
        let did_resolver =
            SnResolverBackedDidResolver::new_ref(resolver.clone(), auth_reader, server_host);
        let pkx_txt_resolver = DohDnsTxtResolver::new_ref(
            server_config
                .pkx_doh_url
                .as_deref()
                .unwrap_or(DEFAULT_PKX_DOH_URL),
        );

        Ok(SNServer {
            id: server_config.id,
            auth_db,
            device_info_db,
            auth,
            name_info_cache: NameInfoCache::new_ref(),
            user_dns_cache_revision: Arc::new(AtomicU64::new(0)),
            bns_dns_cache_state: Arc::new(RwLock::new(HashMap::new())),
            resolver,
            did_resolver,
            bns_proxy,
            pkx_txt_resolver,
            bns_owner_reader,
        })
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

    pub(crate) fn bns_proxy(&self) -> Option<Arc<SnBnsProxy>> {
        self.bns_proxy.clone()
    }

    pub(crate) fn pkx_txt_resolver(&self) -> &DnsTxtResolverRef {
        &self.pkx_txt_resolver
    }

    fn jwk_x_component(jwk: &jsonwebtoken::jwk::Jwk) -> Option<String> {
        match &jwk.algorithm {
            jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(params) => Some(params.x.clone()),
            _ => None,
        }
    }

    /// ed25519 公钥 x 分量的合理性检查（base64url 无 padding 解码为 32 字节）。
    pub(crate) fn is_plausible_ed25519_x(value: &str) -> bool {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD
            .decode(value)
            .map(|bytes| bytes.len() == 32)
            .unwrap_or(false)
    }

    /// 计算 user_domain 绑定期望的 `PKX(sn_user.pkx)` 及其来源。
    ///
    /// 权威优先级：`did:bns:<username>` 链上 owner document / authority key →
    /// 本地 `users.public_key` 缓存 → 确定性 `sn-user:<username>` 标签（无
    /// owner key 的账号仍能证明「DNS owner 同意绑定到该 SN 账号」的意图）。
    ///
    /// BNS reader 已配置但暂不可达时返回 RemoteError（可重试），不静默回落
    /// 本地缓存，避免期望 PKX 随链路抖动来回变化。绑定流程不提供修改 PKX
    /// 的入口。
    pub(crate) async fn expected_user_domain_pkx(
        &self,
        username: &str,
        user: &crate::SNUserInfo,
    ) -> SnResult<(String, &'static str)> {
        match self.bns_owner_reader.resolve_owner(username).await {
            Ok(Some(owner)) => {
                if let Some(x) = owner
                    .owner_config
                    .as_ref()
                    .and_then(owner_key_from_config)
                    .as_ref()
                    .and_then(Self::jwk_x_component)
                {
                    return Ok((crate::pkx_value(x.as_str())?, "bns-owner-config"));
                }
                if let Some(x) = owner
                    .effective_owner
                    .as_deref()
                    .and_then(key_like_string_to_jwk)
                    .as_ref()
                    .and_then(Self::jwk_x_component)
                    .filter(|x| Self::is_plausible_ed25519_x(x.as_str()))
                {
                    return Ok((crate::pkx_value(x.as_str())?, "bns-effective-owner"));
                }
                // 链上存在该名字但没有可用的 ed25519 authority key（例如
                // ChainAccount owner 且 owner_config 无 key）→ 本地回落。
            }
            Ok(None) => {}
            Err(e) => {
                return Err(crate::sn_err!(
                    crate::SnErrorCode::RemoteError,
                    "resolve BNS owner for {} failed: {}",
                    username,
                    e
                ));
            }
        }

        if let Some(source) = crate::pkx_source_of(user.public_key.as_str()) {
            return Ok((format!("PKX({})", source), "local-public-key"));
        }

        Ok((format!("PKX(sn-user:{})", username), "sn-user-label"))
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
        self.resolver.cache().remove_authoritative_name(name);
    }

    pub(crate) fn clear_authoritative_dns_cache(&self) {
        self.resolver.cache().clear();
    }

    fn bns_username_for_dns_query(&self, name: &str) -> Option<String> {
        let normalized = Self::normalize_query_name(name);
        if !normalized.contains('.') {
            return canonical_bns_name(normalized.as_str()).ok();
        }

        let resolver_config = self.resolver.config();
        for host in std::iter::once(resolver_config.server_host.as_str())
            .chain(resolver_config.aliases.iter().map(String::as_str))
        {
            let suffix = format!(".web3.{}", host);
            if let Some(prefix) = normalized.strip_suffix(suffix.as_str()) {
                return canonical_bns_name(prefix.rsplit('.').next()?).ok();
            }
        }
        None
    }

    fn bns_dns_cache_query_state(&self, name: &str) -> Option<BnsDnsCacheQueryState> {
        let username = self.bns_username_for_dns_query(name)?;
        let now = Instant::now();
        let states = self
            .bns_dns_cache_state
            .read()
            .unwrap_or_else(|err| err.into_inner());
        let state = states
            .get(username.as_str())
            .copied()
            .unwrap_or(BnsDnsCacheState {
                generation: 0,
                bypass_until: now,
            });
        Some(BnsDnsCacheQueryState {
            username,
            generation: state.generation,
            bypassed: state.bypass_until > now,
        })
    }

    fn update_bns_dns_cache_if_current(
        &self,
        query_state: Option<&BnsDnsCacheQueryState>,
        update: impl FnOnce(),
    ) -> bool {
        let Some(query_state) = query_state else {
            update();
            return true;
        };
        if query_state.bypassed {
            return false;
        }

        let now = Instant::now();
        let states = self
            .bns_dns_cache_state
            .read()
            .unwrap_or_else(|err| err.into_inner());
        let current = states.get(query_state.username.as_str()).copied();
        let current_generation = current.map(|state| state.generation).unwrap_or(0);
        let bypassed = current
            .map(|state| state.bypass_until > now)
            .unwrap_or(false);
        if current_generation != query_state.generation || bypassed {
            return false;
        }

        // Keep the generation read lock while writing the cache. Invalidation
        // takes the write lock before incrementing the generation and removing
        // entries, so an old in-flight resolver can never write after removal.
        update();
        true
    }

    /// BNS proxy 写投递成功后的本地 DNS 缓存失效（含 tombstone）。
    /// BNS receipt/submission 会早于 indexer 投影可见；失效后若立即重新缓存
    /// 旧投影，会把正常的秒级追赶窗口放大为 60 秒。因此对应 BNS name 在
    /// 一个最小缓存 TTL 内绕过缓存，只读取权威投影。
    pub(crate) fn invalidate_bns_name_dns_cache(&self, username: &str) {
        self.resolver.cache().clear();
        let username = Self::normalize_query_name(username);
        let now = Instant::now();
        let mut states = self
            .bns_dns_cache_state
            .write()
            .unwrap_or_else(|err| err.into_inner());
        let state = states.entry(username.clone()).or_insert(BnsDnsCacheState {
            generation: 0,
            bypass_until: now,
        });
        state.generation = state.generation.wrapping_add(1);
        state.bypass_until = now + Duration::from_secs(MIN_NAME_INFO_CACHE_TTL_SECS as u64);

        self.name_info_cache.remove_matching_names(|name| {
            self.bns_username_for_dns_query(name).as_deref() == Some(username.as_str())
        });

        let resolver_config = self.resolver.config();
        let mut names = vec![username.clone()];
        for host in std::iter::once(resolver_config.server_host.as_str())
            .chain(resolver_config.aliases.iter().map(String::as_str))
        {
            names.push(format!("{}.web3.{}", username, host));
            names.push(format!("{}.{}", username, host));
        }
        for name in names {
            let normalized = Self::normalize_query_name(name.as_str());
            for record_type in [RecordType::TXT, RecordType::A, RecordType::AAAA] {
                self.name_info_cache
                    .remove(normalized.as_str(), record_type);
            }
        }
        drop(states);
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
        collect_device_report_ips_from_json(value.as_ref(), &mut candidates);
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
        name.trim().trim_end_matches('.').to_ascii_lowercase()
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
        let value = serde_json::to_value(SnCheckActiveCodeResp { valid })
            .map_err(|e| RPCErrors::ReasonError(e.to_string()))?;
        let resp = RPCResponse::create_by_req(RPCResult::Success(value), &req);
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
                "activation_code_reset": result.activation_code_reset
            })),
            &req,
        );
        Ok(resp)
    }

    pub(crate) async fn handle_namespaced_rpc_call(
        &self,
        req: RPCRequest,
        ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        info!("sn server handle rpc call: {}", req.method);
        match req.method.as_str() {
            "auth.check_active_code" => {
                handle_auth(
                    self,
                    Self::rewrite_rpc_method(req, "check_active_code"),
                    Some(ip_from),
                )
                .await
            }
            "auth.check_username" => {
                handle_auth(
                    self,
                    Self::rewrite_rpc_method(req, "check_username"),
                    Some(ip_from),
                )
                .await
            }
            "auth.register" | "auth.login" | "auth.refresh" | "auth.logout" | "auth.me" => {
                let bare_method = req
                    .method
                    .strip_prefix("auth.")
                    .unwrap_or(req.method.as_str())
                    .to_string();
                handle_auth(
                    self,
                    Self::rewrite_rpc_method(req, bare_method.as_str()),
                    Some(ip_from),
                )
                .await
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
            "zone.get_info" => handle_zone(self, Self::rewrite_rpc_method(req, "get_info")).await,
            "domain.bind" | "domain.unbind" => {
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
            "bns.publish_dns_txt"
            | "bns.publish_document"
            | "bns.publish_relay_assignment"
            | "bns.register_name_bootstrap" => {
                let bare_method = req
                    .method
                    .strip_prefix("bns.")
                    .unwrap_or(req.method.as_str())
                    .to_string();
                handle_bns_proxy(self, Self::rewrite_rpc_method(req, bare_method.as_str())).await
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

        if let Some(key) = self.registered_device_key_from_did(did).await? {
            if let Some(view) = self
                .device_info_db
                .get_device_state_by_name(key.zone.as_str(), key.device_name.as_str())
                .await
                .map_err(|e| RPCErrors::ReasonError(e.to_string()))?
            {
                let registered_did = view.did.clone();
                return self
                    .ood_info_from_device_state(registered_did.as_str(), view)
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
            canonical_device_id: Some(view.did.clone()),
            owner_id: view.zone,
            self_cert: user.map(|u| u.self_cert).unwrap_or(false),
            state: Self::device_state_to_ood_state(view.state),
        })
    }

    pub(crate) async fn registered_device_key_from_did(
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

    fn registered_device_not_found(did: &str) -> String {
        format!(
            "registered device not found for source_device_id={did}; \
             deviceinfo.resolve_ood_by_did checks the exact DID first, then for \
             did:bns:<device>.<zone> or did:web:<device>.<domain> checks the \
             registered device binding by zone and device_name. Prefer passing the \
             canonical did:dev device DID after registration; scoped BNS/Web device \
             DIDs are accepted as aliases. Verify SnDeviceInfoDB contains a registered \
             device index with the same public key, device name, and zone."
        )
    }

    fn did_hostname(did: &str) -> String {
        DID::from_str(did)
            .map(|did| did.to_host_name())
            .unwrap_or_else(|_| did.to_string())
    }

    fn device_state_to_ood_state(state: SnDeviceState) -> SnOodState {
        match state {
            SnDeviceState::Online => SnOodState::Active,
            SnDeviceState::Offline | SnDeviceState::Stale => SnOodState::Suspended,
            SnDeviceState::Blocked => SnOodState::Banned,
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
                    .unwrap_or(SnOodState::Active);
                return Some(OODInfo {
                    did_hostname,
                    canonical_device_id: Some(gateway.gateway_did),
                    owner_id: gateway.zone_name,
                    self_cert: gateway.self_cert,
                    state,
                });
            }
            Err(e) if e.kind() != SnResolverErrorKind::NotManaged => {
                warn!("sn_resolver hostname query failed for {}: {}", req_host, e);
            }
            Err(_) => {}
        }
        None
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

    async fn query_dns(
        &self,
        name: &str,
        record_type: &str,
        _from_ip: Option<IpAddr>,
    ) -> ServerResult<DnsQueryResult> {
        match self
            .resolver
            .resolve_authoritative_dns_cached(name, record_type)
            .await
            .map_err(|error| error.to_server_error())?
        {
            SnAuthoritativeDnsResult::NotManaged => Err(server_err!(
                ServerErrorCode::NotFound,
                "{} is not in an authoritative SN zone",
                name
            )),
            SnAuthoritativeDnsResult::AuthoritativeAnswer {
                authority,
                resolution,
            } => Ok(DnsQueryResult::Answer {
                name_info: resolution.into_name_info(name),
                authority: Some(authority),
            }),
            SnAuthoritativeDnsResult::AuthoritativeNoData { authority } => {
                Ok(DnsQueryResult::AuthoritativeNoData { authority })
            }
            SnAuthoritativeDnsResult::AuthoritativeNxDomain { authority } => {
                Ok(DnsQueryResult::AuthoritativeNxDomain { authority })
            }
            SnAuthoritativeDnsResult::TemporaryFailure { cause } => {
                Ok(DnsQueryResult::TemporaryFailure { cause })
            }
        }
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
        let user_dns_revision = self
            .resolver
            .synchronize_user_dns_changes()
            .await
            .map_err(|error| error.to_server_error())?;
        let previous_revision = self
            .user_dns_cache_revision
            .swap(user_dns_revision, Ordering::AcqRel);
        if previous_revision != user_dns_revision {
            self.name_info_cache.remove_matching_names(|_| true);
        }
        let bns_cache_state = self.bns_dns_cache_query_state(req_real_name.as_str());
        let bypass_bns_cache = crate::sn_resolver::is_user_dns_control_name(req_real_name.as_str())
            || bns_cache_state
                .as_ref()
                .map(|state| state.bypassed)
                .unwrap_or(false);

        if !bypass_bns_cache {
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
        } else {
            debug!(
                "sn server bypass BNS DNS cache while projection catches up: {} record_type: {:?}",
                req_real_name, record_type
            );
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
                if !bypass_bns_cache {
                    self.update_bns_dns_cache_if_current(bns_cache_state.as_ref(), || {
                        self.name_info_cache.add(
                            req_real_name.as_str(),
                            record_type,
                            name_info.clone(),
                            cache_ttl_secs,
                        );
                    });
                }
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
                if !bypass_bns_cache {
                    self.update_bns_dns_cache_if_current(bns_cache_state.as_ref(), || {
                        self.name_info_cache.add_tombstone(
                            req_real_name.as_str(),
                            record_type,
                            None,
                        );
                    });
                }
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
        let path = request.uri().path().to_string();
        let internal_zone_resolver = is_internal_zone_resolver_ingress(&info);
        if internal_zone_resolver
            && (!path.starts_with(SN_DID_RESOLVER_ROUTE_PREFIX) || request.method() != Method::GET)
        {
            let status = if path.starts_with(SN_DID_RESOLVER_ROUTE_PREFIX) {
                StatusCode::METHOD_NOT_ALLOWED
            } else {
                StatusCode::NOT_FOUND
            };
            return Ok(Response::builder()
                .status(status)
                .body(BoxBody::new(
                    Full::new(Bytes::from_static(if status == StatusCode::NOT_FOUND {
                        b"Not Found"
                    } else {
                        b"Method Not Allowed"
                    }))
                    .map_err(|never| match never {})
                    .boxed(),
                ))
                .unwrap());
        }

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
                if internal_zone_resolver {
                    SnDidResolverProfile::InternalZoneResolver
                } else {
                    SnDidResolverProfile::PublicSupplement
                },
            );
            resolve_request.accept = accept;
            resolve_request.iat = iat;
            let response_accept = resolve_request.accept.clone();
            let started_at = Instant::now();

            match self.did_resolver.resolve(resolve_request).await {
                Ok(resolution) => {
                    let status = resolution.status_code();
                    info!(
                        "SN DID resolver profile={:?} did={} doc_type={} status={} source={:?} latency_ms={}",
                        resolution.profile,
                        resolution.did,
                        resolution.doc_type,
                        resolution
                            .document_status
                            .map(|status| format!("{:?}", status).to_ascii_lowercase())
                            .unwrap_or_else(|| status.as_u16().to_string()),
                        resolution.source,
                        started_at.elapsed().as_millis(),
                    );
                    return Ok(Response::builder()
                        .status(status)
                        .header("Access-Control-Allow-Origin", "*")
                        .header(
                            "Content-Type",
                            resolution.content_type_for_accept(response_accept.as_deref()),
                        )
                        .body(BoxBody::new(
                            Full::new(Bytes::from(
                                resolution.body_for_accept(response_accept.as_deref()),
                            ))
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
                    warn!(
                        "SN DID resolver profile={} status=unknown error_kind={:?} latency_ms={} error={}",
                        if internal_zone_resolver {
                            "internal_zone_resolver"
                        } else {
                            "public_supplement"
                        },
                        e.kind(),
                        started_at.elapsed().as_millis(),
                        e,
                    );
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

        if rpc_path == SnRpcPath::InternalRoot && !is_internal_rpc_client_allowed(client_ip) {
            warn!(
                "Rejected external request to SN internal RPC root from {}",
                client_ip
            );
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(BoxBody::new(
                    Full::new(Bytes::from_static(b"Not Found"))
                        .map_err(|never| match never {})
                        .boxed(),
                ))
                .unwrap());
        }

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

        info!("|==>recv kRPC req: method={}", rpc_request.method);

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
#[serde(deny_unknown_fields)]
pub struct SNServerConfig {
    pub id: String,
    #[doc(hidden)]
    #[serde(rename = "type", default, skip_serializing)]
    pub config_type: Option<String>,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_jwt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pkx: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_jwt: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_data_dir: Option<String>,
    /// C 类种子文件（sn_seed.yaml）路径；相对路径按网关主配置目录解析
    /// （与 local_dns 的 file_path 同语义）。文件缺失时跳过导入。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_path: Option<String>,
    #[serde(default)]
    pub bns_server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_session_token: Option<String>,
    /// user_domain PKX proof 的外部 DoH resolver。默认 Google Public DNS
    /// `https://dns.google/dns-query`（RFC 8484 wire 格式）；URL path 以
    /// `/resolve` 结尾时按 dns.google JSON API 查询。只用于 `domain.bind`
    /// 的服务端 DNS TXT 校验，不影响 SN 自身解析。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkx_doh_url: Option<String>,
    /// Relay 自动分配的有序规则、fallback 和可选 GeoIP XDB。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_allocation: Option<RelayAllocationConfig>,
    /// 与 SN 同进程部署的一体化 relay。配置后启动器会幂等注册该节点，并为
    /// `seed_path` 中已存在但尚未分配 relay 的用户执行自动分配。
    ///
    /// assignment 是运行态数据，仍不写入 `sn_seed.yaml`。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_relay_node: Option<RelayNodeRegistration>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sn_controller_kid: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_controller_doc_types: Option<Vec<String>>,
    /// BNS proxy 写链配置（多 controller key + 白名单 operation）。
    /// 缺省时 SN 以 BNS 只读模式运行。
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bns_proxy: Option<SNBnsProxyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_info_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_path: Option<String>,
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

    fn resolve_geoip_config(mut config: GeoIpResolverConfig) -> GeoIpResolverConfig {
        fn resolve(path: String) -> String {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path.to_string_lossy().to_string()
            } else {
                get_gateway_main_config_dir()
                    .join(path)
                    .to_string_lossy()
                    .to_string()
            }
        }

        config.ipv4_xdb_path = resolve(config.ipv4_xdb_path);
        config.ipv6_xdb_path = config.ipv6_xdb_path.map(resolve);
        config
    }

    async fn probe_bns_rpc(config: &SNServerConfig) -> ServerResult<(BnsRpcClient, BnsSystemInfo)> {
        Self::probe_bns_rpc_with_timeout(config, std::time::Duration::from_secs(5)).await
    }

    async fn probe_bns_rpc_with_timeout(
        config: &SNServerConfig,
        timeout: std::time::Duration,
    ) -> ServerResult<(BnsRpcClient, BnsSystemInfo)> {
        let bns_server_url = config.bns_server_url.trim();
        if bns_server_url.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "bns_server_url is required"
            ));
        }
        let client =
            BnsRpcClient::new_bns_server_url(bns_server_url, config.bns_session_token.clone());
        let system_info = tokio::time::timeout(timeout, client.system_info())
            .await
            .map_err(|_| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "BNS RPC readiness probe timed out: {}",
                    bns_server_url
                )
            })?
            .map_err(|error| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "BNS RPC readiness probe failed for {}: {}",
                    bns_server_url,
                    error
                )
            })?;
        if !system_info.ready {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "BNS RPC is not ready: {}",
                bns_server_url
            ));
        }
        Ok((client, system_info))
    }

    fn sqlite_db_path(config: &SNServerConfig) -> String {
        config.db_path.clone().unwrap_or_else(|| {
            get_buckyos_service_data_dir("sn")
                .join("sn.sqlite3")
                .to_string_lossy()
                .to_string()
        })
    }

    fn remote_db_url(value: &Option<String>, field: &str) -> ServerResult<Option<String>> {
        let Some(value) = value.as_deref() else {
            return Ok(None);
        };
        let value = value.trim();
        if value.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "{} cannot be empty",
                field
            ));
        }
        Ok(Some(value.to_string()))
    }

    fn remote_db_urls(config: &SNServerConfig) -> ServerResult<(Option<String>, Option<String>)> {
        Ok((
            Self::remote_db_url(&config.auth_db, "auth_db")?,
            Self::remote_db_url(&config.device_info_db, "device_info_db")?,
        ))
    }

    /// 解析 BNS proxy controller key 配置。
    /// 返回 (key specs, require_user_asset_owner, allowed_operations)。
    fn resolve_bns_proxy_key_specs(
        proxy_config: &SNBnsProxyConfig,
    ) -> ServerResult<(
        Vec<SnBnsControllerKeySpec>,
        bool,
        HashSet<SnBnsProxyOperation>,
    )> {
        if proxy_config.controllers.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "bns_proxy.controllers cannot be empty"
            ));
        }
        let mut specs = Vec::with_capacity(proxy_config.controllers.len());
        for key_config in &proxy_config.controllers {
            let private_key = key_config
                .load_private_key()
                .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
            specs.push(SnBnsControllerKeySpec {
                id: key_config.id.clone(),
                declared_address: key_config.address.clone(),
                private_key,
                weight: key_config.weight.unwrap_or(1),
            });
        }
        let allowed_operations = proxy_config
            .parse_allowed_operations()
            .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
        Ok((
            specs,
            proxy_config.require_user_asset_owner(),
            allowed_operations,
        ))
    }

    async fn build_bns_proxy(
        config: &SNServerConfig,
        db_path: &str,
        client: BnsRpcClient,
        system_info: &BnsSystemInfo,
    ) -> ServerResult<Option<Arc<SnBnsProxy>>> {
        let Some(proxy_config) = config.bns_proxy.as_ref() else {
            return Ok(None);
        };
        let evm_config = BnsEvmClientConfig::from_system_info(system_info);

        let (key_specs, require_user_asset_owner, allowed_operations) =
            Self::resolve_bns_proxy_key_specs(proxy_config)?;
        let signer_vault = Arc::new(
            SnBnsTxSigner::new(&evm_config, allowed_operations.clone(), key_specs).map_err(
                |e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "create sn bns tx signer failed: {}",
                        e
                    )
                },
            )?,
        );

        let client: Arc<dyn BnsRpcApi> = Arc::new(client);
        let store = Arc::new(SqliteSnBnsWriteRequestStore::open(db_path).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "open sn bns write request store failed: {}",
                e
            )
        })?);

        let mut controllers = Vec::new();
        for info in signer_vault.controller_infos() {
            let key_manager =
                BoundControllerKeyManager::new(signer_vault.clone(), info.id.as_str()).map_err(
                    |e| {
                        server_err!(
                            ServerErrorCode::InvalidConfig,
                            "bind bns proxy controller `{}` failed: {}",
                            info.id,
                            e
                        )
                    },
                )?;
            let evm_controller = Arc::new(BnsEvmControllerClient::new_with_bns_server_submitter(
                evm_config.clone(),
                Arc::new(key_manager),
                client.clone(),
            ));
            let principal = Principal::chain_account(info.address_hex.clone());
            let mut controller_config = SnBnsControllerConfig::new(
                principal.clone(),
                config.sn_controller_kid.clone().unwrap_or_default(),
            );
            if let Some(doc_types) = config.allowed_controller_doc_types.clone() {
                controller_config.allowed_controller_doc_types = doc_types;
            }
            let controller = SnBnsController::new_evm(
                client.clone(),
                store.clone(),
                controller_config,
                evm_controller,
            )
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "create sn bns controller `{}` failed: {}",
                    info.id,
                    e
                )
            })?;
            controllers.push(SnBnsProxyController {
                id: info.id,
                address: info.address_hex,
                principal,
                weight: info.weight,
                controller: Arc::new(controller),
            });
        }

        let binding_store = SqliteSnBnsControllerBindingStore::new_by_path(db_path)
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "open sn bns controller binding store failed: {}",
                    e
                )
            })?;
        binding_store.initialize_database().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "initialize sn bns controller binding store failed: {}",
                e
            )
        })?;
        let bindings: SnBnsControllerBindingStoreRef = Arc::new(binding_store);

        let proxy = SnBnsProxy::new(
            controllers,
            bindings,
            allowed_operations,
            require_user_asset_owner,
        )
        .map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "create sn bns proxy failed: {}",
                e
            )
        })?;
        info!(
            "sn bns proxy enabled: controllers={:?} require_user_asset_owner={}",
            proxy.controller_addresses(),
            require_user_asset_owner
        );
        Ok(Some(Arc::new(proxy)))
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

        let (bns_client, system_info) = Self::probe_bns_rpc(config).await?;

        let db_path = Self::sqlite_db_path(config);
        let (auth_db_url, device_info_db_url) = Self::remote_db_urls(config)?;
        if auth_db_url.is_some() && config.seed_path.is_some() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "seed_path cannot be used with remote auth_db; import seed data through the provider side"
            ));
        }
        let mut allocation_config = config.relay_allocation.clone().unwrap_or_default();
        allocation_config.geoip = allocation_config
            .geoip
            .take()
            .map(Self::resolve_geoip_config);
        let mut seed_users = Vec::new();

        let auth_db: SnAuthDBRef = if let Some(url) = auth_db_url.as_deref() {
            info!("sn server uses remote auth_db provider: {}", url);
            Arc::new(SnAuthDbClient::new_krpc_url(url, None))
        } else {
            let mut auth_db = SqliteSnAuthDB::new_by_path(db_path.as_str())
                .await
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "open sn auth db failed: {}",
                        e
                    )
                })?
                .with_relay_allocation_config(allocation_config.clone());
            if let Some(geoip_config) = allocation_config.geoip.as_ref() {
                match XdbGeoIpResolver::new(geoip_config) {
                    Ok(resolver) => {
                        auth_db = auth_db.with_relay_geo_ip_resolver(Arc::new(resolver));
                        info!("sn AuthDB relay GeoIP resolver enabled");
                    }
                    Err(error) => {
                        warn!(
                            "sn AuthDB relay GeoIP resolver disabled after load failure: error_code={:?} error={}",
                            error.code(),
                            error.msg()
                        );
                    }
                }
            }
            auth_db.initialize_database().await.map_err(|e| {
                server_err!(
                    ServerErrorCode::InvalidConfig,
                    "initialize sn auth db failed: {}",
                    e
                )
            })?;

            // C 类种子幂等导入（ensure-exists）。文件缺失 → 跳过；解析/导入失败 →
            // 启动失败（坏种子不能静默）。语义见 sn_seed.rs 模块注释。
            if let Some(seed_path) = config.seed_path.as_deref() {
                let resolved = crate::resolve_sn_seed_path(seed_path);
                match crate::load_sn_seed_from_path(resolved.as_path()) {
                    Ok(None) => {
                        info!(
                            "sn seed config {} not found; skip seed import",
                            resolved.display()
                        );
                    }
                    Ok(Some(seed)) => {
                        let report = crate::import_sn_seed(&auth_db, &seed).await.map_err(|e| {
                            server_err!(
                                ServerErrorCode::InvalidConfig,
                                "import sn seed config {} failed: {}",
                                resolved.display(),
                                e
                            )
                        })?;
                        seed_users = seed
                            .users
                            .iter()
                            .map(|user| user.username.trim().to_string())
                            .collect();
                        info!("sn seed imported from {}: {}", resolved.display(), report);
                    }
                    Err(e) => {
                        return Err(server_err!(
                            ServerErrorCode::InvalidConfig,
                            "import sn seed config {} failed: {}",
                            resolved.display(),
                            e
                        ));
                    }
                }
            }
            Arc::new(auth_db)
        };
        if let Some(local_relay_node) = config.local_relay_node.as_ref() {
            let relay = auth_db
                .register_relay_node(local_relay_node.clone())
                .await
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "register local relay node {} failed: {}",
                        local_relay_node.relay_id,
                        e
                    )
                })?;
            info!(
                "sn local relay node registered: relay_id={} relay_sn={} ips={:?}",
                relay.relay_id, relay.relay_sn, relay.ips
            );

            for username in seed_users {
                if !auth_db
                    .is_user_exist(username.as_str())
                    .await
                    .map_err(|e| {
                        server_err!(
                            ServerErrorCode::InvalidConfig,
                            "check seed user {} before relay allocation failed: {}",
                            username,
                            e
                        )
                    })?
                {
                    warn!(
                        "skip local relay allocation for seed user {} because the user was not imported",
                        username
                    );
                    continue;
                }
                let mut req = AllocateZoneRelayReq::new(username.clone());
                req.reason = "seed_bootstrap".to_string();
                let assignment = auth_db.allocate_zone_relay(req).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "allocate local relay for seed user {} failed: {}",
                        username,
                        e
                    )
                })?;
                info!(
                    "sn seed user relay ready: zone={} relay_id={} relay_sn={} generation={}",
                    assignment.zone,
                    assignment.relay_id,
                    assignment.relay_sn,
                    assignment.generation
                );
            }
        }
        let capabilities = auth_db.capabilities().await.map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "AuthDB capability check failed: {}",
                e
            )
        })?;
        if capabilities.contract_version != crate::SN_AUTH_DB_CONTRACT_VERSION
            || capabilities.schema_version != crate::SN_AUTH_DB_SCHEMA_VERSION
            || !capabilities.user_dns_rrsets
            || !capabilities.user_dns_change_feed
        {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "incompatible AuthDB capability: expected contract {} / schema {} with user DNS RRsets/change feed, got {:?}",
                crate::SN_AUTH_DB_CONTRACT_VERSION,
                crate::SN_AUTH_DB_SCHEMA_VERSION,
                capabilities
            ));
        }

        let device_info_db: SnDeviceInfoDBRef = if let Some(url) = device_info_db_url.as_deref() {
            info!("sn server uses remote device_info_db provider: {}", url);
            Arc::new(SnDeviceInfoDbClient::new_krpc_url(url, None))
        } else {
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
            Arc::new(device_info_db)
        };

        let bns_proxy =
            Self::build_bns_proxy(config, db_path.as_str(), bns_client.clone(), &system_info)
                .await?;

        let sn = Arc::new(
            SNServer::new(
                config.clone(),
                auth_db,
                device_info_db,
                bns_client,
                bns_proxy,
            )
            .await?,
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

    fn test_relay_registration(relay_id: &str, relay_sn: &str) -> RelayNodeRegistration {
        RelayNodeRegistration {
            relay_id: relay_id.to_string(),
            relay_sn: relay_sn.to_string(),
            ips: [
                "192.0.2.80".parse().unwrap(),
                "2001:db8::80".parse().unwrap(),
            ],
            public_host: relay_sn.to_string(),
            http_endpoint: None,
            rtcp_endpoint: None,
            region: None,
            isp: None,
            tags: Vec::new(),
            capabilities: Vec::new(),
            status: None,
            capacity_score: Some(100),
        }
    }

    #[test]
    fn internal_rpc_root_only_allows_loopback_clients() {
        assert!(is_internal_rpc_client_allowed("127.0.0.1".parse().unwrap()));
        assert!(is_internal_rpc_client_allowed("::1".parse().unwrap()));
        assert!(!is_internal_rpc_client_allowed(
            "10.0.0.10".parse().unwrap()
        ));
        assert!(!is_internal_rpc_client_allowed(
            "198.51.100.10".parse().unwrap()
        ));
    }

    fn test_bns_system_info() -> BnsSystemInfo {
        BnsSystemInfo {
            ready: true,
            chain_id: 31_337,
            contract_address: "0x2222222222222222222222222222222222222222".to_string(),
        }
    }

    fn test_bns_client() -> BnsRpcClient {
        let registry = Arc::new(
            bns_indexer::CentralizedBnsRegistry::new_legacy_state_machine(
                bns_indexer::SqliteBnsRegistryStore::open_memory().unwrap(),
            ),
        );
        BnsRpcClient::new_in_process(Arc::new(bns_indexer::CentralizedBnsIndexerHandler::new(
            registry,
        )))
    }

    /// RFC 8484 wire 格式的 mock DoH 端点：`domain.bind` 的外部 DNS proof
    /// 在测试里通过 `pkx_doh_url` 指到这里；TXT 记录由测试用例动态发布，
    /// 模拟「用户在传统 DNS 配置 PKX TXT」。
    struct MockDohServer {
        records: std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
    }

    impl MockDohServer {
        fn new() -> Self {
            Self {
                records: std::sync::Mutex::new(Default::default()),
            }
        }

        fn record_key(name: &str) -> String {
            name.trim().trim_end_matches('.').to_ascii_lowercase()
        }

        fn set_txt(&self, name: &str, values: Vec<String>) {
            self.records
                .lock()
                .unwrap()
                .insert(Self::record_key(name), values);
        }

        fn remove_txt(&self, name: &str) {
            self.records
                .lock()
                .unwrap()
                .remove(Self::record_key(name).as_str());
        }
    }

    #[async_trait]
    impl HttpServer for MockDohServer {
        async fn serve_request(
            &self,
            request: http::Request<BoxBody<Bytes, ServerError>>,
            _info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            use hickory_proto::op::{Message, MessageType, ResponseCode};
            use hickory_proto::rr::{rdata::TXT, RData, Record};

            let dns_param = request
                .uri()
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|kv| kv.strip_prefix("dns="))
                .expect("mock doh expects RFC 8484 GET with dns param")
                .to_string();
            let raw = URL_SAFE_NO_PAD
                .decode(dns_param.as_bytes())
                .expect("decode dns param");
            let query_message = Message::from_vec(raw.as_slice()).expect("parse dns query message");
            let question = query_message
                .queries()
                .first()
                .cloned()
                .expect("dns query question");
            let name_key = Self::record_key(question.name().to_utf8().as_str());

            let mut response = Message::new();
            response
                .set_id(query_message.id())
                .set_message_type(MessageType::Response)
                .set_op_code(query_message.op_code())
                .set_recursion_desired(true)
                .set_recursion_available(true);
            response.add_query(question.clone());
            match self.records.lock().unwrap().get(name_key.as_str()) {
                Some(values) => {
                    response.set_response_code(ResponseCode::NoError);
                    for value in values {
                        response.add_answer(Record::from_rdata(
                            question.name().clone(),
                            60,
                            RData::TXT(TXT::new(vec![value.clone()])),
                        ));
                    }
                }
                None => {
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }

            let body = response.to_vec().expect("encode dns response");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/dns-message")
                .header("Content-Length", body.len())
                .body(
                    Full::new(Bytes::from(body))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap())
        }

        fn id(&self) -> String {
            "mock-doh".to_string()
        }

        fn http_version(&self) -> http::Version {
            http::Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    /// 从 domain.bind 的 proof 失败错误里取出期望 pkx（错误 message 是
    /// 含 pkx_record_name/pkx 的 JSON，即给用户的「挑战」信息）。
    fn extract_pkx_from_proof_error(error: &str) -> String {
        let start = error.find('{').expect("proof error carries JSON payload");
        let end = error.rfind('}').expect("proof error carries JSON payload");
        let value: Value =
            serde_json::from_str(&error[start..=end]).expect("parse proof error JSON");
        assert_eq!(value["retryable"].as_bool(), Some(true));
        value["pkx"]
            .as_str()
            .expect("pkx in proof error")
            .to_string()
    }

    async fn spawn_test_http_server(http_server: Arc<dyn HttpServer>) -> SocketAddr {
        spawn_test_http_server_with_dst(http_server, None).await
    }

    async fn spawn_test_http_server_with_dst(
        http_server: Arc<dyn HttpServer>,
        dst_addr: Option<String>,
    ) -> SocketAddr {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let http_server = http_server.clone();
                let stream_info = StreamInfo::new(addr.to_string()).with_dst_addr(dst_addr.clone());
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

    #[test]
    fn internal_zone_resolver_ingress_requires_exact_transport_destination() {
        for dst_addr in [
            None,
            Some("invalid"),
            Some("127.0.0.1:3181"),
            Some("[::1]:3180"),
        ] {
            let info = StreamInfo::new("127.0.0.1:12345".to_string())
                .with_dst_addr(dst_addr.map(ToString::to_string));
            assert!(!is_internal_zone_resolver_ingress(&info));
        }
        let info = StreamInfo::new("198.51.100.10:12345".to_string())
            .with_dst_addr(Some(INTERNAL_ZONE_RESOLVER_ADDR.to_string()));
        assert!(is_internal_zone_resolver_ingress(&info));
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

    #[derive(Clone, Copy, Debug)]
    enum ReadinessServerMode {
        Ready,
        Timeout,
        Unauthorized,
        InvalidEnvelope,
    }

    struct ReadinessTestServer {
        mode: ReadinessServerMode,
        next_nonce: std::sync::atomic::AtomicU64,
    }

    impl ReadinessTestServer {
        fn new(mode: ReadinessServerMode) -> Self {
            Self {
                mode,
                next_nonce: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl RPCHandler for ReadinessTestServer {
        async fn handle_rpc_call(
            &self,
            req: RPCRequest,
            _ip_from: IpAddr,
        ) -> std::result::Result<RPCResponse, RPCErrors> {
            if matches!(self.mode, ReadinessServerMode::Timeout) {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            let value = if matches!(self.mode, ReadinessServerMode::InvalidEnvelope) {
                json!({"unexpected": true})
            } else if req.method == bns_client::METHOD_PREPARE_TX {
                let nonce = self
                    .next_nonce
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                serde_json::to_value(bns_client::BnsRpcEnvelope::success(
                    bns_client::BnsPrepareTxResp {
                        nonce,
                        chain_id: 31_337,
                        contract_address: "0x2222222222222222222222222222222222222222".to_string(),
                        estimated_gas: 100_000,
                        gas_limit: 120_000,
                        max_fee_per_gas: 3_000_000_000,
                        max_priority_fee_per_gas: 1_000_000_000,
                    },
                ))
                .unwrap()
            } else if req.method == bns_client::METHOD_SUBMIT_RAW_TX {
                serde_json::to_value(bns_client::BnsRpcEnvelope::success(
                    bns_client::BnsSubmitRawTxResp {
                        tx_hash:
                            "0x4444444444444444444444444444444444444444444444444444444444444444"
                                .to_string(),
                    },
                ))
                .unwrap()
            } else if req.method == bns_client::METHOD_QUERY_TX_STATE {
                serde_json::to_value(bns_client::BnsRpcEnvelope::success(
                    bns_client::BnsTxState {
                        tx_hash:
                            "0x4444444444444444444444444444444444444444444444444444444444444444"
                                .to_string(),
                        state: bns_client::BnsTxExecutionState::Succeeded,
                        block_number: Some(1),
                        confirmations: 1,
                    },
                ))
                .unwrap()
            } else if req.method != bns_client::METHOD_SYSTEM_INFO {
                serde_json::to_value(bns_client::BnsRpcEnvelope::<Value>::failure(
                    bns_client::BnsClientError::registry("NAME_NOT_FOUND", "name not found"),
                ))
                .unwrap()
            } else {
                serde_json::to_value(bns_client::BnsRpcEnvelope::success(test_bns_system_info()))
                    .unwrap()
            };
            Ok(RPCResponse::create_by_req(RPCResult::Success(value), &req))
        }
    }

    #[async_trait]
    impl HttpServer for ReadinessTestServer {
        async fn serve_request(
            &self,
            req: http::Request<BoxBody<Bytes, ServerError>>,
            info: StreamInfo,
        ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
            if matches!(self.mode, ReadinessServerMode::Unauthorized) {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(
                        Full::new(Bytes::from_static(b"unauthorized"))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .unwrap());
            }
            cyfs_gateway_lib::serve_http_by_rpc_handler(req, info, self).await
        }

        fn id(&self) -> String {
            "readiness-test".to_string()
        }

        fn http_version(&self) -> http::Version {
            http::Version::HTTP_11
        }

        fn http3_port(&self) -> Option<u16> {
            None
        }
    }

    fn readiness_config(url: &str) -> SNServerConfig {
        serde_json::from_value(json!({
            "id": "readiness-test",
            "host": "sn.test",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_server_url": url,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn bns_rpc_readiness_is_a_hard_startup_dependency() {
        let missing = SnServerFactory::probe_bns_rpc_with_timeout(
            &readiness_config(""),
            std::time::Duration::from_millis(50),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(missing.contains("bns_server_url is required"), "{missing}");

        let refused_addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let refused = SnServerFactory::probe_bns_rpc_with_timeout(
            &readiness_config(format!("http://{refused_addr}").as_str()),
            std::time::Duration::from_millis(100),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(refused.contains("readiness probe failed"), "{refused}");

        for (mode, expected) in [
            (ReadinessServerMode::Timeout, "timed out"),
            (ReadinessServerMode::Unauthorized, "readiness probe failed"),
            (
                ReadinessServerMode::InvalidEnvelope,
                "readiness probe failed",
            ),
        ] {
            let addr = spawn_test_http_server(Arc::new(ReadinessTestServer::new(mode))).await;
            let error = SnServerFactory::probe_bns_rpc_with_timeout(
                &readiness_config(format!("http://{addr}").as_str()),
                std::time::Duration::from_millis(50),
            )
            .await
            .err()
            .unwrap()
            .to_string();
            assert!(error.contains(expected), "{mode:?}: {error}");
        }

        let addr = spawn_test_http_server(Arc::new(ReadinessTestServer::new(
            ReadinessServerMode::Ready,
        )))
        .await;
        let (_, info) = SnServerFactory::probe_bns_rpc_with_timeout(
            &readiness_config(format!("http://{addr}").as_str()),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(info.ready);
        assert_eq!(info.chain_id, 31_337);
    }

    #[tokio::test]
    async fn read_only_sn_starts_without_ip_and_remote_auth_rejects_seed() {
        let bns_addr = spawn_test_http_server(Arc::new(ReadinessTestServer::new(
            ReadinessServerMode::Ready,
        )))
        .await;
        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let auth_db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
            .await
            .unwrap();
        auth_db.initialize_database().await.unwrap();
        auth_db
            .insert_activation_code("read-only-code")
            .await
            .unwrap();
        let base = json!({
            "id": "read-only",
            "host": "sn.test",
            "bns_server_url": format!("http://{}", bns_addr),
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap()
        });
        let config: SNServerConfig = serde_json::from_value(base.clone()).unwrap();
        let servers = SnServerFactory::new()
            .create(Arc::new(config), None)
            .await
            .unwrap();
        assert_eq!(servers.len(), 3);
        let http_server = servers
            .iter()
            .find_map(|server| match server {
                Server::Http(server) => Some(server.clone()),
                _ => None,
            })
            .unwrap();
        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let register_error = kRPC::new(format!("{}/kapi/sn/auth", base_url).as_str(), None)
            .call(
                "auth.register",
                json!({
                    "name": "readonlyuser",
                    "email": "readonly@example.com",
                    "pwd_hash": "12345678",
                    "active_code": "read-only-code"
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(register_error.contains("[SN:1026:bns_proxy_unavailable]"));
        assert!(register_error.contains("BNS proxy is not configured"));
        assert!(!auth_db.is_user_exist("readonlyuser").await.unwrap());

        let write_error = kRPC::new(base_url.as_str(), None)
            .call(
                "bns.register_name_bootstrap",
                json!({
                    "name": "readonlyuser",
                    "asset_owner": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(write_error.contains("[SN:1026:bns_proxy_unavailable]"));
        assert!(write_error.contains("BNS proxy is not configured"));

        let mut remote_seed = base;
        remote_seed["auth_db"] = json!("http://auth-provider:8080");
        remote_seed["seed_path"] = json!("sn_seed.yaml");
        let config: SNServerConfig = serde_json::from_value(remote_seed).unwrap();
        let error = SnServerFactory::new()
            .create(Arc::new(config), None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("seed_path cannot be used with remote auth_db"));
    }

    #[tokio::test]
    async fn local_relay_bootstrap_repairs_missing_seed_user_assignment() {
        let bns_addr = spawn_test_http_server(Arc::new(ReadinessTestServer::new(
            ReadinessServerMode::Ready,
        )))
        .await;
        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let seed_dir = tempfile::tempdir().unwrap();
        let seed_path = seed_dir.path().join("sn_seed.yaml");
        let seed_yaml = r#"
users:
  - username: seedrelayuser
    email: seedrelayuser@example.com
    password: devtest-password
    owner_public_key: seed-relay-owner-key
"#;
        std::fs::write(seed_path.as_path(), seed_yaml).unwrap();

        // Reproduce an existing VM database: the seed user is present, but no
        // relay node or assignment was created by the old startup path.
        let auth_db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
            .await
            .unwrap();
        auth_db.initialize_database().await.unwrap();
        let seed = crate::load_sn_seed_from_path(seed_path.as_path())
            .unwrap()
            .unwrap();
        crate::import_sn_seed(&auth_db, &seed).await.unwrap();
        assert!(auth_db
            .get_zone_relay("seedrelayuser")
            .await
            .unwrap()
            .is_none());

        let config: SNServerConfig = serde_json::from_value(json!({
            "id": "local-relay-bootstrap",
            "host": "sn.test",
            "bns_server_url": format!("http://{}", bns_addr),
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap(),
            "seed_path": seed_path.to_str().unwrap(),
            "local_relay_node": {
                "relay_id": "embedded-test",
                "relay_sn": "sn.test",
                "ips": ["192.0.2.10", "192.0.2.10"],
                "public_host": "sn.test",
                "http_endpoint": null,
                "rtcp_endpoint": null,
                "region": null,
                "isp": null,
                "tags": ["embedded"],
                "capabilities": ["http_relay", "rtcp_relay"],
                "status": "active",
                "capacity_score": 100
            }
        }))
        .unwrap();
        let servers = SnServerFactory::new()
            .create(Arc::new(config), None)
            .await
            .unwrap();
        assert_eq!(servers.len(), 3);

        let relay = auth_db
            .get_relay_node("embedded-test")
            .await
            .unwrap()
            .expect("local relay node");
        assert_eq!(relay.ips[0], relay.ips[1]);
        let assignment = auth_db
            .get_zone_relay("seedrelayuser")
            .await
            .unwrap()
            .expect("seed user relay assignment");
        assert_eq!(assignment.relay_id, "embedded-test");
        assert_eq!(assignment.relay_sn, "sn.test");
        assert_eq!(
            auth_db
                .get_zone_info("seedrelayuser")
                .await
                .unwrap()
                .unwrap()
                .relay_sn
                .as_deref(),
            Some("sn.test")
        );
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
    fn sn_config_accepts_converged_fields_and_optional_ip() {
        let config = json!({
            "id": "test",
            "type": "sn",
            "host": "buckyos.ai",
            "bns_server_url": "http://127.0.0.1:18080",
            "auth_db": "http://auth-provider:8080",
            "device_info_db": "http://device-provider:8080",
            "db_path": "/var/lib/cyfs/sn.sqlite3"
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        assert!(config.ip.is_none());
        assert!(config.boot_jwt.is_none());
        assert!(config.owner_pkx.is_none());
        assert!(config.device_jwt.is_empty());
        assert!(config.local_relay_node.is_none());
        assert_eq!(config.bns_server_url, "http://127.0.0.1:18080");
        assert_eq!(config.auth_db.as_deref(), Some("http://auth-provider:8080"));
        assert!(SNServer::parse_server_ip(None).unwrap().is_none());
        let invalid_ip = SNServer::parse_server_ip(Some("not-an-ip"))
            .err()
            .unwrap()
            .to_string();
        assert!(invalid_ip.contains("invalid SN server ip not-an-ip"));
    }

    #[test]
    fn sn_config_bootstrap_fields_are_independent_and_not_stack_identity() {
        let base = json!({
            "id": "test",
            "host": "buckyos.ai",
            "bns_server_url": "http://127.0.0.1:18080"
        });
        for (field, value) in [
            ("boot_jwt", json!("boot")),
            ("owner_pkx", json!("owner")),
            ("device_jwt", json!(["device"])),
        ] {
            let mut value_with_field = base.clone();
            value_with_field[field] = value;
            let config: SNServerConfig = serde_json::from_value(value_with_field).unwrap();
            assert_eq!(
                config.boot_jwt.as_deref(),
                (field == "boot_jwt").then_some("boot")
            );
            assert_eq!(
                config.owner_pkx.as_deref(),
                (field == "owner_pkx").then_some("owner")
            );
            assert_eq!(
                config.device_jwt,
                if field == "device_jwt" {
                    vec!["device".to_string()]
                } else {
                    Vec::new()
                }
            );
        }

        let mut misplaced_identity = base;
        misplaced_identity["device_did"] = json!("did:web:sn.example");
        let error = serde_json::from_value::<SNServerConfig>(misplaced_identity)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `device_did`"), "{error}");
    }

    #[test]
    fn auth_and_device_backends_are_selected_independently() {
        for (auth_db, device_info_db) in [
            (None, None),
            (Some("http://auth:8080"), None),
            (None, Some("http://device:8080")),
            (Some("http://auth:8080"), Some("http://device:8080")),
        ] {
            let config: SNServerConfig = serde_json::from_value(json!({
                "id": "test",
                "host": "buckyos.ai",
                "boot_jwt": "",
                "owner_pkx": "",
                "device_jwt": [],
                "bns_server_url": "http://127.0.0.1:18080",
                "auth_db": auth_db,
                "device_info_db": device_info_db
            }))
            .unwrap();
            let selected = SnServerFactory::remote_db_urls(&config).unwrap();
            assert_eq!(selected.0.as_deref(), auth_db);
            assert_eq!(selected.1.as_deref(), device_info_db);
        }

        for (field, value) in [("auth_db", ""), ("device_info_db", "  ")] {
            let mut config = json!({
                "id": "test",
                "host": "buckyos.ai",
                "boot_jwt": "",
                "owner_pkx": "",
                "device_jwt": [],
                "bns_server_url": "http://127.0.0.1:18080"
            });
            config[field] = json!(value);
            let config: SNServerConfig = serde_json::from_value(config).unwrap();
            let error = SnServerFactory::remote_db_urls(&config)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains(&format!("{} cannot be empty", field)));
        }
    }

    #[tokio::test]
    async fn sn_bns_proxy_config_builds_single_controller_proxy() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_server_url": "http://127.0.0.1:18080",
            "bns_proxy": {
                "require_user_asset_owner": false,
                "controllers": [{
                    "id": "default",
                    "private_key": ANVIL_PRIVATE_KEY
                }]
            }
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let proxy = SnServerFactory::build_bns_proxy(
            &config,
            db.path().to_str().unwrap(),
            test_bns_client(),
            &test_bns_system_info(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            proxy.controller_addresses(),
            vec![("default".to_string(), ANVIL_ADDRESS.to_string())]
        );
        assert!(!proxy.require_user_asset_owner());
        let binding = proxy.assign_controller_for_user("alice").await.unwrap();
        assert_eq!(binding.controller_id, "default");
        assert_eq!(binding.controller_address, ANVIL_ADDRESS);
    }

    #[tokio::test]
    async fn sn_bns_proxy_config_builds_multi_controller_proxy() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let config = json!({
            "id": "test",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_server_url": "http://127.0.0.1:18080",
            "bns_proxy": {
                "controllers": [
                    {
                        "id": "controller-a",
                        "address": ANVIL_ADDRESS,
                        "private_key": ANVIL_PRIVATE_KEY
                    },
                    {
                        "id": "controller-b",
                        "private_key": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                    }
                ],
                "allowed_operations": ["register_name_bootstrap", "publish_dns_txt"]
            }
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let proxy = SnServerFactory::build_bns_proxy(
            &config,
            db.path().to_str().unwrap(),
            test_bns_client(),
            &test_bns_system_info(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(proxy.controller_count(), 2);
        // bns_proxy 配置块存在 → 生产默认：注册必须携带用户 asset_owner。
        assert!(proxy.require_user_asset_owner());
        assert!(proxy.allows(crate::SnBnsProxyOperation::PublishDnsTxt));
        assert!(!proxy.allows(crate::SnBnsProxyOperation::PublishRelayAssignment));
    }

    #[tokio::test]
    async fn absent_bns_proxy_is_read_only_and_empty_controllers_are_invalid() {
        let db = tempfile::NamedTempFile::new().unwrap();
        let base = json!({
            "id": "test",
            "host": "buckyos.ai",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "bns_server_url": "http://127.0.0.1:18080"
        });
        let config: SNServerConfig = serde_json::from_value(base.clone()).unwrap();
        let proxy = SnServerFactory::build_bns_proxy(
            &config,
            db.path().to_str().unwrap(),
            test_bns_client(),
            &test_bns_system_info(),
        )
        .await
        .unwrap();
        assert!(proxy.is_none());
        assert_eq!(std::fs::metadata(db.path()).unwrap().len(), 0);

        let mut empty = base;
        empty["bns_proxy"] = json!({ "controllers": [] });
        let config: SNServerConfig = serde_json::from_value(empty).unwrap();
        let error = SnServerFactory::build_bns_proxy(
            &config,
            db.path().to_str().unwrap(),
            test_bns_client(),
            &test_bns_system_info(),
        )
        .await
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("bns_proxy.controllers cannot be empty"));
    }

    /// 模拟「链 + indexer 同步完成」的 EVM 提交器：直接把 TX 应用到
    /// 内存 BNS 状态机（与 bns-client tests 的 ApplyingEvmSubmitter 同构）。
    struct TestApplyingEvmSubmitter {
        registry: Arc<bns_indexer::CentralizedBnsRegistry<bns_indexer::SqliteBnsRegistryStore>>,
        next_nonce: std::sync::Mutex<u64>,
        fail_receipt_wait: bool,
    }

    impl TestApplyingEvmSubmitter {
        fn new(
            registry: Arc<bns_indexer::CentralizedBnsRegistry<bns_indexer::SqliteBnsRegistryStore>>,
            fail_receipt_wait: bool,
        ) -> Self {
            Self {
                registry,
                next_nonce: std::sync::Mutex::new(0),
                fail_receipt_wait,
            }
        }

        fn submission(&self) -> bns_client::BnsEvmTxSubmission {
            let mut next_nonce = self.next_nonce.lock().unwrap();
            let nonce = *next_nonce;
            *next_nonce += 1;
            bns_client::BnsEvmTxSubmission {
                tx_hash: format!("0x{nonce:064x}"),
                raw_tx: format!("0x{nonce:02x}"),
                from: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
                nonce,
                chain_id: 31_337,
                receipt_status: None,
                receipt_block_number: None,
                receipt_confirmations: None,
            }
        }
    }

    #[async_trait]
    impl bns_client::SnBnsEvmSubmitter for TestApplyingEvmSubmitter {
        async fn register_name(
            &self,
            req: &bns_client::BnsRegisterNameReq,
        ) -> bns_client::BnsClientResult<bns_client::BnsEvmTxSubmission> {
            if req.authority_key_updates.is_empty()
                && req.semantic_owner_after_authority.is_none()
                && req.controller_policy.is_empty()
            {
                self.registry
                    .register_name(
                        req.name.as_str(),
                        req.asset_owner.as_str(),
                        req.options.clone(),
                        req.initial_documents.clone(),
                        req.authority.clone(),
                        req.guard,
                    )
                    .map_err(bns_client::BnsClientError::from)?;
            } else {
                self.registry
                    .bootstrap_name(
                        req.name.as_str(),
                        req.asset_owner.as_str(),
                        req.options.clone(),
                        req.initial_documents.clone(),
                        req.authority_key_updates.clone(),
                        req.semantic_owner_after_authority.clone(),
                        req.controller_policy.clone(),
                        req.controller_policy_hash.as_str(),
                        req.authority.clone(),
                        req.guard,
                    )
                    .map_err(bns_client::BnsClientError::from)?;
            }
            Ok(self.submission())
        }

        async fn apply_mutations(
            &self,
            req: &bns_client::BnsApplyMutationsReq,
        ) -> bns_client::BnsClientResult<bns_client::BnsEvmTxSubmission> {
            self.registry
                .apply_mutations(
                    req.name.as_str(),
                    req.authority_key_updates.clone(),
                    req.documents.clone(),
                    req.owner_policy.clone(),
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(bns_client::BnsClientError::from)?;
            Ok(self.submission())
        }

        async fn publish_document(
            &self,
            req: &bns_client::BnsPublishDocumentReq,
        ) -> bns_client::BnsClientResult<bns_client::BnsEvmTxSubmission> {
            self.registry
                .publish_document(
                    req.name.as_str(),
                    req.update.clone(),
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(bns_client::BnsClientError::from)?;
            Ok(self.submission())
        }

        async fn wait_for_receipt(
            &self,
            tx_hash: &str,
            config: bns_client::BnsEvmReceiptWaitConfig,
        ) -> bns_client::BnsClientResult<bns_client::BnsEvmTxReceipt> {
            if self.fail_receipt_wait {
                return Err(bns_client::BnsClientError::Transport(format!(
                    "timed out waiting for BNS EVM tx receipt {tx_hash}"
                )));
            }
            Ok(bns_client::BnsEvmTxReceipt {
                tx_hash: tx_hash.to_string(),
                status: Some(1),
                block_number: 1,
                confirmations: config.confirmations.max(1),
            })
        }
    }

    const PROXY_CONTROLLER_A: &str = "0xcccccccccccccccccccccccccccccccccccccc01";
    const PROXY_CONTROLLER_B: &str = "0xcccccccccccccccccccccccccccccccccccccc02";
    const PROXY_USER_OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// 构建带 in-process BNS 状态机的 SNServer + 双 controller proxy。
    async fn build_sn_with_bns_proxy(
        db_path: &str,
        auth_dir: &std::path::Path,
        require_user_asset_owner: bool,
        fail_receipt_wait: bool,
    ) -> (
        Arc<SNServer>,
        Arc<bns_indexer::CentralizedBnsRegistry<bns_indexer::SqliteBnsRegistryStore>>,
    ) {
        let auth_db = SqliteSnAuthDB::new_by_path(db_path).await.unwrap();
        auth_db.initialize_database().await.unwrap();
        auth_db
            .insert_activation_code(CLEAR_STATE_ACTIVE_CODE)
            .await
            .unwrap();
        auth_db
            .insert_activation_code("bnsProxyCode2")
            .await
            .unwrap();
        let auth_db: SnAuthDBRef = Arc::new(auth_db);

        let device_info_db = SqliteSnDeviceInfoDB::new_by_path(db_path).await.unwrap();
        device_info_db.initialize_database().await.unwrap();
        let device_info_db: SnDeviceInfoDBRef = Arc::new(device_info_db);

        let registry = Arc::new(
            bns_indexer::CentralizedBnsRegistry::new_legacy_state_machine(
                bns_indexer::SqliteBnsRegistryStore::open_memory().unwrap(),
            ),
        );
        let submitter = Arc::new(TestApplyingEvmSubmitter::new(
            registry.clone(),
            fail_receipt_wait,
        ));
        let write_request_store = Arc::new(bns_client::MemorySnBnsWriteRequestStore::new());

        let handler: Arc<dyn BnsRpcApi> = Arc::new(bns_indexer::CentralizedBnsIndexerHandler::new(
            registry.clone(),
        ));
        let bns_client = BnsRpcClient::new_in_process(handler);
        let mut controllers = Vec::new();
        for (id, address) in [
            ("controller-a", PROXY_CONTROLLER_A),
            ("controller-b", PROXY_CONTROLLER_B),
        ] {
            let controller = SnBnsController::new_with_evm_submitter(
                Arc::new(bns_client.clone()),
                write_request_store.clone(),
                SnBnsControllerConfig::new(Principal::chain_account(address), ""),
                submitter.clone(),
            )
            .unwrap();
            controllers.push(crate::SnBnsProxyController {
                id: id.to_string(),
                address: address.to_string(),
                principal: Principal::chain_account(address),
                weight: 1,
                controller: Arc::new(controller),
            });
        }
        let proxy = crate::SnBnsProxy::new(
            controllers,
            Arc::new(crate::MemorySnBnsControllerBindingStore::new()),
            crate::SnBnsProxyOperation::all().into_iter().collect(),
            require_user_asset_owner,
        )
        .unwrap();

        let config = json!({
            "id": "test-bns-proxy",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "auth_data_dir": auth_dir.to_str().unwrap(),
        });
        let config: SNServerConfig = serde_json::from_value(config).unwrap();
        let sn = Arc::new(
            SNServer::new(
                config,
                auth_db,
                device_info_db,
                bns_client,
                Some(Arc::new(proxy)),
            )
            .await
            .unwrap(),
        );
        (sn, registry)
    }

    #[tokio::test]
    async fn test_auth_register_assigns_relay_and_zone_info_reads_it_back() {
        init_logging("sn", false);
        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let (sn, _) =
            build_sn_with_bns_proxy(db.path().to_str().unwrap(), auth_dir.path(), true, false)
                .await;
        for (relay_id, relay_sn, region) in [
            ("relay-eu", "relay-eu.example", "eu"),
            ("relay-us", "relay-us.example", "us-west"),
        ] {
            sn.auth_db()
                .register_relay_node(crate::RelayNodeRegistration {
                    relay_id: relay_id.to_string(),
                    relay_sn: relay_sn.to_string(),
                    ips: [
                        "192.0.2.10".parse().unwrap(),
                        "2001:db8::10".parse().unwrap(),
                    ],
                    public_host: relay_sn.to_string(),
                    http_endpoint: Some(format!("https://{relay_sn}")),
                    rtcp_endpoint: Some(format!("rtcp://{relay_sn}:443")),
                    region: Some(region.to_string()),
                    isp: None,
                    tags: vec!["edge".to_string()],
                    capabilities: vec!["rtcp_relay".to_string()],
                    status: None,
                    capacity_score: Some(100),
                })
                .await
                .unwrap();
        }

        let http_server: Arc<dyn HttpServer> = sn.clone();
        let http_addr = spawn_test_http_server(http_server).await;
        let auth_url = format!("http://{http_addr}/kapi/sn/auth");
        let auth_krpc = kRPC::new(auth_url.as_str(), None);

        let region_result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": "relayregionuser",
                    "email": "relay-region@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "asset_owner": PROXY_USER_OWNER,
                    "region": "US_WEST"
                }),
            )
            .await
            .unwrap();
        let region_token = region_result["access_token"].as_str().unwrap().to_string();
        let region_zone = kRPC::new(auth_url.as_str(), Some(region_token))
            .call("zone.get_info", json!({}))
            .await
            .unwrap();
        assert_eq!(region_zone["relay_sn"], "relay-us.example");
        let region_assignment = sn
            .auth_db()
            .get_zone_relay("relayregionuser")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(region_assignment.relay_sn, "relay-us.example");
        assert_eq!(region_assignment.source, crate::RelayAssignmentSource::Auto);

        // 未提供 region，实际连接源是 loopback，故稳定进入 fallback。客户端伪造的
        // source_ip 字段不属于 RegisterReq，不会传给调度器。
        let fallback_result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": "relayfallbackuser",
                    "email": "relay-fallback@example.com",
                    "pwd_hash": "12345678",
                    "active_code": "bnsProxyCode2",
                    "asset_owner": PROXY_USER_OWNER,
                    "source_ip": "8.8.8.8"
                }),
            )
            .await
            .unwrap();
        let fallback_token = fallback_result["access_token"]
            .as_str()
            .unwrap()
            .to_string();
        let fallback_zone = kRPC::new(auth_url.as_str(), Some(fallback_token))
            .call("zone.get_info", json!({}))
            .await
            .unwrap();
        assert_eq!(fallback_zone["relay_sn"], "relay-eu.example");
        let fallback_assignment = sn
            .auth_db()
            .get_zone_relay("relayfallbackuser")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fallback_assignment.relay_sn, "relay-eu.example");
        assert_eq!(
            fallback_assignment.reason.as_deref(),
            Some("register;rule=fallback")
        );
    }

    #[tokio::test]
    async fn test_sn_bns_proxy_rpc_paths() {
        init_logging("sn", false);
        const PROXY_USER: &str = "bnsproxyuser";

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let (sn, registry) =
            build_sn_with_bns_proxy(db.path().to_str().unwrap(), auth_dir.path(), true, false)
                .await;

        let http_server: Arc<dyn HttpServer> = sn.clone();
        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let bns_proxy_url = format!("{}/kapi/sn/bns-proxy", base_url);
        let internal_url = format!("{}/", base_url);

        // --- 生产模式：缺 asset_owner 注册失败，且不创建本地用户 ---
        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let missing_owner_err = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": PROXY_USER,
                    "email": "proxy-user@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(missing_owner_err.contains("[SN:1000:invalid_params]"));
        assert!(missing_owner_err.contains("asset_owner is required"));

        let result = auth_krpc
            .call("auth.check_username", json!({ "name": PROXY_USER }))
            .await
            .unwrap();
        assert!(
            result["valid"].as_bool().unwrap(),
            "user must not be created when bns bootstrap is rejected"
        );

        // --- 带用户 asset_owner 注册成功，响应携带 BNS TX 信息 ---
        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": PROXY_USER,
                    "email": "proxy-user@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "asset_owner": PROXY_USER_OWNER,
                    "initial_documents": {
                        "dns_txt": [ { "ttl": 600, "value": "pkx=bootstrap" } ]
                    }
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert!(!result["need_bind_owner_key"].as_bool().unwrap());
        let access_token = result["access_token"].as_str().unwrap().to_string();
        let bns = result["bns"].as_object().unwrap();
        assert_eq!(bns["status"].as_str().unwrap(), "confirmed");
        assert_eq!(
            bns["operation"].as_str().unwrap(),
            "register_name_bootstrap"
        );
        assert_eq!(bns["asset_owner"].as_str().unwrap(), PROXY_USER_OWNER);
        assert!(bns["tx_hash"].as_str().unwrap().starts_with("0x"));
        assert!(bns["raw_tx"].as_str().unwrap().starts_with("0x"));
        assert!(bns["nonce"].is_u64());
        assert_eq!(bns["chain_id"].as_u64().unwrap(), 31_337);
        let bound_controller = bns["controller_address"].as_str().unwrap().to_string();
        assert!(
            bound_controller == PROXY_CONTROLLER_A || bound_controller == PROXY_CONTROLLER_B,
            "controller_address must come from SN-side binding"
        );

        // 链上（状态机）验证：assetOwner 是用户地址，绑定 controller 可写 dns_txt。
        let owner = sn
            .bns_proxy()
            .unwrap()
            .controller_for_user(PROXY_USER)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.controller_address, bound_controller);

        // --- publish_dns_txt：token + 本人 name → submitted ---
        let bns_krpc = kRPC::new(bns_proxy_url.as_str(), Some(access_token.clone()));
        let result = bns_krpc
            .call(
                "bns.publish_dns_txt",
                json!({
                    "name": PROXY_USER,
                    "mode": "add",
                    "ttl": 300,
                    "value": "pkx=updated"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["status"].as_str().unwrap(), "submitted");
        assert_eq!(result["doc_type"].as_str().unwrap(), "dns_txt");
        assert_eq!(
            result["controller_address"].as_str().unwrap(),
            bound_controller
        );
        assert!(result["tx_hash"].as_str().unwrap().starts_with("0x"));
        // 响应不等待 receipt：没有 receipt 字段，document_version 是预期版本。
        assert_eq!(result["document_version"].as_u64().unwrap(), 2);

        // --- publish_document：注册后可独立补发任意内容型 document ---
        let result = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-zone-1",
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": { "oods": ["ood1"] }
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["operation"].as_str().unwrap(), "publish_document");
        assert_eq!(result["doc_type"].as_str().unwrap(), "zone");
        assert_eq!(result["document_version"].as_u64().unwrap(), 1);
        let projected_zone = registry.resolve_document(PROXY_USER, "zone").unwrap();
        let projected_zone: serde_json::Value =
            serde_json::from_slice(&projected_zone.document_state.document.inline_document)
                .unwrap();
        assert_eq!(projected_zone["oods"], json!(["ood1"]));

        let zone_jwt = "eyJhbGciOiJFZERTQSJ9.eyJpZCI6ImRpZDpibnM6cHJveHl1c2VyIn0.signature";
        let jwt_result = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-zone-jwt-2",
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": zone_jwt
                }),
            )
            .await
            .unwrap();
        assert_eq!(jwt_result["document_version"].as_u64().unwrap(), 2);
        let projected_zone_jwt = registry.resolve_document(PROXY_USER, "zone").unwrap();
        assert_eq!(
            projected_zone_jwt.document_state.document.inline_document,
            zone_jwt.as_bytes()
        );

        let reused = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-zone-jwt-2",
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": zone_jwt
                }),
            )
            .await
            .unwrap();
        assert!(reused["reused"].as_bool().unwrap());

        let idempotency_error = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-zone-jwt-2",
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": "eyJhbGciOiJFZERTQSJ9.eyJpZCI6ImRpZDp3ZWI6ZXhhbXBsZS5jb20ifQ.signature"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(idempotency_error.contains("idempotency"));

        for invalid_document in [json!(["not", "allowed"]), json!(42), json!(true)] {
            let error = bns_krpc
                .call(
                    "bns.publish_document",
                    json!({
                        "name": PROXY_USER,
                        "doc_type": "zone",
                        "document": invalid_document
                    }),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("[SN:1000:invalid_params]"));
        }

        let owner_jwt_error = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": PROXY_USER,
                    "doc_type": "owner",
                    "document": zone_jwt
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(owner_jwt_error.contains("owner document must be a JSON object"));

        let oversized_jwt = format!("header.{}.signature", "x".repeat(4096));
        let oversized_error = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": oversized_jwt
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(oversized_error.contains("max 4096"));

        // owner 首次补身份字段允许；保持身份字段时其它内容可改；换 key 拒绝且不落 TX。
        let owner_key = json!({"kty":"OKP","crv":"Ed25519","x":"proxy-user-key"});
        let first_owner = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-owner-key-1",
                    "name": PROXY_USER,
                    "doc_type": "owner",
                    "document": { "name": PROXY_USER, "public_key": owner_key.clone() }
                }),
            )
            .await
            .unwrap();
        assert_eq!(first_owner["document_version"].as_u64().unwrap(), 2);
        let owner_content = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-owner-content-2",
                    "name": PROXY_USER,
                    "doc_type": "owner",
                    "document": {
                        "name": PROXY_USER,
                        "public_key": owner_key,
                        "display_name": "Proxy User"
                    }
                }),
            )
            .await
            .unwrap();
        assert_eq!(owner_content["document_version"].as_u64().unwrap(), 3);

        let changed_owner_err = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "request_id": "publish-owner-change-3",
                    "name": PROXY_USER,
                    "doc_type": "owner",
                    "document": {
                        "name": PROXY_USER,
                        "public_key": {"kty":"OKP","crv":"Ed25519","x":"evil-key"}
                    }
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(changed_owner_err.contains("[SN:1000:invalid_params]"));
        assert!(changed_owner_err.contains("cannot be changed"));
        let projected_owner = registry.resolve_document(PROXY_USER, "owner").unwrap();
        assert_eq!(projected_owner.document_state.version, 3);

        // relay_assignment 仍不能借通用入口绕过 internal/admin 边界。
        let reserved_doc_err = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": PROXY_USER,
                    "doc_type": "relay_assignment",
                    "document": { "relays": ["relay1.buckyos.ai"] }
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(reserved_doc_err.contains("[SN:1000:invalid_params]"));
        assert!(reserved_doc_err.contains("internal-only"));

        // --- 跨用户 name 拒绝 ---
        let cross_user_err = bns_krpc
            .call(
                "bns.publish_dns_txt",
                json!({
                    "name": "otheruser",
                    "mode": "add",
                    "value": "pkx=evil"
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(cross_user_err.contains("[SN:1018:cross_user_access_denied]"));

        let cross_user_document_err = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": "otheruser",
                    "doc_type": "zone",
                    "document": { "oods": ["evil"] }
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(cross_user_document_err.contains("[SN:1018:cross_user_access_denied]"));

        // --- 客户端不能指定 controller_address（未知字段直接拒绝）---
        let unknown_field_err = bns_krpc
            .call(
                "bns.publish_dns_txt",
                json!({
                    "name": PROXY_USER,
                    "mode": "add",
                    "value": "pkx=x",
                    "controller_address": PROXY_CONTROLLER_A
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(unknown_field_err.contains("[SN:1000:invalid_params]"));
        assert!(unknown_field_err.contains("controller_address"));

        let unknown_document_field_err = bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": { "oods": ["ood1"] },
                    "authority": {}
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(unknown_document_field_err.contains("[SN:1000:invalid_params]"));
        assert!(unknown_document_field_err.contains("authority"));

        // --- 无 token 拒绝 ---
        let no_token_err = kRPC::new(bns_proxy_url.as_str(), None)
            .call(
                "bns.publish_dns_txt",
                json!({ "name": PROXY_USER, "mode": "add", "value": "pkx=x" }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(no_token_err.contains("[SN:1006:auth_required]"));

        let no_token_document_err = kRPC::new(bns_proxy_url.as_str(), None)
            .call(
                "bns.publish_document",
                json!({
                    "name": PROXY_USER,
                    "doc_type": "zone",
                    "document": { "oods": ["ood1"] }
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(no_token_document_err.contains("[SN:1006:auth_required]"));

        // --- internal-only 方法不暴露在外部 HTTP 路径 ---
        for method in [
            "bns.publish_relay_assignment",
            "bns.register_name_bootstrap",
        ] {
            let err = bns_krpc
                .call(method, json!({ "name": PROXY_USER }))
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(
                err.contains("not available on /kapi/sn/bns-proxy"),
                "{method} must be internal-only, got: {err}"
            );
        }

        // --- internal 路径（"/"）：relay assignment / bootstrap 恢复可用 ---
        let internal_krpc = kRPC::new(internal_url.as_str(), None);
        let result = internal_krpc
            .call(
                "bns.publish_relay_assignment",
                json!({
                    "name": PROXY_USER,
                    "relay_assignment": { "relays": ["relay1.buckyos.ai"] }
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["status"].as_str().unwrap(), "submitted");
        assert_eq!(result["doc_type"].as_str().unwrap(), "relay_assignment");

        const RECOVER_USER: &str = "bnsrecoveruser";
        let result = internal_krpc
            .call(
                "bns.register_name_bootstrap",
                json!({
                    "request_id": "sn:register:bnsrecoveruser",
                    "name": RECOVER_USER,
                    "asset_owner": PROXY_USER_OWNER
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["status"].as_str().unwrap(), "submitted");
        assert_eq!(result["reused"].as_bool().unwrap(), false);
        let first_tx_hash = result["tx_hash"].as_str().unwrap().to_string();

        // Cross the old second-based created_at boundary before replaying.
        tokio::time::sleep(tokio::time::Duration::from_millis(1_100)).await;

        // 同 request_id 幂等重放：返回同一笔 TX，reused=true。
        let replay = internal_krpc
            .call(
                "bns.register_name_bootstrap",
                json!({
                    "request_id": "sn:register:bnsrecoveruser",
                    "name": RECOVER_USER,
                    "asset_owner": PROXY_USER_OWNER
                }),
            )
            .await
            .unwrap();
        assert_eq!(replay["tx_hash"].as_str().unwrap(), first_tx_hash);
        assert!(replay["reused"].as_bool().unwrap());

        // --- 登录路径回归：proxy 存在时 need_bind_owner_key = false ---
        let result = auth_krpc
            .call(
                "auth.login",
                json!({ "name": PROXY_USER, "pwd_hash": "12345678" }),
            )
            .await
            .unwrap();
        assert!(!result["need_bind_owner_key"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_auth_register_does_not_create_user_before_chain_receipt() {
        init_logging("sn", false);
        const USERNAME: &str = "receiptwaituser";

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let (sn, _) =
            build_sn_with_bns_proxy(db.path().to_str().unwrap(), auth_dir.path(), true, true).await;
        let http_server: Arc<dyn HttpServer> = sn.clone();
        let http_addr = spawn_test_http_server(http_server).await;
        let auth_krpc = kRPC::new(format!("http://{http_addr}/kapi/sn/auth").as_str(), None);

        let error = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": USERNAME,
                    "email": "receipt-wait@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE,
                    "asset_owner": PROXY_USER_OWNER
                }),
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("timed out waiting for BNS EVM tx receipt"));
        assert!(!sn.auth_db().is_user_exist(USERNAME).await.unwrap());
        assert!(sn
            .auth_db()
            .check_active_code(CLEAR_STATE_ACTIVE_CODE)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_sn_bns_proxy_dns_txt_projection_visible_after_submit() {
        init_logging("sn", false);
        const PROXY_USER: &str = "bnsprojuser";

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let (sn, registry) =
            build_sn_with_bns_proxy(db.path().to_str().unwrap(), auth_dir.path(), false, false)
                .await;

        let http_server: Arc<dyn HttpServer> = sn.clone();
        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let bns_proxy_url = format!("{}/kapi/sn/bns-proxy", base_url);

        // devtest 模式：asset_owner 缺省回落为绑定 controller 地址。
        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": PROXY_USER,
                    "email": "proxy-user@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        let access_token = result["access_token"].as_str().unwrap().to_string();
        let bns = result["bns"].as_object().unwrap();
        let bound_controller = bns["controller_address"].as_str().unwrap().to_string();
        assert_eq!(bns["asset_owner"].as_str().unwrap(), bound_controller);

        let dns_name = format!("{}.web3.buckyos.ai", PROXY_USER);
        let stale_dns =
            NameServer::query(sn.as_ref(), dns_name.as_str(), Some(RecordType::TXT), None)
                .await
                .unwrap();
        assert!(!stale_dns.txt.iter().any(|txt| txt == "pkx=projection"));
        let stale_cache_state = sn.bns_dns_cache_query_state(dns_name.as_str()).unwrap();

        let bns_krpc = kRPC::new(bns_proxy_url.as_str(), Some(access_token));
        let result = bns_krpc
            .call(
                "bns.publish_dns_txt",
                json!({
                    "name": PROXY_USER,
                    "mode": "add",
                    "value": "pkx=projection"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "submitted");

        // 权威状态经「链→indexer 投影」可见（测试里状态机即投影源）。
        let handler: Arc<dyn BnsRpcApi> =
            Arc::new(bns_indexer::CentralizedBnsIndexerHandler::new(registry));
        let reader = BnsRpcClient::new_in_process(handler);
        let resolved = reader
            .resolve_document(PROXY_USER, "dns_txt")
            .await
            .unwrap();
        let inline = String::from_utf8(resolved.document_state.document.inline_document).unwrap();
        assert!(inline.contains("pkx=projection"), "{inline}");
        assert!(sn
            .name_info_cache
            .query(dns_name.as_str(), RecordType::TXT)
            .is_none());

        // Simulate a DNS query that started before invalidation and completed
        // afterward. Its old generation must not be allowed to repopulate the
        // cache with a long-lived stale value.
        let inserted = sn.update_bns_dns_cache_if_current(Some(&stale_cache_state), || {
            sn.name_info_cache.add(
                dns_name.as_str(),
                RecordType::TXT,
                stale_dns.clone(),
                Some(600),
            );
        });
        assert!(!inserted);
        let projected_dns = NameServer::query(
            sn.as_ref(),
            dns_name.to_ascii_uppercase().as_str(),
            Some(RecordType::TXT),
            None,
        )
        .await
        .unwrap();
        assert!(
            projected_dns.txt.iter().any(|txt| txt == "pkx=projection"),
            "{:?}",
            projected_dns.txt
        );

        // Expire the projection bypass without waiting a minute. The raced
        // old generation must still be rejected, and a mixed-case query must
        // continue to resolve and cache the projected value.
        {
            let mut states = sn
                .bns_dns_cache_state
                .write()
                .unwrap_or_else(|err| err.into_inner());
            states.get_mut(PROXY_USER).unwrap().bypass_until = Instant::now();
        }
        let inserted_after_bypass =
            sn.update_bns_dns_cache_if_current(Some(&stale_cache_state), || {
                sn.name_info_cache
                    .add(dns_name.as_str(), RecordType::TXT, stale_dns, Some(600));
            });
        assert!(!inserted_after_bypass);

        let projected_after_bypass = NameServer::query(
            sn.as_ref(),
            dns_name.to_ascii_uppercase().as_str(),
            Some(RecordType::TXT),
            None,
        )
        .await
        .unwrap();
        assert!(
            projected_after_bypass
                .txt
                .iter()
                .any(|txt| txt == "pkx=projection"),
            "{:?}",
            projected_after_bypass.txt
        );
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

        const TAKEOVER_USER: &str = "takeoveruser";
        const TAKEOVER_ACTIVE_CODE: &str = "kO3pQ4rS5tU6vW7xY8zA";
        const EMAIL_CONFLICT_ACTIVE_CODE: &str = "email-conflict-active-code";

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
            db.insert_activation_code(TAKEOVER_ACTIVE_CODE)
                .await
                .unwrap();
            db.insert_activation_code(EMAIL_CONFLICT_ACTIVE_CODE)
                .await
                .unwrap();
        }

        // domain.bind 的外部 DNS proof path 指向本地 mock DoH（RFC 8484）。
        let mock_doh = Arc::new(MockDohServer::new());
        let doh_addr = spawn_test_http_server(mock_doh.clone()).await;
        let bns_addr = spawn_test_http_server(Arc::new(ReadinessTestServer::new(
            ReadinessServerMode::Ready,
        )))
        .await;

        let config = json!({
            "id": "test-refactor",
            "host": "buckyos.ai",
            "ip": "127.0.0.1",
            "boot_jwt": "",
            "owner_pkx": "",
            "device_jwt": [],
            "db_path": db.path().to_str().unwrap(),
            "auth_data_dir": auth_dir.path().to_str().unwrap(),
            "pkx_doh_url": format!("http://{}/dns-query", doh_addr),
            "bns_server_url": format!("http://{}", bns_addr),
            "bns_proxy": {
                "require_user_asset_owner": false,
                "controllers": [{
                    "id": "default",
                    "private_key": ANVIL_PRIVATE_KEY
                }]
            },
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

        let internal_http_addr = spawn_test_http_server_with_dst(
            http_server.clone(),
            Some(INTERNAL_ZONE_RESOLVER_ADDR.to_string()),
        )
        .await;
        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let internal_base_url = format!("http://{}", internal_http_addr);
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

        let missing_email_err = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": REFACTOR_USER,
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(missing_email_err.contains("[SN:1028:invalid_email]"));

        let invalid_email_err = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": REFACTOR_USER,
                    "email": "not-an-email",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(invalid_email_err.contains("[SN:1028:invalid_email]"));

        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": REFACTOR_USER,
                    "email": "refactor-user@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        let access_token = result["access_token"].as_str().unwrap().to_string();

        // The public and loopback Zone Resolver ingress share one SNServer but
        // select profiles only from transport metadata. Client-controlled
        // headers/query parameters cannot opt into the Internal profile.
        let client = reqwest::Client::new();
        let public_response = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:{}?profile=internal_zone_resolver",
                base_url, REFACTOR_USER
            ))
            .header("x-sn-resolver-profile", "internal_zone_resolver")
            .send()
            .await
            .unwrap();
        assert!(public_response.status().is_success());
        let public_body: Value = public_response.json().await.unwrap();
        assert!(public_body.get("didDocumentMetadata").is_none());

        let internal_response = client
            .get(format!(
                "{}/1.0/identifiers/did:bns:{}",
                internal_base_url, REFACTOR_USER
            ))
            .send()
            .await
            .unwrap();
        assert!(internal_response.status().is_success());
        assert_eq!(
            internal_response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .unwrap(),
            crate::sn_did_resolver::DID_RESOLUTION_CONTENT_TYPE
        );
        let internal_body: Value = internal_response.json().await.unwrap();
        assert_eq!(
            internal_body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "active"
        );
        assert_eq!(
            internal_body["didDocumentMetadata"]["buckyos"]["resolverRole"],
            "zone_resolver"
        );
        let zone_client = ZoneResolverClient::new(ZoneResolverConfig {
            endpoint: internal_base_url.clone(),
            connect_timeout: Duration::from_millis(100),
            request_timeout: Duration::from_secs(1),
        });
        let zone_did = DID::from_str(format!("did:bns:{}", REFACTOR_USER).as_str()).unwrap();
        match zone_client
            .lookup(&zone_did, &DidDocType::Zone, false)
            .await
        {
            ZoneLookup::Answered(answer) => {
                let resolved = answer.result.unwrap();
                assert_eq!(
                    resolved.resolution_metadata.cache_status,
                    Some(CacheStatus::ZoneHit)
                );
                let state = answer.state.unwrap();
                assert_eq!(state.document_status, DocumentStatus::Active);
                assert!(state.document_ref.is_some());
                assert!(state.checked_at.is_some());
                assert!(state.valid_until.is_some());
            }
            ZoneLookup::Unknown(error) => {
                panic!("SN internal response must be a Zone answer: {}", error)
            }
        }

        let forbidden_rpc = client
            .post(format!("{}/kapi/sn/auth", internal_base_url))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden_rpc.status(), StatusCode::NOT_FOUND);
        let forbidden_method = client
            .post(format!(
                "{}/1.0/identifiers/did:bns:{}",
                internal_base_url, REFACTOR_USER
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        let unknown_response = client
            .get(format!(
                "{}/1.0/identifiers/did:web:unmanaged.example?type=device",
                internal_base_url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(unknown_response.status(), StatusCode::NOT_FOUND);
        assert!(
            !unknown_response
                .text()
                .await
                .unwrap()
                .contains("documentStatus"),
            "an unmanaged DID must remain unknown rather than becoming a Zone negative"
        );

        let duplicate_email_err = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": "emaildupeuser",
                    "email": "  REFACTOR-USER@EXAMPLE.COM  ",
                    "pwd_hash": "different-password",
                    "active_code": EMAIL_CONFLICT_ACTIVE_CODE
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(duplicate_email_err.contains("[SN:1029:email_already_bound]"));

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

        // Phase 2 authorization consumes only the already-verified semantic
        // DID's registration binding. The mock BNS has no device document, so
        // this succeeds only if resolve_ood_by_did does not inspect
        // verificationMethod or reconstruct a did:dev from resolver content.
        let scoped_ood = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": format!("did:bns:ood1.{}", REFACTOR_USER)
                }),
            )
            .await
            .unwrap();
        assert_eq!(scoped_ood["owner_id"], REFACTOR_USER);
        assert_eq!(
            scoped_ood["canonical_device_id"],
            device_config.id.to_string()
        );
        assert_eq!(
            scoped_ood["did_hostname"],
            DID::from_str(device_config.id.to_string().as_str())
                .unwrap()
                .to_host_name()
        );

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

        // `user.add_dns_record` keeps the SN-provided web3 bridge namespace in
        // AuthDB even before a traditional user_domain is bound. ACME can
        // therefore create and remove its short-lived TXT challenge without
        // publishing a BNS document on chain.
        let bridge_challenge = format!("_acme-challenge.{}.web3.buckyos.ai", REFACTOR_USER);
        let result = auth_user_krpc
            .call(
                "user.add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": bridge_challenge,
                    "record_type": "TXT",
                    "record": "temporary-acme-proof",
                    "ttl": 60
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["device_name"].as_str().unwrap(), "ood1");

        let result = auth_user_krpc
            .call("user.list_dns_records", json!({}))
            .await
            .unwrap();
        let bridge_record = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"].as_str() == Some(bridge_challenge.as_str()))
            .unwrap();
        assert_eq!(bridge_record["record_type"], "TXT");
        assert_eq!(bridge_record["values"], json!(["temporary-acme-proof"]));

        let other_bridge_err = auth_user_krpc
            .call(
                "user.add_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": "_acme-challenge.other.web3.buckyos.ai",
                    "record_type": "TXT",
                    "record": "not-owned"
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(other_bridge_err.contains("[SN:1015:invalid_domain]"));

        auth_user_krpc
            .call(
                "user.remove_dns_record",
                json!({
                    "device_did": device_config.id.to_string(),
                    "domain": bridge_challenge,
                    "record_type": "TXT"
                }),
            )
            .await
            .unwrap();
        let result = auth_user_krpc
            .call("user.list_dns_records", json!({}))
            .await
            .unwrap();
        assert!(result["items"].as_array().unwrap().is_empty());

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
        assert_eq!(ood_info.state, SnOodState::Active);
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
        assert_eq!(ood_info.state, SnOodState::Active);
        assert!(!ood_info.self_cert);

        // 注册时没有可用 relay，AuthDB 已持久化 pending。node 注册后 provider
        // 内部补偿 assignment，resolver 随后只使用该 assignment 的双 IP。
        {
            let relay_db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            relay_db
                .register_relay_node(test_relay_registration(
                    "relay-refactor",
                    "relay-refactor.example",
                ))
                .await
                .unwrap();
            let assignment = relay_db
                .get_zone_relay(REFACTOR_USER)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(assignment.relay_id, "relay-refactor");
        }

        // 仅有在线上报不能生成静态 device_mini_doc；按 hostname 解析必须等待
        // BNS 静态文档发布，不能从 DeviceInfo 反向伪造身份文档。
        let nested_web3_host = format!("public.{}.web3.buckyos.ai", REFACTOR_USER);
        let nested_error = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_hostname",
                json!({
                    "dest_host": nested_web3_host
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(nested_error.contains("[SN:1017:hostname_not_found]"));

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
        let pkx_record = format!("_pkx.{}", user_domain);

        // §user_domain：外部 DNS 尚未配置 TXT 时，一站式 domain.bind 返回可
        // 重试错误；错误 payload 即「挑战」——携带待配置的 pkx_record_name
        // 与期望 pkx，不写入任何 binding。
        let bind_err = auth_user_krpc
            .call("domain.bind", json!({ "domain": user_domain }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(bind_err.contains("[SN:1016:domain_proof_failed]"));
        assert!(bind_err.contains(pkx_record.as_str()));
        let expected_pkx = extract_pkx_from_proof_error(bind_err.as_str());

        // 客户端传入 txt_records 不再是信任边界：伪造 proof 无法激活绑定，
        // 服务端只认自己的 DNS 查询。
        let forged_err = auth_user_krpc
            .call(
                "domain.bind",
                json!({
                    "domain": user_domain,
                    "txt_records": [expected_pkx]
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(forged_err.contains("[SN:1016:domain_proof_failed]"));
        let profile = auth_user_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert!(profile["user_domain"].is_null());

        // Beta2.2 不再保留两阶段验证 API 的兼容 alias。
        for removed_method in ["domain.begin_verify", "domain.verify"] {
            let removed_err = auth_user_krpc
                .call(removed_method, json!({ "domain": user_domain }))
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(removed_err.contains("not available on /kapi/sn/auth"));
        }

        // 在「外部 DNS」（mock DoH）发布 PKX TXT 后，一站式 bind 成功激活。
        mock_doh.set_txt(pkx_record.as_str(), vec![format!("\"{}\"", expected_pkx)]);
        let bound = auth_user_krpc
            .call("domain.bind", json!({ "domain": user_domain }))
            .await
            .unwrap();
        assert_eq!(bound["code"].as_i64().unwrap(), 0);
        assert_eq!(bound["domain"].as_str().unwrap(), user_domain);
        assert_eq!(bound["pkx"].as_str().unwrap(), expected_pkx);
        assert_eq!(bound["pkx_record_name"].as_str().unwrap(), pkx_record);

        // user_domain 绑定不会改变静态设备文档来源；仍不得用在线态补文档。
        let user_domain_device_error = device_krpc
            .call(
                "deviceinfo.resolve_ood_by_hostname",
                json!({ "dest_host": format!("ood1.{}", user_domain) }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(user_domain_device_error.contains("[SN:1017:hostname_not_found]"));

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

        // §域名转让：新 DNS owner 完成自己的 PKX proof 即可接管同一 canonical
        // domain（历史绑定只作审计，不阻止），无需旧 owner 先 unbind。
        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": TAKEOVER_USER,
                    "email": "takeover-user@example.com",
                    "pwd_hash": "87654321",
                    "active_code": TAKEOVER_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        let takeover_token = result["access_token"].as_str().unwrap().to_string();
        let takeover_krpc = kRPC::new(auth_url.as_str(), Some(takeover_token));

        let takeover_err = takeover_krpc
            .call("domain.bind", json!({ "domain": user_domain }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(takeover_err.contains("[SN:1016:domain_proof_failed]"));
        let takeover_pkx = extract_pkx_from_proof_error(takeover_err.as_str());
        assert_ne!(takeover_pkx, expected_pkx);

        // 新 owner 控制传统 DNS：替换 TXT 为自己的 PKX。
        mock_doh.set_txt(pkx_record.as_str(), vec![takeover_pkx.clone()]);
        let takeover_bound = takeover_krpc
            .call("domain.bind", json!({ "domain": user_domain }))
            .await
            .unwrap();
        assert_eq!(takeover_bound["code"].as_i64().unwrap(), 0);
        assert_eq!(takeover_bound["pkx"].as_str().unwrap(), takeover_pkx);

        // 旧 owner 的 user_domain 兼容缓存已被清理。
        let profile = auth_user_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert!(profile["user_domain"].is_null());
        let profile = takeover_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert_eq!(profile["user_domain"].as_str().unwrap(), user_domain);

        // §unbind：解绑后 SN-DNS 不再响应该 user_domain 及其子域名。
        takeover_krpc
            .call("domain.unbind", json!({ "domain": user_domain }))
            .await
            .unwrap();
        let profile = takeover_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert!(profile["user_domain"].is_null());
        assert!(device_krpc
            .call(
                "deviceinfo.resolve_ood_by_hostname",
                json!({ "dest_host": format!("ood1.{}", user_domain) }),
            )
            .await
            .is_err());
        mock_doh.remove_txt(pkx_record.as_str());

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

    /// 设备级凭证（device token）驱动 device.register / device.update 的
    /// 端到端路径：node_daemon 侧按 `cyfs_gateway_api::generate_sn_device_token`
    /// 签发，SN 侧 `sn_authority::require_sn_device` 校验并锚定 zone 登记的
    /// 设备公钥。覆盖 SN-Auth.md 的 `Device(zone, device, did)` 上下文。
    #[tokio::test]
    async fn test_sn_device_token_report_paths() {
        init_logging("sn", false);
        const DEVTOKEN_USER: &str = "devtokenuser";

        let (device_signing_key, device_pkcs8_bytes) = generate_ed25519_key();
        let device_jwk = encode_ed25519_sk_to_pk_jwk(&device_signing_key);
        let device_config =
            DeviceDocument::new_by_jwk("ood1", serde_json::from_value(device_jwk).unwrap());
        let device_info = DeviceInfo::from_device_doc(&device_config);
        let device_encoding_key =
            jsonwebtoken::EncodingKey::from_ed_der(device_pkcs8_bytes.as_slice());
        let device_key_did = device_config.id.to_string();
        let device_scoped_did = format!("did:bns:ood1.{}", DEVTOKEN_USER);

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let auth_dir = tempfile::tempdir().unwrap();
        let (sn, _) =
            build_sn_with_bns_proxy(db.path().to_str().unwrap(), auth_dir.path(), false, false)
                .await;
        let http_server: Arc<dyn HttpServer> = sn;
        let http_addr = spawn_test_http_server(http_server).await;
        let base_url = format!("http://{}", http_addr);
        let auth_url = format!("{}/kapi/sn/auth", base_url);
        let deviceinfo_url = format!("{}/kapi/sn/deviceinfo", base_url);
        let bns_proxy_url = format!("{}/kapi/sn/bns-proxy", base_url);

        let device_token = cyfs_gateway_api::generate_sn_device_token(
            device_key_did.as_str(),
            device_scoped_did.as_str(),
            None,
            &device_encoding_key,
        )
        .unwrap();
        let device_token_krpc = kRPC::new(deviceinfo_url.as_str(), Some(device_token.clone()));
        let update_params = json!({
            "device_name": "ood1",
            "device_ip": "127.0.0.1",
            "device_info": serde_json::to_string(&device_info).unwrap(),
            "ttl": 600
        });

        // zone 用户还不存在：设备 token 被拒（zone 归属无从谈起）。
        let err = device_token_krpc
            .call("device.update", update_params.clone())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_permission_denied"), "{}", err);

        let auth_krpc = kRPC::new(auth_url.as_str(), None);
        let result = auth_krpc
            .call(
                "auth.register",
                json!({
                    "name": DEVTOKEN_USER,
                    "email": "device-token-user@example.com",
                    "pwd_hash": "12345678",
                    "active_code": CLEAR_STATE_ACTIVE_CODE
                }),
            )
            .await
            .unwrap();
        let access_token = result["access_token"].as_str().unwrap().to_string();

        // zone 权威侧尚无该设备的登记（无 BNS 文档、无历史登记）：拒绝，
        // 不允许"第一个来报的 key 自动成为锚"。
        let err = device_token_krpc
            .call("device.update", update_params.clone())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_permission_denied"), "{}", err);
        assert!(err.contains("is not registered"), "{}", err);

        // 在线登记不能充当静态身份锚。先由账号在 BNS 发布 device_mini_doc，
        // 之后设备 token 才能通过公钥锚定。
        let bns_krpc = kRPC::new(bns_proxy_url.as_str(), Some(access_token.clone()));
        bns_krpc
            .call(
                "bns.publish_document",
                json!({
                    "name": DEVTOKEN_USER,
                    "doc_type": crate::sn_resolver::BNS_DOC_DEVICE_MINI,
                    "document": {
                        "devices": {
                            "ood1": {
                                "did": device_key_did,
                                "mini_config_jwt": "test-device-mini-jwt"
                            }
                        }
                    }
                }),
            )
            .await
            .unwrap();

        // 激活流程用账号 token完成设备首次在线登记。
        let account_krpc = kRPC::new(deviceinfo_url.as_str(), Some(access_token.clone()));
        let result = account_krpc
            .call(
                "device.register",
                json!({
                    "device_name": "ood1",
                    "device_did": device_key_did,
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                    "ttl": 600
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), DEVTOKEN_USER);

        // 设备 token 驱动周期上报（node_daemon 主循环路径）：device_did 缺省
        // 由凭证强制补齐。
        let result = device_token_krpc
            .call("device.update", update_params.clone())
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), DEVTOKEN_USER);
        assert_eq!(result["did"].as_str().unwrap(), device_key_did);

        // The same verified device identity may manage only exact ACME TXT
        // values in its own zone. The payload's device_did is deliberately
        // forged to prove authorization comes from the token context.
        let device_auth_krpc = kRPC::new(auth_url.as_str(), Some(device_token.clone()));
        let challenge = format!("_acme-challenge.{}.web3.buckyos.ai", DEVTOKEN_USER);
        for value in ["root-order", "wildcard-order", "root-order"] {
            device_auth_krpc
                .call(
                    "user.add_dns_record",
                    json!({
                        "device_did": "did:dev:forged-request-value",
                        "domain": challenge,
                        "record_type": "TXT",
                        "record": value,
                        "ttl": 600
                    }),
                )
                .await
                .unwrap();
        }
        device_auth_krpc
            .call(
                "user.remove_dns_record",
                json!({
                    "device_did": "did:dev:forged-request-value",
                    "domain": challenge,
                    "record_type": "TXT",
                    "record": "root-order"
                }),
            )
            .await
            .unwrap();
        let account_auth_krpc = kRPC::new(auth_url.as_str(), Some(access_token.clone()));
        let records = account_auth_krpc
            .call("user.list_dns_records", json!({}))
            .await
            .unwrap();
        assert_eq!(records["items"].as_array().unwrap().len(), 1);
        assert_eq!(records["items"][0]["values"], json!(["wildcard-order"]));

        let err = device_auth_krpc
            .call(
                "user.add_dns_record",
                json!({
                    "device_did": device_key_did,
                    "domain": format!("www.{}.web3.buckyos.ai", DEVTOKEN_USER),
                    "record_type": "A",
                    "record": "127.0.0.1"
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_permission_denied"), "{}", err);

        let result = device_token_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({ "source_device_id": device_key_did }),
            )
            .await
            .unwrap();
        let ood_info = serde_json::from_value::<OODInfo>(result).unwrap();
        assert_eq!(ood_info.owner_id, DEVTOKEN_USER);
        assert_eq!(ood_info.state, SnOodState::Active);

        // ACME completion is reported by the registered device itself. The
        // payload DID is not trusted; zone ownership comes from the verified
        // device token and its registered key anchor.
        let result = device_auth_krpc
            .call(
                "user.set_self_cert",
                json!({
                    "self_cert": true,
                    "device_did": "did:dev:forged-request-value"
                }),
            )
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        let profile = account_auth_krpc
            .call("user.get_profile", json!({}))
            .await
            .unwrap();
        assert!(profile["self_cert"].as_bool().unwrap());

        // 越权：ood1 的设备 token 不能冒名上报 ood2。
        let err = device_token_krpc
            .call(
                "device.update",
                json!({
                    "device_name": "ood2",
                    "device_ip": "127.0.0.1",
                    "device_info": serde_json::to_string(&device_info).unwrap(),
                }),
            )
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_permission_denied"), "{}", err);
        assert!(err.contains("cannot report device ood2"), "{}", err);

        // 冒名：另一把 key 自签 sub，与 zone 登记的设备公钥锚定不上。
        let (rogue_signing_key, rogue_pkcs8_bytes) = generate_ed25519_key();
        let rogue_jwk = encode_ed25519_sk_to_pk_jwk(&rogue_signing_key);
        let rogue_x = rogue_jwk["x"].as_str().unwrap().to_string();
        let rogue_encoding_key =
            jsonwebtoken::EncodingKey::from_ed_der(rogue_pkcs8_bytes.as_slice());
        let rogue_token = cyfs_gateway_api::generate_sn_device_token(
            format!("did:dev:{}", rogue_x).as_str(),
            device_scoped_did.as_str(),
            None,
            &rogue_encoding_key,
        )
        .unwrap();
        let rogue_krpc = kRPC::new(deviceinfo_url.as_str(), Some(rogue_token));
        let err = rogue_krpc
            .call("device.update", update_params.clone())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("device_permission_denied"), "{}", err);
        assert!(err.contains("does not match the registered key"), "{}", err);

        // 签名与 sub 不符（拿别人的 sub、用自己的 key 签）：验签直接失败。
        let forged_token = cyfs_gateway_api::generate_sn_device_token(
            device_key_did.as_str(),
            device_scoped_did.as_str(),
            None,
            &rogue_encoding_key,
        )
        .unwrap();
        let forged_krpc = kRPC::new(deviceinfo_url.as_str(), Some(forged_token));
        let err = forged_krpc
            .call("device.update", update_params.clone())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("invalid_token"), "{}", err);

        // 设备 token 只代表设备，不是账号：账号侧接口拒绝。
        let err = device_token_krpc
            .call("device.list", json!({}))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("invalid_token"), "{}", err);

        // 账号 token 的 device.update 路径不受影响（激活/管理面继续可用）。
        let result = account_krpc
            .call("device.update", update_params.clone())
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), DEVTOKEN_USER);

        // zone.get_info：账号 token 查询本 zone 运行态，zone 由服务端从
        // token 推导；尚未分配 relay 时 relay_sn 为 null。
        let result = account_auth_krpc
            .call("zone.get_info", json!({}))
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), DEVTOKEN_USER);
        assert_eq!(result["bns_name"].as_str().unwrap(), DEVTOKEN_USER);
        assert!(result["relay_sn"].is_null());
        assert!(result["self_cert"].as_bool().unwrap());

        // node 注册后 AuthDB provider 补偿 pending assignment；relay_sn 是
        // assignment join 的只读投影，设备 token 也能读到稳定 relay 名称。
        {
            let relay_db = SqliteSnAuthDB::new_by_path(db.path().to_str().unwrap())
                .await
                .unwrap();
            relay_db
                .register_relay_node(test_relay_registration(
                    "relay-device-token",
                    "us-sn.buckyos.ai",
                ))
                .await
                .unwrap();
            let assignment = relay_db
                .get_zone_relay(DEVTOKEN_USER)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(assignment.relay_id, "relay-device-token");
        }
        let result = device_auth_krpc
            .call("zone.get_info", json!({}))
            .await
            .unwrap();
        assert_eq!(result["code"].as_i64().unwrap(), 0);
        assert_eq!(result["zone"].as_str().unwrap(), DEVTOKEN_USER);
        assert_eq!(result["relay_sn"].as_str().unwrap(), "us-sn.buckyos.ai");

        // 身份字段一律拒绝：不允许"看起来在查别的 zone"。
        let err = account_auth_krpc
            .call("zone.get_info", json!({ "zone": "otherzone" }))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("invalid_params"), "{}", err);

        // 匿名不可查询。
        let err = kRPC::new(auth_url.as_str(), None)
            .call("zone.get_info", json!({}))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("auth_required"), "{}", err);

        // 路径强约束：zone.* 只在 /kapi/sn/auth。
        let err = device_token_krpc
            .call("zone.get_info", json!({}))
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("not available on /kapi/sn/deviceinfo"),
            "{}",
            err
        );
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
                    "email": "sub-domain@example.com",
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
                    "email": "test-user@example.com",
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
                    "email": "short@example.com",
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
                    "email": "registration-user@example.com",
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
