use ::kRPC::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::EncodingKey;
use log::warn;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::result::Result;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const SN_ROOT_PATH: &str = "/kapi/sn";
const SN_AUTH_PATH: &str = "/kapi/sn/auth";
const SN_DEVICEINFO_PATH: &str = "/kapi/sn/deviceinfo";
const SN_BNS_PROXY_PATH: &str = "/kapi/sn/bns-proxy";
const LEGACY_SN_BNS_PATH: &str = "/kapi/sn/bns";
pub const SN_REGION_PROBE_CONFIG_PATH: &str = "/kapi/sn/region-probe-config.json";
pub const SN_REGION_PROBE_SCHEMA_VERSION: u32 = 1;
pub const SN_REGION_PROBE_MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const SN_REGION_PROBE_MAX_REGIONS: usize = 64;
pub const SN_REGION_PROBE_MAX_URLS_PER_REGION: usize = 16;
pub const SN_REGION_PROBE_MAX_TOTAL_URLS: usize = 256;
pub const SN_REGION_PROBE_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnRegionProbeMethod {
    TcpConnect,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnRegionProbeIpFamily {
    Ipv4,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnRegionProbePolicy {
    pub probe_method: SnRegionProbeMethod,
    pub samples_per_url: u8,
    pub connect_timeout_ms: u64,
    pub round_timeout_ms: u64,
    pub max_concurrency: usize,
    pub ip_family: SnRegionProbeIpFamily,
    pub minimum_valid_urls: usize,
    pub confident_ratio: f64,
    pub cache_ttl_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnRegionProbeUrl {
    pub id: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnRegionProbeRegion {
    pub region_id: String,
    #[serde(default)]
    pub priority: i32,
    pub probe_urls: Vec<SnRegionProbeUrl>,
}

/// SN 发布的 Region 探测配置。未知 JSON 字段会被 serde 忽略，以允许 schema v1
/// 在不破坏旧客户端的前提下增加可选字段。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnRegionProbeConfig {
    pub schema_version: u32,
    pub config_version: String,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy: SnRegionProbePolicy,
    pub regions: Vec<SnRegionProbeRegion>,
}

impl SnRegionProbeConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        self.validate_at(Utc::now())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> std::result::Result<(), String> {
        if self.schema_version != SN_REGION_PROBE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {}, expected {}",
                self.schema_version, SN_REGION_PROBE_SCHEMA_VERSION
            ));
        }
        let config_version = self.config_version.trim();
        if config_version.is_empty()
            || config_version.len() > 128
            || config_version != self.config_version
            || config_version.chars().any(char::is_control)
        {
            return Err(
                "config_version must be 1..=128 non-control bytes without surrounding whitespace"
                    .to_string(),
            );
        }
        if self.generated_at >= self.expires_at {
            return Err("expires_at must be later than generated_at".to_string());
        }
        if self.expires_at <= now {
            return Err("region probe config is expired".to_string());
        }

        let policy = &self.policy;
        if !(1..=3).contains(&policy.samples_per_url) {
            return Err("samples_per_url must be in 1..=3".to_string());
        }
        if policy.connect_timeout_ms == 0 || policy.connect_timeout_ms > 10_000 {
            return Err("connect_timeout_ms must be in 1..=10000".to_string());
        }
        if policy.round_timeout_ms == 0 || policy.round_timeout_ms > 30_000 {
            return Err("round_timeout_ms must be in 1..=30000".to_string());
        }
        if policy.max_concurrency == 0 || policy.max_concurrency > 32 {
            return Err("max_concurrency must be in 1..=32".to_string());
        }
        if policy.minimum_valid_urls < 2
            || policy.minimum_valid_urls > SN_REGION_PROBE_MAX_URLS_PER_REGION
        {
            return Err(format!(
                "minimum_valid_urls must be in 2..={}",
                SN_REGION_PROBE_MAX_URLS_PER_REGION
            ));
        }
        if !policy.confident_ratio.is_finite()
            || policy.confident_ratio <= 0.0
            || policy.confident_ratio > 1.0
        {
            return Err("confident_ratio must be finite and in (0, 1]".to_string());
        }
        if policy.cache_ttl_sec == 0 || policy.cache_ttl_sec > 21_600 {
            return Err("cache_ttl_sec must be in 1..=21600".to_string());
        }

        if self.regions.is_empty() || self.regions.len() > SN_REGION_PROBE_MAX_REGIONS {
            return Err(format!(
                "regions must contain 1..={} entries",
                SN_REGION_PROBE_MAX_REGIONS
            ));
        }

        let mut region_ids = HashSet::new();
        let mut probe_ids = HashSet::new();
        let mut origins: HashMap<String, String> = HashMap::new();
        let mut total_urls = 0usize;
        for region in &self.regions {
            if !is_canonical_sn_region_id(region.region_id.as_str()) {
                return Err(format!(
                    "invalid canonical region_id {:?}",
                    region.region_id
                ));
            }
            if !region_ids.insert(region.region_id.as_str()) {
                return Err(format!("duplicate region_id {:?}", region.region_id));
            }
            if region.probe_urls.len() < 2
                || region.probe_urls.len() > SN_REGION_PROBE_MAX_URLS_PER_REGION
            {
                return Err(format!(
                    "region {} must contain 2..={} probe_urls",
                    region.region_id, SN_REGION_PROBE_MAX_URLS_PER_REGION
                ));
            }
            if policy.minimum_valid_urls > region.probe_urls.len() {
                return Err(format!(
                    "region {} has fewer probe_urls than minimum_valid_urls",
                    region.region_id
                ));
            }
            total_urls += region.probe_urls.len();
            if total_urls > SN_REGION_PROBE_MAX_TOTAL_URLS {
                return Err(format!(
                    "config contains more than {} probe URLs",
                    SN_REGION_PROBE_MAX_TOTAL_URLS
                ));
            }

            for probe in &region.probe_urls {
                if probe.id.is_empty()
                    || probe.id.len() > 128
                    || probe.id.trim() != probe.id
                    || probe.id.chars().any(char::is_control)
                {
                    return Err(format!(
                        "probe URL id in region {} must be 1..=128 non-control bytes without surrounding whitespace",
                        region.region_id
                    ));
                }
                if !probe_ids.insert(probe.id.as_str()) {
                    return Err(format!("duplicate probe URL id {:?}", probe.id));
                }

                let parsed = Url::parse(probe.url.as_str())
                    .map_err(|error| format!("invalid probe URL {:?}: {}", probe.url, error))?;
                if parsed.scheme() != "https" {
                    return Err(format!("probe URL {:?} must use https", probe.url));
                }
                if parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                {
                    return Err(format!(
                        "probe URL {:?} must be absolute and must not contain userinfo",
                        probe.url
                    ));
                }
                if parsed.port_or_known_default() != Some(443) {
                    return Err(format!("probe URL {:?} must use port 443", probe.url));
                }
                if let Some(ip) = parsed
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                {
                    if !matches!(ip, IpAddr::V4(_)) || !is_public_sn_probe_ip(ip) {
                        return Err(format!(
                            "probe URL {:?} has a non-public or unsupported literal IP",
                            probe.url
                        ));
                    }
                }
                let origin = parsed.origin().ascii_serialization();
                if let Some(existing_region) = origins.get(origin.as_str()) {
                    if existing_region != &region.region_id {
                        return Err(format!(
                            "probe origin {} is assigned to both {} and {}",
                            origin, existing_region, region.region_id
                        ));
                    }
                    return Err(format!(
                        "probe origin {} is duplicated in region {}",
                        origin, region.region_id
                    ));
                }
                origins.insert(origin, region.region_id.clone());
            }
        }
        Ok(())
    }
}

pub fn is_canonical_sn_region_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// 将注册请求中的非可信 Region 提示规范化为配置使用的 canonical ID。
/// 空白、`_`、`/`、`.`、`-` 和重复分隔符会收敛为单个 `-`；其他字符、非 ASCII
/// 字母数字以及超过 128 字节的输入会被拒绝。
pub fn normalize_sn_region_id_hint(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return None;
    }

    let mut normalized = String::with_capacity(value.len());
    let mut separator_pending = false;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separator_pending && !normalized.is_empty() {
                normalized.push('-');
            }
            separator_pending = false;
            normalized.push(char::from(byte.to_ascii_lowercase()));
        } else if matches!(byte, b'-' | b'_' | b'/' | b'.') || byte.is_ascii_whitespace() {
            separator_pending = !normalized.is_empty();
        } else {
            return None;
        }
    }
    (!normalized.is_empty()).then_some(normalized)
}

/// DNS 解析后、发起 TCP connect 前使用的保守公网地址检查。schema v1 只支持 IPv4；
/// loopback、私网、链路本地、共享地址、文档地址、基准测试网段、多播和保留地址均拒绝。
pub fn is_public_sn_probe_ip(ip: IpAddr) -> bool {
    let IpAddr::V4(ip) = ip else {
        return false;
    };
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

pub fn parse_sn_region_probe_config(
    json: &[u8],
) -> std::result::Result<SnRegionProbeConfig, String> {
    let config: SnRegionProbeConfig = serde_json::from_slice(json)
        .map_err(|error| format!("parse region probe config JSON failed: {}", error))?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnRegionProbeConfigDocument {
    pub config: SnRegionProbeConfig,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SnRegionProbeConfigFetch {
    Modified(SnRegionProbeConfigDocument),
    NotModified,
    NotConfigured,
}

/// `aud` claim of a device-signed SN access token. SN 账号 token 的 aud 是
/// `sn`，设备 token 用独立 aud 隔离，两边的校验路径互不接受对方的 token。
pub const SN_DEVICE_TOKEN_AUD: &str = "sn-device";
/// 设备 token 默认有效期。设备上报周期是秒级，token 只需覆盖单次调用；
/// SN 侧对 exp 有硬上限（见 cyfs-sn sn_authority），不要设置长寿命 token。
pub const SN_DEVICE_TOKEN_DEFAULT_TTL_SECS: u64 = 600;

/// 生成设备级 SN 凭证（JWT，设备私钥 EdDSA 签名）。
///
/// claims 约定（SN 侧 `sn_authority::require_sn_device` 按此校验）：
/// - `sub`: 设备 key DID（`did:dev:<ed25519-x>`），公钥内嵌，签名自证；
/// - `iss`: 设备的 zone 域名层级 DID（如 `did:bns:ood1.alice`、
///   `did:web:ood1.charlie.me`），SN 由此定位 (zone, device_name) 并用
///   zone 权威文档（BNS device_mini_doc / zone doc / 兼容设备表）锚定
///   `sub` 中的公钥，锚定不上则拒绝；
/// - `aud`: [`SN_DEVICE_TOKEN_AUD`]；
/// - `exp`: 过期时间戳。
pub fn generate_sn_device_token(
    device_key_did: &str,
    device_scoped_did: &str,
    ttl_secs: Option<u64>,
    device_private_key: &EncodingKey,
) -> Result<String, RPCErrors> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let session_token = RPCSessionToken {
        token_type: RPCSessionTokenType::JWT,
        token: None,
        aud: Some(SN_DEVICE_TOKEN_AUD.to_string()),
        exp: Some(now + ttl_secs.unwrap_or(SN_DEVICE_TOKEN_DEFAULT_TTL_SECS)),
        iss: Some(device_scoped_did.to_string()),
        jti: None,
        sub: Some(device_key_did.to_string()),
        appid: None,
        sudo: false,
        extra: HashMap::new(),
    };
    session_token.generate_jwt(None, device_private_key)
}

#[derive(Clone, Copy)]
enum SnRpcTarget {
    Auth,
    DeviceInfo,
    BnsProxy,
}

fn normalize_sn_url(sn_url: &str, target: SnRpcTarget) -> String {
    let path = match target {
        SnRpcTarget::Auth => SN_AUTH_PATH,
        SnRpcTarget::DeviceInfo => SN_DEVICEINFO_PATH,
        SnRpcTarget::BnsProxy => SN_BNS_PROXY_PATH,
    };

    let trimmed = sn_url.trim_end_matches('/');
    for known_suffix in [
        SN_BNS_PROXY_PATH,
        SN_DEVICEINFO_PATH,
        SN_AUTH_PATH,
        LEGACY_SN_BNS_PATH,
        SN_ROOT_PATH,
    ] {
        if let Some(base) = trimmed.strip_suffix(known_suffix) {
            return format!("{}{}", base, path);
        }
    }

    format!("{}{}", trimmed, path)
}

fn normalize_sn_region_probe_url(sn_url: &str) -> Result<Url, RPCErrors> {
    let mut url = Url::parse(sn_url.trim()).map_err(|error| {
        RPCErrors::ReasonError(format!(
            "invalid SN base URL for region probe config: {}",
            error
        ))
    })?;
    if url.scheme() != "https" {
        return Err(RPCErrors::ReasonError(
            "region probe config must be fetched from the target SN over HTTPS".to_string(),
        ));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(RPCErrors::ReasonError(
            "SN region probe config URL must have a host and no userinfo".to_string(),
        ));
    }
    url.set_query(None);
    url.set_fragment(None);

    let trimmed_path = url.path().trim_end_matches('/');
    let mut base_path = trimmed_path;
    for known_suffix in [
        SN_REGION_PROBE_CONFIG_PATH,
        SN_BNS_PROXY_PATH,
        SN_DEVICEINFO_PATH,
        SN_AUTH_PATH,
        LEGACY_SN_BNS_PATH,
        SN_ROOT_PATH,
    ] {
        if let Some(base) = trimmed_path.strip_suffix(known_suffix) {
            base_path = base;
            break;
        }
    }
    url.set_path(format!("{}{}", base_path, SN_REGION_PROBE_CONFIG_PATH).as_str());
    Ok(url)
}

/// 匿名获取目标 SN 的 Region 探测配置。重定向被禁用，响应体和总耗时均有本地上限。
/// `304` 与 `404` 作为正常降级结果返回；网络错误、其他状态或非法配置返回错误，调用方
/// 应按激活流程尝试缓存或 fail open，而不是阻断 `auth.register`。
pub async fn fetch_sn_region_probe_config(
    sn_url: &str,
    etag: Option<&str>,
) -> Result<SnRegionProbeConfigFetch, RPCErrors> {
    let url = normalize_sn_region_probe_url(sn_url)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(SN_REGION_PROBE_FETCH_TIMEOUT)
        .build()
        .map_err(|error| {
            RPCErrors::ReasonError(format!(
                "build SN region probe HTTP client failed: {}",
                error
            ))
        })?;
    let mut request = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(etag) = etag {
        let value = reqwest::header::HeaderValue::from_str(etag).map_err(|error| {
            RPCErrors::ReasonError(format!("invalid cached region probe ETag: {}", error))
        })?;
        request = request.header(reqwest::header::IF_NONE_MATCH, value);
    }
    let mut response = request.send().await.map_err(|error| {
        RPCErrors::ReasonError(format!(
            "fetch SN region probe config from {} failed: {}",
            url, error
        ))
    })?;

    match response.status() {
        reqwest::StatusCode::NOT_MODIFIED => return Ok(SnRegionProbeConfigFetch::NotModified),
        reqwest::StatusCode::NOT_FOUND => return Ok(SnRegionProbeConfigFetch::NotConfigured),
        reqwest::StatusCode::OK => {}
        status => {
            return Err(RPCErrors::ReasonError(format!(
                "fetch SN region probe config from {} returned HTTP {}",
                url, status
            )));
        }
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(RPCErrors::ReasonError(format!(
            "SN region probe config from {} has unsupported Content-Type {:?}",
            url, content_type
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > SN_REGION_PROBE_MAX_CONFIG_BYTES as u64)
    {
        return Err(RPCErrors::ReasonError(format!(
            "SN region probe config from {} exceeds {} bytes",
            url, SN_REGION_PROBE_MAX_CONFIG_BYTES
        )));
    }

    let response_etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let cache_control = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        RPCErrors::ReasonError(format!(
            "read SN region probe config from {} failed: {}",
            url, error
        ))
    })? {
        if body.len().saturating_add(chunk.len()) > SN_REGION_PROBE_MAX_CONFIG_BYTES {
            return Err(RPCErrors::ReasonError(format!(
                "SN region probe config from {} exceeds {} bytes",
                url, SN_REGION_PROBE_MAX_CONFIG_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let config = parse_sn_region_probe_config(body.as_slice()).map_err(|error| {
        RPCErrors::ReasonError(format!(
            "invalid SN region probe config from {}: {}",
            url, error
        ))
    })?;
    Ok(SnRegionProbeConfigFetch::Modified(
        SnRegionProbeConfigDocument {
            config,
            etag: response_etag,
            cache_control,
        },
    ))
}

fn new_sn_krpc(sn_url: &str, session_token: Option<String>, target: SnRpcTarget) -> Box<kRPC> {
    let endpoint = normalize_sn_url(sn_url, target);
    Box::new(kRPC::new(endpoint.as_str(), session_token))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthRegisterReq {
    pub name: String,
    pub email: String,
    pub pwd_hash: String,
    pub active_code: String,
    /// Relay 调度的地区偏好。服务端会规范化并将其作为非可信提示；客户端不能指定 relay。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_owner: Option<String>,
    /// BNS owner document 的开放配置对象，字段由具体 BNS 版本定义。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_config: Option<Value>,
    /// 随 BNS `registerName` 原子发布的初始 zone/boot/dns_txt documents。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_documents: Option<SnBnsProxyInitialDocuments>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthLoginReq {
    pub name: String,
    pub pwd_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceOnlineReportReq {
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_did: Option<String>,
    pub device_ip: String,
    /// 设备上报的原始扩展信息；SN 只持久化，不解释其内部 schema。
    pub device_info: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<SnDeviceEndpointUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDnsRecordReq {
    pub device_did: String,
    pub domain: String,
    pub record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_cert: Option<bool>,
}

/// `auth.register` 可携带的 BNS 初始 documents。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnBnsProxyInitialDocuments {
    /// 开放的 BNS zone document。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<Value>,
    /// 开放的 BNS boot document。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_txt: Option<Vec<SnBnsDnsTxtRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnBnsDnsTxtRecord {
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnBnsPublishDnsTxtRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnBnsDnsTxtMode {
    Add,
    Remove,
    Replace,
}

/// `/kapi/sn/bns-proxy` 的 `bns.publish_dns_txt` 参数。
///
/// `add` 需要 `value`（`ttl` 缺省 600），`remove` 需要 `value`，
/// `replace` 需要 `records`。无关字段应保持为 `None`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnBnsPublishDnsTxtReq {
    pub name: String,
    pub mode: SnBnsDnsTxtMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<SnBnsPublishDnsTxtRecord>>,
}

/// `/kapi/sn/bns-proxy` 的 `bns.publish_document` 参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SnBnsPublishDocumentContent {
    JsonObject(Map<String, Value>),
    Jwt(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnBnsPublishDocumentReq {
    pub name: String,
    pub doc_type: String,
    pub document: SnBnsPublishDocumentContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDeviceState {
    Online,
    Offline,
    Stale,
    Blocked,
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str((*self).as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(format!("invalid {}: {}", stringify!($name), value)),
                }
            }
        }
    };
}

string_enum!(SnDeviceState {
    Online => "online",
    Offline => "offline",
    Stale => "stale",
    Blocked => "blocked",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDeviceRole {
    Gateway,
    Ood,
    Normal,
    Unknown,
}

string_enum!(SnDeviceRole {
    Gateway => "gateway",
    Ood => "ood",
    Normal => "normal",
    Unknown => "unknown",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnNatType {
    Public,
    Private,
    Symmetric,
    Unknown,
}

string_enum!(SnNatType {
    Public => "public",
    Private => "private",
    Symmetric => "symmetric",
    Unknown => "unknown",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnEndpointProtocol {
    Tcp,
    Udp,
    Quic,
    Rtcp,
    Http,
    Https,
}

string_enum!(SnEndpointProtocol {
    Tcp => "tcp",
    Udp => "udp",
    Quic => "quic",
    Rtcp => "rtcp",
    Http => "http",
    Https => "https",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnEndpointScope {
    Public,
    Private,
    Relay,
    Loopback,
    Unknown,
}

string_enum!(SnEndpointScope {
    Public => "public",
    Private => "private",
    Relay => "relay",
    Loopback => "loopback",
    Unknown => "unknown",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnEndpointSource {
    DeviceReport,
    FromIp,
    RelayObserved,
    Admin,
}

string_enum!(SnEndpointSource {
    DeviceReport => "device_report",
    FromIp => "from_ip",
    RelayObserved => "relay_observed",
    Admin => "admin",
});

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnEndpointState {
    Active,
    Stale,
    Failed,
    Disabled,
}

string_enum!(SnEndpointState {
    Active => "active",
    Stale => "stale",
    Failed => "failed",
    Disabled => "disabled",
});

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceEndpointUpdate {
    pub endpoint_id: String,
    pub protocol: SnEndpointProtocol,
    pub host: String,
    pub port: Option<u16>,
    pub scope: SnEndpointScope,
    pub priority: i64,
    pub source: SnEndpointSource,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceEndpoint {
    pub did: String,
    pub endpoint_id: String,
    pub protocol: SnEndpointProtocol,
    pub host: String,
    pub port: Option<u16>,
    pub scope: SnEndpointScope,
    pub priority: i64,
    pub source: SnEndpointSource,
    pub state: SnEndpointState,
    pub last_seen_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceStateView {
    pub did: String,
    pub zone: String,
    pub device_name: String,
    pub device_role: SnDeviceRole,
    pub state: SnDeviceState,
    pub public_ips: Vec<String>,
    pub private_ips: Vec<String>,
    pub active_endpoints: Vec<SnDeviceEndpoint>,
    pub preferred_endpoint: Option<SnDeviceEndpoint>,
    pub nat_type: SnNatType,
    pub is_wan_device: bool,
    pub last_seen_at: Option<u64>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnCheckUsernameResp {
    pub valid: bool,
    pub reason: SnCheckUsernameReason,
    pub message: String,
    pub normalized_name: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnCheckUsernameReason {
    Ok,
    InvalidUsername,
    AlreadyExists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnCheckActiveCodeResp {
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnSuccessResp {
    pub code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthSessionResp {
    pub code: u16,
    pub access_token: String,
    pub refresh_token: String,
    pub need_bind_owner_key: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bns: Option<SnBnsProxyTxOutcome>,
}

pub type SnAuthRegisterResp = SnAuthSessionResp;
pub type SnAuthLoginResp = SnAuthSessionResp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthRefreshResp {
    pub code: u16,
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnUserProfileResp {
    pub code: u16,
    pub name: String,
    pub owner_key_bound: bool,
    pub user_domain: Option<String>,
    pub self_cert: bool,
    pub sn_ips: Option<Vec<String>>,
    pub zone_config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAddDnsRecordResp {
    pub code: u16,
    pub device_name: String,
    pub revision: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum SnDnsRecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "TXT")]
    Txt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDnsRrset {
    pub name: String,
    pub record_type: SnDnsRecordType,
    pub ttl: u32,
    pub values: Vec<String>,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnRemoveDnsRecordResp {
    pub code: u16,
    pub revision: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDnsRecordListResp {
    pub code: u16,
    pub items: Vec<SnDnsRrset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnZoneInfoResp {
    pub code: u16,
    pub zone: String,
    pub bns_name: String,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub source_version: Option<String>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnBindDomainResp {
    pub code: u16,
    pub domain: String,
    pub pkx: String,
    pub pkx_record_name: String,
    pub pkx_source: String,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceOnlineResp {
    pub code: u16,
    #[serde(flatten)]
    pub device: SnDeviceStateView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceListResp {
    pub code: u16,
    pub items: Vec<SnDeviceStateView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnOodInfo {
    pub did_hostname: String,
    /// Canonical registered key DID. Older SN responses may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_device_id: Option<String>,
    pub owner_id: String,
    pub self_cert: bool,
    pub state: SnOodState,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnOodState {
    Active,
    Suspended,
    Disabled,
    Banned,
}

/// BNS proxy 写操作的稳定结果。普通写返回 `submitted`，注册路径可返回
/// `confirmed`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnBnsProxyTxOutcome {
    pub request_id: String,
    pub operation: String,
    pub name: String,
    pub controller_id: String,
    pub controller_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx: Option<String>,
    pub status: SnBnsProxyStatus,
    pub reused: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnBnsProxyStatus {
    Submitted,
    Confirmed,
}

string_enum!(SnBnsProxyStatus {
    Submitted => "submitted",
    Confirmed => "confirmed",
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnBnsProxyResp {
    pub code: u16,
    #[serde(flatten)]
    pub outcome: SnBnsProxyTxOutcome,
}

impl SnBnsProxyInitialDocuments {
    pub fn is_empty(&self) -> bool {
        self.zone.is_none() && self.boot.is_none() && self.dns_txt.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnDeviceListReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SnDeviceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

pub enum SnClient {
    InProcess(Box<dyn SnHandler>),
    KRPC {
        auth: Box<kRPC>,
        deviceinfo: Box<kRPC>,
        bns_proxy: Box<kRPC>,
    },
}

impl SnClient {
    pub fn new_in_process(handler: Box<dyn SnHandler>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(sn_url: &str, session_token: Option<String>) -> Self {
        Self::KRPC {
            auth: new_sn_krpc(sn_url, session_token.clone(), SnRpcTarget::Auth),
            deviceinfo: new_sn_krpc(sn_url, session_token.clone(), SnRpcTarget::DeviceInfo),
            bns_proxy: new_sn_krpc(sn_url, session_token, SnRpcTarget::BnsProxy),
        }
    }

    async fn call_auth<T>(&self, method: &str, params: Value) -> Result<T, RPCErrors>
    where
        T: DeserializeOwned,
    {
        let value = match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { auth, .. } => auth.call(method, params).await,
        }?;
        from_value(value, method)
    }

    async fn call_deviceinfo<T>(&self, method: &str, params: Value) -> Result<T, RPCErrors>
    where
        T: DeserializeOwned,
    {
        let value = match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { deviceinfo, .. } => deviceinfo.call(method, params).await,
        }?;
        from_value(value, method)
    }

    async fn call_bns_proxy<T>(&self, method: &str, params: Value) -> Result<T, RPCErrors>
    where
        T: DeserializeOwned,
    {
        let value = match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { bns_proxy, .. } => bns_proxy.call(method, params).await,
        }?;
        from_value(value, method)
    }

    pub async fn check_username(&self, name: &str) -> Result<SnCheckUsernameResp, RPCErrors> {
        self.call_auth(
            "auth.check_username",
            serde_json::json!({
                "name": name
            }),
        )
        .await
    }

    pub async fn check_active_code(
        &self,
        active_code: &str,
    ) -> Result<SnCheckActiveCodeResp, RPCErrors> {
        self.call_auth(
            "auth.check_active_code",
            serde_json::json!({
                "active_code": active_code
            }),
        )
        .await
    }

    pub async fn register(&self, req: SnAuthRegisterReq) -> Result<SnAuthRegisterResp, RPCErrors> {
        self.call_auth("auth.register", to_value(req, "SnAuthRegisterReq")?)
            .await
    }

    pub async fn login(&self, req: SnAuthLoginReq) -> Result<SnAuthLoginResp, RPCErrors> {
        self.call_auth("auth.login", to_value(req, "SnAuthLoginReq")?)
            .await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<SnAuthRefreshResp, RPCErrors> {
        self.call_auth(
            "auth.refresh",
            serde_json::json!({
                "refresh_token": refresh_token
            }),
        )
        .await
    }

    pub async fn logout(&self, refresh_token: Option<&str>) -> Result<SnSuccessResp, RPCErrors> {
        self.call_auth(
            "auth.logout",
            serde_json::json!({
                "refresh_token": refresh_token
            }),
        )
        .await
    }

    pub async fn me(&self) -> Result<SnUserProfileResp, RPCErrors> {
        self.call_auth("auth.me", serde_json::json!({})).await
    }

    pub async fn get_profile(&self) -> Result<SnUserProfileResp, RPCErrors> {
        self.call_auth("user.get_profile", serde_json::json!({}))
            .await
    }

    pub async fn set_self_cert(
        &self,
        self_cert: bool,
        device_did: Option<&str>,
    ) -> Result<SnSuccessResp, RPCErrors> {
        self.call_auth(
            "user.set_self_cert",
            serde_json::json!({
                "self_cert": self_cert,
                "device_did": device_did
            }),
        )
        .await
    }

    pub async fn add_dns_record(
        &self,
        req: SnDnsRecordReq,
    ) -> Result<SnAddDnsRecordResp, RPCErrors> {
        self.call_auth("user.add_dns_record", to_value(req, "SnDnsRecordReq")?)
            .await
    }

    pub async fn remove_dns_record(
        &self,
        req: SnDnsRecordReq,
    ) -> Result<SnRemoveDnsRecordResp, RPCErrors> {
        self.call_auth("user.remove_dns_record", to_value(req, "SnDnsRecordReq")?)
            .await
    }

    pub async fn list_dns_records(&self) -> Result<SnDnsRecordListResp, RPCErrors> {
        self.call_auth("user.list_dns_records", serde_json::json!({}))
            .await
    }

    /// `zone.get_info`：查询调用方所属 zone 的 SN 本地运行态（`relay_sn` 等）。
    ///
    /// 参数固定为空对象，zone 由服务端从已验证 token 推导；账号 access token
    /// 与 `aud=sn-device` 设备 token 均可调用。node_daemon 周期调用该接口检测
    /// `relay_sn` 变化后重建 `keep_tunnel`。尚未分配 relay 时 `relay_sn` 为 null。
    pub async fn get_zone_info(&self) -> Result<SnZoneInfoResp, RPCErrors> {
        self.call_auth("zone.get_info", serde_json::json!({})).await
    }

    pub async fn bind_domain(&self, domain: &str) -> Result<SnBindDomainResp, RPCErrors> {
        self.call_auth(
            "domain.bind",
            serde_json::json!({
                "domain": domain
            }),
        )
        .await
    }

    pub async fn unbind_domain(&self, domain: &str) -> Result<SnSuccessResp, RPCErrors> {
        self.call_auth(
            "domain.unbind",
            serde_json::json!({
                "domain": domain
            }),
        )
        .await
    }

    pub async fn register_device_online(
        &self,
        req: SnDeviceOnlineReportReq,
    ) -> Result<SnDeviceOnlineResp, RPCErrors> {
        self.call_deviceinfo("device.register", to_value(req, "SnDeviceOnlineReportReq")?)
            .await
    }

    pub async fn update_device_online(
        &self,
        req: SnDeviceOnlineReportReq,
    ) -> Result<SnDeviceOnlineResp, RPCErrors> {
        self.call_deviceinfo("device.update", to_value(req, "SnDeviceOnlineReportReq")?)
            .await
    }

    pub async fn get_device_online(
        &self,
        device_name: Option<&str>,
        device_did: Option<&str>,
    ) -> Result<SnDeviceOnlineResp, RPCErrors> {
        self.call_deviceinfo(
            "device.get",
            serde_json::json!({
                "device_name": device_name,
                "device_did": device_did
            }),
        )
        .await
    }

    pub async fn list_devices_online(&self) -> Result<SnDeviceListResp, RPCErrors> {
        self.list_devices_online_with_options(SnDeviceListReq::default())
            .await
    }

    pub async fn list_devices_online_with_options(
        &self,
        req: SnDeviceListReq,
    ) -> Result<SnDeviceListResp, RPCErrors> {
        self.call_deviceinfo("device.list", to_value(req, "SnDeviceListReq")?)
            .await
    }

    pub async fn resolve_ood_by_did(&self, source_device_id: &str) -> Result<SnOodInfo, RPCErrors> {
        self.call_deviceinfo(
            "deviceinfo.resolve_ood_by_did",
            serde_json::json!({
                "source_device_id": source_device_id
            }),
        )
        .await
    }

    pub async fn resolve_ood_by_hostname(&self, dest_host: &str) -> Result<SnOodInfo, RPCErrors> {
        self.call_deviceinfo(
            "deviceinfo.resolve_ood_by_hostname",
            serde_json::json!({
                "dest_host": dest_host
            }),
        )
        .await
    }

    pub async fn publish_dns_txt(
        &self,
        req: SnBnsPublishDnsTxtReq,
    ) -> Result<SnBnsProxyResp, RPCErrors> {
        self.call_bns_proxy(
            "bns.publish_dns_txt",
            to_value(req, "SnBnsPublishDnsTxtReq")?,
        )
        .await
    }

    pub async fn publish_document(
        &self,
        req: SnBnsPublishDocumentReq,
    ) -> Result<SnBnsProxyResp, RPCErrors> {
        self.call_bns_proxy(
            "bns.publish_document",
            to_value(req, "SnBnsPublishDocumentReq")?,
        )
        .await
    }
}

fn to_value<T: Serialize>(value: T, type_name: &str) -> Result<Value, RPCErrors> {
    serde_json::to_value(value)
        .map_err(|e| RPCErrors::ReasonError(format!("Failed to serialize {type_name}: {e}")))
}

fn from_value<T: DeserializeOwned>(value: Value, method: &str) -> Result<T, RPCErrors> {
    serde_json::from_value(value).map_err(|e| {
        RPCErrors::ReasonError(format!(
            "Failed to deserialize {method} response as {}: {e}",
            std::any::type_name::<T>()
        ))
    })
}

/// 底层动态 RPC 适配边界。业务调用应使用 [`SnClient`] 的强类型方法；只有
/// transport 层在这里交换原始 JSON。
#[async_trait]
pub trait SnHandler: Send + Sync {
    async fn handle_sn_rpc(&self, method: &str, params: Value) -> Result<Value, RPCErrors>;
}

pub struct SnServerHandler<T: SnHandler>(pub T);

impl<T: SnHandler> SnServerHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T: SnHandler> RPCHandler for SnServerHandler<T> {
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        let seq = req.seq;
        let trace_id = req.trace_id.clone();
        let result = self
            .0
            .handle_sn_rpc(req.method.as_str(), req.params)
            .await?;

        Ok(RPCResponse {
            result: RPCResult::Success(result),
            seq,
            trace_id,
        })
    }
}

pub async fn sn_auth_register(
    sn_url: &str,
    req: SnAuthRegisterReq,
) -> Result<SnAuthRegisterResp, RPCErrors> {
    SnClient::new_krpc(sn_url, None).register(req).await
}

pub async fn sn_auth_login(
    sn_url: &str,
    req: SnAuthLoginReq,
) -> Result<SnAuthLoginResp, RPCErrors> {
    SnClient::new_krpc(sn_url, None).login(req).await
}

pub async fn sn_update_device_online(
    sn_url: &str,
    access_token: String,
    req: SnDeviceOnlineReportReq,
) -> Result<SnDeviceOnlineResp, RPCErrors> {
    SnClient::new_krpc(sn_url, Some(access_token))
        .update_device_online(req)
        .await
}

pub async fn sn_register_device_online(
    sn_url: &str,
    access_token: String,
    req: SnDeviceOnlineReportReq,
) -> Result<SnDeviceOnlineResp, RPCErrors> {
    SnClient::new_krpc(sn_url, Some(access_token))
        .register_device_online(req)
        .await
}

pub async fn sn_resolve_ood_by_did(
    sn_url: &str,
    source_device_id: &str,
) -> Result<SnOodInfo, RPCErrors> {
    SnClient::new_krpc(sn_url, None)
        .resolve_ood_by_did(source_device_id)
        .await
}

pub async fn sn_resolve_ood_by_hostname(
    sn_url: &str,
    dest_host: &str,
) -> Result<SnOodInfo, RPCErrors> {
    SnClient::new_krpc(sn_url, None)
        .resolve_ood_by_hostname(dest_host)
        .await
}

pub async fn get_real_sn_host_name(
    sn: &str,
    device_id: &str,
) -> std::result::Result<String, RPCErrors> {
    let url = format!("https://{}/config?device_id={}", sn, device_id);
    let response = match reqwest::get(&url).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                "get sn host name from {} failed! {},use sn as host name",
                url, e
            );
            return Ok(sn.to_string());
        }
    };

    let body = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            warn!("get sn host name failed! {}", e);
            return Ok(sn.to_string());
        }
    };

    #[derive(Deserialize)]
    struct SnHostConfig {
        host: String,
    }

    let sn_config = match serde_json::from_str::<SnHostConfig>(&body) {
        Ok(config) if !config.host.trim().is_empty() => config,
        Ok(_) => {
            warn!("get sn host name failed: host is empty");
            return Ok(sn.to_string());
        }
        Err(e) => {
            warn!("get sn host name failed! {}", e);
            return Ok(sn.to_string());
        }
    };

    warn!(
        "get sn real host from {} success! => {}",
        url, sn_config.host
    );
    Ok(sn_config.host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use serde_json::json;

    fn valid_region_probe_config_json() -> Value {
        let now = Utc::now();
        json!({
            "schema_version": 1,
            "config_version": "test-v1",
            "generated_at": (now - ChronoDuration::minutes(1)).to_rfc3339(),
            "expires_at": (now + ChronoDuration::hours(1)).to_rfc3339(),
            "policy": {
                "probe_method": "tcp_connect",
                "samples_per_url": 2,
                "connect_timeout_ms": 1500,
                "round_timeout_ms": 3000,
                "max_concurrency": 8,
                "ip_family": "ipv4",
                "minimum_valid_urls": 2,
                "confident_ratio": 0.75,
                "cache_ttl_sec": 21600
            },
            "regions": [{
                "region_id": "us-west",
                "priority": 100,
                "probe_urls": [{
                    "id": "us-west-a",
                    "url": "https://a.us-west.probe.example/path",
                    "provider": "provider-a"
                }, {
                    "id": "us-west-b",
                    "url": "https://b.us-west.probe.example/"
                }]
            }],
            "future_optional_field": {"ignored": true}
        })
    }

    #[test]
    fn normalize_sn_url_routes_every_known_base_to_the_requested_target() {
        let known_bases = [
            "https://sn.example",
            "https://sn.example/kapi/sn",
            "https://sn.example/kapi/sn/",
            "https://sn.example/kapi/sn/auth",
            "https://sn.example/kapi/sn/deviceinfo",
            "https://sn.example/kapi/sn/bns-proxy",
            "https://sn.example/kapi/sn/bns",
        ];

        for base in known_bases {
            assert_eq!(
                normalize_sn_url(base, SnRpcTarget::Auth),
                "https://sn.example/kapi/sn/auth"
            );
            assert_eq!(
                normalize_sn_url(base, SnRpcTarget::DeviceInfo),
                "https://sn.example/kapi/sn/deviceinfo"
            );
            assert_eq!(
                normalize_sn_url(base, SnRpcTarget::BnsProxy),
                "https://sn.example/kapi/sn/bns-proxy"
            );
        }
    }

    #[test]
    fn region_probe_url_uses_anonymous_resource_on_the_same_https_origin() {
        for base in [
            "https://sn.example",
            "https://sn.example/kapi/sn",
            "https://sn.example/kapi/sn/auth",
            "https://sn.example/kapi/sn/region-probe-config.json",
        ] {
            assert_eq!(
                normalize_sn_region_probe_url(base).unwrap().as_str(),
                "https://sn.example/kapi/sn/region-probe-config.json"
            );
        }
        assert!(normalize_sn_region_probe_url("http://sn.example").is_err());
        assert!(normalize_sn_region_probe_url("https://user@sn.example").is_err());
    }

    #[test]
    fn region_probe_config_accepts_schema_v1_and_ignores_future_fields() {
        let bytes = serde_json::to_vec(&valid_region_probe_config_json()).unwrap();
        let config = parse_sn_region_probe_config(bytes.as_slice()).unwrap();
        assert_eq!(config.schema_version, SN_REGION_PROBE_SCHEMA_VERSION);
        assert_eq!(config.config_version, "test-v1");
        assert_eq!(config.regions[0].region_id, "us-west");
        assert_eq!(config.regions[0].probe_urls.len(), 2);
    }

    #[test]
    fn region_probe_config_rejects_invalid_ids_urls_and_expiry() {
        let mut duplicate_origin = valid_region_probe_config_json();
        duplicate_origin["regions"][0]["probe_urls"][1]["url"] =
            json!("https://a.us-west.probe.example/other-path");
        assert!(
            parse_sn_region_probe_config(&serde_json::to_vec(&duplicate_origin).unwrap())
                .unwrap_err()
                .contains("duplicated")
        );

        let mut invalid_region = valid_region_probe_config_json();
        invalid_region["regions"][0]["region_id"] = json!("US_WEST");
        assert!(
            parse_sn_region_probe_config(&serde_json::to_vec(&invalid_region).unwrap())
                .unwrap_err()
                .contains("region_id")
        );

        let mut unsafe_port = valid_region_probe_config_json();
        unsafe_port["regions"][0]["probe_urls"][0]["url"] =
            json!("https://a.us-west.probe.example:8443/");
        assert!(
            parse_sn_region_probe_config(&serde_json::to_vec(&unsafe_port).unwrap())
                .unwrap_err()
                .contains("port 443")
        );

        let mut private_literal = valid_region_probe_config_json();
        private_literal["regions"][0]["probe_urls"][0]["url"] = json!("https://127.0.0.1/");
        assert!(
            parse_sn_region_probe_config(&serde_json::to_vec(&private_literal).unwrap())
                .unwrap_err()
                .contains("non-public")
        );

        let mut expired = valid_region_probe_config_json();
        expired["generated_at"] = json!((Utc::now() - ChronoDuration::hours(2)).to_rfc3339());
        expired["expires_at"] = json!((Utc::now() - ChronoDuration::hours(1)).to_rfc3339());
        assert!(
            parse_sn_region_probe_config(&serde_json::to_vec(&expired).unwrap())
                .unwrap_err()
                .contains("expired")
        );
    }

    #[test]
    fn region_hint_normalization_matches_register_contract() {
        assert_eq!(
            normalize_sn_region_id_hint("  US__West / 2  ").as_deref(),
            Some("us-west-2")
        );
        assert_eq!(
            normalize_sn_region_id_hint("auto"),
            Some("auto".to_string())
        );
        assert!(normalize_sn_region_id_hint("日本").is_none());
        assert!(normalize_sn_region_id_hint("us@west").is_none());
        assert!(is_canonical_sn_region_id("us-west-2"));
        assert!(!is_canonical_sn_region_id("US-west"));
        assert!(is_public_sn_probe_ip("8.8.8.8".parse().unwrap()));
        for address in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "203.0.113.1", "::1"] {
            assert!(!is_public_sn_probe_ip(address.parse().unwrap()));
        }
    }

    #[test]
    fn register_request_serializes_initial_documents() {
        let request = SnAuthRegisterReq {
            name: "alice".to_string(),
            email: "alice@example.com".to_string(),
            pwd_hash: "hash".to_string(),
            active_code: "code".to_string(),
            region: Some("US-West".to_string()),
            request_id: Some("sn:register:alice".to_string()),
            asset_owner: Some("0x0000000000000000000000000000000000000001".to_string()),
            owner_config: Some(json!({ "display_name": "Alice" })),
            initial_documents: Some(SnBnsProxyInitialDocuments {
                zone: Some(json!({ "gateway": "ood1" })),
                boot: None,
                dns_txt: Some(vec![SnBnsDnsTxtRecord {
                    ttl: 600,
                    value: "pkx=alice".to_string(),
                }]),
            }),
        };

        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({
                "name": "alice",
                "email": "alice@example.com",
                "pwd_hash": "hash",
                "active_code": "code",
                "region": "US-West",
                "request_id": "sn:register:alice",
                "asset_owner": "0x0000000000000000000000000000000000000001",
                "owner_config": { "display_name": "Alice" },
                "initial_documents": {
                    "zone": { "gateway": "ood1" },
                    "dns_txt": [{ "ttl": 600, "value": "pkx=alice" }]
                }
            })
        );
    }

    #[test]
    fn bns_and_device_requests_serialize_documented_values() {
        let publish = SnBnsPublishDnsTxtReq {
            name: "alice".to_string(),
            mode: SnBnsDnsTxtMode::Replace,
            request_id: None,
            ttl: None,
            value: None,
            records: Some(vec![SnBnsPublishDnsTxtRecord {
                ttl: Some(300),
                value: "hello".to_string(),
            }]),
        };
        assert_eq!(
            serde_json::to_value(publish).unwrap(),
            json!({
                "name": "alice",
                "mode": "replace",
                "records": [{ "ttl": 300, "value": "hello" }]
            })
        );

        let list = SnDeviceListReq {
            state: Some(SnDeviceState::Stale),
            offset: Some(10),
            limit: Some(20),
        };
        assert_eq!(
            serde_json::to_value(list).unwrap(),
            json!({ "state": "stale", "offset": 10, "limit": 20 })
        );
    }

    #[test]
    fn response_values_decode_to_public_types() {
        let auth: SnAuthRegisterResp = from_value(
            json!({
                "code": 0,
                "access_token": "access",
                "refresh_token": "refresh",
                "need_bind_owner_key": false,
                "bns": {
                    "request_id": "sn:register:alice",
                    "operation": "register_name_bootstrap",
                    "name": "alice",
                    "controller_id": "controller-a",
                    "controller_address": "0x01",
                    "tx_hash": "0x02",
                    "status": "confirmed",
                    "reused": false
                }
            }),
            "auth.register",
        )
        .unwrap();
        assert_eq!(auth.access_token, "access");
        assert_eq!(auth.bns.unwrap().status, SnBnsProxyStatus::Confirmed);

        let device: SnDeviceOnlineResp = from_value(
            json!({
                "code": 0,
                "did": "did:dev:alice",
                "zone": "alice",
                "device_name": "ood1",
                "device_role": "ood",
                "state": "online",
                "public_ips": ["203.0.113.1"],
                "private_ips": [],
                "active_endpoints": [],
                "preferred_endpoint": null,
                "nat_type": "public",
                "is_wan_device": true,
                "last_seen_at": 1,
                "expires_at": 2
            }),
            "device.get",
        )
        .unwrap();
        assert_eq!(device.device.device_role, SnDeviceRole::Ood);
        assert_eq!(device.device.state, SnDeviceState::Online);
    }

    #[test]
    fn malformed_response_fails_at_the_rpc_boundary() {
        let error = from_value::<SnAuthLoginResp>(
            json!({ "code": 0, "access_token": "missing-other-fields" }),
            "auth.login",
        )
        .unwrap_err();
        assert!(error.to_string().contains("auth.login response"));
    }
}
