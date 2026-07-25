use crate::{
    sn_err, AllocateZoneRelayReq, AssignZoneRelayReq, GeoIpResolverRef, RelayAdmissionDecision,
    RelayAdmissionReq, RelayAllocationConfig, RelayAssignment, RelayAssignmentState,
    RelayHeartbeat, RelayMigrationReq, RelayNode, RelayNodeAddressUpdate, RelayNodeHealth,
    RelayNodeIpMapReq, RelayNodeIpMapSnapshot, RelayNodeRegistration, SnError, SnErrorCode,
    SnRelayManager, SnResult, SqliteSnRelayManager,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVATION_CODE_LEN: usize = 32;
const ACTIVATION_CODE_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const DOMAIN_BINDING_ACTIVE: &str = "active";
const DOMAIN_BINDING_REVOKED: &str = "revoked";
const DOMAIN_BINDING_SUPERSEDED: &str = "superseded";
const SESSION_ACTIVE: &str = "active";
const SESSION_REVOKED: &str = "revoked";
pub const SN_AUTH_DB_SCHEMA_VERSION: u32 = 2;
pub const SN_AUTH_DB_CONTRACT_VERSION: u32 = 2;
pub const USER_DNS_DEFAULT_TTL: u32 = 600;
pub const USER_DNS_MIN_TTL: u32 = 30;
pub const USER_DNS_MAX_TTL: u32 = 86_400;
pub const USER_DNS_MAX_TXT_BYTES: usize = 4_096;
const USER_DNS_CHANGE_RETENTION: u64 = 10_000;

pub type SnAuthDBRef = Arc<dyn SnAuthDB>;

/// 注册邮箱规范化与基本格式校验。
///
/// SN 把邮箱作为本地账号找回标识，不写入 BNS。当前产品规则是 trim 后将
/// ASCII 地址整体转成小写；不接受 quoted local-part、非 ASCII 地址或非法的
/// DNS label。所有唯一性查询和持久化都必须使用本函数的返回值。
pub fn canonical_email(email: &str) -> SnResult<String> {
    let email = email.trim();
    if email.is_empty() || email.len() > 254 || !email.is_ascii() {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email must be a non-empty ASCII address no longer than 254 bytes"
        ));
    }

    let (local, domain) = email.split_once('@').ok_or_else(|| {
        sn_err!(
            SnErrorCode::InvalidInput,
            "email must contain exactly one @ separator"
        )
    })?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || domain.contains('@')
    {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email local part or domain is invalid"
        ));
    }
    if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        })
    {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email local part has invalid syntax"
        ));
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "email domain has invalid syntax"
        ));
    }

    Ok(email.to_ascii_lowercase())
}

/// user_domain 规范化：trim、去尾部 `.`、小写、去可选 `*.` 前缀。
/// 空结果（空串、仅点、仅通配）返回 None。
pub fn canonical_user_domain(domain: &str) -> Option<String> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let canonical = normalized
        .strip_prefix("*.")
        .unwrap_or(normalized.as_str())
        .to_string();
    if canonical.is_empty() || canonical == "*" {
        None
    } else {
        Some(canonical)
    }
}

/// Canonical DNS owner name used by the AuthDB user-DNS contract.
///
/// User DNS names are ASCII, lower-case and stored without a trailing dot.
/// Underscores are accepted because control owners such as
/// `_acme-challenge` and `_pkx` are first-class product features.
pub fn canonical_user_dns_name(name: &str) -> SnResult<String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "DNS name must be a non-empty ASCII name no longer than 253 bytes"
        ));
    }

    let canonical = name.to_ascii_lowercase();
    if canonical.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    }) {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "DNS name contains an invalid label: {}",
            name
        ));
    }
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum UserDnsRecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "TXT")]
    Txt,
}

impl UserDnsRecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Txt => "TXT",
        }
    }
}

impl std::fmt::Display for UserDnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UserDnsRecordType {
    type Err = SnError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "TXT" => Ok(Self::Txt),
            _ => Err(sn_err!(
                SnErrorCode::InvalidInput,
                "unsupported user DNS record type: {}",
                value
            )),
        }
    }
}

pub fn canonical_user_dns_rdata(record_type: UserDnsRecordType, value: &str) -> SnResult<String> {
    match record_type {
        UserDnsRecordType::A => value
            .trim()
            .parse::<Ipv4Addr>()
            .map(|value| value.to_string())
            .map_err(|_| sn_err!(SnErrorCode::InvalidInput, "invalid IPv4 rdata: {}", value)),
        UserDnsRecordType::Aaaa => value
            .trim()
            .parse::<Ipv6Addr>()
            .map(|value| value.to_string())
            .map_err(|_| sn_err!(SnErrorCode::InvalidInput, "invalid IPv6 rdata: {}", value)),
        UserDnsRecordType::Txt => {
            if value.is_empty() {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "TXT rdata must not be empty"
                ));
            }
            if value.as_bytes().len() > USER_DNS_MAX_TXT_BYTES {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "TXT rdata exceeds {} bytes",
                    USER_DNS_MAX_TXT_BYTES
                ));
            }
            // DNS wire encoders may split this logical value into <=255-byte
            // character-strings. Keeping it as one value here preserves commas
            // and other user data without introducing a storage delimiter.
            Ok(value.to_string())
        }
    }
}

pub fn validate_user_dns_ttl(ttl: u32) -> SnResult<u32> {
    if !(USER_DNS_MIN_TTL..=USER_DNS_MAX_TTL).contains(&ttl) {
        return Err(sn_err!(
            SnErrorCode::InvalidInput,
            "user DNS TTL must be in {}..={}",
            USER_DNS_MIN_TTL,
            USER_DNS_MAX_TTL
        ));
    }
    Ok(ttl)
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserDnsRrset {
    pub name: String,
    pub record_type: UserDnsRecordType,
    pub ttl: u32,
    pub values: Vec<String>,
    pub revision: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserDnsLookup {
    pub rrset: Option<UserDnsRrset>,
    pub observed_revision: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserDnsMutationResult {
    pub revision: u64,
    pub changed: bool,
    pub rrset: Option<UserDnsRrset>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDnsChangeOperation {
    UpsertRrset,
    DeleteRrset,
    DeleteName,
}

impl UserDnsChangeOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::UpsertRrset => "upsert_rrset",
            Self::DeleteRrset => "delete_rrset",
            Self::DeleteName => "delete_name",
        }
    }

    fn from_db(value: &str) -> SnResult<Self> {
        match value {
            "upsert_rrset" => Ok(Self::UpsertRrset),
            "delete_rrset" => Ok(Self::DeleteRrset),
            "delete_name" => Ok(Self::DeleteName),
            _ => Err(sn_err!(
                SnErrorCode::DBError,
                "invalid user DNS change operation: {}",
                value
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserDnsChange {
    pub revision: u64,
    pub name: String,
    pub record_type: Option<UserDnsRecordType>,
    pub operation: UserDnsChangeOperation,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserDnsChangePage {
    pub changes: Vec<UserDnsChange>,
    pub current_revision: u64,
    pub earliest_available_revision: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnAuthDbCapabilities {
    pub contract_version: u32,
    pub schema_version: u32,
    pub user_dns_rrsets: bool,
    pub user_dns_change_feed: bool,
}

/// PKX proof TXT 的固定 DNS name：`_pkx.<canonical-domain>`。
pub fn pkx_record_name(canonical_domain: &str) -> String {
    format!("_pkx.{}", canonical_domain)
}

/// 从 owner key 材料中提取 `sn_user.pkx`（公开身份）：
/// - JWK JSON（`{`开头）→ `x` 分量；
/// - `PKX=<x>[:...][;]` 形式 → `<x>`；
/// - 其余原样 trim（兼容已是裸 x 或测试占位串的输入）。
///
/// 空输入返回 None。
pub fn pkx_source_of(key_material: &str) -> Option<String> {
    let trimmed = key_material.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('{') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(x) = value.get("x").and_then(|v| v.as_str()) {
                let x = x.trim();
                if !x.is_empty() {
                    return Some(x.to_string());
                }
            }
        }
        return Some(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("PKX=") {
        let x = rest.split([':', ';']).next().unwrap_or("").trim();
        return if x.is_empty() {
            None
        } else {
            Some(x.to_string())
        };
    }
    Some(trimmed.trim_end_matches(';').to_string())
}

/// PKX 记录值的唯一生成 helper：`PKX(<sn_user.pkx>)`。
/// 稳定状态、无 nonce/exp；SN 接管 DNS 后继续发布同一值。
pub fn pkx_value(key_material: &str) -> SnResult<String> {
    let source = pkx_source_of(key_material).ok_or_else(|| {
        sn_err!(
            SnErrorCode::InvalidInput,
            "owner key ref or public key is required before creating PKX binding"
        )
    })?;
    Ok(format!("PKX({})", source))
}

/// TXT 值与期望 PKX 的比对：容忍首尾空白与包裹引号。
/// 多条 TXT / 多段拼接由外部 DNS 查询层归一后逐条传入。
pub fn txt_matches_pkx(txt: &str, expected_pkx: &str) -> bool {
    txt.trim().trim_matches('"').trim() == expected_pkx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserState {
    Active,
    Suspended,
    Deleted,
    Banned,
}

impl ToString for UserState {
    fn to_string(&self) -> String {
        match self {
            UserState::Active => "active".to_string(),
            UserState::Suspended => "suspended".to_string(),
            UserState::Deleted => "deleted".to_string(),
            UserState::Banned => "banned".to_string(),
        }
    }
}

impl UserState {
    pub fn from_str(s: Option<&str>) -> Self {
        match s {
            Some("suspended") => UserState::Suspended,
            Some("deleted") => UserState::Deleted,
            Some("banned") => UserState::Banned,
            _ => UserState::Active,
        }
    }

    fn is_active(&self) -> bool {
        matches!(self, UserState::Active)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNUserInfo {
    pub username: Option<String>,
    /// 存量/seed 账号在补录前为 None；所有 `auth.register` 新账号必有值。
    #[serde(default)]
    pub email: Option<String>,
    pub state: UserState,
    pub public_key: String,
    pub activation_code: Option<String>,
    pub zone_config: String,
    pub self_cert: bool,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
    /// AuthDB control-plane revision used when projecting a stable Zone-scope
    /// OwnerDocument. Older remote providers may omit it.
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<UserRelayInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnClearStateResult {
    pub deleted_users: u64,
    pub activation_code_reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthInfo {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_login_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBinding {
    pub username: String,
    pub domain: String,
    pub pkx: String,
    pub pkx_record_name: String,
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneInfo {
    pub username: String,
    pub bns_name: String,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<UserRelayInfo>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserRelayInfo {
    pub relay_id: String,
    pub relay_sn: String,
    pub state: RelayAssignmentState,
    pub generation: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterUserWithRelayAllocationReq {
    pub active_code: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
    pub preferred_region: Option<String>,
    pub source_ip: Option<std::net::IpAddr>,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegistrationRelayAllocation {
    Assigned {
        assignment: RelayAssignment,
    },
    Pending {
        error_code: SnErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterUserWithRelayAllocationResult {
    pub registered: bool,
    pub relay: Option<RegistrationRelayAllocation>,
}

impl From<&RelayAssignment> for UserRelayInfo {
    fn from(assignment: &RelayAssignment) -> Self {
        Self {
            relay_id: assignment.relay_id.clone(),
            relay_sn: assignment.relay_sn.clone(),
            state: assignment.state,
            generation: assignment.generation,
        }
    }
}

impl ZoneInfo {
    pub fn default_for(username: &str) -> Self {
        Self {
            username: username.to_string(),
            bns_name: username.to_string(),
            zone: None,
            relay_sn: None,
            self_cert: false,
            cert_checked_at: None,
            cert_expires_at: None,
            sn_ips: None,
            source_version: None,
            updated_at: 0,
            relay: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneInfoPatch {
    pub bns_name: Option<String>,
    pub zone: Option<String>,
    pub relay_sn: Option<String>,
    pub self_cert: Option<bool>,
    pub cert_checked_at: Option<u64>,
    pub cert_expires_at: Option<u64>,
    pub sn_ips: Option<String>,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSession {
    pub session_id: String,
    pub username: String,
    pub token_aud: String,
    pub state: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[async_trait::async_trait]
pub trait SnAuthDB: Send + Sync + 'static {
    async fn capabilities(&self) -> SnResult<SnAuthDbCapabilities>;
    async fn get_activation_codes(&self) -> SnResult<Vec<String>>;
    async fn insert_activation_code(&self, code: &str) -> SnResult<()>;
    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>>;
    async fn check_active_code(&self, active_code: &str) -> SnResult<bool>;
    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult>;
    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn register_user_with_relay_allocation(
        &self,
        req: RegisterUserWithRelayAllocationReq,
    ) -> SnResult<RegisterUserWithRelayAllocationResult> {
        let registered = self
            .register_user(
                req.active_code.as_str(),
                req.username.as_str(),
                req.email.as_str(),
                req.password_hash.as_str(),
                req.password_salt.as_str(),
                req.password_algo.as_str(),
            )
            .await?;
        if !registered {
            return Ok(RegisterUserWithRelayAllocationResult {
                registered: false,
                relay: None,
            });
        }
        let relay = match self
            .allocate_zone_relay(AllocateZoneRelayReq {
                zone: req.username,
                preferred_region: req.preferred_region,
                source_ip: req.source_ip,
                reason: "register".to_string(),
                source_version: req.source_version,
            })
            .await
        {
            Ok(assignment) => RegistrationRelayAllocation::Assigned { assignment },
            Err(error) => RegistrationRelayAllocation::Pending {
                error_code: error.code(),
                message: error.msg().to_string(),
            },
        };
        Ok(RegisterUserWithRelayAllocationResult {
            registered: true,
            relay: Some(relay),
        })
    }
    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool>;
    async fn is_user_exist(&self, username: &str) -> SnResult<bool>;
    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>>;
    /// trusted 路径（seed/import）专用：不经 DNS PKX proof 直接注册并激活
    /// `user_domain` 绑定。不得从对外 RPC 直接暴露。
    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool>;
    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>>;
    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>>;
    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()>;
    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()>;
    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()>;
    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()>;
    /// trusted 路径（seed/import）专用：不经 DNS PKX proof 直接把 `user_domain`
    /// 置 active（或传 None 撤销全部 active 绑定）。不得从对外 RPC 直接暴露；
    /// 线上绑定必须走 `domain.bind` 的服务端 DNS proof + `activate_user_domain_binding`。
    async fn update_user_domain(&self, username: &str, user_domain: Option<String>)
        -> SnResult<()>;
    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>>;
    async fn get_user_sn_ips_as_vec(&self, username: &str) -> SnResult<Option<Vec<String>>> {
        let Some(sn_ips) = self.get_user_sn_ips(username).await? else {
            return Ok(None);
        };
        if sn_ips.trim().is_empty() {
            return Ok(Some(Vec::new()));
        }
        match serde_json::from_str::<Vec<String>>(sn_ips.as_str()) {
            Ok(ips) => Ok(Some(ips)),
            Err(_) => Ok(Some(
                sn_ips
                    .split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(ToString::to_string)
                    .collect(),
            )),
        }
    }
    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>>;
    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()>;

    /// 外部 DNS PKX proof 成功后的激活入口。信任边界：调用方（SN 服务端
    /// `domain.bind`）必须已完成服务端侧 DNS TXT 校验，本方法不做 proof。
    ///
    /// 同一事务内：supersede 同一 canonical domain 的旧 active binding（并清理
    /// 旧 owner 的 `users.user_domain` 兼容缓存）、写入当前 active binding、
    /// 更新本用户 `users.user_domain`、追加 `user_domain_history` 审计记录。
    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding>;
    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()>;

    async fn put_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult>;
    async fn remove_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
    ) -> SnResult<UserDnsMutationResult>;
    async fn delete_user_dns_rrset(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsMutationResult>;
    async fn set_user_dns_rrset_ttl(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult>;
    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsLookup>;
    async fn list_user_dns_rrsets(&self, owner: &str) -> SnResult<Vec<UserDnsRrset>>;
    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResult<UserDnsChangePage>;

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>>;
    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()>;
    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        let _ = (zone, relay_sn, source_version);
        Ok(false)
    }

    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode>;
    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth>;
    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode>;
    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>>;
    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>>;
    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>>;
    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment>;
    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment>;
    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>>;
    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment>;
    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()>;
    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision>;

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()>;
    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()>;
    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64>;
    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>>;
}

/// Remote SnAuthDB backed by the sn_auth_db S2S KRPC API.
#[derive(Clone)]
pub struct RemoteSnAuthDB {
    client: crate::s2s_api::SnAuthDbClient,
}

impl RemoteSnAuthDB {
    pub fn new(client: crate::s2s_api::SnAuthDbClient) -> Self {
        Self { client }
    }

    pub fn new_krpc(client: std::sync::Arc<::kRPC::kRPC>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc(client))
    }

    pub fn new_krpc_url(auth_db_url: &str, session_token: Option<String>) -> Self {
        Self::new(crate::s2s_api::SnAuthDbClient::new_krpc_url(
            auth_db_url,
            session_token,
        ))
    }

    pub fn client(&self) -> &crate::s2s_api::SnAuthDbClient {
        &self.client
    }
}

#[async_trait::async_trait]
impl SnAuthDB for RemoteSnAuthDB {
    async fn capabilities(&self) -> SnResult<SnAuthDbCapabilities> {
        self.client.capabilities().await
    }

    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        self.client.get_activation_codes().await
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        self.client.insert_activation_code(code).await
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        self.client.generate_activation_codes(count).await
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        self.client.check_active_code(active_code).await
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        self.client.clear_state_by_active_code(active_code).await
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .register_user(
                active_code,
                username,
                email,
                password_hash,
                password_salt,
                password_algo,
            )
            .await
    }

    async fn register_user_with_relay_allocation(
        &self,
        req: RegisterUserWithRelayAllocationReq,
    ) -> SnResult<RegisterUserWithRelayAllocationResult> {
        self.client.register_user_with_relay_allocation(req).await
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        self.client
            .create_auth(username, password_hash, password_salt, password_algo)
            .await
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        self.client.is_user_exist(username).await
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_by_email(email).await
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        self.client
            .register_user_with_owner_key(
                active_code,
                username,
                email,
                public_key,
                zone_config,
                user_domain,
                sn_ips,
            )
            .await
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        self.client.get_user_by_public_key(public_key).await
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_info(username).await
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        self.client.get_user_by_domain(domain).await
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        self.client.set_user_state(username, state).await
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        self.client
            .update_user_public_key(username, public_key)
            .await
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.client
            .update_user_zone_config(username, zone_config)
            .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.client.update_user_self_cert(username, self_cert).await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        self.client.update_user_domain(username, user_domain).await
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        self.client.get_user_sn_ips(username).await
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        self.client.get_auth(username).await
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        self.client.update_last_login(username, last_login_at).await
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        self.client
            .activate_user_domain_binding(username, domain, pkx)
            .await
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        self.client.unbind_user_domain(username, domain).await
    }

    async fn put_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        self.client
            .put_user_dns_value(owner, name, record_type, value, ttl)
            .await
    }

    async fn remove_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
    ) -> SnResult<UserDnsMutationResult> {
        self.client
            .remove_user_dns_value(owner, name, record_type, value)
            .await
    }

    async fn delete_user_dns_rrset(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsMutationResult> {
        self.client
            .delete_user_dns_rrset(owner, name, record_type)
            .await
    }

    async fn set_user_dns_rrset_ttl(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        self.client
            .set_user_dns_rrset_ttl(owner, name, record_type, ttl)
            .await
    }

    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsLookup> {
        self.client.get_user_dns_rrset(name, record_type).await
    }

    async fn list_user_dns_rrsets(&self, owner: &str) -> SnResult<Vec<UserDnsRrset>> {
        self.client.list_user_dns_rrsets(owner).await
    }

    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResult<UserDnsChangePage> {
        self.client
            .list_user_dns_changes(after_revision, limit)
            .await
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        self.client.get_zone_info(username).await
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        self.client.update_zone_info(username, patch).await
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        self.client
            .update_zone_relay_sn(zone, relay_sn, source_version)
            .await
    }

    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode> {
        self.client.register_relay_node(node).await
    }

    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth> {
        self.client.heartbeat_relay_node(heartbeat).await
    }

    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode> {
        self.client.update_relay_node_addresses(update).await
    }

    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        self.client.get_relay_node(relay_id).await
    }

    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        self.client.list_relay_nodes().await
    }

    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>> {
        self.client.get_relay_nodes_ip_map(req).await
    }

    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment> {
        self.client.assign_zone_relay(req).await
    }

    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment> {
        self.client.allocate_zone_relay(req).await
    }

    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        self.client.get_zone_relay(zone).await
    }

    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment> {
        self.client.start_relay_migration(req).await
    }

    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()> {
        self.client.complete_relay_migration(zone, generation).await
    }

    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision> {
        self.client.check_relay_admission(req).await
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        self.client
            .create_account_session(session_id, username, token_aud, issued_at, expires_at)
            .await
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        self.client
            .revoke_account_session(session_id, revoked_at)
            .await
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        self.client.revoke_user_sessions(username, revoked_at).await
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        self.client.get_account_session(session_id).await
    }
}

pub struct SqliteSnAuthDB {
    pool: SqlitePool,
    relay_manager: SqliteSnRelayManager,
}

impl SqliteSnAuthDB {
    const USER_DOMAIN_BINDING_LOCK: &'static str = "sn_user_domain_binding";

    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_auth.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().as_ref()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let db_url = if path.starts_with("sqlite:") {
            path.to_string()
        } else {
            format!("sqlite://{}", path)
        };
        let options = SqliteConnectOptions::from_str(db_url.as_str())
            .map_err(|e| Self::db_err("parse sqlite url failed", e))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(300)
            .connect_with(options)
            .await
            .map_err(|e| Self::db_err(format!("open file: {:?}", path), e))?;

        Ok(Self {
            relay_manager: SqliteSnRelayManager::from_pool(pool.clone()),
            pool,
        })
    }

    pub fn with_relay_allocation_config(mut self, config: RelayAllocationConfig) -> Self {
        self.relay_manager = self.relay_manager.with_allocation_config(config);
        self
    }

    pub fn with_relay_geo_ip_resolver(mut self, resolver: GeoIpResolverRef) -> Self {
        self.relay_manager = self.relay_manager.with_geo_ip_resolver(resolver);
        self
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        let schema_version = sqlx::query_scalar::<_, i64>(
            "SELECT version FROM sn_auth_schema WHERE singleton_id = 1",
        )
        .fetch_optional(&self.pool)
        .await;
        match schema_version {
            Ok(Some(version)) if version == SN_AUTH_DB_SCHEMA_VERSION as i64 => {}
            Ok(Some(version)) => {
                return Err(Self::db_err(
                    "incompatible schema, recreate database",
                    format!(
                        "expected auth schema {}, found {}",
                        SN_AUTH_DB_SCHEMA_VERSION, version
                    ),
                ));
            }
            Ok(None) => {
                return Err(Self::db_err(
                    "incompatible schema, recreate database",
                    "sn_auth_schema has no singleton row",
                ));
            }
            Err(sqlx::Error::Database(error))
                if error.message().contains("no such table: sn_auth_schema") =>
            {
                let existing_tables = sqlx::query("PRAGMA table_list")
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| Self::db_err("inspect auth schema failed", e))?;
                let incompatible_tables = [
                    "activation_codes",
                    "users",
                    "user_auth",
                    "user_domain_history",
                    "user_domain_bindings",
                    "zone_info",
                    "account_sessions",
                    "devices",
                    "did_documents",
                    "user_dns_records",
                ];
                if existing_tables.iter().any(|row| {
                    row.try_get::<String, _>("name")
                        .ok()
                        .is_some_and(|name| incompatible_tables.contains(&name.as_str()))
                }) {
                    return Err(Self::db_err(
                        "incompatible schema, recreate database",
                        "unversioned AuthDB or compatibility tables found",
                    ));
                }
            }
            Err(error) => return Err(Self::db_err("read auth schema version failed", error)),
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin auth schema transaction failed", e))?;
        for statement in [
            "CREATE TABLE IF NOT EXISTS sn_auth_schema (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                version INTEGER NOT NULL
            )",
            "INSERT INTO sn_auth_schema (singleton_id, version)
             VALUES (1, 2)
             ON CONFLICT(singleton_id) DO NOTHING",
            "CREATE TABLE IF NOT EXISTS activation_codes (
                code TEXT PRIMARY KEY,
                used INTEGER NOT NULL DEFAULT 0
            )",
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT NULL,
                state TEXT NOT NULL DEFAULT 'active',
                bns_name TEXT,
                public_key TEXT NOT NULL DEFAULT '',
                activation_code TEXT,
                owner_key_ref TEXT,
                zone_config TEXT NOT NULL DEFAULT '',
                self_cert INTEGER NOT NULL DEFAULT 0,
                user_domain TEXT,
                sn_ips TEXT,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                last_login_at INTEGER NULL
            )",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
             ON users (email) WHERE email IS NOT NULL",
            "CREATE TABLE IF NOT EXISTS user_auth (
                username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_algo TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER NULL
            )",
            "CREATE TABLE IF NOT EXISTS user_domain_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                owner TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                created_at INTEGER NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS idx_user_domain_history_domain
             ON user_domain_history (domain)",
            "CREATE TABLE IF NOT EXISTS user_domain_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                owner TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                state TEXT NOT NULL CHECK (state IN ('active', 'revoked', 'superseded')),
                pkx TEXT NOT NULL,
                pkx_record_name TEXT NOT NULL,
                verified_at INTEGER NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_domain_bindings_domain_active
             ON user_domain_bindings (domain) WHERE state = 'active'",
            "CREATE INDEX IF NOT EXISTS idx_user_domain_bindings_owner_state
             ON user_domain_bindings (owner, state)",
            "CREATE TABLE IF NOT EXISTS zone_info (
                username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
                bns_name TEXT NOT NULL,
                zone TEXT NULL,
                relay_sn TEXT NULL,
                self_cert INTEGER NOT NULL DEFAULT 0,
                cert_checked_at INTEGER NULL,
                cert_expires_at INTEGER NULL,
                sn_ips TEXT NULL,
                source_version TEXT NULL,
                updated_at INTEGER NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS account_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                token_aud TEXT NOT NULL,
                state TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER NULL
            )",
            "CREATE INDEX IF NOT EXISTS idx_account_sessions_username_state
             ON account_sessions (username, state)",
            "CREATE TABLE IF NOT EXISTS user_dns_names (
                name TEXT PRIMARY KEY
                    CHECK (name = lower(name) AND name NOT LIKE '%.'
                           AND length(name) BETWEEN 1 AND 253),
                owner TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS idx_user_dns_names_owner_name
             ON user_dns_names (owner, name)",
            "CREATE TABLE IF NOT EXISTS user_dns_rrsets (
                name TEXT NOT NULL REFERENCES user_dns_names(name) ON DELETE CASCADE,
                record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA', 'TXT')),
                ttl INTEGER NOT NULL CHECK (ttl BETWEEN 30 AND 86400),
                revision INTEGER NOT NULL CHECK (revision > 0),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (name, record_type)
            )",
            "CREATE TABLE IF NOT EXISTS user_dns_rdata (
                name TEXT NOT NULL,
                record_type TEXT NOT NULL,
                rdata TEXT NOT NULL CHECK (
                    length(rdata) > 0
                    AND length(CAST(rdata AS BLOB)) <= 4096
                ),
                created_at INTEGER NOT NULL,
                PRIMARY KEY (name, record_type, rdata),
                FOREIGN KEY (name, record_type)
                    REFERENCES user_dns_rrsets(name, record_type) ON DELETE CASCADE
            )",
            "CREATE TABLE IF NOT EXISTS user_dns_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                revision INTEGER NOT NULL CHECK (revision >= 0)
            )",
            "INSERT INTO user_dns_state (singleton_id, revision)
             VALUES (1, 0)
             ON CONFLICT(singleton_id) DO NOTHING",
            "CREATE TABLE IF NOT EXISTS user_dns_changes (
                revision INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                record_type TEXT NULL CHECK (
                    record_type IS NULL OR record_type IN ('A', 'AAAA', 'TXT')
                ),
                operation TEXT NOT NULL CHECK (
                    operation IN ('upsert_rrset', 'delete_rrset', 'delete_name')
                ),
                committed_at INTEGER NOT NULL
            )",
        ] {
            sqlx::query(statement)
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("initialize fresh AuthDB schema failed", e))?;
        }
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit AuthDB schema failed", e))?;

        self.relay_manager.initialize_database().await?;
        Ok(())
    }

    /// seed 导入用：激活码是否存在（含已使用的码；`get_activation_codes`
    /// 只返回未使用的）。
    pub async fn has_activation_code(&self, code: &str) -> SnResult<bool> {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM activation_codes WHERE code = ?1")
                .bind(code)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?;
        Ok(count > 0)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn generate_activation_code() -> String {
        let mut rng = rand::rng();
        (0..ACTIVATION_CODE_LEN)
            .map(|_| {
                let index = rng.random_range(0..ACTIVATION_CODE_CHARS.len());
                ACTIVATION_CODE_CHARS[index] as char
            })
            .collect()
    }

    fn db_err(context: impl AsRef<str>, err: impl std::fmt::Display) -> SnError {
        sn_err!(SnErrorCode::DBError, "{}: {}", context.as_ref(), err)
    }

    fn invalid_input(context: impl AsRef<str>) -> SnError {
        sn_err!(SnErrorCode::InvalidInput, "{}", context.as_ref())
    }

    fn email_already_bound(email: &str) -> SnError {
        sn_err!(SnErrorCode::Conflict, "email already bound: {}", email)
    }

    fn insert_user_err(email: &str, error: sqlx::Error) -> SnError {
        let is_email_unique_violation = error.as_database_error().is_some_and(|db_error| {
            db_error.is_unique_violation()
                && db_error
                    .message()
                    .to_ascii_lowercase()
                    .contains("users.email")
        });
        if is_email_unique_violation {
            Self::email_already_bound(email)
        } else {
            Self::db_err("insert user failed", error)
        }
    }

    fn check_non_empty(value: &str, field: &str) -> SnResult<()> {
        if value.trim().is_empty() {
            return Err(Self::invalid_input(format!("{} is empty", field)));
        }

        Ok(())
    }

    fn i64_to_u64(value: i64) -> u64 {
        value.max(0) as u64
    }

    fn opt_i64_to_u64(value: Option<i64>) -> Option<u64> {
        value.map(Self::i64_to_u64)
    }

    async fn current_user_dns_revision_tx(tx: &mut Transaction<'_, Sqlite>) -> SnResult<u64> {
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM user_dns_state WHERE singleton_id = 1",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| Self::db_err("read user DNS revision failed", e))?;
        Ok(Self::i64_to_u64(revision))
    }

    /// SQLite transactions start deferred. Acquire the single DNS-state writer
    /// lock before any read so two replicas cannot both read an unclaimed name
    /// and then fail while upgrading their transactions to writers.
    async fn lock_user_dns_state_tx(tx: &mut Transaction<'_, Sqlite>) -> SnResult<()> {
        sqlx::query(
            "UPDATE user_dns_state
             SET revision = revision
             WHERE singleton_id = 1",
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::db_err("lock user DNS state failed", e))?;
        Ok(())
    }

    async fn allocate_user_dns_revision_tx(tx: &mut Transaction<'_, Sqlite>) -> SnResult<u64> {
        let revision = sqlx::query_scalar::<_, i64>(
            "UPDATE user_dns_state
             SET revision = revision + 1
             WHERE singleton_id = 1
             RETURNING revision",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| Self::db_err("allocate user DNS revision failed", e))?;
        Ok(Self::i64_to_u64(revision))
    }

    async fn append_user_dns_change_tx(
        tx: &mut Transaction<'_, Sqlite>,
        revision: u64,
        name: &str,
        record_type: Option<UserDnsRecordType>,
        operation: UserDnsChangeOperation,
        now: i64,
    ) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO user_dns_changes
                (revision, name, record_type, operation, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(revision as i64)
        .bind(name)
        .bind(record_type.map(UserDnsRecordType::as_str))
        .bind(operation.as_str())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::db_err("append user DNS change failed", e))?;

        let cutoff = revision.saturating_sub(USER_DNS_CHANGE_RETENTION);
        if cutoff > 0 {
            sqlx::query("DELETE FROM user_dns_changes WHERE revision <= ?1")
                .bind(cutoff as i64)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("prune user DNS changes failed", e))?;
        }
        Ok(())
    }

    async fn user_dns_rrset_tx(
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<Option<UserDnsRrset>> {
        let row = sqlx::query(
            "SELECT ttl, revision
             FROM user_dns_rrsets
             WHERE name = ?1 AND record_type = ?2",
        )
        .bind(name)
        .bind(record_type.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query user DNS RRset failed", e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let ttl = row
            .try_get::<i64, _>("ttl")
            .map_err(|e| Self::db_err("read user DNS TTL failed", e))?;
        let revision = row
            .try_get::<i64, _>("revision")
            .map_err(|e| Self::db_err("read user DNS RRset revision failed", e))?;
        let values = sqlx::query_scalar::<_, String>(
            "SELECT rdata
             FROM user_dns_rdata
             WHERE name = ?1 AND record_type = ?2
             ORDER BY rdata",
        )
        .bind(name)
        .bind(record_type.as_str())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query user DNS rdata failed", e))?;
        Ok(Some(UserDnsRrset {
            name: name.to_string(),
            record_type,
            ttl: ttl.max(0) as u32,
            values,
            revision: Self::i64_to_u64(revision),
        }))
    }

    async fn user_dns_owner_tx(
        tx: &mut Transaction<'_, Sqlite>,
        name: &str,
    ) -> SnResult<Option<String>> {
        sqlx::query_scalar::<_, String>("SELECT owner FROM user_dns_names WHERE name = ?1")
            .bind(name)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Self::db_err("query user DNS name owner failed", e))
    }

    fn ensure_user_dns_owner(actual: &str, requested: &str, name: &str) -> SnResult<()> {
        if actual != requested {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "user DNS name {} is owned by {}, not {}",
                name,
                actual,
                requested
            ));
        }
        Ok(())
    }

    async fn delete_user_dns_names_tx(
        tx: &mut Transaction<'_, Sqlite>,
        owner: &str,
        domain: Option<&str>,
        now: i64,
    ) -> SnResult<u64> {
        let names = if let Some(domain) = domain {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM user_dns_names
                 WHERE owner = ?1 AND (name = ?2 OR name LIKE '%.' || ?2)
                 ORDER BY name",
            )
            .bind(owner)
            .bind(domain)
            .fetch_all(&mut **tx)
            .await
        } else {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM user_dns_names WHERE owner = ?1 ORDER BY name",
            )
            .bind(owner)
            .fetch_all(&mut **tx)
            .await
        }
        .map_err(|e| Self::db_err("list user DNS names for deletion failed", e))?;

        let mut latest = Self::current_user_dns_revision_tx(tx).await?;
        for name in names {
            latest = Self::allocate_user_dns_revision_tx(tx).await?;
            sqlx::query("DELETE FROM user_dns_names WHERE name = ?1 AND owner = ?2")
                .bind(name.as_str())
                .bind(owner)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("delete user DNS name failed", e))?;
            Self::append_user_dns_change_tx(
                tx,
                latest,
                name.as_str(),
                None,
                UserDnsChangeOperation::DeleteName,
                now,
            )
            .await?;
        }
        Ok(latest)
    }

    /// 激活绑定的共享事务逻辑（调用方保证已完成 proof 或走 trusted 路径）。
    ///
    /// 冲突规则（Beta2.2）：`user_domain_history` 仅审计、不阻止绑定；同一
    /// canonical domain 的旧 active binding 被 supersede（旧 owner 的
    /// `users.user_domain` 兼容缓存同步清空）；父/子域名互不排斥，解析按最长
    /// active binding 匹配。同 owner 重复激活仅刷新 pkx/verified_at，不追加审计。
    async fn activate_binding_tx(
        tx: &mut Transaction<'_, Sqlite>,
        username: &str,
        canonical_domain: &str,
        pkx: &str,
        now: i64,
    ) -> SnResult<()> {
        let previous_dns_owners = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT owner FROM user_dns_names
             WHERE owner != ?1 AND (name = ?2 OR name LIKE '%.' || ?2)
             ORDER BY owner",
        )
        .bind(username)
        .bind(canonical_domain)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query previous DNS owners failed", e))?;
        for previous_owner in previous_dns_owners {
            Self::delete_user_dns_names_tx(
                tx,
                previous_owner.as_str(),
                Some(canonical_domain),
                now,
            )
            .await?;
        }

        let record_name = pkx_record_name(canonical_domain);
        let existing = sqlx::query(
            "SELECT id, owner FROM user_domain_bindings
             WHERE domain = ?1 AND state = ?2",
        )
        .bind(canonical_domain)
        .bind(DOMAIN_BINDING_ACTIVE)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| Self::db_err("query active user_domain binding failed", e))?;

        let mut refreshed = false;
        if let Some(row) = existing {
            let binding_id: i64 = row
                .try_get("id")
                .map_err(|e| Self::db_err("read binding id failed", e))?;
            let owner: String = row
                .try_get("owner")
                .map_err(|e| Self::db_err("read binding owner failed", e))?;
            if owner == username {
                sqlx::query(
                    "UPDATE user_domain_bindings
                     SET pkx = ?1, pkx_record_name = ?2, verified_at = ?3, updated_at = ?3
                     WHERE id = ?4",
                )
                .bind(pkx)
                .bind(record_name.as_str())
                .bind(now)
                .bind(binding_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("refresh user_domain binding failed", e))?;
                refreshed = true;
            } else {
                sqlx::query(
                    "UPDATE user_domain_bindings
                     SET state = ?1, updated_at = ?2
                     WHERE id = ?3",
                )
                .bind(DOMAIN_BINDING_SUPERSEDED)
                .bind(now)
                .bind(binding_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("supersede user_domain binding failed", e))?;
                sqlx::query(
                    "UPDATE users
                     SET user_domain = NULL, updated_at = ?1
                     WHERE username = ?2 AND user_domain = ?3",
                )
                .bind(now)
                .bind(owner.as_str())
                .bind(canonical_domain)
                .execute(&mut **tx)
                .await
                .map_err(|e| Self::db_err("clear superseded user_domain cache failed", e))?;
            }
        }

        if !refreshed {
            sqlx::query(
                "INSERT INTO user_domain_bindings
                    (domain, owner, state, pkx, pkx_record_name, verified_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6)",
            )
            .bind(canonical_domain)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .bind(pkx)
            .bind(record_name.as_str())
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain binding failed", e))?;
            sqlx::query(
                "INSERT INTO user_domain_history (domain, owner, created_at)
                 VALUES (?1, ?2, ?3)",
            )
            .bind(canonical_domain)
            .bind(username)
            .bind(now)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("insert user_domain history failed", e))?;
        }

        sqlx::query("UPDATE users SET user_domain = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(canonical_domain)
            .bind(now)
            .bind(username)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("update user_domain failed", e))?;

        Ok(())
    }

    fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<SNUserInfo> {
        let state_str: Option<String> = row
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        let self_cert: Option<i64> = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        Ok(SNUserInfo {
            username: Some(
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
            ),
            email: row
                .try_get("email")
                .map_err(|e| Self::db_err("read email failed", e))?,
            state: UserState::from_str(state_str.as_deref()),
            public_key: row
                .try_get::<Option<String>, _>("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?
                .unwrap_or_default(),
            activation_code: row
                .try_get("activation_code")
                .map_err(|e| Self::db_err("read activation_code failed", e))?,
            zone_config: row
                .try_get::<Option<String>, _>("zone_config")
                .map_err(|e| Self::db_err("read zone_config failed", e))?
                .unwrap_or_default(),
            self_cert: self_cert.unwrap_or(0) != 0,
            user_domain: row
                .try_get("user_domain")
                .map_err(|e| Self::db_err("read user_domain failed", e))?,
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            updated_at: row
                .try_get::<Option<i64>, _>("updated_at")
                .map_err(|e| Self::db_err("read updated_at failed", e))?
                .unwrap_or_default()
                .max(0) as u64,
            relay: None,
        })
    }

    fn zone_info_from_row(row: &sqlx::sqlite::SqliteRow) -> SnResult<ZoneInfo> {
        let self_cert: i64 = row
            .try_get("self_cert")
            .map_err(|e| Self::db_err("read self_cert failed", e))?;
        let updated_at: i64 = row
            .try_get("updated_at")
            .map_err(|e| Self::db_err("read updated_at failed", e))?;
        Ok(ZoneInfo {
            username: row
                .try_get("username")
                .map_err(|e| Self::db_err("read username failed", e))?,
            bns_name: row
                .try_get("bns_name")
                .map_err(|e| Self::db_err("read bns_name failed", e))?,
            zone: row
                .try_get("zone")
                .map_err(|e| Self::db_err("read zone failed", e))?,
            relay_sn: row
                .try_get("relay_sn")
                .map_err(|e| Self::db_err("read relay_sn failed", e))?,
            self_cert: self_cert != 0,
            cert_checked_at: Self::opt_i64_to_u64(
                row.try_get("cert_checked_at")
                    .map_err(|e| Self::db_err("read cert_checked_at failed", e))?,
            ),
            cert_expires_at: Self::opt_i64_to_u64(
                row.try_get("cert_expires_at")
                    .map_err(|e| Self::db_err("read cert_expires_at failed", e))?,
            ),
            sn_ips: row
                .try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            source_version: row
                .try_get("source_version")
                .map_err(|e| Self::db_err("read source_version failed", e))?,
            updated_at: Self::i64_to_u64(updated_at),
            relay: None,
        })
    }

    async fn relay_projection(&self, zone: &str) -> SnResult<Option<UserRelayInfo>> {
        Ok(self
            .relay_manager
            .get_zone_relay(zone)
            .await?
            .as_ref()
            .map(UserRelayInfo::from))
    }

    async fn project_user_relay(&self, mut user: SNUserInfo) -> SnResult<SNUserInfo> {
        if let Some(username) = user.username.as_deref() {
            user.relay = self.relay_projection(username).await?;
        }
        Ok(user)
    }

    async fn register_user_tx(
        tx: &mut Transaction<'_, Sqlite>,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let email_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind(email)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| Self::db_err("query email count failed", e))?;
        if email_count > 0 {
            return Err(Self::email_already_bound(email));
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, email, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, '', ?5, NULL, '', NULL, 0, NULL, ?6, ?6, NULL)",
        )
        .bind(username)
        .bind(email)
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(active_code)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::insert_user_err(email, e))?;

        sqlx::query(
            "INSERT INTO user_auth
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| Self::db_err("insert auth failed", e))?;

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut **tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        Ok(true)
    }
}

#[async_trait::async_trait]
impl SnAuthDB for SqliteSnAuthDB {
    async fn capabilities(&self) -> SnResult<SnAuthDbCapabilities> {
        let version = sqlx::query_scalar::<_, i64>(
            "SELECT version FROM sn_auth_schema WHERE singleton_id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::db_err("read auth schema capability failed", e))?;
        Ok(SnAuthDbCapabilities {
            contract_version: SN_AUTH_DB_CONTRACT_VERSION,
            schema_version: Self::i64_to_u64(version) as u32,
            user_dns_rrsets: true,
            user_dns_change_feed: true,
        })
    }

    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        let rows = sqlx::query("SELECT code FROM activation_codes WHERE used = 0")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Self::db_err("query activation_codes failed", e))?;
        rows.into_iter()
            .map(|row| {
                row.try_get(0)
                    .map_err(|e| Self::db_err("read activation code failed", e))
            })
            .collect()
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        sqlx::query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("insert activation_codes failed", e))?;
        Ok(())
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        let mut codes = Vec::with_capacity(count);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        while codes.len() < count {
            let code = Self::generate_activation_code();
            let result =
                sqlx::query("INSERT OR IGNORE INTO activation_codes (code, used) VALUES (?1, 0)")
                    .bind(code.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("insert activation_codes failed", e))?;

            if result.rows_affected() > 0 {
                codes.push(code);
            }
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(codes)
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        let used =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?;
        Ok(used == Some(0))
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE activation_code = ?1")
                .bind(active_code)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("count users failed", e))?;
        let owners = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users WHERE activation_code = ?1 ORDER BY username",
        )
        .bind(active_code)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| Self::db_err("list users for state clear failed", e))?;
        let now = Self::now_secs() as i64;
        for owner in &owners {
            Self::delete_user_dns_names_tx(&mut tx, owner, None, now).await?;
        }

        for (table, field) in [
            ("relay_admission_events", "zone"),
            ("relay_assignments", "zone"),
            ("relay_allocation_pending", "zone"),
        ] {
            let sql = format!(
                "DELETE FROM {table}
                 WHERE {field} IN (
                    SELECT username FROM users WHERE activation_code = ?1
                 )"
            );
            sqlx::query(sql.as_str())
                .bind(active_code)
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err(format!("delete {table} rows failed"), e))?;
        }

        sqlx::query("DELETE FROM users WHERE activation_code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("delete users failed", e))?;

        sqlx::query(
            "INSERT INTO activation_codes (code, used) VALUES (?1, 0)
             ON CONFLICT(code) DO UPDATE SET used = 0",
        )
        .bind(active_code)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("reset activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(SnClearStateResult {
            deleted_users: user_count.max(0) as u64,
            activation_code_reset: true,
        })
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let email = canonical_email(email)?;
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        // 同进程内尽早串行化同邮箱注册，数据库 UNIQUE 索引仍是跨进程/竞态兜底。
        let _email_locker =
            async_named_locker::Locker::get_locker(format!("sn_email_{}", email)).await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let registered = Self::register_user_tx(
            &mut tx,
            active_code,
            username,
            email.as_str(),
            password_hash,
            password_salt,
            password_algo,
        )
        .await?;
        if !registered {
            return Ok(false);
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(true)
    }

    async fn register_user_with_relay_allocation(
        &self,
        req: RegisterUserWithRelayAllocationReq,
    ) -> SnResult<RegisterUserWithRelayAllocationResult> {
        let email = canonical_email(req.email.as_str())?;
        let _active_code_locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", req.active_code))
                .await;
        let _email_locker =
            async_named_locker::Locker::get_locker(format!("sn_email_{}", email)).await;
        let _zone_locker = async_named_locker::Locker::get_locker(format!(
            "sn_relay_allocate_zone_{}",
            req.username.trim()
        ))
        .await;

        let allocation_req = AllocateZoneRelayReq {
            zone: req.username.clone(),
            preferred_region: req.preferred_region,
            source_ip: req.source_ip,
            reason: "register".to_string(),
            source_version: req.source_version,
        };
        // GeoIP/selection reads happen before the write transaction. The chosen node is
        // revalidated inside the transaction before the assignment is inserted.
        let allocation_plan = self
            .relay_manager
            .plan_registration_allocation(&allocation_req)
            .await;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin registration transaction failed", e))?;
        let registered = Self::register_user_tx(
            &mut tx,
            req.active_code.as_str(),
            req.username.as_str(),
            email.as_str(),
            req.password_hash.as_str(),
            req.password_salt.as_str(),
            req.password_algo.as_str(),
        )
        .await?;
        if !registered {
            return Ok(RegisterUserWithRelayAllocationResult {
                registered: false,
                relay: None,
            });
        }

        let relay = self
            .relay_manager
            .commit_registration_allocation(&mut tx, &allocation_req, allocation_plan)
            .await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit registration transaction failed", e))?;

        Ok(RegisterUserWithRelayAllocationResult {
            registered: true,
            relay: Some(match relay {
                Ok(assignment) => RegistrationRelayAllocation::Assigned { assignment },
                Err(error) => RegistrationRelayAllocation::Pending {
                    error_code: error.code(),
                    message: error.msg().to_string(),
                },
            }),
        })
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("username_{}", username)).await;
        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count == 0 {
            return Err(sn_err!(
                SnErrorCode::NotFound,
                "cannot create auth for missing user: {}",
                username
            ));
        }

        let auth_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_auth WHERE username = ?1")
                .bind(username)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user auth count failed", e))?;
        if auth_count > 0 {
            return Ok(false);
        }

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO user_auth
                (username, password_hash, password_salt, password_algo,
                 created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
        )
        .bind(username)
        .bind(password_hash)
        .bind(password_salt)
        .bind(password_algo)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert auth failed", e))?;

        Ok(true)
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user failed", e))?;
        Ok(count > 0)
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        let email = canonical_email(email)?;
        let row = sqlx::query(
            "SELECT username, email, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips, updated_at
             FROM users WHERE email = ?1",
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user by email failed", e))?;

        match row.as_ref().map(Self::user_from_row).transpose()? {
            Some(user) => Ok(Some(self.project_user_relay(user).await?)),
            None => Ok(None),
        }
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        let email = canonical_email(email)?;
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let _email_locker =
            async_named_locker::Locker::get_locker(format!("sn_email_{}", email)).await;
        let _domain_locker = if user_domain.is_some() {
            Some(
                async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                    .await,
            )
        } else {
            None
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let code_unused =
            sqlx::query_scalar::<_, i64>("SELECT used FROM activation_codes WHERE code = ?1")
                .bind(active_code)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query activation code failed", e))?
                == Some(0);
        if !code_unused {
            return Ok(false);
        }

        let user_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = ?1")
                .bind(username)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query user count failed", e))?;
        if user_count > 0 {
            return Ok(false);
        }

        let email_count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind(email.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("query email count failed", e))?;
        if email_count > 0 {
            return Err(Self::email_already_bound(email.as_str()));
        }

        let canonical_domain = user_domain.as_deref().and_then(canonical_user_domain);

        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO users
                (username, email, state, bns_name, public_key, activation_code, owner_key_ref,
                 zone_config, user_domain, self_cert, sn_ips, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, 0, ?9, ?10, ?10, NULL)",
        )
        .bind(username)
        .bind(email.as_str())
        .bind(UserState::Active.to_string())
        .bind(username)
        .bind(public_key)
        .bind(active_code)
        .bind(zone_config)
        .bind(canonical_domain.as_deref())
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::insert_user_err(email.as_str(), e))?;

        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, NULL, 0, NULL, NULL, ?4, NULL, ?5)",
        )
        .bind(username)
        .bind(username)
        .bind(if zone_config.trim().is_empty() {
            None
        } else {
            Some(zone_config)
        })
        .bind(sn_ips.as_deref())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert zone info failed", e))?;

        if let Some(domain) = canonical_domain.as_deref() {
            // seed/import 捷径：不经 DNS proof 直接激活（含 supersede 语义）。
            let pkx = pkx_value(public_key)?;
            Self::activate_binding_tx(&mut tx, username, domain, pkx.as_str(), now).await?;
        }

        sqlx::query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
            .bind(active_code)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update activation code failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(true)
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let row =
            sqlx::query("SELECT username, zone_config, sn_ips FROM users WHERE public_key = ?1")
                .bind(public_key)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Self::db_err("query user by public_key failed", e))?;

        row.map(|row| {
            Ok((
                row.try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                row.try_get::<Option<String>, _>("zone_config")
                    .map_err(|e| Self::db_err("read zone_config failed", e))?
                    .unwrap_or_default(),
                row.try_get("sn_ips")
                    .map_err(|e| Self::db_err("read sn_ips failed", e))?,
            ))
        })
        .transpose()
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        let row = sqlx::query(
            "SELECT username, email, state, public_key, activation_code, zone_config,
                    self_cert, user_domain, sn_ips, updated_at
             FROM users WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user failed", e))?;

        match row.as_ref().map(Self::user_from_row).transpose()? {
            Some(user) => Ok(Some(self.project_user_relay(user).await?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        let canonical_domain = match canonical_user_domain(domain) {
            Some(domain) => domain,
            None => return Ok(None),
        };
        let row = sqlx::query(
            "SELECT u.username, u.email, u.state, u.public_key, u.activation_code, u.zone_config,
                    u.self_cert, b.domain AS user_domain, u.sn_ips, u.updated_at
             FROM user_domain_bindings b
             JOIN users u ON u.username = b.owner
             WHERE b.state = 'active'
               AND u.state = 'active'
               AND (?1 = b.domain OR ?1 LIKE '%.' || b.domain)
             ORDER BY length(b.domain) DESC
             LIMIT 1",
        )
        .bind(canonical_domain.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query user by domain failed", e))?;

        match row.as_ref().map(Self::user_from_row).transpose()? {
            Some(user) => Ok(Some(self.project_user_relay(user).await?)),
            None => Ok(None),
        }
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user state update failed", e))?;
        sqlx::query("UPDATE users SET state = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(state.to_string())
            .bind(now)
            .bind(username)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update user state failed", e))?;
        if matches!(state, UserState::Deleted) {
            Self::delete_user_dns_names_tx(&mut tx, username, None, now).await?;
        }
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user state update failed", e))?;
        if !state.is_active() {
            self.revoke_user_sessions(username, now as u64).await?;
        }
        Ok(())
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query("UPDATE users SET public_key = ?1, updated_at = ?2 WHERE username = ?3")
            .bind(public_key)
            .bind(now)
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| Self::db_err("update user public_key failed", e))?;
        Ok(())
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                zone: Some(zone_config.to_string()),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        self.update_zone_info(
            username,
            ZoneInfoPatch {
                self_cert: Some(self_cert),
                ..ZoneInfoPatch::default()
            },
        )
        .await
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;

        let canonical_domain = user_domain.as_deref().and_then(canonical_user_domain);

        if let Some(domain) = canonical_domain.as_deref() {
            let user =
                sqlx::query("SELECT public_key, owner_key_ref FROM users WHERE username = ?1")
                    .bind(username)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("query user failed", e))?
                    .ok_or_else(|| {
                        sn_err!(SnErrorCode::NotFound, "user not found: {}", username)
                    })?;
            let owner_key_ref: Option<String> = user
                .try_get("owner_key_ref")
                .map_err(|e| Self::db_err("read owner_key_ref failed", e))?;
            let public_key: Option<String> = user
                .try_get("public_key")
                .map_err(|e| Self::db_err("read public_key failed", e))?;
            let pkx_source = owner_key_ref
                .filter(|value| !value.trim().is_empty())
                .or_else(|| public_key.filter(|value| !value.trim().is_empty()))
                .unwrap_or_default();
            // trusted import 特例：允许无 owner key 的空 pkx 绑定。
            let pkx = if pkx_source.trim().is_empty() {
                String::new()
            } else {
                pkx_value(pkx_source.as_str())?
            };
            Self::activate_binding_tx(&mut tx, username, domain, pkx.as_str(), now).await?;
        } else {
            sqlx::query(
                "UPDATE user_domain_bindings
                 SET state = ?1, updated_at = ?2
                 WHERE owner = ?3 AND state = ?4",
            )
            .bind(DOMAIN_BINDING_REVOKED)
            .bind(now)
            .bind(username)
            .bind(DOMAIN_BINDING_ACTIVE)
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("revoke user_domain bindings failed", e))?;
            sqlx::query("UPDATE users SET user_domain = NULL, updated_at = ?1 WHERE username = ?2")
                .bind(now)
                .bind(username)
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("update user_domain failed", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        if let Some(zone_info) = self.get_zone_info(username).await? {
            if zone_info.sn_ips.is_some() {
                return Ok(zone_info.sn_ips);
            }
        }

        let row = sqlx::query("SELECT sn_ips FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Self::db_err("query user sn_ips failed", e))?;
        row.map(|row| {
            row.try_get("sn_ips")
                .map_err(|e| Self::db_err("read sn_ips failed", e))
        })
        .transpose()
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        let row = sqlx::query(
            "SELECT username, password_hash, password_salt, password_algo,
                    created_at, updated_at, last_login_at
             FROM user_auth WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query auth failed", e))?;

        row.map(|row| {
            let created_at: i64 = row
                .try_get("created_at")
                .map_err(|e| Self::db_err("read created_at failed", e))?;
            let updated_at: i64 = row
                .try_get("updated_at")
                .map_err(|e| Self::db_err("read updated_at failed", e))?;
            let last_login_at: Option<i64> = row
                .try_get("last_login_at")
                .map_err(|e| Self::db_err("read last_login_at failed", e))?;
            Ok(SnAuthInfo {
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                password_hash: row
                    .try_get("password_hash")
                    .map_err(|e| Self::db_err("read password_hash failed", e))?,
                password_salt: row
                    .try_get("password_salt")
                    .map_err(|e| Self::db_err("read password_salt failed", e))?,
                password_algo: row
                    .try_get("password_algo")
                    .map_err(|e| Self::db_err("read password_algo failed", e))?,
                created_at: Self::i64_to_u64(created_at),
                updated_at: Self::i64_to_u64(updated_at),
                last_login_at: Self::opt_i64_to_u64(last_login_at),
            })
        })
        .transpose()
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        let last_login_at = last_login_at as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "UPDATE user_auth
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update last login failed", e))?;
        sqlx::query(
            "UPDATE users
             SET last_login_at = ?1, updated_at = ?1
             WHERE username = ?2",
        )
        .bind(last_login_at)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user last login failed", e))?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        let canonical_domain =
            canonical_user_domain(domain).ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let pkx = pkx.trim();
        Self::check_non_empty(pkx, "pkx")?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;

        let user = sqlx::query("SELECT state FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| Self::db_err("query user failed", e))?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "user not found: {}", username))?;
        let state: Option<String> = user
            .try_get("state")
            .map_err(|e| Self::db_err("read state failed", e))?;
        if !UserState::from_str(state.as_deref()).is_active() {
            return Err(sn_err!(
                SnErrorCode::Blocked,
                "user is not active: {}",
                username
            ));
        }

        let now = Self::now_secs() as i64;
        Self::activate_binding_tx(&mut tx, username, canonical_domain.as_str(), pkx, now).await?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;

        Ok(DomainBinding {
            username: username.to_string(),
            pkx_record_name: pkx_record_name(canonical_domain.as_str()),
            domain: canonical_domain,
            pkx: pkx.to_string(),
            verified_at: now as u64,
        })
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        let canonical_domain =
            canonical_user_domain(domain).ok_or_else(|| Self::invalid_input("domain is empty"))?;
        let _locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        let now = Self::now_secs() as i64;
        sqlx::query(
            "UPDATE user_domain_bindings
             SET state = ?1, updated_at = ?2
             WHERE domain = ?3 AND owner = ?4 AND state = ?5",
        )
        .bind(DOMAIN_BINDING_REVOKED)
        .bind(now)
        .bind(canonical_domain.as_str())
        .bind(username)
        .bind(DOMAIN_BINDING_ACTIVE)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("revoke user_domain binding failed", e))?;
        sqlx::query(
            "UPDATE users
             SET user_domain = NULL, updated_at = ?1
             WHERE username = ?2 AND user_domain = ?3",
        )
        .bind(now)
        .bind(username)
        .bind(canonical_domain.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("clear user_domain failed", e))?;
        Self::delete_user_dns_names_tx(&mut tx, username, Some(canonical_domain.as_str()), now)
            .await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn put_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        let owner = owner.trim();
        Self::check_non_empty(owner, "owner")?;
        let name = canonical_user_dns_name(name)?;
        let value = canonical_user_dns_rdata(record_type, value)?;
        let ttl = validate_user_dns_ttl(ttl)?;
        let now = Self::now_secs() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user DNS put failed", e))?;
        Self::lock_user_dns_state_tx(&mut tx).await?;

        let state = sqlx::query_scalar::<_, String>("SELECT state FROM users WHERE username = ?1")
            .bind(owner)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| Self::db_err("query user for DNS put failed", e))?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "user not found: {}", owner))?;
        if !UserState::from_str(Some(state.as_str())).is_active() {
            return Err(sn_err!(
                SnErrorCode::Blocked,
                "user is not active: {}",
                owner
            ));
        }

        // This write acquires SQLite's writer lock before ownership is read,
        // making simultaneous first claims deterministic across processes.
        sqlx::query(
            "INSERT OR IGNORE INTO user_dns_names
                (name, owner, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)",
        )
        .bind(name.as_str())
        .bind(owner)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("claim user DNS name failed", e))?;
        let actual_owner = Self::user_dns_owner_tx(&mut tx, name.as_str())
            .await?
            .ok_or_else(|| Self::db_err("claim user DNS name failed", "owner row missing"))?;
        Self::ensure_user_dns_owner(actual_owner.as_str(), owner, name.as_str())?;

        let current = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
        let value_exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_dns_rdata
             WHERE name = ?1 AND record_type = ?2 AND rdata = ?3",
        )
        .bind(name.as_str())
        .bind(record_type.as_str())
        .bind(value.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| Self::db_err("query existing user DNS value failed", e))?
            > 0;
        let effective_ttl = current
            .as_ref()
            .map(|rrset| rrset.ttl.min(ttl))
            .unwrap_or(ttl);
        if value_exists
            && current
                .as_ref()
                .is_some_and(|rrset| rrset.ttl == effective_ttl)
        {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit no-op user DNS put failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset: current,
            });
        }

        let revision = Self::allocate_user_dns_revision_tx(&mut tx).await?;
        sqlx::query(
            "INSERT INTO user_dns_rrsets
                (name, record_type, ttl, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(name, record_type) DO UPDATE SET
                ttl = excluded.ttl,
                revision = excluded.revision,
                updated_at = excluded.updated_at",
        )
        .bind(name.as_str())
        .bind(record_type.as_str())
        .bind(effective_ttl as i64)
        .bind(revision as i64)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert user DNS RRset failed", e))?;
        sqlx::query(
            "INSERT OR IGNORE INTO user_dns_rdata
                (name, record_type, rdata, created_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(name.as_str())
        .bind(record_type.as_str())
        .bind(value.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("insert user DNS rdata failed", e))?;
        sqlx::query("UPDATE user_dns_names SET updated_at = ?1 WHERE name = ?2")
            .bind(now)
            .bind(name.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("touch user DNS name failed", e))?;
        Self::append_user_dns_change_tx(
            &mut tx,
            revision,
            name.as_str(),
            Some(record_type),
            UserDnsChangeOperation::UpsertRrset,
            now,
        )
        .await?;
        let rrset = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user DNS put failed", e))?;
        Ok(UserDnsMutationResult {
            revision,
            changed: true,
            rrset,
        })
    }

    async fn remove_user_dns_value(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        value: &str,
    ) -> SnResult<UserDnsMutationResult> {
        let owner = owner.trim();
        Self::check_non_empty(owner, "owner")?;
        let name = canonical_user_dns_name(name)?;
        let value = canonical_user_dns_rdata(record_type, value)?;
        let now = Self::now_secs() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user DNS value delete failed", e))?;
        Self::lock_user_dns_state_tx(&mut tx).await?;
        let Some(actual_owner) = Self::user_dns_owner_tx(&mut tx, name.as_str()).await? else {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit absent user DNS value delete failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset: None,
            });
        };
        Self::ensure_user_dns_owner(actual_owner.as_str(), owner, name.as_str())?;
        let deleted = sqlx::query(
            "DELETE FROM user_dns_rdata
             WHERE name = ?1 AND record_type = ?2 AND rdata = ?3",
        )
        .bind(name.as_str())
        .bind(record_type.as_str())
        .bind(value.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("delete user DNS value failed", e))?;
        if deleted.rows_affected() == 0 {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            let rrset = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit no-op user DNS value delete failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset,
            });
        }

        let revision = Self::allocate_user_dns_revision_tx(&mut tx).await?;
        let remaining = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_dns_rdata
             WHERE name = ?1 AND record_type = ?2",
        )
        .bind(name.as_str())
        .bind(record_type.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| Self::db_err("count remaining user DNS values failed", e))?;
        let (operation, change_type) = if remaining == 0 {
            sqlx::query("DELETE FROM user_dns_rrsets WHERE name = ?1 AND record_type = ?2")
                .bind(name.as_str())
                .bind(record_type.as_str())
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("delete empty user DNS RRset failed", e))?;
            let rrset_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_dns_rrsets WHERE name = ?1",
            )
            .bind(name.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| Self::db_err("count remaining user DNS RRsets failed", e))?;
            if rrset_count == 0 {
                sqlx::query("DELETE FROM user_dns_names WHERE name = ?1")
                    .bind(name.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Self::db_err("delete empty user DNS name failed", e))?;
                (UserDnsChangeOperation::DeleteName, None)
            } else {
                (UserDnsChangeOperation::DeleteRrset, Some(record_type))
            }
        } else {
            sqlx::query(
                "UPDATE user_dns_rrsets
                 SET revision = ?1, updated_at = ?2
                 WHERE name = ?3 AND record_type = ?4",
            )
            .bind(revision as i64)
            .bind(now)
            .bind(name.as_str())
            .bind(record_type.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| Self::db_err("update user DNS RRset revision failed", e))?;
            (UserDnsChangeOperation::UpsertRrset, Some(record_type))
        };
        Self::append_user_dns_change_tx(
            &mut tx,
            revision,
            name.as_str(),
            change_type,
            operation,
            now,
        )
        .await?;
        let rrset = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user DNS value delete failed", e))?;
        Ok(UserDnsMutationResult {
            revision,
            changed: true,
            rrset,
        })
    }

    async fn delete_user_dns_rrset(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsMutationResult> {
        let owner = owner.trim();
        Self::check_non_empty(owner, "owner")?;
        let name = canonical_user_dns_name(name)?;
        let now = Self::now_secs() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user DNS RRset delete failed", e))?;
        Self::lock_user_dns_state_tx(&mut tx).await?;
        let Some(actual_owner) = Self::user_dns_owner_tx(&mut tx, name.as_str()).await? else {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit absent user DNS RRset delete failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset: None,
            });
        };
        Self::ensure_user_dns_owner(actual_owner.as_str(), owner, name.as_str())?;
        let deleted =
            sqlx::query("DELETE FROM user_dns_rrsets WHERE name = ?1 AND record_type = ?2")
                .bind(name.as_str())
                .bind(record_type.as_str())
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("delete user DNS RRset failed", e))?;
        if deleted.rows_affected() == 0 {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit no-op user DNS RRset delete failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset: None,
            });
        }
        let revision = Self::allocate_user_dns_revision_tx(&mut tx).await?;
        let remaining =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_dns_rrsets WHERE name = ?1")
                .bind(name.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Self::db_err("count user DNS RRsets after delete failed", e))?;
        let (operation, change_type) = if remaining == 0 {
            sqlx::query("DELETE FROM user_dns_names WHERE name = ?1")
                .bind(name.as_str())
                .execute(&mut *tx)
                .await
                .map_err(|e| Self::db_err("delete empty user DNS name failed", e))?;
            (UserDnsChangeOperation::DeleteName, None)
        } else {
            (UserDnsChangeOperation::DeleteRrset, Some(record_type))
        };
        Self::append_user_dns_change_tx(
            &mut tx,
            revision,
            name.as_str(),
            change_type,
            operation,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user DNS RRset delete failed", e))?;
        Ok(UserDnsMutationResult {
            revision,
            changed: true,
            rrset: None,
        })
    }

    async fn set_user_dns_rrset_ttl(
        &self,
        owner: &str,
        name: &str,
        record_type: UserDnsRecordType,
        ttl: u32,
    ) -> SnResult<UserDnsMutationResult> {
        let owner = owner.trim();
        Self::check_non_empty(owner, "owner")?;
        let name = canonical_user_dns_name(name)?;
        let ttl = validate_user_dns_ttl(ttl)?;
        let now = Self::now_secs() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user DNS TTL update failed", e))?;
        Self::lock_user_dns_state_tx(&mut tx).await?;
        let actual_owner = Self::user_dns_owner_tx(&mut tx, name.as_str())
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "user DNS name not found: {}", name))?;
        Self::ensure_user_dns_owner(actual_owner.as_str(), owner, name.as_str())?;
        let current = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type)
            .await?
            .ok_or_else(|| {
                sn_err!(
                    SnErrorCode::NotFound,
                    "user DNS RRset not found: {} {}",
                    name,
                    record_type
                )
            })?;
        if current.ttl == ttl {
            let revision = Self::current_user_dns_revision_tx(&mut tx).await?;
            tx.commit()
                .await
                .map_err(|e| Self::db_err("commit no-op user DNS TTL update failed", e))?;
            return Ok(UserDnsMutationResult {
                revision,
                changed: false,
                rrset: Some(current),
            });
        }
        let revision = Self::allocate_user_dns_revision_tx(&mut tx).await?;
        sqlx::query(
            "UPDATE user_dns_rrsets
             SET ttl = ?1, revision = ?2, updated_at = ?3
             WHERE name = ?4 AND record_type = ?5",
        )
        .bind(ttl as i64)
        .bind(revision as i64)
        .bind(now)
        .bind(name.as_str())
        .bind(record_type.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user DNS TTL failed", e))?;
        Self::append_user_dns_change_tx(
            &mut tx,
            revision,
            name.as_str(),
            Some(record_type),
            UserDnsChangeOperation::UpsertRrset,
            now,
        )
        .await?;
        let rrset = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user DNS TTL update failed", e))?;
        Ok(UserDnsMutationResult {
            revision,
            changed: true,
            rrset,
        })
    }

    async fn get_user_dns_rrset(
        &self,
        name: &str,
        record_type: UserDnsRecordType,
    ) -> SnResult<UserDnsLookup> {
        let name = canonical_user_dns_name(name)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin user DNS lookup failed", e))?;
        let observed_revision = Self::current_user_dns_revision_tx(&mut tx).await?;
        let rrset = Self::user_dns_rrset_tx(&mut tx, name.as_str(), record_type).await?;
        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit user DNS lookup failed", e))?;
        Ok(UserDnsLookup {
            rrset,
            observed_revision,
        })
    }

    async fn list_user_dns_rrsets(&self, owner: &str) -> SnResult<Vec<UserDnsRrset>> {
        let rows = sqlx::query(
            "SELECT s.name, s.record_type, s.ttl, s.revision, d.rdata
             FROM user_dns_rrsets s
             JOIN user_dns_names n ON n.name = s.name
             JOIN user_dns_rdata d
               ON d.name = s.name AND d.record_type = s.record_type
             WHERE n.owner = ?1
             ORDER BY s.name, s.record_type, d.rdata",
        )
        .bind(owner.trim())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::db_err("list user DNS RRsets failed", e))?;
        let mut rrsets = Vec::<UserDnsRrset>::new();
        for row in rows {
            let name: String = row
                .try_get("name")
                .map_err(|e| Self::db_err("read user DNS name failed", e))?;
            let record_type_raw: String = row
                .try_get("record_type")
                .map_err(|e| Self::db_err("read user DNS record type failed", e))?;
            let record_type = UserDnsRecordType::from_str(record_type_raw.as_str())?;
            let ttl: i64 = row
                .try_get("ttl")
                .map_err(|e| Self::db_err("read user DNS TTL failed", e))?;
            let revision: i64 = row
                .try_get("revision")
                .map_err(|e| Self::db_err("read user DNS revision failed", e))?;
            let value: String = row
                .try_get("rdata")
                .map_err(|e| Self::db_err("read user DNS rdata failed", e))?;
            if let Some(last) = rrsets.last_mut() {
                if last.name == name && last.record_type == record_type {
                    last.values.push(value);
                    continue;
                }
            }
            rrsets.push(UserDnsRrset {
                name,
                record_type,
                ttl: ttl.max(0) as u32,
                values: vec![value],
                revision: Self::i64_to_u64(revision),
            });
        }
        Ok(rrsets)
    }

    async fn list_user_dns_changes(
        &self,
        after_revision: u64,
        limit: usize,
    ) -> SnResult<UserDnsChangePage> {
        if !(1..=1_000).contains(&limit) {
            return Err(Self::invalid_input(
                "user DNS change page limit must be in 1..=1000",
            ));
        }
        let current_revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM user_dns_state WHERE singleton_id = 1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::db_err("read user DNS current revision failed", e))?;
        let earliest =
            sqlx::query_scalar::<_, Option<i64>>("SELECT MIN(revision) FROM user_dns_changes")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Self::db_err("read earliest user DNS revision failed", e))?;
        let rows = sqlx::query(
            "SELECT revision, name, record_type, operation
             FROM user_dns_changes
             WHERE revision > ?1
             ORDER BY revision
             LIMIT ?2",
        )
        .bind(after_revision as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Self::db_err("list user DNS changes failed", e))?;
        let mut changes = Vec::with_capacity(rows.len());
        for row in rows {
            let revision: i64 = row
                .try_get("revision")
                .map_err(|e| Self::db_err("read user DNS change revision failed", e))?;
            let record_type = row
                .try_get::<Option<String>, _>("record_type")
                .map_err(|e| Self::db_err("read user DNS change record type failed", e))?
                .map(|value| UserDnsRecordType::from_str(value.as_str()))
                .transpose()?;
            let operation: String = row
                .try_get("operation")
                .map_err(|e| Self::db_err("read user DNS change operation failed", e))?;
            changes.push(UserDnsChange {
                revision: Self::i64_to_u64(revision),
                name: row
                    .try_get("name")
                    .map_err(|e| Self::db_err("read user DNS change name failed", e))?,
                record_type,
                operation: UserDnsChangeOperation::from_db(operation.as_str())?,
            });
        }
        let current_revision = Self::i64_to_u64(current_revision);
        Ok(UserDnsChangePage {
            changes,
            current_revision,
            earliest_available_revision: earliest
                .map(Self::i64_to_u64)
                .unwrap_or_else(|| current_revision.saturating_add(1)),
        })
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        let row = sqlx::query(
            "SELECT username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                    cert_expires_at, sn_ips, source_version, updated_at
             FROM zone_info WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query zone_info failed", e))?;
        let mut info = match row.as_ref() {
            Some(row) => Self::zone_info_from_row(row)?,
            None => ZoneInfo::default_for(username),
        };
        info.relay = self.relay_projection(username).await?;
        info.relay_sn = info.relay.as_ref().map(|relay| relay.relay_sn.clone());
        Ok(Some(info))
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        if patch.relay_sn.is_some() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "relay_sn is read-only; use relay allocation or migration APIs"
            ));
        }
        let mut current = self
            .get_zone_info(username)
            .await?
            .unwrap_or_else(|| ZoneInfo::default_for(username));
        current.relay_sn = None;
        current.relay = None;
        if let Some(value) = patch.bns_name {
            current.bns_name = value;
        }
        if let Some(value) = patch.zone {
            current.zone = Some(value);
        }
        if let Some(value) = patch.self_cert {
            current.self_cert = value;
        }
        if let Some(value) = patch.cert_checked_at {
            current.cert_checked_at = Some(value);
        }
        if let Some(value) = patch.cert_expires_at {
            current.cert_expires_at = Some(value);
        }
        if let Some(value) = patch.sn_ips {
            current.sn_ips = Some(value);
        }
        if let Some(value) = patch.source_version {
            current.source_version = Some(value);
        }
        current.updated_at = Self::now_secs();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Self::db_err("begin transaction failed", e))?;
        sqlx::query(
            "INSERT INTO zone_info
                (username, bns_name, zone, relay_sn, self_cert, cert_checked_at,
                 cert_expires_at, sn_ips, source_version, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(username) DO UPDATE SET
                bns_name = excluded.bns_name,
                zone = excluded.zone,
                relay_sn = excluded.relay_sn,
                self_cert = excluded.self_cert,
                cert_checked_at = excluded.cert_checked_at,
                cert_expires_at = excluded.cert_expires_at,
                sn_ips = excluded.sn_ips,
                source_version = excluded.source_version,
                updated_at = excluded.updated_at",
        )
        .bind(username)
        .bind(current.bns_name.as_str())
        .bind(current.zone.as_deref())
        .bind(current.relay_sn.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.cert_checked_at.map(|v| v as i64))
        .bind(current.cert_expires_at.map(|v| v as i64))
        .bind(current.sn_ips.as_deref())
        .bind(current.source_version.as_deref())
        .bind(current.updated_at as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("upsert zone_info failed", e))?;

        sqlx::query(
            "UPDATE users
             SET zone_config = COALESCE(?1, zone_config),
                 self_cert = ?2,
                 sn_ips = ?3,
                 updated_at = ?4
             WHERE username = ?5",
        )
        .bind(current.zone.as_deref())
        .bind(if current.self_cert { 1_i64 } else { 0_i64 })
        .bind(current.sn_ips.as_deref())
        .bind(current.updated_at as i64)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(|e| Self::db_err("update user zone cache failed", e))?;

        tx.commit()
            .await
            .map_err(|e| Self::db_err("commit transaction failed", e))?;
        Ok(())
    }

    async fn update_zone_relay_sn(
        &self,
        _zone: &str,
        _relay_sn: &str,
        _source_version: Option<&str>,
    ) -> SnResult<bool> {
        Err(sn_err!(
            SnErrorCode::InvalidInput,
            "relay_sn is read-only; use relay allocation or migration APIs"
        ))
    }

    async fn register_relay_node(&self, node: RelayNodeRegistration) -> SnResult<RelayNode> {
        self.relay_manager.register_relay_node(node).await
    }

    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> SnResult<RelayNodeHealth> {
        self.relay_manager.heartbeat_relay_node(heartbeat).await
    }

    async fn update_relay_node_addresses(
        &self,
        update: RelayNodeAddressUpdate,
    ) -> SnResult<RelayNode> {
        self.relay_manager.update_relay_node_addresses(update).await
    }

    async fn get_relay_node(&self, relay_id: &str) -> SnResult<Option<RelayNode>> {
        self.relay_manager.get_relay_node(relay_id).await
    }

    async fn list_relay_nodes(&self) -> SnResult<Vec<RelayNode>> {
        self.relay_manager.list_relay_nodes().await
    }

    async fn get_relay_nodes_ip_map(
        &self,
        req: RelayNodeIpMapReq,
    ) -> SnResult<Option<RelayNodeIpMapSnapshot>> {
        self.relay_manager.get_relay_nodes_ip_map(req).await
    }

    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> SnResult<RelayAssignment> {
        self.relay_manager.assign_zone_relay(req).await
    }

    async fn allocate_zone_relay(&self, req: AllocateZoneRelayReq) -> SnResult<RelayAssignment> {
        self.relay_manager.allocate_zone_relay(req).await
    }

    async fn get_zone_relay(&self, zone: &str) -> SnResult<Option<RelayAssignment>> {
        self.relay_manager.get_zone_relay(zone).await
    }

    async fn start_relay_migration(&self, req: RelayMigrationReq) -> SnResult<RelayAssignment> {
        self.relay_manager.start_relay_migration(req).await
    }

    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> SnResult<()> {
        self.relay_manager
            .complete_relay_migration(zone, generation)
            .await
    }

    async fn check_relay_admission(
        &self,
        req: RelayAdmissionReq,
    ) -> SnResult<RelayAdmissionDecision> {
        self.relay_manager.check_relay_admission(req).await
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        sqlx::query(
            "INSERT INTO account_sessions
                (session_id, username, token_aud, state, issued_at, expires_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        )
        .bind(session_id)
        .bind(username)
        .bind(token_aud)
        .bind(SESSION_ACTIVE)
        .bind(issued_at as i64)
        .bind(expires_at as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("insert account session failed", e))?;
        Ok(())
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE session_id = ?3",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke account session failed", e))?;
        Ok(())
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        let result = sqlx::query(
            "UPDATE account_sessions
             SET state = ?1, revoked_at = ?2
             WHERE username = ?3 AND state != ?1",
        )
        .bind(SESSION_REVOKED)
        .bind(revoked_at as i64)
        .bind(username)
        .execute(&self.pool)
        .await
        .map_err(|e| Self::db_err("revoke user sessions failed", e))?;
        Ok(result.rows_affected())
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        let row = sqlx::query(
            "SELECT session_id, username, token_aud, state, issued_at, expires_at, revoked_at
             FROM account_sessions WHERE session_id = ?1",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Self::db_err("query account session failed", e))?;
        row.map(|row| {
            let issued_at: i64 = row
                .try_get("issued_at")
                .map_err(|e| Self::db_err("read issued_at failed", e))?;
            let expires_at: i64 = row
                .try_get("expires_at")
                .map_err(|e| Self::db_err("read expires_at failed", e))?;
            let revoked_at: Option<i64> = row
                .try_get("revoked_at")
                .map_err(|e| Self::db_err("read revoked_at failed", e))?;
            Ok(AccountSession {
                session_id: row
                    .try_get("session_id")
                    .map_err(|e| Self::db_err("read session_id failed", e))?,
                username: row
                    .try_get("username")
                    .map_err(|e| Self::db_err("read username failed", e))?,
                token_aud: row
                    .try_get("token_aud")
                    .map_err(|e| Self::db_err("read token_aud failed", e))?,
                state: row
                    .try_get("state")
                    .map_err(|e| Self::db_err("read state failed", e))?,
                issued_at: Self::i64_to_u64(issued_at),
                expires_at: Self::i64_to_u64(expires_at),
                revoked_at: Self::opt_i64_to_u64(revoked_at),
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_test_db() -> SnResult<(tempfile::TempDir, SqliteSnAuthDB)> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        db.initialize_database().await?;
        Ok((tmp_dir, db))
    }

    async fn assign_test_relay(db: &SqliteSnAuthDB, zone: &str) -> SnResult<RelayAssignment> {
        if db.get_relay_node("relay-a").await?.is_none() {
            db.register_relay_node(RelayNodeRegistration {
                relay_id: "relay-a".to_string(),
                relay_sn: "relay-a.example".to_string(),
                ips: [
                    "192.0.2.10".parse().unwrap(),
                    "2001:db8::10".parse().unwrap(),
                ],
                public_host: "relay-a.example".to_string(),
                http_endpoint: None,
                rtcp_endpoint: None,
                region: Some("test".to_string()),
                isp: None,
                tags: Vec::new(),
                capabilities: vec!["rtcp_relay".to_string()],
                status: None,
                capacity_score: Some(100),
            })
            .await?;
        }
        db.assign_zone_relay(AssignZoneRelayReq {
            zone: zone.to_string(),
            relay_id: Some("relay-a".to_string()),
            relay_sn: None,
            from_ip: None,
            region: None,
            source: crate::RelayAssignmentSource::Admin,
            reason: Some("test".to_string()),
            sticky_until: None,
            lease_expires_at: None,
            backup_relay_id: None,
            source_version: Some("v2".to_string()),
        })
        .await
    }

    #[test]
    fn test_canonical_email_validation() {
        assert_eq!(
            canonical_email("  Alice.Recovery+SN@Example.COM  ").unwrap(),
            "alice.recovery+sn@example.com"
        );
        for invalid in [
            "",
            "missing-at.example.com",
            "two@@example.com",
            ".alice@example.com",
            "alice..sn@example.com",
            "alice@-example.com",
            "alice@example..com",
            "爱丽丝@example.com",
        ] {
            assert!(canonical_email(invalid).is_err(), "must reject {invalid:?}");
        }
    }

    #[tokio::test]
    async fn test_register_email_is_normalized_queryable_and_unique() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("email-code-1").await?;
        db.insert_activation_code("email-code-2").await?;

        assert!(
            db.register_user(
                "email-code-1",
                "alice",
                "  Alice.Recovery@Example.COM  ",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );
        let by_name = db.get_user_info("alice").await?.unwrap();
        assert_eq!(by_name.email.as_deref(), Some("alice.recovery@example.com"));
        let by_email = db
            .get_user_by_email("ALICE.RECOVERY@EXAMPLE.COM")
            .await?
            .unwrap();
        assert_eq!(by_email.username.as_deref(), Some("alice"));

        let duplicate = db
            .register_user(
                "email-code-2",
                "bob",
                "alice.recovery@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await
            .unwrap_err();
        assert_eq!(duplicate.code(), SnErrorCode::Conflict);
        assert!(duplicate.msg().starts_with("email already bound:"));
        assert!(db.check_active_code("email-code-2").await?);
        assert!(!db.is_user_exist("bob").await?);

        // 应用层预查之外，SQLite 唯一索引也必须独立拒绝重复绑定。
        let raw_duplicate =
            sqlx::query("INSERT INTO users (username, email, state) VALUES (?1, ?2, 'active')")
                .bind("raw-duplicate")
                .bind("alice.recovery@example.com")
                .execute(&db.pool)
                .await
                .unwrap_err();
        assert!(raw_duplicate
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation()));

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_registration_rejects_same_normalized_email() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("email-race-code-1").await?;
        db.insert_activation_code("email-race-code-2").await?;
        let db = Arc::new(db);

        let alice = {
            let db = db.clone();
            tokio::spawn(async move {
                db.register_user(
                    "email-race-code-1",
                    "alice",
                    "Recovery@Example.COM",
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            })
        };
        let bob = {
            let db = db.clone();
            tokio::spawn(async move {
                db.register_user(
                    "email-race-code-2",
                    "bob",
                    " recovery@example.com ",
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            })
        };

        let outcomes = [
            alice.await.expect("alice registration task panicked"),
            bob.await.expect("bob registration task panicked"),
        ];
        let mut successes = 0;
        let mut conflicts = 0;
        for outcome in outcomes {
            match outcome {
                Ok(true) => successes += 1,
                Err(error) if error.code() == SnErrorCode::Conflict => conflicts += 1,
                other => panic!("unexpected concurrent registration outcome: {other:?}"),
            }
        }
        assert_eq!(successes, 1);
        assert_eq!(conflicts, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = ?1")
                .bind("recovery@example.com")
                .fetch_one(&db.pool)
                .await
                .map_err(|e| SqliteSnAuthDB::db_err("count registered email failed", e))?,
            1
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_unversioned_legacy_schema_is_rejected() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("legacy-sn-auth.sqlite3");
        let db = SqliteSnAuthDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        sqlx::query(
            "CREATE TABLE users (
                username TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'active',
                public_key TEXT NOT NULL DEFAULT '',
                activation_code TEXT,
                zone_config TEXT NOT NULL DEFAULT '',
                self_cert INTEGER NOT NULL DEFAULT 0,
                user_domain TEXT,
                sn_ips TEXT
            )",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("create legacy users table failed", e))?;
        let error = db.initialize_database().await.unwrap_err();
        assert!(error
            .to_string()
            .contains("incompatible schema, recreate database"));

        Ok(())
    }

    #[tokio::test]
    async fn test_activation_code_and_auth_flow() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        let codes = db.generate_activation_codes(3).await?;
        assert_eq!(codes.len(), 3);
        assert!(codes.iter().all(|code| code.len() == ACTIVATION_CODE_LEN));

        let active_code = codes[0].as_str();
        assert!(db.check_active_code(active_code).await?);
        assert!(
            db.register_user(
                active_code,
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );
        assert!(!db.check_active_code(active_code).await?);
        assert!(
            !db.register_user(
                active_code,
                "bob",
                "bob@example.com",
                "hash2",
                "salt2",
                "pbkdf2",
            )
            .await?
        );
        assert!(db.is_user_exist("alice").await?);

        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
        assert_eq!(user.activation_code.as_deref(), Some(active_code));
        assert_eq!(user.public_key, "");
        assert!(!user.self_cert);

        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");
        assert!(auth.last_login_at.is_none());

        db.update_last_login("alice", 12345).await?;
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.last_login_at, Some(12345));
        assert_eq!(auth.updated_at, 12345);

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);

        Ok(())
    }

    #[tokio::test]
    async fn test_register_with_relay_reports_pending_then_provider_compensates() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("relay-register-code").await?;
        let result = db
            .register_user_with_relay_allocation(RegisterUserWithRelayAllocationReq {
                active_code: "relay-register-code".to_string(),
                username: "alice".to_string(),
                email: "alice@example.com".to_string(),
                password_hash: "hash".to_string(),
                password_salt: "salt".to_string(),
                password_algo: "pbkdf2".to_string(),
                preferred_region: Some("test".to_string()),
                source_ip: Some("192.0.2.1".parse().unwrap()),
                source_version: Some("v1".to_string()),
            })
            .await?;
        assert!(result.registered);
        assert!(matches!(
            result.relay,
            Some(RegistrationRelayAllocation::Pending {
                error_code: SnErrorCode::NotFound,
                ..
            })
        ));
        assert!(db.get_user_info("alice").await?.unwrap().relay.is_none());

        db.register_relay_node(RelayNodeRegistration {
            relay_id: "relay-a".to_string(),
            relay_sn: "relay-a.example".to_string(),
            ips: [
                "192.0.2.50".parse().unwrap(),
                "2001:db8::50".parse().unwrap(),
            ],
            public_host: "relay-a.example".to_string(),
            http_endpoint: None,
            rtcp_endpoint: None,
            region: Some("test".to_string()),
            isp: None,
            tags: Vec::new(),
            capabilities: Vec::new(),
            status: None,
            capacity_score: Some(100),
        })
        .await?;
        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(
            user.relay.as_ref().map(|relay| relay.relay_id.as_str()),
            Some("relay-a")
        );
        assert_eq!(
            db.get_zone_info("alice").await?.unwrap().relay.unwrap(),
            user.relay.unwrap()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_register_with_relay_rolls_back_user_when_pending_cannot_commit() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("relay-atomic-code").await?;
        sqlx::query("DROP TABLE relay_allocation_pending")
            .execute(&db.pool)
            .await
            .unwrap();

        let error = db
            .register_user_with_relay_allocation(RegisterUserWithRelayAllocationReq {
                active_code: "relay-atomic-code".to_string(),
                username: "alice".to_string(),
                email: "alice@example.com".to_string(),
                password_hash: "hash".to_string(),
                password_salt: "salt".to_string(),
                password_algo: "pbkdf2".to_string(),
                preferred_region: None,
                source_ip: None,
                source_version: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), SnErrorCode::DBError);
        assert!(!db.is_user_exist("alice").await?);
        assert!(db.check_active_code("relay-atomic-code").await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_activate_binding_flow_and_supersede() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );
        assert!(
            db.register_user(
                "bob-code",
                "bob",
                "bob@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );

        let binding = db
            .activate_user_domain_binding("alice", "*.Example.COM.", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(binding.pkx_record_name, "_pkx.example.com");
        assert_eq!(binding.pkx, "PKX(alice-owner-key)");
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            db.get_user_info("alice")
                .await?
                .unwrap()
                .user_domain
                .as_deref(),
            Some("example.com")
        );

        // 域名转让：bob 完成自己的 DNS proof（由服务端校验后调用），无需
        // alice 先手工 unbind；旧 active binding 被 supersede、旧缓存清空。
        let takeover = db
            .activate_user_domain_binding("bob", "example.com", "PKX(bob-owner-key)")
            .await?;
        assert_eq!(takeover.domain, "example.com");
        assert_eq!(
            db.get_user_by_domain("api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_SUPERSEDED
        );
        assert!(db
            .get_user_info("alice")
            .await?
            .unwrap()
            .user_domain
            .is_none());

        db.unbind_user_domain("bob", "example.com").await?;
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());
        // unbind 只影响 bob 的 active 行，alice 的 superseded 审计态保持不变。
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_SUPERSEDED
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_zone_info_patch_and_session_revocation() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );

        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                self_cert: Some(true),
                cert_checked_at: Some(10),
                cert_expires_at: Some(20),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                source_version: Some("v1".to_string()),
                ..Default::default()
            },
        )
        .await?;
        assign_test_relay(&db, "alice").await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a.example"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        assert_eq!(db.get_user_info("alice").await?.unwrap().self_cert, true);

        db.create_account_session("refresh-1", "alice", "sn-refresh", 1, 100)
            .await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_ACTIVE);
        db.revoke_account_session("refresh-1", 50).await?;
        let session = db.get_account_session("refresh-1").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);
        assert_eq!(session.revoked_at, Some(50));

        db.create_account_session("refresh-2", "alice", "sn-refresh", 51, 100)
            .await?;
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        let session = db.get_account_session("refresh-2").await?.unwrap();
        assert_eq!(session.state, SESSION_REVOKED);

        Ok(())
    }

    #[tokio::test]
    async fn test_clear_state_by_active_code_resets_account_and_emits_dns_changes() -> SnResult<()>
    {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("clear-me").await?;
        assert!(
            db.register_user(
                "clear-me",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );

        db.put_user_dns_value(
            "alice",
            "alice.example.com",
            UserDnsRecordType::A,
            "127.0.0.1",
            60,
        )
        .await?;

        let result = db.clear_state_by_active_code("clear-me").await?;
        assert_eq!(result.deleted_users, 1);
        assert!(result.activation_code_reset);
        assert!(db.check_active_code("clear-me").await?);
        assert!(!db.is_user_exist("alice").await?);
        assert!(db.get_auth("alice").await?.is_none());
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(!zone.self_cert);
        assert!(zone.zone.is_none());
        let changes = db.list_user_dns_changes(0, 10).await?;
        assert_eq!(changes.changes.len(), 2);
        assert_eq!(
            changes.changes.last().unwrap().operation,
            UserDnsChangeOperation::DeleteName
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_fresh_user_dns_schema_has_constraints_and_no_compatibility_tables() -> SnResult<()>
    {
        let (_tmp_dir, db) = new_test_db().await?;
        let foreign_keys = sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read foreign_keys pragma failed", e))?;
        assert_eq!(foreign_keys, 1);

        let tables = sqlx::query_scalar::<_, String>(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        )
        .fetch_all(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("list schema tables failed", e))?;
        for expected in [
            "user_dns_names",
            "user_dns_rrsets",
            "user_dns_rdata",
            "user_dns_state",
            "user_dns_changes",
        ] {
            assert!(tables.iter().any(|table| table == expected));
        }
        for removed in ["devices", "did_documents", "user_dns_records"] {
            assert!(!tables.iter().any(|table| table == removed));
        }

        let rrset_columns = sqlx::query("PRAGMA table_info(user_dns_rrsets)")
            .fetch_all(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read RRset columns failed", e))?;
        assert_eq!(
            rrset_columns
                .iter()
                .find(|row| row.get::<String, _>("name") == "name")
                .unwrap()
                .get::<i64, _>("pk"),
            1
        );
        assert_eq!(
            rrset_columns
                .iter()
                .find(|row| row.get::<String, _>("name") == "record_type")
                .unwrap()
                .get::<i64, _>("pk"),
            2
        );
        let rdata_foreign_keys = sqlx::query("PRAGMA foreign_key_list(user_dns_rdata)")
            .fetch_all(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read rdata foreign keys failed", e))?;
        assert_eq!(rdata_foreign_keys.len(), 2);
        assert!(rdata_foreign_keys
            .iter()
            .all(|row| row.get::<String, _>("on_delete") == "CASCADE"));
        let name_indexes = sqlx::query("PRAGMA index_list(user_dns_names)")
            .fetch_all(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read user DNS indexes failed", e))?;
        assert!(name_indexes.iter().any(|row| {
            row.get::<String, _>("name") == "idx_user_dns_names_owner_name"
        }));
        let rrset_sql = sqlx::query_scalar::<_, String>(
            "SELECT sql FROM sqlite_master
             WHERE type = 'table' AND name = 'user_dns_rrsets'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("read RRset DDL failed", e))?;
        assert!(rrset_sql.contains("record_type IN ('A', 'AAAA', 'TXT')"));
        assert!(rrset_sql.contains("ttl BETWEEN 30 AND 86400"));
        Ok(())
    }

    #[tokio::test]
    async fn test_user_dns_canonicalization_owner_claim_and_stable_values() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        for (code, username) in [("dns-alice", "alice"), ("dns-bob", "bob")] {
            db.insert_activation_code(code).await?;
            assert!(
                db.register_user(
                    code,
                    username,
                    format!("{}@example.com", username).as_str(),
                    "h",
                    "s",
                    "pbkdf2",
                )
                .await?
            );
        }
        let a = db
            .put_user_dns_value(
                "alice",
                "Host.Example.COM.",
                UserDnsRecordType::A,
                "192.000.002.001",
                600,
            )
            .await;
        assert!(a.is_err(), "non-canonical IPv4 syntax must be rejected");
        db.put_user_dns_value(
            "alice",
            "Host.Example.COM.",
            UserDnsRecordType::A,
            "192.0.2.1",
            600,
        )
        .await?;
        db.put_user_dns_value(
            "alice",
            "host.example.com",
            UserDnsRecordType::Aaaa,
            "2001:0db8:0:0:0:0:0:1",
            300,
        )
        .await?;
        for value in ["z,value", "a,value"] {
            db.put_user_dns_value(
                "alice",
                "host.example.com",
                UserDnsRecordType::Txt,
                value,
                120,
            )
            .await?;
        }
        let rrsets = db.list_user_dns_rrsets("alice").await?;
        assert_eq!(
            rrsets
                .iter()
                .find(|rrset| rrset.record_type == UserDnsRecordType::Aaaa)
                .unwrap()
                .values,
            vec!["2001:db8::1"]
        );
        assert_eq!(
            rrsets
                .iter()
                .find(|rrset| rrset.record_type == UserDnsRecordType::Txt)
                .unwrap()
                .values,
            vec!["a,value", "z,value"]
        );
        let conflict = db
            .put_user_dns_value(
                "bob",
                "host.example.com",
                UserDnsRecordType::Txt,
                "mine",
                600,
            )
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), SnErrorCode::Conflict);
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_user_dns_claim_and_multivalue_add() -> SnResult<()> {
        let (tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("claim-a").await?;
        db.insert_activation_code("claim-b").await?;
        assert!(
            db.register_user("claim-a", "alice", "alice@example.com", "h", "s", "pbkdf2",)
                .await?
        );
        assert!(
            db.register_user("claim-b", "bob", "bob@example.com", "h", "s", "pbkdf2",)
                .await?
        );
        let db = Arc::new(db);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut claims = Vec::new();
        for owner in ["alice", "bob"] {
            let db = db.clone();
            let barrier = barrier.clone();
            claims.push(tokio::spawn(async move {
                barrier.wait().await;
                db.put_user_dns_value(
                    owner,
                    "claimed.example.com",
                    UserDnsRecordType::Txt,
                    owner,
                    600,
                )
                .await
            }));
        }
        barrier.wait().await;
        let outcomes = [
            claims.remove(0).await.unwrap(),
            claims.remove(0).await.unwrap(),
        ];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.code() == SnErrorCode::Conflict))
                .count(),
            1
        );

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut adds = Vec::new();
        for value in ["one", "two"] {
            let db = db.clone();
            let barrier = barrier.clone();
            adds.push(tokio::spawn(async move {
                barrier.wait().await;
                db.put_user_dns_value(
                    "alice",
                    "multi.example.com",
                    UserDnsRecordType::Txt,
                    value,
                    600,
                )
                .await
            }));
        }
        barrier.wait().await;
        for add in adds {
            add.await.unwrap()?;
        }
        assert_eq!(
            db.get_user_dns_rrset("multi.example.com", UserDnsRecordType::Txt)
                .await?
                .rrset
                .unwrap()
                .values,
            vec!["one", "two"]
        );

        db.put_user_dns_value(
            "alice",
            "interleave.example.com",
            UserDnsRecordType::Txt,
            "remove-me",
            600,
        )
        .await?;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let add = {
            let db = db.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                db.put_user_dns_value(
                    "alice",
                    "interleave.example.com",
                    UserDnsRecordType::Txt,
                    "keep-me",
                    600,
                )
                .await
            })
        };
        let remove = {
            let db = db.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                db.remove_user_dns_value(
                    "alice",
                    "interleave.example.com",
                    UserDnsRecordType::Txt,
                    "remove-me",
                )
                .await
            })
        };
        barrier.wait().await;
        assert!(add.await.unwrap()?.changed);
        assert!(remove.await.unwrap()?.changed);
        assert_eq!(
            db.get_user_dns_rrset("interleave.example.com", UserDnsRecordType::Txt)
                .await?
                .rrset
                .unwrap()
                .values,
            vec!["keep-me"]
        );

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut duplicates = Vec::new();
        for _ in 0..2 {
            let db = db.clone();
            let barrier = barrier.clone();
            duplicates.push(tokio::spawn(async move {
                barrier.wait().await;
                db.put_user_dns_value(
                    "alice",
                    "duplicate.example.com",
                    UserDnsRecordType::Txt,
                    "same-request",
                    600,
                )
                .await
            }));
        }
        barrier.wait().await;
        let duplicate_results = [
            duplicates.remove(0).await.unwrap()?,
            duplicates.remove(0).await.unwrap()?,
        ];
        assert_eq!(
            duplicate_results
                .iter()
                .filter(|result| result.changed)
                .count(),
            1
        );
        drop(tmp_dir);
        Ok(())
    }

    #[tokio::test]
    async fn test_resolver_recovers_from_user_dns_change_retention_gap() -> SnResult<()> {
        use crate::{SnAuthResolverReader, SnResolver, SnResolverConfig};
        use name_client::RecordType;

        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("gap-code").await?;
        assert!(
            db.register_user("gap-code", "alice", "alice@example.com", "h", "s", "pbkdf2",)
                .await?
        );
        let name = "host.alice.web3.example";
        db.put_user_dns_value("alice", name, UserDnsRecordType::A, "192.0.2.1", 600)
            .await?;
        let db = Arc::new(db);
        let auth: SnAuthDBRef = db.clone();
        let resolver = SnResolver::new(
            SnResolverConfig::new(
                "example",
                Some("192.0.2.10".parse().unwrap()),
                None,
                None,
                Vec::new(),
            ),
            Arc::new(SnAuthResolverReader::new(auth.clone())),
        );
        assert_eq!(
            resolver
                .resolve_dns_cached(name, RecordType::A)
                .await
                .unwrap()
                .addresses,
            vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
        );
        auth.put_user_dns_value("alice", name, UserDnsRecordType::A, "192.0.2.2", 600)
            .await?;
        auth.remove_user_dns_value("alice", name, UserDnsRecordType::A, "192.0.2.1")
            .await?;
        sqlx::query("DELETE FROM user_dns_changes WHERE revision <= 2")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("simulate DNS retention gap failed", e))?;
        assert_eq!(
            resolver
                .resolve_dns_cached(name, RecordType::A)
                .await
                .unwrap()
                .addresses,
            vec!["192.0.2.2".parse::<std::net::IpAddr>().unwrap()]
        );
        Ok(())
    }

    // ---- §3.1 账号与凭证（DB 层）----

    /// 激活码：生成 32 位、charset 受限、唯一；`check_active_code` 区分存在/已用/未知；
    /// 注册后事务内置 `used=1`，二次使用被拒。
    #[tokio::test]
    async fn test_activation_code_generation_and_single_use() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        let codes = db.generate_activation_codes(8).await?;
        assert_eq!(codes.len(), 8);
        for code in &codes {
            assert_eq!(code.len(), ACTIVATION_CODE_LEN);
            assert!(code.bytes().all(|b| ACTIVATION_CODE_CHARS.contains(&b)));
        }
        let unique: std::collections::HashSet<_> = codes.iter().cloned().collect();
        assert_eq!(unique.len(), codes.len(), "generated codes must be unique");

        // 未知激活码 → false（既非存在也非未用）。
        assert!(!db.check_active_code("does-not-exist").await?);

        let code = codes[0].as_str();
        assert!(db.check_active_code(code).await?);
        assert!(
            db.register_user(code, "alice", "alice@example.com", "h", "s", "pbkdf2")
                .await?
        );

        // 注册后事务内 used=1。
        let used: i64 = sqlx::query_scalar("SELECT used FROM activation_codes WHERE code = ?1")
            .bind(code)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("read used flag failed", e))?;
        assert_eq!(used, 1);
        assert!(!db.check_active_code(code).await?);

        // 二次使用被拒（既不创建用户，也不报错，按契约返回 false）。
        assert!(
            !db.register_user(code, "bob", "bob@example.com", "h", "s", "pbkdf2")
                .await?
        );
        assert!(!db.is_user_exist("bob").await?);

        Ok(())
    }

    /// `register_user` 事务性：`users` + `user_auth` + `zone_info` 一致写入，激活码标记 used。
    #[tokio::test]
    async fn test_register_user_writes_consistent_rows() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("code-1").await?;
        assert!(
            db.register_user(
                "code-1",
                "alice",
                "alice@example.com",
                "hash",
                "salt",
                "pbkdf2",
            )
            .await?
        );

        // users 行。
        let user = db.get_user_info("alice").await?.unwrap();
        assert_eq!(user.username.as_deref(), Some("alice"));
        assert_eq!(user.activation_code.as_deref(), Some("code-1"));
        assert!(matches!(user.state, UserState::Active));

        // user_auth 行。
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password_hash, "hash");
        assert_eq!(auth.password_salt, "salt");
        assert_eq!(auth.password_algo, "pbkdf2");

        // zone_info 行（bns_name 默认为 username）。
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");

        // 同名二次注册（换激活码）被拒，且不破坏已有行。
        db.insert_activation_code("code-2").await?;
        assert!(
            !db.register_user(
                "code-2",
                "alice",
                "alice2@example.com",
                "h2",
                "s2",
                "pbkdf2",
            )
            .await?
        );
        // code-2 未被消费。
        assert!(db.check_active_code("code-2").await?);
        let auth = db.get_auth("alice").await?.unwrap();
        assert_eq!(
            auth.password_hash, "hash",
            "existing auth must be untouched"
        );

        Ok(())
    }

    /// 命名锁下并发注册：N 个任务用同一激活码注册不同用户名，只允许一个成功。
    #[tokio::test]
    async fn test_register_user_concurrent_single_success() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("shared-code").await?;
        let db = Arc::new(db);

        let mut handles = Vec::new();
        for i in 0..8 {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                db.register_user(
                    "shared-code",
                    &format!("user-{i}"),
                    &format!("user-{i}@example.com"),
                    "hash",
                    "salt",
                    "pbkdf2",
                )
                .await
            }));
        }

        let mut success = 0;
        for handle in handles {
            if handle.await.expect("task panicked")? {
                success += 1;
            }
        }
        assert_eq!(success, 1, "exactly one concurrent registration may win");

        // 激活码已消费，且只创建了一个用户。
        assert!(!db.check_active_code("shared-code").await?);
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("count users failed", e))?;
        assert_eq!(user_count, 1);

        Ok(())
    }

    /// 密码：PBKDF2-sha256-100000、16B salt(hex)、32B hash(hex)；`verify_password` 正确/错误；
    /// 服务端不存明文；不支持的算法被拒。
    #[tokio::test]
    async fn test_password_pbkdf2_hash_and_verify() -> SnResult<()> {
        use crate::sn_auth_manager::{hash_password, verify_password, PASSWORD_ALGO};

        let (hash, salt) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        // 16 字节 salt → 32 hex 字符；32 字节 hash → 64 hex 字符。
        assert_eq!(salt.len(), 32);
        assert_eq!(hash.len(), 64);
        assert_eq!(hex::decode(&salt).unwrap().len(), 16);
        assert_eq!(hex::decode(&hash).unwrap().len(), 32);
        // 不存明文。
        assert_ne!(hash, "hunter2");

        // 同一密码 + 不同随机 salt → 不同 hash。
        let (hash2, salt2) = hash_password("hunter2")
            .map_err(|e| sn_err!(SnErrorCode::Failed, "hash failed: {:?}", e))?;
        assert_ne!(salt, salt2);
        assert_ne!(hash, hash2);

        let auth = SnAuthInfo {
            username: "alice".to_string(),
            password_hash: hash,
            password_salt: salt,
            password_algo: PASSWORD_ALGO.to_string(),
            created_at: 0,
            updated_at: 0,
            last_login_at: None,
        };
        assert!(verify_password("hunter2", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);
        assert!(!verify_password("wrong-pass", &auth).map_err(|e| sn_err!(
            SnErrorCode::Failed,
            "verify failed: {:?}",
            e
        ))?);

        // 不支持的算法 → 错误，而非 false。
        let mut bad = auth.clone();
        bad.password_algo = "plaintext".to_string();
        assert!(verify_password("hunter2", &bad).is_err());

        Ok(())
    }

    /// 用户状态机：`set_user_state` 写入 active/suspended/deleted/banned；
    /// 置非 active 时自动撤销该用户 session；active 不撤销。
    #[tokio::test]
    async fn test_set_user_state_revokes_sessions() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("state-code").await?;
        assert!(
            db.register_user(
                "state-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        // active → active：session 保留。
        db.create_account_session("sess-keep", "alice", "sn-refresh", 1, 100)
            .await?;
        db.set_user_state("alice", UserState::Active).await?;
        assert_eq!(
            db.get_account_session("sess-keep").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 逐个非 active 状态：写库 + 撤销 session。
        for (state, label) in [
            (UserState::Suspended, "suspended"),
            (UserState::Deleted, "deleted"),
            (UserState::Banned, "banned"),
        ] {
            // 重新发一个活跃 session。
            let sid = format!("sess-{label}");
            db.create_account_session(&sid, "alice", "sn-refresh", 1, 100)
                .await?;
            db.set_user_state("alice", state).await?;

            let stored: String =
                sqlx::query_scalar("SELECT state FROM users WHERE username = 'alice'")
                    .fetch_one(&db.pool)
                    .await
                    .map_err(|e| SqliteSnAuthDB::db_err("read user state failed", e))?;
            assert_eq!(stored, label);

            let session = db.get_account_session(&sid).await?.unwrap();
            assert_eq!(
                session.state, SESSION_REVOKED,
                "{label} must revoke session"
            );
            assert!(session.revoked_at.is_some());
        }

        Ok(())
    }

    // ---- §3.2 session（account_sessions）----

    /// session 生命周期：create/get/revoke/revoke_user_sessions 语义与计数。
    #[tokio::test]
    async fn test_account_session_lifecycle_and_counts() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;

        // 未知 session → None。
        assert!(db.get_account_session("missing").await?.is_none());
        for username in ["alice", "bob"] {
            sqlx::query("INSERT INTO users (username) VALUES (?1)")
                .bind(username)
                .execute(&db.pool)
                .await
                .map_err(|e| SqliteSnAuthDB::db_err("insert session test user failed", e))?;
        }

        db.create_account_session("a1", "alice", "sn-refresh", 1, 100)
            .await?;
        db.create_account_session("a2", "alice", "sn-refresh", 2, 100)
            .await?;
        db.create_account_session("b1", "bob", "sn-refresh", 3, 100)
            .await?;

        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.username, "alice");
        assert_eq!(s.token_aud, "sn-refresh");
        assert_eq!(s.state, SESSION_ACTIVE);
        assert_eq!(s.issued_at, 1);
        assert_eq!(s.expires_at, 100);
        assert!(s.revoked_at.is_none());

        // 单条撤销。
        db.revoke_account_session("a1", 50).await?;
        let s = db.get_account_session("a1").await?.unwrap();
        assert_eq!(s.state, SESSION_REVOKED);
        assert_eq!(s.revoked_at, Some(50));

        // 批量撤销只命中 alice 的活跃 session（a1 已撤销，仅 a2 计入）。
        assert_eq!(db.revoke_user_sessions("alice", 60).await?, 1);
        assert_eq!(
            db.get_account_session("a2").await?.unwrap().state,
            SESSION_REVOKED
        );
        // bob 不受影响。
        assert_eq!(
            db.get_account_session("b1").await?.unwrap().state,
            SESSION_ACTIVE
        );

        // 再次批量撤销 alice：已无活跃 session → 0。
        assert_eq!(db.revoke_user_sessions("alice", 70).await?, 0);

        Ok(())
    }

    // ---- §3.3 user_domain + PKX proof ----

    /// `canonical_user_domain` / `pkx_record_name` / `pkx_value` / `txt_matches_pkx` helper 稳定性。
    #[test]
    fn test_user_domain_helpers_are_stable() {
        // 去 `*.` 前缀、小写、去尾点。
        assert_eq!(
            canonical_user_domain("*.Example.COM."),
            Some("example.com".to_string())
        );
        assert_eq!(
            canonical_user_domain("  API.Example.com  "),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            canonical_user_domain("example.com"),
            Some("example.com".to_string())
        );
        // 空 / 仅点 / 仅通配 → None。
        assert_eq!(canonical_user_domain("   "), None);
        assert_eq!(canonical_user_domain("."), None);
        assert_eq!(canonical_user_domain("*."), None);

        // 派生 helper 同输入恒等（无 nonce / exp）。
        assert_eq!(pkx_record_name("example.com"), "_pkx.example.com");
        assert_eq!(
            pkx_value("owner-key").unwrap(),
            pkx_value("owner-key").unwrap()
        );
        assert_eq!(pkx_value("  owner-key  ").unwrap(), "PKX(owner-key)");
        assert!(pkx_value("   ").is_err());

        // `sn_user.pkx` 归一：JWK JSON → x 分量；`PKX=<x>[:...];` → <x>。
        assert_eq!(
            pkx_value(r#"{"crv":"Ed25519","kty":"OKP","x":"alice-x-component"}"#).unwrap(),
            "PKX(alice-x-component)"
        );
        assert_eq!(
            pkx_source_of("PKX=alice-x-component:bns:alice;").as_deref(),
            Some("alice-x-component")
        );
        assert_eq!(pkx_source_of("raw-x;").as_deref(), Some("raw-x"));
        assert_eq!(pkx_source_of("  "), None);

        // TXT 比较容忍包裹引号与首尾空白。
        assert!(txt_matches_pkx("  \"PKX(owner-key)\"  ", "PKX(owner-key)"));
        assert!(!txt_matches_pkx("PKX(other)", "PKX(owner-key)"));
    }

    /// 状态机：activate → active + history；同 owner 重复激活仅刷新（无重复
    /// 审计行）；unbind → revoked；重新激活 → 新 active 行 + 新审计行。
    #[tokio::test]
    async fn test_activate_binding_state_transitions_and_history() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        let binding = db
            .activate_user_domain_binding("alice", "Example.com.", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(binding.domain, "example.com");
        assert_eq!(binding.pkx_record_name, "_pkx.example.com");
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_ACTIVE
        );
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);

        // 同 owner 重复激活：幂等刷新（pkx 可轮换），不追加审计行、不新增绑定行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-rotated-key)")
            .await?;
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);
        let active_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_bindings WHERE domain = 'example.com'",
        )
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count binding rows failed", e))?;
        assert_eq!(active_rows, 1);
        assert_eq!(
            db.get_user_by_domain("example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        // unbind → revoked，history 保留；SN-DNS 侧 get_user_by_domain 不再命中
        // 该域名及其子域名。
        db.unbind_user_domain("alice", "example.com").await?;
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_REVOKED
        );
        assert!(db.get_user_by_domain("example.com").await?.is_none());
        assert!(db.get_user_by_domain("api.example.com").await?.is_none());
        assert_eq!(history_count(&db, "example.com", "alice").await?, 1);
        assert!(db
            .get_user_info("alice")
            .await?
            .unwrap()
            .user_domain
            .is_none());

        // 重新完成 proof 后再次激活：新 active 行 + 新审计行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-owner-key)")
            .await?;
        assert_eq!(
            binding_state(&db, "example.com", "alice").await?,
            DOMAIN_BINDING_ACTIVE
        );
        assert_eq!(history_count(&db, "example.com", "alice").await?, 2);

        Ok(())
    }

    /// Beta2.2 冲突规则：history 仅审计，不阻止接管；同域名旧 active binding
    /// 被新 DNS owner supersede；父/子域名不互斥。非 active 用户不能激活。
    #[tokio::test]
    async fn test_history_is_audit_only_and_domains_are_not_exclusive() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        for (code, user) in [("a-code", "alice"), ("b-code", "bob")] {
            db.insert_activation_code(code).await?;
            assert!(
                db.register_user(
                    code,
                    user,
                    &format!("{user}@example.com"),
                    "h",
                    "s",
                    "pbkdf2",
                )
                .await?
            );
        }

        // alice 激活 example.com 后 unbind：留下 history 与 revoked 行。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-key)")
            .await?;
        db.unbind_user_domain("alice", "example.com").await?;

        // history 不构成硬冲突：bob 能通过自己的 DNS proof 接管同一域名。
        db.activate_user_domain_binding("bob", "example.com", "PKX(bob-key)")
            .await?;
        assert_eq!(
            db.get_user_by_domain("example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );

        // 祖先/子域名不再互斥：alice 可绑定 bob 域名的子域，反向亦然。
        db.activate_user_domain_binding("alice", "api.example.com", "PKX(alice-key)")
            .await?;
        db.activate_user_domain_binding("alice", "com", "PKX(alice-key)")
            .await?;

        // 解析按最长 active binding 匹配。
        assert_eq!(
            db.get_user_by_domain("host.api.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );
        assert_eq!(
            db.get_user_by_domain("www.example.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("bob")
        );
        assert_eq!(
            db.get_user_by_domain("other.com")
                .await?
                .unwrap()
                .username
                .as_deref(),
            Some("alice")
        );

        // 非 active 用户不能激活绑定。
        db.set_user_state("bob", UserState::Suspended).await?;
        let err = db
            .activate_user_domain_binding("bob", "blocked.example.org", "PKX(bob-key)")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Blocked);

        // 空 pkx 不能激活（proof 值必须由服务端算出）。
        let err = db
            .activate_user_domain_binding("alice", "empty.example.org", "  ")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::InvalidInput);

        Ok(())
    }

    /// `get_user_by_domain`：只查询 active binding，旧 `users.user_domain` 不再作为回退。
    #[tokio::test]
    async fn test_get_user_by_domain_longest_match_without_legacy_fallback() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("alice-code").await?;
        assert!(
            db.register_user(
                "alice-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        // alice 同时激活 example.com 与更具体的 sub.example.com。
        db.activate_user_domain_binding("alice", "example.com", "PKX(alice-key)")
            .await?;
        db.activate_user_domain_binding("alice", "sub.example.com", "PKX(alice-key)")
            .await?;

        // host.sub.example.com → 命中最长的 sub.example.com binding（同样属 alice）。
        let matched = db
            .get_user_by_domain("host.sub.example.com")
            .await?
            .unwrap();
        assert_eq!(matched.username.as_deref(), Some("alice"));
        assert_eq!(matched.user_domain.as_deref(), Some("sub.example.com"));
        db.set_user_state("alice", UserState::Suspended).await?;
        assert!(db
            .get_user_by_domain("host.sub.example.com")
            .await?
            .is_none());
        db.set_user_state("alice", UserState::Active).await?;
        assert!(db.get_user_by_domain("unrelated.org").await?.is_none());

        // breaking change：bob 仅在 users.user_domain 留有遗留域名、无 binding 行，不再命中。
        db.insert_activation_code("bob-code").await?;
        assert!(
            db.register_user("bob-code", "bob", "bob@example.com", "h", "s", "pbkdf2",)
                .await?
        );
        sqlx::query("UPDATE users SET user_domain = 'legacy.test' WHERE username = 'bob'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("set legacy domain failed", e))?;
        assert!(db.get_user_by_domain("host.legacy.test").await?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_wrong_schema_version_is_rejected() -> SnResult<()> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_auth.sqlite3");
        let db_path_str = db_path.to_string_lossy().to_string();
        let db = SqliteSnAuthDB::new_by_path(db_path_str.as_str()).await?;
        sqlx::query(
            "CREATE TABLE sn_auth_schema (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                version INTEGER NOT NULL
             )",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("create old schema marker failed", e))?;
        sqlx::query("INSERT INTO sn_auth_schema VALUES (1, 1)")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("insert old schema marker failed", e))?;
        let error = db.initialize_database().await.unwrap_err();
        assert!(error
            .to_string()
            .contains("incompatible schema, recreate database"));
        Ok(())
    }

    // ---- §3.4 zone_info ----

    /// `update_zone_info` patch 语义：只改传入字段，其余保留；users 缓存同步。
    #[tokio::test]
    async fn test_zone_info_patch_only_changes_given_fields() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        // 初始整体写入。
        db.update_zone_info(
            "alice",
            ZoneInfoPatch {
                zone: Some("did:zone:alice".to_string()),
                self_cert: Some(true),
                sn_ips: Some("[\"1.2.3.4\"]".to_string()),
                ..Default::default()
            },
        )
        .await?;

        // relay_sn 已变为只读 assignment 投影。
        assert_eq!(
            db.update_zone_info(
                "alice",
                ZoneInfoPatch {
                    relay_sn: Some("relay-a".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err()
            .code(),
            SnErrorCode::InvalidInput
        );
        assign_test_relay(&db, "alice").await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a.example"));
        assert_eq!(zone.zone.as_deref(), Some("did:zone:alice"));
        assert!(zone.self_cert);
        assert_eq!(zone.sn_ips.as_deref(), Some("[\"1.2.3.4\"]"));
        // users 缓存同步。
        assert!(db.get_user_info("alice").await?.unwrap().self_cert);

        Ok(())
    }

    /// `get_zone_info` 缺 zone_info 行时返回默认值，不再从 `users.zone_config` 派生。
    #[tokio::test]
    async fn test_get_zone_info_without_legacy_user_cache_fallback() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        // 删 zone_info 行，并在 users 上留下旧 zone_config / self_cert。
        sqlx::query("DELETE FROM zone_info WHERE username = 'alice'")
            .execute(&db.pool)
            .await
            .map_err(|e| SqliteSnAuthDB::db_err("delete zone_info failed", e))?;
        sqlx::query(
            "UPDATE users SET zone_config = 'did:zone:legacy', self_cert = 1 WHERE username = 'alice'",
        )
        .execute(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("update user cache failed", e))?;

        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.username, "alice");
        assert_eq!(zone.bns_name, "alice");
        assert!(zone.zone.is_none());
        assert!(!zone.self_cert);

        // 完全未知用户 → 默认值（不报错）。
        let zone = db.get_zone_info("ghost").await?.unwrap();
        assert_eq!(zone.username, "ghost");
        assert!(zone.zone.is_none());
        assert!(!zone.self_cert);

        Ok(())
    }

    /// `update_zone_relay_sn` 不再允许维护第二份真相；assignment 通过 join 投影。
    #[tokio::test]
    async fn test_zone_relay_is_read_only_assignment_projection() -> SnResult<()> {
        let (_tmp_dir, db) = new_test_db().await?;
        db.insert_activation_code("zone-code").await?;
        assert!(
            db.register_user(
                "zone-code",
                "alice",
                "alice@example.com",
                "h",
                "s",
                "pbkdf2",
            )
            .await?
        );

        assert_eq!(
            db.update_zone_relay_sn("alice", "relay-a", Some("v2"))
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assign_test_relay(&db, "alice").await?;
        let zone = db.get_zone_info("alice").await?.unwrap();
        assert_eq!(zone.relay_sn.as_deref(), Some("relay-a.example"));
        assert_eq!(zone.relay.unwrap().generation, 1);

        assert_eq!(
            db.update_zone_relay_sn("", "relay-a", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assert_eq!(
            db.update_zone_relay_sn("alice", "  ", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );

        assert_eq!(
            db.update_zone_relay_sn("ghost-zone", "relay-b", None)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        let zone = db.get_zone_info("ghost-zone").await?.unwrap();
        assert!(zone.relay_sn.is_none());

        Ok(())
    }

    /// 指定 (domain, owner) 最新一行绑定的状态。
    async fn binding_state(db: &SqliteSnAuthDB, domain: &str, owner: &str) -> SnResult<String> {
        sqlx::query_scalar(
            "SELECT state FROM user_domain_bindings
             WHERE domain = ?1 AND owner = ?2
             ORDER BY id DESC LIMIT 1",
        )
        .bind(domain)
        .bind(owner)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("read binding state failed", e))
    }

    async fn history_count(db: &SqliteSnAuthDB, domain: &str, owner: &str) -> SnResult<i64> {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_domain_history WHERE domain = ?1 AND owner = ?2",
        )
        .bind(domain)
        .bind(owner)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| SqliteSnAuthDB::db_err("count history failed", e))
    }
}
