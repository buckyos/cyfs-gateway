use ::kRPC::*;
use async_trait::async_trait;
use jsonwebtoken::EncodingKey;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::result::Result;
use std::time::{SystemTime, UNIX_EPOCH};

const SN_ROOT_PATH: &str = "/kapi/sn";
const SN_AUTH_PATH: &str = "/kapi/sn/auth";
const SN_DEVICEINFO_PATH: &str = "/kapi/sn/deviceinfo";
const SN_BNS_PROXY_PATH: &str = "/kapi/sn/bns-proxy";
const LEGACY_SN_BNS_PATH: &str = "/kapi/sn/bns";

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_owner: Option<String>,
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
    pub device_info: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Value>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<Value>,
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
#[serde(deny_unknown_fields)]
pub struct SnBnsPublishDocumentReq {
    pub name: String,
    pub doc_type: String,
    pub document: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDeviceState {
    Online,
    Offline,
    Stale,
    Blocked,
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

    async fn call_auth(&self, method: &str, params: Value) -> Result<Value, RPCErrors> {
        match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { auth, .. } => auth.call(method, params).await,
        }
    }

    async fn call_deviceinfo(&self, method: &str, params: Value) -> Result<Value, RPCErrors> {
        match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { deviceinfo, .. } => deviceinfo.call(method, params).await,
        }
    }

    async fn call_bns_proxy(&self, method: &str, params: Value) -> Result<Value, RPCErrors> {
        match self {
            Self::InProcess(handler) => handler.handle_sn_rpc(method, params).await,
            Self::KRPC { bns_proxy, .. } => bns_proxy.call(method, params).await,
        }
    }

    pub async fn check_username(&self, name: &str) -> Result<Value, RPCErrors> {
        self.call_auth(
            "auth.check_username",
            serde_json::json!({
                "name": name
            }),
        )
        .await
    }

    pub async fn check_active_code(&self, active_code: &str) -> Result<Value, RPCErrors> {
        self.call_auth(
            "auth.check_active_code",
            serde_json::json!({
                "active_code": active_code
            }),
        )
        .await
    }

    pub async fn register(&self, req: SnAuthRegisterReq) -> Result<Value, RPCErrors> {
        self.call_auth("auth.register", to_value(req, "SnAuthRegisterReq")?)
            .await
    }

    pub async fn login(&self, req: SnAuthLoginReq) -> Result<Value, RPCErrors> {
        self.call_auth("auth.login", to_value(req, "SnAuthLoginReq")?)
            .await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Value, RPCErrors> {
        self.call_auth(
            "auth.refresh",
            serde_json::json!({
                "refresh_token": refresh_token
            }),
        )
        .await
    }

    pub async fn logout(&self, refresh_token: Option<&str>) -> Result<Value, RPCErrors> {
        self.call_auth(
            "auth.logout",
            serde_json::json!({
                "refresh_token": refresh_token
            }),
        )
        .await
    }

    pub async fn me(&self) -> Result<Value, RPCErrors> {
        self.call_auth("auth.me", serde_json::json!({})).await
    }

    pub async fn get_profile(&self) -> Result<Value, RPCErrors> {
        self.call_auth("user.get_profile", serde_json::json!({}))
            .await
    }

    pub async fn set_self_cert(
        &self,
        self_cert: bool,
        device_did: Option<&str>,
    ) -> Result<Value, RPCErrors> {
        self.call_auth(
            "user.set_self_cert",
            serde_json::json!({
                "self_cert": self_cert,
                "device_did": device_did
            }),
        )
        .await
    }

    pub async fn add_dns_record(&self, req: SnDnsRecordReq) -> Result<Value, RPCErrors> {
        self.call_auth("user.add_dns_record", to_value(req, "SnDnsRecordReq")?)
            .await
    }

    pub async fn remove_dns_record(&self, req: SnDnsRecordReq) -> Result<Value, RPCErrors> {
        self.call_auth("user.remove_dns_record", to_value(req, "SnDnsRecordReq")?)
            .await
    }

    pub async fn list_dns_records(&self) -> Result<Value, RPCErrors> {
        self.call_auth("user.list_dns_records", serde_json::json!({}))
            .await
    }

    pub async fn bind_domain(&self, domain: &str) -> Result<Value, RPCErrors> {
        self.call_auth(
            "domain.bind",
            serde_json::json!({
                "domain": domain
            }),
        )
        .await
    }

    pub async fn unbind_domain(&self, domain: &str) -> Result<Value, RPCErrors> {
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
    ) -> Result<Value, RPCErrors> {
        self.call_deviceinfo("device.register", to_value(req, "SnDeviceOnlineReportReq")?)
            .await
    }

    pub async fn update_device_online(
        &self,
        req: SnDeviceOnlineReportReq,
    ) -> Result<Value, RPCErrors> {
        self.call_deviceinfo("device.update", to_value(req, "SnDeviceOnlineReportReq")?)
            .await
    }

    pub async fn get_device_online(
        &self,
        device_name: Option<&str>,
        device_did: Option<&str>,
    ) -> Result<Value, RPCErrors> {
        self.call_deviceinfo(
            "device.get",
            serde_json::json!({
                "device_name": device_name,
                "device_did": device_did
            }),
        )
        .await
    }

    pub async fn list_devices_online(&self) -> Result<Value, RPCErrors> {
        self.list_devices_online_with_options(SnDeviceListReq::default())
            .await
    }

    pub async fn list_devices_online_with_options(
        &self,
        req: SnDeviceListReq,
    ) -> Result<Value, RPCErrors> {
        self.call_deviceinfo("device.list", to_value(req, "SnDeviceListReq")?)
            .await
    }

    pub async fn resolve_ood_by_did(&self, source_device_id: &str) -> Result<Value, RPCErrors> {
        self.call_deviceinfo(
            "deviceinfo.resolve_ood_by_did",
            serde_json::json!({
                "source_device_id": source_device_id
            }),
        )
        .await
    }

    pub async fn resolve_ood_by_hostname(&self, dest_host: &str) -> Result<Value, RPCErrors> {
        self.call_deviceinfo(
            "deviceinfo.resolve_ood_by_hostname",
            serde_json::json!({
                "dest_host": dest_host
            }),
        )
        .await
    }

    pub async fn publish_dns_txt(&self, req: SnBnsPublishDnsTxtReq) -> Result<Value, RPCErrors> {
        self.call_bns_proxy(
            "bns.publish_dns_txt",
            to_value(req, "SnBnsPublishDnsTxtReq")?,
        )
        .await
    }

    pub async fn publish_document(&self, req: SnBnsPublishDocumentReq) -> Result<Value, RPCErrors> {
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

pub async fn sn_auth_register(sn_url: &str, req: SnAuthRegisterReq) -> Result<Value, RPCErrors> {
    SnClient::new_krpc(sn_url, None).register(req).await
}

pub async fn sn_auth_login(sn_url: &str, req: SnAuthLoginReq) -> Result<Value, RPCErrors> {
    SnClient::new_krpc(sn_url, None).login(req).await
}

pub async fn sn_update_device_online(
    sn_url: &str,
    access_token: String,
    req: SnDeviceOnlineReportReq,
) -> Result<Value, RPCErrors> {
    SnClient::new_krpc(sn_url, Some(access_token))
        .update_device_online(req)
        .await
}

pub async fn sn_register_device_online(
    sn_url: &str,
    access_token: String,
    req: SnDeviceOnlineReportReq,
) -> Result<Value, RPCErrors> {
    SnClient::new_krpc(sn_url, Some(access_token))
        .register_device_online(req)
        .await
}

pub async fn sn_resolve_ood_by_did(
    sn_url: &str,
    source_device_id: &str,
) -> Result<Value, RPCErrors> {
    SnClient::new_krpc(sn_url, None)
        .resolve_ood_by_did(source_device_id)
        .await
}

pub async fn sn_resolve_ood_by_hostname(sn_url: &str, dest_host: &str) -> Result<Value, RPCErrors> {
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

    let sn_config = serde_json::from_str(&body);
    if sn_config.is_err() {
        warn!("get sn host name failed! {}", sn_config.err().unwrap());
        return Ok(sn.to_string());
    }

    let sn_config: Value = sn_config.unwrap();
    let host_name = sn_config["host"].as_str().unwrap();
    warn!("get sn real host from {} success! => {}", url, host_name);
    Ok(host_name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn register_request_serializes_initial_documents() {
        let request = SnAuthRegisterReq {
            name: "alice".to_string(),
            email: "alice@example.com".to_string(),
            pwd_hash: "hash".to_string(),
            active_code: "code".to_string(),
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
}
