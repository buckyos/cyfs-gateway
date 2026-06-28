use ::kRPC::*;
use async_trait::async_trait;
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::result::Result;

const SN_ROOT_PATH: &str = "/kapi/sn";
const SN_AUTH_PATH: &str = "/kapi/sn/auth";
const SN_DEVICEINFO_PATH: &str = "/kapi/sn/deviceinfo";
const LEGACY_SN_BNS_PATH: &str = "/kapi/sn/bns";

#[derive(Clone, Copy)]
enum SnRpcTarget {
    Auth,
    DeviceInfo,
}

fn normalize_sn_url(sn_url: &str, target: SnRpcTarget) -> String {
    let path = match target {
        SnRpcTarget::Auth => SN_AUTH_PATH,
        SnRpcTarget::DeviceInfo => SN_DEVICEINFO_PATH,
    };

    let trimmed = sn_url.trim_end_matches('/');
    for known_suffix in [
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
    pub pwd_hash: String,
    pub active_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_config: Option<Value>,
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

pub enum SnClient {
    InProcess(Box<dyn SnHandler>),
    KRPC {
        auth: Box<kRPC>,
        deviceinfo: Box<kRPC>,
    },
}

impl SnClient {
    pub fn new_in_process(handler: Box<dyn SnHandler>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(sn_url: &str, session_token: Option<String>) -> Self {
        Self::KRPC {
            auth: new_sn_krpc(sn_url, session_token.clone(), SnRpcTarget::Auth),
            deviceinfo: new_sn_krpc(sn_url, session_token, SnRpcTarget::DeviceInfo),
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
        self.call_deviceinfo("device.list", serde_json::json!({}))
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
