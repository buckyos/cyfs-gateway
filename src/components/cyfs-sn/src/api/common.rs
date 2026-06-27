use crate::{SNServer, SnAuthDBRef, SnCompatibilityStoreRef};
use ::kRPC::*;
use bns_client::SnBnsController;
use bns_indexer::{CallAuthority, PrincipalKind};
use jsonwebtoken::{jwk::Jwk, DecodingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::{parse_error, reason_error, SnV2ErrorCode};

pub(crate) type RpcCallResult<T> = std::result::Result<T, RPCErrors>;

pub(crate) trait IntoRpcResult<T> {
    fn into_rpc(self) -> RpcCallResult<T>;
}

impl<T> IntoRpcResult<T> for crate::SnResult<T> {
    fn into_rpc(self) -> RpcCallResult<T> {
        self.map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))
    }
}

#[derive(Deserialize)]
pub(crate) struct NameReq {
    pub(crate) name: String,
}

#[derive(Deserialize)]
pub(crate) struct ActiveCodeReq {
    pub(crate) active_code: String,
}

#[derive(Deserialize)]
pub(crate) struct RegisterReq {
    pub(crate) name: String,
    pub(crate) pwd_hash: String,
    pub(crate) active_code: String,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
    #[serde(default)]
    pub(crate) asset_owner: Option<String>,
    #[serde(default)]
    pub(crate) owner_config: Option<Value>,
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    pub(crate) name: String,
    pub(crate) pwd_hash: String,
    #[serde(default)]
    pub(crate) active_code: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RefreshReq {
    pub(crate) refresh_token: String,
}

#[derive(Deserialize)]
pub(crate) struct BindOwnerKeyReq {
    pub(crate) public_key: Value,
}

#[derive(Deserialize)]
pub(crate) struct SetSelfCertReq {
    pub(crate) self_cert: bool,
    #[serde(default)]
    pub(crate) device_did: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct BindZoneReq {
    pub(crate) zone_config: String,
    #[serde(default)]
    pub(crate) boot_config: Option<String>,
    #[serde(default)]
    pub(crate) user_domain: Option<String>,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceRegisterReq {
    pub(crate) device_name: String,
    pub(crate) device_did: String,
    pub(crate) mini_config_jwt: String,
    pub(crate) device_ip: String,
    pub(crate) device_info: String,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceUpdateReq {
    pub(crate) device_name: String,
    #[serde(default)]
    pub(crate) device_did: Option<String>,
    #[serde(default)]
    pub(crate) mini_config_jwt: Option<String>,
    pub(crate) device_ip: String,
    pub(crate) device_info: String,
}

#[derive(Deserialize)]
pub(crate) struct DeviceGetReq {
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) device_name: String,
}

#[derive(Deserialize)]
pub(crate) struct QueryByPkReq {
    pub(crate) public_key: String,
}

#[derive(Deserialize)]
pub(crate) struct QueryByDidReq {
    pub(crate) source_device_id: String,
}

#[derive(Deserialize)]
pub(crate) struct QueryByHostnameReq {
    pub(crate) dest_host: String,
}

#[derive(Deserialize)]
pub(crate) struct AddDnsRecordReq {
    pub(crate) device_did: String,
    pub(crate) domain: String,
    pub(crate) record_type: String,
    pub(crate) record: String,
    #[serde(default)]
    pub(crate) ttl: Option<u32>,
    #[serde(default)]
    pub(crate) has_cert: Option<bool>,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RemoveDnsRecordReq {
    pub(crate) device_did: String,
    pub(crate) domain: String,
    pub(crate) record_type: String,
    #[serde(default)]
    pub(crate) record: Option<String>,
    #[serde(default)]
    pub(crate) has_cert: Option<bool>,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct SetDidDocumentReq {
    pub(crate) obj_name: String,
    #[serde(default)]
    pub(crate) did_document: Value,
    #[serde(default)]
    pub(crate) doc_type: Option<String>,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GetDidDocumentReq {
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) obj_name: String,
    #[serde(default)]
    pub(crate) doc_type: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ResolveDidReq {
    pub(crate) did: String,
    #[serde(default)]
    pub(crate) doc_type: Option<String>,
    #[serde(default)]
    #[serde(rename = "type")]
    pub(crate) legacy_type: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ResolveHostnameReq {
    pub(crate) host: String,
}

#[derive(Deserialize)]
pub(crate) struct ResolveDeviceReq {
    pub(crate) name: String,
    pub(crate) device_name: String,
}

pub(crate) fn parse_params<T>(req: &RPCRequest) -> RpcCallResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(req.params.clone()).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidParams,
            format!("{}: {}", req.method, e),
        )
    })
}

pub(crate) fn ok_response(req: &RPCRequest, value: Value) -> RpcCallResult<RPCResponse> {
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

pub(crate) fn normalize_username(username: &str) -> RpcCallResult<String> {
    let username = username.trim().to_lowercase();
    if username.is_empty() {
        return Err(parse_error(
            SnV2ErrorCode::InvalidUsername,
            "username is empty",
        ));
    }
    if SNServer::contains_special_chars(username.as_str()) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidUsername,
            "username contains special characters",
        ));
    }
    Ok(username)
}

pub(crate) fn normalize_public_key(public_key: Value) -> RpcCallResult<String> {
    match public_key {
        Value::String(s) => {
            let _: Jwk = serde_json::from_str(s.as_str()).map_err(|e| {
                parse_error(
                    SnV2ErrorCode::InvalidPublicKey,
                    format!("invalid public key string: {}", e),
                )
            })?;
            Ok(s)
        }
        Value::Object(_) => {
            let s = public_key.to_string();
            let _: Jwk = serde_json::from_str(s.as_str()).map_err(|e| {
                parse_error(
                    SnV2ErrorCode::InvalidPublicKey,
                    format!("invalid public key: {}", e),
                )
            })?;
            Ok(s)
        }
        _ => Err(parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            "public_key must be a JSON object or string",
        )),
    }
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn stable_request_id(
    provided: Option<String>,
    operation: &str,
    name: &str,
    payload: &Value,
) -> String {
    if let Some(request_id) = provided.filter(|value| !value.trim().is_empty()) {
        return request_id;
    }
    let mut hasher = Sha256::new();
    hasher.update(operation.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(payload.to_string().as_bytes());
    format!(
        "sn:v2:{}:{}:{}",
        operation,
        name,
        hex::encode(hasher.finalize())
    )
}

pub(crate) fn document_value_from_param(raw: &str, fallback_key: &str) -> Value {
    serde_json::from_str::<Value>(raw)
        .ok()
        .unwrap_or_else(|| json!({ fallback_key: raw }))
}

fn is_evm_address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub(crate) fn normalize_evm_address(value: &str, field: &str) -> RpcCallResult<String> {
    let value = value.trim();
    if is_evm_address(value) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(parse_error(
            SnV2ErrorCode::InvalidParams,
            format!("{field} must be a 0x-prefixed EVM address"),
        ))
    }
}

pub(crate) fn bns_default_asset_owner(controller: &SnBnsController) -> RpcCallResult<String> {
    let principal = &controller.config().sn_controller_principal;
    if principal.kind != PrincipalKind::ChainAccount {
        return Err(parse_error(
            SnV2ErrorCode::InvalidParams,
            "asset_owner is required when SN controller principal is not a chain account",
        ));
    }

    normalize_evm_address(principal.value.as_str(), "sn_controller_principal.value")
}

pub(crate) fn bns_managed_owner_authority(
    controller: &SnBnsController,
) -> RpcCallResult<CallAuthority> {
    let principal = &controller.config().sn_controller_principal;
    if principal.kind != PrincipalKind::ChainAccount || !is_evm_address(principal.value.as_str()) {
        return Err(parse_error(
            SnV2ErrorCode::AuthRequired,
            "managed BNS owner writes require an EVM chain-account SN controller principal",
        ));
    }
    Ok(controller.config().sn_managed_owner_authority())
}

pub(crate) fn build_profile_json(username: &str, user: &crate::SNUserInfo) -> Value {
    json!({
        "code": 0,
        "name": username,
        "owner_key_bound": !user.public_key.trim().is_empty(),
        "user_domain": user.user_domain.clone(),
        "self_cert": user.self_cert,
        "sn_ips": user.sn_ips.as_ref().and_then(|v| serde_json::from_str::<Value>(v).ok()).unwrap_or(Value::Null),
        "zone_config": user.zone_config.clone(),
    })
}

pub(crate) fn device_to_json(device: &crate::SNDeviceInfo) -> Value {
    json!({
        "code": 0,
        "owner": device.owner.clone(),
        "device_name": device.device_name.clone(),
        "mini_config_jwt": device.mini_config_jwt.clone(),
        "did": device.did.clone(),
        "ip": device.ip.clone(),
        "description": device.description.clone(),
        "created_at": device.created_at,
        "updated_at": device.updated_at,
    })
}

pub(crate) async fn query_by_did(
    compat_store: &SnCompatibilityStoreRef,
    auth_db: &SnAuthDBRef,
    did: &str,
) -> RpcCallResult<crate::OODInfo> {
    let device = compat_store
        .query_device_by_did(did)
        .await
        .into_rpc()?
        .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
    let user = auth_db
        .get_user_info(device.owner.as_str())
        .await
        .into_rpc()?;
    Ok(crate::OODInfo {
        did_hostname: device.did,
        owner_id: device.owner,
        self_cert: user.map(|u| u.self_cert).unwrap_or(false),
        state: "active".to_string(),
    })
}

pub(crate) async fn ensure_owned_device(
    compat_store: &SnCompatibilityStoreRef,
    username: &str,
    device_did: &str,
) -> RpcCallResult<crate::SNDeviceInfo> {
    let device = compat_store
        .query_device_by_did(device_did)
        .await
        .into_rpc()?
        .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
    if device.owner != username {
        return Err(parse_error(
            SnV2ErrorCode::DevicePermissionDenied,
            "device has no permission",
        ));
    }
    Ok(device)
}

pub(crate) fn ensure_owner_key_bound(user: &crate::SNUserInfo) -> RpcCallResult<()> {
    if user.public_key.trim().is_empty() {
        return Err(parse_error(
            SnV2ErrorCode::OwnerKeyRequired,
            "owner public key is not bound",
        ));
    }
    Ok(())
}

pub(crate) fn ensure_owner_decoding_key(user: &crate::SNUserInfo) -> RpcCallResult<DecodingKey> {
    ensure_owner_key_bound(user)?;
    let user_public_key: Jwk = serde_json::from_str(user.public_key.as_str()).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            format!("invalid user public key: {}", e),
        )
    })?;
    DecodingKey::from_jwk(&user_public_key).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            format!("decode public key failed: {}", e),
        )
    })
}

pub(crate) async fn require_account_username(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<String> {
    let context = crate::sn_authority::require_sn_user(server, req).await?;
    context
        .sn_username()
        .map(ToString::to_string)
        .ok_or_else(|| parse_error(SnV2ErrorCode::AuthRequired, "session token is not a user"))
}

pub(crate) async fn resolve_self_scoped_username(
    server: &SNServer,
    req: &RPCRequest,
    allow_anonymous_name: bool,
) -> RpcCallResult<String> {
    let requested_name = req
        .params
        .get("name")
        .and_then(|value| value.as_str())
        .map(normalize_username)
        .transpose()?;

    match req.token.as_ref() {
        Some(_) => {
            let username = require_account_username(server, req).await?;
            if let Some(requested_name) = requested_name {
                if requested_name != username {
                    return Err(parse_error(
                        SnV2ErrorCode::CrossUserAccessDenied,
                        "cross-user access is not allowed",
                    ));
                }
            }
            Ok(username)
        }
        None if allow_anonymous_name => requested_name.ok_or_else(|| {
            parse_error(
                SnV2ErrorCode::InvalidParams,
                "name is required when token is absent",
            )
        }),
        None => Err(parse_error(
            SnV2ErrorCode::AuthRequired,
            "session_token is none",
        )),
    }
}
