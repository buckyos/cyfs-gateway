use crate::{SnDBRef, SnV2AuthInfo, SNServer};
use ::kRPC::*;
use buckyos_kit::get_buckyos_service_data_dir;
use jsonwebtoken::{jwk::Jwk, DecodingKey, EncodingKey};
use name_lib::{generate_ed25519_key_pair, load_private_key};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use serde::Deserialize;
use serde_json::{json, Value};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::{parse_error, reason_error, SnV2ErrorCode};

const V2_ACCESS_AUD: &str = "sn-v2";
const V2_REFRESH_AUD: &str = "sn-v2-refresh";
const V2_ACCESS_TOKEN_EXPIRE_SECS: u64 = 60 * 60;
const V2_REFRESH_TOKEN_EXPIRE_SECS: u64 = 60 * 60 * 24;
pub(crate) const PASSWORD_ALGO: &str = "pbkdf2-sha256-100000";
const PASSWORD_ITERATIONS: u32 = 100_000;

pub(crate) type RpcCallResult<T> = std::result::Result<T, RPCErrors>;

pub(crate) trait IntoRpcResult<T> {
    fn into_rpc(self) -> RpcCallResult<T>;
}

impl<T> IntoRpcResult<T> for crate::SnResult<T> {
    fn into_rpc(self) -> RpcCallResult<T> {
        self.map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))
    }
}

#[derive(Clone)]
pub(crate) struct SnV2AuthManager {
    token_encode_key: EncodingKey,
    token_decode_key: DecodingKey,
}

impl SnV2AuthManager {
    pub(crate) async fn new(configured_dir: Option<&str>) -> std::result::Result<Self, String> {
        let data_dir = resolve_v2_auth_dir(configured_dir);
        std::fs::create_dir_all(&data_dir).map_err(|e| {
            format!(
                "failed to create sn v2 auth dir {}: {}",
                data_dir.display(),
                e
            )
        })?;

        let private_key = data_dir.join("private_key.pem");
        let public_key = data_dir.join("public_key.json");
        let (encode_key, decode_key) = if private_key.exists() && public_key.exists() {
            let encode_key =
                load_private_key(private_key.as_path()).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(public_key.as_path())
                .map_err(|e| format!("read public key failed: {}", e))?;
            let public_key: Jwk = serde_json::from_str(public_key.as_str())
                .map_err(|e| format!("parse public key failed: {}", e))?;
            let decode_key =
                DecodingKey::from_jwk(&public_key).map_err(|e| format!("decode key: {}", e))?;
            (encode_key, decode_key)
        } else {
            let (sign_key, public_key_value) = generate_ed25519_key_pair();
            std::fs::write(private_key.as_path(), sign_key.as_bytes())
                .map_err(|e| format!("write private key failed: {}", e))?;
            std::fs::write(
                public_key.as_path(),
                serde_json::to_string(&public_key_value).unwrap(),
            )
            .map_err(|e| format!("write public key failed: {}", e))?;
            let jwk = serde_json::from_value::<Jwk>(public_key_value)
                .map_err(|e| format!("parse generated jwk failed: {}", e))?;
            let encode_key = load_private_key(private_key.as_path()).map_err(|e| e.to_string())?;
            let decode_key =
                DecodingKey::from_jwk(&jwk).map_err(|e| format!("decode key: {}", e))?;
            (encode_key, decode_key)
        };

        Ok(Self {
            token_encode_key: encode_key,
            token_decode_key: decode_key,
        })
    }

    pub(crate) fn issue_access_token(&self, username: &str) -> RpcCallResult<String> {
        issue_rpc_jwt(
            username,
            V2_ACCESS_AUD,
            V2_ACCESS_TOKEN_EXPIRE_SECS,
            &self.token_encode_key,
        )
    }

    pub(crate) fn issue_refresh_token(&self, username: &str) -> RpcCallResult<String> {
        issue_rpc_jwt(
            username,
            V2_REFRESH_AUD,
            V2_REFRESH_TOKEN_EXPIRE_SECS,
            &self.token_encode_key,
        )
    }

    pub(crate) fn verify_access_token(&self, token: &str) -> RpcCallResult<String> {
        verify_rpc_jwt(token, V2_ACCESS_AUD, &self.token_decode_key)
    }

    pub(crate) fn verify_refresh_token(&self, token: &str) -> RpcCallResult<String> {
        verify_rpc_jwt(token, V2_REFRESH_AUD, &self.token_decode_key)
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
    pub(crate) active_code: String,
    pub(crate) pwd: String,
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    pub(crate) name: String,
    pub(crate) pwd: String,
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
}

#[derive(Deserialize)]
pub(crate) struct BindZoneReq {
    pub(crate) zone_config: String,
    #[serde(default)]
    pub(crate) user_domain: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DeviceRegisterReq {
    pub(crate) device_name: String,
    pub(crate) device_did: String,
    pub(crate) mini_config_jwt: String,
    pub(crate) device_ip: String,
    pub(crate) device_info: String,
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
}

#[derive(Deserialize)]
pub(crate) struct RemoveDnsRecordReq {
    pub(crate) device_did: String,
    pub(crate) domain: String,
    pub(crate) record_type: String,
    #[serde(default)]
    pub(crate) has_cert: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct SetDidDocumentReq {
    pub(crate) obj_name: String,
    #[serde(default)]
    pub(crate) did_document: Value,
    #[serde(default)]
    pub(crate) doc_type: Option<String>,
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
    serde_json::from_value(req.params.clone())
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidParams, format!("{}: {}", req.method, e)))
}

pub(crate) fn ok_response(req: &RPCRequest, value: Value) -> RpcCallResult<RPCResponse> {
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

fn resolve_v2_auth_dir(configured_dir: Option<&str>) -> PathBuf {
    if let Some(path) = configured_dir {
        let configured = PathBuf::from(path);
        if configured.is_absolute() {
            return configured;
        }
        return std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(configured);
    }
    get_buckyos_service_data_dir("cyfs_gateway").join("sn_v2_token_key")
}

fn issue_rpc_jwt(
    username: &str,
    aud: &str,
    expire_secs: u64,
    key: &EncodingKey,
) -> RpcCallResult<String> {
    let (_, mut session) =
        RPCSessionToken::generate_jwt_token(username, aud, None, key).map_err(|e| {
            reason_error(
                SnV2ErrorCode::InternalError,
                format!("generate jwt token failed: {}", e),
            )
        })?;
    session.aud = Some(aud.to_string());
    session.exp = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + expire_secs,
    );
    session
        .generate_jwt(None, key)
        .map(|jwt| jwt.to_string())
        .map_err(|e| {
            reason_error(
                SnV2ErrorCode::InternalError,
                format!("generate jwt token failed: {}", e),
            )
        })
}

fn verify_rpc_jwt(token: &str, expected_aud: &str, key: &DecodingKey) -> RpcCallResult<String> {
    let mut session = RPCSessionToken::from_string(token)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    session
        .verify_by_key(key)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    if session.aud.as_deref() != Some(expected_aud) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            format!("invalid aud {:?}, expect {}", session.aud, expected_aud),
        ));
    }
    session
        .sub
        .ok_or_else(|| parse_error(SnV2ErrorCode::InvalidToken, "subject is none"))
}

pub(crate) fn hash_password(password: &str) -> RpcCallResult<(String, String)> {
    let salt = rand::random::<[u8; 16]>();
    let salt_hex = hex::encode(salt);
    let password_hash = derive_password_hash(password, salt_hex.as_str())?;
    Ok((password_hash, salt_hex))
}

pub(crate) fn verify_password(password: &str, auth: &SnV2AuthInfo) -> RpcCallResult<bool> {
    if auth.password_algo != PASSWORD_ALGO {
        return Err(reason_error(
            SnV2ErrorCode::UnsupportedPasswordAlgo,
            format!("unsupported password algo {}", auth.password_algo),
        ));
    }
    let salt = hex::decode(auth.password_salt.as_str())
        .map_err(|e| reason_error(SnV2ErrorCode::InvalidPasswordStorage, format!("invalid password salt: {}", e)))?;
    let expected = hex::decode(auth.password_hash.as_str())
        .map_err(|e| reason_error(SnV2ErrorCode::InvalidPasswordStorage, format!("invalid password hash: {}", e)))?;
    Ok(pbkdf2::verify(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &expected,
    )
    .is_ok())
}

fn derive_password_hash(password: &str, salt_hex: &str) -> RpcCallResult<String> {
    let salt = hex::decode(salt_hex)
        .map_err(|e| reason_error(SnV2ErrorCode::InvalidPasswordStorage, format!("invalid password salt: {}", e)))?;
    let mut hash = [0u8; 32];
    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Ok(hex::encode(hash))
}

pub(crate) fn normalize_username(username: &str) -> RpcCallResult<String> {
    let username = username.trim().to_lowercase();
    if username.is_empty() {
        return Err(parse_error(SnV2ErrorCode::InvalidUsername, "username is empty"));
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
            let _: Jwk = serde_json::from_str(s.as_str())
                .map_err(|e| {
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

pub(crate) async fn query_by_did(db: &SnDBRef, did: &str) -> RpcCallResult<crate::OODInfo> {
    let device = db
        .query_device_by_did(did)
        .await
        .into_rpc()?
        .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
    let user = db.get_user_info(device.owner.as_str()).await.into_rpc()?;
    Ok(crate::OODInfo {
        did_hostname: device.did,
        owner_id: device.owner,
        self_cert: user.map(|u| u.self_cert).unwrap_or(false),
        state: "active".to_string(),
    })
}

pub(crate) async fn ensure_owned_device(
    db: &SnDBRef,
    username: &str,
    device_did: &str,
) -> RpcCallResult<crate::SNDeviceInfo> {
    let device = db
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
    let user_public_key: Jwk = serde_json::from_str(user.public_key.as_str())
        .map_err(|e| {
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

pub(crate) fn require_account_username(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<String> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnV2ErrorCode::AuthRequired, "session_token is none"))?;
    server.v2_auth().verify_access_token(token.as_str())
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
        Some(token) => {
            let username = server.v2_auth().verify_access_token(token.as_str())?;
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
