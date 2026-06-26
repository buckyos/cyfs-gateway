use crate::api::{parse_error, reason_error, RpcCallResult, SnV2ErrorCode};
use crate::SNServer;
use bns_indexer::{CallAuthority, Principal};
use jsonwebtoken::{jwk::Jwk, DecodingKey};
use kRPC::{RPCRequest, RPCSessionToken};
use name_lib::DID;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum AuthContext {
    Owner {
        name: String,
        principal: Principal,
        kid: String,
    },
    Controller {
        name: String,
        doc_type_scope: Vec<String>,
        principal: Principal,
        kid: String,
    },
    Device {
        zone: String,
        device_name: String,
        did: String,
    },
    SnUser {
        username: String,
        session_id: Option<String>,
    },
}

impl AuthContext {
    pub(crate) fn sn_username(&self) -> Option<&str> {
        match self {
            Self::SnUser { username, .. } => Some(username),
            _ => None,
        }
    }

    pub(crate) fn to_call_authority(&self) -> Option<CallAuthority> {
        match self {
            Self::Owner { principal, kid, .. } => {
                Some(CallAuthority::owner(principal.clone(), kid.clone()))
            }
            Self::Controller { principal, kid, .. } => {
                Some(CallAuthority::controller(principal.clone(), kid.clone()))
            }
            Self::SnUser { username, .. } => {
                Some(CallAuthority::owner(Principal::chain_account(username), ""))
            }
            _ => None,
        }
    }
}

pub(crate) async fn require_sn_user(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<AuthContext> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnV2ErrorCode::AuthRequired, "session_token is none"))?;
    let session = server.v2_auth().verify_access_session(token.as_str())?;
    validate_account_session(server, &session, token.as_str()).await?;
    let username = session
        .sub
        .clone()
        .ok_or_else(|| parse_error(SnV2ErrorCode::InvalidToken, "subject is none"))?;
    Ok(AuthContext::SnUser {
        username,
        session_id: session_id(&session, token.as_str()),
    })
}

pub(crate) async fn require_owner_for_name(
    server: &SNServer,
    req: &RPCRequest,
    name: &str,
) -> RpcCallResult<AuthContext> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnV2ErrorCode::AuthRequired, "session_token is none"))?;

    if let Ok(session) = verify_owner_key_token(server, token.as_str(), name).await {
        return Ok(session);
    }

    let context = require_sn_user(server, req).await?;
    match context {
        AuthContext::SnUser {
            username,
            session_id,
        } if username == name => Ok(AuthContext::Owner {
            name: username,
            principal: Principal::chain_account(name),
            kid: session_id.unwrap_or_default(),
        }),
        AuthContext::SnUser { .. } => Err(parse_error(
            SnV2ErrorCode::CrossUserAccessDenied,
            "cross-user access is not allowed",
        )),
        other => Ok(other),
    }
}

pub(crate) async fn require_device(
    server: &SNServer,
    token: &str,
    zone: &str,
    device_name: &str,
) -> RpcCallResult<AuthContext> {
    let device = server
        .compat_store()
        .query_device_by_name(zone, device_name)
        .await
        .map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))?
        .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
    let did = DID::from_str(device.did.as_str()).map_err(|_| {
        parse_error(
            SnV2ErrorCode::InvalidDeviceDid,
            "stored device did is invalid",
        )
    })?;
    let verify_public_key = DecodingKey::from_ed_components(did.id.as_str()).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            format!("decode device public key failed: {}", e),
        )
    })?;
    let mut session = RPCSessionToken::from_string(token)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    session
        .verify_by_key(&verify_public_key)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    if session.sub.as_deref() != Some(device_name) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            "device token subject mismatch",
        ));
    }

    Ok(AuthContext::Device {
        zone: zone.to_string(),
        device_name: device_name.to_string(),
        did: device.did,
    })
}

pub(crate) fn session_id(session: &RPCSessionToken, token: &str) -> Option<String> {
    session.jti.clone().or_else(|| {
        if token.trim().is_empty() {
            None
        } else {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            Some(hex::encode(hasher.finalize()))
        }
    })
}

async fn verify_owner_key_token(
    server: &SNServer,
    token: &str,
    name: &str,
) -> RpcCallResult<AuthContext> {
    let user = server
        .auth_db()
        .get_user_info(name)
        .await
        .map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))?
        .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
    if user.public_key.trim().is_empty() {
        return Err(parse_error(
            SnV2ErrorCode::OwnerKeyRequired,
            "owner public key is not bound",
        ));
    }

    let user_public_key: Jwk = serde_json::from_str(user.public_key.as_str()).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            format!("invalid owner public key: {}", e),
        )
    })?;
    let verify_public_key = DecodingKey::from_jwk(&user_public_key).map_err(|e| {
        parse_error(
            SnV2ErrorCode::InvalidPublicKey,
            format!("decode owner public key failed: {}", e),
        )
    })?;
    let mut session = RPCSessionToken::from_string(token)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    session
        .verify_by_key(&verify_public_key)
        .map_err(|e| parse_error(SnV2ErrorCode::InvalidToken, e.to_string()))?;
    if session.aud.as_deref() != Some("sn") {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            "invalid owner token audience",
        ));
    }
    if session.sub.as_deref() != Some(name) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            "owner token subject mismatch",
        ));
    }

    Ok(AuthContext::Owner {
        name: name.to_string(),
        principal: Principal::chain_account(name),
        kid: session_id(&session, token).unwrap_or_default(),
    })
}

async fn validate_account_session(
    server: &SNServer,
    session: &RPCSessionToken,
    token: &str,
) -> RpcCallResult<()> {
    let Some(session_id) = session_id(session, token) else {
        return Ok(());
    };
    let Some(stored) = server
        .auth_db()
        .get_account_session(session_id.as_str())
        .await
        .map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))?
    else {
        return Ok(());
    };

    if stored.state != "active" {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            "session has been revoked",
        ));
    }
    if stored.expires_at < now_secs() {
        return Err(parse_error(SnV2ErrorCode::InvalidToken, "session expired"));
    }
    if session.sub.as_deref() != Some(stored.username.as_str()) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidToken,
            "session subject mismatch",
        ));
    }

    Ok(())
}

pub(crate) async fn validate_refresh_session(
    server: &SNServer,
    session: &RPCSessionToken,
    token: &str,
) -> RpcCallResult<()> {
    validate_account_session(server, session, token).await
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
