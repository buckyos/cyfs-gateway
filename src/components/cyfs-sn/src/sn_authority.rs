use crate::api::{parse_error, reason_error, RpcCallResult, SnV2ErrorCode};
use crate::SNServer;
use kRPC::{RPCRequest, RPCSessionToken};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum AuthContext {
    SnUser {
        username: String,
        session_id: Option<String>,
    },
}

impl AuthContext {
    pub(crate) fn sn_username(&self) -> Option<&str> {
        match self {
            Self::SnUser { username, .. } => Some(username),
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
