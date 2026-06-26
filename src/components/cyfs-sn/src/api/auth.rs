use super::common::{
    build_profile_json, normalize_username, now_secs, ok_response, parse_params,
    require_account_username, ActiveCodeReq, IntoRpcResult, LoginReq, NameReq, RefreshReq,
    RegisterReq, RpcCallResult,
};
use super::errors::{bns_write_error, parse_error, SnV2ErrorCode};
use crate::sn_v2_auth::{hash_password, verify_password, PASSWORD_ALGO};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::BootstrapNameParams;
use bns_indexer::{CallAuthority, MutationGuard, RegisterOptions};
use serde_json::{json, Value};

async fn build_auth_success_response(
    server: &SNServer,
    req: &RPCRequest,
    username: &str,
    need_bind_owner_key: bool,
) -> RpcCallResult<RPCResponse> {
    let access_token = server.v2_auth().issue_access_session(username)?;
    let refresh_token = server.v2_auth().issue_refresh_session(username)?;
    server
        .auth_db()
        .create_account_session(
            access_token.session_id.as_str(),
            username,
            access_token.token_aud.as_str(),
            access_token.issued_at,
            access_token.expires_at,
        )
        .await
        .into_rpc()?;
    server
        .auth_db()
        .create_account_session(
            refresh_token.session_id.as_str(),
            username,
            refresh_token.token_aud.as_str(),
            refresh_token.issued_at,
            refresh_token.expires_at,
        )
        .await
        .into_rpc()?;
    ok_response(
        req,
        json!({
            "code": 0,
            "access_token": access_token.token,
            "refresh_token": refresh_token.token,
            "need_bind_owner_key": need_bind_owner_key
        }),
    )
}

fn default_owner_config(username: &str) -> Value {
    json!({
        "name": username,
        "created_by": "cyfs-sn",
        "created_at": now_secs(),
    })
}

pub(crate) async fn handle_auth(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "check_username" => {
            let params: NameReq = parse_params(&req)?;
            let proxy_req = RPCRequest {
                params: json!({ "username": params.name }),
                ..req
            };
            server.check_username(proxy_req).await
        }
        "check_active_code" => {
            let params: ActiveCodeReq = parse_params(&req)?;
            let proxy_req = RPCRequest {
                params: json!({ "active_code": params.active_code }),
                ..req
            };
            server.check_active_code(proxy_req).await
        }
        "register" => {
            let params: RegisterReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            SNServer::validate_registration_username(username.as_str())
                .map_err(|message| parse_error(SnV2ErrorCode::InvalidUsername, message))?;
            if server
                .auth_db()
                .is_user_exist(username.as_str())
                .await
                .into_rpc()?
                || server
                    .auth_db()
                    .get_v2_auth(username.as_str())
                    .await
                    .into_rpc()?
                    .is_some()
            {
                return Err(parse_error(
                    SnV2ErrorCode::UsernameAlreadyExists,
                    format!("username {} already exists", username),
                ));
            }
            if !server
                .auth_db()
                .check_active_code(params.active_code.as_str())
                .await
                .into_rpc()?
            {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            let (password_hash, password_salt) = hash_password(params.pwd_hash.as_str())?;
            let need_bind_owner_key = server.bns_controller().is_none();
            if let Some(controller) = server.bns_controller() {
                controller
                    .bootstrap_name(BootstrapNameParams {
                        request_id: params
                            .request_id
                            .clone()
                            .unwrap_or_else(|| format!("sn:v2:register:{}", username)),
                        name: username.clone(),
                        asset_owner: params
                            .asset_owner
                            .clone()
                            .unwrap_or_else(|| username.clone()),
                        register_options: RegisterOptions {
                            ..RegisterOptions::default()
                        },
                        owner_config: params
                            .owner_config
                            .clone()
                            .unwrap_or_else(|| default_owner_config(username.as_str())),
                        owner_authority_keys: Vec::new(),
                        semantic_owner_after_authority: None,
                        initial_documents: Vec::new(),
                        authority: CallAuthority::public(),
                        guard: MutationGuard::default(),
                    })
                    .await
                    .map_err(bns_write_error)?;
            }
            let ok = server
                .auth_db()
                .register_user_v2(
                    params.active_code.as_str(),
                    username.as_str(),
                    password_hash.as_str(),
                    password_salt.as_str(),
                    PASSWORD_ALGO,
                )
                .await
                .into_rpc()?;
            if !ok {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            build_auth_success_response(server, &req, username.as_str(), need_bind_owner_key).await
        }
        "login" => {
            let params: LoginReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            let auth = server
                .auth_db()
                .get_v2_auth(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::UserAuthNotFound, "user auth not found")
                })?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::UserNotActivated, "user not activated")
                })?;
            if !matches!(user.state, crate::UserState::Active) {
                return Err(parse_error(
                    SnV2ErrorCode::UserNotActivated,
                    "user is not active",
                ));
            }
            if !verify_password(params.pwd_hash.as_str(), &auth)? {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidPassword,
                    "invalid password",
                ));
            }
            server
                .auth_db()
                .update_v2_last_login(username.as_str(), now_secs())
                .await
                .into_rpc()?;
            build_auth_success_response(
                server,
                &req,
                username.as_str(),
                server.bns_controller().is_none() && user.public_key.trim().is_empty(),
            )
            .await
        }
        "refresh" => {
            let params: RefreshReq = parse_params(&req)?;
            let refresh_session = server
                .v2_auth()
                .verify_refresh_session(params.refresh_token.as_str())?;
            crate::sn_authority::validate_refresh_session(
                server,
                &refresh_session,
                params.refresh_token.as_str(),
            )
            .await?;
            let username = refresh_session
                .sub
                .ok_or_else(|| parse_error(SnV2ErrorCode::InvalidToken, "subject is none"))?;
            let access_token = server.v2_auth().issue_access_session(username.as_str())?;
            server
                .auth_db()
                .create_account_session(
                    access_token.session_id.as_str(),
                    username.as_str(),
                    access_token.token_aud.as_str(),
                    access_token.issued_at,
                    access_token.expires_at,
                )
                .await
                .into_rpc()?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "access_token": access_token.token,
                }),
            )
        }
        "logout" => {
            if let Some(token) = req.token.as_deref() {
                if let Ok(session) = server.v2_auth().verify_access_session(token) {
                    if let Some(session_id) = crate::sn_authority::session_id(&session, token) {
                        server
                            .auth_db()
                            .revoke_account_session(session_id.as_str(), now_secs())
                            .await
                            .into_rpc()?;
                    }
                }
            }
            if let Some(refresh_token) = req
                .params
                .get("refresh_token")
                .and_then(|value| value.as_str())
            {
                if let Ok(session) = server.v2_auth().verify_refresh_session(refresh_token) {
                    if let Some(session_id) =
                        crate::sn_authority::session_id(&session, refresh_token)
                    {
                        server
                            .auth_db()
                            .revoke_account_session(session_id.as_str(), now_secs())
                            .await
                            .into_rpc()?;
                    }
                }
            }
            ok_response(&req, json!({ "code": 0 }))
        }
        "me" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            ok_response(&req, build_profile_json(username.as_str(), &user))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
