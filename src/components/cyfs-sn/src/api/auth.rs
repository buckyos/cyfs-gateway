use super::common::{
    build_profile_json, normalize_evm_address, normalize_username, now_secs, ok_response,
    parse_params, require_account_username, ActiveCodeReq, IntoRpcResult, LoginReq, NameReq,
    RefreshReq, RegisterReq, RpcCallResult,
};
use super::errors::{bns_proxy_error, parse_error, reason_error, SnApiErrorCode};
use crate::sn_auth_manager::{hash_password, verify_password, PASSWORD_ALGO};
use crate::sn_bns_proxy::SnBnsProxyRegisterParams;
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::{json, Value};

async fn build_auth_success_response(
    server: &SNServer,
    req: &RPCRequest,
    username: &str,
    need_bind_owner_key: bool,
    bns: Option<Value>,
) -> RpcCallResult<RPCResponse> {
    let access_token = server.auth().issue_access_session(username)?;
    let refresh_token = server.auth().issue_refresh_session(username)?;
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
    let mut response = json!({
        "code": 0,
        "access_token": access_token.token,
        "refresh_token": refresh_token.token,
        "need_bind_owner_key": need_bind_owner_key
    });
    if let Some(bns) = bns {
        response["bns"] = bns;
    }
    ok_response(req, response)
}

pub(crate) fn default_owner_config(username: &str) -> Value {
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
            let username = params.name.trim().to_lowercase();
            let (valid, reason, message) =
                if let Err(message) = SNServer::validate_registration_username(username.as_str()) {
                    (false, "invalid_username".to_string(), message)
                } else {
                    let exists = server
                        .auth_db()
                        .is_user_exist(username.as_str())
                        .await
                        .into_rpc()?;
                    if exists {
                        (
                            false,
                            "already_exists".to_string(),
                            format!("username {} already exists", username),
                        )
                    } else {
                        (true, "ok".to_string(), String::new())
                    }
                };

            ok_response(
                &req,
                json!({
                    "valid": valid,
                    "reason": reason,
                    "message": message,
                    "normalized_name": username,
                }),
            )
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
                .map_err(|message| parse_error(SnApiErrorCode::InvalidUsername, message))?;
            let email = crate::canonical_email(params.email.as_str())
                .map_err(|error| parse_error(SnApiErrorCode::InvalidEmail, error.msg()))?;
            // 锁覆盖预查、可选 BNS bootstrap 和本地事务，避免同进程并发请求
            // 在邮箱冲突已知前产生两次外部注册副作用。SQLite UNIQUE 索引仍兜底。
            let _email_locker = async_named_locker::Locker::get_locker(format!(
                "sn_auth_register_email_{}",
                email
            ))
            .await;
            if server
                .auth_db()
                .is_user_exist(username.as_str())
                .await
                .into_rpc()?
                || server
                    .auth_db()
                    .get_auth(username.as_str())
                    .await
                    .into_rpc()?
                    .is_some()
            {
                return Err(parse_error(
                    SnApiErrorCode::UsernameAlreadyExists,
                    format!("username {} already exists", username),
                ));
            }
            if server
                .auth_db()
                .get_user_by_email(email.as_str())
                .await
                .into_rpc()?
                .is_some()
            {
                return Err(parse_error(
                    SnApiErrorCode::EmailAlreadyBound,
                    "email is already bound to another account",
                ));
            }
            if !server
                .auth_db()
                .check_active_code(params.active_code.as_str())
                .await
                .into_rpc()?
            {
                return Err(parse_error(
                    SnApiErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            let (password_hash, password_salt) = hash_password(params.pwd_hash.as_str())?;
            let need_bind_owner_key = server.bns_proxy().is_none();
            // BNS bootstrap 在本地建号之前执行：失败则不创建本地用户，避免
            // 本地账号与 BNS name 不一致（同 request_id 重试幂等）。
            let mut bns_info: Option<Value> = None;
            if let Some(proxy) = server.bns_proxy() {
                let asset_owner = match params.asset_owner.as_deref() {
                    Some(value) => normalize_evm_address(value, "asset_owner")?,
                    None if proxy.require_user_asset_owner() => {
                        return Err(parse_error(
                            SnApiErrorCode::InvalidParams,
                            "asset_owner is required: upload the user's owner EVM address",
                        ));
                    }
                    // devtest 回落：使用该用户绑定 controller 的地址。
                    None => proxy
                        .default_asset_owner_for_user(username.as_str())
                        .await
                        .map_err(bns_proxy_error)?,
                };
                let outcome = proxy
                    .register_bootstrap(SnBnsProxyRegisterParams {
                        request_id: params
                            .request_id
                            .clone()
                            .unwrap_or_else(|| format!("sn:register:{}", username)),
                        name: username.clone(),
                        asset_owner,
                        owner_config: params
                            .owner_config
                            .clone()
                            .unwrap_or_else(|| default_owner_config(username.as_str())),
                        initial_documents: params.initial_documents.clone().unwrap_or_default(),
                    })
                    .await
                    .map_err(bns_proxy_error)?;
                server.invalidate_bns_name_dns_cache(username.as_str());
                bns_info = Some(outcome.to_bns_json());
            }
            let ok = server
                .auth_db()
                .register_user(
                    params.active_code.as_str(),
                    username.as_str(),
                    email.as_str(),
                    password_hash.as_str(),
                    password_salt.as_str(),
                    PASSWORD_ALGO,
                )
                .await
                .map_err(|error| {
                    if error.code() == crate::SnErrorCode::Conflict
                        && error.msg().starts_with("email already bound:")
                    {
                        parse_error(
                            SnApiErrorCode::EmailAlreadyBound,
                            "email is already bound to another account",
                        )
                    } else {
                        reason_error(SnApiErrorCode::InternalError, error.to_string())
                    }
                })?;
            if !ok {
                return Err(parse_error(
                    SnApiErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            build_auth_success_response(
                server,
                &req,
                username.as_str(),
                need_bind_owner_key,
                bns_info,
            )
            .await
        }
        "login" => {
            let params: LoginReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            let auth = server
                .auth_db()
                .get_auth(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnApiErrorCode::UserAuthNotFound, "user auth not found")
                })?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnApiErrorCode::UserNotActivated, "user not activated")
                })?;
            if !matches!(user.state, crate::UserState::Active) {
                return Err(parse_error(
                    SnApiErrorCode::UserNotActivated,
                    "user is not active",
                ));
            }
            if !verify_password(params.pwd_hash.as_str(), &auth)? {
                return Err(parse_error(
                    SnApiErrorCode::InvalidPassword,
                    "invalid password",
                ));
            }
            server
                .auth_db()
                .update_last_login(username.as_str(), now_secs())
                .await
                .into_rpc()?;
            build_auth_success_response(
                server,
                &req,
                username.as_str(),
                server.bns_proxy().is_none() && user.public_key.trim().is_empty(),
                None,
            )
            .await
        }
        "refresh" => {
            let params: RefreshReq = parse_params(&req)?;
            let refresh_session = server
                .auth()
                .verify_refresh_session(params.refresh_token.as_str())?;
            crate::sn_authority::validate_refresh_session(
                server,
                &refresh_session,
                params.refresh_token.as_str(),
            )
            .await?;
            let username = refresh_session
                .sub
                .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "subject is none"))?;
            let access_token = server.auth().issue_access_session(username.as_str())?;
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
                if let Ok(session) = server.auth().verify_access_session(token) {
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
                if let Ok(session) = server.auth().verify_refresh_session(refresh_token) {
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
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            ok_response(&req, build_profile_json(username.as_str(), &user))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
