use super::common::{
    build_profile_json, hash_password, normalize_username, now_secs, ok_response, parse_params,
    require_account_username, verify_password, ActiveCodeReq, IntoRpcResult, LoginReq, NameReq,
    PASSWORD_ALGO, RefreshReq, RegisterReq, RpcCallResult,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCRequest, RPCResponse, RPCErrors};
use serde_json::json;

fn build_auth_success_response(
    server: &SNServer,
    req: &RPCRequest,
    username: &str,
    need_bind_owner_key: bool,
) -> RpcCallResult<RPCResponse> {
    let access_token = server.v2_auth().issue_access_token(username)?;
    let refresh_token = server.v2_auth().issue_refresh_token(username)?;
    ok_response(
        req,
        json!({
            "code": 0,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "need_bind_owner_key": need_bind_owner_key
        }),
    )
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
            SNServer::validate_registration_username(username.as_str()).map_err(|message| {
                parse_error(SnV2ErrorCode::InvalidUsername, message)
            })?;
            if server.db().is_user_exist(username.as_str()).await.into_rpc()?
                || server.db().get_v2_auth(username.as_str()).await.into_rpc()?.is_some()
            {
                return Err(parse_error(
                    SnV2ErrorCode::UsernameAlreadyExists,
                    format!("username {} already exists", username),
                ));
            }
            let (password_hash, password_salt) = hash_password(params.pwd_hash.as_str())?;
            let ok = server
                .db()
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
            build_auth_success_response(server, &req, username.as_str(), true)
        }
        "login" => {
            let params: LoginReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            let auth = server
                .db()
                .get_v2_auth(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::UserAuthNotFound, "user auth not found")
                })?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::UserNotActivated, "user not activated")
                })?;
            if user.activation_code.as_deref() != Some(params.active_code.as_str()) {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidActiveCode,
                    "invalid active code",
                ));
            }
            if !verify_password(params.pwd_hash.as_str(), &auth)? {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidPassword,
                    "invalid password",
                ));
            }
            server
                .db()
                .update_v2_last_login(username.as_str(), now_secs())
                .await
                .into_rpc()?;
            build_auth_success_response(
                server,
                &req,
                username.as_str(),
                user.public_key.trim().is_empty(),
            )
        }
        "refresh" => {
            let params: RefreshReq = parse_params(&req)?;
            let username = server
                .v2_auth()
                .verify_refresh_token(params.refresh_token.as_str())?;
            let access_token = server.v2_auth().issue_access_token(username.as_str())?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "access_token": access_token,
                }),
            )
        }
        "logout" => ok_response(&req, json!({ "code": 0 })),
        "me" => {
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            ok_response(&req, build_profile_json(username.as_str(), &user))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
