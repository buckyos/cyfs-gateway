use super::common::{
    build_profile_json, normalize_public_key, ok_response, parse_params,
    require_account_username, BindOwnerKeyReq, IntoRpcResult, RpcCallResult, SetSelfCertReq,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCRequest, RPCResponse, RPCErrors};
use jsonwebtoken::{jwk::Jwk, DecodingKey};
use serde_json::{json, Value};

pub(crate) async fn handle_user(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "bind_owner_key" => {
            let username = require_account_username(server, &req)?;
            let params: BindOwnerKeyReq = parse_params(&req)?;
            let public_key_str = normalize_public_key(params.public_key)?;
            let public_key_jwk: Jwk = serde_json::from_str(public_key_str.as_str())
                .map_err(|e| {
                    parse_error(
                        SnV2ErrorCode::InvalidPublicKey,
                        format!("invalid public key: {}", e),
                    )
                })?;
            let _ = DecodingKey::from_jwk(&public_key_jwk)
                .map_err(|e| {
                    parse_error(
                        SnV2ErrorCode::InvalidPublicKey,
                        format!("invalid public key: {}", e),
                    )
                })?;
            server
                .db()
                .update_user_public_key(username.as_str(), public_key_str.as_str())
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0 }))
        }
        "get_owner_key" => {
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let public_key_value = if user.public_key.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str::<Value>(user.public_key.as_str())
                    .unwrap_or_else(|_| Value::String(user.public_key.clone()))
            };
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "public_key": public_key_value
                }),
            )
        }
        "set_self_cert" => {
            let username = require_account_username(server, &req)?;
            let params: SetSelfCertReq = parse_params(&req)?;
            server
                .db()
                .update_user_self_cert(username.as_str(), params.self_cert)
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0 }))
        }
        "get_profile" => {
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
