use super::common::{
    ensure_owner_key_bound, ok_response, parse_params, require_account_username,
    resolve_self_scoped_username, BindZoneReq, IntoRpcResult, RpcCallResult,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::json;

pub(crate) async fn handle_zone(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "get" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "user_name": username,
                    "boot": user.zone_config,
                    "user_domain": user.user_domain,
                    "self_cert": user.self_cert,
                }),
            )
        }
        "bind_config" => {
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            ensure_owner_key_bound(&user)?;
            let params: BindZoneReq = parse_params(&req)?;
            server
                .db()
                .update_user_zone_config(username.as_str(), params.zone_config.as_str())
                .await
                .into_rpc()?;
            if let Some(user_domain) = params.user_domain {
                server
                    .db()
                    .update_user_domain(username.as_str(), Some(user_domain))
                    .await
                    .into_rpc()?;
            }
            server.invalidate_query_cache_for_username(username.as_str()).await;
            ok_response(&req, json!({ "code": 0 }))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
