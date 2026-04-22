use super::common::{
    device_to_json, ensure_owner_decoding_key, ok_response, parse_params, query_by_did,
    require_account_username, resolve_self_scoped_username, DeviceGetReq, DeviceRegisterReq,
    DeviceUpdateReq, IntoRpcResult, QueryByDidReq, QueryByHostnameReq, QueryByPkReq, RpcCallResult,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::{json, Value};

pub(crate) async fn handle_device(
    server: &SNServer,
    req: RPCRequest,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "register" => {
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let public_key = ensure_owner_decoding_key(&user)?;
            let params: DeviceRegisterReq = parse_params(&req)?;
            let decode_context = format!("v2 register_device {}.{}", username, params.device_name);
            let mini_device_config = SNServer::decode_mini_config_with_schema_compat(
                params.mini_config_jwt.as_str(),
                &public_key,
                decode_context.as_str(),
            )
            .map_err(|e| parse_error(SnV2ErrorCode::InvalidParams, e))?;
            let dev_did = format!("did:dev:{}", mini_device_config.x.as_str());
            if dev_did != params.device_did {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidDeviceDid,
                    format!("invalid device did: {} != {}", dev_did, params.device_did),
                ));
            }
            server
                .db()
                .register_device(
                    username.as_str(),
                    params.device_name.as_str(),
                    params.device_did.as_str(),
                    params.mini_config_jwt.as_str(),
                    params.device_ip.as_str(),
                    params.device_info.as_str(),
                )
                .await
                .into_rpc()?;
            server.invalidate_query_cache_for_username(username.as_str()).await;
            ok_response(&req, json!({ "code": 0 }))
        }
        "update" => {
            let username = require_account_username(server, &req)?;
            let params: DeviceUpdateReq = parse_params(&req)?;
            match (
                params.device_did.as_deref(),
                params.mini_config_jwt.as_deref(),
            ) {
                (Some(device_did), Some(mini_config_jwt)) => {
                    server
                        .db()
                        .update_device_by_name(
                            username.as_str(),
                            params.device_name.as_str(),
                            device_did,
                            mini_config_jwt,
                            params.device_ip.as_str(),
                            params.device_info.as_str(),
                        )
                        .await
                        .into_rpc()?;
                }
                _ => {
                    server
                        .db()
                        .update_device_info_by_name(
                            username.as_str(),
                            params.device_name.as_str(),
                            params.device_ip.as_str(),
                            params.device_info.as_str(),
                        )
                        .await
                        .into_rpc()?;
                }
            }
            server.invalidate_query_cache_for_username(username.as_str()).await;
            ok_response(&req, json!({ "code": 0 }))
        }
        "get" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let params: DeviceGetReq = parse_params(&req)?;
            let device = server
                .db()
                .query_device_by_name(username.as_str(), params.device_name.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
            ok_response(&req, device_to_json(&device))
        }
        "list" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .db()
                .list_user_devices(username.as_str())
                .await
                .into_rpc()?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "items": items.iter().map(device_to_json).collect::<Vec<Value>>(),
                }),
            )
        }
        "get_by_pk" => {
            let params: QueryByPkReq = parse_params(&req)?;
            let proxy_req = RPCRequest {
                params: json!({ "public_key": params.public_key }),
                ..req
            };
            server.get_device_by_public_key(proxy_req).await
        }
        "query_by_did" => {
            let params: QueryByDidReq = parse_params(&req)?;
            let ood_info = query_by_did(server.db(), params.source_device_id.as_str()).await?;
            ok_response(&req, serde_json::to_value(ood_info).unwrap())
        }
        "query_by_hostname" => {
            let params: QueryByHostnameReq = parse_params(&req)?;
            let ood_info = server
                .query_device_by_hostname_v2(params.dest_host.as_str())
                .await
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::HostnameNotFound, "hostname not found")
                })?;
            ok_response(&req, serde_json::to_value(ood_info).unwrap())
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
