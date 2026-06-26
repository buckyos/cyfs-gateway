use super::common::{
    device_to_json, ensure_owner_decoding_key, ok_response, parse_params, query_by_did,
    require_account_username, resolve_self_scoped_username, stable_request_id, DeviceGetReq,
    DeviceRegisterReq, DeviceUpdateReq, IntoRpcResult, QueryByDidReq, QueryByHostnameReq,
    QueryByPkReq, RpcCallResult,
};
use super::errors::{bns_write_error, parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::PublishDeviceMiniDocParams;
use serde_json::{json, Value};

pub(crate) async fn handle_device(
    server: &SNServer,
    req: RPCRequest,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "register" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
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
            let mut bns_receipt = None;
            let mut pending_bns_publish = server.bns_controller().is_none();
            let mut published_to_bns = false;
            if let Some(controller) = server.bns_controller() {
                let auth_context =
                    crate::sn_authority::require_owner_for_name(server, &req, username.as_str())
                        .await?;
                let authority = auth_context.to_call_authority().ok_or_else(|| {
                    parse_error(SnV2ErrorCode::AuthRequired, "owner authority is required")
                })?;
                let mut device_mini_doc =
                    serde_json::from_str::<Value>(params.device_info.as_str())
                        .ok()
                        .filter(|value| value.is_object())
                        .unwrap_or_else(|| json!({ "device_info": params.device_info }));
                if let Some(obj) = device_mini_doc.as_object_mut() {
                    obj.insert("did".to_string(), Value::String(params.device_did.clone()));
                    obj.insert(
                        "device_name".to_string(),
                        Value::String(params.device_name.clone()),
                    );
                    obj.insert(
                        "mini_config_jwt".to_string(),
                        Value::String(params.mini_config_jwt.clone()),
                    );
                }
                let payload = json!({
                    "device_name": params.device_name.clone(),
                    "device_did": params.device_did.clone(),
                    "device_mini_doc": device_mini_doc,
                });
                let receipt = controller
                    .publish_device_mini_doc(PublishDeviceMiniDocParams {
                        request_id: stable_request_id(
                            params.request_id.clone(),
                            "publish_device",
                            username.as_str(),
                            &payload,
                        ),
                        name: username.clone(),
                        device_name: payload["device_name"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                        did: payload["device_did"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                        device_mini_doc: payload["device_mini_doc"].clone(),
                        authority,
                    })
                    .await
                    .map_err(bns_write_error)?;
                bns_receipt = Some(serde_json::to_value(receipt).unwrap_or_default());
                pending_bns_publish = false;
                published_to_bns = true;
            }
            if !published_to_bns {
                server
                    .register_device_record(
                        username.as_str(),
                        params.device_name.as_str(),
                        params.device_did.as_str(),
                        params.mini_config_jwt.as_str(),
                        params.device_ip.as_str(),
                        params.device_info.as_str(),
                    )
                    .await
                    .into_rpc()?;
            }
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "pending_bns_publish": pending_bns_publish,
                    "bns_receipt": bns_receipt,
                }),
            )
        }
        "update" => {
            let username = require_account_username(server, &req).await?;
            let params: DeviceUpdateReq = parse_params(&req)?;
            server
                .update_device_record(
                    username.as_str(),
                    params.device_name.as_str(),
                    params.device_did.as_deref(),
                    params.mini_config_jwt.as_deref(),
                    params.device_ip.as_str(),
                    params.device_info.as_str(),
                )
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0 }))
        }
        "get" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let params: DeviceGetReq = parse_params(&req)?;
            let device = server
                .compat_store()
                .query_device_by_name(username.as_str(), params.device_name.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
            ok_response(&req, device_to_json(&device))
        }
        "list" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .compat_store()
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
            let ood_info = query_by_did(
                server.compat_store(),
                server.auth_db(),
                params.source_device_id.as_str(),
            )
            .await?;
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
