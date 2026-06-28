use super::common::{
    ok_response, parse_params, require_account_username, resolve_self_scoped_username,
    IntoRpcResult, QueryByDidReq, QueryByHostnameReq, RpcCallResult,
};
use super::errors::{parse_error, SnApiErrorCode};
use crate::{
    SNServer, SnDeviceEndpointUpdate, SnDeviceListOptions, SnDeviceState, SnDeviceStateView,
};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) async fn handle_device(
    server: &SNServer,
    req: RPCRequest,
    ip_from: std::net::IpAddr,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "register" => {
            let username = require_account_username(server, &req).await?;
            let params: DeviceOnlineRegisterReq = parse_params(&req)?;
            let view = report_device_online_state(
                server,
                username.as_str(),
                params.device_name.as_str(),
                params.device_did.as_str(),
                params.device_ip.as_str(),
                &params.device_info,
                Some(ip_from),
                params.endpoints,
                params.report_seq,
                params.ttl,
            )
            .await?;
            ok_response(&req, online_state_response(view))
        }
        "update" => {
            let username = require_account_username(server, &req).await?;
            let params: DeviceOnlineUpdateReq = parse_params(&req)?;
            if params.mini_config_jwt.is_some() {
                return Err(parse_error(
                    SnApiErrorCode::InvalidParams,
                    "device identity document updates moved to /kapi/bns",
                ));
            }
            let device_did = resolve_report_did(
                server,
                username.as_str(),
                params.device_name.as_str(),
                params.device_did.as_deref(),
            )
            .await?;
            let view = report_device_online_state(
                server,
                username.as_str(),
                params.device_name.as_str(),
                device_did.as_str(),
                params.device_ip.as_str(),
                &params.device_info,
                Some(ip_from),
                params.endpoints,
                params.report_seq,
                params.ttl,
            )
            .await?;
            ok_response(&req, online_state_response(view))
        }
        "get" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let params: DeviceOnlineGetReq = parse_params(&req)?;
            let view = if let Some(device_did) = params.device_did {
                let view = server
                    .device_info_db()
                    .get_device_state(device_did.as_str())
                    .await
                    .into_rpc()?
                    .ok_or_else(|| {
                        parse_error(SnApiErrorCode::DeviceNotFound, "device not found")
                    })?;
                if view.zone != username {
                    return Err(parse_error(
                        SnApiErrorCode::CrossUserAccessDenied,
                        "cross-user access is not allowed",
                    ));
                }
                view
            } else {
                let device_name = params.device_name.ok_or_else(|| {
                    parse_error(
                        SnApiErrorCode::InvalidParams,
                        "device_name or device_did is required",
                    )
                })?;
                server
                    .device_info_db()
                    .get_device_state_by_name(username.as_str(), device_name.as_str())
                    .await
                    .into_rpc()?
                    .ok_or_else(|| parse_error(SnApiErrorCode::DeviceNotFound, "device not found"))?
            };
            ok_response(&req, online_state_response(view))
        }
        "list" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let params: DeviceOnlineListReq = parse_params(&req)?;
            let items = server
                .device_info_db()
                .list_zone_devices(
                    username.as_str(),
                    SnDeviceListOptions {
                        state: params.state,
                        offset: params.offset,
                        limit: params.limit,
                    },
                )
                .await
                .into_rpc()?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "items": items,
                }),
            )
        }
        "resolve_ood_by_did" => {
            let params: QueryByDidReq = parse_params(&req)?;
            let ood_info = server
                .resolve_ood_by_did(params.source_device_id.as_str())
                .await?;
            ok_response(&req, serde_json::to_value(ood_info).unwrap())
        }
        "resolve_ood_by_hostname" => {
            let params: QueryByHostnameReq = parse_params(&req)?;
            let ood_info = server
                .query_device_by_hostname(params.dest_host.as_str())
                .await
                .ok_or_else(|| {
                    parse_error(SnApiErrorCode::HostnameNotFound, "hostname not found")
                })?;
            ok_response(&req, serde_json::to_value(ood_info).unwrap())
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}

#[derive(Deserialize)]
struct DeviceOnlineRegisterReq {
    device_name: String,
    device_did: String,
    device_ip: String,
    device_info: Value,
    #[serde(default)]
    endpoints: Vec<SnDeviceEndpointUpdate>,
    #[serde(default)]
    report_seq: Option<u64>,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Deserialize)]
struct DeviceOnlineUpdateReq {
    device_name: String,
    #[serde(default)]
    device_did: Option<String>,
    #[serde(default)]
    mini_config_jwt: Option<String>,
    device_ip: String,
    device_info: Value,
    #[serde(default)]
    endpoints: Vec<SnDeviceEndpointUpdate>,
    #[serde(default)]
    report_seq: Option<u64>,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Deserialize)]
struct DeviceOnlineGetReq {
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    device_did: Option<String>,
}

#[derive(Deserialize)]
struct DeviceOnlineListReq {
    #[serde(default)]
    state: Option<SnDeviceState>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

fn online_state_response(view: SnDeviceStateView) -> Value {
    let mut value = serde_json::to_value(view).unwrap_or_else(|_| json!({}));
    if let Some(obj) = value.as_object_mut() {
        obj.insert("code".to_string(), Value::Number(0.into()));
    }
    value
}

fn device_info_to_report_string(value: &Value) -> String {
    value
        .as_str()
        .map(ToString::to_string)
        .unwrap_or_else(|| value.to_string())
}

async fn resolve_report_did(
    server: &SNServer,
    username: &str,
    device_name: &str,
    requested_did: Option<&str>,
) -> RpcCallResult<String> {
    if let Some(did) = requested_did.filter(|did| !did.trim().is_empty()) {
        return Ok(did.to_string());
    }

    if let Some(view) = server
        .device_info_db()
        .get_device_state_by_name(username, device_name)
        .await
        .into_rpc()?
    {
        return Ok(view.did);
    }

    if let Some(device) = server
        .compat_store()
        .query_device_by_name(username, device_name)
        .await
        .into_rpc()?
    {
        return Ok(device.did);
    }

    Err(parse_error(
        SnApiErrorCode::InvalidDeviceDid,
        "device_did is required for the first online report",
    ))
}

async fn report_device_online_state(
    server: &SNServer,
    username: &str,
    device_name: &str,
    device_did: &str,
    device_ip: &str,
    device_info: &Value,
    from_ip: Option<std::net::IpAddr>,
    endpoints: Vec<SnDeviceEndpointUpdate>,
    report_seq: Option<u64>,
    ttl: Option<u64>,
) -> RpcCallResult<SnDeviceStateView> {
    let report = device_info_to_report_string(device_info);
    server
        .upsert_device_online_state(
            username,
            device_name,
            device_did,
            device_ip,
            report.as_str(),
            from_ip,
            endpoints,
            report_seq,
            ttl,
        )
        .await
        .into_rpc()?;

    server
        .device_info_db()
        .get_device_state(device_did)
        .await
        .into_rpc()?
        .ok_or_else(|| parse_error(SnApiErrorCode::DeviceNotFound, "device not found"))
}
