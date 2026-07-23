use super::common::{
    build_profile_response, ok_response, parse_params, require_account_username, IntoRpcResult,
    RpcCallResult, SetSelfCertReq,
};
use super::errors::{parse_error, SnApiErrorCode};
use crate::sn_authority::{require_sn_user_or_device, AuthContext};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::SnSuccessResp;

pub(crate) async fn handle_user(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "set_self_cert" => {
            let params: SetSelfCertReq = parse_params(&req)?;
            let username = match require_sn_user_or_device(server, &req).await? {
                AuthContext::SnUser { username, .. } => {
                    if params.self_cert {
                        let device_did = params.device_did.as_deref().ok_or_else(|| {
                            parse_error(
                                SnApiErrorCode::DevicePermissionDenied,
                                "device_did is required to enable self_cert",
                            )
                        })?;
                        ensure_owned_runtime_device(server, username.as_str(), device_did).await?;
                    }
                    username
                }
                // require_sn_device has already anchored the signing key to this
                // active zone, so the request cannot select another username.
                AuthContext::Device { zone, .. } => zone,
            };
            server
                .auth_db()
                .update_user_self_cert(username.as_str(), params.self_cert)
                .await
                .into_rpc()?;
            ok_response(&req, SnSuccessResp { code: 0 })
        }
        "get_profile" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            ok_response(&req, build_profile_response(username.as_str(), &user))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}

async fn ensure_owned_runtime_device(
    server: &SNServer,
    username: &str,
    device_did: &str,
) -> RpcCallResult<()> {
    if let Some(view) = server
        .device_info_db()
        .get_device_state(device_did)
        .await
        .into_rpc()?
    {
        if view.zone == username {
            return Ok(());
        }
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device has no permission",
        ));
    }

    if let Some(device) = server
        .compat_store()
        .query_device_by_did(device_did)
        .await
        .into_rpc()?
    {
        if device.owner == username {
            return Ok(());
        }
    }

    Err(parse_error(
        SnApiErrorCode::DevicePermissionDenied,
        "device has no permission",
    ))
}
