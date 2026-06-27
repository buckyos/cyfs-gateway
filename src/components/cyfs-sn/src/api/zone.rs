use super::common::{
    bns_managed_owner_authority, document_value_from_param, ok_response, parse_params,
    require_account_username, resolve_self_scoped_username, stable_request_id, BindZoneReq,
    IntoRpcResult, RpcCallResult,
};
use super::errors::{bns_write_error, parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::BindZoneDocumentsParams;
use serde_json::{json, Value};

async fn ensure_verified_user_domain(
    server: &SNServer,
    username: &str,
    user_domain: &str,
) -> RpcCallResult<()> {
    let Some(owner) = server
        .auth_db()
        .get_user_by_domain(user_domain)
        .await
        .into_rpc()?
        .and_then(|user| user.username)
    else {
        return Err(parse_error(
            SnV2ErrorCode::InvalidDomain,
            "user_domain is not verified",
        ));
    };

    if owner != username {
        return Err(parse_error(
            SnV2ErrorCode::InvalidDomain,
            format!("user_domain is owned by {}", owner),
        ));
    }

    Ok(())
}

pub(crate) async fn handle_zone(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "get" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let user = server
                .auth_db()
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
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let params: BindZoneReq = parse_params(&req)?;
            if let Some(user_domain) = params.user_domain.as_deref() {
                ensure_verified_user_domain(server, username.as_str(), user_domain).await?;
            }
            let mut bns_receipt = None;
            if let Some(controller) = server.bns_controller() {
                let _auth_context =
                    crate::sn_authority::require_owner_for_name(server, &req, username.as_str())
                        .await?;
                let authority = bns_managed_owner_authority(&controller)?;
                let zone_config =
                    document_value_from_param(params.zone_config.as_str(), "zone_config_jwt");
                if !zone_config.is_object() {
                    return Err(parse_error(
                        SnV2ErrorCode::InvalidZoneConfig,
                        "zone_config must be a JSON object or JWT string",
                    ));
                }
                // When boot_config is omitted, leave it null and let the
                // controller publish a zone-only mutation batch. When present,
                // boot_config is written as its own BNS boot document.
                let boot_config = match params.boot_config.as_deref() {
                    Some(value) => {
                        let parsed = document_value_from_param(value, "boot_config_jwt");
                        if !parsed.is_object() {
                            return Err(parse_error(
                                SnV2ErrorCode::InvalidZoneConfig,
                                "boot_config must be a JSON object or JWT string",
                            ));
                        }
                        parsed
                    }
                    None => Value::Null,
                };
                let payload = json!({
                    "zone_config": zone_config,
                    "boot_config": boot_config,
                    "user_domain": params.user_domain.clone(),
                });
                let receipt = controller
                    .bind_zone_documents(BindZoneDocumentsParams {
                        request_id: stable_request_id(
                            params.request_id.clone(),
                            "bind_zone",
                            username.as_str(),
                            &payload,
                        ),
                        name: username.clone(),
                        zone_config: payload["zone_config"].clone(),
                        boot_config: payload["boot_config"].clone(),
                        authority,
                    })
                    .await
                    .map_err(bns_write_error)?;
                bns_receipt = Some(serde_json::to_value(receipt).unwrap_or_default());
            } else if user.public_key.trim().is_empty() {
                return Err(parse_error(
                    SnV2ErrorCode::OwnerKeyRequired,
                    "owner public key is not bound",
                ));
            }
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "bns_receipt": bns_receipt,
                }),
            )
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
