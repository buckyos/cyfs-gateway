use super::common::{
    ok_response, parse_params, require_account_username, resolve_self_scoped_username,
    AddDnsRecordReq, IntoRpcResult, RemoveDnsRecordReq, RpcCallResult,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::{json, Value};

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_same_or_subdomain(domain: &str, zone: &str) -> bool {
    domain == zone || domain.ends_with(format!(".{}", zone).as_str())
}

fn ensure_user_dns_domain(user_domain: Option<&str>, domain: &str) -> RpcCallResult<()> {
    let domain = normalize_domain(domain);
    let Some(user_domain) = user_domain else {
        return Err(parse_error(
            SnV2ErrorCode::InvalidDomain,
            "user_domain is required for user DNS records",
        ));
    };
    let user_domain = normalize_domain(user_domain);
    if !user_domain.is_empty() && is_same_or_subdomain(domain.as_str(), user_domain.as_str()) {
        return Ok(());
    }

    Err(parse_error(
        SnV2ErrorCode::InvalidDomain,
        format!("invalid domain, expect {} or its subdomain", user_domain),
    ))
}

pub(crate) async fn handle_dns(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "add_record" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let params: AddDnsRecordReq = parse_params(&req)?;
            let device_name =
                ensure_owned_runtime_device(server, username.as_str(), params.device_did.as_str())
                    .await?;
            ensure_user_dns_domain(user.user_domain.as_deref(), params.domain.as_str())?;
            server
                .compat_store()
                .add_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                    params.record.as_str(),
                    params.ttl.unwrap_or(600),
                )
                .await
                .into_rpc()?;
            if let Some(record_type) =
                crate::SNServer::parse_name_record_type(params.record_type.as_str())
            {
                server.remove_name_info_cache(params.domain.as_str(), record_type);
            }
            if params.has_cert.unwrap_or(false) {
                server
                    .auth_db()
                    .update_user_self_cert(username.as_str(), true)
                    .await
                    .into_rpc()?;
            }
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "device_name": device_name,
                }),
            )
        }
        "remove_record" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let params: RemoveDnsRecordReq = parse_params(&req)?;
            ensure_owned_runtime_device(server, username.as_str(), params.device_did.as_str())
                .await?;
            ensure_user_dns_domain(user.user_domain.as_deref(), params.domain.as_str())?;
            if params.has_cert.unwrap_or(false) {
                server
                    .auth_db()
                    .update_user_self_cert(username.as_str(), true)
                    .await
                    .into_rpc()?;
            }
            server
                .compat_store()
                .remove_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                )
                .await
                .into_rpc()?;
            if let Some(record_type) =
                crate::SNServer::parse_name_record_type(params.record_type.as_str())
            {
                server.remove_name_info_cache(params.domain.as_str(), record_type);
            }
            ok_response(&req, json!({ "code": 0 }))
        }
        "list_records" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .compat_store()
                .query_user_domain_records(username.as_str())
                .await
                .into_rpc()?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "items": items.into_iter().map(|(domain, record_type, record, ttl)| {
                        json!({
                            "domain": domain,
                            "record_type": record_type,
                            "record": record,
                            "ttl": ttl,
                        })
                    }).collect::<Vec<Value>>(),
                }),
            )
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}

async fn ensure_owned_runtime_device(
    server: &SNServer,
    username: &str,
    device_did: &str,
) -> RpcCallResult<String> {
    if let Some(view) = server
        .device_info_db()
        .get_device_state(device_did)
        .await
        .into_rpc()?
    {
        if view.zone == username {
            return Ok(view.device_name);
        }
        return Err(parse_error(
            SnV2ErrorCode::DevicePermissionDenied,
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
            return Ok(device.device_name);
        }
    }

    Err(parse_error(
        SnV2ErrorCode::DevicePermissionDenied,
        "device has no permission",
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_user_dns_domain;

    #[test]
    fn test_ensure_user_dns_domain_requires_user_domain() {
        let err = ensure_user_dns_domain(None, "home.alice.web3.buckyos.ai")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[SNV2:1015:invalid_domain]"));
    }

    #[test]
    fn test_ensure_user_dns_domain_for_custom_user_domain() {
        assert!(
            ensure_user_dns_domain(Some("alice.example.com"), "home.alice.example.com",).is_ok()
        );
        assert!(ensure_user_dns_domain(Some("alice.example.com"), "alice.example.com",).is_ok());

        let err = ensure_user_dns_domain(Some("alice.example.com"), "home.bob.example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[SNV2:1015:invalid_domain]"));
    }
}
