use super::common::{
    ensure_owned_device, ok_response, parse_params, require_account_username,
    resolve_self_scoped_username, stable_request_id, AddDnsRecordReq, IntoRpcResult,
    RemoveDnsRecordReq, RpcCallResult,
};
use super::errors::{bns_write_error, parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::{DnsTxtUpdate, UpsertDnsTxtParams};
use serde_json::{json, Value};

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_same_or_subdomain(domain: &str, zone: &str) -> bool {
    domain == zone || domain.ends_with(format!(".{}", zone).as_str())
}

fn ensure_user_dns_domain(
    username: &str,
    user_domain: Option<&str>,
    domain: &str,
    server_host: &str,
) -> RpcCallResult<()> {
    let domain = normalize_domain(domain);
    if let Some(user_domain) = user_domain {
        let user_domain = normalize_domain(user_domain);
        if !user_domain.is_empty() && is_same_or_subdomain(domain.as_str(), user_domain.as_str()) {
            return Ok(());
        }

        return Err(parse_error(
            SnV2ErrorCode::InvalidDomain,
            format!("invalid domain, expect {} or its subdomain", user_domain),
        ));
    }

    let domain_suffix = format!(".{}.web3.{}", username, server_host);
    if !domain.ends_with(domain_suffix.as_str()) {
        return Err(parse_error(
            SnV2ErrorCode::InvalidDomain,
            format!("invalid domain, expect suffix {}", domain_suffix),
        ));
    }

    Ok(())
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
            let device = ensure_owned_device(
                server.compat_store(),
                username.as_str(),
                params.device_did.as_str(),
            )
            .await?;
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                params.domain.as_str(),
                server.server_host_v2(),
            )?;
            let mut bns_receipt = None;
            if params.record_type.eq_ignore_ascii_case("TXT") {
                if let Some(controller) = server.bns_controller() {
                    let payload = json!({
                        "domain": normalize_domain(params.domain.as_str()),
                        "record": params.record.clone(),
                        "ttl": params.ttl.unwrap_or(600),
                    });
                    let receipt = controller
                        .upsert_dns_txt(UpsertDnsTxtParams {
                            request_id: stable_request_id(
                                params.request_id.clone(),
                                "upsert_dns_txt",
                                username.as_str(),
                                &payload,
                            ),
                            name: username.clone(),
                            update: DnsTxtUpdate::Add {
                                ttl: params.ttl.unwrap_or(600),
                                value: params.record.clone(),
                            },
                            authority: controller.sn_controller_authority(),
                        })
                        .await
                        .map_err(bns_write_error)?;
                    bns_receipt = Some(serde_json::to_value(receipt).unwrap_or_default());
                }
            }
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
                    "device_name": device.device_name,
                    "bns_receipt": bns_receipt,
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
            ensure_owned_device(
                server.compat_store(),
                username.as_str(),
                params.device_did.as_str(),
            )
            .await?;
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                params.domain.as_str(),
                server.server_host_v2(),
            )?;
            let mut bns_receipt = None;
            if params.record_type.eq_ignore_ascii_case("TXT") {
                if let Some(controller) = server.bns_controller() {
                    let update = params
                        .record
                        .clone()
                        .map(|value| DnsTxtUpdate::Remove { value })
                        .unwrap_or_else(|| DnsTxtUpdate::Replace {
                            records: Vec::new(),
                        });
                    let payload = json!({
                        "domain": normalize_domain(params.domain.as_str()),
                        "record": params.record.clone(),
                    });
                    let receipt = controller
                        .upsert_dns_txt(UpsertDnsTxtParams {
                            request_id: stable_request_id(
                                params.request_id.clone(),
                                "remove_dns_txt",
                                username.as_str(),
                                &payload,
                            ),
                            name: username.clone(),
                            update,
                            authority: controller.sn_controller_authority(),
                        })
                        .await
                        .map_err(bns_write_error)?;
                    bns_receipt = Some(serde_json::to_value(receipt).unwrap_or_default());
                }
            }
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
            ok_response(&req, json!({ "code": 0, "bns_receipt": bns_receipt }))
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

#[cfg(test)]
mod tests {
    use super::ensure_user_dns_domain;

    #[test]
    fn test_ensure_user_dns_domain_for_web3_namespace() {
        assert!(
            ensure_user_dns_domain("alice", None, "home.alice.web3.buckyos.ai", "buckyos.ai")
                .is_ok()
        );

        let err = ensure_user_dns_domain("alice", None, "home.bob.web3.buckyos.ai", "buckyos.ai")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[SNV2:1015:invalid_domain]"));
    }

    #[test]
    fn test_ensure_user_dns_domain_for_custom_user_domain() {
        assert!(ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "home.alice.example.com",
            "buckyos.ai"
        )
        .is_ok());
        assert!(ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "alice.example.com",
            "buckyos.ai"
        )
        .is_ok());

        let err = ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "home.bob.example.com",
            "buckyos.ai",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("[SNV2:1015:invalid_domain]"));
    }
}
