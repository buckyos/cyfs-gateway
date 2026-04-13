use super::common::{
    ensure_owned_device, ok_response, parse_params, require_account_username,
    resolve_self_scoped_username, AddDnsRecordReq, IntoRpcResult, RemoveDnsRecordReq,
    RpcCallResult,
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
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let params: AddDnsRecordReq = parse_params(&req)?;
            let device =
                ensure_owned_device(server.db(), username.as_str(), params.device_did.as_str())
                    .await?;
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                params.domain.as_str(),
                server.server_host_v2(),
            )?;
            server
                .db()
                .add_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                    params.record.as_str(),
                    params.ttl.unwrap_or(600),
                )
                .await
                .into_rpc()?;
            if params.has_cert.unwrap_or(false) {
                server
                    .db()
                    .update_user_self_cert(username.as_str(), true)
                    .await
                    .into_rpc()?;
            }
            ok_response(
                &req,
                json!({ "code": 0, "device_name": device.device_name }),
            )
        }
        "remove_record" => {
            let username = require_account_username(server, &req)?;
            let user = server
                .db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::UserNotFound, "user not found"))?;
            let params: RemoveDnsRecordReq = parse_params(&req)?;
            ensure_owned_device(server.db(), username.as_str(), params.device_did.as_str()).await?;
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                params.domain.as_str(),
                server.server_host_v2(),
            )?;
            if params.has_cert.unwrap_or(false) {
                server
                    .db()
                    .update_user_self_cert(username.as_str(), true)
                    .await
                    .into_rpc()?;
            }
            server
                .db()
                .remove_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                )
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0 }))
        }
        "list_records" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .db()
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
