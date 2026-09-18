use super::common::{
    ok_response, parse_params, resolve_self_scoped_username, AddDnsRecordReq, IntoRpcResult,
    RemoveDnsRecordReq, RpcCallResult,
};
use super::errors::{parse_error, SnApiErrorCode};
use crate::sn_authority::{require_sn_user_or_device, AuthContext};
use crate::{canonical_user_dns_name, canonical_user_dns_rdata, SNServer, UserDnsRecordType};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::{
    SnAddDnsRecordResp, SnDnsRecordListResp, SnDnsRecordType, SnDnsRrset, SnRemoveDnsRecordResp,
};
use std::str::FromStr;

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_same_or_subdomain(domain: &str, zone: &str) -> bool {
    domain == zone || domain.ends_with(format!(".{}", zone).as_str())
}

fn ensure_user_dns_domain(
    username: &str,
    user_domain: Option<&str>,
    server_host: &str,
    domain: &str,
) -> RpcCallResult<()> {
    let domain = normalize_domain(domain);
    if let Some(user_domain) = user_domain {
        let user_domain = normalize_domain(user_domain);
        if !user_domain.is_empty() && is_same_or_subdomain(domain.as_str(), user_domain.as_str()) {
            return Ok(());
        }
    }

    // Records under the SN-provided `<username>.web3.<server_host>` namespace
    // remain AuthDB-managed. In particular, ACME challenges must not require a
    // temporary BNS document update and its associated on-chain gas cost.
    let bridge_domain = format!(
        "{}.web3.{}",
        normalize_domain(username),
        normalize_domain(server_host)
    );
    if is_same_or_subdomain(domain.as_str(), bridge_domain.as_str()) {
        return Ok(());
    }

    Err(parse_error(
        SnApiErrorCode::InvalidDomain,
        format!(
            "invalid domain, expect {} or its subdomain, or an active user_domain",
            bridge_domain
        ),
    ))
}

struct DnsMutationIdentity {
    username: String,
    device_name: String,
    is_device: bool,
}

async fn resolve_dns_mutation_identity(
    server: &SNServer,
    req: &RPCRequest,
    requested_device_did: &str,
) -> RpcCallResult<DnsMutationIdentity> {
    match require_sn_user_or_device(server, req).await? {
        AuthContext::SnUser { username, .. } => Ok(DnsMutationIdentity {
            device_name: ensure_owned_runtime_device(server, &username, requested_device_did)
                .await?,
            username,
            is_device: false,
        }),
        AuthContext::Device {
            zone, device_name, ..
        } => Ok(DnsMutationIdentity {
            username: zone,
            device_name,
            is_device: true,
        }),
    }
}

fn ensure_device_acme_record(domain: &str, record_type: UserDnsRecordType) -> RpcCallResult<()> {
    if record_type != UserDnsRecordType::Txt {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device DNS mutation only allows TXT",
        ));
    }
    let domain = normalize_domain(domain);
    if !domain.starts_with("_acme-challenge.") || domain.len() == "_acme-challenge.".len() {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device DNS mutation only allows _acme-challenge names",
        ));
    }
    Ok(())
}

pub(crate) async fn handle_dns(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "add_record" => {
            let params: AddDnsRecordReq = parse_params(&req)?;
            let name = canonical_user_dns_name(params.domain.as_str()).into_rpc()?;
            let record_type =
                UserDnsRecordType::from_str(params.record_type.as_str()).into_rpc()?;
            let value = canonical_user_dns_rdata(record_type, params.record.as_str()).into_rpc()?;
            let identity =
                resolve_dns_mutation_identity(server, &req, params.device_did.as_str()).await?;
            let username = identity.username;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            if identity.is_device {
                ensure_device_acme_record(name.as_str(), record_type)?;
            }
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                server.resolver().config().server_host.as_str(),
                name.as_str(),
            )?;
            let mutation = server
                .auth_db()
                .put_user_dns_value(
                    username.as_str(),
                    name.as_str(),
                    record_type,
                    value.as_str(),
                    params.ttl.unwrap_or(600),
                )
                .await
                .into_rpc()?;
            server.resolver().invalidate_user_dns_name(name.as_str());
            if let Some(cache_type) = crate::SNServer::parse_name_record_type(record_type.as_str())
            {
                server.remove_name_info_cache(name.as_str(), cache_type);
            }
            if let Err(error) = server.resolver().synchronize_user_dns_changes().await {
                log::warn!(
                    "refresh user DNS change cursor after {} failed: {}",
                    mutation.revision,
                    error
                );
            }
            ok_response(
                &req,
                SnAddDnsRecordResp {
                    code: 0,
                    device_name: identity.device_name,
                    revision: mutation.revision,
                    changed: mutation.changed,
                },
            )
        }
        "remove_record" => {
            let params: RemoveDnsRecordReq = parse_params(&req)?;
            let name = canonical_user_dns_name(params.domain.as_str()).into_rpc()?;
            let record_type =
                UserDnsRecordType::from_str(params.record_type.as_str()).into_rpc()?;
            let value = params
                .record
                .as_deref()
                .map(|value| canonical_user_dns_rdata(record_type, value))
                .transpose()
                .into_rpc()?;
            let identity =
                resolve_dns_mutation_identity(server, &req, params.device_did.as_str()).await?;
            let username = identity.username;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            if identity.is_device {
                ensure_device_acme_record(name.as_str(), record_type)?;
                if value.is_none() {
                    return Err(parse_error(
                        SnApiErrorCode::InvalidParams,
                        "device DNS removal requires an exact record value",
                    ));
                }
            }
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                server.resolver().config().server_host.as_str(),
                name.as_str(),
            )?;
            let mutation = if let Some(value) = value.as_deref() {
                server
                    .auth_db()
                    .remove_user_dns_value(username.as_str(), name.as_str(), record_type, value)
                    .await
                    .into_rpc()?
            } else {
                server
                    .auth_db()
                    .delete_user_dns_rrset(username.as_str(), name.as_str(), record_type)
                    .await
                    .into_rpc()?
            };
            server.resolver().invalidate_user_dns_name(name.as_str());
            if let Some(cache_type) = crate::SNServer::parse_name_record_type(record_type.as_str())
            {
                server.remove_name_info_cache(name.as_str(), cache_type);
            }
            if let Err(error) = server.resolver().synchronize_user_dns_changes().await {
                log::warn!(
                    "refresh user DNS change cursor after {} failed: {}",
                    mutation.revision,
                    error
                );
            }
            ok_response(
                &req,
                SnRemoveDnsRecordResp {
                    code: 0,
                    revision: mutation.revision,
                    changed: mutation.changed,
                },
            )
        }
        "list_records" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .auth_db()
                .list_user_dns_rrsets(username.as_str())
                .await
                .into_rpc()?;
            ok_response(
                &req,
                SnDnsRecordListResp {
                    code: 0,
                    items: items
                        .into_iter()
                        .map(|rrset| SnDnsRrset {
                            name: rrset.name,
                            record_type: match rrset.record_type {
                                UserDnsRecordType::A => SnDnsRecordType::A,
                                UserDnsRecordType::Aaaa => SnDnsRecordType::Aaaa,
                                UserDnsRecordType::Txt => SnDnsRecordType::Txt,
                            },
                            ttl: rrset.ttl,
                            values: rrset.values,
                            revision: rrset.revision,
                        })
                        .collect(),
                },
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
            SnApiErrorCode::DevicePermissionDenied,
            "device has no permission",
        ));
    }

    Err(parse_error(
        SnApiErrorCode::DevicePermissionDenied,
        "device has no permission",
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_user_dns_domain;

    #[test]
    fn test_ensure_user_dns_domain_allows_own_web3_bridge_domain_without_user_domain() {
        assert!(
            ensure_user_dns_domain("alice", None, "buckyos.ai", "alice.web3.buckyos.ai").is_ok()
        );
        assert!(ensure_user_dns_domain(
            "alice",
            None,
            "buckyos.ai",
            "_acme-challenge.alice.web3.buckyos.ai"
        )
        .is_ok());

        let err = ensure_user_dns_domain("alice", None, "buckyos.ai", "home.bob.web3.buckyos.ai")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[SN:1015:invalid_domain]"));
    }

    #[test]
    fn test_ensure_user_dns_domain_for_custom_user_domain() {
        assert!(ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "buckyos.ai",
            "home.alice.example.com",
        )
        .is_ok());
        assert!(ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "buckyos.ai",
            "alice.example.com",
        )
        .is_ok());

        let err = ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "buckyos.ai",
            "home.bob.example.com",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("[SN:1015:invalid_domain]"));
    }
}
