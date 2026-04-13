use super::common::{
    ensure_owned_device, ok_response, parse_params, require_account_username,
    resolve_self_scoped_username, AddDnsRecordReq, IntoRpcResult, RemoveDnsRecordReq,
    RpcCallResult,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::{json, Value};

pub(crate) async fn handle_dns(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "add_record" => {
            let username = require_account_username(server, &req)?;
            let params: AddDnsRecordReq = parse_params(&req)?;
            let device =
                ensure_owned_device(server.db(), username.as_str(), params.device_did.as_str())
                    .await?;
            let domain_suffix = format!(".{}.web3.{}", username, server.server_host_v2());
            if !params.domain.ends_with(domain_suffix.as_str()) {
                return Err(parse_error(
                    SnV2ErrorCode::InvalidDomain,
                    format!("invalid domain, expect suffix {}", domain_suffix),
                ));
            }
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
            let params: RemoveDnsRecordReq = parse_params(&req)?;
            ensure_owned_device(server.db(), username.as_str(), params.device_did.as_str()).await?;
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
