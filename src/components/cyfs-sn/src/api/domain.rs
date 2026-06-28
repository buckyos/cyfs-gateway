use super::common::{
    ok_response, parse_params, require_account_username, IntoRpcResult, RpcCallResult,
};
use super::errors::{parse_error, reason_error, SnApiErrorCode};
use crate::{SNServer, SnError, SnErrorCode};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct DomainReq {
    domain: String,
}

#[derive(Deserialize)]
struct VerifyDomainReq {
    domain: String,
    #[serde(default)]
    txt_records: Vec<String>,
    #[serde(default)]
    txt_record: Option<String>,
    #[serde(default)]
    record: Option<String>,
}

fn map_domain_error(error: SnError) -> RPCErrors {
    match error.code() {
        SnErrorCode::InvalidInput | SnErrorCode::Conflict | SnErrorCode::Blocked => {
            parse_error(SnApiErrorCode::InvalidDomain, error.to_string())
        }
        SnErrorCode::NotFound => {
            if error.to_string().contains("user not found") {
                parse_error(SnApiErrorCode::UserNotFound, error.to_string())
            } else {
                parse_error(SnApiErrorCode::InvalidDomain, error.to_string())
            }
        }
        SnErrorCode::DBError | SnErrorCode::RemoteError | SnErrorCode::Failed => {
            reason_error(SnApiErrorCode::InternalError, error.to_string())
        }
        SnErrorCode::StaleReport => reason_error(SnApiErrorCode::InternalError, error.to_string()),
    }
}

pub(crate) async fn handle_domain(
    server: &SNServer,
    req: RPCRequest,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "begin_verify" | "create_pkx_binding" => {
            let username = require_account_username(server, &req).await?;
            let params: DomainReq = parse_params(&req)?;
            let challenge = server
                .auth_db()
                .create_pkx_binding(username.as_str(), params.domain.as_str())
                .await
                .map_err(map_domain_error)?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "domain": challenge.domain,
                    "pkx": challenge.pkx,
                    "pkx_record_name": challenge.pkx_record_name,
                    "state": challenge.state,
                    "created_at": challenge.created_at,
                    "updated_at": challenge.updated_at,
                }),
            )
        }
        "verify" | "verify_pkx_binding" => {
            let username = require_account_username(server, &req).await?;
            let params: VerifyDomainReq = parse_params(&req)?;
            let mut txt_records = params.txt_records;
            if let Some(record) = params.txt_record {
                txt_records.push(record);
            }
            if let Some(record) = params.record {
                txt_records.push(record);
            }
            if txt_records.is_empty() {
                return Err(parse_error(
                    SnApiErrorCode::InvalidParams,
                    "txt_records is required",
                ));
            }
            let binding = server
                .auth_db()
                .verify_pkx_binding(username.as_str(), params.domain.as_str(), &txt_records)
                .await
                .map_err(map_domain_error)?;
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "domain": binding.domain,
                    "pkx": binding.pkx,
                    "pkx_record_name": binding.pkx_record_name,
                    "verified_at": binding.verified_at,
                }),
            )
        }
        "unbind" => {
            let username = require_account_username(server, &req).await?;
            let params: DomainReq = parse_params(&req)?;
            server
                .auth_db()
                .unbind_user_domain(username.as_str(), params.domain.as_str())
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0 }))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
