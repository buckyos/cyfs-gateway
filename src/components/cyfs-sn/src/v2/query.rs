use super::common::{
    device_to_json, normalize_username, ok_response, parse_params, IntoRpcResult,
    ResolveDeviceReq, ResolveDidReq, ResolveHostnameReq, RpcCallResult,
};
use super::errors::{parse_error, reason_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCRequest, RPCResponse, RPCErrors};
use name_lib::DID;
use serde_json::json;

pub(crate) async fn handle_query(
    server: &SNServer,
    req: RPCRequest,
    ip_from: std::net::IpAddr,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "resolve_did" => {
            let params: ResolveDidReq = parse_params(&req)?;
            let doc_type = params
                .doc_type
                .as_deref()
                .or(params.legacy_type.as_deref());
            let did = DID::from_str(params.did.as_str())
                .map_err(|e| parse_error(SnV2ErrorCode::InvalidDid, format!("invalid did: {}", e)))?;
            let doc = server
                .query_did_v2(&did, doc_type, Some(ip_from))
                .await
                .map_err(|e| reason_error(SnV2ErrorCode::InternalError, e.to_string()))?;
            let value = match doc {
                name_lib::EncodedDocument::JsonLd(v) => v,
                name_lib::EncodedDocument::Jwt(jwt) => json!({ "jwt": jwt }),
            };
            ok_response(&req, json!({ "code": 0, "document": value }))
        }
        "resolve_hostname" => {
            let params: ResolveHostnameReq = parse_params(&req)?;
            let ood = server
                .query_device_by_hostname_v2(params.host.as_str())
                .await
                .ok_or_else(|| parse_error(SnV2ErrorCode::HostnameNotFound, "hostname not found"))?;
            ok_response(&req, serde_json::to_value(ood).unwrap())
        }
        "resolve_device" => {
            let params: ResolveDeviceReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            let device = server
                .db()
                .query_device_by_name(username.as_str(), params.device_name.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnV2ErrorCode::DeviceNotFound, "device not found"))?;
            ok_response(&req, device_to_json(&device))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
