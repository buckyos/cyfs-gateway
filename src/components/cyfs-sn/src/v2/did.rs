use super::common::{
    normalize_username, ok_response, parse_params, require_account_username, GetDidDocumentReq,
    IntoRpcResult, RpcCallResult, SetDidDocumentReq,
};
use super::errors::{parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use serde_json::{json, Value};
use sha2::Digest;

pub(crate) async fn handle_did(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "set_document" => {
            let username = require_account_username(server, &req)?;
            let params: SetDidDocumentReq = parse_params(&req)?;
            let doc_string = if params.did_document.is_null() {
                String::new()
            } else {
                params.did_document.to_string()
            };
            let mut hasher = sha2::Sha256::new();
            hasher.update(doc_string.as_bytes());
            let obj_id = hex::encode(hasher.finalize());
            server
                .db()
                .insert_user_did_document(
                    obj_id.as_str(),
                    username.as_str(),
                    params.obj_name.as_str(),
                    doc_string.as_str(),
                    params.doc_type.as_deref(),
                )
                .await
                .into_rpc()?;
            ok_response(&req, json!({ "code": 0, "obj_id": obj_id }))
        }
        "get_document" => {
            let params: GetDidDocumentReq = parse_params(&req)?;
            let username = if let Some(name) = params.name {
                normalize_username(name.as_str())?
            } else {
                require_account_username(server, &req)?
            };
            let doc = server
                .db()
                .query_user_did_document(
                    username.as_str(),
                    params.obj_name.as_str(),
                    params.doc_type.as_deref(),
                )
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnV2ErrorCode::DidDocumentNotFound, "did document not found")
                })?;
            let did_document = if doc.1.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str::<Value>(doc.1.as_str()).map_err(|e| {
                    parse_error(
                        SnV2ErrorCode::InvalidParams,
                        format!("invalid stored did document: {}", e),
                    )
                })?
            };
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "obj_id": doc.0,
                    "did_document": did_document,
                    "doc_type": doc.2,
                }),
            )
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
