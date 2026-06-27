use super::common::{
    bns_managed_owner_authority, normalize_username, ok_response, parse_params,
    require_account_username, stable_request_id, GetDidDocumentReq, IntoRpcResult, RpcCallResult,
    SetDidDocumentReq,
};
use super::errors::{bns_write_error, parse_error, SnV2ErrorCode};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::PublishDocumentParams;
use serde_json::{json, Value};
use sha2::Digest;

pub(crate) async fn handle_did(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "set_document" => {
            let username = require_account_username(server, &req).await?;
            let params: SetDidDocumentReq = parse_params(&req)?;
            let doc_type = params
                .doc_type
                .clone()
                .unwrap_or_else(|| "did_doc".to_string());
            let mut bns_receipt = None;
            let mut published_to_bns = false;
            if let Some(controller) = server.bns_controller() {
                let _auth_context =
                    crate::sn_authority::require_owner_for_name(server, &req, username.as_str())
                        .await?;
                let authority = bns_managed_owner_authority(&controller)?;
                let document = if params.did_document.is_object() {
                    params.did_document.clone()
                } else {
                    json!({
                        "obj_name": params.obj_name.clone(),
                        "document": params.did_document.clone(),
                    })
                };
                let payload = json!({
                    "obj_name": params.obj_name.clone(),
                    "doc_type": doc_type.clone(),
                    "document": document,
                });
                let receipt = controller
                    .publish_document(PublishDocumentParams {
                        request_id: stable_request_id(
                            params.request_id.clone(),
                            "publish_did",
                            username.as_str(),
                            &payload,
                        ),
                        name: username.clone(),
                        doc_type: doc_type.clone(),
                        document,
                        authority,
                    })
                    .await
                    .map_err(bns_write_error)?;
                bns_receipt = Some(serde_json::to_value(receipt).unwrap_or_default());
                published_to_bns = true;
            }
            let doc_string = if params.did_document.is_null() {
                String::new()
            } else {
                params.did_document.to_string()
            };
            let mut hasher = sha2::Sha256::new();
            hasher.update(doc_string.as_bytes());
            let obj_id = hex::encode(hasher.finalize());
            if !published_to_bns {
                server
                    .compat_store()
                    .insert_user_did_document(
                        obj_id.as_str(),
                        username.as_str(),
                        params.obj_name.as_str(),
                        doc_string.as_str(),
                        Some(doc_type.as_str()),
                    )
                    .await
                    .into_rpc()?;
            }
            ok_response(
                &req,
                json!({
                    "code": 0,
                    "obj_id": obj_id,
                    "doc_type": doc_type,
                    "bns_receipt": bns_receipt,
                }),
            )
        }
        "get_document" => {
            let params: GetDidDocumentReq = parse_params(&req)?;
            let username = if let Some(name) = params.name {
                normalize_username(name.as_str())?
            } else {
                require_account_username(server, &req).await?
            };
            let doc = server
                .compat_store()
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
