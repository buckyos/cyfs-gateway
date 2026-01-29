use async_trait::async_trait;
use bytes::Bytes;
use cyfs_gateway_lib::{serve_http_by_rpc_handler, HttpServer, ServerError, ServerResult, StreamInfo};
use http::{Method, Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use log::info;
use std::net::IpAddr;

use ::kRPC::{RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use serde_json::json;

#[derive(Default, Clone)]
pub struct SimpleHttpServer;

impl SimpleHttpServer {
    pub fn new() -> Self {
        Self
    }
}


#[async_trait]
impl RPCHandler for SimpleHttpServer {
    async fn handle_rpc_call(&self, req: RPCRequest, _client_ip: IpAddr) -> Result<RPCResponse, RPCErrors> {
        info!("|==>recv kRPC req: {:?}", req);
        Ok(RPCResponse::create_by_req(
            RPCResult::Success(json!({ "ok": true })),
            &req,
        ))
    }
}


#[async_trait]
impl HttpServer for SimpleHttpServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        if *req.method() == Method::POST {
            return serve_http_by_rpc_handler(req, info, self).await;
        }

        let body = format!(
            "test_server says hello!\nmethod: {}\npath: {}\nsrc: {}\n",
            req.method(),
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
            info.src_addr.clone().unwrap_or_else(|| "unknown".into()),
        );

        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed())
            .map_err(|e| {
                cyfs_gateway_lib::server_err!(
                    cyfs_gateway_lib::ServerErrorCode::EncodeError,
                    "build response failed: {e}"
                )
            })?;

        info!("served request {}", resp.status());
        Ok(resp)
    }

    fn id(&self) -> String {
        "test-server".to_string()
    }

    fn http_version(&self) -> Version {
        Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}
