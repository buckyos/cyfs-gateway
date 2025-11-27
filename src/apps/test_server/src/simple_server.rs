use async_trait::async_trait;
use bytes::Bytes;
use cyfs_gateway_lib::{HttpServer, ServerError, ServerResult, StreamInfo};
use http::{Response, StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use log::info;

#[derive(Default)]
pub struct SimpleHttpServer;

impl SimpleHttpServer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl HttpServer for SimpleHttpServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let body = format!(
            "test_server says hello!\nmethod: {}\npath: {}\nsrc: {}\n",
            req.method(),
            req.uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
            info.src_addr.unwrap_or_else(|| "unknown".into()),
        );

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
            .map_err(|e| {
                cyfs_gateway_lib::server_err!(
                    cyfs_gateway_lib::ServerErrorCode::EncodeError,
                    "build response failed: {e}"
                )
            })?;

        info!("served request {}", response.status());
        Ok(response)
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
