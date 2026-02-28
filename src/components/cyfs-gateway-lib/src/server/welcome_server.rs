use http::{StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use crate::{HttpServer, ServerError, ServerResult, StreamInfo};

const WELCOME_HTML: &[u8] = br#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Welcome to Cyfs-Gateway</title>
  <style>
    body {
      width: 60em;
      margin: 0 auto;
      padding: 0;
      font-family: "Trebuchet MS", Verdana, Arial, sans-serif;
      background: #f4f6f8;
      color: #333;
    }
    .container {
      margin: 6em auto;
      padding: 3em 4em;
      background: #fff;
      border: 1px solid #d9d9d9;
      border-radius: 6px;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06);
    }
    h1 {
      color: #0f4c81;
      font-weight: 600;
      margin-top: 0;
    }
    p {
      line-height: 1.6;
    }
    ul {
      padding-left: 1.2em;
    }
    code {
      background: #f1f1f1;
      padding: 2px 4px;
      border-radius: 3px;
    }
    .footer {
      margin-top: 2em;
      font-size: 0.9em;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Welcome to Cyfs-Gateway</h1>
    <p>
      Cyfs-Gateway is a programmable network gateway for the CYFS stack. It routes,
      forwards, and transforms traffic through configurable stacks and process chains.
    </p>
    <p>Common uses include:</p>
    <ul>
      <li>HTTP and TCP routing with policy-driven rules</li>
      <li>Protocol bridging and traffic inspection</li>
      <li>Service exposure with built-in control and security features</li>
    </ul>
    <p>
      This page is served by the built-in welcome server to confirm the gateway is running.
    </p>
    <div class="footer">
      <p>Customize behavior in your gateway configuration files or control server.</p>
    </div>
  </div>
</body>
</html>
"#;

pub struct WelcomeServer;

impl WelcomeServer {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl HttpServer for WelcomeServer {
    async fn serve_request(
        &self,
        _req: http::Request<BoxBody<Bytes, ServerError>>,
        _info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", WELCOME_HTML.len())
            .body(
                Full::new(Bytes::from_static(WELCOME_HTML))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .unwrap())
    }

    fn id(&self) -> String {
        "welcome".to_string()
    }

    fn http_version(&self) -> Version {
        Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}
