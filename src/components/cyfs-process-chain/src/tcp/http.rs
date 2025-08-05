use super::stream::PrefixedStream;
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::cmd::*;
use crate::collection::CollectionValue;
use buckyos_kit::AsyncStream;
use clap::Command;
use httparse::{EMPTY_HEADER, Request, Status};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

/*
GET /some/path HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: ...\r\n
...Other Headers...\r\n
\r\n
<Optional Body>
*/
#[derive(Debug, Clone)]
struct ProbeHeaders {
    method: String,
    version: String,
    path: String,

    // Must be present at HTTP 1.1, but maybe absent in HTTP 1.0
    host: Option<String>,
}

struct ProbeResult {
    stream: Box<dyn AsyncStream>,
    headers: Option<ProbeHeaders>,
}

struct HttpProbe;

impl HttpProbe {
    pub async fn process_stream(mut stream: Box<dyn AsyncStream>) -> Result<ProbeResult, String> {
        let mut buffer = vec![0; 4096];
        let bytes_read = stream.read(&mut buffer).await.map_err(|e| {
            let msg = format!("Failed to read from stream: {}", e);
            error!("{}", msg);
            msg
        })?;

        if bytes_read == 0 {
            let msg = "No data read from stream".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        // Extract SNI from the buffer
        let headers = Self::extract_headers(&buffer[..bytes_read]);

        let prefix_stream = PrefixedStream::new(buffer[..bytes_read].to_vec(), stream);

        let stream = Box::new(prefix_stream) as Box<dyn AsyncStream>;
        let result = ProbeResult { stream, headers };

        Ok(result)
    }

    // Parse some necessary headers from the buffer
    fn extract_headers(buffer: &[u8]) -> Option<ProbeHeaders> {
        let mut headers = [EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);

        match req.parse(buffer) {
            Ok(Status::Complete(_)) => {
                let method = req.method?.to_string();
                let path = req.path?.to_string();
                let version = format!("1.{}", req.version.unwrap_or(1)); // e.g. 1.1

                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .map(|h| String::from_utf8_lossy(h.value).into_owned());

                Some(ProbeHeaders {
                    method,
                    version,
                    path,
                    host,
                })
            }
            _ => None,
        }
    }
}

pub struct HttpProbeCommand {
    name: String,
    cmd: Command,
}

impl HttpProbeCommand {
    pub fn new() -> Self {
        let name = "http-probe".to_string();
        let cmd = Command::new(&name)
            .about("Probe an incoming HTTP stream to extract method, path, version, and host.")
            .after_help(
                r#"
Attempts to probe an incoming plaintext HTTP stream to extract key request line and header information.

Usage:
  http-probe

Behavior:
  - This command reads the beginning of an incoming stream to determine whether it contains a valid HTTP request.
  - If valid, it extracts the following information and updates the environment:
      $REQ.method       ← HTTP method (e.g., GET, POST)
      $REQ.path         ← Request path (e.g., /index.html)
      $REQ.version      ← HTTP version string (e.g., HTTP/1.1)
      $REQ.dest_host    ← Host from the `Host:` header
      $REQ.app_protocol ← "http"
      $REQ.url          ← Full URL constructed from the host and path
  - Returns success(host) if parsing is successful and a host is found.
  - Returns error if the request is invalid or a Host: header is missing (required for HTTP/1.1).

Requirements:
  - The variable $REQ.incoming_stream must be present in the environment.
    It must be of type AsyncStream.

Examples:
  http-probe && match $REQ.dest_host "api.example.com" && accept
  http-probe && match $REQ.path "/admin/*" && drop
"#,
            );

        Self { cmd, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl ExternalCommand for HttpProbeCommand {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid command arguments: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        _args: &[CollectionValue],
        _origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let ret = context.env().get("REQ", None).await?;
        if ret.is_none() {
            let msg = "No $REQ found in the environment".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let req = ret.unwrap();
        let req = req.as_map();
        if req.is_none() {
            let msg = "$REQ is not a map".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let req = req.unwrap();
        let stream = req.get("incoming_stream").await?;
        if stream.is_none() {
            let msg = "No incoming stream found in $REQ".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let stream = stream.unwrap();
        let ret = stream.to_any_type();
        if ret.is_none() {
            let msg = "Incoming stream is not of type Any".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let slot: Arc<Mutex<Option<Box<dyn AsyncStream>>>> = ret.unwrap();
        let stream = slot.lock().unwrap().take();
        if stream.is_none() {
            let msg = "Incoming stream is None".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_value(msg));
        }

        let stream = stream.unwrap();
        let ret = HttpProbe::process_stream(stream).await.map_err(|e| {
            let msg = format!("Failed to process stream: {}", e);
            error!("{}", msg);
            msg
        })?;

        let host;
        if let Some(headers) = ret.headers {
            info!("HTTP header found: {:?}", headers);

            /*
            // Update the method, path, version, and host in the request
            req.insert("method", CollectionValue::String(headers.method))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert method into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;

            req.insert("version", CollectionValue::String(headers.version))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert version into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;
            */

            if let Some(value) = headers.host {
                host = Some(value.clone());

                /*
                let url = format!("http://{}{}", value, headers.path);
                req.insert("url", CollectionValue::String(url))
                    .await
                    .map_err(|e| {
                        let msg = format!("Failed to insert url into request: {}", e);
                        error!("{}", msg);
                        msg
                    })?;

                */

                req.insert("dest_host", CollectionValue::String(value))
                    .await
                    .map_err(|e| {
                        let msg = format!("Failed to insert dest_host into request: {}", e);
                        error!("{}", msg);
                        msg
                    })?;
            } else {
                warn!("No Host header found in the request, may not be valid HTTP/1.1");
                host = Some("".to_string());
            }

            /*
            req.insert("path", CollectionValue::String(headers.path))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert path into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;
            */

            // Update the protocol to HTTPS
            req.insert("app_protocol", CollectionValue::String("http".to_string()))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert app_protocol into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;
        } else {
            info!("No valid HTTP headers found in the stream");
            host = None;
        }

        // Update the slot with the processed stream
        {
            let mut slot = slot.lock().unwrap();
            *slot = Some(ret.stream);
        }

        match host {
            Some(value) => Ok(CommandResult::success_with_value(value)),
            None => Ok(CommandResult::error()),
        }
    }
}
