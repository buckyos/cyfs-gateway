use super::stream::PrefixedStream;
use crate::block::CommandArgs;
use crate::chain::Context;
use crate::cmd::*;
use crate::collection::CollectionValue;
use buckyos_kit::AsyncStream;
use clap::Command;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;

struct ProbeResult {
    stream: Box<dyn AsyncStream>,
    sni: Option<String>,
}
struct HttpsSniProbe;

impl HttpsSniProbe {
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
        let sni = Self::extract_sni(&buffer[..bytes_read]);

        let prefix_stream = PrefixedStream::new(buffer[..bytes_read].to_vec(), stream);

        let stream = Box::new(prefix_stream) as Box<dyn AsyncStream>;
        let result = ProbeResult { stream, sni };

        Ok(result)
    }

    // Parse the SNI from TLS Client Hello
    fn extract_sni(buffer: &[u8]) -> Option<String> {
        // Check if the buffer is a valid TLS Client Hello message
        // TLS Client Hello starts with 0x16 (handshake) and version 0x0301 (TLS 1.0)
        if buffer.len() < 5 || buffer[0] != 0x16 || buffer[1] != 0x03 {
            return None;
        }

        // TLS Client Hello has a fixed header length of 43 bytes
        let mut pos = 43;
        if buffer.len() <= pos {
            return None;
        }

        // Skip Session ID
        if pos < buffer.len() {
            let session_id_len = buffer[pos] as usize;
            pos += 1 + session_id_len;
        }

        // Skip Cipher Suites
        if pos + 2 <= buffer.len() {
            let cipher_len = ((buffer[pos] as usize) << 8) | (buffer[pos + 1] as usize);
            pos += 2 + cipher_len;
        }

        // Skip Compression Methods
        if pos + 1 <= buffer.len() {
            let comp_len = buffer[pos] as usize;
            pos += 1 + comp_len;
        }

        // Parse Extensions
        if pos + 2 <= buffer.len() {
            let extensions_len = ((buffer[pos] as usize) << 8) | (buffer[pos + 1] as usize);
            pos += 2;
            let extensions_end = pos + extensions_len;

            while pos + 4 <= extensions_end {
                let ext_type = ((buffer[pos] as u16) << 8) | (buffer[pos + 1] as u16);
                let ext_len = ((buffer[pos + 2] as usize) << 8) | (buffer[pos + 3] as usize);
                pos += 4;

                // SNI extension type is 0
                if ext_type == 0 && pos + ext_len <= buffer.len() {
                    // Parse SNI content
                    if ext_len > 5 {
                        let sni_len =
                            ((buffer[pos + 3] as usize) << 8) | (buffer[pos + 4] as usize);
                        if pos + 5 + sni_len <= buffer.len() {
                            return String::from_utf8(buffer[pos + 5..pos + 5 + sni_len].to_vec())
                                .ok();
                        }
                    }
                }
                pos += ext_len;
            }
        }
        None
    }
}

pub struct HttpsSniProbeCommand {
    name: String,
    cmd: Command,
}

impl HttpsSniProbeCommand {
    pub fn new() -> Self {
        let name = "https-sni-probe".to_string();
        let cmd = Command::new(&name)
            .about("Probe TLS Client Hello SNI")
            .after_help(
                r#"
Attempts to probe the SNI (Server Name Indication) from an incoming TLS stream.

Usage:
  https-sni-probe

Behavior:
  - This command inspects the beginning of an incoming stream to determine whether
    it is a valid HTTPS connection.
  - If the connection is HTTPS and contains a valid SNI field, the SNI hostname will
    be extracted and used to update the environment as follows:
      $REQ.dest_host     ← extracted hostname
      $REQ.app_protocol  ← "https"
  - Returns success(host) if an SNI hostname is successfully parsed.
  - Returns error if the connection is not HTTPS or no SNI is found.

Requirements:
  - The variable $REQ.incoming_stream must be present in the environment.
    It must be of type AsyncStream.

Examples:
  https-sni-probe && accept

"#,
            );

        Self { cmd, name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[async_trait::async_trait]
impl ExternalCommand for HttpsSniProbeCommand {
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
        let ret = HttpsSniProbe::process_stream(stream).await.map_err(|e| {
            let msg = format!("Failed to process stream: {}", e);
            error!("{}", msg);
            msg
        })?;

        if let Some(sni) = &ret.sni {
            info!("SNI found: {}", sni);

            // Update the request with the SNI
            req.insert("dest_host", CollectionValue::String(sni.clone()))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert SNI into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;

            // Update the protocol to HTTPS
            req.insert("app_protocol", CollectionValue::String("https".to_string()))
                .await
                .map_err(|e| {
                    let msg = format!("Failed to insert app_protocol into request: {}", e);
                    error!("{}", msg);
                    msg
                })?;
        } else {
            info!("No SNI found in the stream");
        }

        // Update the slot with the processed stream
        {
            let mut slot = slot.lock().unwrap();
            *slot = Some(ret.stream);
        }

        match ret.sni {
            Some(sni) => Ok(CommandResult::success_with_value(sni)),
            None => Ok(CommandResult::error()),
        }
    }
}
