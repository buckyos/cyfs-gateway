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
        if pos < buffer.len() {
            let comp_len = buffer[pos] as usize;
            pos += 1 + comp_len;
        }

        // Parse Extensions
        if pos + 2 <= buffer.len() {
            let extensions_len = ((buffer[pos] as usize) << 8) | (buffer[pos + 1] as usize);
            pos += 2;
            // A single stream read may contain only part of the ClientHello.
            // Never trust the declared length beyond the bytes actually read.
            let extensions_end = (pos + extensions_len).min(buffer.len());

            while pos + 4 <= extensions_end {
                let ext_type = ((buffer[pos] as u16) << 8) | (buffer[pos + 1] as u16);
                let ext_len = ((buffer[pos + 2] as usize) << 8) | (buffer[pos + 3] as usize);
                pos += 4;

                let extension_end = pos + ext_len;
                if extension_end > extensions_end {
                    return None;
                }

                // SNI extension type is 0
                if ext_type == 0 {
                    let extension = &buffer[pos..extension_end];
                    if extension.len() <= 5 {
                        return None;
                    }

                    // Only host_name (type 0) is supported. Its list and hostname
                    // must fit inside this extension, not merely inside the buffer.
                    let names_len = ((extension[0] as usize) << 8) | extension[1] as usize;
                    let sni_len = ((extension[3] as usize) << 8) | extension[4] as usize;
                    if names_len + 2 != ext_len
                        || extension[2] != 0
                        || sni_len == 0
                        || sni_len + 3 != names_len
                    {
                        return None;
                    }

                    return String::from_utf8(extension[5..].to_vec()).ok();
                }
                pos = extension_end;
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

impl Default for HttpsSniProbeCommand {
    fn default() -> Self {
        Self::new()
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
            return Ok(CommandResult::error_with_string(msg));
        }

        let req = ret.unwrap();
        let req = req.as_map();
        if req.is_none() {
            let msg = "$REQ is not a map".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_string(msg));
        }

        let req = req.unwrap();
        let stream = req.get("incoming_stream").await?;
        if stream.is_none() {
            let msg = "No incoming stream found in $REQ".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_string(msg));
        }

        let stream = stream.unwrap();
        let ret = stream.to_any_type();
        if ret.is_none() {
            let msg = "Incoming stream is not of type Any".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_string(msg));
        }

        let slot: Arc<Mutex<Option<Box<dyn AsyncStream>>>> = ret.unwrap();
        let stream = slot.lock().unwrap().take();
        if stream.is_none() {
            let msg = "Incoming stream is None".to_string();
            error!("{}", msg);
            return Ok(CommandResult::error_with_string(msg));
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
            Some(sni) => Ok(CommandResult::success_with_string(sni)),
            None => Ok(CommandResult::error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0; 32]); // Random
        hello.push(0); // Session ID length
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // Cipher suites
        hello.extend_from_slice(&[1, 0]); // Compression methods
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(extensions);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
        record.push(1); // ClientHello
        record.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&hello);
        record
    }

    fn sni_extension(host: &[u8]) -> Vec<u8> {
        let mut extension = vec![0, 0]; // server_name
        extension.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        extension.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        extension.push(0); // host_name
        extension.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extension.extend_from_slice(host);
        extension
    }

    fn issue_35_truncated_client_hello() -> Vec<u8> {
        let mut extensions = vec![0; 1610];
        // Skipping this incomplete extension used to read buffer[1657].
        extensions[..4].copy_from_slice(&[0, 10, 0x06, 0x41]);
        let mut hello = client_hello(&extensions);
        hello.truncate(1340);
        hello
    }

    #[test]
    fn test_extract_sni_valid_client_hello() {
        let mut extensions = vec![0, 10, 0, 2, 0, 0];
        extensions.extend_from_slice(&sni_extension(b"buckyos.com"));
        let hello = client_hello(&extensions);
        assert_eq!(
            HttpsSniProbe::extract_sni(&hello).as_deref(),
            Some("buckyos.com")
        );
    }

    #[test]
    fn test_extract_sni_before_truncated_later_extension() {
        let mut extensions = sni_extension(b"buckyos.com");
        extensions.extend_from_slice(&[0, 10, 0, 2, 0, 0]);
        let mut hello = client_hello(&extensions);
        hello.truncate(hello.len() - 1);
        assert_eq!(
            HttpsSniProbe::extract_sni(&hello).as_deref(),
            Some("buckyos.com")
        );
    }

    #[test]
    fn test_extract_sni_issue_35_truncated_extension() {
        assert_eq!(
            HttpsSniProbe::extract_sni(&issue_35_truncated_client_hello()),
            None
        );
    }

    #[test]
    fn test_extract_sni_all_truncated_prefixes() {
        let mut extensions = vec![0, 10, 0, 2, 0, 0];
        extensions.extend_from_slice(&sni_extension(b"buckyos.com"));
        let hello = client_hello(&extensions);
        for end in 0..hello.len() {
            assert_eq!(
                HttpsSniProbe::extract_sni(&hello[..end]),
                None,
                "prefix length {end}"
            );
        }
    }

    #[test]
    fn test_extract_sni_truncated_extension_header() {
        let extensions_start = client_hello(&[]).len();
        for header_len in 0..4 {
            let mut hello = client_hello(&[0, 10, 0, 0]);
            hello.truncate(extensions_start + header_len);
            assert_eq!(HttpsSniProbe::extract_sni(&hello), None);
        }
    }

    #[test]
    fn test_extract_sni_respects_extensions_length() {
        let mut hello = client_hello(&sni_extension(b"buckyos.com"));
        let extensions_start = client_hello(&[]).len();
        // Bytes after the declared extension list must not become the hostname.
        hello[extensions_start - 2..extensions_start].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(HttpsSniProbe::extract_sni(&hello), None);
    }

    #[test]
    fn test_extract_sni_respects_sni_extension_length() {
        let mut extension = sni_extension(b"buckyos.com");
        // The hostname extends beyond this extension into subsequent bytes.
        extension[2..4].copy_from_slice(&6u16.to_be_bytes());
        assert_eq!(HttpsSniProbe::extract_sni(&client_hello(&extension)), None);
    }

    #[test]
    fn test_extract_sni_rejects_invalid_server_name_lengths() {
        for list_len in [0u16, 2, 13, 15, u16::MAX] {
            let mut extension = sni_extension(b"buckyos.com");
            extension[4..6].copy_from_slice(&list_len.to_be_bytes());
            assert_eq!(HttpsSniProbe::extract_sni(&client_hello(&extension)), None);
        }
        for host_len in [0u16, 10, 12, u16::MAX] {
            let mut extension = sni_extension(b"buckyos.com");
            extension[7..9].copy_from_slice(&host_len.to_be_bytes());
            assert_eq!(HttpsSniProbe::extract_sni(&client_hello(&extension)), None);
        }
    }

    #[test]
    fn test_extract_sni_rejects_invalid_server_name() {
        let mut extension = sni_extension(b"buckyos.com");
        extension[6] = 1; // Unsupported name type
        assert_eq!(HttpsSniProbe::extract_sni(&client_hello(&extension)), None);
        for host in [b"".as_slice(), b"\xff".as_slice()] {
            assert_eq!(
                HttpsSniProbe::extract_sni(&client_hello(&sni_extension(host))),
                None
            );
        }
    }

    #[test]
    fn test_extract_sni_without_sni() {
        for hello in [
            Vec::new(),
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            client_hello(&[]),
            client_hello(&[0, 10, 0, 0]),
        ] {
            assert_eq!(HttpsSniProbe::extract_sni(&hello), None);
        }
    }

    #[tokio::test]
    async fn test_process_stream_preserves_bytes() {
        for (hello, expected_sni) in [
            (
                client_hello(&sni_extension(b"buckyos.com")),
                Some("buckyos.com"),
            ),
            (issue_35_truncated_client_hello(), None),
        ] {
            let mut result = HttpsSniProbe::process_stream(Box::new(Cursor::new(hello.clone())))
                .await
                .unwrap();
            assert_eq!(result.sni.as_deref(), expected_sni);
            let mut replayed = Vec::new();
            result.stream.read_to_end(&mut replayed).await.unwrap();
            assert_eq!(replayed, hello);
        }
    }
}
