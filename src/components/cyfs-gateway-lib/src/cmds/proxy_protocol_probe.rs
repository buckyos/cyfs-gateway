use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use buckyos_kit::AsyncStream;
use clap::Command;
use cyfs_process_chain::{
    CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, ExternalCommand,
    MapCollectionRef, MemoryMapCollection, PrefixedStream, command_help,
};
use tokio::io::AsyncReadExt;

const CMD_PROXY_PROTOCOL_PROBE_NAME: &str = "proxy-protocol-probe";
const MAX_READ_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy)]
enum ProxyVersion {
    V1,
    V2,
}

impl ProxyVersion {
    fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

struct ProbeResult {
    stream: Box<dyn AsyncStream>,
    version: Option<ProxyVersion>,
    source_addr: Option<SocketAddr>,
    dest_addr: Option<SocketAddr>,
}

struct ProxyProtocolProbe;

impl ProxyProtocolProbe {
    async fn process_stream(mut stream: Box<dyn AsyncStream>) -> Result<ProbeResult, String> {
        let mut buffer = vec![0u8; MAX_READ_SIZE];
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

        let data = &buffer[..bytes_read];
        let parsed = parse_proxy_protocol(data);

        let (consumed, version, source_addr, dest_addr) = match parsed {
            Some((consumed, version, source_addr, dest_addr)) => {
                (consumed, Some(version), source_addr, dest_addr)
            }
            None => (0, None, None, None),
        };

        let prefix_stream = PrefixedStream::new(data[consumed..].to_vec(), stream);
        Ok(ProbeResult {
            stream: Box::new(prefix_stream),
            version,
            source_addr,
            dest_addr,
        })
    }
}

fn parse_proxy_protocol(data: &[u8]) -> Option<(usize, ProxyVersion, Option<SocketAddr>, Option<SocketAddr>)> {
    if let Some(parsed) = parse_proxy_v2(data) {
        return Some(parsed);
    }

    parse_proxy_v1(data)
}

fn parse_proxy_v1(data: &[u8]) -> Option<(usize, ProxyVersion, Option<SocketAddr>, Option<SocketAddr>)> {
    if !data.starts_with(b"PROXY ") {
        return None;
    }

    let header_end = data.windows(2).position(|w| w == b"\r\n")? + 2;
    let line = std::str::from_utf8(&data[..header_end - 2]).ok()?;
    let mut parts = line.split_whitespace();

    if parts.next()? != "PROXY" {
        return None;
    }

    let protocol = parts.next()?;
    if protocol.eq_ignore_ascii_case("UNKNOWN") {
        return Some((header_end, ProxyVersion::V1, None, None));
    }

    let src_ip: IpAddr = parts.next()?.parse().ok()?;
    let dst_ip: IpAddr = parts.next()?.parse().ok()?;
    let src_port: u16 = parts.next()?.parse().ok()?;
    let dst_port: u16 = parts.next()?.parse().ok()?;

    let source_addr = SocketAddr::new(src_ip, src_port);
    let dest_addr = SocketAddr::new(dst_ip, dst_port);
    Some((
        header_end,
        ProxyVersion::V1,
        Some(source_addr),
        Some(dest_addr),
    ))
}

fn parse_proxy_v2(data: &[u8]) -> Option<(usize, ProxyVersion, Option<SocketAddr>, Option<SocketAddr>)> {
    const SIG: [u8; 12] = [
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
    ];

    if data.len() < 16 || !data.starts_with(&SIG) {
        return None;
    }

    let ver_cmd = data[12];
    if (ver_cmd >> 4) != 0x2 {
        return None;
    }

    let fam_proto = data[13];
    let len = u16::from_be_bytes([data[14], data[15]]) as usize;
    if data.len() < 16 + len {
        return None;
    }

    let cmd = ver_cmd & 0x0f;
    if cmd != 0x1 {
        return Some((16 + len, ProxyVersion::V2, None, None));
    }

    let family = fam_proto >> 4;
    let addresses = &data[16..16 + len];
    match family {
        0x1 => {
            if addresses.len() < 12 {
                return None;
            }

            let src_ip = IpAddr::from([addresses[0], addresses[1], addresses[2], addresses[3]]);
            let dst_ip = IpAddr::from([addresses[4], addresses[5], addresses[6], addresses[7]]);
            let src_port = u16::from_be_bytes([addresses[8], addresses[9]]);
            let dst_port = u16::from_be_bytes([addresses[10], addresses[11]]);

            Some((
                16 + len,
                ProxyVersion::V2,
                Some(SocketAddr::new(src_ip, src_port)),
                Some(SocketAddr::new(dst_ip, dst_port)),
            ))
        }
        0x2 => {
            if addresses.len() < 36 {
                return None;
            }

            let src_ip = IpAddr::from(<[u8; 16]>::try_from(&addresses[0..16]).ok()?);
            let dst_ip = IpAddr::from(<[u8; 16]>::try_from(&addresses[16..32]).ok()?);
            let src_port = u16::from_be_bytes([addresses[32], addresses[33]]);
            let dst_port = u16::from_be_bytes([addresses[34], addresses[35]]);

            Some((
                16 + len,
                ProxyVersion::V2,
                Some(SocketAddr::new(src_ip, src_port)),
                Some(SocketAddr::new(dst_ip, dst_port)),
            ))
        }
        _ => Some((16 + len, ProxyVersion::V2, None, None)),
    }
}

pub struct ProxyProtocolProbeCommand {
    cmd: Command,
}

impl ProxyProtocolProbeCommand {
    pub fn new() -> Self {
        let cmd = Command::new(CMD_PROXY_PROTOCOL_PROBE_NAME)
            .about("Probe incoming stream for PROXY protocol v1/v2")
            .after_help(
                r#"
Detect whether an incoming stream starts with PROXY protocol header.

Behavior:
  - Reads a small prefix from $REQ.incoming_stream
  - Detects PROXY protocol v1/v2
  - Removes the PROXY header bytes from stream for downstream processing
  - Writes probe result to $REQ.ext:
      $REQ.ext.proxy_protocol      = v1|v2
      $REQ.ext.proxy_source_addr   = source ip:port
      $REQ.ext.proxy_dest_addr     = dest ip:port
  - Updates $REQ.source_addr when source_addr is available
  - Returns success(version) when detected, otherwise returns error
"#,
            );

        Self { cmd }
    }

    pub fn name(&self) -> &str {
        CMD_PROXY_PROTOCOL_PROBE_NAME
    }

    async fn ensure_req_ext(req: MapCollectionRef) -> Result<MapCollectionRef, String> {
        match req.get("ext").await? {
            Some(CollectionValue::Map(ext)) => Ok(ext),
            _ => {
                let ext = MemoryMapCollection::new_ref();
                req.insert("ext", CollectionValue::Map(ext.clone())).await?;
                Ok(ext)
            }
        }
    }
}

#[async_trait::async_trait]
impl ExternalCommand for ProxyProtocolProbeCommand {
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
        let req = context.env().get("REQ", None).await?;
        let req = match req.and_then(|v| v.into_map()) {
            Some(req) => req,
            None => {
                let msg = "No $REQ map found in environment".to_string();
                error!("{}", msg);
                return Ok(CommandResult::error_with_value(msg));
            }
        };

        let stream_value = req.get("incoming_stream").await?;
        let stream_value = match stream_value {
            Some(v) => v,
            None => {
                let msg = "No incoming stream found in $REQ".to_string();
                error!("{}", msg);
                return Ok(CommandResult::error_with_value(msg));
            }
        };

        let slot: Arc<Mutex<Option<Box<dyn AsyncStream>>>> = match stream_value.to_any_type() {
            Some(slot) => slot,
            None => {
                let msg = "Incoming stream is not AnyType".to_string();
                error!("{}", msg);
                return Ok(CommandResult::error_with_value(msg));
            }
        };

        let stream = match slot.lock().unwrap().take() {
            Some(stream) => stream,
            None => {
                let msg = "Incoming stream is None".to_string();
                error!("{}", msg);
                return Ok(CommandResult::error_with_value(msg));
            }
        };

        let probe_result = ProxyProtocolProbe::process_stream(stream).await?;

        {
            let mut guard = slot.lock().unwrap();
            *guard = Some(probe_result.stream);
        }

        let version = match probe_result.version {
            Some(version) => version,
            None => return Ok(CommandResult::error()),
        };

        let ext = Self::ensure_req_ext(req.clone()).await?;
        ext.insert(
            "proxy_protocol",
            CollectionValue::String(version.as_str().to_string()),
        )
        .await?;

        if let Some(source_addr) = probe_result.source_addr {
            ext.insert(
                "proxy_source_addr",
                CollectionValue::String(source_addr.to_string()),
            )
            .await?;
            req.insert(
                "source_addr",
                CollectionValue::String(source_addr.to_string()),
            )
            .await?;
        }

        if let Some(dest_addr) = probe_result.dest_addr {
            ext.insert(
                "proxy_dest_addr",
                CollectionValue::String(dest_addr.to_string()),
            )
            .await?;
        }

        Ok(CommandResult::success_with_value(version.as_str()))
    }
}
