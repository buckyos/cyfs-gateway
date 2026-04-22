use crate::{StackErrorCode, StackResult, into_stack_err, stack_err};
use buckyos_kit::AsyncStream;
use cyfs_process_chain::PrefixedStream;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_PROXY_READ_SIZE: usize = 4096;
const PROXY_V1_PREFIX: &[u8; 6] = b"PROXY ";
pub(crate) const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

#[derive(Debug, Clone, Copy)]
pub(crate) enum ProxyProbeResult {
    NeedMore,
    NotProxy,
    Matched {
        consumed: usize,
        source_addr: Option<SocketAddr>,
    },
}

/// Probe the inbound stream for a PROXY protocol (v1/v2) header and strip it.
///
/// Returns a stream that replays any non-header bytes already read, plus the
/// parsed source address when a PROXY header was successfully detected.
pub async fn probe_proxy_protocol_stream(
    mut stream: Box<dyn AsyncStream>,
) -> StackResult<(Box<dyn AsyncStream>, Option<SocketAddr>)> {
    let mut buffer = vec![0u8; MAX_PROXY_READ_SIZE];
    let mut total = 0usize;
    let mut consumed = 0usize;
    let mut source_addr = None;

    loop {
        if total >= MAX_PROXY_READ_SIZE {
            break;
        }

        let read = stream
            .read(&mut buffer[total..])
            .await
            .map_err(into_stack_err!(
                StackErrorCode::StreamError,
                "read stream for proxy protocol failed"
            ))?;

        if read == 0 {
            if total == 0 {
                return Err(stack_err!(
                    StackErrorCode::StreamError,
                    "read stream for proxy protocol failed: early eof"
                ));
            }
            break;
        }

        total += read;

        match parse_proxy_protocol(&buffer[..total]) {
            ProxyProbeResult::Matched {
                consumed: parsed,
                source_addr: parsed_source,
            } => {
                consumed = parsed;
                source_addr = parsed_source;
                break;
            }
            ProxyProbeResult::NotProxy => break,
            ProxyProbeResult::NeedMore => {
                if total >= MAX_PROXY_READ_SIZE {
                    break;
                }
            }
        }
    }

    let prefixed_stream = PrefixedStream::new(buffer[consumed..total].to_vec(), stream);
    Ok((Box::new(prefixed_stream), source_addr))
}

pub(crate) fn parse_proxy_protocol(data: &[u8]) -> ProxyProbeResult {
    match parse_proxy_v2(data) {
        ProxyProbeResult::NotProxy => parse_proxy_v1(data),
        ret => ret,
    }
}

fn parse_proxy_v2(data: &[u8]) -> ProxyProbeResult {
    let check_len = data.len().min(PROXY_V2_SIGNATURE.len());
    if data[..check_len] != PROXY_V2_SIGNATURE[..check_len] {
        return ProxyProbeResult::NotProxy;
    }

    if data.len() < PROXY_V2_SIGNATURE.len() {
        return ProxyProbeResult::NeedMore;
    }

    if data.len() < 16 {
        return ProxyProbeResult::NeedMore;
    }

    let ver_cmd = data[12];
    if (ver_cmd >> 4) != 0x2 {
        return ProxyProbeResult::NotProxy;
    }

    let fam_proto = data[13];
    let len = u16::from_be_bytes([data[14], data[15]]) as usize;
    if data.len() < 16 + len {
        return ProxyProbeResult::NeedMore;
    }

    let cmd = ver_cmd & 0x0f;
    if cmd != 0x1 {
        return ProxyProbeResult::Matched {
            consumed: 16 + len,
            source_addr: None,
        };
    }

    let family = fam_proto >> 4;
    let addresses = &data[16..16 + len];
    let source_addr = match family {
        0x1 => {
            if addresses.len() < 12 {
                return ProxyProbeResult::NotProxy;
            }

            let src_ip = IpAddr::from([addresses[0], addresses[1], addresses[2], addresses[3]]);
            let src_port = u16::from_be_bytes([addresses[8], addresses[9]]);
            Some(SocketAddr::new(src_ip, src_port))
        }
        0x2 => {
            if addresses.len() < 36 {
                return ProxyProbeResult::NotProxy;
            }

            let src_ip = match <[u8; 16]>::try_from(&addresses[0..16]) {
                Ok(v) => IpAddr::from(v),
                Err(_) => return ProxyProbeResult::NotProxy,
            };
            let src_port = u16::from_be_bytes([addresses[32], addresses[33]]);
            Some(SocketAddr::new(src_ip, src_port))
        }
        _ => None,
    };

    ProxyProbeResult::Matched {
        consumed: 16 + len,
        source_addr,
    }
}

fn parse_proxy_v1(data: &[u8]) -> ProxyProbeResult {
    let check_len = data.len().min(PROXY_V1_PREFIX.len());
    if data[..check_len] != PROXY_V1_PREFIX[..check_len] {
        return ProxyProbeResult::NotProxy;
    }

    if data.len() < PROXY_V1_PREFIX.len() {
        return ProxyProbeResult::NeedMore;
    }

    let header_end = match data.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => pos + 2,
        None => {
            if data.len() < MAX_PROXY_READ_SIZE {
                return ProxyProbeResult::NeedMore;
            }
            return ProxyProbeResult::NotProxy;
        }
    };

    let line = match std::str::from_utf8(&data[..header_end - 2]) {
        Ok(line) => line,
        Err(_) => return ProxyProbeResult::NotProxy,
    };

    let mut parts = line.split_whitespace();
    if parts.next() != Some("PROXY") {
        return ProxyProbeResult::NotProxy;
    }

    let protocol = match parts.next() {
        Some(protocol) => protocol,
        None => return ProxyProbeResult::NotProxy,
    };

    if protocol.eq_ignore_ascii_case("UNKNOWN") {
        return ProxyProbeResult::Matched {
            consumed: header_end,
            source_addr: None,
        };
    }

    let src_ip = match parts.next().and_then(|v| v.parse::<IpAddr>().ok()) {
        Some(ip) => ip,
        None => return ProxyProbeResult::NotProxy,
    };
    let _dst_ip = match parts.next().and_then(|v| v.parse::<IpAddr>().ok()) {
        Some(ip) => ip,
        None => return ProxyProbeResult::NotProxy,
    };
    let src_port = match parts.next().and_then(|v| v.parse::<u16>().ok()) {
        Some(port) => port,
        None => return ProxyProbeResult::NotProxy,
    };
    let _dst_port = match parts.next().and_then(|v| v.parse::<u16>().ok()) {
        Some(port) => port,
        None => return ProxyProbeResult::NotProxy,
    };

    ProxyProbeResult::Matched {
        consumed: header_end,
        source_addr: Some(SocketAddr::new(src_ip, src_port)),
    }
}

/// Encode a PROXY protocol v2 header for TCP over IPv4/IPv6.
///
/// When `src` and `dst` address families do not match, or either is not a
/// socket addr we can express, returns a LOCAL command header (no addresses)
/// so the receiver still consumes the prefix without propagating invalid data.
pub fn encode_proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(&PROXY_V2_SIGNATURE);

    match (src, dst) {
        (SocketAddr::V4(src4), SocketAddr::V4(dst4)) => {
            header.push(0x21); // version 2, PROXY command
            header.push(0x11); // AF_INET + STREAM
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&src4.ip().octets());
            header.extend_from_slice(&dst4.ip().octets());
            header.extend_from_slice(&src4.port().to_be_bytes());
            header.extend_from_slice(&dst4.port().to_be_bytes());
        }
        (SocketAddr::V6(src6), SocketAddr::V6(dst6)) => {
            header.push(0x21);
            header.push(0x21); // AF_INET6 + STREAM
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src6.ip().octets());
            header.extend_from_slice(&dst6.ip().octets());
            header.extend_from_slice(&src6.port().to_be_bytes());
            header.extend_from_slice(&dst6.port().to_be_bytes());
        }
        _ => {
            // Mismatched families — emit a LOCAL header so the receiver consumes
            // it but falls back to the underlying TCP peer address.
            header.push(0x20); // version 2, LOCAL command
            header.push(0x00); // AF_UNSPEC
            header.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    header
}

/// Write a PROXY v2 header at the head of the outbound stream, derived from
/// `src_addr` / `dst_addr`. If either address cannot be parsed as a SocketAddr,
/// no header is written and `Ok(false)` is returned so the caller can log.
pub async fn write_proxy_v2_preamble(
    stream: &mut Box<dyn AsyncStream>,
    src_addr: Option<&str>,
    dst_addr: Option<&str>,
) -> StackResult<bool> {
    let Some(src) = src_addr.and_then(|s| s.parse::<SocketAddr>().ok()) else {
        return Ok(false);
    };
    // Destination is informational; fall back to a zeroed same-family peer when unknown.
    let dst = dst_addr
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| match src {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::from([0u8; 16]), 0),
        });
    let header = encode_proxy_v2_header(src, dst);
    stream.write_all(&header).await.map_err(into_stack_err!(
        StackErrorCode::StreamError,
        "write proxy protocol header failed"
    ))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_v2_roundtrip_v4() {
        let src: SocketAddr = "1.2.3.4:1111".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:2222".parse().unwrap();
        let header = encode_proxy_v2_header(src, dst);
        match parse_proxy_protocol(&header) {
            ProxyProbeResult::Matched {
                consumed,
                source_addr,
            } => {
                assert_eq!(consumed, header.len());
                assert_eq!(source_addr, Some(src));
            }
            r => panic!("unexpected {:?}", r),
        }
    }

    #[test]
    fn proxy_v2_roundtrip_v6() {
        let src: SocketAddr = "[::1]:1111".parse().unwrap();
        let dst: SocketAddr = "[::2]:2222".parse().unwrap();
        let header = encode_proxy_v2_header(src, dst);
        match parse_proxy_protocol(&header) {
            ProxyProbeResult::Matched {
                consumed,
                source_addr,
            } => {
                assert_eq!(consumed, header.len());
                assert_eq!(source_addr, Some(src));
            }
            r => panic!("unexpected {:?}", r),
        }
    }

    #[test]
    fn proxy_v2_local_when_mismatched() {
        let src: SocketAddr = "1.2.3.4:1111".parse().unwrap();
        let dst: SocketAddr = "[::2]:2222".parse().unwrap();
        let header = encode_proxy_v2_header(src, dst);
        // LOCAL command -> Matched with no source addr
        match parse_proxy_protocol(&header) {
            ProxyProbeResult::Matched {
                consumed,
                source_addr,
            } => {
                assert_eq!(consumed, header.len());
                assert_eq!(source_addr, None);
            }
            r => panic!("unexpected {:?}", r),
        }
    }

    #[test]
    fn not_proxy_passthrough() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        matches!(parse_proxy_protocol(data), ProxyProbeResult::NotProxy);
    }
}
