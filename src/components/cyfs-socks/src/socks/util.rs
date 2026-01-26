#![allow(deprecated)]

use crate::error::{SocksError, SocksResult};
use buckyos_kit::AsyncStream;
use fast_socks5::consts;
use fast_socks5::server::{SimpleUserPassword, Socks5Socket};
use fast_socks5::ReplyError;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;

pub struct Socks5Util {}

impl Socks5Util {
    pub fn new_reply(error: ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
        let (addr_type, mut ip_oct, mut port) = match sock_addr {
            SocketAddr::V4(sock) => (
                consts::SOCKS5_ADDR_TYPE_IPV4,
                sock.ip().octets().to_vec(),
                sock.port().to_be_bytes().to_vec(),
            ),
            SocketAddr::V6(sock) => (
                consts::SOCKS5_ADDR_TYPE_IPV6,
                sock.ip().octets().to_vec(),
                sock.port().to_be_bytes().to_vec(),
            ),
        };

        let mut reply = vec![
            consts::SOCKS5_VERSION,
            error.as_u8(), // transform the error into byte code
            0x00,          // reserved
            addr_type,     // address type (ipv4, v6, domain)
        ];
        reply.append(&mut ip_oct);
        reply.append(&mut port);

        reply
    }

    pub async fn reply_error(
        socket: &mut Socks5Socket<Box<dyn AsyncStream>, SimpleUserPassword>,
        error: ReplyError,
    ) -> SocksResult<()> {
        let reply = Self::new_reply(error, "0.0.0.0:0".parse().unwrap());

        socket.write(&reply).await.map_err(|e| {
            let msg = format!("Error replying socks5 error: {}", e);
            error!("{}", msg);
            SocksError::IoError(msg)
        })?;

        socket.flush().await.map_err(|e| {
            let msg = format!("Error flushing socks5 error: {}", e);
            error!("{}", msg);
            SocksError::IoError(msg)
        })?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ProxyAccessMethod {
    Proxy(Option<String>),
    Direct,
    Reject,
}

impl FromStr for ProxyAccessMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.is_empty() {
            let msg = format!("Empty access method string");
            error!("{}", msg);
            return Err(msg);
        }

        match parts[0].to_uppercase().as_str() {
            "PROXY" | "SOCKS" => {
                if parts.len() < 2 {
                    return Ok(Self::Proxy(None));
                }

                Ok(Self::Proxy(Some(parts[1].to_string())))
            }
            "DIRECT" => Ok(ProxyAccessMethod::Direct),
            "REJECT" => Ok(ProxyAccessMethod::Reject),
            _ => {
                let msg = format!("Invalid proxy access method: {}", s);
                error!("{}", msg);
                Err(msg)
            }
        }
    }
}

// Same as the return value of pac script
pub fn parse_hook_point_return_value(pac_string: &str) -> SocksResult<Vec<ProxyAccessMethod>> {
    // Split the string by semicolons to get different access methods
    let list = pac_string
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>();

    let mut result = Vec::new();
    for item in list {
        let value = ProxyAccessMethod::from_str(item).map_err(|e| {
            let msg = format!("Invalid hook point return value: {}, err={}", item, e);
            error!("{}", msg);
            SocksError::HookPointError(msg)
        })?;

        result.push(value);
    }

    Ok(result)
}
