use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::{lookup_err, LookupResult};

pub async fn active_probe(ip: IpAddr) -> LookupResult<()> {
    let ports = [7u16, 9u16, 5353u16];
    let mut success = false;
    let mut last_error: Option<std::io::Error> = None;

    for port in ports {
        match probe_udp(ip, port).await {
            Ok(()) => success = true,
            Err(e) => last_error = Some(e),
        }
    }

    if success {
        Ok(())
    } else {
        let message = if let Some(e) = last_error {
            format!("active probe for {} failed: {}", ip, e)
        } else {
            format!("active probe for {} failed", ip)
        };
        Err(lookup_err!("{}", message))
    }
}

async fn probe_udp(ip: IpAddr, port: u16) -> std::io::Result<()> {
    let bind_addr = match ip {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    let target = SocketAddr::new(ip, port);
    timeout(Duration::from_millis(250), socket.send_to(&[0u8], target))
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e.to_string()))??;
    Ok(())
}
