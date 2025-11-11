use crate::tunnel::{DatagramClient};
use std::net::{IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub struct UdpClient {
    client: Arc<UdpSocket>,
    dest_port: u16,
    dest_addr: String,
}

impl UdpClient {
    pub async fn new(dest_addr: String, dest_port: u16,bind_addr:Option<String>) -> Result<UdpClient, std::io::Error> {
        let client;
        if bind_addr.is_some() {
            client = UdpSocket::bind(bind_addr.unwrap().as_str()).await?;
        } else {
            let dest = IpAddr::from_str(dest_addr.as_str())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            if dest.is_ipv4() {
                client = UdpSocket::bind("0.0.0.0:0").await?;
            } else {
                client = UdpSocket::bind("[::]:0").await?;
            }
        }

        Ok(UdpClient {
            client: Arc::new(client),
            dest_port,
            dest_addr,
        })
    }
}

#[async_trait::async_trait]
impl DatagramClient for UdpClient {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        let (size, _) = self.client.recv_from(buffer).await?;
        Ok(size)
    }

    async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        let server_addr = format!("{}:{}", self.dest_addr, self.dest_port);
        let size = self.client.send_to(buffer, server_addr.clone()).await?;
        trace!("udpclient send datagram to {} size:{}", server_addr, size);
        Ok(size)
    }
}