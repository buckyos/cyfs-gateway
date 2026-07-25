use crate::tunnel::DatagramClient;
use buckyos_kit::AsyncStream;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub const MAX_RTCP_DATAGRAM_BYTES: usize = 65_507;

#[derive(Clone)]
pub struct AsyncStreamWithDatagram {
    send: Arc<Mutex<WriteHalf<Box<dyn AsyncStream>>>>,
    recv: Arc<Mutex<ReadHalf<Box<dyn AsyncStream>>>>,
    max_datagram_bytes: usize,
}

impl AsyncStreamWithDatagram {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self::new_with_limit(stream, MAX_RTCP_DATAGRAM_BYTES)
    }

    pub fn new_with_limit(stream: Box<dyn AsyncStream>, max_datagram_bytes: usize) -> Self {
        let (recv, send) = tokio::io::split(stream);
        AsyncStreamWithDatagram {
            send: Arc::new(Mutex::new(send)),
            recv: Arc::new(Mutex::new(recv)),
            max_datagram_bytes: max_datagram_bytes.min(MAX_RTCP_DATAGRAM_BYTES),
        }
    }

    pub async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        let mut stream = self.recv.lock().await;

        // First write the length of the datagram in u32, to the buffer
        let mut len_buffer = [0u8; 4];
        let len = stream.read_exact(&mut len_buffer).await?;
        if len != 4 {
            let msg = format!("recv datagram error: read len={}", len);
            error!("{}", msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }

        let datagram_len = u32::from_be_bytes(len_buffer) as usize;
        if datagram_len > self.max_datagram_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rtcp datagram length {} exceeds protocol limit {}",
                    datagram_len, self.max_datagram_bytes
                ),
            ));
        }
        if datagram_len > buffer.len() {
            let msg = format!(
                "recv datagram error with insufficient buffer: datagram_len={}, buffer_len={}",
                datagram_len,
                buffer.len()
            );
            error!("{}", msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }

        let len = stream.read_exact(buffer[..datagram_len].as_mut()).await?;
        if len != datagram_len {
            let msg = format!(
                "recv datagram error: read len={}, expected len={}",
                len, datagram_len
            );
            error!("{}", msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }

        Ok(len)
    }

    pub async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        if buffer.len() > self.max_datagram_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "rtcp datagram length {} exceeds protocol limit {}",
                    buffer.len(),
                    self.max_datagram_bytes
                ),
            ));
        }
        let mut stream = self.send.lock().await;

        //TODO: u16 is enough?
        // First write the length of the datagram in u32, to the buffer
        let len = buffer.len() as u32;
        let len_buffer = len.to_be_bytes();
        stream.write_all(&len_buffer).await?;

        // Then write the datagram to the buffer
        stream.write_all(buffer).await?;

        Ok(len as usize)
    }
}

#[derive(Clone)]
pub struct RTcpTunnelDatagramClient {
    stream: AsyncStreamWithDatagram,
}

impl RTcpTunnelDatagramClient {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self::new_with_limit(stream, MAX_RTCP_DATAGRAM_BYTES)
    }

    pub fn new_with_limit(stream: Box<dyn AsyncStream>, max_datagram_bytes: usize) -> Self {
        Self {
            stream: AsyncStreamWithDatagram::new_with_limit(stream, max_datagram_bytes),
        }
    }
}

#[async_trait::async_trait]
impl DatagramClient for RTcpTunnelDatagramClient {
    async fn recv_datagram(&self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        self.stream.recv_datagram(buffer).await
    }

    async fn send_datagram(&self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        self.stream.send_datagram(buffer).await
    }
}

#[derive(Clone)]
pub struct DatagramForwarder {
    target_addr: String,
    client: Arc<UdpSocket>,
    stream: AsyncStreamWithDatagram,
}

impl DatagramForwarder {
    pub async fn new(
        target_addr: &str,
        bind: &str,
        stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Self> {
        let client = UdpSocket::bind(bind).await.map_err(|e| {
            let msg = format!("UDP socket bind to {} failed: {:?}", bind, e);
            error!("{}", msg);
            std::io::Error::new(std::io::ErrorKind::Other, msg)
        })?;

        let ret = Self {
            target_addr: target_addr.to_string(),
            client: Arc::new(client),
            stream: AsyncStreamWithDatagram::new(stream),
        };

        Ok(ret)
    }

    pub fn start(&self) {
        let forwarder = self.clone();
        tokio::spawn(async move {
            match forwarder.run().await {
                Ok(_) => {
                    info!("Datagram forwarder stopped: {}", forwarder.target_addr);
                }
                Err(e) => {
                    error!(
                        "Datagram forwarder stopped with error: {}, {:?}",
                        forwarder.target_addr, e
                    );
                }
            }
        });
    }

    pub async fn run(&self) -> Result<(), std::io::Error> {
        let (recv, send) = tokio::join!(self.run_recv(), self.run_send());
        recv?;
        send?;

        Ok(())
    }

    async fn run_recv(&self) -> Result<(), std::io::Error> {
        loop {
            let mut buffer = [0u8; MAX_RTCP_DATAGRAM_BYTES];
            let (size, _) = self.client.recv_from(&mut buffer).await?;
            if size > 0 {
                let buffer = &buffer[..size];
                self.stream.send_datagram(buffer).await?;
            }
        }
    }

    async fn run_send(&self) -> Result<(), std::io::Error> {
        loop {
            let mut buffer = [0u8; MAX_RTCP_DATAGRAM_BYTES];
            let size = self.stream.recv_datagram(&mut buffer).await?;
            let buffer = &buffer[..size];
            self.client.send(buffer).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn datagram_limit_is_symmetric_and_send_rejection_preserves_framing() {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let sender = AsyncStreamWithDatagram::new(Box::new(a));
        let receiver = AsyncStreamWithDatagram::new(Box::new(b));
        let too_large = vec![0u8; MAX_RTCP_DATAGRAM_BYTES + 1];
        let err = sender.send_datagram(&too_large).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let payload = vec![0x5a; MAX_RTCP_DATAGRAM_BYTES];
        let expected = payload.clone();
        let send = tokio::spawn(async move {
            assert_eq!(
                sender.send_datagram(&payload).await.unwrap(),
                MAX_RTCP_DATAGRAM_BYTES
            );
        });
        let mut received = vec![0u8; MAX_RTCP_DATAGRAM_BYTES];
        assert_eq!(
            receiver.recv_datagram(&mut received).await.unwrap(),
            MAX_RTCP_DATAGRAM_BYTES
        );
        assert_eq!(received, expected);
        send.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_declared_datagram_is_rejected_before_payload_read() {
        let (mut raw, framed) = tokio::io::duplex(64);
        raw.write_all(&((MAX_RTCP_DATAGRAM_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let receiver = AsyncStreamWithDatagram::new(Box::new(framed));
        let mut buffer = vec![0u8; MAX_RTCP_DATAGRAM_BYTES];
        let err = receiver.recv_datagram(&mut buffer).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
