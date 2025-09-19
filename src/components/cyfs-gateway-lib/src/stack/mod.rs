mod tcp_stack;
mod rtcp_stack;
mod udp_stack;
mod stack;
mod tls_stack;
mod quic_stack;
mod limiter;

use std::future::Future;
use buckyos_kit::AsyncStream;
pub use tcp_stack::*;
pub use rtcp_stack::*;
pub use udp_stack::*;
pub use quic_stack::*;
pub use stack::*;
pub use tls_stack::*;

#[derive(Debug, Copy, Clone)]
pub enum StackErrorCode {
    BindFailed,
    ProcessChainError,
    InvalidConfig,
    TunnelError,
    StreamError,
    InvalidTlsKey,
    InvalidTlsCert,
    ServerError,
    IoError,
    QuicError,
}
pub type StackResult<T> = sfo_result::Result<T, StackErrorCode>;
pub type StackError = sfo_result::Error<StackErrorCode>;
pub use sfo_result::into_err as into_stack_err;
pub use sfo_result::err as stack_err;
use url::Url;
use crate::{DatagramClient, DatagramClientBox, TunnelManager};

pub(crate) async fn stream_forward(mut stream: Box<dyn AsyncStream>, target: &str, tunnel_manager: &TunnelManager) -> StackResult<()> {
    let url = Url::parse(target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
    let mut forward_stream = tunnel_manager
        .open_stream_by_url(&url)
        .await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;

    tokio::io::copy_bidirectional(&mut stream, forward_stream.as_mut())
        .await
        .map_err(into_stack_err!(StackErrorCode::StreamError, "target {target}"))?;
    Ok(())
}

pub(crate) async fn datagram_forward(datagram: Box<dyn DatagramClientBox>, target: &str, tunnel_manager: &TunnelManager) -> StackResult<()> {
    let url = Url::parse(&target).map_err(into_stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward url {}",
                                    target
                                ))?;
    let forward_datagram = tunnel_manager.create_datagram_client_by_url(&url).await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;

    copy_datagram_bidirectional(datagram, forward_datagram).await
        .map_err(into_stack_err!(StackErrorCode::TunnelError))?;
    Ok(())
}

pub(crate) async fn copy_datagram_bidirectional(a: Box<dyn DatagramClientBox>, b: Box<dyn DatagramClientBox>) -> Result<(), std::io::Error> {
    let recv = {
        let a = a.clone();
        let b = b.clone();
        async move {
            loop {
                let mut buf = [0u8; 4096];
                let n = a.recv_datagram(&mut buf).await?;
                b.send_datagram(&buf[..n]).await?;
            }
            Ok::<(), std::io::Error>(())
        }
    };

    let send = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = b.recv_datagram(&mut buf).await?;
            a.send_datagram(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let ret = tokio::try_join!(recv, send);
    ret?;
    Ok(())
}
