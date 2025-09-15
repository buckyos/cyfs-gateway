mod tcp_stack;
mod rtcp_stack;
mod udp_stack;
mod stack;
mod tls_stack;
mod quic_stack;
mod limiter;

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
use crate::{TunnelManager};

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
