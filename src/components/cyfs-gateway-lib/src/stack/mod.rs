mod tcp_stack;
mod rtcp_stack;
mod udp_stack;
mod quic_stack;
mod stack;
mod tls_stack;

pub use tcp_stack::*;
pub use rtcp_stack::*;
pub use udp_stack::*;
pub use quic_stack::*;
pub use stack::*;

#[derive(Debug, Copy, Clone)]
pub enum StackErrorCode {
    BindFailed,
    ProcessChainError,
    InvalidConfig,
    TunnelError,
    StreamError,
    InvalidTlsKey,
    InvalidTlsCert,
}
pub type StackResult<T> = sfo_result::Result<T, StackErrorCode>;
pub type StackError = sfo_result::Error<StackErrorCode>;
pub use sfo_result::into_err as into_stack_err;
pub use sfo_result::err as stack_err;
