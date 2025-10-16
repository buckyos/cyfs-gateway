mod http_server;
mod socks5_server;
mod server;

pub use http_server::*;
pub use socks5_server::*;
pub use server::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerErrorCode {
    BindFailed,
    InvalidConfig,
    InvalidParam,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
    InvalidData,
    IOError,
    BadRequest,
    UnknownServerType,
    EncodeError,
    InvalidDnsOpType,
    InvalidDnsMessageType,
    InvalidDnsRecordType,
    Rejected,
    AlreadyExists
}
pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
pub use sfo_result::err as server_err;
pub use sfo_result::into_err as into_server_err;
