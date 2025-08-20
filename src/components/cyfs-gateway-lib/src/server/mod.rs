mod cyfs_server;
mod cyfs_server_manager;
mod http_server;
mod socks5_server;
mod server;
mod dns_server;

pub use cyfs_server::*;
pub use cyfs_server_manager::*;
pub use http_server::*;
pub use socks5_server::*;
pub use server::*;
pub use dns_server::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerErrorCode {
    BindFailed,
    InvalidConfig,
    ProcessChainError,
    StreamError,
    TunnelError,
    InvalidTlsKey,
    InvalidTlsCert,
}
pub type ServerResult<T> = sfo_result::Result<T, ServerErrorCode>;
pub type ServerError = sfo_result::Error<ServerErrorCode>;
use sfo_result::err as server_err;
use sfo_result::into_err as into_server_err;