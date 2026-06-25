#![allow(dead_code)]

pub mod name_info_cache;
mod relay_mgr;
mod sn_auth;
mod sn_db;
mod sn_device_info;
pub mod sn_resolver;
mod sn_server;
mod sqlite_db;
mod v2;

pub use name_info_cache::*;
pub use relay_mgr::*;
pub use sn_auth::*;
pub use sn_db::*;
pub use sn_device_info::*;
pub use sn_resolver::*;
pub use sn_server::*;
pub use sqlite_db::*;

pub use sfo_result::err as sn_err;
pub use sfo_result::into_err as into_sn_err;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnErrorCode {
    Failed,
    InvalidInput,
    NotFound,
    Conflict,
    StaleReport,
    Blocked,
    DBError,
    RemoteError,
}

pub type SnResult<T> = sfo_result::Result<T, SnErrorCode>;
pub type SnError = sfo_result::Error<SnErrorCode>;
