#![allow(dead_code)]

mod sn_db;
mod sn_server;
mod sqlite_db;

pub use sn_db::*;
pub use sn_server::*;
pub use sqlite_db::*;

pub use sfo_result::err as sn_err;
pub use sfo_result::into_err as into_sn_err;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnErrorCode {
    Failed,
    NotFound,
    DBError,
}

pub type SnResult<T> = sfo_result::Result<T, SnErrorCode>;
pub type SnError = sfo_result::Error<SnErrorCode>;