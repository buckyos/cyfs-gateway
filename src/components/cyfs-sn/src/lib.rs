mod api;
pub mod name_info_cache;
mod relay_mgr;
pub mod s2s;
mod sn_auth;
mod sn_auth_manager;
mod sn_authority;
mod sn_bns_proxy;
mod sn_bns_reader;
mod sn_bns_signer;
mod sn_device_info;
pub mod sn_did_resolver;
mod sn_dns_proof;
pub mod sn_resolver;
mod sn_seed;
mod sn_server;

pub use name_info_cache::*;
pub use relay_mgr::*;
pub use s2s::*;
pub use sn_auth::*;
pub use sn_bns_proxy::*;
pub use sn_bns_signer::*;
pub use sn_device_info::*;
pub use sn_did_resolver::*;
pub use sn_dns_proof::*;
pub use sn_resolver::*;
pub use sn_seed::*;
pub use sn_server::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnErrorCode {
    #[default]
    Failed,
    InvalidInput,
    NotFound,
    /// 用户不存在。wire 值 `user_not_found`，sn-business sn_auth_db 的 SnRpcErrorCode 同步。
    UserNotFound,
    Conflict,
    /// 邮箱已绑定其他账号。wire 值 `email_already_bound`，sn-business 同步。
    EmailAlreadyBound,
    StaleReport,
    Blocked,
    DBError,
    RemoteError,
}

#[derive(thiserror::Error)]
#[error("{}", self.display_line())]
pub struct SnError {
    code: SnErrorCode,
    msg: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    trace: buckyos_kit::ErrorTrace,
}

pub type SnResult<T> = std::result::Result<T, SnError>;

impl SnError {
    #[track_caller]
    pub fn new(code: SnErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
            source: None,
            trace: buckyos_kit::ErrorTrace::capture(),
        }
    }

    #[track_caller]
    pub fn with_source(
        code: SnErrorCode,
        msg: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            code,
            msg: msg.into(),
            source: Some(source.into()),
            trace: buckyos_kit::ErrorTrace::capture(),
        }
    }

    pub fn code(&self) -> SnErrorCode {
        self.code
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }

    pub fn trace(&self) -> &buckyos_kit::ErrorTrace {
        &self.trace
    }

    fn source_ref(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }

    fn display_line(&self) -> buckyos_kit::ErrorLine<'_> {
        buckyos_kit::ErrorLine::new(&self.code, &self.msg, self.source_ref())
    }
}

impl std::fmt::Debug for SnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.trace
            .fmt_debug(f, &self.code, &self.msg, self.source_ref())
    }
}

/// `sn_err!(code)` / `sn_err!(code, fmt, args..)` / `sn_err!(fmt, args..)`
#[macro_export]
macro_rules! sn_err {
    ( $fmt:literal ) => {
        $crate::SnError::new(::std::default::Default::default(), format!($fmt))
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        $crate::SnError::new(::std::default::Default::default(), format!($fmt, $($arg)*))
    };
    ( $code:path ) => {
        $crate::SnError::new($code, ::std::string::String::new())
    };
    ( $code:path, $($arg:tt)* ) => {
        $crate::SnError::new($code, format!($($arg)*))
    };
}

/// Closure for `map_err` that keeps the error as `source`. Same forms as `sn_err!`.
#[macro_export]
macro_rules! into_sn_err {
    ( $fmt:literal ) => {
        |e| $crate::SnError::with_source(::std::default::Default::default(), format!($fmt), e)
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        |e| $crate::SnError::with_source(::std::default::Default::default(), format!($fmt, $($arg)*), e)
    };
    ( $code:path ) => {
        |e| $crate::SnError::with_source($code, ::std::string::String::new(), e)
    };
    ( $code:path, $($arg:tt)* ) => {
        |e| $crate::SnError::with_source($code, format!($($arg)*), e)
    };
}
