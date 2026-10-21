mod hostname;
mod mac;
mod probe;

use std::net::IpAddr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum LookupErrorCode {
    #[default]
    Failed,
}

#[derive(thiserror::Error)]
#[error("{}", self.display_line())]
pub struct LookupError {
    code: LookupErrorCode,
    msg: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    trace: buckyos_kit::ErrorTrace,
}

pub type LookupResult<T> = std::result::Result<T, LookupError>;

impl LookupError {
    #[track_caller]
    pub fn new(code: LookupErrorCode, msg: impl Into<String>) -> Self {
        Self {
            code,
            msg: msg.into(),
            source: None,
            trace: buckyos_kit::ErrorTrace::capture(),
        }
    }

    #[track_caller]
    pub fn with_source(
        code: LookupErrorCode,
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

    pub fn code(&self) -> LookupErrorCode {
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

impl std::fmt::Debug for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.trace
            .fmt_debug(f, &self.code, &self.msg, self.source_ref())
    }
}

/// `lookup_err!(code)` / `lookup_err!(code, fmt, args..)` / `lookup_err!(fmt, args..)`
#[macro_export]
macro_rules! lookup_err {
    ( $fmt:literal ) => {
        $crate::LookupError::new(::std::default::Default::default(), format!($fmt))
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        $crate::LookupError::new(::std::default::Default::default(), format!($fmt, $($arg)*))
    };
    ( $code:path ) => {
        $crate::LookupError::new($code, ::std::string::String::new())
    };
    ( $code:path, $($arg:tt)* ) => {
        $crate::LookupError::new($code, format!($($arg)*))
    };
}

/// Closure for `map_err` that keeps the error as `source`. Same forms as `lookup_err!`.
#[macro_export]
macro_rules! into_lookup_err {
    ( $fmt:literal ) => {
        |e| $crate::LookupError::with_source(::std::default::Default::default(), format!($fmt), e)
    };
    ( $fmt:literal, $($arg:tt)* ) => {
        |e| $crate::LookupError::with_source(::std::default::Default::default(), format!($fmt, $($arg)*), e)
    };
    ( $code:path ) => {
        |e| $crate::LookupError::with_source($code, ::std::string::String::new(), e)
    };
    ( $code:path, $($arg:tt)* ) => {
        |e| $crate::LookupError::with_source($code, format!($($arg)*), e)
    };
}

pub async fn lookup_hostname(ip: IpAddr) -> LookupResult<Option<String>> {
    if let Some(name) = hostname::lookup_hostname_once(ip).await? {
        return Ok(Some(name));
    }

    probe::active_probe(ip).await?;

    hostname::lookup_hostname_once(ip).await
}

pub async fn lookup_mac(ip: IpAddr) -> LookupResult<Option<String>> {
    if let Some(mac) = mac::lookup_mac_once(ip).await? {
        return Ok(Some(mac));
    }

    mac::active_probe(ip).await?;

    mac::lookup_mac_once(ip).await
}
