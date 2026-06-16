use thiserror::Error;

#[derive(Debug, Error)]
pub enum BnsIndexerError {
    #[error("invalid BNS name `{name}`: {reason}")]
    InvalidName { name: String, reason: String },

    #[error("invalid BNS document type `{doc_type}`: {reason}")]
    InvalidDocType { doc_type: String, reason: String },

    #[error("invalid BNS hash `{value}`: {reason}")]
    InvalidHash { value: String, reason: String },

    #[error("integer value for `{field}` is outside sqlite INTEGER range: {value}")]
    IntegerOutOfRange { field: &'static str, value: u64 },

    #[error("BNS sqlite database lock is poisoned")]
    DbLockPoisoned,

    #[error("contract view error: {0}")]
    Contract(String),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type BnsIndexerResult<T> = Result<T, BnsIndexerError>;

impl BnsIndexerError {
    pub fn invalid_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_doc_type(doc_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidDocType {
            doc_type: doc_type.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_hash(value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidHash {
            value: value.into(),
            reason: reason.into(),
        }
    }
}
