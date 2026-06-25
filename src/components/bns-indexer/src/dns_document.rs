use serde::{Deserialize, Serialize};

use crate::{
    default_document_update, BnsRegistryError, BnsRegistryResult, DocumentRef, DocumentState,
    DocumentUpdate, STORAGE_TYPE_INLINE,
};

pub const DNS_TXT_DOC_TYPE: &str = "dns_txt";

/// One TXT record entry in a `dns_txt` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTxtRecord {
    pub ttl: u32,
    pub value: String,
}

impl DnsTxtRecord {
    pub fn new(ttl: u32, value: impl Into<String>) -> BnsRegistryResult<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "DNS TXT record value must not be empty".to_string(),
            ));
        }

        Ok(Self { ttl, value })
    }
}

/// Builds a `dns_txt` document update with one TXT record appended.
///
/// Pass `None` to create the first `dns_txt` document version, or pass the
/// current `dns_txt` [`DocumentState`] to append to the existing inline JSON
/// record array. The returned [`DocumentUpdate`] can be passed directly to
/// `CentralizedBnsRegistry::publish_document`.
pub fn add_txt_record(
    current: Option<&DocumentState>,
    ttl: u32,
    value: impl Into<String>,
) -> BnsRegistryResult<DocumentUpdate> {
    let mut records = match current {
        Some(state) => txt_records_from_document(state)?,
        None => Vec::new(),
    };
    let expected_version = current.map_or(0, |state| state.version);

    records.push(DnsTxtRecord::new(ttl, value)?);
    txt_records_update(expected_version, &records)
}

/// Parses an inline `dns_txt` document into TXT records.
pub fn txt_records_from_document(state: &DocumentState) -> BnsRegistryResult<Vec<DnsTxtRecord>> {
    if state.doc_type != DNS_TXT_DOC_TYPE {
        return Err(BnsRegistryError::InvalidMutation(format!(
            "expected doc_type={}, got {}",
            DNS_TXT_DOC_TYPE, state.doc_type
        )));
    }

    if state.document.storage_type != STORAGE_TYPE_INLINE {
        return Err(BnsRegistryError::InvalidMutation(
            "DNS TXT helper can only update inline documents".to_string(),
        ));
    }

    serde_json::from_slice(&state.document.inline_document).map_err(Into::into)
}

/// Builds a `dns_txt` document update from a complete TXT record array.
pub fn txt_records_update(
    expected_version: u64,
    records: &[DnsTxtRecord],
) -> BnsRegistryResult<DocumentUpdate> {
    if records.is_empty() {
        return Err(BnsRegistryError::InvalidMutation(
            "DNS TXT document must contain at least one record".to_string(),
        ));
    }

    let document = DocumentRef::inline(serde_json::to_vec(records)?);
    let update = default_document_update(DNS_TXT_DOC_TYPE, expected_version, document)?;
    update.validate()?;
    Ok(update)
}
