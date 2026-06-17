//! BNS contract validation and local BNS database projection support.
//!
//! The first production phase treats `bns-db` as the source of truth and uses
//! the contract view as an auditable projection. The public traits keep that
//! boundary explicit so a later phase can switch `TruthSource` to the contract
//! and reuse the same state model, sqlite backend, and validation reports.

mod contract;
mod db;
mod error;
mod indexer;
mod model;
mod sqlite;
mod validation;

pub use indexer::{BnsIndexer, BnsIndexerConfig};

pub use contract::{BnsContractEventSource, BnsContractView, BnsContractWriter};
pub use db::BnsDb;
pub use error::{BnsIndexerError, BnsIndexerResult};
pub use sqlite::SqliteBnsDb;

pub use model::{
    canonical_bns_name, canonical_doc_type, did_bns_from_name, name_from_did_bns, now_timestamp,
    AliasKind, AliasState, AuthProof, ContractEvent, ContractEventEnvelope, ControllerRule,
    DocumentKey, DocumentRef, DocumentState, DocumentStatus, DocumentUpdate, IndexerCursor,
    NameState, NameStatus, Principal, PrincipalKind, PurchaseContext, RegisterOptions, ReleaseMode,
    ResolveResult, TruthSource, DID_BNS_PREFIX, STANDARD_DOC_TYPES, STORAGE_TYPE_INLINE, ZERO_HASH,
};

pub use validation::{
    ReconciliationAction, ReconciliationPlan, ValidationMismatch, ValidationReport,
    ValidationSeverity, ValidationStatus, ValidationTarget,
};

pub(crate) use validation::{compare_optional_projection, reconciliation_plan};
