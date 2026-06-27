//! BNS contract event indexer and read projection.
//!
//! The contract is the authority for BNS state. This crate persists a SQLite
//! read projection and event log derived from BNS contract logs. The
//! [`CentralizedBnsRegistry`] facade is read-only by default; its legacy
//! in-process mutation state machine is only available through the hidden
//! compatibility constructor used by historical tests.

pub mod dns_document;

mod error;
mod evm_projection;
mod model;
mod registry;
mod sqlite;
mod store;
mod sync;

pub use error::{BnsRegistryError, BnsRegistryResult};
pub use evm_projection::{
    checkpoint_from_event, store_event_record, ContractEventProjector, ContractProtocolEvent,
    ProjectedContractEvent,
};
pub use model::*;
pub use registry::{
    controller_rule, default_document_update, policy_hash_from_rules, CentralizedBnsRegistry,
};
pub use sqlite::SqliteBnsRegistryStore;
pub use store::{BnsRegistryStore, BnsRegistryStoreTx};
pub use sync::{
    sync_bns_contract_once, BnsBlockSyncSourceConfig, BnsContractEventIndexer,
    BnsIndexerSyncConfig, BnsIndexerSyncOutcome,
};

pub type SqliteBnsDb = SqliteBnsRegistryStore;
