//! Centralized BNS registry state machine.
//!
//! The implementation follows `doc/BNS 智能合约接口设计.md`: the registry core is
//! independent from RPC/session authentication and only accepts an already
//! authenticated [`CallAuthority`]. State is persisted through
//! [`BnsRegistryStore`], with SQLite provided as the first backend.

pub mod dns_document;

mod error;
mod model;
mod registry;
mod sqlite;
mod store;

pub use error::{BnsRegistryError, BnsRegistryResult};
pub use model::*;
pub use registry::{
    controller_rule, default_document_update, policy_hash_from_rules, CentralizedBnsRegistry,
};
pub use sqlite::SqliteBnsRegistryStore;
pub use store::{BnsRegistryStore, BnsRegistryStoreTx};

pub type SqliteBnsDb = SqliteBnsRegistryStore;
