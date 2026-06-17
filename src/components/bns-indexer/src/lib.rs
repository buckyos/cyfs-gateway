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

pub use contract::*;
pub use db::*;
pub use error::*;
pub use indexer::*;
pub use model::*;
pub use sqlite::*;
pub use validation::*;
