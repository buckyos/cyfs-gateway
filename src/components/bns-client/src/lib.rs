//! BNS API types, indexer/server RPC client, and SN-side BNS write controller.
//!
//! The legacy RPC path still supports the centralized registry state-machine
//! contract. New write paths should use the EVM clients so authorization is
//! enforced by the BNS contract through `msg.sender`.

pub mod dns_document;

mod error;
mod evm;
pub mod model;
mod rpc;
mod sn_bns_controller;
mod sn_bns_store;

pub use error::{BnsRegistryError, BnsRegistryResult};
pub use evm::*;
pub use model::*;
pub use rpc::*;
pub use sn_bns_controller::*;
pub use sn_bns_store::*;
