//! BNS indexer RPC client and SN-side BNS write controller.
//!
//! The crate intentionally keeps authentication out of the BNS RPC boundary:
//! callers must pass an already verified `CallAuthority`, matching the
//! `bns-indexer` state-machine contract.

mod rpc;
mod sn_bns_controller;
mod sn_bns_store;

pub use rpc::*;
pub use sn_bns_controller::*;
pub use sn_bns_store::*;
