//! BNS indexer RPC client and SN-side BNS write controller.
//!
//! The legacy RPC path still supports the centralized registry state-machine
//! contract. New write paths should use the EVM clients so authorization is
//! enforced by the BNS contract through `msg.sender`.

mod evm;
mod rpc;
mod sn_bns_controller;
mod sn_bns_store;

pub use evm::*;
pub use rpc::*;
pub use sn_bns_controller::*;
pub use sn_bns_store::*;
