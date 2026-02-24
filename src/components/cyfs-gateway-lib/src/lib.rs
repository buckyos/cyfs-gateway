#![allow(dead_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod aes_stream;
mod config;
mod ip;
mod rtcp;
mod tunnel;
mod tunnel_connector;
mod tunnel_mgr;
mod socks;
//mod selector;
pub mod server;
//mod inner_service;
mod stack;
mod global_process_chains;
mod js_externals;
mod connection_manager;
mod quic_tunnel;
mod cmds;
mod self_cert_mgr;
mod tls_tunnel;
mod collections;
mod global_collection_manager;
mod timer_manager;
mod io_dump;

pub use aes_stream::*;
pub use config::*;
pub use rtcp::*;
pub use tunnel::*;
pub use tunnel_connector::*;
pub use tunnel_mgr::*;
pub use socks::*;
//pub use selector::*;
pub use server::*;
//pub use inner_service::*;
pub use stack::*;
pub use connection_manager::*;
pub use global_process_chains::*;
pub use js_externals::*;
pub use cyfs_acme::*;
pub use cmds::*;
pub use self_cert_mgr::*;
pub use collections::*;
pub use global_collection_manager::*;
pub use timer_manager::*;
pub use io_dump::*;

use thiserror::Error;
use std::sync::Arc;
use name_lib::DeviceConfig;

#[macro_use]
extern crate log;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("parse url {0} error : {1}")]
    UrlParseError(String, String),
    #[error("Unknown Protocol: {0}")]
    UnknownProtocol(String),
    #[error("Bind Error: {0}")]
    BindError(String),
    #[error("Connect Error: {0}")]
    ConnectError(String),
    #[error("DIDDocument Error: {0}")]
    DocumentError(String),
    #[error("Reason Error: {0}")]
    ReasonError(String),
    #[error("Invalid State: {0}")]
    InvalidState(String),
    #[error("Already Exists: {0}")]
    AlreadyExists(String),
    #[error("IO Error: {0}")]
    IoError(String),
}

pub type TunnelResult<T> = std::result::Result<T, TunnelError>;


pub struct GatewayDevice {
    pub config: DeviceConfig,
    pub private_key: [u8; 48],
}

pub type GatewayDeviceRef = Arc<GatewayDevice>;
