#![allow(dead_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

mod aes_stream;
mod config;
mod ip;
mod rtcp;
mod socks;
mod tunnel;
mod tunnel_connector;
mod tunnel_mgr;
mod tunnel_url_status;
//mod selector;
pub mod server;
//mod inner_service;
mod cmds;
mod collections;
mod connection_manager;
mod device_manager;
mod forward;
mod global_collection_manager;
mod global_process_chains;
mod io_dump;
mod js_externals;
mod quic_tunnel;
mod self_cert_mgr;
mod stack;
mod timer_manager;
mod tls_tunnel;

pub use aes_stream::*;
pub use config::*;
pub use rtcp::*;
pub use socks::*;
pub use tunnel::*;
pub use tunnel_connector::*;
pub use tunnel_mgr::*;
pub use tunnel_url_status::*;
//pub use selector::*;
pub use server::*;
//pub use inner_service::*;
pub use cmds::*;
pub use collections::*;
pub use connection_manager::*;
pub use cyfs_acme::*;
pub use device_manager::*;
pub use forward::*;
pub use global_collection_manager::*;
pub use global_process_chains::*;
pub use io_dump::*;
pub use js_externals::*;
pub use self_cert_mgr::*;
pub use stack::*;
pub use timer_manager::*;

use name_lib::DeviceConfig;
use std::sync::Arc;
use thiserror::Error;

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
