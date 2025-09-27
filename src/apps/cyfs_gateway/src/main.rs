#![allow(dead_code)]
#![allow(unused_imports)]
//mod config;
//mod gateway;
//mod interface;
mod config_loader;
mod dispatcher;
mod gateway;
mod socks;
mod cyfs_cmd_server;
mod cyfs_cmd_client;
//mod peer;
//mod proxy;
//mod service;
//mod storage;
//mod tunnel;

#[macro_use]
extern crate log;

use crate::gateway::{Gateway, GatewayFactory, GatewayParams};
use buckyos_kit::*;
use clap::{Arg, ArgAction, Command};
use console_subscriber::{self, Server};
use cyfs_dns::start_cyfs_dns_server;
use cyfs_gateway_lib::*;
use cyfs_warp::*;
use log::*;
use name_client::*;
use name_lib::*;
use std::path::PathBuf;
use std::sync::Arc;
use json_value_merge::Merge;
use serde_json::{Value};
use tokio::task;
use url::Url;
use crate::config_loader::{GatewayConfigParser, HttpServerConfigParser, QuicStackConfigParser, RtcpStackConfigParser, TcpStackConfigParser, TlsStackConfigParser, UdpStackConfigParser};
use crate::cyfs_cmd_server::{CyfsCmdServerConfigParser, CyfsCmdServerFactory, CYFS_CMD_SERVER_CONFIG};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

async fn service_main(config_json: serde_json::Value, matches: &clap::ArgMatches) -> Result<()> {
    // Load config from json
    let parser = GatewayConfigParser::new();
    parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
    parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
    parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
    parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
    parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));

    parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));

    parser.register_inner_service_config_parser("cmd_server", Arc::new(CyfsCmdServerConfigParser::new()));

    let load_result = parser.parse(config_json);
    if load_result.is_err() {
        let msg = format!("Error loading config: {}", load_result.err().unwrap().msg());
        error!("{}", msg);
        std::process::exit(1);
    }
    let config_loader = load_result.unwrap();

    // Extract necessary params from command line
    let params = GatewayParams {
        keep_tunnel: matches
            .get_many::<String>("keep_tunnel")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect(),
    };

    let connect_manager = ConnectionManager::new();
    let tunnel_manager = TunnelManager::new();
    let server_manager = Arc::new(ServerManager::new());
    let global_process_chains = Arc::new(GlobalProcessChains::new());
    let inner_service_manager = Arc::new(InnerServiceManager::new());

    let factory = GatewayFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        inner_service_manager.clone(),
    );
    factory.register_stack_factory(StackProtocol::Tcp, Arc::new(TcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Udp, Arc::new(UdpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Tls, Arc::new(TlsStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Quic, Arc::new(QuicStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Rtcp, Arc::new(RtcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
    )));

    factory.register_server_factory("http", Arc::new(ProcessChainHttpServerFactory::new(
        inner_service_manager.clone(),
        global_process_chains.clone(),
    )));
    
    factory.register_inner_service_factory("cmd_server", Arc::new(CyfsCmdServerFactory::new()));

    let mut gateway = match factory.create_gateway(config_loader).await {
        Ok(gateway) => gateway,
        Err(e) => {
            error!("create gateway failed: {}", e);
            std::process::exit(1);
        }
    };
    gateway.start(params).await;

    // Sleep forever
    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}

// Parse config first, then config file if supplied by user
async fn load_config_from_args(matches: &clap::ArgMatches) -> Result<serde_json::Value> {
    let default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.json");
    let config_file = matches.get_one::<String>("config_file");
    let real_config_file;
    if config_file.is_none() {
        real_config_file = default_config;
    } else {
        real_config_file = PathBuf::from(config_file.unwrap());
    }

    let config_dir = real_config_file.parent().ok_or_else(|| {
        let msg = format!("cannot get config dir: {:?}", real_config_file);
        error!("{}", msg);
        msg
    })?;

    let config_json = buckyos_kit::ConfigMerger::load_dir_with_root(&config_dir, &real_config_file).await?;

    Ok(config_json)
}

fn generate_ed25519_key_pair_to_local() {
    // Get temp path
    let temp_dir = std::env::temp_dir();
    let key_dir = temp_dir.join("buckyos").join("keys");
    if !key_dir.is_dir() {
        std::fs::create_dir_all(&key_dir).unwrap();
    }
    println!("key_dir: {:?}", key_dir);

    let (private_key, public_key) = generate_ed25519_key_pair();

    let sk_file = key_dir.join("private_key.pem");
    std::fs::write(&sk_file, private_key).unwrap();
    println!("Private key saved to: {:?}", sk_file);

    let pk_file = key_dir.join("public_key.json");
    std::fs::write(&pk_file, serde_json::to_string(&public_key).unwrap()).unwrap();
    println!("Public key saved to: {:?}", pk_file);
}

#[tokio::main]
async fn main() {
    let matches = Command::new("CYFS Gateway Service")
        .version(buckyos_kit::get_version())
        .arg(
            Arg::new("config")
                .long("config")
                .help("config in json format")
                .required(false),
        )
        .arg(
            Arg::new("config_file")
                .long("config_file")
                .help("config file path file with json format content")
                .required(false),
        )
        .arg(
            Arg::new("keep_tunnel")
                .long("keep_tunnel")
                .help("keep tunnel when start")
                .num_args(1..),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("enable debug mode")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("new_key_pair")
                .long("new-key-pair")
                .help("Generate a new key pair for service")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // set buckyos root dir
    if matches.get_flag("new_key_pair") {
        generate_ed25519_key_pair_to_local();
        std::process::exit(0);
    }

    // init log
    init_logging("cyfs_gateway",true);
    info!("cyfs_gateway start...");

    let config_json: serde_json::Value = load_config_from_args(&matches)
        .await
        .map_err(|e| {
            error!("Error loading config: {}", e);
            std::process::exit(1);
        })
        .unwrap();

    let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(CYFS_CMD_SERVER_CONFIG).unwrap();
    cmd_config.merge(&config_json);
    
    //let config_json : Value = config_json.unwrap();
    info!("Gateway config: {}", serde_json::to_string_pretty(&cmd_config).unwrap());

    if matches.get_flag("debug") {
        info!("Debug mode enabled");
        std::env::set_var("RUST_BACKTRACE", "1");
        console_subscriber::init();
    }

    if let Err(e) = service_main(cmd_config, &matches).await {
        error!("Gateway run error: {}", e);
    }

}
