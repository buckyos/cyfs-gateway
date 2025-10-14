#![allow(dead_code)]
#![allow(unused_imports)]
#[macro_use]
extern crate log;

use buckyos_kit::*;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console_subscriber::{self, Server};
use cyfs_dns::{start_cyfs_dns_server, ProcessChainDnsServerFactory};
use cyfs_gateway_lib::*;
use cyfs_warp::*;
use log::*;
use name_client::*;
use name_lib::*;
use std::path::PathBuf;
use std::sync::Arc;
use json_value_merge::Merge;
use kRPC::RPCSessionToken;
use serde_json::{Value};
use tokio::fs::create_dir_all;
use tokio::task;
use url::Url;
use cyfs_gateway::*;
use cyfs_socks::SocksServerFactory;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

async fn service_main(config_json: serde_json::Value, params: GatewayParams) -> Result<()> {
    let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(CYFS_CMD_SERVER_CONFIG).unwrap();
    cmd_config.merge(&config_json);

    // Load config from json
    let parser = GatewayConfigParser::new();
    parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
    parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
    parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
    parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
    parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));

    parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));
    parser.register_server_config_parser("socks", Arc::new(SocksServerConfigParser::new()));
    parser.register_server_config_parser("dns", Arc::new(DnsServerConfigParser::new()));

    parser.register_inner_service_config_parser("cmd_server", Arc::new(CyfsCmdServerConfigParser::new()));

    let load_result = parser.parse(cmd_config);
    if load_result.is_err() {
        let msg = format!("Error loading config: {}", load_result.err().unwrap().msg());
        error!("{}", msg);
        std::process::exit(1);
    }
    let config_loader = load_result.unwrap();

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

    factory.register_server_factory("socks", Arc::new(SocksServerFactory::new(
        global_process_chains.clone(),
    )));

    factory.register_server_factory("dns", Arc::new(ProcessChainDnsServerFactory::new(
        inner_service_manager.clone(),
        global_process_chains.clone(),
    )));

    let user_name: Option<String> = match config_json.get("user_name") {
        Some(user_name) => {
            match user_name.as_str() {
                Some(user_name) => Some(user_name.to_string()),
                None => None,
            }
        },
        None => None,
    };
    let password: Option<String> = match config_json.get("password") {
        Some(password) => {
            match password.as_str() {
                Some(password) => Some(password.to_string()),
                None => None,
            }
        },
        None => None,
    };

    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("token_key");
    if !data_dir.exists() {
        create_dir_all(data_dir.clone()).await?;
    }

    let store = LocalTokenKeyStore::new(data_dir);
    let token_manager = LocalTokenManager::new(user_name, password, store).await?;
    let external_cmd_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("add_chain_cmds");
    if !external_cmd_dir.exists() {
        create_dir_all(external_cmd_dir.clone()).await?;
    }
    let external_cmd_store = LocalExternalCmdStore::new(external_cmd_dir);
    let handler = GatewayCmdHandler::new(Arc::new(external_cmd_store));
    factory.register_inner_service_factory(
        "cmd_server",
        Arc::new(CyfsCmdServerFactory::new(handler.clone(), token_manager.clone(), token_manager.clone())));

    let gateway = match factory.create_gateway(config_loader).await {
        Ok(gateway) => gateway,
        Err(e) => {
            error!("create gateway failed: {}", e);
            std::process::exit(1);
        }
    };
    gateway.start(params).await;
    handler.set_gateway(Arc::new(gateway));

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

fn read_login_token(server: &str) -> Option<String> {
    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("token_key");
    let token_dir = get_buckyos_service_data_dir("cyfs_gateway").join("cli_token");
    if !token_dir.exists() {
        let _ = create_dir_all(token_dir.as_path());
    }

    if server.to_lowercase() == CMD_SERVER {
        let private_key = data_dir.join("private_key.pem");
        let encode_key = match load_private_key(private_key.as_path()) {
            Ok(key) => key,
            Err(e) => {
                error!("load private key failed: {}", e);
                return None;
            }
        };

        let (token, _) = match RPCSessionToken::generate_jwt_token(
            "root",
            "cyfs-gateway",
            None,
            &encode_key, ) {
            Ok(token) => token,
            Err(e) => {
                error!("generate jwt token failed: {}", e);
                return None;
            }
        };
        Some(token)
    } else {
        let token_file = token_dir.join(hex::encode(server.to_lowercase()));
        match std::fs::read_to_string(token_file) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("read token file failed: {}", e);
                None
            }
        }
    }
}

fn save_login_token(server: &str, token: &str) {
    if server.to_lowercase() == CMD_SERVER {
        return;
    }
    let token_dir = get_buckyos_service_data_dir("cyfs_gateway").join("cli_token");
    let token_file = token_dir.join(hex::encode(server.to_lowercase()));
    let _ = std::fs::write(token_file, token);
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
        .subcommand(Command::new("login")
            .about("Login to server")
            .arg(Arg::new("user")
                .long("user")
                .short('u')
                .help("user name")
                .required(true))
            .arg(Arg::new("password")
                .long("password")
                .short('p')
                .help("password")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CMD_SERVER)))
        .subcommand(Command::new("show_config")
            .about("Show current config")
            .arg(Arg::new("config_type")
                .long("config_type")
                .short('t')
                .help("Config type, optional stack | server | inner_service | global_process_chain")
                .required(false))
            .arg(Arg::new("config_id")
                .long("config_id")
                .short('i')
                .help("Config id")
                .required(false))
            .arg(Arg::new("format")
                .long("format")
                .short('f')
                .help("Show format, optional json | yaml")
                .required(false)
                .default_value("yaml"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CMD_SERVER)))
        .subcommand(Command::new("show_connections")
            .about("Show current connections")
            .arg(Arg::new("format")
                .long("format")
                .short('f')
                .help("Show format, optional json | yaml")
                .required(false)
                .default_value("yaml"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CMD_SERVER)))
        .subcommand(Command::new("add_chain")
            .about("Add a chain")
            .arg(Arg::new("config_type")
                .long("config_type")
                .short('t')
                .help("Config type, optional stack | server | inner_service | global_process_chain")
                .required(true))
            .arg(Arg::new("config_id")
                .long("config_id")
                .short('i')
                .help("Config id")
                .required(true))
            .arg(Arg::new("chain_id")
                .long("chain_id")
                .short('n')
                .help("Chain id")
                .required(false))
            .arg(Arg::new("hook_point")
                .long("hook_point")
                .short('k')
                .help("The hook point to which the chain belongs, optional pre | post")
                .required(false)
                .default_value("pre"))
            .arg(Arg::new("chain_type")
                .long("chain_type")
                .short('y')
                .help("Chain type")
                .required(true))
            .arg(Arg::new("chain_params")
                .long("chain_params")
                .short('p')
                .help("Chain params")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CMD_SERVER)))
        .subcommand(Command::new("del_chain")
            .about("Delete a chain")
            .arg(Arg::new("config_type")
                .long("config_type")
                .short('t')
                .help("Config type, optional stack | server | inner_service | global_process_chain")
                .required(true))
            .arg(Arg::new("config_id")
                .long("config_id")
                .short('i')
                .help("Config id")
                .required(true))
            .arg(Arg::new("chain_id")
                .long("chain_id")
                .short('n')
                .help("Chain id")
                .required(true))
            .arg(Arg::new("hook_point")
                .long("hook_point")
                .short('k')
                .help("The hook point to which the chain belongs, optional pre | post")
                .required(false)
                .default_value("pre"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CMD_SERVER))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("login", sub_matches)) => {
            let user = sub_matches.get_one::<String>("user").unwrap();
            let password = sub_matches.get_one::<String>("password").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            if server.to_lowercase() == CMD_SERVER {
                std::process::exit(0);
            }
            let cyfs_cmd_client = CyfsCmdClient::new(server.as_str(), None);
            let login_result = match cyfs_cmd_client.login(user, password).await {
                Ok(result) => result,
                Err(e) => {
                    println!("login error: {}", e);
                    std::process::exit(1);
                }
            };
            save_login_token(server.as_str(), login_result.as_str());
        }
        Some(("show_config", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("config_type");
            let config_id = sub_matches.get_one::<String>("config_id");
            let format = sub_matches.get_one::<String>("format").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            let cyfs_cmd_client = CyfsCmdClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_config(
                config_type.map(|s| s.to_string()),
                config_id.map(|s| s.to_string())).await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("show config error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("show_connections", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let format = sub_matches.get_one::<String>("format").unwrap();
            let cyfs_cmd_client = CyfsCmdClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_connections().await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("show connections error: {}", e);
                }
            }
        }
        Some(("del_chain", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("config_type").expect("config_type is required");
            let config_id = sub_matches.get_one::<String>("config_id").expect("config_id is required");
            let chain_id = sub_matches.get_one::<String>("chain_id").expect("chain_id is required");
            let hook_point = sub_matches.get_one::<String>("hook_point").expect("hook_point is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = CyfsCmdClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.del_chain(config_type, config_id, chain_id, hook_point).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("del chain error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("add_chain", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("config_type").expect("config_type is required");
            let config_id = sub_matches.get_one::<String>("config_id").expect("config_id is required");
            let chain_id = sub_matches.get_one::<String>("chain_id").expect("chain_id is required");
            let chain_type = sub_matches.get_one::<String>("chain_type").expect("chain_type is required");
            let hook_point = sub_matches.get_one::<String>("hook_point").expect("hook_point is required");
            let chain_params = sub_matches.get_one::<String>("chain_params").expect("chain_config is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = CyfsCmdClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_chain(config_type, config_id, hook_point, chain_id, chain_type, chain_params).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("add chain error: {}", e);
                    std::process::exit(1);
                }
            }
        },
        _ => {}
    }
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

    //let config_json : Value = config_json.unwrap();
    info!("Gateway config: {}", serde_json::to_string_pretty(&config_json).unwrap());

    if matches.get_flag("debug") {
        info!("Debug mode enabled");
        std::env::set_var("RUST_BACKTRACE", "1");
        console_subscriber::init();
    }

    // Extract necessary params from command line
    let params = GatewayParams {
        keep_tunnel: matches
            .get_many::<String>("keep_tunnel")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect(),
    };

    if let Err(e) = service_main(config_json, params).await {
        error!("Gateway run error: {}", e);
    }

}
