#![allow(dead_code)]
#![allow(unused_imports)]

mod gateway;
mod gateway_control_client;
mod gateway_control_server;
mod config_loader;

pub use gateway::*;
pub use gateway_control_client::*;
pub use gateway_control_server::*;
pub use config_loader::*;


use std::collections::HashSet;
use buckyos_kit::*;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console_subscriber::{self, Server};
use cyfs_dns::{LocalDnsFactory, ProcessChainDnsServerFactory};
use cyfs_gateway_lib::*;

use log::*;
use name_client::*;
use name_lib::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use json_value_merge::Merge;
use kRPC::RPCSessionToken;
use serde_json::{Value};
use tokio::fs::create_dir_all;
use tokio::task;
use url::Url;
use cyfs_sn::SNServerFactory;
use cyfs_socks::SocksServerFactory;
use cyfs_tun::TunStackFactory;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub async fn gateway_service_main(config_file: &Path, params: GatewayParams) -> Result<()> {
    let mut config_json = load_config_from_file(config_file).await?;
    let base_dir = PathBuf::from(config_file.parent().unwrap());
    normalize_all_path_value_config(&mut config_json,&base_dir);
    info!("Gateway config: {}", serde_json::to_string_pretty(&config_json).unwrap());

    let config_dir = config_file.parent().ok_or_else(|| {
        let msg = format!("cannot get config dir: {:?}", config_file);
        error!("{}", msg);
        msg
    })?;

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

    // Load config from json
    let parser = GatewayConfigParser::new();
    parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
    parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
    parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
    parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
    parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));
    parser.register_stack_config_parser("tun", Arc::new(TunStackConfigParser::new()));

    parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));
    parser.register_server_config_parser("socks", Arc::new(SocksServerConfigParser::new()));
    parser.register_server_config_parser("dns", Arc::new(DnsServerConfigParser::new()));
    parser.register_server_config_parser("dir", Arc::new(DirServerConfigParser::new()));

    parser.register_server_config_parser("control_server", Arc::new(GatewayControlServerConfigParser::new()));
    parser.register_server_config_parser("local_dns", Arc::new(LocalDnsConfigParser::new()));
    parser.register_server_config_parser("sn", Arc::new(SNServerConfigParser::new()));
    parser.register_server_config_parser("acme_response", Arc::new(AcmeHttpChallengeServerConfigParser::new()));

    info!("Parse cyfs-gatway config...");
    let load_result = parser.parse(config_json);
    if load_result.is_err() {
        let msg = format!("Error loading config: {}", load_result.err().unwrap().msg());
        error!("{}", msg);
        std::process::exit(1);
    }
    let config_loader = load_result.unwrap();
    info!("Parse cyfs-gatway config success");
    
    let connect_manager = ConnectionManager::new();
    let tunnel_manager = TunnelManager::new();
    let server_manager = Arc::new(ServerManager::new());
    let global_process_chains = Arc::new(GlobalProcessChains::new());
    let limiter_manager = LimiterManager::new();
    let stat_manager = StatManager::new();
    if let Some(limiters_config) = config_loader.limiters_config.clone() {
        for limiter_config in limiters_config.iter() {
            if limiter_manager.get_limiter(limiter_config.id.as_str()).is_some() {
                log::error!("Create limiter {} error: limiter already exists", limiter_config.id);
                continue;
            }
            if let Some(upper_limiter) = limiter_config.upper_limiter.clone() {
                if limiter_manager.get_limiter(upper_limiter.as_str()).is_none() {
                    log::error!("Create limiter {} error: upper limiter {} not found", limiter_config.id, upper_limiter);
                }
            }
            let _ = limiter_manager.new_limiter(limiter_config.id.clone(),
                                                limiter_config.upper_limiter.clone(),
                                                limiter_config.concurrent.map(|v| v as u32),
                                                limiter_config.download_speed.map(|v| v as u32),
                                                limiter_config.upload_speed.map(|v| v as u32));
        }
    }

    let mut cert_config = CertManagerConfig::default();
    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("certs");
    let dns_provider_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("acme_dns_provider");
    cert_config.keystore_path = data_dir.to_string_lossy().to_string();
    if let Some(acme_config) = config_loader.acme_config.clone() {
        cert_config.account = acme_config.account;
        if acme_config.issuer.is_some() {
            cert_config.acme_server = acme_config.issuer.unwrap();
        }
        cert_config.dns_providers = acme_config.dns_providers;
        if acme_config.check_interval.is_some() {
            if let Some(check_interval) = chrono::Duration::new(acme_config.check_interval.unwrap() as i64, 0) {
                cert_config.check_interval = check_interval;
            }
        }

        if acme_config.renew_before_expiry.is_some() {
            if let Some(renew_before_expiry) = chrono::Duration::new(acme_config.renew_before_expiry.unwrap() as i64, 0) {
                cert_config.renew_before_expiry = renew_before_expiry;
            }
        }
    }
    cert_config.dns_provider_path = Some(dns_provider_dir.to_string_lossy().to_string());

    let cert_manager = AcmeCertManager::create(cert_config).await?;

    let factory = GatewayFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        cert_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    );
    factory.register_stack_factory(StackProtocol::Tcp, Arc::new(TcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    debug!("Register tcp stack factory");
    factory.register_stack_factory(StackProtocol::Udp, Arc::new(UdpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    debug!("Register udp stack factory");
    factory.register_stack_factory(StackProtocol::Tls, Arc::new(TlsStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        cert_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    debug!("Register tls stack factory");
    factory.register_stack_factory(StackProtocol::Quic, Arc::new(QuicStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        cert_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Rtcp, Arc::new(RtcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    debug!("Register rtcp stack factory");
    factory.register_stack_factory(StackProtocol::Extension("tun".to_string()), Arc::new(TunStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
    )));
    debug!("Register tun stack factory");
    factory.register_server_factory("http", Arc::new(ProcessChainHttpServerFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        tunnel_manager.clone(),
    )));
    debug!("Register http server factory");
    factory.register_server_factory("dir", Arc::new(DirServerFactory::new()));

    factory.register_server_factory("socks", Arc::new(SocksServerFactory::new(
        global_process_chains.clone(),
    )));
    debug!("Register dir server factory");
    factory.register_server_factory("dns", Arc::new(ProcessChainDnsServerFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
    )));
    debug!("Register dns server factory");
    factory.register_server_factory("acme_response", Arc::new(AcmeHttpChallengeServerFactory::new(cert_manager.clone())));
    debug!("Register acme response server factory");
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
    let handler = GatewayCmdHandler::new(
        Arc::new(external_cmd_store),
        config_file.to_path_buf(),
        parser);
    factory.register_server_factory(
        "control_server",
        Arc::new(GatewayControlServerFactory::new(handler.clone(), token_manager.clone(), token_manager.clone())));
    factory.register_server_factory(
        "local_dns",
        Arc::new(LocalDnsFactory::new(config_dir.to_string_lossy().to_string())));
    factory.register_server_factory(
        "sn",
        Arc::new(SNServerFactory::new())
    );

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
async fn load_config_from_args(matches: &clap::ArgMatches) -> Result<(PathBuf, PathBuf, serde_json::Value)> {
    let mut default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.yaml");
    if !default_config.exists() {
        default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.json");
    }
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

    Ok((config_dir.to_path_buf(), real_config_file, config_json))
}

fn get_config_file_path(matches: &clap::ArgMatches) -> PathBuf {
    let mut default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.yaml");
    if !default_config.exists() {
        default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.json");
    }
    let config_file = matches.get_one::<String>("config_file");
    let real_config_file;
    if config_file.is_none() {
        real_config_file = default_config;
    } else {
        real_config_file = PathBuf::from(config_file.unwrap());
    }
    set_gateway_main_config_dir(&real_config_file);
    real_config_file
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

    if server.to_lowercase() == CONTROL_SERVER {
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
    if server.to_lowercase() == CONTROL_SERVER {
        return;
    }
    let token_dir = get_buckyos_service_data_dir("cyfs_gateway").join("cli_token");
    let token_file = token_dir.join(hex::encode(server.to_lowercase()));
    let _ = std::fs::write(token_file, token);
}


pub async fn cyfs_gateway_main() {
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
        .subcommand(Command::new("gen_rtcp_key")
            .about("Generate a new rtcp key pair")
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("rtcp name")
                .required(true))
            .arg(Arg::new("path")
                .long("path")
                .short('p')
                .help("The save path of the generated key")
                .required(false)))
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
                .default_value(CONTROL_SERVER)))
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
                .default_value(CONTROL_SERVER)))
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
                .default_value(CONTROL_SERVER)))
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
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER))
            .arg(Arg::new("chain_params")
                .help("Chain params") // 接受一个或多个值
                .num_args(1..)
                .value_delimiter(None) // 禁用分隔符解析，保持参数原样
                .last(true)     // 确保此参数必须放在最后
                .required(false)))
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
                .default_value(CONTROL_SERVER))
        )
        .subcommand(Command::new("reload")
            .about("reload config")
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .get_matches();

    match matches.subcommand() {
        Some(("gen_rtcp_key", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").expect("Missing key 'name'");
            // Get temp path
            let temp_dir = std::env::temp_dir();
            let key_dir = temp_dir.join("buckyos").join("keys");
            let default_path = key_dir.to_string_lossy().to_string();
            let save_path = sub_matches.get_one::<String>("path").unwrap_or(&default_path);
            let key_dir = Path::new(save_path);
            if !key_dir.is_dir() {
                std::fs::create_dir_all(&key_dir).unwrap();
            }
            println!("key_dir: {:?}", key_dir);

            let (private_key, public_key) = generate_ed25519_key_pair();
            let device_config = DeviceConfig::new_by_jwk(name, serde_json::from_value(public_key).unwrap());
            let sk_file = key_dir.join("device.key.pem");
            std::fs::write(&sk_file, private_key).unwrap();
            println!("Private key saved to: {:?}", sk_file);

            let pk_file = key_dir.join("device.doc.json");
            std::fs::write(&pk_file, serde_json::to_string(&device_config).unwrap()).unwrap();
            println!("Device doc saved to: {:?}", pk_file);
            std::process::exit(0);
        }
        Some(("login", sub_matches)) => {
            let user = sub_matches.get_one::<String>("user").unwrap();
            let password = sub_matches.get_one::<String>("password").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            if server.to_lowercase() == CONTROL_SERVER {
                std::process::exit(0);
            }
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), None);
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
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_config(
                config_type.map(|s| s.to_string()),
                config_id.map(|s| s.to_string())).await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("show config error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("show_connections", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let format = sub_matches.get_one::<String>("format").unwrap();
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_connections().await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("show connections error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("del_chain", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("config_type").expect("config_type is required");
            let config_id = sub_matches.get_one::<String>("config_id").expect("config_id is required");
            let chain_id = sub_matches.get_one::<String>("chain_id").expect("chain_id is required");
            let hook_point = sub_matches.get_one::<String>("hook_point").expect("hook_point is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.del_chain(config_type, config_id, chain_id, hook_point).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("del chain error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
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
            let chain_params = sub_matches.get_many::<String>("chain_params").expect("chain_params is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_chain(config_type, config_id, hook_point, chain_id, chain_type, chain_params.map(|s| s.clone()).collect::<Vec<_>>().join(" ").as_str()).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("add chain error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        },
        Some(("reload", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.reload().await {
                Ok(result) => {
                    println!("{}", result.to_string());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("reload error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        _ => {}
    }

    // init log
    init_logging("cyfs_gateway",true);
    info!("cyfs_gateway start...");

    let config_file = get_config_file_path(&matches);


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

    if let Err(e) = gateway_service_main(config_file.as_path(), params).await {
        error!("Gateway run error: {}", e);
    }

}
