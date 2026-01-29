#![allow(dead_code)]
#![allow(unused_imports)]

mod gateway;
mod gateway_control_client;
mod gateway_control_server;
mod config_loader;
mod config_merger;
mod acme_sn_provider;
mod process_chain_doc;
mod socks;

pub use gateway::*;
pub use gateway_control_client::*;
pub use gateway_control_server::*;
pub use config_loader::*;
pub use config_merger::*;
use acme_sn_provider::*;


use std::collections::HashSet;
use clap::{Arg, ArgAction, ArgMatches, Command};
use console_subscriber::{self, Server};
use cyfs_dns::{InnerDnsRecordManager, LocalDnsFactory, ProcessChainDnsServerFactory};
use cyfs_gateway_lib::*;
use process_chain_doc::GatewayProcessChainDoc;

use log::*;
use name_client::*;
use name_lib::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use anyhow::anyhow;
use anyhow::Result;
use buckyos_kit::{get_buckyos_log_dir, get_buckyos_service_data_dir, get_buckyos_system_etc_dir};
use kRPC::RPCSessionToken;
use serde::{Deserialize};
use serde_json::{Value};
use sfo_js::{JsEngine, JsPkgManager, JsString, JsValue};
use sfo_js::object::builtins::JsArray;
use tokio::fs::create_dir_all;
use tokio::task;
use url::Url;
use cyfs_sn::{SnServerFactory, SqliteDBFactory};
use cyfs_socks::SocksServerFactory;
use cyfs_tun::TunStackFactory;


#[derive(Deserialize)]
pub struct LogParams {
    pub level: Option<String>,
    pub path: Option<String>,
    pub file_size: Option<String>,
    pub file_count: Option<usize>,
}

fn parse_size_bytes(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("size is empty").into());
    }

    let upper = trimmed.to_ascii_uppercase();
    let (number_part, unit) = if upper.ends_with("GB") {
        (&upper[..upper.len() - 2], "GB")
    } else if upper.ends_with("MB") {
        (&upper[..upper.len() - 2], "MB")
    } else if upper.ends_with("KB") {
        (&upper[..upper.len() - 2], "KB")
    } else if upper.ends_with('B') {
        (&upper[..upper.len() - 1], "B")
    } else {
        (upper.as_str(), "B")
    };

    let number_part = number_part.trim();
    if number_part.is_empty() {
        return Err(anyhow!("size missing number: {}", input).into());
    }

    let value: u64 = number_part
        .parse()
        .map_err(|_| anyhow!("invalid size number: {}", input))?;
    let multiplier = match unit {
        "GB" => 1024_u64.pow(3),
        "MB" => 1024_u64.pow(2),
        "KB" => 1024_u64,
        "B" => 1,
        _ => return Err(anyhow!("unsupported size unit: {}", input).into()),
    };

    Ok(value.saturating_mul(multiplier))
}

pub async fn gateway_service_main(config_file: &Path, params: GatewayParams) -> Result<()> {
    let config_json = load_config_from_file(config_file).await?;
    info!("Gateway config: {}", serde_json::to_string_pretty(&config_json).unwrap());

    run_gateway_with_config(config_json, Some(config_file), params).await
}

async fn run_gateway_with_config(
    config_json: Value,
    config_file: Option<&Path>,
    params: GatewayParams,
) -> Result<()> {
    let config_dir = if let Some(config_file) = config_file {
        Some(config_file.parent().ok_or_else(|| {
            let msg = format!("cannot get config dir: {:?}", config_file);
            error!("{}", msg);
            anyhow!(msg)
        })?)
    } else {
        None
    };

    let user_name: Option<String> = match config_json.get("user_name") {
        Some(user_name) => user_name.as_str().map(|value| value.to_string()),
        None => None,
    };
    let password: Option<String> = match config_json.get("password") {
        Some(password) => password.as_str().map(|value| value.to_string()),
        None => None,
    };

    let parser = Arc::new(GatewayConfigParser::new());
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
    let gateway_config = parser.parse(config_json.clone()).map_err(|e| {
        let msg = format!("Error loading config: {}", e.msg());
        error!("{}", msg);
        anyhow::anyhow!(msg)
    })?;
    info!("Parse cyfs-gatway config success");

    let connect_manager = ConnectionManager::new();
    let tunnel_manager = TunnelManager::new();
    let stack_manager = StackManager::new();
    let server_manager = Arc::new(ServerManager::new());
    let global_process_chains = Arc::new(GlobalProcessChains::new());
    let limiter_manager = LimiterManager::new();
    let stat_manager = StatManager::new();
    if let Some(limiters_config) = gateway_config.limiters_config.clone() {
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
            let _ = limiter_manager.new_limiter(
                limiter_config.id.clone(),
                limiter_config.upper_limiter.clone(),
                limiter_config.concurrent.map(|v| v as u32),
                limiter_config.download_speed.map(|v| v as u32),
                limiter_config.upload_speed.map(|v| v as u32),
            );
        }
    }

    let sn_acme_data = get_buckyos_service_data_dir("cyfs_gateway").join("sn_dns");
    if !sn_acme_data.exists() {
        std::fs::create_dir_all(&sn_acme_data).unwrap();
    }
    let sn_provider_factory = AcmeSnProviderFactory::new(sn_acme_data);
    AcmeCertManager::register_dns_provider_factory("sn-dns", sn_provider_factory.clone());
    let mut cert_config = CertManagerConfig::default();
    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("certs");
    let dns_provider_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("acme_dns_provider");
    cert_config.keystore_path = data_dir.to_string_lossy().to_string();
    if let Some(acme_config) = gateway_config.acme_config.clone() {
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
    sn_provider_factory.set_acme_mgr(cert_manager.clone());
    let inner_dns_record_manager = InnerDnsRecordManager::new();
    let record_manager = inner_dns_record_manager.clone();
    cert_manager.register_dns_provider("local", move |op: String, domain: String, key_hash: String| {
        let record_manager = record_manager.clone();
        async move {
            if op == "add_challenge" {
                record_manager.add_record(domain, "TXT", key_hash).map_err(|e| anyhow!(e.to_string()))
            } else if op == "del_challenge" {
                record_manager.remove_record(domain, "TXT");
                Ok(())
            } else {
                Err(anyhow!("Unsupported op: {}", op))
            }
        }
    });

    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("self_certs");
    let mut self_cert_config = SelfCertConfig::default();
    if let Some(config) = gateway_config.tls_ca.clone() {
        self_cert_config.ca_path = Some(config.cert_path);
        self_cert_config.key_path = Some(config.key_path);
    }
    self_cert_config.store_path = data_dir.to_string_lossy().to_string();
    let self_cert_manager = SelfCertMgr::create(self_cert_config).await?;

    let global_collections = GlobalCollectionManager::create(gateway_config.collections.clone()).await?;

    let chain_cmds = get_buckyos_system_etc_dir().join("cyfs_gateway").join("server_templates");
    let external_cmds = JsPkgManager::new(chain_cmds);
    let factory = GatewayFactory::new(
        stack_manager.clone(),
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        cert_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
        self_cert_manager.clone(),
        global_collections.clone(),
        external_cmds,
        parser.clone(),
    );
    factory.register_stack_factory(StackProtocol::Tcp, Arc::new(TcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
        global_collections.clone(),
    )));
    debug!("Register tcp stack factory");
    factory.register_stack_factory(StackProtocol::Udp, Arc::new(UdpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
        global_collections.clone(),
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
        self_cert_manager.clone(),
        global_collections.clone(),
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
        self_cert_manager.clone(),
        global_collections.clone(),
    )));
    factory.register_stack_factory(StackProtocol::Rtcp, Arc::new(RtcpStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
        global_collections.clone(),
    )));
    debug!("Register rtcp stack factory");
    factory.register_stack_factory(StackProtocol::Extension("tun".to_string()), Arc::new(TunStackFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        connect_manager.clone(),
        tunnel_manager.clone(),
        limiter_manager.clone(),
        stat_manager.clone(),
        global_collections.clone(),
    )));
    debug!("Register tun stack factory");
    factory.register_server_factory("http", Arc::new(ProcessChainHttpServerFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        tunnel_manager.clone(),
        global_collections.clone(),
    )));
    debug!("Register http server factory");
    factory.register_server_factory("dir", Arc::new(DirServerFactory::new()));
    factory.register_server_factory("socks", Arc::new(SocksServerFactory::new(
        global_process_chains.clone(),
        global_collections.clone(),
        socks::SocksTunnelBuilder::new_ref(tunnel_manager.clone())
    )));
    debug!("Register dir server factory");
    factory.register_server_factory("dns", Arc::new(ProcessChainDnsServerFactory::new(
        server_manager.clone(),
        global_process_chains.clone(),
        global_collections.clone(),
        inner_dns_record_manager,
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
    let handler = GatewayCmdHandler::new(config_file.map(|v| v.to_path_buf()), parser.clone());
    factory.register_server_factory(
        "control_server",
        Arc::new(GatewayControlServerFactory::new(handler.clone(), token_manager.clone(), token_manager.clone())),
    );
    info!("Register control server factory");
    factory.register_server_factory(
        "local_dns",
        Arc::new(LocalDnsFactory::new(config_dir.map(|v| v.to_string_lossy().to_string()))),
    );
    info!("Register local dns server factory");
    let mut sn_factory = SnServerFactory::new();
    sn_factory.register_db_factory("sqlite", SqliteDBFactory::new());
    factory.register_server_factory("sn", Arc::new(sn_factory));
    info!("Register sn server factory");
    let gateway = factory.create_gateway(gateway_config).await.map_err(|e| {
        let msg = format!("create gateway failed: {}", e);
        error!("{}", msg);
        anyhow::anyhow!(msg)
    })?;
    gateway.start(params).await?;
    handler.set_gateway(Arc::new(gateway));

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}

fn get_config_file_path(matches: &clap::ArgMatches) -> PathBuf {
    let default_config = get_default_config_path();
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

pub fn read_login_token(server: &str) -> Option<String> {
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

struct StartTemplateArgs {
    template_id: Option<String>,
    args: Vec<String>,
    help: bool,
}

fn parse_template_args(command: &str, ignore_server: bool) -> StartTemplateArgs {
    let mut args = Vec::new();
    let mut seen_start = false;
    for arg in std::env::args() {
        if seen_start {
            args.push(arg);
        } else if arg == command {
            seen_start = true;
        }
    }

    let mut filtered = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if !ignore_server {
            filtered.push(arg);
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--server" || arg == "-s" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--server=") || arg.starts_with("-s=") {
            continue;
        }
        filtered.push(arg);
    }

    let mut help = false;
    let mut template_id = None;
    let mut template_args = Vec::new();
    for arg in filtered {
        if arg == "--help" || arg == "-h" {
            help = true;
            continue;
        }
        if template_id.is_none() && !arg.starts_with('-') {
            template_id = Some(arg);
        } else if template_id.is_some() {
            template_args.push(arg);
        }
    }

    StartTemplateArgs {
        template_id,
        args: template_args,
        help,
    }
}

async fn run_template_local(template_id: &str, args: Vec<String>) -> Result<()> {
    let template_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("server_templates");
    let external_cmds = JsPkgManager::new(template_dir);
    let pkg = external_cmds.get_pkg(template_id)
        .await
        .map_err(|e| anyhow!("get pkg failed: {:?}", e))?;
    let output = run_server_tempalte_pkg(pkg, args).await.map_err(|e| {
        let msg = format!("run template failed: {}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;
    let output = output.trim();
    if output.is_empty() {
        return Err(anyhow!("template returned empty config"));
    }
    let template_config: Value = serde_json::from_str(output)
        .map_err(|e| anyhow!("invalid template config: {}", e))?;
    let mut config_json = buckyos_kit::apply_params_to_json(&template_config, None)
        .map_err(|e| anyhow!("apply params failed: {}", e))?;
    let config_dir = std::env::current_dir().map_err(|e| anyhow!("read current dir failed: {}", e))?;
    normalize_all_path_value_config(&mut config_json, config_dir.as_path());
    run_gateway_with_config(config_json, None, GatewayParams { keep_tunnel: vec![] }).await
}


pub async fn cyfs_gateway_main() {
    let command = Command::new("CYFS Gateway Service")
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
        .subcommand(Command::new("show")
            .about("Show config")
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
                .default_value(CONTROL_SERVER))
            .subcommand(Command::new("config")
                .about("Show current config")
                .arg(Arg::new("id")
                    .help("config id")
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
                    .default_value(CONTROL_SERVER))))
        .subcommand(Command::new("save")
            .about("Save current config to device")
            .arg(Arg::new("config")
                .long("config")
                .short('c')
                .help("save path")
                .required(false))
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
        .subcommand(Command::new("add_rule")
            .about("Add a rule")
            .after_help("Examples:\n  cyfs_gateway add_rule stack:s1:main \"http-probe && call-server www;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("append_rule")
            .about("Append a rule with lowest priority")
            .after_help("Examples:\n  cyfs_gateway append_rule stack:s1:main \"eq ${REQ.host} \\\"a.com\\\" && call-server a;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("insert_rule")
            .about("Insert a rule at specific position/priority")
            .after_help("Examples:\n  cyfs_gateway insert_rule stack:s1:main 2 \"rewrite /old /new;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("pos")
                .help("priority or line position")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("move_rule")
            .about("Move a chain/block/rule to a new position or priority")
            .after_help("Examples:\n  cyfs_gateway move_rule stack:s1:main 1\n  cyfs_gateway move_rule stack:s1:main:b1:2 3")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("new_pos")
                .help("new priority or line position")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("set_rule")
            .about("Replace a chain/block/line rule content")
            .after_help("Examples:\n  cyfs_gateway set_rule stack:s1:main:b1 \"forward \\\"tcp:///1.1.1.1:80\\\";\"\n  cyfs_gateway set_rule stack:s1:main:b1:2 \"rewrite /old /new;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("new rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add_dispatch")
            .about("Add a local port dispatch to target")
            .after_help("Examples:\n  cyfs_gateway add_dispatch 18080 192.168.0.1:1900\n  cyfs_gateway add_dispatch 0.0.0.0:8080 10.0.0.1:9000 --protocol udp")
            .arg(Arg::new("local")
                .help("local endpoint, such as 18080 or 0.0.0.0:18080")
                .required(true))
            .arg(Arg::new("target")
                .help("target endpoint, ip:port format")
                .required(true))
            .arg(Arg::new("protocol")
                .long("protocol")
                .short('p')
                .help("tcp or udp, default tcp")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_dispatch")
            .about("Remove a local port dispatch")
            .after_help("Examples:\n  cyfs_gateway remove_dispatch 18080\n  cyfs_gateway remove_dispatch 0.0.0.0:8080 --protocol udp")
            .arg(Arg::new("local")
                .help("local endpoint, such as 18080 or 0.0.0.0:18080")
                .required(true))
            .arg(Arg::new("protocol")
                .long("protocol")
                .short('p')
                .help("tcp or udp, default tcp")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add_router")
            .about("Add a router rule to http server")
            .after_help("Examples:\n  cyfs_gateway add_router --uri /sn --target /www\n  cyfs_gateway add_router --uri /api --target http://127.0.0.1:9000/ --id server:api:main")
            .arg(Arg::new("id")
                .long("id")
                .help("rule id (same format as add_rule, e.g. server:<id>:<chain>[:blocks:<block>]), optional; if missing will create router_<rand>")
                .required(false))
            .arg(Arg::new("uri")
                .long("uri")
                .help("uri match rule, supports =/path, /path (prefix), /path/*, ~regex")
                .required(true))
            .arg(Arg::new("target")
                .long("target")
                .help("target mapping, supports dir path or http(s) url")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_router")
            .about("Remove a router rule from http server")
            .after_help("Examples:\n  cyfs_gateway remove_router --id api_router --uri /api --target http://127.0.0.1:9000/")
            .arg(Arg::new("id")
                .long("id")
                .help("rule id (same format as add_rule, optional if unique match can be found)")
                .required(false))
            .arg(Arg::new("uri")
                .long("uri")
                .help("uri match rule used when adding router")
                .required(true))
            .arg(Arg::new("target")
                .long("target")
                .help("target mapping used when adding router")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_rule")
            .about("Delete a rule")
            .after_help("Examples:\n  cyfs_gateway remove_rule stack:s1:main:b1\n  cyfs_gateway remove_rule stack:s1:main:b1:2")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER))
        )
        .subcommand(Command::new("start")
            .allow_external_subcommands(true)
            .allow_missing_positional(true)
            .ignore_errors(true)
            .about("start a new server")
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("run")
            .allow_external_subcommands(true)
            .allow_missing_positional(true)
            .ignore_errors(true)
            .about("run a server template locally"))
        .subcommand(Command::new("process_chain")
            .about("Show process chain command help")
            .arg(Arg::new("command")
                .help("process chain command name")
                .required(false))
            .arg(Arg::new("all")
                .long("all")
                .short('a')
                .help("show full documentation for all commands")
                .action(ArgAction::SetTrue))
            .arg(Arg::new("file")
                .long("file")
                .short('f')
                .help("write output to file")
                .value_name("PATH")
                .required(false)))
        .subcommand(Command::new("reload")
            .about("reload config")
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)));

    let matches = command.clone().get_matches();

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
        Some(("show", sub_matches)) => {
            match sub_matches.subcommand() {
                Some(("config", config_matches)) => {
                    let id = config_matches.get_one::<String>("id");
                    let format = config_matches.get_one::<String>("format").unwrap();
                    let server = config_matches.get_one::<String>("server").unwrap();
                    let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                    let result = cyfs_cmd_client.get_config_by_id(id.map(|value| value.as_str())).await;
                    match result {
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
                            println!("show init config error: {}", e);
                            if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                                save_login_token(server.as_str(), token.as_str());
                            }
                            std::process::exit(1);
                        }
                    }
                }
                None => {
                    let format = sub_matches.get_one::<String>("format").unwrap();
                    let server = sub_matches.get_one::<String>("server").unwrap();
                    let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                    match cyfs_cmd_client.get_init_config().await {
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
                _ => {}
            }
        }
        Some(("save", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let path = sub_matches.get_one::<String>("config");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.save_config(path.map(|s| s.as_str())).await {
                Ok(result) => {
                    if let Some(path) = result.as_str() {
                        println!("config saved: {}", path);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("save config error: {}", e);
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
        Some(("remove_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_rule(id).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("del rule error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_rule", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("id").expect("id is required");
            let config_id = sub_matches.get_one::<String>("rule").expect("rule is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_rule(config_type, config_id).await {
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
        Some(("append_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let rule = sub_matches.get_one::<String>("rule").expect("rule is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.append_rule(id, rule).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("append rule error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("insert_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let pos = sub_matches.get_one::<String>("pos").expect("pos is required");
            let rule = sub_matches.get_one::<String>("rule").expect("rule is required");
            let pos: i32 = pos.parse().expect("pos must be integer");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.insert_rule(id, pos, rule).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("insert rule error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("move_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let pos = sub_matches.get_one::<String>("new_pos").expect("new_pos is required");
            let pos: i32 = pos.parse().expect("new_pos must be integer");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.move_rule(id, pos).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("move rule error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("set_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let rule = sub_matches.get_one::<String>("rule").expect("rule is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.set_rule(id, rule).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("set rule error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_dispatch", sub_matches)) => {
            let local = sub_matches.get_one::<String>("local").expect("local is required");
            let target = sub_matches.get_one::<String>("target").expect("target is required");
            let protocol = sub_matches.get_one::<String>("protocol").map(|s| s.as_str());
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_dispatch(local, target, protocol).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("add dispatch error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_router", sub_matches)) => {
            let server_id = sub_matches.get_one::<String>("id").map(|s| s.as_str());
            let uri = sub_matches.get_one::<String>("uri").expect("uri is required");
            let target = sub_matches.get_one::<String>("target").expect("target is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_router(server_id, uri, target).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("add router error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("remove_router", sub_matches)) => {
            let server_id = sub_matches.get_one::<String>("id").map(|s| s.as_str());
            let uri = sub_matches.get_one::<String>("uri").expect("uri is required");
            let target = sub_matches.get_one::<String>("target").expect("target is required");
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_router(server_id, uri, target).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("remove router error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("remove_dispatch", sub_matches)) => {
            let local = sub_matches.get_one::<String>("local").expect("local is required");
            let protocol = sub_matches.get_one::<String>("protocol").map(|s| s.as_str());
            let server = sub_matches.get_one::<String>("server").expect("server is required");
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_dispatch(local, protocol).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("remove dispatch error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("process_chain", sub_matches)) => {
            let doc = match GatewayProcessChainDoc::new() {
                Ok(doc) => doc,
                Err(e) => {
                    println!("process_chain init error: {}", e);
                    std::process::exit(1);
                }
            };

            let cmd = sub_matches.get_one::<String>("command");
            let output = if sub_matches.get_flag("all") {
                doc.render_all_docs()
            } else if let Some(cmd) = cmd {
                doc.render_command_help(cmd)
            } else {
                doc.render_command_list()
            };

            if let Some(path) = sub_matches.get_one::<String>("file") {
                if let Err(e) = std::fs::write(path, output) {
                    println!("process_chain write error: {}", e);
                    std::process::exit(1);
                }
                println!("Documentation saved to {}", path);
            } else {
                println!("{}", output);
            }
            std::process::exit(0);
        }
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
        Some(("start", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let start_args = parse_template_args("start", true);
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            if start_args.template_id.is_none() {
                match cyfs_cmd_client.get_external_cmds().await {
                    Ok(cmds) => {
                        println!("Available templates ({}):", cmds.len());
                        for cmd in cmds {
                            if cmd.description.is_empty() {
                                println!("  {}", cmd.name);
                            } else {
                                println!("  {} - {}", cmd.name, cmd.description);
                            }
                        }
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("start template list error: {}", e);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }

            let template_id = start_args.template_id.unwrap();
            if start_args.help {
                match cyfs_cmd_client.get_external_cmd_help(template_id.as_str()).await {
                    Ok(help) => {
                        println!("{}", help);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("start template help error: {}", e);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }

            match cyfs_cmd_client.start_template(template_id.as_str(), start_args.args).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("start template error: {}", e);
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("run", _sub_matches)) => {
            let run_args = parse_template_args("run", false);
            let template_dir = get_buckyos_system_etc_dir().join("cyfs_gateway").join("server_templates");
            let external_cmds = JsPkgManager::new(template_dir);
            if run_args.template_id.is_none() {
                match external_cmds.list_pkgs().await {
                    Ok(cmds) => {
                        println!("Available templates ({}):", cmds.len());
                        for cmd in cmds {
                            if cmd.description().is_empty() {
                                println!("  {}", cmd.name());
                            } else {
                                println!("  {} - {}", cmd.name(), cmd.description());
                            }
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("run template list error: {:?}", e);
                        std::process::exit(1);
                    }
                }
            }

            let template_id = run_args.template_id.unwrap();
            if run_args.help {
                match external_cmds.get_pkg(template_id.as_str()).await {
                    Ok(pkg) => match pkg.help().await {
                        Ok(help) => {
                            println!("{}", help);
                            std::process::exit(0);
                        }
                        Err(e) => {
                            println!("run template help error: {:?}", e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        println!("run template help error: {:?}", e);
                        std::process::exit(1);
                    }
                }
            }
            let log_dir = get_buckyos_log_dir("cyfs_gateway", true);
            std::fs::create_dir_all(&log_dir).unwrap();

            sfo_log::Logger::new("cyfs_gateway")
                .set_log_path(log_dir.to_string_lossy().to_string().as_str())
                .set_log_to_file(true)
                .start().unwrap();
            info!("cyfs_gateway start...");

            if matches.get_flag("debug") {
                info!("Debug mode enabled");
                unsafe { std::env::set_var("RUST_BACKTRACE", "1"); }
                console_subscriber::init();
            }
            match run_template_local(template_id.as_str(), run_args.args).await {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("run template error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {}
    }

    let log_config = get_buckyos_service_data_dir("cyfs_gateway").join("log.yaml");
    let mut log_params = LogParams {
        level: None,
        path: None,
        file_size: None,
        file_count: None,
    };
    if log_config.exists() {
        if let Ok(config) = tokio::fs::read_to_string(log_config).await {
            if let Ok(params) = serde_yaml_ng::from_str::<LogParams>(config.as_str()) {
                log_params = params;
            }
        }
    }

    let log_dir = get_buckyos_log_dir("cyfs_gateway", true);
    std::fs::create_dir_all(&log_dir).unwrap();

    sfo_log::Logger::new("cyfs_gateway")
        .set_log_level(log_params.level.unwrap_or("info".to_string()).as_str())
        .set_log_path(log_params.path.unwrap_or(log_dir.to_string_lossy().to_string()).as_str())
        .set_log_to_file(true)
        .set_log_file_count(log_params.file_count.unwrap_or(10))
        .set_log_file_size(parse_size_bytes(log_params.file_size.unwrap_or("20MB".to_string()).as_str()).unwrap_or(20 * 1024 * 1024))
        .start().unwrap();
    // init log
    // init_logging("cyfs_gateway",true);
    info!("cyfs_gateway start...");

    if matches.get_flag("debug") {
        info!("Debug mode enabled");
        unsafe { std::env::set_var("RUST_BACKTRACE", "1"); }
        console_subscriber::init();
    }

    let config_file = get_config_file_path(&matches);

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
