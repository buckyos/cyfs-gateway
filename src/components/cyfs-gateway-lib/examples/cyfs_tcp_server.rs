use std::collections::HashMap;
use std::env::current_dir;
use std::sync::Arc;
use buckyos_kit::init_logging;
use name_client::init_name_lib;
use name_lib::{generate_ed25519_key_pair, load_raw_private_key, DeviceConfig};
use cyfs_gateway_lib::{GatewayDevice, TunnelManager, GATEWAY_TUNNEL_MANAGER};

#[tokio::main]
async fn main() {
    // init_logging("cyfs_tcp_server",false);
    //
    // let path = current_dir().unwrap().join("cyfs_tcp_server.yaml");
    // let config = if path.exists() {
    //     let yaml_config = std::fs::read_to_string(path).unwrap();
    //     let config = match YamlCyfsServerConfigParser::parse(yaml_config.as_str()) {
    //         Ok(config) => config,
    //         Err(e) => {
    //             println!("parse config error: {}", e);
    //             return;
    //         }
    //     };
    //     config
    // } else {
    //     let yaml_config = include_str!("cyfs_tcp_server.yaml");
    //     let config = match YamlCyfsServerConfigParser::parse(yaml_config) {
    //         Ok(config) => config,
    //         Err(e) => {
    //             println!("parse config error: {}", e);
    //             return;
    //         }
    //     };
    //     config
    // };
    //
    // let key_path = current_dir().unwrap().join("device_key.pem");
    // let device_path = current_dir().unwrap().join("device.doc.json");
    // if !key_path.exists() || !device_path.exists() {
    //     let (signing_key, pkcs8_bytes) = generate_ed25519_key_pair();
    //     let device_config = DeviceConfig::new_by_jwk("test", serde_json::from_value(pkcs8_bytes).unwrap());
    //     let device_doc = serde_json::to_string(&device_config).unwrap();
    //     std::fs::write(key_path.as_path(), signing_key).unwrap();
    //     std::fs::write(device_path.as_path(), device_doc).unwrap();
    // }
    //
    // let pkcs8_bytes = load_raw_private_key(key_path.as_path()).unwrap();
    // let device = std::fs::read_to_string(device_path.as_path()).unwrap();
    // let device_config = serde_json::from_str::<DeviceConfig>(device.as_str()).unwrap();
    // let tunnel_manager = TunnelManager::new();
    // tunnel_manager.get_tunnel_builder_by_protocol("rtcp").await.unwrap();
    // let _ = GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);
    // init_name_lib(&HashMap::new()).await.unwrap();
    // std::future::pending::<()>().await;
}
