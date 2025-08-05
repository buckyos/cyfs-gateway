use std::env::current_dir;
use std::sync::Arc;
use buckyos_kit::init_logging;
use name_lib::DeviceConfig;
use cyfs_gateway_lib::{CyfsServerConfigParser, CyfsServerManager, GatewayDevice, TunnelManager, YamlCyfsServerConfigParser, GATEWAY_TUNNEL_MANAGER};

#[tokio::main]
async fn main() {
    init_logging("cyfs_tcp_server",false);

    let path = current_dir().unwrap().join("cyfs_tcp_server.yaml");
    let config = if path.exists() {
        let yaml_config = std::fs::read_to_string(path).unwrap();
        let config = match YamlCyfsServerConfigParser::parse(yaml_config.as_str()) {
            Ok(config) => config,
            Err(e) => {
                println!("parse config error: {}", e);
                return;
            }
        };
        config
    } else {
        let yaml_config = include_str!("cyfs_tcp_server.yaml");
        let config = match YamlCyfsServerConfigParser::parse(yaml_config) {
            Ok(config) => config,
            Err(e) => {
                println!("parse config error: {}", e);
                return;
            }
        };
        config
    };


    let tunnel_manager = TunnelManager::new(Arc::new(GatewayDevice {
        config: DeviceConfig::new("test", "MC4CAQAwBQYDK2VwBCIEICCrQGVPIZGLTbmhPi9K3Sv3L7P+W+O7RdnVxx5y7Rvb".to_string()),
        private_key: [0u8; 48],
    }));
    let _ = GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);
    let server_manager = CyfsServerManager::new();
    server_manager.start_server(config).await.unwrap();
    std::future::pending::<()>().await;
}
