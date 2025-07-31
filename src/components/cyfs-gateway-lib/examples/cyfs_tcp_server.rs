use std::sync::Arc;
use buckyos_kit::init_logging;
use name_lib::DeviceConfig;
use cyfs_gateway_lib::{CyfsServerConfigParser, CyfsServerManager, GatewayDevice, TunnelManager, YamlCyfsServerConfigParser, GATEWAY_TUNNEL_MANAGER};

#[tokio::main]
async fn main() {
    init_logging("cyfs_tcp_server",false);
    let yaml_config = r#"
servers:
- server:
    protocol: tcp
    bind: 0.0.0.0
    port: 8080
    process_chains:
      - id: main
        priority: 1
        blocks:
            # 根据host匹配的规则
           - id: default
             block: |
                return "forward tcp:///www.baidu.com:80";
- server:
    port: 80
    process_chains:
      - id: main
        priority: 1
        blocks:
          - id: default
            block: |
                return "http www.buckyos.com";
      - id: www.buckyos.com
        priority: 2
        blocks:
          - id: default
            block: |
                echo "hello world";
                "#;

    let config = YamlCyfsServerConfigParser::parse(yaml_config).unwrap();

    let tunnel_manager = TunnelManager::new(Arc::new(GatewayDevice {
        config: DeviceConfig::new("test", "MC4CAQAwBQYDK2VwBCIEICCrQGVPIZGLTbmhPi9K3Sv3L7P+W+O7RdnVxx5y7Rvb".to_string()),
        private_key: [0u8; 48],
    }));
    GATEWAY_TUNNEL_MANAGER.set(tunnel_manager);
    let server_manager = CyfsServerManager::new();
    server_manager.start_server(config).await.unwrap();
    std::future::pending::<()>().await;
}
