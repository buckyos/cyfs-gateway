use buckyos_kit::init_logging;
use cyfs_gateway_lib::{CyfsServerConfigParser, CyfsServerManager, YamlCyfsServerConfigParser};

#[tokio::main]
async fn main() {
    init_logging("cyfs_tcp_server",false);
    let yaml_config = r#"
servers:
- server:
    protocol: tcp
    bind: 0.0.0.0
    port: 80
    process_chains:
      - id: main
        priority: 1
        blocks:
            # 根据host匹配的规则
           - id: default
             block: |
                return "forward tcp://127.0.0.1:8081";
                "#;

    let config = YamlCyfsServerConfigParser::parse(yaml_config).unwrap();

    let server_manager = CyfsServerManager::new();
    server_manager.start_server(config).await.unwrap();
    std::future::pending::<()>().await;
}
