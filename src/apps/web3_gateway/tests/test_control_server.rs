#[cfg(test)]
mod tests {
    use buckyos_kit::init_logging;
    use cyfs_gateway_lib::*;
    use log::error;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use web3_gateway::*;

    #[tokio::test]
    async fn test_cmd_server() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var(
            "BUCKYOS_ROOT",
            temp_dir.path().to_string_lossy().to_string(),
        );
        init_logging("web3_gateway", false);
        let mut cmd_config: serde_json::Value =
            serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
        let control_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        cmd_config["stacks"]["__control_server__"]["bind"] =
            json!(format!("127.0.0.1:{control_port}"));

        // Load config from json
        let parser = Arc::new(GatewayConfigParser::new(
            build_default_gateway_server_registry().unwrap(),
        ));
        parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
        parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
        parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
        parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
        parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));

        let load_result = parser.parse(cmd_config);
        if load_result.is_err() {
            let msg = format!("Error loading config: {}", load_result.err().unwrap().msg());
            error!("{}", msg);
            std::process::exit(1);
        }
        let mut config_loader = load_result.unwrap();

        let connect_manager = ConnectionManager::new();
        let factory = GatewayFactory::new(connect_manager.clone(), parser.clone());
        factory.register_stack_factory(
            StackProtocol::Tcp,
            Arc::new(TcpStackFactory::new(connect_manager.clone())),
        );
        factory.register_stack_factory(
            StackProtocol::Udp,
            Arc::new(UdpStackFactory::new(connect_manager.clone())),
        );
        factory.register_stack_factory(
            StackProtocol::Tls,
            Arc::new(TlsStackFactory::new(connect_manager.clone())),
        );
        factory.register_stack_factory(
            StackProtocol::Quic,
            Arc::new(QuicStackFactory::new(connect_manager.clone())),
        );
        factory.register_stack_factory(
            StackProtocol::Rtcp,
            Arc::new(RtcpStackFactory::new(connect_manager.clone())),
        );

        let login = json!({
            "user_name": "test",
            "password": "123456"
        });
        merge(&mut config_loader.raw_config, &login);
        let gateway = factory
            .create_gateway(None, config_loader.clone(), config_loader)
            .await;
        assert!(gateway.is_ok());
        let gateway = gateway.unwrap();
        let params = GatewayParams {
            keep_tunnel: vec![],
        };
        gateway.start(params).await.unwrap();

        let cmd_client =
            GatewayControlClient::new(format!("http://127.0.0.1:{control_port}"), None);
        let ret = cmd_client.get_system_info().await;
        assert!(ret.is_ok());
        let system_info = ret.unwrap();
        assert_eq!(
            system_info.get("ui_mode").and_then(Value::as_str),
            Some("developer")
        );
        assert!(system_info
            .get("uptime_sec")
            .and_then(Value::as_u64)
            .is_some());

        // The replacement manager is built entirely through the registry before any
        // stack is updated. Force a late manager-build failure by colliding with the
        // built-in `welcome` HTTP server, then verify the old control plane survives.
        let old_config = gateway.get_all_config().unwrap();
        let mut failing_raw = old_config.clone();
        failing_raw
            .as_object_mut()
            .unwrap()
            .entry("servers")
            .or_insert_with(|| json!({}))["welcome"] = json!({
            "type": "dir",
            "root_path": temp_dir.path().to_string_lossy()
        });
        let failing_config = parser.parse(failing_raw).unwrap();
        assert!(gateway.reload(failing_config).await.is_err());
        assert_eq!(gateway.get_all_config().unwrap(), old_config);
        assert!(cmd_client.get_system_info().await.is_ok());

        let ret = cmd_client.get_config_by_id(None).await;
        assert!(ret.is_err());

        let ret = cmd_client.login("test", "123456").await;
        assert!(ret.is_ok());

        let ret = cmd_client.get_config_by_id(None).await;
        ret.as_ref().unwrap();
        assert!(ret.is_ok());

        let ret = cmd_client
            .add_name_provider("http://127.0.0.1:8080", Some(100))
            .await;
        ret.as_ref().unwrap();
        let added_provider = ret.unwrap();
        assert_eq!(
            added_provider.get("provider").and_then(Value::as_str),
            Some("https-resolver:127.0.0.1:8080")
        );
        assert_eq!(
            added_provider.get("scheme").and_then(Value::as_str),
            Some("http")
        );

        let urls = vec![
            "udp://127.0.0.1:9/".to_string(),
            "unknown://127.0.0.1:9/".to_string(),
        ];
        let ret = cmd_client
            .query_tunnel_url_statuses(
                &urls,
                TunnelProbeOptions {
                    sort: TunnelUrlSortPolicy::ReachableFirst,
                    include_unsupported: false,
                    ..Default::default()
                },
            )
            .await;
        ret.as_ref().unwrap();
        let tunnel_statuses = ret.unwrap();
        assert_eq!(
            tunnel_statuses
                .get("statuses")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            tunnel_statuses
                .get("sorted_urls")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }
}
