#[cfg(test)]
mod tests {
    use buckyos_kit::init_logging;
    use cyfs_gateway::*;
    use cyfs_gateway_lib::*;
    use log::error;
    use name_lib::generate_ed25519_key_pair;
    use serde_json::{Value, json};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;
    use url::Url;

    async fn build_rtcp_gateway(
        temp_dir: &TempDir,
        stack_id: &str,
        bind: &str,
        keep_tunnel: &str,
        device_manager_enabled: bool,
    ) -> (Arc<Gateway>, Arc<GatewayConfigParser>, Value, String) {
        std::env::set_var(
            "BUCKYOS_ROOT",
            temp_dir.path().to_string_lossy().to_string(),
        );

        let control_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let (private_key, _) = generate_ed25519_key_pair();
        let key_path = temp_dir.path().join(format!("{stack_id}.private.pem"));
        std::fs::write(&key_path, private_key).unwrap();

        let mut raw_config: Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
        raw_config["stacks"]["__control_server__"]["bind"] =
            json!(format!("127.0.0.1:{control_port}"));
        raw_config["stacks"][stack_id] = json!({
            "id": stack_id,
            "protocol": "rtcp",
            "bind": bind,
            "hook_point": {},
            "key_path": key_path.to_string_lossy(),
            "name": format!("{stack_id}-identity"),
            "keep_tunnel": [keep_tunnel]
        });
        if device_manager_enabled {
            raw_config["device_manager"] = json!({
                "enabled": true,
                "offline_timeout_seconds": 60,
                "cleanup_interval_seconds": 60,
            });
        }

        let parser = Arc::new(GatewayConfigParser::new(Arc::new(
            build_gateway_composition().unwrap(),
        )));
        let config = parser.parse(raw_config.clone()).unwrap();
        let connect_manager = ConnectionManager::new();
        if device_manager_enabled {
            let store = Arc::new(
                SqliteDeviceOnlineStore::new(temp_dir.path().join("device_online.db"))
                    .await
                    .unwrap(),
            );
            connect_manager.set_device_manager(
                DeviceManager::new(
                    store,
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                )
                .await,
            );
        }
        let factory = GatewayFactory::new(connect_manager, parser.clone());
        let gateway = factory
            .create_gateway(None, config.clone(), config)
            .await
            .unwrap();
        gateway
            .start(GatewayParams {
                keep_tunnel: vec![],
            })
            .await
            .unwrap();

        (
            gateway,
            parser,
            raw_config,
            key_path.to_string_lossy().to_string(),
        )
    }

    async fn reload_raw_config(
        gateway: &Gateway,
        parser: &GatewayConfigParser,
        raw_config: Value,
    ) -> anyhow::Result<()> {
        gateway
            .reload(
                parser
                    .parse(raw_config)
                    .map_err(|e| anyhow::anyhow!(e.msg().to_owned()))?,
            )
            .await
    }

    async fn is_pinned(gateway: &Gateway, target: &str) -> bool {
        let url = Url::parse(&format!("rtcp://{target}")).unwrap();
        let normalized = normalize_tunnel_url(&url);
        gateway
            .tunnel_manager()
            .list_tunnel_url_history()
            .await
            .into_iter()
            .find(|entry| entry.normalized_url == normalized)
            .map(|entry| entry.pinned)
            .unwrap_or(false)
    }

    fn free_bind() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn assert_device_manager_state(gateway: &Gateway, enabled: bool) {
        let manager = gateway.connection_manager();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 77, 77, 77)), 12345);
        let destination = "127.0.0.1:23456";
        let connection_id = format!("{source} -> {destination}");
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        manager.add_connection(ConnectionInfo::new(
            source.to_string(),
            destination.to_string(),
            StackProtocol::Tcp,
            Arc::new(NoSpeedStat::new()),
            HandleConnectionController::new(handle),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            !manager.get_all_connection_device_info().is_empty(),
            enabled,
            "connection_manager device_manager state mismatch after failed reload"
        );
        if let Some(connection) = manager.get_connection_info(&connection_id) {
            connection.stop_connection();
        }
    }

    #[tokio::test]
    async fn test_cmd_server() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::env::set_var(
            "BUCKYOS_ROOT",
            temp_dir.path().to_string_lossy().to_string(),
        );
        init_logging("cyfs_gateway", false);
        let mut cmd_config: serde_json::Value =
            serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();
        let control_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        cmd_config["stacks"]["__control_server__"]["bind"] =
            json!(format!("127.0.0.1:{control_port}"));

        // Load config from json
        let parser = Arc::new(GatewayConfigParser::new(Arc::new(
            build_gateway_composition().unwrap(),
        )));
        let load_result = parser.parse(cmd_config);
        if load_result.is_err() {
            let msg = format!("Error loading config: {}", load_result.err().unwrap().msg());
            error!("{}", msg);
            std::process::exit(1);
        }
        let mut config_loader = load_result.unwrap();

        let connect_manager = ConnectionManager::new();
        let factory = GatewayFactory::new(connect_manager.clone(), parser.clone());
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
        assert!(
            system_info
                .get("uptime_sec")
                .and_then(Value::as_u64)
                .is_some()
        );

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

    #[tokio::test]
    async fn test_rtcp_gateway_reload_keep_tunnel_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        init_logging("cyfs_gateway", false);
        let bind = free_bind();
        let (gateway, parser, mut raw_config, key_path) = build_rtcp_gateway(
            &temp_dir,
            "rtcp_reload",
            &bind,
            "old-peer.example",
            false,
        )
        .await;

        assert!(is_pinned(&gateway, "old-peer.example").await);

        raw_config["stacks"]["rtcp_reload"]["keep_tunnel"] = json!(["new-peer.example"]);
        reload_raw_config(&gateway, &parser, raw_config.clone())
            .await
            .unwrap();
        assert!(!is_pinned(&gateway, "old-peer.example").await);
        assert!(is_pinned(&gateway, "new-peer.example").await);

        // Reapplying the same configuration must not add another pin owner.
        reload_raw_config(&gateway, &parser, raw_config.clone())
            .await
            .unwrap();

        // Remove the old Stack and add a replacement with the same bind address.
        raw_config["stacks"]
            .as_object_mut()
            .unwrap()
            .remove("rtcp_reload");
        raw_config["stacks"]["rtcp_reload_replacement"] = json!({
            "id": "rtcp_reload_replacement",
            "protocol": "rtcp",
            "bind": bind,
            "hook_point": {},
            "key_path": key_path,
            "name": "rtcp_reload_replacement-identity",
            "keep_tunnel": ["replacement-peer.example"]
        });
        reload_raw_config(&gateway, &parser, raw_config.clone())
            .await
            .unwrap();
        assert!(!is_pinned(&gateway, "new-peer.example").await);
        assert!(is_pinned(&gateway, "replacement-peer.example").await);

        // Exercise the actual removal path so the test does not leave a live
        // RTCP keep-tunnel task behind when the Gateway is dropped.
        raw_config["stacks"]
            .as_object_mut()
            .unwrap()
            .remove("rtcp_reload_replacement");
        reload_raw_config(&gateway, &parser, raw_config)
            .await
            .unwrap();
        assert!(!is_pinned(&gateway, "replacement-peer.example").await);
    }

    #[tokio::test]
    async fn test_rtcp_gateway_reload_failure_restores_old_stack() {
        let temp_dir = tempfile::tempdir().unwrap();
        init_logging("cyfs_gateway", false);
        let old_bind = free_bind();
        let (gateway, parser, mut raw_config, key_path) = build_rtcp_gateway(
            &temp_dir,
            "rtcp_reload_old",
            &old_bind,
            "old-peer.example",
            false,
        )
        .await;
        assert!(is_pinned(&gateway, "old-peer.example").await);
        let old_raw_config = raw_config.clone();

        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let failing_bind = occupied.local_addr().unwrap().to_string();
        raw_config["stacks"]
            .as_object_mut()
            .unwrap()
            .remove("rtcp_reload_old");
        raw_config["stacks"]["rtcp_reload_new"] = json!({
            "id": "rtcp_reload_new",
            "protocol": "rtcp",
            "bind": failing_bind,
            "hook_point": {},
            "key_path": key_path,
            "name": "rtcp_reload_new-identity",
            "keep_tunnel": ["new-peer.example"]
        });

        assert!(
            reload_raw_config(&gateway, &parser, raw_config)
                .await
                .is_err()
        );
        assert!(gateway.get_config("stack", "rtcp_reload_old").is_ok());
        assert!(is_pinned(&gateway, "old-peer.example").await);
        assert!(!is_pinned(&gateway, "new-peer.example").await);

        drop(occupied);
        reload_raw_config(&gateway, &parser, old_raw_config)
            .await
            .unwrap();
    }

    async fn run_device_manager_reload_failure_case(initial_enabled: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        init_logging("cyfs_gateway", false);
        let old_bind = free_bind();
        let (gateway, parser, mut raw_config, key_path) = build_rtcp_gateway(
            &temp_dir,
            "rtcp_device_manager_reload",
            &old_bind,
            "old-peer.example",
            initial_enabled,
        )
        .await;
        let old_raw_config = raw_config.clone();

        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let failing_bind = occupied.local_addr().unwrap().to_string();
        raw_config["stacks"]
            .as_object_mut()
            .unwrap()
            .remove("rtcp_device_manager_reload");
        raw_config["stacks"]["rtcp_device_manager_new"] = json!({
            "id": "rtcp_device_manager_new",
            "protocol": "rtcp",
            "bind": failing_bind,
            "hook_point": {},
            "key_path": key_path,
            "name": "rtcp_device_manager_new-identity",
            "keep_tunnel": ["new-peer.example"]
        });
        raw_config["device_manager"] = json!({
            "enabled": !initial_enabled,
            "offline_timeout_seconds": 60,
            "cleanup_interval_seconds": 60,
        });

        assert!(
            reload_raw_config(&gateway, &parser, raw_config)
                .await
                .is_err()
        );
        assert!(gateway.get_config("stack", "rtcp_device_manager_reload").is_ok());
        assert!(is_pinned(&gateway, "old-peer.example").await);
        assert!(!is_pinned(&gateway, "new-peer.example").await);
        assert_device_manager_state(&gateway, initial_enabled).await;

        drop(occupied);
        reload_raw_config(&gateway, &parser, old_raw_config)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_rtcp_gateway_reload_failure_restores_device_manager() {
        run_device_manager_reload_failure_case(false).await;
        run_device_manager_reload_failure_case(true).await;
    }
}
