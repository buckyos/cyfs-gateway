#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::Arc;
    use buckyos_kit::init_logging;
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use jsonwebtoken::jwk::Jwk;
    use log::error;
    use name_lib::generate_ed25519_key_pair;
    use serde_json::Value;
    use cyfs_gateway::*;
    use cyfs_gateway_lib::*;
    use sfo_js::JsPkgManager;

    pub struct TempKeyStore {
        private_key: tokio::sync::Mutex<tempfile::NamedTempFile>,
        public_key: tokio::sync::Mutex<tempfile::NamedTempFile>,
    }

    impl TempKeyStore {
        pub fn new() -> Self {
            TempKeyStore {
                private_key: tokio::sync::Mutex::new(tempfile::NamedTempFile::new().unwrap()),
                public_key: tokio::sync::Mutex::new(tempfile::NamedTempFile::new().unwrap()),
            }
        }

        pub async fn new_key(&self) {
            let (sign_key, public_key_value) = generate_ed25519_key_pair();
            self.save_key(sign_key, public_key_value).await.unwrap();
        }
    }

    #[async_trait::async_trait]
    impl TokenKeyStore for TempKeyStore {
        async fn load_key(&self) -> ControlResult<(EncodingKey, DecodingKey)> {
            let mut private_key = self.private_key.lock().await;
            let mut content: String = String::new();
            private_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let private_key = EncodingKey::from_ed_pem(content.as_bytes())
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let mut public_key = self.public_key.lock().await;
            let mut content: String = String::new();
            public_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;

            let public_key: Jwk = serde_json::from_str(content.as_str())
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            let decode_key = DecodingKey::from_jwk(&public_key)
                .map_err(into_cmd_err!(ControlErrorCode::Failed))?;
            Ok((private_key, decode_key))
        }

        async fn save_key(&self, sign_key: String, public_key: Value) -> ControlResult<()> {
            let mut private_key = self.private_key.lock().await;
            private_key.write_all(sign_key.as_bytes()).unwrap();
            let mut public_file = self.public_key.lock().await;
            public_file.write_all(serde_json::to_string(&public_key).unwrap().as_bytes()).unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_cmd_server() {
        init_logging("cyfs_gateway", false);
        let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG).unwrap();

        // Load config from json
        let parser = Arc::new(GatewayConfigParser::new());
        parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
        parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
        parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
        parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
        parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));

        parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));

        parser.register_server_config_parser("control_server", Arc::new(GatewayControlServerConfigParser::new()));
        parser.register_server_config_parser("acme_response", Arc::new(AcmeHttpChallengeServerConfigParser::new()));

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
        let cert_manager = AcmeCertManager::create(CertManagerConfig::default()).await.unwrap();
        let limiter_manager = LimiterManager::new();
        let stat_manager = StatManager::new();
        let self_cert_mgr = SelfCertMgr::create(SelfCertConfig::default()).await.unwrap();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let external_cmds = JsPkgManager::new(PathBuf::from("."));

        let stack_manager = StackManager::new();
        let factory = GatewayFactory::new(
            stack_manager.clone(),
            server_manager.clone(),
            global_process_chains.clone(),
            connect_manager.clone(),
            tunnel_manager.clone(),
            cert_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            self_cert_mgr.clone(),
            collection_manager.clone(),
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
            collection_manager.clone(),
        )));
        factory.register_stack_factory(StackProtocol::Udp, Arc::new(UdpStackFactory::new(
            server_manager.clone(),
            global_process_chains.clone(),
            connect_manager.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            collection_manager.clone(),
        )));
        factory.register_stack_factory(StackProtocol::Tls, Arc::new(TlsStackFactory::new(
            server_manager.clone(),
            global_process_chains.clone(),
            connect_manager.clone(),
            tunnel_manager.clone(),
            cert_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            self_cert_mgr.clone(),
            collection_manager.clone(),
        )));
        factory.register_stack_factory(StackProtocol::Quic, Arc::new(QuicStackFactory::new(
            server_manager.clone(),
            global_process_chains.clone(),
            connect_manager.clone(),
            tunnel_manager.clone(),
            cert_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            self_cert_mgr.clone(),
            collection_manager.clone(),
        )));
        factory.register_stack_factory(StackProtocol::Rtcp, Arc::new(RtcpStackFactory::new(
            server_manager.clone(),
            global_process_chains.clone(),
            connect_manager.clone(),
            tunnel_manager.clone(),
            limiter_manager.clone(),
            stat_manager.clone(),
            collection_manager.clone(),
        )));

        factory.register_server_factory("http", Arc::new(ProcessChainHttpServerFactory::new(
            server_manager.clone(),
            global_process_chains.clone(),
            tunnel_manager.clone(),
            collection_manager.clone(),
        )));

        let store = TempKeyStore::new();
        let token_manager = LocalTokenManager::new(
            Some("test".to_string()),
            Some("123456".to_string()),
            store).await.unwrap();
        let handler = GatewayCmdHandler::new(Some(PathBuf::from("config.yaml")), parser.clone());
        factory.register_server_factory("control_server", Arc::new(GatewayControlServerFactory::new(handler.clone(), token_manager.clone(), token_manager.clone())));
        factory.register_server_factory("acme_response", Arc::new(AcmeHttpChallengeServerFactory::new(
            cert_manager.clone(),
        )));
        let gateway = factory.create_gateway(config_loader).await;
        assert!(gateway.is_ok());
        let gateway = gateway.unwrap();
        let params = GatewayParams {
            keep_tunnel: vec![],
        };
        gateway.start(params).await.unwrap();
        handler.set_gateway(Arc::new(gateway));

        let cmd_client = GatewayControlClient::new("http://127.0.0.1:13451".to_string(), None);
        let ret = cmd_client.get_config_by_id(None).await;
        assert!(ret.is_err());

        let ret = cmd_client.login("test", "123456").await;
        assert!(ret.is_ok());

        let ret = cmd_client.get_config_by_id(None).await;
        assert!(ret.is_ok());
    }
}
