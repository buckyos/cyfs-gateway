#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use jsonwebtoken::jwk::Jwk;
    use log::error;
    use name_lib::generate_ed25519_key_pair;
    use serde_json::Value;
    use cyfs_gateway::*;
    use cyfs_gateway_lib::*;

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
        async fn load_key(&self) -> CmdResult<(EncodingKey, DecodingKey)> {
            let mut private_key = self.private_key.lock().await;
            let mut content: String = String::new();
            private_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let private_key = EncodingKey::from_ed_pem(content.as_bytes())
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let mut public_key = self.public_key.lock().await;
            let mut content: String = String::new();
            public_key.read_to_string(&mut content)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;

            let public_key: Jwk = serde_json::from_str(content.as_str())
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            let decode_key = DecodingKey::from_jwk(&public_key)
                .map_err(into_cmd_err!(CmdErrorCode::Failed))?;
            Ok((private_key, decode_key))
        }

        async fn save_key(&self, sign_key: String, public_key: Value) -> CmdResult<()> {
            let mut private_key = self.private_key.lock().await;
            private_key.write_all(sign_key.as_bytes()).unwrap();
            let mut public_file = self.public_key.lock().await;
            public_file.write_all(serde_json::to_string(&public_key).unwrap().as_bytes()).unwrap();
            Ok(())
        }
    }
    #[tokio::test]
    async fn test_cmd_server() {
        let mut cmd_config: serde_json::Value = serde_yaml_ng::from_str(CYFS_CMD_SERVER_CONFIG).unwrap();

        // Load config from json
        let parser = GatewayConfigParser::new();
        parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
        parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
        parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
        parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
        parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));

        parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));

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

        let store = TempKeyStore::new();
        let token_manager = LocalTokenManager::new(
            Some("test".to_string()),
            Some("123456".to_string()),
            store).await.unwrap();
        let handler = GatewayCmdHandler::new();
        factory.register_inner_service_factory(
            "cmd_server",
            Arc::new(CyfsCmdServerFactory::new(handler.clone(), token_manager.clone(), token_manager.clone())));

        let gateway = factory.create_gateway(config_loader).await;
        assert!(gateway.is_ok());
        let gateway = gateway.unwrap();
        let params = GatewayParams {
            keep_tunnel: vec![],
        };
        gateway.start(params).await;
        handler.set_gateway(Arc::new(gateway));

        let cmd_client = CyfsCmdClient::new("http://127.0.0.1:13451".to_string(), None);
        let ret = cmd_client.get_config(None, None).await;
        assert!(ret.is_err());

        let ret = cmd_client.login("test", "123456").await;
        assert!(ret.is_ok());

        let ret = cmd_client.get_config(None, None).await;
        assert!(ret.is_ok());
    }
}
