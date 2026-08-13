use std::collections::HashMap;
use std::sync::Arc;

use cyfs_gateway_lib::{config_err, ConfigErrorCode, ConfigResult};
use cyfs_gateway_lib::{
    stack_err, ConnectionManagerRef, GlobalCollectionManagerRef, GlobalProcessChainsRef,
    JsExternalsManagerRef, LimiterManagerRef, QuicStackContext, QuicStackFactory, RtcpStackContext,
    RtcpStackFactory, SelfCertMgrRef, ServerManagerRef, StackConfig, StackContext, StackErrorCode,
    StackFactory, StackProtocol, StackRef, StackResult, StatManagerRef, TcpStackContext,
    TcpStackFactory, TlsStackContext, TlsStackFactory, TunnelManager, UdpStackContext,
    UdpStackFactory,
};
use serde::Deserialize;

use crate::{
    QuicStackConfigParser, RtcpStackConfigParser, StackConfigParser, TcpStackConfigParser,
    TlsStackConfigParser, UdpStackConfigParser,
};

pub type JsonStackConfigParser = dyn StackConfigParser<serde_json::Value>;

/// All services a stack registration may use while building one runtime generation.
///
/// A fresh value is created for initial startup and every reload. Registration closures must only
/// use this value and must not capture managers from an earlier generation.
pub struct GatewayStackRuntime {
    pub connection_manager: ConnectionManagerRef,
    pub server_manager: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
    pub self_cert_manager: SelfCertMgrRef,
    pub server_runtime: cyfs_gateway_lib::ReuseportServerRuntime,
}

pub trait GatewayStackFactoryBuilder: Send + Sync {
    fn build(&self, runtime: &GatewayStackRuntime) -> StackResult<Arc<dyn StackFactory>>;
}

impl<F> GatewayStackFactoryBuilder for F
where
    F: Fn(&GatewayStackRuntime) -> StackResult<Arc<dyn StackFactory>> + Send + Sync,
{
    fn build(&self, runtime: &GatewayStackRuntime) -> StackResult<Arc<dyn StackFactory>> {
        self(runtime)
    }
}

pub trait GatewayStackContextBuilder: Send + Sync {
    fn build(&self, runtime: &GatewayStackRuntime) -> StackResult<Arc<dyn StackContext>>;
}

impl<F> GatewayStackContextBuilder for F
where
    F: Fn(&GatewayStackRuntime) -> StackResult<Arc<dyn StackContext>> + Send + Sync,
{
    fn build(&self, runtime: &GatewayStackRuntime) -> StackResult<Arc<dyn StackContext>> {
        self(runtime)
    }
}

pub struct GatewayStackRegistration {
    protocol: String,
    source: String,
    config_parser: Arc<JsonStackConfigParser>,
    factory_builder: Arc<dyn GatewayStackFactoryBuilder>,
    context_builder: Arc<dyn GatewayStackContextBuilder>,
}

impl GatewayStackRegistration {
    pub fn new<P, S, F, C>(
        protocol: P,
        source: S,
        config_parser: Arc<JsonStackConfigParser>,
        factory_builder: F,
        context_builder: C,
    ) -> Self
    where
        P: Into<String>,
        S: Into<String>,
        F: GatewayStackFactoryBuilder + 'static,
        C: GatewayStackContextBuilder + 'static,
    {
        Self {
            protocol: protocol.into(),
            source: source.into(),
            config_parser,
            factory_builder: Arc::new(factory_builder),
            context_builder: Arc::new(context_builder),
        }
    }

    pub fn protocol(&self) -> &str {
        self.protocol.as_str()
    }

    pub fn source(&self) -> &str {
        self.source.as_str()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GatewayStackRegistryError {
    #[error("stack protocol must not be empty (source: {registration_source})")]
    EmptyProtocol { registration_source: String },

    #[error(
        "stack protocol '{protocol}' is already registered by '{existing_source}'; duplicate source: '{new_source}'"
    )]
    DuplicateProtocol {
        protocol: String,
        existing_source: String,
        new_source: String,
    },
}

#[derive(Default)]
pub struct GatewayStackRegistryBuilder {
    registrations: HashMap<String, GatewayStackRegistration>,
}

impl GatewayStackRegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        registration: GatewayStackRegistration,
    ) -> Result<(), GatewayStackRegistryError> {
        let protocol = registration.protocol().to_string();
        if protocol.trim().is_empty() {
            return Err(GatewayStackRegistryError::EmptyProtocol {
                registration_source: registration.source().to_string(),
            });
        }
        if let Some(existing) = self.registrations.get(protocol.as_str()) {
            return Err(GatewayStackRegistryError::DuplicateProtocol {
                protocol,
                existing_source: existing.source().to_string(),
                new_source: registration.source().to_string(),
            });
        }
        self.registrations.insert(protocol, registration);
        Ok(())
    }

    pub fn build(self) -> Result<GatewayStackRegistry, GatewayStackRegistryError> {
        Ok(GatewayStackRegistry {
            registrations: self
                .registrations
                .into_iter()
                .map(|(protocol, registration)| (protocol, Arc::new(registration)))
                .collect(),
        })
    }
}

pub struct GatewayStackRegistry {
    registrations: HashMap<String, Arc<GatewayStackRegistration>>,
}

impl GatewayStackRegistry {
    pub fn registered_protocols(&self) -> Vec<String> {
        let mut protocols = self.registrations.keys().cloned().collect::<Vec<_>>();
        protocols.sort();
        protocols
    }

    pub fn registration(&self, protocol: &str) -> Option<Arc<GatewayStackRegistration>> {
        self.registrations.get(protocol).cloned()
    }

    pub fn parse_stack_config(
        &self,
        value: serde_json::Value,
    ) -> ConfigResult<Arc<dyn StackConfig>> {
        #[derive(Deserialize)]
        struct ProtocolConfig {
            protocol: String,
        }

        let protocol = serde_json::from_value::<ProtocolConfig>(value.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack protocol: {} input:\n{}",
                e,
                serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| "<invalid json>".to_string())
            )
        })?;
        let Some(registration) = self.registrations.get(protocol.protocol.as_str()) else {
            return Err(config_err!(
                ConfigErrorCode::InvalidConfig,
                "unknown stack protocol '{}'; registered stack protocols: [{}]",
                protocol.protocol,
                self.registered_protocols().join(", ")
            ));
        };
        registration.config_parser.parse(value)
    }

    pub async fn create_stack(
        &self,
        config: Arc<dyn StackConfig>,
        runtime: &GatewayStackRuntime,
    ) -> StackResult<StackRef> {
        let protocol = protocol_key(&config.stack_protocol());
        let Some(registration) = self.registrations.get(protocol.as_str()) else {
            return Err(stack_err!(
                StackErrorCode::UnsupportedStackProtocol,
                "unknown stack protocol '{}'; registered stack protocols: [{}]",
                protocol,
                self.registered_protocols().join(", ")
            ));
        };
        let factory = registration.factory_builder.build(runtime)?;
        let context = registration.context_builder.build(runtime)?;
        factory.create(config, context).await
    }

    pub fn build_context(
        &self,
        config: &Arc<dyn StackConfig>,
        runtime: &GatewayStackRuntime,
    ) -> StackResult<Arc<dyn StackContext>> {
        let protocol = protocol_key(&config.stack_protocol());
        let Some(registration) = self.registrations.get(protocol.as_str()) else {
            return Err(stack_err!(
                StackErrorCode::UnsupportedStackProtocol,
                "unknown stack protocol '{}'; registered stack protocols: [{}]",
                protocol,
                self.registered_protocols().join(", ")
            ));
        };
        registration.context_builder.build(runtime)
    }

    pub async fn prepare_stack_update(
        &self,
        stack: &StackRef,
        config: Arc<dyn StackConfig>,
        runtime: &GatewayStackRuntime,
    ) -> StackResult<()> {
        let context = self.build_context(&config, runtime)?;
        stack.prepare_update(config, Some(context)).await
    }
}

fn protocol_key(protocol: &StackProtocol) -> String {
    match protocol {
        StackProtocol::Tcp => "tcp".to_string(),
        StackProtocol::Udp => "udp".to_string(),
        StackProtocol::Rtcp => "rtcp".to_string(),
        StackProtocol::Tls => "tls".to_string(),
        StackProtocol::Quic => "quic".to_string(),
        StackProtocol::Extension(protocol) => protocol.clone(),
    }
}

pub(crate) fn register_core_gateway_stacks(
    builder: &mut GatewayStackRegistryBuilder,
) -> Result<(), GatewayStackRegistryError> {
    builder.register(GatewayStackRegistration::new(
        "tcp",
        "cyfs-gateway-app-lib::tcp",
        Arc::new(TcpStackConfigParser::new()),
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(TcpStackFactory::new(
                runtime.connection_manager.clone(),
                runtime.server_runtime.clone(),
            )) as Arc<dyn StackFactory>)
        },
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(TcpStackContext::new(
                runtime.server_manager.clone(),
                runtime.tunnel_manager.clone(),
                runtime.limiter_manager.clone(),
                runtime.stat_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.global_collection_manager.clone(),
                runtime.js_externals.clone(),
            )) as Arc<dyn StackContext>)
        },
    ))?;
    builder.register(GatewayStackRegistration::new(
        "udp",
        "cyfs-gateway-app-lib::udp",
        Arc::new(UdpStackConfigParser::new()),
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(UdpStackFactory::new(
                runtime.connection_manager.clone(),
                runtime.server_runtime.clone(),
            )) as Arc<dyn StackFactory>)
        },
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(UdpStackContext::new(
                runtime.server_manager.clone(),
                runtime.tunnel_manager.clone(),
                runtime.limiter_manager.clone(),
                runtime.stat_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.global_collection_manager.clone(),
                runtime.js_externals.clone(),
            )) as Arc<dyn StackContext>)
        },
    ))?;
    builder.register(GatewayStackRegistration::new(
        "rtcp",
        "cyfs-gateway-app-lib::rtcp",
        Arc::new(RtcpStackConfigParser::new()),
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(RtcpStackFactory::new(
                runtime.connection_manager.clone(),
                runtime.server_runtime.clone(),
            )) as Arc<dyn StackFactory>)
        },
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(RtcpStackContext::new(
                runtime.server_manager.clone(),
                runtime.tunnel_manager.clone(),
                runtime.limiter_manager.clone(),
                runtime.stat_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.global_collection_manager.clone(),
                runtime.js_externals.clone(),
            )) as Arc<dyn StackContext>)
        },
    ))?;
    builder.register(GatewayStackRegistration::new(
        "tls",
        "cyfs-gateway-app-lib::tls",
        Arc::new(TlsStackConfigParser::new()),
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(TlsStackFactory::new(
                runtime.connection_manager.clone(),
                runtime.server_runtime.clone(),
            )) as Arc<dyn StackFactory>)
        },
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(TlsStackContext::new(
                runtime.server_manager.clone(),
                runtime.tunnel_manager.clone(),
                runtime.limiter_manager.clone(),
                runtime.stat_manager.clone(),
                runtime.self_cert_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.global_collection_manager.clone(),
                runtime.js_externals.clone(),
            )) as Arc<dyn StackContext>)
        },
    ))?;
    builder.register(GatewayStackRegistration::new(
        "quic",
        "cyfs-gateway-app-lib::quic",
        Arc::new(QuicStackConfigParser::new()),
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(QuicStackFactory::new(
                runtime.connection_manager.clone(),
                runtime.server_runtime.clone(),
            )) as Arc<dyn StackFactory>)
        },
        |runtime: &GatewayStackRuntime| {
            Ok(Arc::new(QuicStackContext::new(
                runtime.server_manager.clone(),
                runtime.tunnel_manager.clone(),
                runtime.limiter_manager.clone(),
                runtime.stat_manager.clone(),
                runtime.self_cert_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.global_collection_manager.clone(),
                runtime.js_externals.clone(),
            )) as Arc<dyn StackContext>)
        },
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cyfs_gateway_lib::{
        ConnectionManager, DefaultLimiterManager, SelfCertConfig, SelfCertMgr, ServerManager,
        Stack, StackContext, StatManager,
    };
    use serde_json::json;

    use super::*;

    struct TestConfig(String);

    impl StackConfig for TestConfig {
        fn id(&self) -> String {
            self.0.clone()
        }

        fn stack_protocol(&self) -> StackProtocol {
            StackProtocol::Tcp
        }

        fn get_config_json(&self) -> String {
            json!({ "id": self.0, "protocol": "tcp" }).to_string()
        }
    }

    struct TestParser;

    impl StackConfigParser<serde_json::Value> for TestParser {
        fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn StackConfig>> {
            Ok(Arc::new(TestConfig(
                value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("test")
                    .to_string(),
            )))
        }
    }

    struct TestContext(usize);

    impl StackContext for TestContext {
        fn stack_protocol(&self) -> StackProtocol {
            StackProtocol::Tcp
        }
    }

    struct TestStack(String);

    #[async_trait::async_trait]
    impl Stack for TestStack {
        fn id(&self) -> String {
            self.0.clone()
        }

        fn stack_protocol(&self) -> StackProtocol {
            StackProtocol::Tcp
        }

        fn get_bind_addr(&self) -> String {
            String::new()
        }

        async fn start(&self) -> StackResult<()> {
            Ok(())
        }

        async fn prepare_update(
            &self,
            _config: Arc<dyn StackConfig>,
            _context: Option<Arc<dyn StackContext>>,
        ) -> StackResult<()> {
            Ok(())
        }

        async fn commit_update(&self) {}

        async fn rollback_update(&self) {}
    }

    struct TestFactory {
        expected_runtime: usize,
        seen: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait::async_trait]
    impl StackFactory for TestFactory {
        async fn create(
            &self,
            config: Arc<dyn StackConfig>,
            context: Arc<dyn StackContext>,
        ) -> StackResult<StackRef> {
            let context = context
                .as_any()
                .downcast_ref::<TestContext>()
                .expect("test context");
            assert_eq!(context.0, self.expected_runtime);
            self.seen.lock().unwrap().push(context.0);
            Ok(Arc::new(TestStack(config.id())))
        }
    }

    async fn test_runtime(self_cert_manager: SelfCertMgrRef) -> GatewayStackRuntime {
        GatewayStackRuntime {
            connection_manager: ConnectionManager::new(),
            server_manager: Arc::new(ServerManager::new()),
            tunnel_manager: TunnelManager::new(),
            limiter_manager: Arc::new(DefaultLimiterManager::new()),
            stat_manager: StatManager::new(),
            global_process_chains: None,
            global_collection_manager: None,
            js_externals: None,
            self_cert_manager,
            server_runtime: cyfs_gateway_lib::ReuseportServerRuntime::start(
                cyfs_gateway_lib::ReuseportServerRuntimeConfig::new(),
            )
            .unwrap(),
        }
    }

    fn registration(protocol: &str, source: &str) -> GatewayStackRegistration {
        GatewayStackRegistration::new(
            protocol,
            source,
            Arc::new(TcpStackConfigParser::new()),
            |runtime: &GatewayStackRuntime| {
                Ok(Arc::new(TcpStackFactory::new(
                    runtime.connection_manager.clone(),
                    runtime.server_runtime.clone(),
                )) as Arc<dyn StackFactory>)
            },
            |runtime: &GatewayStackRuntime| {
                Ok(Arc::new(TcpStackContext::new(
                    runtime.server_manager.clone(),
                    runtime.tunnel_manager.clone(),
                    runtime.limiter_manager.clone(),
                    runtime.stat_manager.clone(),
                    runtime.global_process_chains.clone(),
                    runtime.global_collection_manager.clone(),
                    runtime.js_externals.clone(),
                )) as Arc<dyn StackContext>)
            },
        )
    }

    #[test]
    fn duplicate_registration_fails_without_overwriting_first() {
        let mut builder = GatewayStackRegistryBuilder::new();
        builder.register(registration("tcp", "first")).unwrap();
        let error = builder.register(registration("tcp", "second")).unwrap_err();
        assert_eq!(
            error,
            GatewayStackRegistryError::DuplicateProtocol {
                protocol: "tcp".to_string(),
                existing_source: "first".to_string(),
                new_source: "second".to_string(),
            }
        );
    }

    #[test]
    fn empty_protocol_is_rejected() {
        for protocol in ["", "  "] {
            let mut builder = GatewayStackRegistryBuilder::new();
            assert!(matches!(
                builder.register(registration(protocol, "empty-test")),
                Err(GatewayStackRegistryError::EmptyProtocol { .. })
            ));
        }
    }

    #[test]
    fn unknown_protocol_lists_sorted_capabilities() {
        let mut builder = GatewayStackRegistryBuilder::new();
        builder.register(registration("zeta", "zeta")).unwrap();
        builder.register(registration("alpha", "alpha")).unwrap();
        let registry = builder.build().unwrap();
        let error = registry
            .parse_stack_config(serde_json::json!({ "protocol": "missing" }))
            .err()
            .unwrap();
        assert!(error.msg().contains("missing"));
        assert!(error.msg().contains("[alpha, zeta]"));
    }

    #[test]
    fn core_capability_snapshot_is_complete() {
        let mut builder = GatewayStackRegistryBuilder::new();
        register_core_gateway_stacks(&mut builder).unwrap();
        let registry = builder.build().unwrap();
        assert_eq!(
            registry.registered_protocols(),
            ["quic", "rtcp", "tcp", "tls", "udp"].map(str::to_string)
        );
    }

    #[tokio::test]
    async fn factory_and_context_use_each_runtime_generation() {
        let temp = tempfile::tempdir().unwrap();
        let mut self_cert_config = SelfCertConfig::default();
        self_cert_config.store_path = temp.path().to_string_lossy().to_string();
        let self_cert_manager = SelfCertMgr::create(self_cert_config).await.unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut builder = GatewayStackRegistryBuilder::new();
        let factory_seen = seen.clone();
        builder
            .register(GatewayStackRegistration::new(
                "tcp",
                "runtime-test",
                Arc::new(TestParser),
                move |runtime: &GatewayStackRuntime| {
                    Ok(Arc::new(TestFactory {
                        expected_runtime: Arc::as_ptr(&runtime.connection_manager) as usize,
                        seen: factory_seen.clone(),
                    }) as Arc<dyn StackFactory>)
                },
                |runtime: &GatewayStackRuntime| {
                    Ok(Arc::new(TestContext(
                        Arc::as_ptr(&runtime.connection_manager) as usize
                    )) as Arc<dyn StackContext>)
                },
            ))
            .unwrap();
        let registry = builder.build().unwrap();

        let first = test_runtime(self_cert_manager.clone()).await;
        let second = test_runtime(self_cert_manager).await;
        let first_marker = Arc::as_ptr(&first.connection_manager) as usize;
        let second_marker = Arc::as_ptr(&second.connection_manager) as usize;
        assert_ne!(first_marker, second_marker);

        for (id, runtime) in [("first", &first), ("second", &second)] {
            let config = registry
                .parse_stack_config(json!({ "id": id, "protocol": "tcp" }))
                .unwrap();
            registry.create_stack(config, runtime).await.unwrap();
        }
        assert_eq!(*seen.lock().unwrap(), vec![first_marker, second_marker]);
    }
}
