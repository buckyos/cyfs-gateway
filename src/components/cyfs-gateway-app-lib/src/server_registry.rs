use std::collections::HashMap;
use std::sync::{Arc, Weak};

use cyfs_acme::AcmeCertManagerRef;
use cyfs_gateway_lib::{
    config_err, server_err, AcmeHttpChallengeServerContext, AcmeHttpChallengeServerFactory,
    CyfsDirServerContext, CyfsDirServerFactory, CyfsTokenFactory, CyfsTokenVerifier,
    DirServerFactory, GatewayControlCmdHandler, GlobalCollectionManagerRef, GlobalProcessChainsRef,
    HttpServerContext, JsExternalsManagerRef, ProcessChainHttpServerFactory, Server, ServerConfig,
    ServerContextRef, ServerErrorCode, ServerFactory, ServerManagerWeakRef, ServerResult,
    TunnelManager,
};
use cyfs_gateway_lib::{ConfigErrorCode, ConfigResult};
use serde::Deserialize;

use crate::{
    AcmeHttpChallengeServerConfigParser, CyfsDirServerConfigParser, DirServerConfigParser,
    GatewayControlServerConfigParser, GatewayControlServerContext, GatewayControlServerFactory,
    HttpServerConfigParser, ServerConfigParser,
};

pub type JsonServerConfigParser = dyn ServerConfigParser<serde_json::Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayServerContextMode {
    Required,
    Contextless,
}

pub struct GatewayServerRuntime {
    pub server_manager: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub tunnel_manager: TunnelManager,
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub acme_manager: AcmeCertManagerRef,
    pub capabilities: Arc<crate::GatewayRuntimeCapabilities>,
    pub control_handler: Weak<dyn GatewayControlCmdHandler>,
    pub control_token_verifier: Arc<dyn CyfsTokenVerifier>,
    pub control_token_factory: Arc<dyn CyfsTokenFactory>,
}

pub trait GatewayServerContextBuilder: Send + Sync {
    fn build(&self, runtime: &GatewayServerRuntime) -> ServerResult<Option<ServerContextRef>>;
}

impl<F> GatewayServerContextBuilder for F
where
    F: Fn(&GatewayServerRuntime) -> ServerResult<Option<ServerContextRef>> + Send + Sync,
{
    fn build(&self, runtime: &GatewayServerRuntime) -> ServerResult<Option<ServerContextRef>> {
        self(runtime)
    }
}

pub struct GatewayServerRegistration {
    server_type: String,
    source: String,
    config_parser: Arc<JsonServerConfigParser>,
    server_factory: Arc<dyn ServerFactory>,
    context_builder: Arc<dyn GatewayServerContextBuilder>,
    context_mode: GatewayServerContextMode,
}

impl GatewayServerRegistration {
    pub fn new<T, S, B>(
        server_type: T,
        source: S,
        config_parser: Arc<JsonServerConfigParser>,
        server_factory: Arc<dyn ServerFactory>,
        context_mode: GatewayServerContextMode,
        context_builder: B,
    ) -> Self
    where
        T: Into<String>,
        S: Into<String>,
        B: GatewayServerContextBuilder + 'static,
    {
        Self {
            server_type: server_type.into(),
            source: source.into(),
            config_parser,
            server_factory,
            context_builder: Arc::new(context_builder),
            context_mode,
        }
    }

    pub fn server_type(&self) -> &str {
        self.server_type.as_str()
    }

    pub fn source(&self) -> &str {
        self.source.as_str()
    }

    pub fn context_mode(&self) -> GatewayServerContextMode {
        self.context_mode
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GatewayServerRegistryError {
    #[error("server type must not be empty (source: {registration_source})")]
    EmptyServerType { registration_source: String },

    #[error(
        "server type '{server_type}' is already registered by '{existing_source}'; duplicate source: '{new_source}'"
    )]
    DuplicateServerType {
        server_type: String,
        existing_source: String,
        new_source: String,
    },
}

#[derive(Default)]
pub struct GatewayServerRegistryBuilder {
    registrations: HashMap<String, GatewayServerRegistration>,
}

impl GatewayServerRegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        registration: GatewayServerRegistration,
    ) -> Result<(), GatewayServerRegistryError> {
        let server_type = registration.server_type().to_string();
        if server_type.trim().is_empty() {
            return Err(GatewayServerRegistryError::EmptyServerType {
                registration_source: registration.source().to_string(),
            });
        }

        if let Some(existing) = self.registrations.get(server_type.as_str()) {
            return Err(GatewayServerRegistryError::DuplicateServerType {
                server_type,
                existing_source: existing.source().to_string(),
                new_source: registration.source().to_string(),
            });
        }

        self.registrations.insert(server_type, registration);
        Ok(())
    }

    pub fn build(self) -> Result<GatewayServerRegistry, GatewayServerRegistryError> {
        Ok(GatewayServerRegistry {
            registrations: self
                .registrations
                .into_iter()
                .map(|(server_type, registration)| (server_type, Arc::new(registration)))
                .collect(),
        })
    }
}

pub struct GatewayServerRegistry {
    registrations: HashMap<String, Arc<GatewayServerRegistration>>,
}

impl GatewayServerRegistry {
    pub fn registered_server_types(&self) -> Vec<String> {
        let mut server_types = self.registrations.keys().cloned().collect::<Vec<_>>();
        server_types.sort();
        server_types
    }

    pub fn registration(&self, server_type: &str) -> Option<Arc<GatewayServerRegistration>> {
        self.registrations.get(server_type).cloned()
    }

    pub fn parse_server_config(
        &self,
        value: serde_json::Value,
    ) -> ConfigResult<Arc<dyn ServerConfig>> {
        #[derive(Deserialize)]
        struct ServerType {
            #[serde(rename = "type")]
            server_type: String,
        }

        let server_type = serde_json::from_value::<ServerType>(value.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid server config type: {} input:\n{}",
                e,
                serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| "<invalid json>".to_string())
            )
        })?;

        let Some(registration) = self.registrations.get(server_type.server_type.as_str()) else {
            return Err(config_err!(
                ConfigErrorCode::InvalidConfig,
                "unknown server type '{}'; registered server types: [{}]",
                server_type.server_type,
                self.registered_server_types().join(", ")
            ));
        };

        registration.config_parser.parse(value)
    }

    pub async fn create_servers(
        &self,
        config: Arc<dyn ServerConfig>,
        runtime: &GatewayServerRuntime,
    ) -> ServerResult<Vec<Server>> {
        let server_type = config.server_type();
        let Some(registration) = self.registrations.get(server_type.as_str()) else {
            return Err(server_err!(
                ServerErrorCode::UnknownServerType,
                "unknown server type '{}'; registered server types: [{}]",
                server_type,
                self.registered_server_types().join(", ")
            ));
        };

        let context = registration.context_builder.build(runtime)?;
        match (registration.context_mode, context.is_some()) {
            (GatewayServerContextMode::Required, false) => {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "server type '{}' requires a context, but its builder returned none",
                    server_type
                ));
            }
            (GatewayServerContextMode::Contextless, true) => {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "server type '{}' is contextless, but its builder returned a context",
                    server_type
                ));
            }
            _ => {}
        }

        registration.server_factory.create(config, context).await
    }
}

pub(crate) fn register_core_gateway_servers(
    builder: &mut GatewayServerRegistryBuilder,
) -> Result<(), GatewayServerRegistryError> {
    use GatewayServerContextMode::{Contextless, Required};

    builder.register(GatewayServerRegistration::new(
        "http",
        "cyfs-gateway-app-lib::http",
        Arc::new(HttpServerConfigParser::new()),
        Arc::new(ProcessChainHttpServerFactory::new()),
        Required,
        |runtime: &GatewayServerRuntime| {
            Ok(Some(Arc::new(HttpServerContext::new(
                runtime.server_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.js_externals.clone(),
                runtime.tunnel_manager.clone(),
                runtime.global_collection_manager.clone(),
            )) as ServerContextRef))
        },
    ))?;
    builder.register(GatewayServerRegistration::new(
        "dir",
        "cyfs-gateway-app-lib::dir",
        Arc::new(DirServerConfigParser::new()),
        Arc::new(DirServerFactory::new()),
        Contextless,
        |_runtime: &GatewayServerRuntime| Ok(None),
    ))?;
    builder.register(GatewayServerRegistration::new(
        "cyfs-dir",
        "cyfs-gateway-app-lib::cyfs-dir",
        Arc::new(CyfsDirServerConfigParser::new()),
        Arc::new(CyfsDirServerFactory::new()),
        Required,
        |runtime: &GatewayServerRuntime| {
            Ok(Some(Arc::new(CyfsDirServerContext::new(
                runtime.server_manager.clone(),
                runtime.global_process_chains.clone(),
                runtime.js_externals.clone(),
                runtime.global_collection_manager.clone(),
            )) as ServerContextRef))
        },
    ))?;
    builder.register(GatewayServerRegistration::new(
        "control_server",
        "cyfs-gateway-app-lib::control_server",
        Arc::new(GatewayControlServerConfigParser::new()),
        Arc::new(GatewayControlServerFactory::new()),
        Required,
        |runtime: &GatewayServerRuntime| {
            Ok(Some(Arc::new(GatewayControlServerContext::new(
                runtime.control_handler.clone(),
                runtime.control_token_verifier.clone(),
                runtime.control_token_factory.clone(),
            )) as ServerContextRef))
        },
    ))?;
    builder.register(GatewayServerRegistration::new(
        "acme_response",
        "cyfs-gateway-app-lib::acme_response",
        Arc::new(AcmeHttpChallengeServerConfigParser::new()),
        Arc::new(AcmeHttpChallengeServerFactory::new()),
        Required,
        |runtime: &GatewayServerRuntime| {
            Ok(Some(Arc::new(AcmeHttpChallengeServerContext::new(
                runtime.acme_manager.clone(),
            )) as ServerContextRef))
        },
    ))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use cyfs_acme::CertManagerConfig;
    use cyfs_gateway_lib::{
        ControlResult, GlobalCollectionManager, GlobalProcessChains, JsExternalsManager,
        ServerContext, ServerManager,
    };
    use serde_json::{json, Value};

    use super::*;

    struct TestConfig {
        id: String,
        server_type: String,
    }

    impl ServerConfig for TestConfig {
        fn id(&self) -> String {
            self.id.clone()
        }

        fn server_type(&self) -> String {
            self.server_type.clone()
        }

        fn get_config_json(&self) -> String {
            json!({ "id": self.id, "type": self.server_type }).to_string()
        }
    }

    struct TestParser {
        marker: &'static str,
    }

    impl ServerConfigParser<Value> for TestParser {
        fn parse(&self, value: Value) -> ConfigResult<Arc<dyn ServerConfig>> {
            Ok(Arc::new(TestConfig {
                id: format!(
                    "{}:{}",
                    self.marker,
                    value.get("id").and_then(Value::as_str).unwrap_or("test")
                ),
                server_type: value["type"].as_str().unwrap().to_string(),
            }))
        }
    }

    struct TestContext {
        server_manager: ServerManagerWeakRef,
    }

    impl ServerContext for TestContext {
        fn get_server_type(&self) -> String {
            "contextful".to_string()
        }
    }

    struct TestFactory {
        expect_context: bool,
        called: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl ServerFactory for TestFactory {
        async fn create(
            &self,
            _config: Arc<dyn ServerConfig>,
            context: Option<ServerContextRef>,
        ) -> ServerResult<Vec<Server>> {
            if context.is_some() != self.expect_context {
                return Err(server_err!(
                    ServerErrorCode::InvalidConfig,
                    "unexpected context presence"
                ));
            }
            if let Some(context) = context {
                let context = context
                    .as_any()
                    .downcast_ref::<TestContext>()
                    .ok_or_else(|| {
                        server_err!(ServerErrorCode::InvalidConfig, "unexpected context type")
                    })?;
                if context.server_manager.upgrade().is_none() {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "context did not use the current runtime manager"
                    ));
                }
            }
            self.called.store(true, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    struct TestControl;

    #[async_trait::async_trait]
    impl GatewayControlCmdHandler for TestControl {
        async fn handle(&self, _method: &str, _params: Value) -> ControlResult<Value> {
            Ok(Value::Null)
        }
    }

    #[async_trait::async_trait]
    impl CyfsTokenFactory for TestControl {
        async fn create(
            &self,
            _use_name: &str,
            _password: &str,
            _timestamp: u64,
        ) -> ControlResult<String> {
            Ok("token".to_string())
        }
    }

    #[async_trait::async_trait]
    impl CyfsTokenVerifier for TestControl {
        async fn verify_and_renew(&self, _token: &str) -> ControlResult<Option<String>> {
            Ok(None)
        }
    }

    fn test_registration(
        server_type: &str,
        source: &str,
        marker: &'static str,
        mode: GatewayServerContextMode,
        expect_context: bool,
        called: Arc<AtomicBool>,
    ) -> GatewayServerRegistration {
        GatewayServerRegistration::new(
            server_type,
            source,
            Arc::new(TestParser { marker }),
            Arc::new(TestFactory {
                expect_context,
                called,
            }),
            mode,
            move |runtime: &GatewayServerRuntime| match mode {
                GatewayServerContextMode::Required => Ok(Some(Arc::new(TestContext {
                    server_manager: runtime.server_manager.clone(),
                })
                    as ServerContextRef)),
                GatewayServerContextMode::Contextless => Ok(None),
            },
        )
    }

    #[test]
    fn duplicate_registration_fails_without_overwriting_first() {
        let mut builder = GatewayServerRegistryBuilder::new();
        builder
            .register(test_registration(
                "test",
                "first",
                "first",
                GatewayServerContextMode::Contextless,
                false,
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        let error = builder
            .register(test_registration(
                "test",
                "second",
                "second",
                GatewayServerContextMode::Contextless,
                false,
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap_err();
        assert_eq!(
            error,
            GatewayServerRegistryError::DuplicateServerType {
                server_type: "test".to_string(),
                existing_source: "first".to_string(),
                new_source: "second".to_string(),
            }
        );

        let registry = builder.build().unwrap();
        let config = registry
            .parse_server_config(json!({ "type": "test", "id": "one" }))
            .unwrap();
        assert_eq!(config.id(), "first:one");
    }

    #[test]
    fn empty_and_whitespace_server_types_are_rejected() {
        for server_type in ["", "   "] {
            let mut builder = GatewayServerRegistryBuilder::new();
            let error = builder
                .register(test_registration(
                    server_type,
                    "empty-test",
                    "unused",
                    GatewayServerContextMode::Contextless,
                    false,
                    Arc::new(AtomicBool::new(false)),
                ))
                .unwrap_err();
            assert!(matches!(
                error,
                GatewayServerRegistryError::EmptyServerType { .. }
            ));
        }
    }

    #[test]
    fn unknown_type_error_lists_stably_sorted_registered_types() {
        let mut builder = GatewayServerRegistryBuilder::new();
        for server_type in ["zeta", "alpha"] {
            builder
                .register(test_registration(
                    server_type,
                    server_type,
                    "unused",
                    GatewayServerContextMode::Contextless,
                    false,
                    Arc::new(AtomicBool::new(false)),
                ))
                .unwrap();
        }
        let registry = builder.build().unwrap();
        assert_eq!(
            registry.registered_server_types(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );

        let error = registry
            .parse_server_config(json!({ "type": "missing" }))
            .err()
            .unwrap();
        assert!(error.msg().contains("missing"));
        assert!(error.msg().contains("[alpha, zeta]"));
    }

    #[tokio::test]
    async fn parse_and_create_share_registration_and_runtime() {
        let contextful_called = Arc::new(AtomicBool::new(false));
        let contextless_called = Arc::new(AtomicBool::new(false));
        let mut builder = GatewayServerRegistryBuilder::new();
        builder
            .register(test_registration(
                "contextful",
                "test",
                "parsed",
                GatewayServerContextMode::Required,
                true,
                contextful_called.clone(),
            ))
            .unwrap();
        builder
            .register(test_registration(
                "contextless",
                "test",
                "parsed",
                GatewayServerContextMode::Contextless,
                false,
                contextless_called.clone(),
            ))
            .unwrap();
        let registry = builder.build().unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let mut acme_config = CertManagerConfig::default();
        acme_config.keystore_path = temp_dir.path().to_string_lossy().to_string();
        let acme_manager = cyfs_acme::AcmeCertManager::create(acme_config)
            .await
            .unwrap();
        let server_manager = Arc::new(ServerManager::new());
        let control = Arc::new(TestControl);
        let control_handler: Arc<dyn GatewayControlCmdHandler> = control.clone();
        let runtime = GatewayServerRuntime {
            server_manager: Arc::downgrade(&server_manager),
            global_process_chains: Arc::new(GlobalProcessChains::new()),
            js_externals: Arc::new(JsExternalsManager::new()),
            tunnel_manager: TunnelManager::new(),
            global_collection_manager: GlobalCollectionManager::new(),
            acme_manager,
            capabilities: Arc::new(crate::GatewayRuntimeCapabilities::default()),
            control_handler: Arc::downgrade(&control_handler),
            control_token_verifier: control.clone(),
            control_token_factory: control,
        };

        for server_type in ["contextful", "contextless"] {
            let config = registry
                .parse_server_config(json!({ "type": server_type, "id": server_type }))
                .unwrap();
            registry.create_servers(config, &runtime).await.unwrap();
        }

        assert!(contextful_called.load(Ordering::SeqCst));
        assert!(contextless_called.load(Ordering::SeqCst));
    }

    #[test]
    fn core_capability_snapshot_is_complete() {
        let mut builder = GatewayServerRegistryBuilder::new();
        register_core_gateway_servers(&mut builder).unwrap();
        let registry = builder.build().unwrap();
        assert_eq!(
            registry.registered_server_types(),
            ["acme_response", "control_server", "cyfs-dir", "dir", "http"].map(str::to_string)
        );

        let expected_modes = [
            ("acme_response", GatewayServerContextMode::Required),
            ("control_server", GatewayServerContextMode::Required),
            ("cyfs-dir", GatewayServerContextMode::Required),
            ("dir", GatewayServerContextMode::Contextless),
            ("http", GatewayServerContextMode::Required),
        ];
        for (server_type, expected_mode) in expected_modes {
            let registration = registry.registration(server_type).unwrap();
            assert_eq!(registration.server_type(), server_type);
            assert!(!registration.source().is_empty());
            assert_eq!(registration.context_mode(), expected_mode);
        }
    }
}
