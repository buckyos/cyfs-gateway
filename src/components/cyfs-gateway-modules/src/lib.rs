mod acme_sn_provider;

use std::sync::Arc;

use anyhow::Result;
use cyfs_dns::{
    DnsServerConfig, DnsServerContext, InnerDnsRecordManager, InnerDnsRecordManagerRef,
    LocalDnsConfig, LocalDnsFactory, LocalDnsServerContext, ProcessChainDnsServerFactory,
};
use cyfs_gateway_app_lib::{
    hook_point_value_map_to_vector, GatewayCompositionBuilder, GatewayModule,
    GatewayServerContextMode, GatewayServerRegistration, GatewayServerRuntime,
    GatewayStackRegistration, GatewayStackRuntime, GatewayTrafficAdapter, GatewayTrafficConfig,
    GatewayTrafficConfigRef, GatewayTrafficService, GatewayTrafficStatFactory,
    GatewayTrafficStatFactoryRef, ServerConfigParser, StackConfigParser,
};
use cyfs_gateway_lib::{
    config_err, server_err, ConfigErrorCode, ConfigResult, LimiterManager, LimiterManagerRef,
    ServerConfig, ServerContextRef, ServerErrorCode, StackConfig, StackContext, StackFactory,
    StatFactoryRef, StatManagerRef,
};
use cyfs_sn::{SNServerConfig, SnServerFactory};
use cyfs_socks::{SocksServerConfig, SocksServerContext, SocksServerFactory, SocksTunnelBuilder};
use cyfs_traffic::{
    TrafficConfig, TrafficQuotaService, TrafficServiceHandle, TrafficStatFactory,
    TrafficStatFactoryRef, TrafficUserLimiterFactory,
};
use cyfs_tun::{TunStackConfig, TunStackContext, TunStackFactory};
use serde::Deserialize;

pub use acme_sn_provider::*;

pub struct DnsServerConfigParser;

impl DnsServerConfigParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfigParser<serde_json::Value> for DnsServerConfigParser {
    fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = DnsServerConfig::deserialize(hook_point_value_map_to_vector(
            value.clone(),
            "hook_point",
        )?)
        .map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid dns server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&value).unwrap_or_default()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct LocalDnsConfigParser;

impl LocalDnsConfigParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalDnsConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfigParser<serde_json::Value> for LocalDnsConfigParser {
    fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = LocalDnsConfig::deserialize(value.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid local dns config.{}\n{}",
                e,
                serde_json::to_string_pretty(&value).unwrap_or_default()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct SocksServerConfigParser;

impl SocksServerConfigParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SocksServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfigParser<serde_json::Value> for SocksServerConfigParser {
    fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = SocksServerConfig::deserialize(hook_point_value_map_to_vector(
            value.clone(),
            "hook_point",
        )?)
        .map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid socks server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&value).unwrap_or_default()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct TunStackConfigParser;

impl TunStackConfigParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TunStackConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StackConfigParser<serde_json::Value> for TunStackConfigParser {
    fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn StackConfig>> {
        let config = TunStackConfig::deserialize(hook_point_value_map_to_vector(
            value.clone(),
            "hook_point",
        )?)
        .map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid tun stack config.{}\n{}",
                e,
                serde_json::to_string_pretty(&value).unwrap_or_default()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct SNServerConfigParser;

impl SNServerConfigParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SNServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfigParser<serde_json::Value> for SNServerConfigParser {
    fn parse(&self, value: serde_json::Value) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = SNServerConfig::deserialize(value.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid sn server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&value).unwrap_or_default()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct DnsGatewayModule;

impl DnsGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for DnsGatewayModule {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        builder.register_process_chain_doc_extension("dns-resolve", |env, server_manager| {
            let resolve_cmd = cyfs_dns::CmdResolve::new(server_manager);
            let resolve_name = resolve_cmd.name().to_string();
            env.register_external_command(resolve_name.as_str(), Arc::new(Box::new(resolve_cmd)))
        })?;
        builder.register_runtime_capability::<InnerDnsRecordManagerRef, _>(|_| {
            Ok(InnerDnsRecordManager::new())
        })?;
        builder.register_runtime_hook("dns-local-acme-provider", |runtime| {
            let record_manager = runtime
                .capabilities
                .get::<InnerDnsRecordManagerRef>("dns")?;
            runtime.acme_manager.register_dns_provider(
                "local",
                move |op: String, domain: String, value: String| {
                    let record_manager = record_manager.clone();
                    async move {
                        match op.as_str() {
                            "add_challenge" => record_manager
                                .add_record(domain, "TXT", value)
                                .map_err(|e| anyhow::anyhow!(e.to_string())),
                            "del_challenge" => {
                                record_manager.remove_record(domain, "TXT");
                                Ok(())
                            }
                            _ => Err(anyhow::anyhow!("unsupported local DNS operation: {}", op)),
                        }
                    }
                },
            );
            Ok(())
        })?;
        builder.register_server(GatewayServerRegistration::new(
            "dns",
            "dns",
            Arc::new(DnsServerConfigParser::new()),
            Arc::new(ProcessChainDnsServerFactory::new()),
            GatewayServerContextMode::Required,
            |runtime: &GatewayServerRuntime| {
                let record_manager = runtime
                    .capabilities
                    .get::<InnerDnsRecordManagerRef>("dns")
                    .map_err(|e| server_err!(ServerErrorCode::InvalidConfig, "{}", e))?;
                Ok(Some(Arc::new(DnsServerContext::new(
                    runtime.server_manager.clone(),
                    runtime.global_process_chains.clone(),
                    runtime.js_externals.clone(),
                    runtime.global_collection_manager.clone(),
                    record_manager,
                )) as ServerContextRef))
            },
        ))?;
        builder.register_server(GatewayServerRegistration::new(
            "local_dns",
            "dns",
            Arc::new(LocalDnsConfigParser::new()),
            Arc::new(LocalDnsFactory::new()),
            GatewayServerContextMode::Required,
            |_runtime: &GatewayServerRuntime| {
                Ok(Some(
                    Arc::new(LocalDnsServerContext::new(None)) as ServerContextRef
                ))
            },
        ))?;
        Ok(())
    }
}

pub struct SocksGatewayModule;

impl SocksGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SocksGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for SocksGatewayModule {
    fn id(&self) -> &'static str {
        "socks"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        builder.register_server(GatewayServerRegistration::new(
            "socks",
            "socks",
            Arc::new(SocksServerConfigParser::new()),
            Arc::new(SocksServerFactory::new()),
            GatewayServerContextMode::Required,
            |runtime: &GatewayServerRuntime| {
                Ok(Some(Arc::new(SocksServerContext::new(
                    runtime.global_process_chains.clone(),
                    runtime.js_externals.clone(),
                    runtime.global_collection_manager.clone(),
                    SocksTunnelBuilder::new_ref(runtime.tunnel_manager.clone()),
                )) as ServerContextRef))
            },
        ))?;
        Ok(())
    }
}

pub struct TunGatewayModule;

impl TunGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TunGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for TunGatewayModule {
    fn id(&self) -> &'static str {
        "tun"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        builder.register_stack(GatewayStackRegistration::new(
            "tun",
            "tun",
            Arc::new(TunStackConfigParser::new()),
            |runtime: &GatewayStackRuntime| {
                Ok(
                    Arc::new(TunStackFactory::new(runtime.connection_manager.clone()))
                        as Arc<dyn StackFactory>,
                )
            },
            |runtime: &GatewayStackRuntime| {
                Ok(Arc::new(TunStackContext::new(
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
        Ok(())
    }
}

pub struct SnGatewayModule;

impl SnGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SnGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for SnGatewayModule {
    fn id(&self) -> &'static str {
        "sn"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        let data_path =
            buckyos_kit::get_buckyos_service_data_dir(builder.profile().service_data_namespace)
                .join("sn_dns");
        builder.register_acme_dns_provider("sn-dns", AcmeSnProviderFactory::new(data_path))?;
        builder.register_server(GatewayServerRegistration::new(
            "sn",
            "sn",
            Arc::new(SNServerConfigParser::new()),
            Arc::new(SnServerFactory::new()),
            GatewayServerContextMode::Contextless,
            |_runtime: &GatewayServerRuntime| Ok(None),
        ))?;
        Ok(())
    }
}

/// Traffic remains a separate explicit capability even though its host lifecycle is shared.
pub struct TrafficGatewayModule;

impl TrafficGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TrafficGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for TrafficGatewayModule {
    fn id(&self) -> &'static str {
        "traffic"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        builder.register_traffic_adapter(Arc::new(TrafficAdapter))?;
        Ok(())
    }
}

struct TrafficConfigAdapter(TrafficConfig);

impl GatewayTrafficConfig for TrafficConfigAdapter {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn enabled(&self) -> bool {
        self.0.enabled
    }
}

struct TrafficStatFactoryAdapter(TrafficStatFactoryRef);

impl GatewayTrafficStatFactory for TrafficStatFactoryAdapter {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_stat_factory(&self) -> StatFactoryRef {
        self.0.clone()
    }
}

struct TrafficServiceAdapter(TrafficServiceHandle);

#[async_trait::async_trait]
impl GatewayTrafficService for TrafficServiceAdapter {
    async fn stop(self: Box<Self>) {
        self.0.stop().await;
    }

    fn shutdown_now(self: Box<Self>) {
        self.0.shutdown_now();
    }
}

struct TrafficAdapter;

impl TrafficAdapter {
    fn config(config: &GatewayTrafficConfigRef) -> Result<&TrafficConfig> {
        config
            .as_any()
            .downcast_ref::<TrafficConfigAdapter>()
            .map(|config| &config.0)
            .ok_or_else(|| anyhow::anyhow!("traffic module received an incompatible config"))
    }

    fn stat_factory(stat_factory: &GatewayTrafficStatFactoryRef) -> Result<&TrafficStatFactoryRef> {
        stat_factory
            .as_any()
            .downcast_ref::<TrafficStatFactoryAdapter>()
            .map(|adapter| &adapter.0)
            .ok_or_else(|| anyhow::anyhow!("traffic module received an incompatible stat factory"))
    }
}

#[async_trait::async_trait]
impl GatewayTrafficAdapter for TrafficAdapter {
    fn parse_config(
        &self,
        value: Option<&serde_json::Value>,
    ) -> ConfigResult<GatewayTrafficConfigRef> {
        let config = value
            .map(|value| {
                serde_json::from_value::<TrafficConfig>(value.clone()).map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid traffic config: {}\n{}",
                        e,
                        serde_json::to_string_pretty(value).unwrap_or_default()
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Arc::new(TrafficConfigAdapter(config)))
    }

    fn create_stat_factory(
        &self,
        config: &GatewayTrafficConfigRef,
    ) -> Result<GatewayTrafficStatFactoryRef> {
        let config = Self::config(config)?;
        Ok(Arc::new(TrafficStatFactoryAdapter(
            TrafficStatFactory::new(config.stat_prefix.clone()),
        )))
    }

    fn configure_limiter_factory(
        &self,
        config: &GatewayTrafficConfigRef,
        stat_factory: &GatewayTrafficStatFactoryRef,
        limiter_manager: &mut dyn LimiterManager,
    ) -> Result<()> {
        let config = Self::config(config)?;
        if config.enabled {
            limiter_manager.set_limiter_factory(Some(Arc::new(
                TrafficUserLimiterFactory::new_http(
                    config.clone(),
                    Self::stat_factory(stat_factory)?.clone(),
                )?,
            )));
        } else {
            limiter_manager.set_limiter_factory(None);
        }
        Ok(())
    }

    async fn start_service(
        &self,
        config: &GatewayTrafficConfigRef,
        stat_manager: StatManagerRef,
        stat_factory: &GatewayTrafficStatFactoryRef,
        limiter_manager: LimiterManagerRef,
    ) -> Result<Option<Box<dyn GatewayTrafficService>>> {
        let service = TrafficQuotaService::start_http(
            Self::config(config)?.clone(),
            stat_manager,
            Self::stat_factory(stat_factory)?.clone(),
            limiter_manager,
        )
        .await?;
        Ok(service.map(|service| {
            Box::new(TrafficServiceAdapter(service)) as Box<dyn GatewayTrafficService>
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_gateway_app_lib::{CoreGatewayModule, GatewayAppProfile, GatewayCompositionBuilder};

    fn composition() -> cyfs_gateway_app_lib::GatewayComposition {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(CoreGatewayModule::new()).unwrap();
        builder.install(DnsGatewayModule::new()).unwrap();
        builder.install(SocksGatewayModule::new()).unwrap();
        builder.install(TunGatewayModule::new()).unwrap();
        builder.install(SnGatewayModule::new()).unwrap();
        builder.install(TrafficGatewayModule::new()).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn full_gateway_capability_snapshot() {
        let composition = composition();
        assert_eq!(
            composition.manifest().servers,
            vec![
                "acme_response",
                "control_server",
                "cyfs-dir",
                "dir",
                "dns",
                "http",
                "local_dns",
                "sn",
                "socks",
            ]
        );
        assert_eq!(
            composition.manifest().stacks,
            vec!["quic", "rtcp", "tcp", "tls", "tun", "udp"]
        );
        assert_eq!(composition.manifest().acme_dns_providers, vec!["sn-dns"]);
    }

    #[test]
    fn each_optional_module_builds_with_its_own_capability_snapshot() {
        let profile = GatewayAppProfile::cyfs_gateway();

        let mut dns = GatewayCompositionBuilder::new(profile);
        dns.install(DnsGatewayModule::new()).unwrap();
        let dns = dns.build().unwrap();
        assert_eq!(dns.manifest().modules, vec!["dns"]);
        assert_eq!(dns.manifest().servers, vec!["dns", "local_dns"]);
        assert!(dns.manifest().stacks.is_empty());
        let dns_runtime = dns.build_runtime_capabilities().unwrap();
        dns_runtime.get::<InnerDnsRecordManagerRef>("dns").unwrap();

        let mut socks = GatewayCompositionBuilder::new(profile);
        socks.install(SocksGatewayModule::new()).unwrap();
        let socks = socks.build().unwrap();
        assert_eq!(socks.manifest().modules, vec!["socks"]);
        assert_eq!(socks.manifest().servers, vec!["socks"]);

        let mut tun = GatewayCompositionBuilder::new(profile);
        tun.install(TunGatewayModule::new()).unwrap();
        let tun = tun.build().unwrap();
        assert_eq!(tun.manifest().modules, vec!["tun"]);
        assert_eq!(tun.manifest().stacks, vec!["tun"]);

        let mut sn = GatewayCompositionBuilder::new(profile);
        sn.install(SnGatewayModule::new()).unwrap();
        let sn = sn.build().unwrap();
        assert_eq!(sn.manifest().modules, vec!["sn"]);
        assert_eq!(sn.manifest().servers, vec!["sn"]);
        assert_eq!(sn.manifest().acme_dns_providers, vec!["sn-dns"]);

        let mut traffic = GatewayCompositionBuilder::new(profile);
        traffic.install(TrafficGatewayModule::new()).unwrap();
        let traffic = traffic.build().unwrap();
        assert_eq!(traffic.manifest().modules, vec!["traffic"]);
        assert!(traffic.traffic_adapter().is_some());
    }

    #[test]
    fn missing_module_fails_during_parse() {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(CoreGatewayModule::new()).unwrap();
        let composition = builder.build().unwrap();
        let error = composition
            .server_registry()
            .parse_server_config(serde_json::json!({ "type": "dns" }))
            .err()
            .unwrap();
        assert!(error.msg().contains("registered server types"));

        let error = composition
            .stack_registry()
            .parse_stack_config(serde_json::json!({ "protocol": "tun" }))
            .err()
            .unwrap();
        assert!(error.msg().contains("registered stack protocols"));
    }
}
