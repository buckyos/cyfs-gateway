use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use cyfs_acme::{AcmeCertManager, AcmeCertManagerRef, DnsProviderFactoryRef};
use cyfs_gateway_lib::ServerManagerWeakRef;
use cyfs_process_chain::HookPointEnv;

use crate::{
    register_core_gateway_servers, register_core_gateway_stacks, GatewayAppProfile,
    GatewayServerRegistration, GatewayServerRegistry, GatewayServerRegistryBuilder,
    GatewayStackRegistration, GatewayStackRegistry, GatewayStackRegistryBuilder,
    GatewayTrafficAdapterRef,
};

pub trait GatewayModule: Send + Sync + 'static {
    fn id(&self) -> &'static str;
    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()>;
}

pub struct GatewayRuntimeCapabilities {
    values: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    sources: HashMap<TypeId, &'static str>,
}

impl Default for GatewayRuntimeCapabilities {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
            sources: HashMap::new(),
        }
    }
}

impl GatewayRuntimeCapabilities {
    pub fn get<T>(&self, module_id: &str) -> Result<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        self.values
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref::<T>())
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "gateway module '{}' requires missing runtime capability '{}'",
                    module_id,
                    std::any::type_name::<T>()
                )
            })
    }

    pub fn source<T: Send + Sync + 'static>(&self) -> Option<&'static str> {
        self.sources.get(&TypeId::of::<T>()).copied()
    }
}

type RuntimeCapabilityFactory =
    dyn Fn(&GatewayAppProfile) -> Result<Arc<dyn Any + Send + Sync>> + Send + Sync;

struct RuntimeCapabilityRegistration {
    type_id: TypeId,
    type_name: &'static str,
    source: &'static str,
    factory: Arc<RuntimeCapabilityFactory>,
}

pub struct GatewayRuntimeHookContext<'a> {
    pub profile: &'a GatewayAppProfile,
    pub capabilities: &'a GatewayRuntimeCapabilities,
    pub acme_manager: &'a AcmeCertManagerRef,
}

type RuntimeHook = dyn for<'a> Fn(&GatewayRuntimeHookContext<'a>) -> Result<()> + Send + Sync;
type ProcessChainDocExtension =
    dyn Fn(&HookPointEnv, ServerManagerWeakRef) -> Result<(), String> + Send + Sync;

struct AcmeProviderRegistration {
    name: String,
    source: &'static str,
    factory: DnsProviderFactoryRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCapabilityManifest {
    pub modules: Vec<String>,
    pub servers: Vec<String>,
    pub stacks: Vec<String>,
    pub acme_dns_providers: Vec<String>,
}

pub struct GatewayCompositionBuilder {
    profile: GatewayAppProfile,
    current_module: Option<&'static str>,
    modules: BTreeMap<&'static str, ()>,
    server_registry: GatewayServerRegistryBuilder,
    stack_registry: GatewayStackRegistryBuilder,
    acme_providers: HashMap<String, AcmeProviderRegistration>,
    runtime_capabilities: HashMap<TypeId, RuntimeCapabilityRegistration>,
    runtime_hooks: BTreeMap<String, (&'static str, Arc<RuntimeHook>)>,
    traffic_adapter: Option<(&'static str, GatewayTrafficAdapterRef)>,
    process_chain_doc_extensions: BTreeMap<String, (&'static str, Arc<ProcessChainDocExtension>)>,
}

impl GatewayCompositionBuilder {
    pub fn new(profile: GatewayAppProfile) -> Self {
        Self {
            profile,
            current_module: None,
            modules: BTreeMap::new(),
            server_registry: GatewayServerRegistryBuilder::new(),
            stack_registry: GatewayStackRegistryBuilder::new(),
            acme_providers: HashMap::new(),
            runtime_capabilities: HashMap::new(),
            runtime_hooks: BTreeMap::new(),
            traffic_adapter: None,
            process_chain_doc_extensions: BTreeMap::new(),
        }
    }

    pub fn profile(&self) -> &GatewayAppProfile {
        &self.profile
    }

    pub fn install<M: GatewayModule>(&mut self, module: M) -> Result<&mut Self> {
        let id = module.id();
        if id.trim().is_empty() {
            return Err(anyhow!("gateway module id must not be empty"));
        }
        if self.modules.contains_key(id) {
            return Err(anyhow!("gateway module '{}' is already installed", id));
        }

        self.modules.insert(id, ());
        self.current_module = Some(id);
        let result = module.install(self);
        self.current_module = None;
        if let Err(error) = result {
            self.modules.remove(id);
            return Err(error);
        }
        Ok(self)
    }

    fn module_id(&self) -> Result<&'static str> {
        self.current_module
            .ok_or_else(|| anyhow!("gateway registrations are only allowed during module install"))
    }

    pub fn register_server(&mut self, registration: GatewayServerRegistration) -> Result<()> {
        let module_id = self.module_id()?;
        self.server_registry.register(registration).map_err(|e| {
            anyhow!(
                "gateway module '{}' failed to register server: {}",
                module_id,
                e
            )
        })
    }

    pub fn register_stack(&mut self, registration: GatewayStackRegistration) -> Result<()> {
        let module_id = self.module_id()?;
        self.stack_registry.register(registration).map_err(|e| {
            anyhow!(
                "gateway module '{}' failed to register stack: {}",
                module_id,
                e
            )
        })
    }

    pub fn register_acme_dns_provider(
        &mut self,
        name: impl Into<String>,
        factory: DnsProviderFactoryRef,
    ) -> Result<()> {
        let source = self.module_id()?;
        let name = name.into();
        if name.trim().is_empty() {
            return Err(anyhow!(
                "ACME DNS provider name must not be empty (module: {})",
                source
            ));
        }
        if let Some(existing) = self.acme_providers.get(name.as_str()) {
            return Err(anyhow!(
                "ACME DNS provider '{}' is already registered by '{}'; duplicate module: '{}'",
                name,
                existing.source,
                source
            ));
        }
        self.acme_providers.insert(
            name.clone(),
            AcmeProviderRegistration {
                name,
                source,
                factory,
            },
        );
        Ok(())
    }

    pub fn register_runtime_capability<T, F>(&mut self, factory: F) -> Result<()>
    where
        T: Send + Sync + 'static,
        F: Fn(&GatewayAppProfile) -> Result<T> + Send + Sync + 'static,
    {
        let source = self.module_id()?;
        let type_id = TypeId::of::<T>();
        if let Some(existing) = self.runtime_capabilities.get(&type_id) {
            return Err(anyhow!(
                "runtime capability '{}' is already registered by '{}'; duplicate module: '{}'",
                std::any::type_name::<T>(),
                existing.source,
                source
            ));
        }
        self.runtime_capabilities.insert(
            type_id,
            RuntimeCapabilityRegistration {
                type_id,
                type_name: std::any::type_name::<T>(),
                source,
                factory: Arc::new(move |profile| {
                    Ok(Arc::new(factory(profile)?) as Arc<dyn Any + Send + Sync>)
                }),
            },
        );
        Ok(())
    }

    pub fn register_runtime_hook<F>(&mut self, id: impl Into<String>, hook: F) -> Result<()>
    where
        F: for<'a> Fn(&GatewayRuntimeHookContext<'a>) -> Result<()> + Send + Sync + 'static,
    {
        let source = self.module_id()?;
        let id = id.into();
        if id.trim().is_empty() {
            return Err(anyhow!(
                "runtime hook id must not be empty (module: {})",
                source
            ));
        }
        if let Some((existing, _)) = self.runtime_hooks.get(id.as_str()) {
            return Err(anyhow!(
                "runtime hook '{}' is already registered by '{}'; duplicate module: '{}'",
                id,
                existing,
                source
            ));
        }
        self.runtime_hooks.insert(id, (source, Arc::new(hook)));
        Ok(())
    }

    pub fn register_traffic_adapter(&mut self, adapter: GatewayTrafficAdapterRef) -> Result<()> {
        let source = self.module_id()?;
        if let Some((existing, _)) = &self.traffic_adapter {
            return Err(anyhow!(
                "traffic adapter is already registered by '{}'; duplicate module: '{}'",
                existing,
                source
            ));
        }
        self.traffic_adapter = Some((source, adapter));
        Ok(())
    }

    pub fn register_process_chain_doc_extension<F>(
        &mut self,
        id: impl Into<String>,
        extension: F,
    ) -> Result<()>
    where
        F: Fn(&HookPointEnv, ServerManagerWeakRef) -> Result<(), String> + Send + Sync + 'static,
    {
        let source = self.module_id()?;
        let id = id.into();
        if id.trim().is_empty() {
            return Err(anyhow!(
                "process-chain doc extension id must not be empty (module: {})",
                source
            ));
        }
        if let Some((existing, _)) = self.process_chain_doc_extensions.get(id.as_str()) {
            return Err(anyhow!(
                "process-chain doc extension '{}' is already registered by '{}'; duplicate module: '{}'",
                id,
                existing,
                source
            ));
        }
        self.process_chain_doc_extensions
            .insert(id, (source, Arc::new(extension)));
        Ok(())
    }

    pub fn build(self) -> Result<GatewayComposition> {
        let server_registry = Arc::new(
            self.server_registry
                .build()
                .map_err(|e| anyhow!("build server registry failed: {}", e))?,
        );
        let stack_registry = Arc::new(
            self.stack_registry
                .build()
                .map_err(|e| anyhow!("build stack registry failed: {}", e))?,
        );
        let mut modules = self
            .modules
            .keys()
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>();
        modules.sort();
        let mut acme_dns_providers = self.acme_providers.keys().cloned().collect::<Vec<_>>();
        acme_dns_providers.sort();
        let manifest = GatewayCapabilityManifest {
            modules,
            servers: server_registry.registered_server_types(),
            stacks: stack_registry.registered_protocols(),
            acme_dns_providers,
        };
        Ok(GatewayComposition {
            profile: self.profile,
            server_registry,
            stack_registry,
            acme_providers: self.acme_providers.into_values().collect(),
            runtime_capabilities: self.runtime_capabilities.into_values().collect(),
            runtime_hooks: self
                .runtime_hooks
                .into_values()
                .map(|(_, hook)| hook)
                .collect(),
            traffic_adapter: self.traffic_adapter.map(|(_, adapter)| adapter),
            process_chain_doc_extensions: self
                .process_chain_doc_extensions
                .into_values()
                .map(|(_, extension)| extension)
                .collect(),
            manifest,
        })
    }
}

pub struct GatewayComposition {
    profile: GatewayAppProfile,
    server_registry: Arc<GatewayServerRegistry>,
    stack_registry: Arc<GatewayStackRegistry>,
    acme_providers: Vec<AcmeProviderRegistration>,
    runtime_capabilities: Vec<RuntimeCapabilityRegistration>,
    runtime_hooks: Vec<Arc<RuntimeHook>>,
    traffic_adapter: Option<GatewayTrafficAdapterRef>,
    process_chain_doc_extensions: Vec<Arc<ProcessChainDocExtension>>,
    manifest: GatewayCapabilityManifest,
}

impl GatewayComposition {
    pub fn profile(&self) -> &GatewayAppProfile {
        &self.profile
    }

    pub fn server_registry(&self) -> &Arc<GatewayServerRegistry> {
        &self.server_registry
    }

    pub fn stack_registry(&self) -> &Arc<GatewayStackRegistry> {
        &self.stack_registry
    }

    pub fn manifest(&self) -> &GatewayCapabilityManifest {
        &self.manifest
    }

    pub fn traffic_adapter(&self) -> Option<&GatewayTrafficAdapterRef> {
        self.traffic_adapter.as_ref()
    }

    pub fn install_process_chain_doc_extensions(
        &self,
        env: &HookPointEnv,
        server_manager: ServerManagerWeakRef,
    ) -> Result<(), String> {
        for extension in &self.process_chain_doc_extensions {
            extension(env, server_manager.clone())?;
        }
        Ok(())
    }

    pub fn apply_acme_dns_provider_factories(&self) {
        for registration in &self.acme_providers {
            AcmeCertManager::register_dns_provider_factory(
                registration.name.clone(),
                registration.factory.clone(),
            );
        }
    }

    pub fn build_runtime_capabilities(&self) -> Result<GatewayRuntimeCapabilities> {
        let mut values = HashMap::new();
        let mut sources = HashMap::new();
        for registration in &self.runtime_capabilities {
            let value = (registration.factory)(&self.profile).map_err(|e| {
                anyhow!(
                    "module '{}' failed to create runtime capability '{}': {}",
                    registration.source,
                    registration.type_name,
                    e
                )
            })?;
            values.insert(registration.type_id, value);
            sources.insert(registration.type_id, registration.source);
        }
        Ok(GatewayRuntimeCapabilities { values, sources })
    }

    pub fn apply_runtime_hooks(
        &self,
        capabilities: &GatewayRuntimeCapabilities,
        acme_manager: &AcmeCertManagerRef,
    ) -> Result<()> {
        let context = GatewayRuntimeHookContext {
            profile: &self.profile,
            capabilities,
            acme_manager,
        };
        for hook in &self.runtime_hooks {
            hook(&context)?;
        }
        Ok(())
    }
}

pub struct CoreGatewayModule;

impl CoreGatewayModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CoreGatewayModule {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayModule for CoreGatewayModule {
    fn id(&self) -> &'static str {
        "core"
    }

    fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
        register_core_gateway_servers(&mut builder.server_registry)?;
        register_core_gateway_stacks(&mut builder.stack_registry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Weak};

    use cyfs_acme::{AcmeCertManager, DnsProviderFactory, DnsProviderRef};

    use super::*;

    struct EmptyModule(&'static str);

    impl GatewayModule for EmptyModule {
        fn id(&self) -> &'static str {
            self.0
        }

        fn install(&self, _builder: &mut GatewayCompositionBuilder) -> Result<()> {
            Ok(())
        }
    }

    struct TestDnsProviderFactory;

    #[async_trait::async_trait]
    impl DnsProviderFactory for TestDnsProviderFactory {
        async fn create(
            &self,
            _acme_manager: Weak<AcmeCertManager>,
            _params: serde_json::Value,
        ) -> Result<DnsProviderRef> {
            Err(anyhow!("not used by registration test"))
        }
    }

    struct AcmeModule(&'static str);

    impl GatewayModule for AcmeModule {
        fn id(&self) -> &'static str {
            self.0
        }

        fn install(&self, builder: &mut GatewayCompositionBuilder) -> Result<()> {
            builder.register_acme_dns_provider("same-provider", Arc::new(TestDnsProviderFactory))
        }
    }

    #[test]
    fn duplicate_module_fails_fast() {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(EmptyModule("same")).unwrap();
        let error = match builder.install(EmptyModule("same")) {
            Ok(_) => panic!("duplicate module must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("same"));
    }

    #[test]
    fn duplicate_acme_provider_reports_both_modules() {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(AcmeModule("first-acme")).unwrap();
        let error = match builder.install(AcmeModule("second-acme")) {
            Ok(_) => panic!("duplicate provider must fail"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("same-provider"));
        assert!(message.contains("first-acme"));
        assert!(message.contains("second-acme"));
    }

    #[test]
    fn core_manifest_is_stably_sorted() {
        let mut builder = GatewayCompositionBuilder::new(GatewayAppProfile::cyfs_gateway());
        builder.install(CoreGatewayModule::new()).unwrap();
        let composition = builder.build().unwrap();
        assert_eq!(composition.manifest().modules, vec!["core"]);
        assert_eq!(
            composition.manifest().servers,
            vec!["acme_response", "control_server", "cyfs-dir", "dir", "http"]
        );
        assert_eq!(
            composition.manifest().stacks,
            vec!["quic", "rtcp", "tcp", "tls", "udp"]
        );
    }
}
