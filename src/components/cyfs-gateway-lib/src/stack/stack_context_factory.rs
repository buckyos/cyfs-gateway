use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::{
    AcmeCertManagerRef, GlobalCollectionManagerRef, GlobalProcessChainsRef, LimiterManagerRef,
    SelfCertMgrRef, ServerManagerRef, StackContext, StackErrorCode, StackProtocol, StackResult,
    StatManagerRef, TunnelManager,
};

use super::{
    QuicStackContext, RtcpStackContext, TcpStackContext, TlsStackContext, UdpStackContext,
};

pub trait ExtensionStackContextFactory: Send + Sync {
    fn create(&self, base: &StackContextFactory) -> StackResult<Arc<dyn StackContext>>;
}

pub struct StackContextFactory {
    servers: ServerManagerRef,
    tunnel_manager: TunnelManager,
    limiter_manager: LimiterManagerRef,
    stat_manager: StatManagerRef,
    global_process_chains: Option<GlobalProcessChainsRef>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    acme_manager: Option<AcmeCertManagerRef>,
    self_cert_mgr: Option<SelfCertMgrRef>,
    extension_factories: Mutex<HashMap<String, Arc<dyn ExtensionStackContextFactory>>>,
}

impl StackContextFactory {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        acme_manager: Option<AcmeCertManagerRef>,
        self_cert_mgr: Option<SelfCertMgrRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
            acme_manager,
            self_cert_mgr,
            extension_factories: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_extension(
        &self,
        protocol: impl Into<String>,
        factory: Arc<dyn ExtensionStackContextFactory>,
    ) {
        self.extension_factories
            .lock()
            .unwrap()
            .insert(protocol.into(), factory);
    }

    pub fn create(&self, protocol: &StackProtocol) -> StackResult<Arc<dyn StackContext>> {
        match protocol {
            StackProtocol::Tcp => Ok(Arc::new(TcpStackContext::new(
                self.servers.clone(),
                self.tunnel_manager.clone(),
                self.limiter_manager.clone(),
                self.stat_manager.clone(),
                self.global_process_chains.clone(),
                self.global_collection_manager.clone(),
            ))),
            StackProtocol::Udp => Ok(Arc::new(UdpStackContext::new(
                self.servers.clone(),
                self.tunnel_manager.clone(),
                self.limiter_manager.clone(),
                self.stat_manager.clone(),
                self.global_process_chains.clone(),
                self.global_collection_manager.clone(),
            ))),
            StackProtocol::Rtcp => Ok(Arc::new(RtcpStackContext::new(
                self.servers.clone(),
                self.tunnel_manager.clone(),
                self.limiter_manager.clone(),
                self.stat_manager.clone(),
                self.global_process_chains.clone(),
                self.global_collection_manager.clone(),
            ))),
            StackProtocol::Tls => {
                let (acme_manager, self_cert_mgr) = self.tls_dependencies()?;
                Ok(Arc::new(TlsStackContext::new(
                    self.servers.clone(),
                    self.tunnel_manager.clone(),
                    self.limiter_manager.clone(),
                    self.stat_manager.clone(),
                    acme_manager,
                    self_cert_mgr,
                    self.global_process_chains.clone(),
                    self.global_collection_manager.clone(),
                )))
            }
            StackProtocol::Quic => {
                let (acme_manager, self_cert_mgr) = self.tls_dependencies()?;
                Ok(Arc::new(QuicStackContext::new(
                    self.servers.clone(),
                    self.tunnel_manager.clone(),
                    self.limiter_manager.clone(),
                    self.stat_manager.clone(),
                    acme_manager,
                    self_cert_mgr,
                    self.global_process_chains.clone(),
                    self.global_collection_manager.clone(),
                )))
            }
            StackProtocol::Extension(name) => {
                let factory = self.extension_factories.lock().unwrap().get(name).cloned();
                match factory {
                    Some(factory) => factory.create(self),
                    None => Err(crate::stack_err!(
                        StackErrorCode::UnsupportedStackProtocol,
                        "unsupported stack protocol {:?}",
                        protocol
                    )),
                }
            }
        }
    }

    fn tls_dependencies(&self) -> StackResult<(AcmeCertManagerRef, SelfCertMgrRef)> {
        let acme_manager = self.acme_manager.clone().ok_or(crate::stack_err!(
            StackErrorCode::InvalidConfig,
            "acme manager is required for tls/quic stack context"
        ))?;
        let self_cert_mgr = self.self_cert_mgr.clone().ok_or(crate::stack_err!(
            StackErrorCode::InvalidConfig,
            "self cert manager is required for tls/quic stack context"
        ))?;
        Ok((acme_manager, self_cert_mgr))
    }
}
