use crate::identity::{DeviceIdentity, DeviceIdentityCertFactory, DeviceIdentityFactory};
use crate::identity::load_x509_identity_from_paths;
use crate::pn_server::{register_pn_service, unregister_pn_service};
use crate::sn_server::P2pStreamExtra;
use crate::stream::P2pAsyncStream;
use crate::tunnel::{
    CyfsP2pTunnelBuilder, P2pDatagramClient, P2pTransportKind, parse_wire_purpose,
};
use buckyos_kit::AsyncStream;
use cyfs_gateway_lib::{
    ConnectionInfo, ConnectionManagerRef, DatagramClient, DatagramInfo, DumpStream,
    GlobalCollectionManagerRef, GlobalProcessChainsRef, HandleConnectionController,
    IoDumpStackConfig, JsExternalsManagerRef, Limiter, LimiterManagerRef, MutComposedSpeedStat,
    MutComposedSpeedStatRef, ProcessChainConfig, ProcessChainConfigs, Server, ServerManagerRef,
    Stack, StackConfig, StackContext, StackErrorCode, StackFactory, StackProtocol, StackRef,
    StackResult, StatManagerRef, StreamInfo, TunnelManager, create_io_dump_stack_config,
    create_process_chain_executor, datagram_forward, execute_chain, get_external_commands,
    get_limit_info, get_stat_info, hyper_serve_http, into_stack_err, stack_err, stream_forward,
};
use cyfs_process_chain::{
    CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor,
};
use log::{debug, error, warn};
use p2p_frame::endpoint::{Endpoint, Protocol};
use p2p_frame::error::{P2pErrorCode, P2pResult, p2p_err};
use p2p_frame::executor::Executor as P2pExecutor;
use p2p_frame::networks::{
    DefaultDeviceFinder, IncomingTunnelValidateContext, IncomingTunnelValidator, NetManagerRef,
    TunnelManager as P2pTunnelManager, TunnelManagerRef as P2pTunnelManagerRef, TunnelRef,
    ValidateResult, allow_all_tunnel_purposes,
};
use p2p_frame::p2p_identity::{
    P2pId, P2pIdentityCertFactoryRef, P2pIdentityFactoryRef, P2pIdentityRef,
    P2pSn,
};
use p2p_frame::sn::client::{SNClientService, SNClientServiceRef};
use p2p_frame::stack::{P2pConfig, P2pEnvRef, create_p2p_env};
use p2p_frame::tls::TlsServerCertResolver;
use p2p_frame::types::{SequenceGenerator, TunnelIdGenerator};
use p2p_frame::x509::{X509IdentityCertFactory, X509IdentityFactory};
use name_lib::{
    encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key, DeviceConfig,
    DIDDocumentTrait, EncodedDocument,
};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use sfo_io::{LimitStream, StatStream};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;

const DEFAULT_CONN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SN_PING_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_SN_CALL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SN_QUERY_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_SN_TUNNEL_COUNT: u16 = 5;

#[derive(Clone)]
pub struct CyfsP2pStackContext {
    pub servers: ServerManagerRef,
    pub tunnel_manager: TunnelManager,
    pub limiter_manager: LimiterManagerRef,
    pub stat_manager: StatManagerRef,
    pub global_process_chains: Option<GlobalProcessChainsRef>,
    pub global_collection_manager: Option<GlobalCollectionManagerRef>,
    pub js_externals: Option<JsExternalsManagerRef>,
}

impl CyfsP2pStackContext {
    pub fn new(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> Self {
        Self {
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            global_collection_manager,
            js_externals,
        }
    }
}

impl StackContext for CyfsP2pStackContext {
    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Extension("p2p".to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CyfsP2pSnConfig {
    pub id: String,
    pub name: String,
    pub endpoints: Vec<String>,
}

impl CyfsP2pSnConfig {
    fn to_p2p_sn(&self) -> StackResult<P2pSn> {
        let id = P2pId::from_str(self.id.as_str()).map_err(into_stack_err!(
            StackErrorCode::InvalidConfig,
            "invalid sn id {}",
            self.id
        ))?;
        let mut endpoints = Vec::with_capacity(self.endpoints.len());
        for endpoint in &self.endpoints {
            endpoints.push(parse_endpoint(endpoint).map_err(into_stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid sn endpoint {}",
                endpoint
            ))?);
        }
        Ok(P2pSn::new(id, self.name.clone(), endpoints))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsP2pCertConfig {
    #[serde(rename = "type")]
    pub cert_type: String,
    #[serde(alias = "key-path")]
    pub key_path: String,
    #[serde(alias = "cert-path")]
    pub cert_path: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SingleOrVec<T> {
    Single(T),
    Vec(Vec<T>),
}

fn deserialize_sn_configs<'de, D>(deserializer: D) -> Result<Vec<CyfsP2pSnConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<SingleOrVec<CyfsP2pSnConfig>>::deserialize(deserializer)?;
    Ok(match value {
        Some(SingleOrVec::Single(item)) => vec![item],
        Some(SingleOrVec::Vec(items)) => items,
        None => vec![],
    })
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CyfsP2pStackConfig {
    pub id: String,
    pub protocol: StackProtocol,
    pub bind: SocketAddr,
    #[serde(default, deserialize_with = "deserialize_sn_configs")]
    pub sn: Vec<CyfsP2pSnConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_address: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_rotate_max_files: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_upload_bytes_per_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_dump_max_download_bytes_per_conn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    pub cert: CyfsP2pCertConfig,
    #[serde(
        default,
        alias = "pre-hook-point",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_hook_point: Option<Vec<ProcessChainConfig>>,
    pub hook_point: Vec<ProcessChainConfig>,
}

impl StackConfig for CyfsP2pStackConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Extension("p2p".to_string())
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

struct CyfsP2pConnectionHandler {
    env: Arc<CyfsP2pStackContext>,
    executor: ProcessChainLibExecutor,
    pre_executor: Option<ProcessChainLibExecutor>,
    io_dump: Option<IoDumpStackConfig>,
}

#[derive(Clone)]
struct P2pTunnelMeta {
    source_device_id: P2pId,
    dest_device_id: P2pId,
    source_ep: Option<Endpoint>,
    dest_ep: Option<Endpoint>,
    transport_protocol: String,
    tunnel_id: String,
    candidate_id: String,
    is_reverse: bool,
    tunnel_form: String,
}

#[derive(Clone)]
struct P2pStreamMeta {
    tunnel: P2pTunnelMeta,
    purpose: String,
}

impl CyfsP2pConnectionHandler {
    async fn create(
        hook_point: ProcessChainConfigs,
        pre_hook_point: Option<ProcessChainConfigs>,
        env: Arc<CyfsP2pStackContext>,
        io_dump: Option<IoDumpStackConfig>,
    ) -> StackResult<Self> {
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            env.global_process_chains.clone(),
            env.global_collection_manager.clone(),
            Some(get_external_commands(Arc::downgrade(&env.servers))),
            env.js_externals.clone(),
        )
        .await
        .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        let pre_executor = if let Some(pre_hook_point) = pre_hook_point {
            let (executor, _) = create_process_chain_executor(
                &pre_hook_point,
                env.global_process_chains.clone(),
                env.global_collection_manager.clone(),
                Some(get_external_commands(Arc::downgrade(&env.servers))),
                env.js_externals.clone(),
            )
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
            Some(executor)
        } else {
            None
        };
        Ok(Self {
            env,
            executor,
            pre_executor,
            io_dump,
        })
    }

    async fn handle_new_tunnel(&self, meta: &P2pTunnelMeta) -> StackResult<()> {
        let Some(executor) = self.pre_executor.as_ref() else {
            return Ok(());
        };
        let executor = executor.fork();
        let map = MemoryMapCollection::new_ref();
        let source_device_id = meta.source_device_id.to_string();
        let dest_device_id = meta.dest_device_id.to_string();
        insert_map_string(&map, "source_device_id", source_device_id.as_str()).await?;
        insert_map_string(&map, "dest_device_id", dest_device_id.as_str()).await?;
        insert_endpoint_addr(&map, "source_ip", "source_port", meta.source_ep.as_ref()).await?;
        insert_endpoint_addr(&map, "dest_ip", "dest_port", meta.dest_ep.as_ref()).await?;

        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() && (ret.is_drop() || ret.is_reject()) {
            return Err(stack_err!(
                StackErrorCode::PermissionDenied,
                "p2p tunnel rejected by process_chain, source_device_id={}, source_ep={:?}",
                source_device_id,
                meta.source_ep.as_ref().map(|ep| ep.addr())
            ));
        }
        Ok(())
    }

    async fn handle_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        meta: P2pStreamMeta,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let map = MemoryMapCollection::new_ref();
        let source_device_id = meta.tunnel.source_device_id.to_string();
        let dest_device_id = meta.tunnel.dest_device_id.to_string();
        insert_map_string(&map, "protocol", "p2p").await?;
        insert_map_string(&map, "purpose", meta.purpose.as_str()).await?;
        insert_map_string(&map, "source_device_id", source_device_id.as_str()).await?;
        insert_map_string(&map, "dest_device_id", dest_device_id.as_str()).await?;
        insert_map_string(
            &map,
            "transport_protocol",
            meta.tunnel.transport_protocol.as_str(),
        )
        .await?;
        insert_map_string(&map, "tunnel_id", meta.tunnel.tunnel_id.as_str()).await?;
        insert_map_string(&map, "candidate_id", meta.tunnel.candidate_id.as_str()).await?;
        insert_map_string(
            &map,
            "is_reverse",
            meta.tunnel.is_reverse.to_string().as_str(),
        )
        .await?;
        insert_map_string(&map, "tunnel_form", meta.tunnel.tunnel_form.as_str()).await?;
        insert_endpoint_addr(
            &map,
            "source_ip",
            "source_port",
            meta.tunnel.source_ep.as_ref(),
        )
        .await?;
        insert_endpoint_addr(&map, "dest_ip", "dest_port", meta.tunnel.dest_ep.as_ref()).await?;
        insert_p2p_target_fields(&map, meta.purpose.as_str()).await?;

        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() || ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    return Ok(());
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) =
                        get_limit_info(global_env.clone()).await?;
                    let upper = limiter_id
                        .as_ref()
                        .and_then(|id| self.env.limiter_manager.get_limiter(id.to_string()));
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(
                            upper,
                            Some(1),
                            down_speed.map(|v| v as u32),
                            up_speed.map(|v| v as u32),
                        ))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self
                        .env
                        .stat_manager
                        .get_speed_stats(stat_group_ids.as_slice());
                    stat.set_external_stats(speed_groups);

                    let stream = if let Some(limiter) = limiter.as_ref() {
                        let (read_limit, write_limit) = limiter.new_limit_session();
                        Box::new(LimitStream::new(stream, read_limit, write_limit))
                            as Box<dyn AsyncStream>
                    } else {
                        stream
                    };

                    match list[0].as_str() {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            stream_forward(stream, list[1].as_str(), &self.env.tunnel_manager)
                                .await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                let source_label = meta
                                    .tunnel
                                    .source_ep
                                    .as_ref()
                                    .map(|ep| ep.addr().to_string())
                                    .unwrap_or_else(|| meta.tunnel.source_device_id.to_string());
                                let dst_label =
                                    meta.tunnel.dest_ep.as_ref().map(|ep| ep.addr().to_string());
                                let stream_extra = P2pStreamExtra {
                                    source_device_id: meta.tunnel.source_device_id.to_string(),
                                    dest_device_id: meta.tunnel.dest_device_id.to_string(),
                                    source_endpoint: meta.tunnel.source_ep.map(|ep| ep.to_string()),
                                    dest_endpoint: meta.tunnel.dest_ep.map(|ep| ep.to_string()),
                                    transport_protocol: meta.tunnel.transport_protocol.clone(),
                                    tunnel_id: meta.tunnel.tunnel_id.clone(),
                                    candidate_id: meta.tunnel.candidate_id.clone(),
                                    purpose: meta.purpose.clone(),
                                    is_reverse: meta.tunnel.is_reverse,
                                    tunnel_form: meta.tunnel.tunnel_form.clone(),
                                }
                                .encode()
                                .map_err(into_stack_err!(
                                    StackErrorCode::InvalidData,
                                    "encode p2p stream extra"
                                ))?;
                                match server {
                                    Server::Http(server) => {
                                        hyper_serve_http(
                                            stream,
                                            server,
                                            StreamInfo::new(source_label)
                                                .with_dst_addr(dst_label)
                                                .with_extra(stream_extra),
                                        )
                                        .await
                                        .map_err(
                                            into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ),
                                        )?;
                                    }
                                    Server::Stream(server) => {
                                        server
                                            .serve_connection(
                                                stream,
                                                StreamInfo::new(source_label)
                                                    .with_dst_addr(dst_label)
                                                    .with_extra(stream_extra),
                                            )
                                            .await
                                            .map_err(into_stack_err!(
                                                StackErrorCode::ServerError,
                                                "server {server_name}"
                                            ))?;
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type {server_name}"
                                        ));
                                    }
                                }
                            }
                        }
                        cmd => {
                            error!("unknown p2p hook command: {}", cmd);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_datagram(
        &self,
        stream: Box<dyn AsyncStream>,
        meta: P2pStreamMeta,
        stat: MutComposedSpeedStatRef,
    ) -> StackResult<()> {
        let executor = self.executor.fork();
        let servers = self.env.servers.clone();
        let map = MemoryMapCollection::new_ref();
        let source_device_id = meta.tunnel.source_device_id.to_string();
        let dest_device_id = meta.tunnel.dest_device_id.to_string();
        insert_map_string(&map, "protocol", "p2p").await?;
        insert_map_string(&map, "purpose", meta.purpose.as_str()).await?;
        insert_map_string(&map, "source_device_id", source_device_id.as_str()).await?;
        insert_map_string(&map, "dest_device_id", dest_device_id.as_str()).await?;
        insert_map_string(
            &map,
            "transport_protocol",
            meta.tunnel.transport_protocol.as_str(),
        )
        .await?;
        insert_map_string(&map, "tunnel_id", meta.tunnel.tunnel_id.as_str()).await?;
        insert_map_string(&map, "candidate_id", meta.tunnel.candidate_id.as_str()).await?;
        insert_map_string(
            &map,
            "is_reverse",
            meta.tunnel.is_reverse.to_string().as_str(),
        )
        .await?;
        insert_map_string(&map, "tunnel_form", meta.tunnel.tunnel_form.as_str()).await?;
        insert_endpoint_addr(
            &map,
            "source_ip",
            "source_port",
            meta.tunnel.source_ep.as_ref(),
        )
        .await?;
        insert_endpoint_addr(&map, "dest_ip", "dest_port", meta.tunnel.dest_ep.as_ref()).await?;
        insert_p2p_target_fields(&map, meta.purpose.as_str()).await?;

        let global_env = executor.global_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() || ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    return Ok(());
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        return Ok(());
                    }

                    let (limiter_id, down_speed, up_speed) =
                        get_limit_info(global_env.clone()).await?;
                    let upper = limiter_id
                        .as_ref()
                        .and_then(|id| self.env.limiter_manager.get_limiter(id.to_string()));
                    let limiter = if down_speed.is_some() && up_speed.is_some() {
                        Some(Limiter::new(
                            upper,
                            Some(1),
                            down_speed.map(|v| v as u32),
                            up_speed.map(|v| v as u32),
                        ))
                    } else {
                        upper
                    };

                    let stat_group_ids = get_stat_info(global_env).await?;
                    let speed_groups = self
                        .env
                        .stat_manager
                        .get_speed_stats(stat_group_ids.as_slice());
                    stat.set_external_stats(speed_groups);

                    let stream = if let Some(limiter) = limiter.as_ref() {
                        let (read_limit, write_limit) = limiter.new_limit_session();
                        Box::new(LimitStream::new(stream, read_limit, write_limit))
                            as Box<dyn AsyncStream>
                    } else {
                        stream
                    };

                    match list[0].as_str() {
                        "forward" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid forward command"
                                ));
                            }
                            datagram_forward(
                                Box::new(P2pDatagramClient::new(stream)),
                                list[1].as_str(),
                                &self.env.tunnel_manager,
                            )
                            .await?;
                        }
                        "server" => {
                            if list.len() < 2 {
                                return Err(stack_err!(
                                    StackErrorCode::InvalidConfig,
                                    "invalid server command"
                                ));
                            }

                            let server_name = list[1].as_str();
                            if let Some(server) = servers.get_server(server_name) {
                                match server {
                                    Server::Datagram(server) => {
                                        let datagram = P2pDatagramClient::new(stream);
                                        let source_label = meta
                                            .tunnel
                                            .source_ep
                                            .as_ref()
                                            .map(|ep| ep.addr().to_string())
                                            .unwrap_or_else(|| {
                                                meta.tunnel.source_device_id.to_string()
                                            });
                                        let dst_label = meta
                                            .tunnel
                                            .dest_ep
                                            .as_ref()
                                            .map(|ep| ep.addr().to_string());
                                        let mut buf = vec![0; 4096];
                                        loop {
                                            let len = datagram
                                                .recv_datagram(&mut buf)
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "recv datagram error"
                                                ))?;
                                            let resp = server
                                                .serve_datagram(
                                                    &buf[..len],
                                                    DatagramInfo::new(Some(source_label.clone()))
                                                        .with_dst_addr(dst_label.clone()),
                                                )
                                                .await
                                                .map_err(into_stack_err!(
                                                    StackErrorCode::ServerError,
                                                    "server {server_name}"
                                                ))?;
                                            datagram.send_datagram(resp.as_slice()).await.map_err(
                                                into_stack_err!(
                                                    StackErrorCode::IoError,
                                                    "send datagram error"
                                                ),
                                            )?;
                                        }
                                    }
                                    _ => {
                                        return Err(stack_err!(
                                            StackErrorCode::InvalidConfig,
                                            "unsupported server type {server_name}"
                                        ));
                                    }
                                }
                            }
                        }
                        cmd => {
                            error!("unknown p2p hook command: {}", cmd);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

struct CyfsP2pIncomingTunnelValidator {
    handler: Arc<RwLock<Arc<CyfsP2pConnectionHandler>>>,
}

impl CyfsP2pIncomingTunnelValidator {
    fn new(handler: Arc<RwLock<Arc<CyfsP2pConnectionHandler>>>) -> Self {
        Self { handler }
    }
}

#[async_trait::async_trait]
impl IncomingTunnelValidator for CyfsP2pIncomingTunnelValidator {
    async fn validate(&self, ctx: &IncomingTunnelValidateContext) -> P2pResult<ValidateResult> {
        let meta = P2pTunnelMeta {
            source_device_id: ctx.remote_id.to_owned(),
            dest_device_id: ctx.local_id.to_owned(),
            source_ep: ctx.remote_ep.map(|ep| ep.to_owned()),
            dest_ep: ctx.local_ep.map(|ep| ep.to_owned()),
            transport_protocol: protocol_to_string(ctx.protocol),
            tunnel_id: format!("{:?}", ctx.tunnel_id),
            candidate_id: format!("{:?}", ctx.candidate_id),
            is_reverse: ctx.is_reverse,
            tunnel_form: if ctx.is_reverse {
                "reverse".to_string()
            } else {
                "active".to_string()
            },
        };
        let handler = self.handler.read().unwrap().clone();
        match handler.handle_new_tunnel(&meta).await {
            Ok(_) => Ok(ValidateResult::Accept),
            Err(err) => Ok(ValidateResult::Reject(err.msg().to_string())),
        }
    }
}

struct CyfsP2pRuntime {
    _env: P2pEnvRef,
    net_manager: NetManagerRef,
    sn_service: SNClientServiceRef,
    _tunnel_manager: P2pTunnelManagerRef,
    subscription_task: tokio::task::JoinHandle<()>,
    local_id: P2pId,
    local_id_str: String,
}

impl CyfsP2pRuntime {
    async fn shutdown(self) {
        self.subscription_task.abort();
        unregister_pn_service(&self.local_id);
        let _ = self
            .net_manager
            .remove_listen_device(self.local_id_str.as_str())
            .await;
        self.net_manager.unregister_tunnel_acceptor(&self.local_id);
        self.sn_service.stop().await;
    }
}

pub struct CyfsP2pStack {
    id: String,
    bind_addr: SocketAddr,
    gateway_tunnel_manager: TunnelManager,
    local_identity: P2pIdentityRef,
    cert_type: String,
    sn_config: Vec<CyfsP2pSnConfig>,
    sn_list: Vec<P2pSn>,
    reuse_address: bool,
    concurrency: u32,
    handler: Arc<RwLock<Arc<CyfsP2pConnectionHandler>>>,
    prepare_handler: Arc<RwLock<Option<Arc<CyfsP2pConnectionHandler>>>>,
    connection_manager: Option<ConnectionManagerRef>,
    running: Mutex<Option<CyfsP2pRuntime>>,
}

impl Drop for CyfsP2pStack {
    fn drop(&mut self) {
        self.gateway_tunnel_manager.remove_tunnel_builder("sp2p");
        self.gateway_tunnel_manager.remove_tunnel_builder("up2p");
        if let Some(runtime) = self.running.lock().unwrap().take() {
            P2pExecutor::block_on(runtime.shutdown());
        }
    }
}

impl CyfsP2pStack {
    async fn create(
        config: &CyfsP2pStackConfig,
        stack_context: Arc<CyfsP2pStackContext>,
        connection_manager: Option<ConnectionManagerRef>,
        local_identity: P2pIdentityRef,
        sn_list: Vec<P2pSn>,
        io_dump: Option<IoDumpStackConfig>,
    ) -> StackResult<Self> {
        let cert_type = config.cert.cert_type.clone();
        let handler = CyfsP2pConnectionHandler::create(
            config.hook_point.clone(),
            config.pre_hook_point.clone(),
            stack_context.clone(),
            io_dump,
        )
        .await?;
        Ok(Self {
            id: config.id.clone(),
            bind_addr: config.bind,
            gateway_tunnel_manager: stack_context.tunnel_manager.clone(),
            local_identity,
            cert_type,
            sn_config: config.sn.clone(),
            sn_list,
            reuse_address: config.reuse_address.unwrap_or(false),
            concurrency: config.concurrency.unwrap_or(0),
            handler: Arc::new(RwLock::new(Arc::new(handler))),
            prepare_handler: Arc::new(RwLock::new(None)),
            connection_manager,
            running: Mutex::new(None),
        })
    }

    async fn create_runtime(&self) -> StackResult<CyfsP2pRuntime> {
        if self.reuse_address {
            warn!(
                "p2p stack {} configured reuse_address=true, but p2p-frame quic listener has no public reuse-address switch; ignoring",
                self.id
            );
        }

        // Select identity/cert factory based on cert_type (rsa/ed25519 or device),
        // not sign_type. Ed25519 keys may appear in both x509 certs and device
        // certs, but they use different encoding formats and therefore different
        // factories.
        let (identity_factory, cert_factory): (P2pIdentityFactoryRef, P2pIdentityCertFactoryRef) =
            if self.cert_type != "device" {
                (
                    Arc::new(X509IdentityFactory) as P2pIdentityFactoryRef,
                    Arc::new(X509IdentityCertFactory) as P2pIdentityCertFactoryRef,
                )
            } else {
                (
                    Arc::new(DeviceIdentityFactory) as P2pIdentityFactoryRef,
                    Arc::new(DeviceIdentityCertFactory) as P2pIdentityCertFactoryRef,
                )
            };
        let validator = Arc::new(CyfsP2pIncomingTunnelValidator::new(self.handler.clone()));
        let endpoint = Endpoint::from((Protocol::Quic, self.bind_addr));
        let p2p_config = P2pConfig::new(identity_factory, cert_factory.clone(), vec![])
            .set_incoming_tunnel_validator(validator);
        let cert_cache = p2p_config.identity_cert_cache().clone();
        let connection_info_cache = p2p_config.connection_info_cache().clone();
        // Clone the cert resolver before consuming p2p_config so we can set the
        // default server identity after the env is created.
        let cert_resolver = p2p_config.sever_cert_resolver().clone();
        let env = create_p2p_env(p2p_config).await.map_err(into_stack_err!(
            StackErrorCode::Failed,
            "create p2p env failed"
        ))?;
        let net_manager = env.net_manager().clone();

        let sn_service = SNClientService::new(
            net_manager.clone(),
            self.sn_list.clone(),
            self.local_identity.clone(),
            Arc::new(SequenceGenerator::new()),
            Arc::new(TunnelIdGenerator::new()),
            cert_factory.clone(),
            DEFAULT_SN_TUNNEL_COUNT,
            DEFAULT_SN_PING_INTERVAL,
            DEFAULT_SN_CALL_TIMEOUT,
            DEFAULT_CONN_TIMEOUT,
        );
        let device_finder = DefaultDeviceFinder::new(
            sn_service.clone(),
            cert_factory,
            cert_cache,
            DEFAULT_SN_QUERY_INTERVAL,
        );

        net_manager
            .add_listen_device(self.local_identity.clone())
            .await
            .map_err(into_stack_err!(
                StackErrorCode::BindFailed,
                "register p2p identity failed"
            ))?;
        net_manager
            .listen(&[endpoint], None)
            .await
            .map_err(into_stack_err!(
                StackErrorCode::BindFailed,
                "listen quic endpoint failed"
            ))?;

        let tunnel_manager = P2pTunnelManager::new(
            self.local_identity.clone(),
            device_finder,
            net_manager.clone(),
            Some(sn_service.clone()),
            Arc::new(X509IdentityCertFactory),
            None,
            connection_info_cache,
            Arc::new(TunnelIdGenerator::new()),
            DEFAULT_CONN_TIMEOUT,
            DEFAULT_IDLE_TIMEOUT,
        )
        .map_err(into_stack_err!(
            StackErrorCode::Failed,
            "create p2p tunnel manager failed"
        ))?;
        sn_service.start().await.map_err(into_stack_err!(
            StackErrorCode::Failed,
            "start sn client failed"
        ))?;
        let local_id = self.local_identity.get_id();
        register_pn_service(&local_id, tunnel_manager.clone());

        let subscription_task = start_subscription_loop(
            self.handler.clone(),
            tunnel_manager.clone(),
            self.connection_manager.clone(),
            self.concurrency,
        );
        Ok(CyfsP2pRuntime {
            _env: env,
            net_manager,
            sn_service,
            _tunnel_manager: tunnel_manager,
            subscription_task,
            local_id: local_id.clone(),
            local_id_str: local_id.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl Stack for CyfsP2pStack {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn stack_protocol(&self) -> StackProtocol {
        StackProtocol::Extension("p2p".to_string())
    }

    fn get_bind_addr(&self) -> String {
        self.bind_addr.to_string()
    }

    async fn start(&self) -> StackResult<()> {
        if self.running.lock().unwrap().is_some() {
            return Ok(());
        }
        let runtime = self.create_runtime().await?;
        self.gateway_tunnel_manager.register_tunnel_builder(
            "sp2p",
            Arc::new(CyfsP2pTunnelBuilder::new(
                runtime._tunnel_manager.clone(),
                P2pTransportKind::Stream,
            )),
        );
        self.gateway_tunnel_manager.register_tunnel_builder(
            "up2p",
            Arc::new(CyfsP2pTunnelBuilder::new(
                runtime._tunnel_manager.clone(),
                P2pTransportKind::Datagram,
            )),
        );
        *self.running.lock().unwrap() = Some(runtime);
        Ok(())
    }

    async fn prepare_update(
        &self,
        config: Arc<dyn StackConfig>,
        context: Option<Arc<dyn StackContext>>,
    ) -> StackResult<()> {
        let config = config
            .as_ref()
            .as_any()
            .downcast_ref::<CyfsP2pStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid p2p stack config"
            ))?;

        if config.id != self.id {
            return Err(stack_err!(StackErrorCode::InvalidConfig, "id unmatch"));
        }
        if config.bind != self.bind_addr {
            return Err(stack_err!(StackErrorCode::BindUnmatched, "bind unmatch"));
        }
        if config.reuse_address.unwrap_or(false) != self.reuse_address {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "reuse_address unmatch"
            ));
        }
        if config.concurrency.unwrap_or(0) != self.concurrency {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "concurrency unmatch"
            ));
        }

        if config.sn != self.sn_config {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "sn config unmatch"
            ));
        }

        let env = match context {
            Some(context) => {
                let p2p_context = context
                    .as_ref()
                    .as_any()
                    .downcast_ref::<CyfsP2pStackContext>()
                    .ok_or(stack_err!(
                        StackErrorCode::InvalidConfig,
                        "invalid p2p stack context"
                    ))?;
                Arc::new(p2p_context.clone())
            }
            None => self.handler.read().unwrap().env.clone(),
        };
        let io_dump = create_io_dump_stack_config(
            &config.id,
            config.io_dump_file.as_deref(),
            config.io_dump_rotate_size.as_deref(),
            config.io_dump_rotate_max_files,
            config.io_dump_max_upload_bytes_per_conn.as_deref(),
            config.io_dump_max_download_bytes_per_conn.as_deref(),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;
        let handler = CyfsP2pConnectionHandler::create(
            config.hook_point.clone(),
            config.pre_hook_point.clone(),
            env,
            io_dump,
        )
        .await?;
        *self.prepare_handler.write().unwrap() = Some(Arc::new(handler));
        Ok(())
    }

    async fn commit_update(&self) {
        if let Some(handler) = self.prepare_handler.write().unwrap().take() {
            *self.handler.write().unwrap() = handler;
        }
    }

    async fn rollback_update(&self) {
        self.prepare_handler.write().unwrap().take();
    }
}

pub struct CyfsP2pStackFactory {
    connection_manager: ConnectionManagerRef,
}

impl CyfsP2pStackFactory {
    pub fn new(connection_manager: ConnectionManagerRef) -> Self {
        Self { connection_manager }
    }
}

#[async_trait::async_trait]
impl StackFactory for CyfsP2pStackFactory {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let config = config
            .as_any()
            .downcast_ref::<CyfsP2pStackConfig>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid p2p stack config"
            ))?;
        let stack_context = context
            .as_ref()
            .as_any()
            .downcast_ref::<CyfsP2pStackContext>()
            .ok_or(stack_err!(
                StackErrorCode::InvalidConfig,
                "invalid p2p stack context"
            ))?;
        let stack_context = Arc::new(stack_context.clone());
        let io_dump = create_io_dump_stack_config(
            &config.id,
            config.io_dump_file.as_deref(),
            config.io_dump_rotate_size.as_deref(),
            config.io_dump_rotate_max_files,
            config.io_dump_max_upload_bytes_per_conn.as_deref(),
            config.io_dump_max_download_bytes_per_conn.as_deref(),
        )
        .await
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "{e}"))?;

        let cert = &config.cert;

        let sn_list = parse_sn_list(&config.sn)?;
        let local_identity = match cert.cert_type.as_str() {
            // "x509" accepted as a backward-compatible alias for "rsa"
            "rsa" | "x509" => {
                load_x509_identity_from_paths(
                    Path::new(cert.cert_path.as_str()),
                    Path::new(cert.key_path.as_str()),
                    sn_list.clone(),
                    vec![],
                )
                .map_err(into_stack_err!(
                    StackErrorCode::InvalidConfig,
                    "load p2p rsa identity failed"
                ))?
            }
            "ed25519" => {
                load_x509_identity_from_paths(
                    Path::new(cert.cert_path.as_str()),
                    Path::new(cert.key_path.as_str()),
                    sn_list.clone(),
                    vec![],
                )
                .map_err(into_stack_err!(
                    StackErrorCode::InvalidConfig,
                    "load p2p ed25519 identity failed"
                ))?
            }
            "device" => {
                load_device_identity_from_config(cert, config.bind).map_err(into_stack_err!(
                    StackErrorCode::InvalidConfig,
                    "load p2p device identity failed"
                ))?
            }
            _ => {
                return Err(stack_err!(
                    StackErrorCode::InvalidConfig,
                    "unsupported p2p cert type {}",
                    cert.cert_type
                ))
            }
        };

        let stack = CyfsP2pStack::create(
            config,
            stack_context,
            Some(self.connection_manager.clone()),
            local_identity,
            sn_list,
            io_dump,
        )
        .await?;
        Ok(Arc::new(stack))
    }
}

fn parse_sn_list(sn_list: &[CyfsP2pSnConfig]) -> StackResult<Vec<P2pSn>> {
    let mut result = Vec::with_capacity(sn_list.len());
    for sn in sn_list {
        result.push(sn.to_p2p_sn()?);
    }
    Ok(result)
}

fn load_device_identity_from_config(
    cert: &CyfsP2pCertConfig,
    _bind: std::net::SocketAddr,
) -> StackResult<P2pIdentityRef> {
    let private_key = load_raw_private_key(Path::new(cert.key_path.as_str()))
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "load private key failed: {}", e))?;
    let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

    let content = std::fs::read_to_string(cert.cert_path.as_str()).map_err(|e| {
        stack_err!(
            StackErrorCode::InvalidConfig,
            "load device config {} failed: {}",
            cert.cert_path,
            e
        )
    })?;
    let device_config = load_device_config_from_path(
        content.as_str(),
        cert.cert_path.as_str(),
        &public_key,
    )?;

    let identity = DeviceIdentity::new(device_config, private_key.to_vec())
        .map_err(|e| stack_err!(StackErrorCode::InvalidConfig, "create device identity failed: {}", e))?;
    Ok(Arc::new(identity))
}

fn load_device_config_from_path(
    content: &str,
    path: &str,
    public_key: &str,
) -> StackResult<DeviceConfig> {
    if let Ok(device_config) = serde_json::from_str::<DeviceConfig>(content) {
        let default_key = device_config.get_default_key().ok_or(stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} has no default key",
            path
        ))?;
        let x_of_auth_key = get_x_from_jwk(&default_key).map_err(|e| stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} has no auth key: {}",
            path, e
        ))?;
        if x_of_auth_key != public_key {
            return Err(stack_err!(
                StackErrorCode::InvalidConfig,
                "device config {} public key not match",
                path
            ));
        }
        return Ok(device_config);
    }

    let jwt = content.trim();
    let device_config = DeviceConfig::decode(&EncodedDocument::Jwt(jwt.to_string()), None)
        .map_err(|e| stack_err!(
            StackErrorCode::InvalidConfig,
            "parse device config jwt {} failed: {}",
            path, e
        ))?;
    let default_key = device_config.get_default_key().ok_or(stack_err!(
        StackErrorCode::InvalidConfig,
        "device config {} has no default key",
        path
    ))?;
    let x_of_auth_key = get_x_from_jwk(&default_key).map_err(|e| stack_err!(
        StackErrorCode::InvalidConfig,
        "device config {} has no auth key: {}",
        path, e
    ))?;
    if x_of_auth_key != public_key {
        return Err(stack_err!(
            StackErrorCode::InvalidConfig,
            "device config {} public key not match",
            path
        ));
    }
    Ok(device_config)
}

fn start_subscription_loop(
    handler: Arc<RwLock<Arc<CyfsP2pConnectionHandler>>>,
    tunnel_manager: P2pTunnelManagerRef,
    connection_manager: Option<ConnectionManagerRef>,
    concurrency: u32,
) -> tokio::task::JoinHandle<()> {
    let mut subscription = tunnel_manager.subscribe();
    let semaphore = if concurrency == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(concurrency as usize)))
    };
    tokio::spawn(async move {
        loop {
            let tunnel = match subscription.accept_tunnel().await {
                Ok(tunnel) => tunnel,
                Err(err) => {
                    warn!("p2p tunnel subscription stopped: {:?}", err);
                    break;
                }
            };
            if let Err(err) = tunnel.listen_stream(allow_all_tunnel_purposes()).await {
                warn!(
                    "p2p tunnel listen stream failed remote={} err={:?}",
                    tunnel.remote_id(),
                    err
                );
                continue;
            }
            let handler = handler.clone();
            let connection_manager = connection_manager.clone();
            let semaphore = semaphore.clone();
            tokio::spawn(async move {
                accept_tunnel_streams(tunnel, handler, connection_manager, semaphore).await;
            });
        }
    })
}

async fn accept_tunnel_streams(
    tunnel: TunnelRef,
    handler: Arc<RwLock<Arc<CyfsP2pConnectionHandler>>>,
    connection_manager: Option<ConnectionManagerRef>,
    semaphore: Option<Arc<Semaphore>>,
) {
    loop {
        let accepted = tunnel.accept_stream().await;
        let (purpose, read, write) = match accepted {
            Ok(v) => v,
            Err(err) => {
                debug!(
                    "p2p tunnel stream accept stopped remote={} err={:?}",
                    tunnel.remote_id(),
                    err
                );
                break;
            }
        };

        let permit_fut = semaphore
            .clone()
            .map(|semaphore| async move { semaphore.acquire_owned().await.ok() });
        let (transport, payload) = parse_wire_purpose(&purpose);
        let meta = build_stream_meta(tunnel.as_ref(), payload);
        let handler_snapshot = { handler.read().unwrap().clone() };
        let stream: Box<dyn AsyncStream> = Box::new(P2pAsyncStream::new(read, write));
        let remote_label = meta
            .tunnel
            .source_ep
            .as_ref()
            .map(|ep| ep.addr().to_string())
            .unwrap_or_else(|| meta.tunnel.source_device_id.to_string());
        let local_label = meta
            .tunnel
            .dest_ep
            .as_ref()
            .map(|ep| ep.addr().to_string())
            .unwrap_or_else(|| meta.tunnel.dest_device_id.to_string());
        let stream: Box<dyn AsyncStream> = if let Some(io_dump) = handler_snapshot.io_dump.clone() {
            Box::new(DumpStream::new(
                stream,
                io_dump,
                remote_label.clone(),
                local_label.clone(),
            ))
        } else {
            stream
        };
        let stat = MutComposedSpeedStat::new();
        let stat_stream = Box::new(StatStream::new_with_tracker(stream, stat.clone()));
        let speed = stat_stream.get_speed_stat();
        let task = tokio::spawn(async move {
            let _permit = match permit_fut {
                Some(fut) => fut.await,
                None => None,
            };
            let ret = match transport {
                P2pTransportKind::Stream => {
                    handler_snapshot
                        .handle_stream(stat_stream, meta, stat)
                        .await
                }
                P2pTransportKind::Datagram => {
                    handler_snapshot
                        .handle_datagram(stat_stream, meta, stat)
                        .await
                }
            };
            if let Err(err) = ret {
                error!("p2p handle stream failed: {}", err);
            }
        });
        if let Some(manager) = &connection_manager {
            let controller = HandleConnectionController::new(task);
            manager.add_connection(ConnectionInfo::new(
                remote_label,
                local_label,
                StackProtocol::Extension("p2p".to_string()),
                speed,
                controller,
            ));
        }
    }
}

fn build_stream_meta(tunnel: &dyn p2p_frame::networks::Tunnel, purpose: String) -> P2pStreamMeta {
    let tunnel_meta = P2pTunnelMeta {
        source_device_id: tunnel.remote_id().to_owned(),
        dest_device_id: tunnel.local_id().to_owned(),
        source_ep: tunnel.remote_ep().map(|ep| ep.to_owned()),
        dest_ep: tunnel.local_ep().map(|ep| ep.to_owned()),
        transport_protocol: protocol_to_string(tunnel.protocol()),
        tunnel_id: format!("{:?}", tunnel.tunnel_id()),
        candidate_id: format!("{:?}", tunnel.candidate_id()),
        is_reverse: tunnel.is_reverse(),
        tunnel_form: format!("{:?}", tunnel.form()).to_ascii_lowercase(),
    };
    P2pStreamMeta {
        tunnel: tunnel_meta,
        purpose,
    }
}

fn parse_target_url(value: &str) -> Option<Url> {
    if !cyfs_gateway_lib::has_scheme(value) {
        return None;
    }
    Url::parse(value).ok()
}

fn parse_endpoint(value: &str) -> Result<Endpoint, p2p_frame::error::P2pError> {
    let first = value.chars().next();
    if matches!(first, Some('L' | 'D' | 'W' | 'M')) {
        Endpoint::from_str(value)
    } else {
        let addr = SocketAddr::from_str(value)
            .map_err(|_| p2p_err!(P2pErrorCode::InvalidInput, "invalid endpoint {}", value))?;
        Ok(Endpoint::from((Protocol::Quic, addr)))
    }
}

fn protocol_to_string(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "tcp".to_string(),
        Protocol::Quic => "quic".to_string(),
        Protocol::Ext(v) => format!("ext-{}", v),
    }
}

async fn insert_map_string(
    map: &cyfs_process_chain::MapCollectionRef,
    key: &str,
    value: &str,
) -> StackResult<()> {
    map.insert(key, CollectionValue::String(value.to_string()))
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;
    Ok(())
}

async fn insert_endpoint_addr(
    map: &cyfs_process_chain::MapCollectionRef,
    ip_key: &str,
    port_key: &str,
    endpoint: Option<&Endpoint>,
) -> StackResult<()> {
    if let Some(endpoint) = endpoint {
        let addr = endpoint.addr();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        insert_map_string(map, ip_key, ip.as_str()).await?;
        insert_map_string(map, port_key, port.as_str()).await?;
    }
    Ok(())
}

async fn insert_p2p_target_fields(
    map: &cyfs_process_chain::MapCollectionRef,
    purpose: &str,
) -> StackResult<()> {
    if let Some(url) = parse_target_url(purpose) {
        insert_map_string(map, "target_url", purpose).await?;
        insert_map_string(map, "target_protocol", url.scheme()).await?;
        if let Some(host) = url.host_str() {
            insert_map_string(map, "target_host", host).await?;
        }
        if let Some(port) = url.port() {
            let port = port.to_string();
            insert_map_string(map, "target_port", port.as_str()).await?;
        }
        if url.path() != "/" {
            insert_map_string(map, "target_path", url.path()).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use buckyos_kit::AsyncStream;
    use cyfs_gateway_lib::{
        ConnectionManager, DatagramInfo, DatagramServer, DefaultLimiterManager,
        GlobalProcessChains, ServerErrorCode, ServerManager, ServerResult, StatManager,
        StreamServer, server_err,
    };
    use p2p_frame::networks::{IncomingTunnelValidateContext, TunnelPurpose, ValidateResult};
    use p2p_frame::p2p_identity::{P2pId, P2pIdentity, P2pIdentityCert, P2pIdentityCertRef, P2pIdentityRef, P2pIdentitySignType, P2pSignature, P2pSn};
    use p2p_frame::types::{TunnelCandidateId, TunnelId};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn build_handler_env(
        servers: ServerManagerRef,
        tunnel_manager: TunnelManager,
        limiter_manager: LimiterManagerRef,
        stat_manager: StatManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
    ) -> Arc<CyfsP2pStackContext> {
        Arc::new(CyfsP2pStackContext::new(
            servers,
            tunnel_manager,
            limiter_manager,
            stat_manager,
            global_process_chains,
            None,
            None,
        ))
    }

    fn default_handler_env() -> Arc<CyfsP2pStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            None,
        )
    }

    fn handler_env_with_process_chains() -> Arc<CyfsP2pStackContext> {
        build_handler_env(
            Arc::new(ServerManager::new()),
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        )
    }

    fn parse_chains(chains: &str) -> ProcessChainConfigs {
        serde_yaml_ng::from_str(chains).unwrap()
    }

    fn test_p2p_id(seed: u8) -> P2pId {
        P2pId::from(vec![seed; 32])
    }

    fn test_endpoint(port: u16) -> Endpoint {
        Endpoint::from((Protocol::Quic, SocketAddr::from(([127, 0, 0, 1], port))))
    }

    fn test_tunnel_meta() -> P2pTunnelMeta {
        P2pTunnelMeta {
            source_device_id: test_p2p_id(1),
            dest_device_id: test_p2p_id(2),
            source_ep: Some(test_endpoint(20001)),
            dest_ep: Some(test_endpoint(20002)),
            transport_protocol: "quic".to_string(),
            tunnel_id: TunnelId::from(100).to_string(),
            candidate_id: format!("{:?}", TunnelCandidateId::from(200)),
            is_reverse: false,
            tunnel_form: "active".to_string(),
        }
    }

    fn test_stream_meta() -> P2pStreamMeta {
        P2pStreamMeta {
            tunnel: test_tunnel_meta(),
            purpose: "test-purpose".to_string(),
        }
    }

    fn expected_stream_extra() -> P2pStreamExtra {
        let meta = test_stream_meta();
        P2pStreamExtra {
            source_device_id: meta.tunnel.source_device_id.to_string(),
            dest_device_id: meta.tunnel.dest_device_id.to_string(),
            source_endpoint: meta.tunnel.source_ep.map(|ep| ep.to_string()),
            dest_endpoint: meta.tunnel.dest_ep.map(|ep| ep.to_string()),
            transport_protocol: meta.tunnel.transport_protocol,
            tunnel_id: meta.tunnel.tunnel_id,
            candidate_id: meta.tunnel.candidate_id,
            purpose: meta.purpose,
            is_reverse: meta.tunnel.is_reverse,
            tunnel_form: meta.tunnel.tunnel_form,
        }
    }

    fn build_test_config(
        id: &str,
        bind: &str,
        pre_hook_point: Option<ProcessChainConfigs>,
        hook_point: ProcessChainConfigs,
    ) -> CyfsP2pStackConfig {
        CyfsP2pStackConfig {
            id: id.to_string(),
            protocol: StackProtocol::Extension("p2p".to_string()),
            bind: bind.parse().unwrap(),
            sn: vec![],
            reuse_address: Some(false),
            io_dump_file: None,
            io_dump_rotate_size: None,
            io_dump_rotate_max_files: None,
            io_dump_max_upload_bytes_per_conn: None,
            io_dump_max_download_bytes_per_conn: None,
            concurrency: Some(0),
            cert: CyfsP2pCertConfig {
                cert_type: "rsa".to_string(),
                key_path: "test.key".to_string(),
                cert_path: "test.cert".to_string(),
            },
            pre_hook_point,
            hook_point,
        }
    }

    async fn build_test_stack(
        config: &CyfsP2pStackConfig,
        context: Arc<CyfsP2pStackContext>,
    ) -> StackResult<CyfsP2pStack> {
        CyfsP2pStack::create(config, context, None, mock_identity(), vec![], None).await
    }

    fn current_handler(stack: &CyfsP2pStack) -> Arc<CyfsP2pConnectionHandler> {
        stack.handler.read().unwrap().clone()
    }

    async fn run_handler_roundtrip(
        handler: Arc<CyfsP2pConnectionHandler>,
        request: &[u8],
    ) -> StackResult<Vec<u8>> {
        let (mut client, server_stream) = tokio::io::duplex(1024);
        let stat = MutComposedSpeedStat::new();
        let tracked_stream = Box::new(StatStream::new_with_tracker(server_stream, stat.clone()))
            as Box<dyn AsyncStream>;
        let task = tokio::spawn(async move {
            handler
                .handle_stream(tracked_stream, test_stream_meta(), stat)
                .await
        });

        client.write_all(request).await.unwrap();
        let mut buf = vec![0u8; request.len()];
        client.read_exact(&mut buf).await.unwrap();
        drop(client);

        task.await.unwrap()?;
        Ok(buf)
    }

    async fn run_handler_expect_eof(handler: Arc<CyfsP2pConnectionHandler>) -> StackResult<()> {
        let (mut client, server_stream) = tokio::io::duplex(1024);
        let stat = MutComposedSpeedStat::new();
        let tracked_stream = Box::new(StatStream::new_with_tracker(server_stream, stat.clone()))
            as Box<dyn AsyncStream>;
        let task = tokio::spawn(async move {
            handler
                .handle_stream(tracked_stream, test_stream_meta(), stat)
                .await
        });

        task.await.unwrap()?;
        let mut buf = [0u8; 1];
        let len = client.read(&mut buf).await.unwrap();
        assert_eq!(len, 0);
        Ok(())
    }

    async fn run_handler_expect_err(handler: Arc<CyfsP2pConnectionHandler>) -> StackResult<()> {
        let (_client, server_stream) = tokio::io::duplex(1024);
        let stat = MutComposedSpeedStat::new();
        let tracked_stream = Box::new(StatStream::new_with_tracker(server_stream, stat.clone()))
            as Box<dyn AsyncStream>;
        handler
            .handle_stream(tracked_stream, test_stream_meta(), stat)
            .await
    }

    async fn run_datagram_handler_roundtrip(
        handler: Arc<CyfsP2pConnectionHandler>,
        request: &[u8],
        purpose: &str,
    ) -> StackResult<Vec<u8>> {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let client = P2pDatagramClient::new(Box::new(client_stream));
        let stat = MutComposedSpeedStat::new();
        let tracked_stream = Box::new(StatStream::new_with_tracker(server_stream, stat.clone()))
            as Box<dyn AsyncStream>;
        let meta = P2pStreamMeta {
            tunnel: test_tunnel_meta(),
            purpose: purpose.to_string(),
        };
        let task =
            tokio::spawn(async move { handler.handle_datagram(tracked_stream, meta, stat).await });

        client.send_datagram(request).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let len = client.recv_datagram(&mut buf).await.unwrap();

        task.abort();
        Ok(buf[..len].to_vec())
    }

    #[derive(Clone)]
    struct MockIdentityCert {
        id: P2pId,
        name: String,
        endpoints: Vec<Endpoint>,
    }

    impl MockIdentityCert {
        fn new(id: P2pId, name: impl Into<String>, endpoints: Vec<Endpoint>) -> Self {
            Self {
                id,
                name: name.into(),
                endpoints,
            }
        }
    }

    impl P2pIdentityCert for MockIdentityCert {
        fn get_id(&self) -> P2pId {
            self.id.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn sign_type(&self) -> P2pIdentitySignType {
            P2pIdentitySignType::Rsa
        }

        fn verify(&self, _message: &[u8], _sign: &P2pSignature) -> bool {
            true
        }

        fn verify_cert(&self, _name: &str) -> bool {
            true
        }

        fn get_encoded_cert(&self) -> P2pResult<Vec<u8>> {
            Ok(vec![])
        }

        fn endpoints(&self) -> Vec<Endpoint> {
            self.endpoints.clone()
        }

        fn sn_list(&self) -> Vec<P2pSn> {
            vec![]
        }

        fn update_endpoints(&self, eps: Vec<Endpoint>) -> P2pIdentityCertRef {
            Arc::new(Self {
                id: self.id.clone(),
                name: self.name.clone(),
                endpoints: eps,
            })
        }
    }

    struct MockIdentity {
        cert: P2pIdentityCertRef,
    }

    impl MockIdentity {
        fn new() -> Self {
            let cert = Arc::new(MockIdentityCert::new(
                test_p2p_id(9),
                "mock-device",
                vec![test_endpoint(20003)],
            )) as P2pIdentityCertRef;
            Self { cert }
        }
    }

    impl P2pIdentity for MockIdentity {
        fn get_identity_cert(&self) -> P2pResult<P2pIdentityCertRef> {
            Ok(self.cert.clone())
        }

        fn get_id(&self) -> P2pId {
            self.cert.get_id()
        }

        fn get_name(&self) -> String {
            self.cert.get_name()
        }

        fn sign_type(&self) -> P2pIdentitySignType {
            P2pIdentitySignType::Rsa
        }

        fn sign(&self, _message: &[u8]) -> P2pResult<P2pSignature> {
            Ok(vec![])
        }

        fn get_encoded_identity(&self) -> P2pResult<Vec<u8>> {
            Ok(vec![])
        }

        fn endpoints(&self) -> Vec<Endpoint> {
            self.cert.endpoints()
        }

        fn update_endpoints(&self, eps: Vec<Endpoint>) -> P2pIdentityRef {
            Arc::new(Self {
                cert: self.cert.update_endpoints(eps),
            })
        }
    }

    fn mock_identity() -> P2pIdentityRef {
        Arc::new(MockIdentity::new()) as P2pIdentityRef
    }

    struct MockServer {
        id: String,
        request: Vec<u8>,
        response: Vec<u8>,
    }

    impl MockServer {
        fn new(id: impl Into<String>, request: &[u8], response: &[u8]) -> Self {
            Self {
                id: id.into(),
                request: request.to_vec(),
                response: response.to_vec(),
            }
        }
    }

    struct ExtraCaptureServer {
        id: String,
        captured: Arc<Mutex<Vec<P2pStreamExtra>>>,
        response: Vec<u8>,
    }

    struct MockDatagramServer {
        id: String,
        request: Vec<u8>,
        response: Vec<u8>,
        seen_infos: Arc<Mutex<Vec<DatagramInfo>>>,
    }

    impl ExtraCaptureServer {
        fn new(
            id: impl Into<String>,
            captured: Arc<Mutex<Vec<P2pStreamExtra>>>,
            response: &[u8],
        ) -> Self {
            Self {
                id: id.into(),
                captured,
                response: response.to_vec(),
            }
        }
    }

    impl MockDatagramServer {
        fn new(
            id: impl Into<String>,
            request: &[u8],
            response: &[u8],
            seen_infos: Arc<Mutex<Vec<DatagramInfo>>>,
        ) -> Self {
            Self {
                id: id.into(),
                request: request.to_vec(),
                response: response.to_vec(),
                seen_infos,
            }
        }
    }

    #[async_trait::async_trait]
    impl StreamServer for MockServer {
        async fn serve_connection(
            &self,
            mut stream: Box<dyn AsyncStream>,
            _info: StreamInfo,
        ) -> ServerResult<()> {
            let mut buf = vec![0u8; self.request.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, self.request);
            stream.write_all(self.response.as_slice()).await.unwrap();
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[async_trait::async_trait]
    impl StreamServer for ExtraCaptureServer {
        async fn serve_connection(
            &self,
            mut stream: Box<dyn AsyncStream>,
            info: StreamInfo,
        ) -> ServerResult<()> {
            let extra = P2pStreamExtra::decode(info.extra.as_slice())
                .map_err(|e| server_err!(ServerErrorCode::InvalidData, "{}", e))?;
            self.captured.lock().unwrap().push(extra);

            let mut req = [0u8; 4];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"test");
            stream.write_all(self.response.as_slice()).await.unwrap();
            Ok(())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[async_trait::async_trait]
    impl DatagramServer for MockDatagramServer {
        async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>> {
            assert_eq!(buf, self.request);
            self.seen_infos.lock().unwrap().push(info);
            Ok(self.response.clone())
        }

        fn id(&self) -> String {
            self.id.clone()
        }
    }

    #[test]
    fn test_p2p_parse_helpers() {
        let endpoint = parse_endpoint("127.0.0.1:3456").unwrap();
        assert_eq!(endpoint.protocol(), Protocol::Quic);
        assert_eq!(endpoint.addr(), &SocketAddr::from(([127, 0, 0, 1], 3456)));
        assert!(parse_endpoint("not-an-endpoint").is_err());
        assert_eq!(protocol_to_string(Protocol::Quic), "quic");

        let purpose = TunnelPurpose::from_value(&"service".to_string()).unwrap();
        assert_eq!(purpose.decode_as::<String>().unwrap(), "service");
    }

    #[tokio::test]
    async fn test_p2p_stack_creation() {
        let valid_config = build_test_config("test", "127.0.0.1:9451", None, vec![]);
        let result = build_test_stack(&valid_config, default_handler_env()).await;
        assert!(result.is_ok());

        let result = build_test_stack(&valid_config, handler_env_with_process_chains()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_p2p_factory_validation() {
        let factory = CyfsP2pStackFactory::new(ConnectionManager::new());
        let context: Arc<dyn StackContext> = handler_env_with_process_chains();

        let mut unsupported = build_test_config("test", "127.0.0.1:9453", None, vec![]);
        unsupported.cert.cert_type = "unsupported_type".to_string();
        let result = factory.create(Arc::new(unsupported), context.clone()).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().code(), StackErrorCode::InvalidConfig);

        let mut invalid_sn = build_test_config("test", "127.0.0.1:9454", None, vec![]);
        invalid_sn.sn = vec![CyfsP2pSnConfig {
            id: "bad-sn-id".to_string(),
            name: "sn-1".to_string(),
            endpoints: vec!["127.0.0.1:3456".to_string()],
        }];
        let result = factory.create(Arc::new(invalid_sn), context).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().code(), StackErrorCode::InvalidConfig);
    }

    #[tokio::test]
    async fn test_p2p_validator_rejects_tunnel() {
        let handler = CyfsP2pConnectionHandler::create(
            vec![],
            Some(parse_chains(
                r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        reject;
                "#,
            )),
            handler_env_with_process_chains(),
            None,
        )
        .await
        .unwrap();
        let validator =
            CyfsP2pIncomingTunnelValidator::new(Arc::new(RwLock::new(Arc::new(handler))));
        let ctx = IncomingTunnelValidateContext {
            local_id: test_p2p_id(2),
            remote_id: test_p2p_id(1),
            protocol: Protocol::Quic,
            tunnel_id: TunnelId::from(101),
            candidate_id: TunnelCandidateId::from(201),
            is_reverse: false,
            local_ep: Some(test_endpoint(20010)),
            remote_ep: Some(test_endpoint(20011)),
        };

        let result = validator.validate(&ctx).await.unwrap();
        match result {
            ValidateResult::Reject(msg) => {
                assert!(msg.contains("rejected by process_chain"));
            }
            ValidateResult::Accept => panic!("expected tunnel rejection"),
        }
    }

    #[tokio::test]
    async fn test_p2p_stream_drop() {
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
                    "#,
                ),
                None,
                handler_env_with_process_chains(),
                None,
            )
            .await
            .unwrap(),
        );

        run_handler_expect_eof(handler).await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_stream_server() {
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "test-server",
                b"test",
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server test-server";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    Arc::new(DefaultLimiterManager::new()),
                    StatManager::new(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");
    }

    #[test]
    fn test_p2p_stream_extra_json_roundtrip() {
        let extra = expected_stream_extra();
        let encoded = extra.encode().unwrap();
        let decoded = P2pStreamExtra::decode(encoded.as_slice()).unwrap();

        assert_eq!(decoded, extra);
        assert_eq!(decoded.source_device_id, test_p2p_id(1).to_string());
        assert_eq!(decoded.dest_device_id, test_p2p_id(2).to_string());
        assert_eq!(decoded.purpose, "test-purpose");
    }

    #[tokio::test]
    async fn test_p2p_stream_server_receives_p2p_extra() {
        let server_manager = Arc::new(ServerManager::new());
        let captured = Arc::new(Mutex::new(Vec::new()));
        server_manager
            .add_server(Server::Stream(Arc::new(ExtraCaptureServer::new(
                "capture-extra",
                captured.clone(),
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server capture-extra";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    Arc::new(DefaultLimiterManager::new()),
                    StatManager::new(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], expected_stream_extra());
    }

    #[tokio::test]
    async fn test_p2p_stream_forward() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forward_addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");
            stream.write_all(b"recv").await.unwrap();
        });

        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(&format!(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///{forward_addr}";
                    "#,
                )),
                None,
                handler_env_with_process_chains(),
                None,
            )
            .await
            .unwrap(),
        );

        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_p2p_stream_forward_err() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forward_addr = listener.local_addr().unwrap();
        drop(listener);

        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(&format!(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "forward tcp:///{forward_addr}";
                    "#,
                )),
                None,
                handler_env_with_process_chains(),
                None,
            )
            .await
            .unwrap(),
        );

        let err = run_handler_expect_err(handler).await.unwrap_err();
        assert_eq!(err.code(), StackErrorCode::TunnelError);
    }

    #[tokio::test]
    async fn test_p2p_datagram_server() {
        let server_manager = Arc::new(ServerManager::new());
        let infos = Arc::new(Mutex::new(Vec::new()));
        server_manager
            .add_server(Server::Datagram(Arc::new(MockDatagramServer::new(
                "test-datagram",
                b"ping",
                b"pong",
                infos.clone(),
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server test-datagram";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    Arc::new(DefaultLimiterManager::new()),
                    StatManager::new(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let response = run_datagram_handler_roundtrip(handler, b"ping", "service")
            .await
            .unwrap();
        assert_eq!(response, b"pong");

        let infos = infos.lock().unwrap();
        assert_eq!(infos.len(), 1);
        assert!(infos[0].src_addr.is_some());
    }

    #[tokio::test]
    async fn test_p2p_target_url_fields() {
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "target-server",
                b"test",
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        eq ${REQ.target_protocol} "rtcp" && eq ${REQ.target_host} "device" && eq ${REQ.target_port} "443" && return "server target-server";
        drop;
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    Arc::new(DefaultLimiterManager::new()),
                    StatManager::new(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let (mut client, server_stream) = tokio::io::duplex(1024);
        let stat = MutComposedSpeedStat::new();
        let tracked_stream = Box::new(StatStream::new_with_tracker(server_stream, stat.clone()))
            as Box<dyn AsyncStream>;
        let meta = P2pStreamMeta {
            tunnel: test_tunnel_meta(),
            purpose: "rtcp://device:443/tcp://127.0.0.1:80".to_string(),
        };
        let task =
            tokio::spawn(async move { handler.handle_stream(tracked_stream, meta, stat).await });

        client.write_all(b"test").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"recv");

        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_p2p_stream_stat_limiter_server() {
        let stat_manager = StatManager::new();
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "test-server",
                b"test",
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit "2B/s" "2B/s";
        return "server test-server";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    Arc::new(DefaultLimiterManager::new()),
                    stat_manager.clone(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let start = Instant::now();
        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");

        let test_stat = stat_manager.get_speed_stat("test").unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
    }

    #[tokio::test]
    async fn test_p2p_stream_stat_group_limiter_server() {
        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "test-server",
                b"test",
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test;
        return "server test-server";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    limiter_manager,
                    stat_manager.clone(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let start = Instant::now();
        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");

        let test_stat = stat_manager.get_speed_stat("test").unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
    }

    #[tokio::test]
    async fn test_p2p_stream_stat_group_limiter_override_server() {
        let stat_manager = StatManager::new();
        let mut limiter_manager = DefaultLimiterManager::new();
        let _ = limiter_manager.new_limiter(
            "test".to_string(),
            None::<String>,
            Some(1),
            Some(2),
            Some(2),
        );
        let limiter_manager = Arc::new(limiter_manager);
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "test-server",
                b"test",
                b"recv",
            ))))
            .unwrap();
        let handler = Arc::new(
            CyfsP2pConnectionHandler::create(
                parse_chains(
                    r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        set-stat test;
        set-limit test 10KB/s 10KB/s;
        return "server test-server";
                    "#,
                ),
                None,
                build_handler_env(
                    server_manager,
                    TunnelManager::new(),
                    limiter_manager,
                    stat_manager.clone(),
                    Some(Arc::new(GlobalProcessChains::new())),
                ),
                None,
            )
            .await
            .unwrap(),
        );

        let start = Instant::now();
        let response = run_handler_roundtrip(handler, b"test").await.unwrap();
        assert_eq!(response, b"recv");

        let test_stat = stat_manager.get_speed_stat("test").unwrap();
        assert_eq!(test_stat.get_read_sum_size(), 4);
        assert_eq!(test_stat.get_write_sum_size(), 4);
        assert!(start.elapsed().as_millis() > 1800);
    }

    #[tokio::test]
    async fn test_p2p_prepare_update_validation() {
        let config = build_test_config(
            "test",
            "127.0.0.1:9455",
            None,
            parse_chains(
                r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        drop;
                "#,
            ),
        );
        let stack = build_test_stack(&config, handler_env_with_process_chains())
            .await
            .unwrap();

        let mut bind_unmatched = config.clone();
        bind_unmatched.bind = "127.0.0.1:9555".parse().unwrap();
        let err = stack
            .prepare_update(Arc::new(bind_unmatched), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), StackErrorCode::BindUnmatched);

        let mut sn_unmatched = config.clone();
        sn_unmatched.sn = vec![CyfsP2pSnConfig {
            id: test_p2p_id(3).to_string(),
            name: "sn-1".to_string(),
            endpoints: vec!["127.0.0.1:3456".to_string()],
        }];
        let err = stack
            .prepare_update(Arc::new(sn_unmatched), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), StackErrorCode::InvalidConfig);
    }

    #[tokio::test]
    async fn test_p2p_prepare_commit_and_rollback_update() {
        let server_manager = Arc::new(ServerManager::new());
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "old-server",
                b"test",
                b"old!",
            ))))
            .unwrap();
        server_manager
            .add_server(Server::Stream(Arc::new(MockServer::new(
                "new-server",
                b"test",
                b"new!",
            ))))
            .unwrap();
        let context = build_handler_env(
            server_manager,
            TunnelManager::new(),
            Arc::new(DefaultLimiterManager::new()),
            StatManager::new(),
            Some(Arc::new(GlobalProcessChains::new())),
        );
        let config = build_test_config(
            "test",
            "127.0.0.1:9456",
            None,
            parse_chains(
                r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server old-server";
                "#,
            ),
        );
        let stack = build_test_stack(&config, context).await.unwrap();

        let response = run_handler_roundtrip(current_handler(&stack), b"test")
            .await
            .unwrap();
        assert_eq!(response, b"old!");

        let new_config = build_test_config(
            "test",
            "127.0.0.1:9456",
            None,
            parse_chains(
                r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        return "server new-server";
                "#,
            ),
        );
        stack
            .prepare_update(Arc::new(new_config.clone()), None)
            .await
            .unwrap();

        let response = run_handler_roundtrip(current_handler(&stack), b"test")
            .await
            .unwrap();
        assert_eq!(response, b"old!");

        stack.rollback_update().await;
        let response = run_handler_roundtrip(current_handler(&stack), b"test")
            .await
            .unwrap();
        assert_eq!(response, b"old!");

        stack
            .prepare_update(Arc::new(new_config), None)
            .await
            .unwrap();
        stack.commit_update().await;

        let response = run_handler_roundtrip(current_handler(&stack), b"test")
            .await
            .unwrap();
        assert_eq!(response, b"new!");
    }
}
