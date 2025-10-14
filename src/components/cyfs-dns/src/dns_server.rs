use std::f32::consts::E;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;

use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::authority::{Catalog, MessageRequest, MessageResponse, MessageResponseBuilder, Queries};
use hickory_server::proto::op::*;
use hickory_server::proto::rr::*;
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use log::trace;
use log::{debug, error, info, warn};
use rdata::{A, AAAA, CNAME, TXT};
use tokio::net::UdpSocket;

use anyhow::Result;
use cyfs_gateway_lib::*;
use cyfs_sn::get_sn_server_by_id;
use futures::stream::{self, StreamExt};
use name_client::{DnsProvider, LocalConfigDnsProvider, NameInfo, NsProvider, RecordType};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use hickory_proto::{ProtoError, ProtoErrorKind};
use hickory_proto::op::message::EmitAndCount;
use hickory_proto::xfer::{Protocol, SerialMessage};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use url::Url;
use cyfs_process_chain::{CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor};
use crate::map_collection_to_nameinfo;
use crate::resolve::Resolve;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Name not found: {0:}")]
    NameNotFound(String),
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("Invalid RecordType {0:}")]
    InvalidRecordType(String),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
    #[error("Proto error: {0:}")]
    Proto(#[from] hickory_proto::ProtoError),
}

#[derive(Clone)]
pub struct DNSServer {
    config: DNSServerConfig,
    resolver_chain: Arc<Vec<Box<dyn NsProvider>>>,
}

pub async fn create_ns_provider(
    provider_config: &DNSProviderConfig,
) -> Result<Box<dyn NsProvider>> {
    match provider_config.provider_type {
        DNSProviderType::DNS => {
            let dns_provider = DnsProvider::new_with_config(provider_config.config.clone())?;
            Ok(Box::new(dns_provider))
        }
        DNSProviderType::LocalConfig => {
            let local_provider = LocalConfigDnsProvider::new_with_config(provider_config.config.clone())?;
            Ok(Box::new(local_provider))
        }

        DNSProviderType::SN => {
            let sn_server_id = provider_config.config.get("server_id");
            if sn_server_id.is_none() {
                error!("server_id is none");
                return Err(anyhow::anyhow!("server_id is none"));
            }
            let sn_server_id = sn_server_id.unwrap();
            let sn_server_id = sn_server_id.as_str();
            if sn_server_id.is_none() {
                error!("server_id is none");
                return Err(anyhow::anyhow!("server_id is none"));
            }
            let sn_server_id = sn_server_id.unwrap();
            let sn_server = get_sn_server_by_id(sn_server_id).await;
            //let sn_server = SNServer::new(sn_server_id);
            if sn_server.is_none() {
                error!("sn_server not found:{}", sn_server_id);
                return Err(anyhow::anyhow!("sn_server not found:{}", sn_server_id));
            }
            let sn_server = sn_server.unwrap();
            Ok(Box::new(sn_server))
        }
        _ => Err(anyhow::anyhow!(
            "Unknown provider type: {:?}",
            provider_config.provider_type
        )),
    }
}

//TODO: dns_provider is realy a demo implementation, must refactor before  used in a offical server.
fn nameinfo_to_rdata(record_type: &str, name_info: &NameInfo) -> Result<Vec<RData>> {
    match record_type {
        "A" => {
            if name_info.address.is_empty() {
                return Err(anyhow::anyhow!("Address is none"));
            }

            let mut records = Vec::new();
            // Convert all IPv4 addresses to A records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V4(addr) => {
                        records.push(RData::A(A::from(*addr)));
                    }
                    _ => {
                        debug!("Skipping non-IPv4 address");
                        continue;
                    }
                }
            }

            if records.is_empty() {
                return Err(anyhow::anyhow!("No valid IPv4 addresses found"));
            }
            Ok(records)
        }
        "AAAA" => {
            if name_info.address.is_empty() {
                return Err(anyhow::anyhow!("Address is none"));
            }
            let mut records = Vec::new();
            // Convert all IPv6 addresses to AAAA records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V6(addr) => {
                        records.push(RData::AAAA(AAAA::from(*addr)));
                    }
                    _ => {
                        debug!("Skipping non-IPv6 address");
                        continue;
                    }
                }
            }

            if records.is_empty() {
                return Err(anyhow::anyhow!("No valid IPv6 addresses found"));
            }
            Ok(records)
        }
        "CNAME" => {
            if name_info.cname.is_none() {
                return Err(anyhow::anyhow!("CNAME is none"));
            }
            let cname = name_info.cname.clone().unwrap();
            let mut records = Vec::new();
            records.push(RData::CNAME(CNAME(Name::from_str(cname.as_str()).unwrap())));
            return Ok(records);
        }
        "TXT" => {
            let mut records = Vec::new();
            if name_info.txt.is_some() {
                let txt = name_info.txt.clone().unwrap();
                if txt.len() > 255 {
                    warn!("TXT is too long, split it");
                    let s1 = txt[0..254].to_string();
                    let s2 = txt[254..].to_string();

                    records.push(RData::TXT(TXT::new(vec![s1, s2])));
                } else {
                    records.push(RData::TXT(TXT::new(vec![txt])));
                }
            }

            if name_info.did_document.is_some() {
                let did_string = name_info.did_document.as_ref().unwrap().to_string();
                records.push(RData::TXT(TXT::new(vec![format!("DID={};", did_string)])));
            }

            if name_info.pk_x_list.is_some() {
                let pk_x_list = name_info.pk_x_list.as_ref().unwrap();
                for pk_x in pk_x_list.iter() {
                    records.push(RData::TXT(TXT::new(vec![format!("PKX={};", pk_x)])));
                }
            }

            return Ok(records);
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown record type:{}", record_type));
        }
    }
}

impl DNSServer {
    pub async fn new(config: DNSServerConfig) -> Result<Self> {
        let mut resolver_chain: Vec<Box<dyn NsProvider>> = Vec::new();

        for provider_config in config.resolver_chain.iter() {
            let provider = create_ns_provider(provider_config).await;
            if provider.is_err() {
                error!("Failed to create provider: {}", provider_config.config);
            } else {
                resolver_chain.push(provider.unwrap());
            }
        }

        Ok(DNSServer {
            config,
            resolver_chain: Arc::new(resolver_chain),
        })
    }

    async fn start(&self) -> Result<()> {
        let bind_addr = self.config.bind.clone().unwrap_or("0.0.0.0".to_string());
        let addr = format!("{}:{}", bind_addr, self.config.port);
        info!("cyfs-dns-server try bind at:{}", addr);
        let udp_socket = UdpSocket::bind(addr.clone()).await?;

        let mut server = ServerFuture::new(self.clone());
        server.register_socket(udp_socket);

        tokio::spawn(async move {
            info!("cyfs-dns-server run at:{}", addr);
            match server.block_until_done().await {
                Ok(_) => {
                    info!("cyfs-dns-server done: {}", addr);
                }
                Err(e) => {
                    error!("cyfs-dns-server error: {}, {}", e, addr);
                }
            }
        });

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // TODO: stop server for config dynamic update or outside control
        Ok(())
    }

    async fn handle_fallback<R: ResponseHandler>(
        &self,
        request: &Request,
        server_name: &str,
        mut response: R,
    ) -> Result<Message, Error> {
        let message = request.to_bytes();
        let message = message.unwrap();
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target_url = Url::parse(server_name);
        if target_url.is_err() {
            return Err(Error::NameNotFound("".to_string()));
        }
        let target_url = target_url.unwrap();
        let host = target_url.host_str().unwrap();
        let port = target_url.port().unwrap_or(53);
        let target_addr = SocketAddr::new(IpAddr::from_str(host).unwrap(), port);
        socket.send_to(&message, target_addr).await?;
        let mut buf = [0u8; 2048];
        let mut resp_len = 512;
        let proxy_result = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await;
        //let resp_vec =buf[0..resp_len].to_vec();
        let resp_message = Message::from_vec(&buf[0..resp_len]);
        if resp_message.is_err() {
            return Err(Error::NameNotFound("".to_string()));
        }
        let resp_message = resp_message.unwrap();
        let resp_info = resp_message.into();
        return Ok(resp_info);
        //unimplemented!("handle_fallback");
    }

    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response: R,
    ) -> Result<ResponseInfo, Error> {
        // make sure the request is a query
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        let from_ip = request.src().ip();

        // WARN!!!
        // Be careful to handle the request that may be delivered to the DNS-Server again to avoid the dead cycle
        let reqeust_info = request.request_info()?;
        let name = reqeust_info.query.name().to_string();
        let record_type_str = reqeust_info.query.query_type().to_string();
        let record_type = RecordType::from_str(&record_type_str)
            .ok_or_else(|| Error::InvalidRecordType(record_type_str))?;

        info!("|==>DNS query name:{}, record_type:{:?}", name, record_type);

        for provider in self.resolver_chain.iter() {
            let name_info = provider
                .query(name.as_str(), Some(record_type.clone()), Some(from_ip))
                .await;
            if name_info.is_err() {
                trace!("Provider {} can't resolve name:{}", provider.get_id(), name);
                continue;
            }

            let name_info = name_info.unwrap();
            let rdata_vec = nameinfo_to_rdata(record_type.to_string().as_str(), &name_info);
            if rdata_vec.is_err() {
                error!(
                    "Failed to convert nameinfo to rdata:{}",
                    rdata_vec.err().unwrap()
                );
                continue;
            }

            let rdata_vec = rdata_vec.unwrap();
            let mut builder = MessageResponseBuilder::from_message_request(request);
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::NoError);

            let mut ttl = name_info.ttl.unwrap_or(600);
            let records = rdata_vec
                .into_iter()
                .map(|rdata| Record::from_rdata(reqeust_info.query.name().into(), ttl, rdata))
                .collect::<Vec<_>>();
            let mut message = builder.build(header, records.iter(), &[], &[], &[]);
            response.send_response(message).await;
            info!(
                "<==|name:{} {} resolved by provider:{}",
                name,
                record_type.to_string(),
                provider.get_id()
            );
            //let mut response = message.into();
            return Ok(header.into());
        }

        // if let Some(server_name) = self.config.this_name.as_ref() {
        //     if !name.ends_with(server_name.as_str()) {
        // info!(
        //     "All providers can't resolve name:{}, {} enter fallback",
        //     name,
        //     server_name.as_str()
        // );
        // for server_name in self.config.fallback.iter() {
        //     let resp_message = self.handle_fallback(request,server_name,response.clone()).await;
        //     if resp_message.is_ok() {

        //         return resp_info;
        //     }
        // }
        //     }
        // }

        warn!(
            "[{:?}] All providers can't resolve name:{}",
            record_type, name
        );
        return Err(Error::NameNotFound("".to_string()));
    }
}

#[async_trait]
impl RequestHandler for DNSServer {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // try to handle request
        let mut resp2 = response.clone();
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(error) => {
                error!("Error in RequestHandler: {error}");
                let mut builder = MessageResponseBuilder::from_message_request(request);
                let mut header = Header::response_from_request(request.header());
                header.set_response_code(ResponseCode::NXDomain);
                let records = vec![];
                let mut message = builder.build(header, records.iter(), &[], &[], &[]);
                resp2.send_response(message).await;
                header.into()
            }
        }
    }
}

pub async fn start_cyfs_dns_server(config: DNSServerConfig) -> anyhow::Result<DNSServer> {
    let server = DNSServer::new(config).await?;
    server.start().await?;

    Ok(server)
}

/// Trait for handling incoming requests, and providing a message response.
#[async_trait::async_trait]
trait DnsRequestHandler<'q, 'a, Answers, NameServers, Soa, Additionals>: Send + Sync + Unpin + 'static
where
    Answers: Iterator<Item=&'a Record> + Send + 'a,
    NameServers: Iterator<Item=&'a Record> + Send + 'a,
    Soa: Iterator<Item=&'a Record> + Send + 'a,
    Additionals: Iterator<Item=&'a Record> + Send + 'a,
{
    async fn handle_request(
        &self,
        request: &Request,
    ) -> MessageResponse<
        '_,
        'a,
        impl Iterator<Item=&'a Record> + Send + 'a,
        impl Iterator<Item=&'a Record> + Send + 'a,
        impl Iterator<Item=&'a Record> + Send + 'a,
        impl Iterator<Item=&'a Record> + Send + 'a,
    >;
}


pub(crate) struct CyfsQueriesEmitAndCount {
    /// Number of queries in this segment
    length: usize,
    /// Use the first query, if it exists, to pre-populate the string compression cache
    first_query: Option<LowerQuery>,
    /// The cached rendering of the original (wire-format) queries
    cached_serialized: Vec<u8>,
}

impl CyfsQueriesEmitAndCount {
    fn new() -> Self {
        CyfsQueriesEmitAndCount {
            length: 0,
            first_query: None,
            cached_serialized: vec![],
        }
    }
}

impl EmitAndCount for CyfsQueriesEmitAndCount {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> std::result::Result<usize, ProtoError> {
        let original_offset = encoder.offset();
        encoder.emit_vec(self.cached_serialized.as_slice())?;
        if !encoder.is_canonical_names() && self.first_query.is_some() {
            encoder.store_label_pointer(
                original_offset,
                original_offset + self.cached_serialized.len(),
            )
        }
        Ok(self.length)
    }
}


pub struct ProcessChainDnsServer {
    id: String,
    inner_dns_services: InnerServiceManagerRef,
    global_process_chains: Option<GlobalProcessChainsRef>,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
}

impl ProcessChainDnsServer {
    pub async fn create_server(
        id: String,
        inner_dns_services: InnerServiceManagerRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        hook_point: ProcessChainConfigs,
    ) -> ServerResult<Self> {
        let resolve_cmd = Resolve::new(inner_dns_services.clone());
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            global_process_chains.clone(),
            Some(vec![(resolve_cmd.name().to_string(), Arc::new(Box::new(resolve_cmd)))])).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;

        Ok(Self {
            id,
            inner_dns_services,
            global_process_chains,
            executor: Arc::new(Mutex::new(executor)),
        })
    }

    async fn name_info_to_buffer(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        record_type: &str,
        name_info: NameInfo,
    ) -> ServerResult<Vec<u8>> {
        let mut builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);

        let rdata_vec = nameinfo_to_rdata(record_type, &name_info)
            .map_err(|e| server_err!(ServerErrorCode::EncodeError, "{}", e))?;
        let mut ttl = name_info.ttl.unwrap_or(600);
        let records = rdata_vec
            .into_iter()
            .map(|rdata| Record::from_rdata(request_info.query.name().into(), ttl, rdata))
            .collect::<Vec<_>>();
        let mut message = builder.build(header, records.iter(), &[], &[], &[]);


        let mut buffer = Vec::with_capacity(512);
        let encode_result = {
            let mut encoder = BinEncoder::new(&mut buffer);

            let max_size = if let Some(edns) = message.get_edns() {
                edns.max_payload()
            } else {
                // No EDNS, use the recommended max from RFC6891.
                hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
            };
            encoder.set_max_size(max_size);

            message.destructive_emit(&mut encoder)
        }.map_err(into_server_err!(ServerErrorCode::EncodeError));
        Ok(buffer)
    }

    async fn handle_request<'a, >(
        &self,
        request: &Request,
        src_addr: Option<String>,
    ) -> ServerResult<Vec<u8>>
    {
        if request.op_code() != OpCode::Query {
            return Err(server_err!(ServerErrorCode::InvalidDnsOpType, "{}", request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(server_err!(ServerErrorCode::InvalidDnsMessageType, "{}", request.message_type()));
        }

        let from_ip = request.src();

        let reqeust_info = request.request_info().map_err(into_server_err!(ServerErrorCode::BadRequest))?;
        let name = reqeust_info.query.name().to_string();
        let record_type_str = reqeust_info.query.query_type().to_string();

        let map = MemoryMapCollection::new_ref();
        map.insert("name", CollectionValue::String(name)).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert("record_type", CollectionValue::String(record_type_str.clone())).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(from_ip.ip().to_string())).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_port", CollectionValue::String(from_ip.port().to_string())).await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;

        let executor = {
            self.executor.lock().unwrap().fork()
        };
        let chain_env = executor.chain_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Err(server_err!(ServerErrorCode::Rejected));
            } else if ret.is_reject() {
                return Err(server_err!(ServerErrorCode::Rejected));
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                if let Some(list) = shlex::split(ret.value.as_str()) {
                    if list.is_empty() {
                        let resp = chain_env.get("RESP").await.map_err(
                            |e| server_err!(ServerErrorCode::ProcessChainError, "{e}")
                        )?;
                        if let Some(resp) = resp {
                            if let CollectionValue::Map(resp) = resp {
                                let name_info = map_collection_to_nameinfo(&resp).await
                                    .map_err(
                                        |e| server_err!(ServerErrorCode::ProcessChainError, "{e}")
                                    )?;
                                return self.name_info_to_buffer(request, &reqeust_info, record_type_str.as_str(), name_info).await;
                            }
                        }
                    }

                    // let cmd = list[0].as_str();
                    // match cmd {
                    //     "inner_service" => {}
                    // }
                }
            }
        }
        Err(server_err!(ServerErrorCode::ProcessChainError, "invalid process chain result"))
    }

    async fn handle(
        &self,
        message_bytes: &[u8],
        src_addr: Option<String>,
    ) -> ServerResult<Vec<u8>> {
        let mut decoder = BinDecoder::new(message_bytes);

        // Attempt to decode the message
        match MessageRequest::read(&mut decoder) {
            Ok(message) => {
                let addr = if let Some(src_addr) = src_addr.as_ref() {
                    match src_addr.parse::<SocketAddr>() {
                        Ok(src_addr) => {
                            src_addr
                        }
                        Err(_) => {
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                        }
                    }
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                };

                let request = Request::new(message, addr, Protocol::Udp);
                match self.handle_request(&request, src_addr).await {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        let mut builder = MessageResponseBuilder::from_message_request(&request);
                        let mut header = Header::response_from_request(request.header());
                        header.set_response_code(ResponseCode::NXDomain);
                        let mut message = builder.build(header, vec![], &[], &[], &[]);

                        let mut buffer = Vec::with_capacity(512);
                        let encode_result = {
                            let mut encoder = BinEncoder::new(&mut buffer);

                            let max_size = if let Some(edns) = message.get_edns() {
                                edns.max_payload()
                            } else {
                                // No EDNS, use the recommended max from RFC6891.
                                hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
                            };
                            encoder.set_max_size(max_size);

                            message.destructive_emit(&mut encoder)
                        }.map_err(into_server_err!(ServerErrorCode::EncodeError));
                        Ok(buffer)
                    },
                }
            }
            Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
                // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
                let (header, error) = kind
                    .into_form_error()
                    .expect("as form_error already confirmed this is a FormError");

                let mut buffer = Vec::with_capacity(512);
                let mut encoder = BinEncoder::new(&mut buffer);
                message::emit_message_parts(
                    &header,
                    &mut CyfsQueriesEmitAndCount::new(),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    None,
                    &vec![],
                    &mut encoder,
                ).map_err(into_server_err!(ServerErrorCode::EncodeError))?;

                Ok(buffer)
            }
            Err(error) => {
                Err(server_err!(ServerErrorCode::InvalidData, "request:Failed"))
            },
        }
    }
}

#[async_trait::async_trait]
impl cyfs_gateway_lib::server::DatagramServer for ProcessChainDnsServer {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>> {
        if info.src_addr.is_none() {
            return Err(server_err!(ServerErrorCode::InvalidData, "no src_addr"));
        }
        let src_addr: SocketAddr = info.src_addr.as_ref().unwrap().parse()
            .map_err(into_server_err!(ServerErrorCode::InvalidData, "invalid src addr {}", info.src_addr.as_ref().unwrap()))?;
        let response = self.handle(buf, info.src_addr).await?;

        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    async fn update_config(&self, config: Arc<dyn ServerConfig>) -> ServerResult<()> {
        let config = config.as_any().downcast_ref::<DnsServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid config"))?;

        if config.id != self.id {
            return Err(stack_err!(ServerErrorCode::InvalidConfig, "id unmatch"));
        }

        let resolve_cmd = Resolve::new(self.inner_dns_services.clone());
        let (executor, _) = create_process_chain_executor(
            &config.hook_point,
            self.global_process_chains.clone(),
            Some(vec![(resolve_cmd.name().to_string(), Arc::new(Box::new(resolve_cmd)))])).await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        *self.executor.lock().unwrap() = executor;
        Ok(())
    }
}

pub struct ProcessChainDnsServerFactory {
    inner_dns_services: InnerServiceManagerRef,
    global_process_chains: GlobalProcessChainsRef,
}

impl ProcessChainDnsServerFactory {
    pub fn new(
        inner_dns_services: InnerServiceManagerRef,
        global_process_chains: GlobalProcessChainsRef,
    ) -> Self {
        Self {
            inner_dns_services,
            global_process_chains,
        }
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainDnsServerFactory {
    async fn create(&self, config: Arc<dyn ServerConfig>) -> ServerResult<Server> {
        let config = config.as_any().downcast_ref::<DnsServerConfig>()
            .ok_or(server_err!(ServerErrorCode::InvalidConfig, "invalid config"))?;

        let server = ProcessChainDnsServer::create_server(
            config.id.clone(),
            self.inner_dns_services.clone(),
            Some(self.global_process_chains.clone()),
            config.hook_point.clone(),
        ).await?;
        Ok(Server::Datagram(Arc::new(server)))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DnsServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub hook_point: ProcessChainConfigs,

}

impl ServerConfig for DnsServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "dns".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn add_pre_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        config.hook_point.push(process_chain);
        Arc::new(config)
    }

    fn remove_pre_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        let mut config = self.clone();
        config.hook_point.retain(|chain| chain.id != process_chain_id);
        Arc::new(config)
    }

    fn add_post_hook_point_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn ServerConfig> {
        let config = self.clone();
        Arc::new(config)
    }

    fn remove_post_hook_point_process_chain(&self, process_chain_id: &str) -> Arc<dyn ServerConfig> {
        let config = self.clone();
        Arc::new(config)
    }
}
