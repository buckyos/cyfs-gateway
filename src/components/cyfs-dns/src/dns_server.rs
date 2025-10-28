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
        let response = self.handle(buf, info.src_addr).await?;

        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::RecordType;
    use hickory_server::proto::rr::{Name, RData};
    use cyfs_gateway_lib::{ConnectionManager, DatagramInfo, GlobalProcessChains, InnerService, InnerServiceManager, ServerFactory, ServerManager, StackFactory, TunnelManager, UdpStackConfig, UdpStackFactory};
    use cyfs_gateway_lib::server::DatagramServer;
    use crate::{DnsServerConfig, LocalDns, ProcessChainDnsServer, ProcessChainDnsServerFactory};

    #[tokio::test]
    async fn test_process_chain_dns_server_factory() {
        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          return "server www.buckyos.com";
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let config = Arc::new(config);
        let factory = ProcessChainDnsServerFactory::new(
            Arc::new(InnerServiceManager::new()),
            Arc::new(GlobalProcessChains::new()),
        );
        let ret = factory.create(config).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_local_dns() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
A = ["192.168.1.1"]
TXT="THISISATEST"

["*.buckyos.com"]
ttl = 300
A = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
A = ["192.168.1.3"]

["mail.buckyos.com"]
ttl = 300
A = ["192.168.1.106"]
        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let inner_services = Arc::new(InnerServiceManager::new());
        let dns_server = LocalDns::create("local_dns".to_string(), local_dns.path().to_string_lossy().to_string());
        assert!(dns_server.is_ok());
        inner_services.add_service(InnerService::DnsService(Arc::new(dns_server.unwrap())));

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} ttt && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            inner_services.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            config.hook_point,
        ).await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(Some("127.0.0.1:434".to_string()))).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} local_dns && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            inner_services.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            config.hook_point,
        ).await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(resp.answers()[0].data(), &RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::from_str("192.168.1.1").unwrap())));

        let mut message = Message::new();
        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);
        assert_eq!(resp.answers()[0].data(), &RData::TXT(hickory_proto::rr::rdata::txt::TXT::new(vec!["THISISATEST".to_string()])));

        let mut message = Message::new();
        // 添加查询
        let name = Name::from_str("www.buckyos1.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(Some("127.0.0.1:434".to_string()))).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);


        let data = server.serve_datagram(&msg_vec[..1], DatagramInfo::new(None)).await;
        assert!(data.is_err());

        let data = server.serve_datagram(&msg_vec[..msg_vec.len() - 1], DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_query() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
A = ["192.168.1.1"]
TXT="THISISATEST"

["*.buckyos.com"]
ttl = 300
A = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
A = ["192.168.1.3"]

["mail.buckyos.com"]
ttl = 300
A = ["192.168.1.106"]
        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let inner_services = Arc::new(InnerServiceManager::new());
        let dns_server = LocalDns::create("local_dns".to_string(), local_dns.path().to_string_lossy().to_string());
        assert!(dns_server.is_ok());
        inner_services.add_service(InnerService::DnsService(Arc::new(dns_server.unwrap())));

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} local_dns && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let server_factory = ProcessChainDnsServerFactory::new(inner_services.clone(), global_process_chains.clone());
        let ret = server_factory.create(Arc::new(config)).await;
        assert!(ret.is_ok());
        let server = ret.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        server_manager.add_server(server);
        let stack_config = r#"
id: test_dns
bind: 127.0.0.1:9325
protocol: udp
hook_point:
  - id: main
    priority: 1
    blocks:
       - id: default
         block: |
            return "server test";
        "#;

        let stack_config: UdpStackConfig = serde_yaml_ng::from_str(stack_config).unwrap();
        let stack = UdpStackFactory::new(server_manager.clone(),
                                         global_process_chains.clone(),
                                         ConnectionManager::new(),
                                         TunnelManager::new());
        let ret = stack.create(Arc::new(stack_config)).await;
        assert!(ret.is_ok());
        let stack = ret.unwrap();
        stack.start().await;

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} "127.0.0.1:9325" && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            inner_services.clone(),
            Some(Arc::new(GlobalProcessChains::new())),
            config.hook_point,
        ).await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(resp.answers()[0].data(), &RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::from_str("192.168.1.1").unwrap())));


        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos1.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server.serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None)).await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }
}
