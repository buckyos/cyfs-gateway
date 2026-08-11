use std::collections::HashMap;
use std::f32::consts::E;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;
use buckyos_kit::AsyncStream;

use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::authority::{
    Catalog, MessageRequest, MessageResponse, MessageResponseBuilder, Queries,
};
use hickory_server::proto::op::*;
use hickory_server::proto::rr::*;
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use log::trace;
use log::{debug, error, info, warn};
use rdata::{A, AAAA, CNAME, NS, PTR, SOA, TXT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::cmd_resolve::CmdResolve;
use crate::map_collection_to_nameinfo;
use anyhow::Result;
use cyfs_gateway_lib::*;
use cyfs_process_chain::{
    CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor,
};
use futures::stream::{self, StreamExt};
use hickory_proto::op::message::EmitAndCount;
use hickory_proto::serialize::txt::RDataParser;
use hickory_proto::xfer::{Protocol, SerialMessage};
use hickory_proto::{ProtoError, ProtoErrorKind};
use name_client::{DnsProvider, LocalConfigDnsProvider, NameInfo, NsProvider, RecordType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::time::timeout;
use url::Url;

const DNS_TCP_MAX_MESSAGE_SIZE: usize = u16::MAX as usize;
const DNS_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

//TODO: dns_provider is realy a demo implementation, must refactor before  used in a offical server.
fn nameinfo_to_rdata(record_type: &str, name_info: &NameInfo) -> Result<Vec<RData>> {
    match record_type {
        "A" => {
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

            Ok(records)
        }
        "AAAA" => {
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
        "HTTPS" => {
            // Recognize HTTPS/SVCB queries, but treat them as NODATA until
            // explicit HTTPS record support is added.
            return Ok(vec![]);
        }
        "TXT" => {
            let mut records = Vec::new();
            for txt in name_info.txt.iter() {
                records.push(RData::TXT(TXT::new(vec![txt.clone()])));
            }
            return Ok(records);
        }
        "CAA" => {
            let mut records = Vec::new();
            for caa in name_info.caa.iter() {
                let rdata =
                    RData::try_from_str(hickory_server::proto::rr::RecordType::CAA, caa.as_str())
                        .map_err(|e| anyhow::anyhow!("invalid CAA {}: {}", caa, e))?;
                records.push(rdata);
            }
            return Ok(records);
        }
        "PTR" => {
            if name_info.ptr_records.is_empty() {
                return Err(anyhow::anyhow!("PTR is none"));
            }
            let mut records = Vec::new();
            for ptr in name_info.ptr_records.iter() {
                let target = Name::from_str(ptr)
                    .or_else(|_| Name::from_str(format!("{}.", ptr).as_str()))
                    .map_err(|e| anyhow::anyhow!("invalid PTR target {}: {}", ptr, e))?;
                records.push(RData::PTR(PTR(target)));
            }
            return Ok(records);
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown record type:{}", record_type));
        }
    }
}

fn normalize_fqdn(name: &Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

fn authority_name(value: &str) -> ServerResult<Name> {
    Name::from_str(format!("{}.", value.trim_end_matches('.')).as_str()).map_err(|error| {
        server_err!(
            ServerErrorCode::EncodeError,
            "invalid authoritative DNS name {}: {}",
            value,
            error
        )
    })
}

fn zone_ns_record(authority: &DnsAuthority) -> ServerResult<Record> {
    Ok(Record::from_rdata(
        authority_name(authority.zone_apex.as_str())?,
        authority.positive_ttl,
        RData::NS(NS(authority_name(authority.primary_ns.as_str())?)),
    ))
}

fn zone_soa_record(authority: &DnsAuthority, negative: bool) -> ServerResult<Record> {
    let ttl = if negative {
        authority.positive_ttl.min(authority.soa_minimum)
    } else {
        authority.positive_ttl
    };
    Ok(Record::from_rdata(
        authority_name(authority.zone_apex.as_str())?,
        ttl,
        RData::SOA(SOA::new(
            authority_name(authority.primary_ns.as_str())?,
            authority_name(authority.responsible_mailbox.as_str())?,
            authority.soa_serial,
            authority.soa_refresh,
            authority.soa_retry,
            authority.soa_expire,
            authority.soa_minimum,
        )),
    ))
}

/// Trait for handling incoming requests, and providing a message response.
#[async_trait::async_trait]
trait DnsRequestHandler<'q, 'a, Answers, NameServers, Soa, Additionals>:
    Send + Sync + Unpin + 'static
where
    Answers: Iterator<Item = &'a Record> + Send + 'a,
    NameServers: Iterator<Item = &'a Record> + Send + 'a,
    Soa: Iterator<Item = &'a Record> + Send + 'a,
    Additionals: Iterator<Item = &'a Record> + Send + 'a,
{
    async fn handle_request(
        &self,
        request: &Request,
    ) -> MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
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

pub struct InnerDnsRecordManager {
    records: RwLock<HashMap<String, HashMap<String, NameInfo>>>,
}
pub type InnerDnsRecordManagerRef = Arc<InnerDnsRecordManager>;

impl InnerDnsRecordManager {
    pub fn new() -> Arc<Self> {
        Arc::new(InnerDnsRecordManager {
            records: RwLock::new(HashMap::new()),
        })
    }

    pub fn add_record(
        &self,
        name: impl Into<String>,
        record_type: impl Into<String>,
        value: impl Into<String>,
    ) -> ServerResult<()> {
        let name = name.into();
        let record_type = record_type.into();
        let value = value.into();
        let mut records = self.records.write().unwrap();
        match record_type.as_str() {
            "A" | "AAAA" => {
                let ip = IpAddr::from_str(value.as_str()).map_err(into_server_err!(
                    ServerErrorCode::InvalidParam,
                    "invalid ip {}",
                    value
                ))?;
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.address.push(ip);
            }
            "TXT" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.txt.push(value);
            }
            "CAA" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.caa.push(value);
            }
            "CNAME" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.cname = Some(value);
            }
            _ => {
                return Err(ServerError::new(
                    ServerErrorCode::InvalidParam,
                    format!("Invalid record type:{}", record_type),
                ));
            }
        }
        Ok(())
    }

    pub fn remove_record(&self, name: impl Into<String>, record_type: impl Into<String>) {
        let name = name.into();
        let record_type = record_type.into();
        let mut records = self.records.write().unwrap();
        if let Some(record) = records.get_mut(name.as_str()) {
            record.remove(record_type.as_str());
            if record.is_empty() {
                records.remove(name.as_str());
            }
        }
    }

    pub fn get_record(
        &self,
        name: impl Into<String>,
        record_type: impl Into<String>,
    ) -> Option<NameInfo> {
        let name = name.into();
        let record_type = record_type.into();
        let records = self.records.read().unwrap();
        records
            .get(name.as_str())
            .and_then(|record| record.get(record_type.as_str()).cloned())
    }
}

pub struct ProcessChainDnsServer {
    id: String,
    server_mgr: ServerManagerWeakRef,
    global_process_chains: Option<GlobalProcessChainsRef>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    inner_record_manager: InnerDnsRecordManagerRef,
}

impl ProcessChainDnsServer {
    fn response_max_size(request: &Request) -> u16 {
        if request.protocol() == Protocol::Udp {
            request.max_payload()
        } else {
            u16::MAX
        }
    }

    async fn authority_from_collection_value(
        value: &CollectionValue,
    ) -> ServerResult<DnsAuthority> {
        let CollectionValue::Map(map) = value else {
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "RESOLVE_DNS_AUTHORITY is not a map"
            ));
        };

        async fn string_field(
            map: &cyfs_process_chain::MapCollectionRef,
            key: &str,
        ) -> ServerResult<String> {
            map.get(key)
                .await
                .map_err(|error| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "read authority field {} failed: {}",
                        key,
                        error
                    )
                })?
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "authority field {} is missing or not a string",
                        key
                    )
                })
        }

        async fn number_field<T>(
            map: &cyfs_process_chain::MapCollectionRef,
            key: &str,
        ) -> ServerResult<T>
        where
            T: FromStr,
            T::Err: std::fmt::Display,
        {
            let value = string_field(map, key).await?;
            value.parse::<T>().map_err(|error| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "authority field {} is invalid: {}",
                    key,
                    error
                )
            })
        }

        Ok(DnsAuthority {
            zone_apex: string_field(map, "zone_apex").await?,
            primary_ns: string_field(map, "primary_ns").await?,
            responsible_mailbox: string_field(map, "responsible_mailbox").await?,
            soa_serial: number_field(map, "soa_serial").await?,
            soa_refresh: number_field(map, "soa_refresh").await?,
            soa_retry: number_field(map, "soa_retry").await?,
            soa_expire: number_field(map, "soa_expire").await?,
            soa_minimum: number_field(map, "soa_minimum").await?,
            positive_ttl: number_field(map, "positive_ttl").await?,
        })
    }

    async fn command_error_to_server_error(&self, value: &CollectionValue) -> Option<ServerError> {
        let CollectionValue::Map(map) = value else {
            return None;
        };

        let code = map.get("code").await.ok().flatten()?;
        let message = map
            .get("message")
            .await
            .ok()
            .flatten()
            .and_then(|value| value.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let CollectionValue::String(code) = code else {
            return None;
        };

        let server_code = match code.as_str() {
            "NotFound" => ServerErrorCode::NotFound,
            "DnsQueryError" => ServerErrorCode::DnsQueryError,
            "Rejected" => ServerErrorCode::Rejected,
            "InvalidParam" => ServerErrorCode::InvalidParam,
            _ => ServerErrorCode::ProcessChainError,
        };

        Some(ServerError::new(server_code, message))
    }

    pub async fn create_server(
        id: String,
        server_mgr: ServerManagerWeakRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        hook_point: ProcessChainConfigs,
        inner_record_manager: InnerDnsRecordManagerRef,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> ServerResult<Self> {
        let resolve_cmd = CmdResolve::new(server_mgr.clone());
        let mut commands = get_external_commands(server_mgr.clone());
        commands.push((
            resolve_cmd.name().to_string(),
            Arc::new(Box::new(resolve_cmd)),
        ));
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            global_process_chains.clone(),
            global_collection_manager.clone(),
            Some(commands),
            js_externals,
        )
        .await
        .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;

        Ok(Self {
            id,
            server_mgr,
            global_process_chains,
            global_collection_manager,
            executor: Arc::new(Mutex::new(executor)),
            inner_record_manager,
        })
    }

    async fn name_info_to_buffer(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        record_type: &str,
        name_info: NameInfo,
        authority: Option<&DnsAuthority>,
    ) -> ServerResult<Vec<u8>> {
        let rdata_vec = nameinfo_to_rdata(record_type, &name_info)
            .map_err(|e| server_err!(ServerErrorCode::EncodeError, "{}", e))?;
        let ttl = name_info.ttl.unwrap_or(600);
        let records = rdata_vec
            .into_iter()
            .map(|rdata| Record::from_rdata(request_info.query.name().into(), ttl, rdata))
            .collect::<Vec<_>>();
        if let Some(authority) = authority {
            if records.is_empty() {
                return self.authoritative_negative_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    authority,
                );
            }
            return self.records_response_to_buffer(
                request,
                ResponseCode::NoError,
                true,
                records,
                vec![],
                vec![],
            );
        }
        self.records_response_to_buffer(
            request,
            ResponseCode::NoError,
            false,
            records,
            vec![],
            vec![],
        )
    }

    fn records_response_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
        authoritative: bool,
        answers: Vec<Record>,
        name_servers: Vec<Record>,
        soa: Vec<Record>,
    ) -> ServerResult<Vec<u8>> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(response_code);
        header.set_authoritative(authoritative);
        let mut message =
            builder.build(header, answers.iter(), name_servers.iter(), soa.iter(), &[]);

        let mut buffer = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buffer);

            encoder.set_max_size(Self::response_max_size(request));

            message
                .destructive_emit(&mut encoder)
                .map_err(into_server_err!(ServerErrorCode::EncodeError))?;
        }

        Ok(buffer)
    }

    fn response_code_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
    ) -> ServerResult<Vec<u8>> {
        self.records_response_to_buffer(request, response_code, false, vec![], vec![], vec![])
    }

    fn authoritative_zone_response_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
        answers: Vec<Record>,
        authority_soa: Vec<Record>,
    ) -> ServerResult<Vec<u8>> {
        self.records_response_to_buffer(
            request,
            response_code,
            true,
            answers,
            vec![],
            authority_soa,
        )
    }

    fn authoritative_negative_response_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
        authority: &DnsAuthority,
    ) -> ServerResult<Vec<u8>> {
        self.authoritative_zone_response_to_buffer(
            request,
            response_code,
            vec![],
            vec![zone_soa_record(authority, true)?],
        )
    }

    fn authoritative_special_response(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        authority: &DnsAuthority,
    ) -> Option<ServerResult<Vec<u8>>> {
        let query_name = request_info.query.name();
        let query_type = request_info.query.query_type();
        let query_name_str = normalize_fqdn(query_name);
        let is_zone_apex = query_name_str == authority.zone_apex;

        match query_type {
            hickory_server::proto::rr::RecordType::NS if is_zone_apex => {
                Some(zone_ns_record(authority).and_then(|record| {
                    self.authoritative_zone_response_to_buffer(
                        request,
                        ResponseCode::NoError,
                        vec![record],
                        vec![],
                    )
                }))
            }
            hickory_server::proto::rr::RecordType::SOA if is_zone_apex => {
                Some(zone_soa_record(authority, false).and_then(|record| {
                    self.authoritative_zone_response_to_buffer(
                        request,
                        ResponseCode::NoError,
                        vec![record],
                        vec![],
                    )
                }))
            }
            hickory_server::proto::rr::RecordType::NS
            | hickory_server::proto::rr::RecordType::SOA => {
                Some(self.authoritative_negative_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    authority,
                ))
            }
            _ => None,
        }
    }

    async fn handle_request<'a>(
        &self,
        request: &Request,
        dst_addr: Option<String>,
    ) -> ServerResult<Vec<u8>> {
        if request.op_code() != OpCode::Query {
            return Err(server_err!(
                ServerErrorCode::InvalidDnsOpType,
                "{}",
                request.op_code()
            ));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(server_err!(
                ServerErrorCode::InvalidDnsMessageType,
                "{}",
                request.message_type()
            ));
        }

        let from_ip = request.src();

        let reqeust_info = request
            .request_info()
            .map_err(into_server_err!(ServerErrorCode::BadRequest))?;
        let name = reqeust_info.query.name().to_string();
        let record_type_str = reqeust_info.query.query_type().to_string();

        // First, check if the record exists in the inner record manager
        if let Some(name_info) = self
            .inner_record_manager
            .get_record(&name, &record_type_str)
        {
            debug!(
                "dns query resolved by provider=inner_record_manager: name={} type={}",
                name, record_type_str
            );
            return self
                .name_info_to_buffer(
                    request,
                    &reqeust_info,
                    record_type_str.as_str(),
                    name_info,
                    None,
                )
                .await;
        }

        let map = MemoryMapCollection::new_ref();
        map.insert("name", CollectionValue::String(name.clone()))
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "record_type",
            CollectionValue::String(record_type_str.clone()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert("source_addr", CollectionValue::String(from_ip.to_string()))
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_ip",
            CollectionValue::String(from_ip.ip().to_string()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_port",
            CollectionValue::String(from_ip.port().to_string()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        if let Some(dst_addr) = dst_addr {
            if let Ok(socket_addr) = dst_addr.parse::<SocketAddr>() {
                map.insert(
                    "dest_addr",
                    CollectionValue::String(socket_addr.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                map.insert(
                    "dest_ip",
                    CollectionValue::String(socket_addr.ip().to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                map.insert(
                    "dest_port",
                    CollectionValue::String(socket_addr.port().to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
            }
        }

        let executor = { self.executor.lock().unwrap().fork() };
        let chain_env = executor.chain_env().clone();
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        if ret.is_error() {
            if let Some(err) = self.command_error_to_server_error(ret.value_ref()).await {
                return Err(err);
            }
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "{}",
                ret.value()
            ));
        }

        let structured_status = chain_env
            .get("RESOLVE_DNS_STATUS")
            .await
            .map_err(|error| server_err!(ServerErrorCode::ProcessChainError, "{error}"))?
            .and_then(|value| value.as_str().map(ToOwned::to_owned));
        let structured_authority = if matches!(
            structured_status.as_deref(),
            Some("authoritative_answer" | "authoritative_nodata" | "authoritative_nxdomain")
        ) {
            let value = chain_env
                .get("RESOLVE_DNS_AUTHORITY")
                .await
                .map_err(|error| server_err!(ServerErrorCode::ProcessChainError, "{error}"))?
                .ok_or_else(|| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "structured authoritative DNS result has no authority metadata"
                    )
                })?;
            Some(Self::authority_from_collection_value(&value).await?)
        } else {
            None
        };

        match structured_status.as_deref() {
            Some("temporary_failure") => {
                return self.response_code_to_buffer(request, ResponseCode::ServFail);
            }
            Some("authoritative_nxdomain") => {
                return self.authoritative_negative_response_to_buffer(
                    request,
                    ResponseCode::NXDomain,
                    structured_authority
                        .as_ref()
                        .expect("authority parsed above"),
                );
            }
            Some("authoritative_nodata") => {
                let authority = structured_authority
                    .as_ref()
                    .expect("authority parsed above");
                if let Some(response) =
                    self.authoritative_special_response(request, &reqeust_info, authority)
                {
                    return response;
                }
                return self.authoritative_negative_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    authority,
                );
            }
            Some("authoritative_answer") => {
                let authority = structured_authority
                    .as_ref()
                    .expect("authority parsed above");
                if let Some(response) =
                    self.authoritative_special_response(request, &reqeust_info, authority)
                {
                    return response;
                }
            }
            Some(other) => {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "unknown structured DNS result status {}",
                    other
                ));
            }
            None => {}
        }
        if ret.is_control() {
            if ret.is_drop() {
                return Err(server_err!(ServerErrorCode::Rejected));
            } else if ret.is_reject() {
                return Err(server_err!(ServerErrorCode::Rejected));
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    return Err(server_err!(
                        ServerErrorCode::ProcessChainError,
                        "invalid process chain result"
                    ));
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        let resp = chain_env
                            .get("RESOLVE_RESP")
                            .await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                        if let Some(resp) = resp {
                            if let CollectionValue::Map(resp) = resp {
                                let provider_name = chain_env
                                    .get("RESOLVE_PROVIDER")
                                    .await
                                    .ok()
                                    .flatten()
                                    .and_then(|value| value.as_str().map(|s| s.to_string()))
                                    .unwrap_or_else(|| "process_chain".to_string());
                                let name_info =
                                    map_collection_to_nameinfo(&resp).await.map_err(|e| {
                                        server_err!(ServerErrorCode::ProcessChainError, "{e}")
                                    })?;
                                debug!(
                                    "dns query resolved by provider={}: name={} type={}",
                                    provider_name, name, record_type_str
                                );
                                return self
                                    .name_info_to_buffer(
                                        request,
                                        &reqeust_info,
                                        record_type_str.as_str(),
                                        name_info,
                                        structured_authority.as_ref(),
                                    )
                                    .await;
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
        Err(server_err!(
            ServerErrorCode::ProcessChainError,
            "invalid process chain result"
        ))
    }

    async fn handle(
        &self,
        message_bytes: &[u8],
        src_addr: Option<String>,
        dst_addr: Option<String>,
        protocol: Protocol,
    ) -> ServerResult<Vec<u8>> {
        let mut decoder = BinDecoder::new(message_bytes);

        // Attempt to decode the message
        match MessageRequest::read(&mut decoder) {
            Ok(message) => {
                let addr = if let Some(src_addr) = src_addr.as_ref() {
                    match src_addr.parse::<SocketAddr>() {
                        Ok(src_addr) => src_addr,
                        Err(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    }
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                };

                let request = Request::new(message, addr, protocol);
                let request_info = request
                    .request_info()
                    .map_err(into_server_err!(ServerErrorCode::BadRequest))?;
                let query_name = request_info.query.name().to_string();
                let query_type = request_info.query.query_type().to_string();
                match self.handle_request(&request, dst_addr.clone()).await {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        let response_code = match e.code() {
                            ServerErrorCode::NotFound => ResponseCode::NXDomain,
                            ServerErrorCode::Rejected => ResponseCode::Refused,
                            _ => ResponseCode::ServFail,
                        };
                        warn!(
                            "dns query failed: name={} type={} src={} response_code={:?} err={}",
                            query_name, query_type, addr, response_code, e
                        );
                        self.response_code_to_buffer(&request, response_code)
                    }
                }
            }
            Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
                // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
                let (header, error) = kind
                    .into_form_error()
                    .expect("as form_error already confirmed this is a FormError");

                let mut buffer = Vec::with_capacity(512);
                let mut encoder = BinEncoder::new(&mut buffer);
                encoder.set_max_size(if protocol == Protocol::Udp {
                    512
                } else {
                    u16::MAX
                });
                message::emit_message_parts(
                    &header,
                    &mut CyfsQueriesEmitAndCount::new(),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    None,
                    &vec![],
                    &mut encoder,
                )
                .map_err(into_server_err!(ServerErrorCode::EncodeError))?;

                Ok(buffer)
            }
            Err(error) => Err(server_err!(ServerErrorCode::InvalidData, "request:Failed")),
        }
    }
}

#[async_trait::async_trait]
impl cyfs_gateway_lib::server::DatagramServer for ProcessChainDnsServer {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>> {
        let response = self
            .handle(buf, info.src_addr, info.dst_addr, Protocol::Udp)
            .await?;

        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

#[async_trait::async_trait]
impl cyfs_gateway_lib::server::StreamServer for ProcessChainDnsServer {
    async fn serve_connection(
        &self,
        mut stream: Box<dyn AsyncStream>,
        info: StreamInfo,
    ) -> ServerResult<()> {
        let src_addr = info.src_addr.or(info.conn_src_addr);
        let dst_addr = info.dst_addr;
        let connection = format!(
            "{} -> {}",
            src_addr.as_deref().unwrap_or("unknown"),
            dst_addr.as_deref().unwrap_or("unknown")
        );

        loop {
            let mut length_bytes = [0u8; 2];
            match timeout(DNS_TCP_IDLE_TIMEOUT, stream.read(&mut length_bytes[..1])).await {
                Ok(Ok(0)) => {
                    debug!("dns tcp connection closed cleanly: {}", connection);
                    return Ok(());
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    return Err(server_err!(
                        ServerErrorCode::IOError,
                        "read dns tcp frame length from {} failed: {}",
                        connection,
                        err
                    ));
                }
                Err(_) => {
                    debug!(
                        "dns tcp connection idle for {:?}, closing: {}",
                        DNS_TCP_IDLE_TIMEOUT, connection
                    );
                    return Ok(());
                }
            }

            match timeout(
                DNS_TCP_IDLE_TIMEOUT,
                stream.read_exact(&mut length_bytes[1..]),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    warn!("incomplete dns tcp frame length from {}", connection);
                    return Ok(());
                }
                Ok(Err(err)) => {
                    return Err(server_err!(
                        ServerErrorCode::IOError,
                        "read dns tcp frame length from {} failed: {}",
                        connection,
                        err
                    ));
                }
                Err(_) => {
                    warn!("dns tcp frame length timed out from {}", connection);
                    return Ok(());
                }
            }

            let message_len = u16::from_be_bytes(length_bytes) as usize;
            if message_len == 0 {
                warn!("rejecting zero-length dns tcp frame from {}", connection);
                return Ok(());
            }
            if message_len > DNS_TCP_MAX_MESSAGE_SIZE {
                warn!(
                    "rejecting oversized dns tcp frame from {}: {} bytes",
                    connection, message_len
                );
                return Ok(());
            }

            let mut message = vec![0u8; message_len];
            match timeout(DNS_TCP_IDLE_TIMEOUT, stream.read_exact(&mut message)).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    warn!(
                        "incomplete dns tcp frame from {}: expected {} bytes",
                        connection, message_len
                    );
                    return Ok(());
                }
                Ok(Err(err)) => {
                    return Err(server_err!(
                        ServerErrorCode::IOError,
                        "read dns tcp frame from {} failed: {}",
                        connection,
                        err
                    ));
                }
                Err(_) => {
                    warn!(
                        "dns tcp frame body timed out from {}: expected {} bytes",
                        connection, message_len
                    );
                    return Ok(());
                }
            }

            let response = match self
                .handle(
                    message.as_slice(),
                    src_addr.clone(),
                    dst_addr.clone(),
                    Protocol::Tcp,
                )
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    warn!(
                        "dns tcp request handling failed for {}: {}",
                        connection, err
                    );
                    return Err(err);
                }
            };
            let response_len = u16::try_from(response.len()).map_err(|_| {
                server_err!(
                    ServerErrorCode::EncodeError,
                    "dns tcp response for {} exceeds {} bytes",
                    connection,
                    DNS_TCP_MAX_MESSAGE_SIZE
                )
            })?;

            let write_result = timeout(DNS_TCP_IDLE_TIMEOUT, async {
                stream.write_all(&response_len.to_be_bytes()).await?;
                stream.write_all(response.as_slice()).await?;
                stream.flush().await
            })
            .await;
            match write_result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(server_err!(
                        ServerErrorCode::IOError,
                        "write dns tcp response to {} failed: {}",
                        connection,
                        err
                    ));
                }
                Err(_) => {
                    warn!("dns tcp response write timed out for {}", connection);
                    return Ok(());
                }
            }
        }
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

pub struct ProcessChainDnsServerFactory;

#[derive(Clone)]
pub struct DnsServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub inner_record_manager: InnerDnsRecordManagerRef,
}

impl DnsServerContext {
    pub fn new(
        server_mgr: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        global_collection_manager: GlobalCollectionManagerRef,
        inner_record_manager: InnerDnsRecordManagerRef,
    ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            js_externals,
            global_collection_manager,
            inner_record_manager,
        }
    }
}

impl ServerContext for DnsServerContext {
    fn get_server_type(&self) -> String {
        "dns".to_string()
    }
}

impl ProcessChainDnsServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainDnsServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<DnsServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid dns server config"
            ))?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "dns server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<DnsServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid dns server context"
            ))?;

        let server = Arc::new(
            ProcessChainDnsServer::create_server(
                config.id.clone(),
                context.server_mgr.clone(),
                Some(context.global_process_chains.clone()),
                Some(context.global_collection_manager.clone()),
                config.hook_point.clone(),
                context.inner_record_manager.clone(),
                Some(context.js_externals.clone()),
            )
            .await?,
        );
        Ok(vec![
            Server::Datagram(server.clone()),
            Server::Stream(server),
        ])
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
}

#[cfg(test)]
mod tests {
    use super::nameinfo_to_rdata;
    use crate::{
        DnsServerConfig, DnsServerContext, InnerDnsRecordManager, LocalDns, ProcessChainDnsServer,
        ProcessChainDnsServerFactory,
    };
    use async_trait::async_trait;
    use cyfs_gateway_lib::server::DatagramServer;
    use cyfs_gateway_lib::{
        ConnectionManager, DatagramInfo, DefaultLimiterManager, DnsAuthority, DnsQueryResult,
        GlobalCollectionManager, GlobalProcessChains, JsExternalsManager, NameServer, Server,
        ServerErrorCode, ServerFactory, ServerManager, ServerResult, StackContext, StackFactory,
        StatManager, TunnelManager, UdpStackConfig, UdpStackContext, UdpStackFactory,
    };
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::RecordType;
    use hickory_server::proto::rr::{Name, RData};
    use name_client::NameInfo;
    use name_lib::{EncodedDocument, DID};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;

    const EXISTING_WEB3_NAME: &str = "wugren2026.web3.buckyos.ai";
    const WEB3_ZONE: &str = "web3.buckyos.ai";
    const USER_ZONE: &str = "example.test";
    const EXISTING_USER_NAME: &str = "www.example.test";

    struct EmptyAaaaNameServer;

    fn test_authority(zone_apex: &str) -> DnsAuthority {
        DnsAuthority {
            zone_apex: zone_apex.to_string(),
            primary_ns: "dns.buckyos.ai".to_string(),
            responsible_mailbox: "hostmaster.buckyos.ai".to_string(),
            soa_serial: 42,
            soa_refresh: 300,
            soa_retry: 60,
            soa_expire: 86_400,
            soa_minimum: 60,
            positive_ttl: 300,
        }
    }

    fn test_zone_for_name(name: &str) -> Option<&'static str> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        [WEB3_ZONE, USER_ZONE]
            .into_iter()
            .filter(|zone| name == *zone || name.ends_with(format!(".{}", zone).as_str()))
            .max_by_key(|zone| zone.len())
    }

    #[async_trait]
    impl NameServer for EmptyAaaaNameServer {
        fn id(&self) -> String {
            "empty_aaaa".to_string()
        }

        async fn query_dns(
            &self,
            name: &str,
            record_type: &str,
            _from_ip: Option<IpAddr>,
        ) -> ServerResult<DnsQueryResult> {
            let normalized = name.trim_end_matches('.').to_ascii_lowercase();
            let Some(zone_apex) = test_zone_for_name(normalized.as_str()) else {
                let record_type =
                    name_client::RecordType::from_str(record_type).ok_or_else(|| {
                        cyfs_gateway_lib::server_err!(
                            ServerErrorCode::InvalidParam,
                            "unsupported record type {}",
                            record_type
                        )
                    })?;
                return self
                    .query(name, Some(record_type), None)
                    .await
                    .map(DnsQueryResult::non_authoritative_answer);
            };
            let authority = test_authority(zone_apex);
            if normalized == "backend.web3.buckyos.ai" {
                return Ok(DnsQueryResult::TemporaryFailure {
                    cause: "test backend unavailable".to_string(),
                });
            }
            let name_exists = normalized == zone_apex
                || normalized == EXISTING_WEB3_NAME
                || normalized == EXISTING_USER_NAME
                || normalized == "txt-only.web3.buckyos.ai";
            if !name_exists {
                return Ok(DnsQueryResult::AuthoritativeNxDomain { authority });
            }
            let record_type = record_type.to_ascii_uppercase();
            if normalized == zone_apex || !matches!(record_type.as_str(), "A" | "AAAA" | "TXT") {
                return Ok(DnsQueryResult::AuthoritativeNoData { authority });
            }
            if normalized == "txt-only.web3.buckyos.ai" && record_type != "TXT" {
                return Ok(DnsQueryResult::AuthoritativeNoData { authority });
            }

            let mut name_info = NameInfo::new(name);
            name_info.ttl = Some(300);
            match record_type.as_str() {
                "A" => name_info
                    .address
                    .push(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                "AAAA" => name_info
                    .address
                    .push(IpAddr::V6(Ipv6Addr::from_str("2001:db8::10").unwrap())),
                "TXT" => name_info.txt.push("authoritative-test".to_string()),
                _ => unreachable!(),
            }
            Ok(DnsQueryResult::Answer {
                name_info,
                authority: Some(authority),
            })
        }

        async fn query(
            &self,
            name: &str,
            record_type: Option<name_client::RecordType>,
            _from_ip: Option<IpAddr>,
        ) -> ServerResult<NameInfo> {
            match record_type.unwrap_or_default() {
                name_client::RecordType::A
                    if name
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(EXISTING_WEB3_NAME) =>
                {
                    Ok(NameInfo::from_address(
                        name,
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    ))
                }
                name_client::RecordType::A => Err(cyfs_gateway_lib::server_err!(
                    ServerErrorCode::NotFound,
                    "name not found"
                )),
                name_client::RecordType::AAAA => Ok(NameInfo::from_address_vec(name, vec![])),
                name_client::RecordType::CAA => Err(cyfs_gateway_lib::server_err!(
                    ServerErrorCode::InvalidParam,
                    "unsupported record type CAA"
                )),
                _ => Err(cyfs_gateway_lib::server_err!(
                    ServerErrorCode::NotFound,
                    "record type not found"
                )),
            }
        }

        async fn query_did(
            &self,
            _did: &DID,
            _fragment: Option<&str>,
            _from_ip: Option<IpAddr>,
        ) -> ServerResult<EncodedDocument> {
            Err(cyfs_gateway_lib::server_err!(
                ServerErrorCode::NotFound,
                "did not found"
            ))
        }
    }

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
        let server_mgr = Arc::new(ServerManager::new());
        let context = DnsServerContext::new(
            Arc::downgrade(&server_mgr),
            Arc::new(GlobalProcessChains::new()),
            Arc::new(JsExternalsManager::new()),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
            InnerDnsRecordManager::new(),
        );
        let factory = ProcessChainDnsServerFactory::new();
        let ret = factory.create(config, Some(Arc::new(context))).await;
        assert!(ret.is_ok());
        let servers = ret.unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers
            .iter()
            .any(|server| matches!(server, Server::Datagram(_))));
        assert!(servers
            .iter()
            .any(|server| matches!(server, Server::Stream(_))));
    }

    async fn create_authoritative_test_server() -> (ProcessChainDnsServer, Arc<ServerManager>) {
        let server_mgr = Arc::new(ServerManager::new());
        server_mgr
            .add_server(Server::NameServer(Arc::new(EmptyAaaaNameServer)))
            .unwrap();
        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          call resolve ${REQ.name} ${REQ.record_type} empty_aaaa && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap();
        (server, server_mgr)
    }

    async fn create_authoritative_notfound_test_server(
    ) -> (ProcessChainDnsServer, Arc<ServerManager>) {
        let server_mgr = Arc::new(ServerManager::new());
        server_mgr
            .add_server(Server::NameServer(Arc::new(EmptyAaaaNameServer)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          call resolve ${REQ.name} ${REQ.record_type} empty_aaaa && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap();
        (server, server_mgr)
    }

    async fn query_wire(
        server: &ProcessChainDnsServer,
        name: &str,
        record_type: RecordType,
        protocol: hickory_proto::xfer::Protocol,
    ) -> Message {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut message = Message::new();
        message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
        let data = server
            .handle(
                message.to_vec().unwrap().as_slice(),
                Some("127.0.0.1:53000".to_string()),
                None,
                protocol,
            )
            .await
            .unwrap();
        Message::from_vec(data.as_slice()).unwrap()
    }

    #[tokio::test]
    async fn test_authoritative_positive_answers_set_aa_for_web3_and_user_domain() {
        let (server, _server_mgr) = create_authoritative_test_server().await;
        for name in [EXISTING_WEB3_NAME, EXISTING_USER_NAME] {
            for record_type in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
                let response = query_wire(
                    &server,
                    format!("{}.", name).as_str(),
                    record_type,
                    hickory_proto::xfer::Protocol::Udp,
                )
                .await;
                assert_eq!(response.response_code(), ResponseCode::NoError);
                assert!(response.header().authoritative(), "{name} {record_type}");
                assert!(!response.answers().is_empty(), "{name} {record_type}");
                assert!(response.name_servers().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn test_authoritative_negative_matrix_and_user_zone_soa_owner() {
        let (server, _server_mgr) = create_authoritative_test_server().await;
        for record_type in [
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::CAA,
            RecordType::MX,
        ] {
            let response = query_wire(
                &server,
                "txt-only.web3.buckyos.ai.",
                record_type,
                hickory_proto::xfer::Protocol::Udp,
            )
            .await;
            assert_eq!(response.response_code(), ResponseCode::NoError);
            assert!(response.header().authoritative());
            assert!(response.answers().is_empty());
            assert_eq!(response.name_servers().len(), 1);
            assert_eq!(
                response.name_servers()[0].name().to_string(),
                "web3.buckyos.ai."
            );
        }

        let user_nodata = query_wire(
            &server,
            "www.example.test.",
            RecordType::MX,
            hickory_proto::xfer::Protocol::Udp,
        )
        .await;
        assert_eq!(user_nodata.response_code(), ResponseCode::NoError);
        assert!(user_nodata.header().authoritative());
        assert_eq!(
            user_nodata.name_servers()[0].name().to_string(),
            "example.test."
        );

        let user_nxdomain = query_wire(
            &server,
            "_missing.example.test.",
            RecordType::A,
            hickory_proto::xfer::Protocol::Udp,
        )
        .await;
        assert_eq!(user_nxdomain.response_code(), ResponseCode::NXDomain);
        assert!(user_nxdomain.header().authoritative());
        assert_eq!(
            user_nxdomain.name_servers()[0].name().to_string(),
            "example.test."
        );
    }

    #[tokio::test]
    async fn test_nonconfigured_web3_shapes_are_never_authoritative() {
        let (server, _server_mgr) = create_authoritative_test_server().await;
        for name in [
            "alice.web3.example.net.",
            "web3.example.net.",
            "foo.web3.evil.test.",
        ] {
            let response = query_wire(
                &server,
                name,
                RecordType::A,
                hickory_proto::xfer::Protocol::Udp,
            )
            .await;
            assert!(!response.header().authoritative(), "{name}");
            assert!(response.name_servers().is_empty(), "{name}");
        }
    }

    #[tokio::test]
    async fn test_authoritative_backend_failure_is_servfail() {
        let (server, _server_mgr) = create_authoritative_test_server().await;
        let response = query_wire(
            &server,
            "backend.web3.buckyos.ai.",
            RecordType::A,
            hickory_proto::xfer::Protocol::Udp,
        )
        .await;
        assert_eq!(response.response_code(), ResponseCode::ServFail);
        assert!(response.answers().is_empty());
        assert!(response.name_servers().is_empty());
    }

    #[tokio::test]
    async fn test_authoritative_udp_tcp_have_identical_dns_semantics() {
        let (server, _server_mgr) = create_authoritative_test_server().await;
        for (name, record_type) in [
            (EXISTING_WEB3_NAME, RecordType::A),
            (EXISTING_USER_NAME, RecordType::MX),
            ("missing.web3.buckyos.ai", RecordType::CAA),
            ("backend.web3.buckyos.ai", RecordType::A),
        ] {
            let fqdn = format!("{}.", name);
            let udp = query_wire(
                &server,
                fqdn.as_str(),
                record_type,
                hickory_proto::xfer::Protocol::Udp,
            )
            .await;
            let tcp = query_wire(
                &server,
                fqdn.as_str(),
                record_type,
                hickory_proto::xfer::Protocol::Tcp,
            )
            .await;
            assert_eq!(udp.response_code(), tcp.response_code(), "{name}");
            assert_eq!(
                udp.header().authoritative(),
                tcp.header().authoritative(),
                "{name}"
            );
            assert_eq!(udp.answers(), tcp.answers(), "{name}");
            assert_eq!(udp.name_servers(), tcp.name_servers(), "{name}");
        }
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_ns_query_returns_answer() {
        let (server, _server_mgr) = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::NS);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::NS);
        match resp.answers()[0].data() {
            RData::NS(ns) => assert_eq!(ns.0.to_string(), "dns.buckyos.ai."),
            _ => panic!("expected NS answer"),
        }
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_soa_query_returns_answer() {
        let (server, _server_mgr) = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::SOA);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::SOA);
        match resp.answers()[0].data() {
            RData::SOA(soa) => {
                assert_eq!(soa.mname().to_string(), "dns.buckyos.ai.");
                assert_eq!(soa.rname().to_string(), "hostmaster.buckyos.ai.");
                assert_eq!(soa.serial(), 42);
            }
            _ => panic!("expected SOA answer"),
        }
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_subdomain_ns_query_returns_nodata_with_soa() {
        let (server, _server_mgr) = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str(format!("{}.", EXISTING_WEB3_NAME).as_str()).unwrap();
        let query = Query::query(name, RecordType::NS);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_apex_missing_record_returns_nodata_with_soa() {
        let (server, _server_mgr) = create_authoritative_notfound_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::MX);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_subdomain_unsupported_caa_returns_nodata() {
        let (server, _server_mgr) = create_authoritative_notfound_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("wugren2026.web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_nonexistent_subdomain_caa_returns_nxdomain() {
        let (server, _server_mgr) = create_authoritative_notfound_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("missing.web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn test_nameinfo_to_rdata_caa_variants() {
        let mut name_info = NameInfo::new("web3.buckyos.ai");
        name_info.caa = vec![
            "0 issue \"letsencrypt.org\"".to_string(),
            "0 iodef \"mailto:ops@buckyos.ai\"".to_string(),
        ];

        let rdata = nameinfo_to_rdata("CAA", &name_info).unwrap();
        assert_eq!(rdata.len(), 2);
        assert!(matches!(rdata[0], RData::CAA(_)));
        assert!(matches!(rdata[1], RData::CAA(_)));

        let empty = nameinfo_to_rdata("CAA", &NameInfo::new("web3.buckyos.ai")).unwrap();
        assert!(empty.is_empty());

        let mut invalid = NameInfo::new("web3.buckyos.ai");
        invalid.caa = vec!["not-a-valid-caa".to_string()];
        assert!(nameinfo_to_rdata("CAA", &invalid).is_err());
    }

    #[test]
    fn test_nameinfo_to_rdata_https_is_empty_success() {
        let rdata = nameinfo_to_rdata("HTTPS", &NameInfo::new("web3.buckyos.ai")).unwrap();
        assert!(rdata.is_empty());
    }

    #[test]
    fn test_inner_dns_record_manager_caa_records() {
        let manager = InnerDnsRecordManager::new();
        manager
            .add_record("web3.buckyos.ai", "CAA", "0 issue \"letsencrypt.org\"")
            .unwrap();
        manager
            .add_record(
                "web3.buckyos.ai",
                "CAA",
                "0 iodef \"mailto:ops@buckyos.ai\"",
            )
            .unwrap();

        let name_info = manager.get_record("web3.buckyos.ai", "CAA").unwrap();
        assert_eq!(name_info.caa.len(), 2);
        assert!(name_info
            .caa
            .contains(&"0 issue \"letsencrypt.org\"".to_string()));

        manager.remove_record("web3.buckyos.ai", "CAA");
        assert!(manager.get_record("web3.buckyos.ai", "CAA").is_none());
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_local_dns() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
address = ["192.168.1.1"]
txt = [
"BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;",
"PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;",
"DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;"
]
caa = ["0 issue \"letsencrypt.org\""]

["_acme-challenge.web3.buckyos.com"]
ttl = 300
txt = ["challenge-token"]

["*.buckyos.com"]
ttl = 300
address = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
address = ["192.168.1.3"]


["mail.buckyos.com"]
ttl = 300
address = ["2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa"]

        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let server_mgr = Arc::new(ServerManager::new());
        let dns_server = LocalDns::create(
            "local_dns".to_string(),
            local_dns.path().to_string_lossy().to_string(),
        );
        assert!(dns_server.is_ok());
        let dns_server = dns_server.unwrap();

        server_mgr
            .add_server(Server::NameServer(Arc::new(dns_server)))
            .unwrap();

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
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
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

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::ServFail);

        let data = server
            .serve_datagram(
                msg_vec.as_slice(),
                DatagramInfo::new(Some("127.0.0.1:434".to_string())),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::ServFail);

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
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
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

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(
            resp.answers()[0].data(),
            &RData::A(hickory_proto::rr::rdata::A(
                Ipv4Addr::from_str("192.168.1.1").unwrap()
            ))
        );

        let mut message = Message::new();
        let name = Name::from_str("1.1.168.192.in-addr.arpa.").unwrap();
        let query = Query::query(name, RecordType::PTR);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::PTR);
        match resp.answers()[0].data() {
            RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "www.buckyos.com."),
            _ => panic!("expected PTR answer"),
        }

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

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 3);
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);

        let mut message = Message::new();
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::CAA);
        match resp.answers()[0].data() {
            RData::CAA(caa) => assert_eq!(caa.to_string(), "0 issue \"letsencrypt.org\""),
            _ => panic!("expected CAA answer"),
        }

        let mut message = Message::new();
        let name = Name::from_str("mail.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);

        let mut message = Message::new();
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::HTTPS);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);

        let mut message = Message::new();
        let name = Name::from_str("_acme-challenge.web3.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);

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

        let data = server
            .serve_datagram(
                msg_vec.as_slice(),
                DatagramInfo::new(Some("127.0.0.1:434".to_string())),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);

        let data = server
            .serve_datagram(&msg_vec[..1], DatagramInfo::new(None))
            .await;
        assert!(data.is_err());

        let data = server
            .serve_datagram(&msg_vec[..msg_vec.len() - 1], DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_empty_aaaa_returns_noerror() {
        let server_mgr = Arc::new(ServerManager::new());
        server_mgr
            .add_server(Server::NameServer(Arc::new(EmptyAaaaNameServer)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} empty_aaaa && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap();

        let mut message = Message::new();
        let name = Name::from_str("sn.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::AAAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(Some("127.0.0.1:5353".to_string())),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_query() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
address = ["192.168.1.1"]
txt = [
"THISISATEST",
"BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;",
"PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;",
"DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;"
]

["*.buckyos.com"]
ttl = 300
address = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
address = ["192.168.1.3"]


["mail.buckyos.com"]
ttl = 300
address = ["2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa"]

        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let server_mgr = Arc::new(ServerManager::new());
        let dns_server = LocalDns::create(
            "local_dns".to_string(),
            local_dns.path().to_string_lossy().to_string(),
        );
        assert!(dns_server.is_ok());
        let dns_server = dns_server.unwrap();

        server_mgr
            .add_server(Server::NameServer(Arc::new(dns_server)))
            .unwrap();

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
        let context = DnsServerContext::new(
            Arc::downgrade(&server_mgr),
            global_process_chains.clone(),
            Arc::new(JsExternalsManager::new()),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
            InnerDnsRecordManager::new(),
        );
        let server_factory = ProcessChainDnsServerFactory::new();
        let ret = server_factory
            .create(Arc::new(config), Some(Arc::new(context)))
            .await;
        assert!(ret.is_ok());
        let servers = ret.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        for server in servers {
            server_manager.add_server(server);
        }
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
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let stack = UdpStackFactory::new(ConnectionManager::new());
        let stack_context: Arc<dyn StackContext> = Arc::new(UdpStackContext::new(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains.clone()),
            Some(collection_manager),
            Some(Arc::new(JsExternalsManager::new())),
        ));
        let ret = stack.create(Arc::new(stack_config), stack_context).await;
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
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
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

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(
            resp.answers()[0].data(),
            &RData::A(hickory_proto::rr::rdata::A(
                Ipv4Addr::from_str("192.168.1.1").unwrap()
            ))
        );

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

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }
}
