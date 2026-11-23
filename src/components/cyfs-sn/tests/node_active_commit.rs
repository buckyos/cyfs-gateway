//! The SN side of `node_active_commit.py`: an unchanged SN with its SQLite
//! databases, BNS in memory, HTTP for kRPC and UDP for DNS. The node's side is
//! the ignored test of node_daemon that commits activations against it.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bns_client::{
    BnsApplyMutationsReq, BnsClientError, BnsClientResult, BnsEvmPreparedTx,
    BnsEvmReceiptWaitConfig, BnsEvmTxReceipt, BnsEvmTxSubmission, BnsIndexerApi, BnsIndexerClient,
    BnsIndexerRpcHandler, BnsPublishDocumentReq, BnsRegisterNameReq, MemorySnBnsWriteRequestStore,
    SnBnsController, SnBnsControllerConfig, SnBnsEvmSubmitter,
};
use bns_indexer::{
    CentralizedBnsIndexerHandler, CentralizedBnsRegistry, Principal, SqliteBnsRegistryStore,
};
use cyfs_gateway_lib::{
    hyper_serve_http, serve_http_by_rpc_handler, DnsAuthority, DnsQueryResult, HttpServer,
    NameServer, ServerResult, StreamInfo,
};
use cyfs_sn::{
    MemorySnBnsControllerBindingStore, RelayHeartbeat, RelayNodeRegistration, SNServer,
    SNServerConfig, SnAuthDB, SnAuthDBRef, SnBnsProxy, SnBnsProxyController, SnBnsProxyOperation,
    SnDeviceInfoDBRef, SqliteSnAuthDB, SqliteSnDeviceInfoDB,
};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::json;
use tokio::net::{TcpListener, UdpSocket};

type BoxedBody =
    http_body_util::combinators::BoxBody<hyper::body::Bytes, cyfs_gateway_lib::ServerError>;

const SN_HOST: &str = "buckyos.ai";
const RELAY_IP: &str = "198.51.100.9";
const CONTROLLER: &str = "0xcccccccccccccccccccccccccccccccccccccc01";

type Registry = Arc<CentralizedBnsRegistry<SqliteBnsRegistryStore>>;

/// Applies a transaction to the registry at once, as chain and indexer would.
struct ApplyingSubmitter {
    registry: Registry,
    nonce: std::sync::Mutex<u64>,
}

impl ApplyingSubmitter {
    fn prepared(&self) -> BnsEvmPreparedTx {
        let mut nonce = self.nonce.lock().unwrap();
        let current = *nonce;
        *nonce += 1;
        BnsEvmPreparedTx {
            tx_hash: format!("0x{current:064x}"),
            raw_tx: format!("0x{current:02x}"),
            from: CONTROLLER.to_string(),
            nonce: current,
            chain_id: 31_337,
        }
    }
}

#[async_trait]
impl SnBnsEvmSubmitter for ApplyingSubmitter {
    async fn prepare_register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> BnsClientResult<BnsEvmPreparedTx> {
        if req.authority_key_updates.is_empty()
            && req.semantic_owner_after_authority.is_none()
            && req.controller_policy.is_empty()
        {
            self.registry
                .register_name(
                    &req.name,
                    &req.asset_owner,
                    req.options.clone(),
                    req.initial_documents.clone(),
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(BnsClientError::from)?;
        } else {
            self.registry
                .bootstrap_name(
                    &req.name,
                    &req.asset_owner,
                    req.options.clone(),
                    req.initial_documents.clone(),
                    req.authority_key_updates.clone(),
                    req.semantic_owner_after_authority.clone(),
                    req.controller_policy.clone(),
                    &req.controller_policy_hash,
                    req.authority.clone(),
                    req.guard,
                )
                .map_err(BnsClientError::from)?;
        }
        Ok(self.prepared())
    }

    async fn prepare_apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> BnsClientResult<BnsEvmPreparedTx> {
        self.registry
            .apply_mutations(
                &req.name,
                req.authority_key_updates.clone(),
                req.documents.clone(),
                req.owner_policy.clone(),
                req.authority.clone(),
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(self.prepared())
    }

    async fn prepare_publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsEvmPreparedTx> {
        self.registry
            .publish_document(
                &req.name,
                req.update.clone(),
                req.authority.clone(),
                req.guard,
            )
            .map_err(BnsClientError::from)?;
        Ok(self.prepared())
    }

    async fn submit_prepared(
        &self,
        prepared: &BnsEvmPreparedTx,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        Ok(prepared.submission())
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> BnsClientResult<BnsEvmTxReceipt> {
        Ok(BnsEvmTxReceipt {
            tx_hash: tx_hash.to_string(),
            status: Some(1),
            block_number: 1,
            confirmations: config.confirmations.max(1),
        })
    }
}

/// `sn.<host>` and `bns.<host>` on one port.
struct Front {
    sn: Arc<SNServer>,
    bns: BnsIndexerRpcHandler<CentralizedBnsIndexerHandler<SqliteBnsRegistryStore>>,
}

#[async_trait]
impl HttpServer for Front {
    async fn serve_request(
        &self,
        req: http::Request<BoxedBody>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxedBody>> {
        if req.uri().path() == "/kapi/bns" {
            return serve_http_by_rpc_handler(req, info, &self.bns).await;
        }
        HttpServer::serve_request(self.sn.as_ref(), req, info).await
    }

    fn id(&self) -> String {
        "node-active-commit".to_string()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

fn fqdn(name: &str) -> Name {
    Name::from_utf8(format!("{}.", name.trim_end_matches('.'))).unwrap()
}

fn soa(authority: &DnsAuthority) -> Record {
    Record::from_rdata(
        fqdn(&authority.zone_apex),
        authority.soa_minimum,
        RData::SOA(SOA::new(
            fqdn(&authority.primary_ns),
            fqdn(&authority.responsible_mailbox),
            authority.soa_serial,
            authority.soa_refresh,
            authority.soa_retry,
            authority.soa_expire,
            authority.soa_minimum,
        )),
    )
}

/// What cyfs-dns answers for a name server of type `sn` (`dns_server.rs`).
async fn answer(sn: &SNServer, request: &Message) -> Message {
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired());
    let Some(query) = request.queries().first() else {
        response.set_response_code(ResponseCode::FormErr);
        return response;
    };
    response.add_query(query.clone());
    let name = query
        .name()
        .to_utf8()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let ty = query.query_type();
    let result = sn.query_dns(&name, &ty.to_string(), None).await;
    let (authority, code) = match result {
        Ok(DnsQueryResult::Answer {
            name_info,
            authority,
        }) => {
            let ttl = name_info.ttl.unwrap_or(600);
            let mut records = Vec::new();
            for address in &name_info.address {
                match (address, ty) {
                    (IpAddr::V4(ip), RecordType::A) => records.push(RData::A(A::from(*ip))),
                    (IpAddr::V6(ip), RecordType::AAAA) => {
                        records.push(RData::AAAA(AAAA::from(*ip)))
                    }
                    _ => {}
                }
            }
            if ty == RecordType::TXT {
                for text in &name_info.txt {
                    let parts = text
                        .as_bytes()
                        .chunks(255)
                        .map(|part| String::from_utf8_lossy(part).to_string())
                        .collect();
                    records.push(RData::TXT(TXT::new(parts)));
                }
            }
            response.set_authoritative(authority.is_some());
            if !records.is_empty() {
                for data in records {
                    response.add_answer(Record::from_rdata(query.name().clone(), ttl, data));
                }
                return response;
            }
            (authority, ResponseCode::NoError)
        }
        Ok(DnsQueryResult::AuthoritativeNoData { authority }) => {
            (Some(authority), ResponseCode::NoError)
        }
        Ok(DnsQueryResult::AuthoritativeNxDomain { authority }) => {
            (Some(authority), ResponseCode::NXDomain)
        }
        Ok(DnsQueryResult::TemporaryFailure { .. }) => (None, ResponseCode::ServFail),
        Err(_) => (None, ResponseCode::Refused),
    };
    response.set_response_code(code);
    let Some(authority) = authority else {
        return response;
    };
    response.set_authoritative(true);
    let at_apex = name == authority.zone_apex;
    match ty {
        RecordType::NS if at_apex => {
            response.set_response_code(ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                fqdn(&authority.zone_apex),
                authority.positive_ttl,
                RData::NS(NS(fqdn(&authority.primary_ns))),
            ));
        }
        RecordType::SOA if at_apex => {
            response.set_response_code(ResponseCode::NoError);
            response.add_answer(soa(&authority));
        }
        RecordType::NS | RecordType::SOA => {
            response.set_response_code(ResponseCode::NoError);
            response.add_name_server(soa(&authority));
        }
        _ => {
            response.add_name_server(soa(&authority));
        }
    }
    response
}

async fn serve_dns(sn: Arc<SNServer>, socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; 4096];
    while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
        let Ok(request) = Message::from_vec(&buffer[..length]) else {
            continue;
        };
        let (sn, socket) = (sn.clone(), socket.clone());
        tokio::spawn(async move {
            let response = answer(&sn, &request).await;
            let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
        });
    }
}

async fn serve_http(front: Arc<Front>, listener: TcpListener) {
    while let Ok((stream, peer)) = listener.accept().await {
        let server: Arc<dyn HttpServer> = front.clone();
        tokio::spawn(async move {
            let info = StreamInfo::new(peer.to_string());
            let _ = hyper_serve_http(Box::new(stream), server, info).await;
        });
    }
}

/// `NODE_ACTIVE_SN_FIXTURE`: where to write the addresses; the server runs
/// until `<path>.stop` exists. `NODE_ACTIVE_DOH`: the public resolver the SN
/// asks for `_pkx`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "cross-repository fixture of node_active_commit.py"]
async fn serve_node_active_commit_fixture() {
    let path = PathBuf::from(std::env::var("NODE_ACTIVE_SN_FIXTURE").expect("fixture path"));
    let doh = std::env::var("NODE_ACTIVE_DOH").expect("DoH endpoint");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sn.sqlite").to_string_lossy().to_string();

    let auth_db = SqliteSnAuthDB::new_by_path(&db).await.unwrap();
    auth_db.initialize_database().await.unwrap();
    let codes = (0..16)
        .map(|n| format!("node-active-{n}"))
        .collect::<Vec<_>>();
    for code in &codes {
        auth_db.insert_activation_code(code).await.unwrap();
    }
    auth_db
        .register_relay_node(RelayNodeRegistration {
            relay_id: "relay-1".to_string(),
            relay_sn: format!("relay.{SN_HOST}"),
            ips: [RELAY_IP.parse().unwrap(), "2001:db8::9".parse().unwrap()],
            public_host: format!("relay.{SN_HOST}"),
            http_endpoint: None,
            rtcp_endpoint: None,
            region: Some("test".to_string()),
            isp: None,
            tags: vec!["region:test".to_string()],
            capabilities: vec!["http_relay".to_string(), "rtcp_relay".to_string()],
            status: None,
            capacity_score: Some(100),
        })
        .await
        .unwrap();
    auth_db
        .heartbeat_relay_node(RelayHeartbeat {
            relay_id: "relay-1".to_string(),
            status: None,
            current_load: Some(0),
            capacity_score: Some(100),
            drain_until: None,
            http_endpoint: None,
            rtcp_endpoint: None,
        })
        .await
        .unwrap();
    let auth_db: SnAuthDBRef = Arc::new(auth_db);
    let device_info_db = SqliteSnDeviceInfoDB::new_by_path(&db).await.unwrap();
    device_info_db.initialize_database().await.unwrap();
    let device_info_db: SnDeviceInfoDBRef = Arc::new(device_info_db);

    let registry: Registry = Arc::new(CentralizedBnsRegistry::new_legacy_state_machine(
        SqliteBnsRegistryStore::open_memory().unwrap(),
    ));
    let handler: Arc<dyn BnsIndexerApi> =
        Arc::new(CentralizedBnsIndexerHandler::new(registry.clone()));
    let bns_client = BnsIndexerClient::new_in_process(handler);
    let controller = SnBnsController::new_with_evm_submitter(
        Arc::new(bns_client.clone()),
        Arc::new(MemorySnBnsWriteRequestStore::new()),
        SnBnsControllerConfig::new(Principal::chain_account(CONTROLLER), ""),
        Arc::new(ApplyingSubmitter {
            registry: registry.clone(),
            nonce: std::sync::Mutex::new(0),
        }),
    )
    .unwrap();
    let proxy = SnBnsProxy::new(
        vec![SnBnsProxyController {
            id: "controller".to_string(),
            address: CONTROLLER.to_string(),
            principal: Principal::chain_account(CONTROLLER),
            weight: 1,
            controller: Arc::new(controller),
        }],
        Arc::new(MemorySnBnsControllerBindingStore::new()),
        SnBnsProxyOperation::all().into_iter().collect(),
        true,
    )
    .unwrap();
    let config: SNServerConfig = serde_json::from_value(json!({
        "id": "node-active-commit",
        "host": SN_HOST,
        "ip": "127.0.0.1",
        "boot_jwt": "",
        "owner_pkx": "",
        "device_jwt": [],
        "auth_data_dir": dir.path().join("auth").to_string_lossy(),
        "pkx_doh_url": doh,
    }))
    .unwrap();
    std::fs::create_dir_all(dir.path().join("auth")).unwrap();
    let sn = Arc::new(
        SNServer::new(
            config,
            auth_db,
            device_info_db,
            bns_client,
            Some(Arc::new(proxy)),
        )
        .await
        .unwrap(),
    );

    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let dns = UdpSocket::bind(local).await.unwrap();
    let dns_address = dns.local_addr().unwrap();
    tokio::spawn(serve_dns(sn.clone(), dns));
    let http = TcpListener::bind(local).await.unwrap();
    let http_address = http.local_addr().unwrap();
    let front = Arc::new(Front {
        sn,
        bns: BnsIndexerRpcHandler(CentralizedBnsIndexerHandler::new(registry)),
    });
    tokio::spawn(serve_http(front, http));

    let fixture = json!({
        "sn_url": format!("http://{http_address}/kapi/sn"),
        "bns_url": format!("http://{http_address}/kapi/bns"),
        "dns": dns_address.to_string(),
        "doh": doh,
        "relay_ip": RELAY_IP,
        "active_codes": codes,
    });
    let staged = path.with_extension("tmp");
    std::fs::write(&staged, fixture.to_string()).unwrap();
    std::fs::rename(&staged, &path).unwrap();
    let stop = PathBuf::from(format!("{}.stop", path.display()));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1200);
    while !stop.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
