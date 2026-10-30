//! SN 的 Internal zone-resolver 作为 name-client Zone locker（127.0.0.1:3180）时，RTCP
//! `authority_current` 出站身份解析看到的结果（buckyos#710）。locker 是 hosts 语义的强制
//! 回答：托管域由 SN 自己的数据作答，不再请求该域名的公网 HTTPS（method authority）。
//!
//! HTTP 层按 `SNServer::serve_request` 的 `/1.0/identifiers` 处理方式作答。

use super::*;
use crate::sn_resolver::{
    BnsDocument, BnsDocumentReader, SnAuthReader, SnResolver, SnResolverConfig,
};
use crate::{SNUserInfo, UserState, ZoneInfo};
use jsonwebtoken::{jwk::Jwk, EncodingKey};
use name_client::{
    DocResult, NameClient, NameClientConfig, ResolveOpts, Revision, Source, SourceAnswer,
    SourceRef, SourceTier, TypeState, ZoneLockerConfig,
};
use name_lib::{DIDDocumentTrait, DeviceDocument, DidDocType};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const OWNER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr\n-----END PRIVATE KEY-----";
const DEVICE_X: &str = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
const ROTATED_DEVICE_X: &str = "pNq79YSL_EW-oZaHdJ5vU6I_lrl4QssD1joOtlKCLNQ";

/// 文档时间相对当前时刻（JWT 解码按真实时间检查 exp）；同一进程内基准固定。
fn issued_at(offset: u64) -> u64 {
    static BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BASE.get_or_init(|| buckyos_kit::buckyos_get_unix_timestamp() - 10_000) + offset
}

#[derive(Default)]
struct TestAuth {
    users: Mutex<HashMap<String, SNUserInfo>>,
    failing_domains: Mutex<HashSet<String>>,
}

impl TestAuth {
    fn add_user(&self, username: &str, domain: &str) {
        self.users.lock().unwrap().insert(
            username.to_string(),
            SNUserInfo {
                username: Some(username.to_string()),
                email: None,
                state: UserState::Active,
                public_key: String::new(),
                activation_code: None,
                zone_config: String::new(),
                self_cert: true,
                user_domain: Some(domain.to_string()),
                sn_ips: None,
                updated_at: 7,
                relay: None,
            },
        );
    }

    fn set_state(&self, username: &str, state: UserState) {
        self.users.lock().unwrap().get_mut(username).unwrap().state = state;
    }
}

#[async_trait]
impl SnAuthReader for TestAuth {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
        Ok(self.users.lock().unwrap().get(username).cloned())
    }

    // 与 sn-business provider 一致：按最长 active binding 返回，不按用户状态过滤。
    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
        let failing = self
            .failing_domains
            .lock()
            .unwrap()
            .iter()
            .any(|d| domain == d || domain.ends_with(format!(".{}", d).as_str()));
        if failing {
            return Err(SnResolverError::backend("AuthDB unavailable (test)"));
        }
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .filter(|user| {
                user.user_domain.as_deref().is_some_and(|user_domain| {
                    domain == user_domain || domain.ends_with(format!(".{}", user_domain).as_str())
                })
            })
            .max_by_key(|user| user.user_domain.as_deref().map(str::len))
            .cloned())
    }

    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
        Ok(Some(ZoneInfo::default_for(username)))
    }
}

#[derive(Default)]
struct TestBns {
    documents: Mutex<HashMap<(String, String), BnsDocument>>,
}

impl TestBns {
    fn put(&self, zone: &str, name: &str, document: BnsDocument) {
        self.documents
            .lock()
            .unwrap()
            .insert((zone.to_string(), name.to_string()), document);
    }
}

#[async_trait]
impl BnsDocumentReader for TestBns {
    async fn get_document(
        &self,
        name: &str,
        doc_type: &str,
    ) -> SnResolverResult<Option<BnsDocument>> {
        Ok(self
            .documents
            .lock()
            .unwrap()
            .get(&(name.to_string(), doc_type.to_string()))
            .cloned())
    }
}

/// 代表 did:web 的 method authority（WebProvider）：记录调用的 DID。
#[derive(Default)]
struct PublicWeb {
    dids: Mutex<Vec<String>>,
}

impl PublicWeb {
    fn calls(&self) -> usize {
        self.dids.lock().unwrap().len()
    }
}

#[async_trait]
impl Source for PublicWeb {
    fn id(&self) -> String {
        "web-provider".to_string()
    }

    async fn get_document(
        &self,
        did: &DID,
        _doc_type: &DidDocType,
        _revision: &Revision,
        _opts: &ResolveOpts,
    ) -> SourceAnswer {
        self.dids.lock().unwrap().push(did.to_string());
        SourceAnswer::failure(
            SourceRef::provider("web-provider", SourceTier::Authority),
            "public HTTPS is unreachable (test)",
        )
    }
}

/// 只回答 `GET /1.0/identifiers/{did}?type=`，状态与 body 同 `SNServer::serve_request`
/// 的 internal profile 分支。
async fn spawn_internal_zone_resolver(resolver: Arc<SnResolverBackedDidResolver>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8_lossy(&request).to_string();
                let target = request.split_whitespace().nth(1).unwrap().to_string();
                let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
                let did = DID::from_str(path.trim_start_matches(SN_DID_RESOLVER_ROUTE_PREFIX)).unwrap();
                let doc_type = url::form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "type")
                    .map(|(_, value)| value.to_string());
                let response = resolver
                    .resolve(SnDidResolveRequest::new(
                        did,
                        doc_type,
                        None,
                        SnDidResolverProfile::InternalZoneResolver,
                    ))
                    .await;
                let (status, content_type, body) = match response {
                    Ok(resolution) => (
                        resolution.status_code(),
                        resolution.content_type_for_accept(None),
                        resolution.body_for_accept(None),
                    ),
                    Err(error) => (
                        match error.kind() {
                            SnResolverErrorKind::NotManaged
                            | SnResolverErrorKind::NameNotFound
                            | SnResolverErrorKind::DocumentNotFound
                            | SnResolverErrorKind::DeviceNotFound => StatusCode::NOT_FOUND,
                            SnResolverErrorKind::BackendUnavailable => {
                                StatusCode::INTERNAL_SERVER_ERROR
                            }
                            _ => StatusCode::BAD_REQUEST,
                        },
                        "text/plain",
                        error.to_string(),
                    ),
                };
                let head = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or(""),
                    content_type,
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    format!("http://{}", addr)
}

fn device_jwt(id: &str, iat_offset: u64, x: &str) -> String {
    let jwk: Jwk =
        serde_json::from_value(json!({"kty": "OKP", "crv": "Ed25519", "x": x})).unwrap();
    let mut device = DeviceDocument::new_by_jwk("ood1", jwk);
    device.id = DID::from_str(id).unwrap();
    if let Some((_, domain)) = id.strip_prefix("did:web:").and_then(|host| host.split_once('.')) {
        device.owner = DID::from_str(format!("did:web:{}", domain).as_str()).unwrap();
        device.zone_did = Some(device.owner.clone());
    }
    device.iat = issued_at(iat_offset);
    device.exp = issued_at(iat_offset) + 3600 * 24 * 365;
    let key = EncodingKey::from_ed_pem(OWNER_KEY_PEM.as_bytes()).unwrap();
    match device.encode(Some(&key)).unwrap() {
        EncodedDocument::Jwt(jwt) => jwt,
        other => panic!("unexpected device encoding {:?}", other),
    }
}

struct Fixture {
    auth: Arc<TestAuth>,
    bns: Arc<TestBns>,
    public_web: Arc<PublicWeb>,
    client: NameClient,
}

impl Fixture {
    async fn new() -> Self {
        let auth = Arc::new(TestAuth::default());
        auth.add_user("alice", "example.com");
        auth.add_user("bob", "bob.example.net");
        let bns = Arc::new(TestBns::default());
        bns.put(
            "alice",
            "ood1",
            BnsDocument::jwt("alice", "ood1", device_jwt("did:web:ood1.example.com", 1_000, DEVICE_X)),
        );
        bns.put(
            "bob",
            "ood1",
            BnsDocument::jwt("bob", "ood1", device_jwt("did:web:ood1.bob.example.net", 1_000, DEVICE_X)),
        );
        let resolver = Arc::new(SnResolver::new_with_bns(
            SnResolverConfig::new("sn.test", None, None, None, Vec::new()),
            auth.clone(),
            bns.clone(),
        ));
        let endpoint = spawn_internal_zone_resolver(Arc::new(SnResolverBackedDidResolver::new(
            resolver,
            auth.clone(),
            "sn.test",
        )))
        .await;
        let client = NameClient::new(NameClientConfig {
            enable_zone_locker: true,
            zone_locker: ZoneLockerConfig {
                endpoint,
                connect_timeout: Duration::from_millis(500),
                request_timeout: Duration::from_secs(5),
            },
            ..NameClientConfig::for_test()
        });
        let public_web = Arc::new(PublicWeb::default());
        client.set_method_authority("web", public_web.clone());
        Self {
            auth,
            bns,
            public_web,
            client,
        }
    }

    /// RTCP `authority_current` 出站解析的选项（rtcp.rs `handshake_resolve_opts`）。
    async fn resolve(&self, did: &str, doc_type: DidDocType) -> DocResult {
        let budget = Duration::from_secs(5);
        let opts = ResolveOpts::default()
            .authority_only()
            .with_force_authority_query()
            .with_timeout(budget)
            .normalize(budget);
        self.client
            .resolve_did_ex(&DID::from_str(did).unwrap(), Some(doc_type), Revision::current(), opts)
            .await
            .unwrap()
    }

    /// locker 的强制回答里选出的当前文档。
    async fn locked_device(&self, did: &str) -> Option<String> {
        let result = self.resolve(did, DidDocType::Device).await;
        assert!(result.locked, "{} must be answered by the SN zone resolver", did);
        result
            .select(&Revision::current())
            .filter(|choice| choice.is_valid())
            .map(|choice| {
                assert!(choice.source.is_zone_locker());
                match &choice.doc {
                    EncodedDocument::Jwt(jwt) => jwt.clone(),
                    other => panic!("expected the stored JWT, got {:?}", other),
                }
            })
    }
}

#[tokio::test]
async fn managed_device_is_a_zone_locker_answer_without_public_https() {
    let fx = Fixture::new().await;
    assert_eq!(
        fx.locked_device("did:web:ood1.example.com").await.unwrap(),
        device_jwt("did:web:ood1.example.com", 1_000, DEVICE_X)
    );
    // 每次建流都重新取 locker 的回答（不进普通缓存），仍不碰公网 HTTPS。
    assert!(fx.locked_device("did:web:ood1.bob.example.net").await.is_some());
    assert!(fx.locked_device("did:web:ood1.example.com").await.is_some());
    assert_eq!(fx.public_web.calls(), 0);
}

#[tokio::test]
async fn names_outside_the_sn_go_to_the_method_authority() {
    let fx = Fixture::new().await;
    for did in [
        "did:web:ood1.unrelated.org",
        // 边界相似但不是 example.com 的子域。
        "did:web:ood1.evil-example.com",
        // 绑定域名下第二级以下不是本 SN 发布的设备名。
        "did:web:a.ood1.example.com",
    ] {
        let result = fx.resolve(did, DidDocType::Device).await;
        assert!(!result.locked, "{} is not covered by the SN zone resolver", did);
    }
    assert_eq!(
        *fx.public_web.dids.lock().unwrap(),
        vec![
            "did:web:ood1.unrelated.org".to_string(),
            "did:web:ood1.evil-example.com".to_string(),
            "did:web:a.ood1.example.com".to_string(),
        ]
    );
}

#[tokio::test]
async fn current_sn_state_wins_after_rotation_and_revocation() {
    let fx = Fixture::new().await;
    let did = "did:web:ood1.example.com";
    assert!(fx.locked_device(did).await.is_some());

    // 设备密钥轮换：下一次建流得到新版本。
    let rotated = device_jwt(did, 1_100, ROTATED_DEVICE_X);
    fx.bns.put("alice", "ood1", BnsDocument::jwt("alice", "ood1", rotated.clone()));
    assert_eq!(fx.locked_device(did).await.unwrap(), rotated);

    // owner 暂停 / 注销：locker 的禁用回答不交给 method authority。
    fx.auth.set_state("alice", UserState::Suspended);
    let result = fx.resolve(did, DidDocType::Device).await;
    assert!(result.locked && result.is_disabled());
    fx.auth.set_state("alice", UserState::Deleted);
    let result = fx.resolve(did, DidDocType::Zone).await;
    assert!(result.locked && result.is_disabled());
    assert_eq!(fx.public_web.calls(), 0);
}

#[tokio::test]
async fn missing_mismatched_and_invalid_documents_are_forced_answers() {
    let fx = Fixture::new().await;

    // 只有在线记录、没有完整 DeviceDocument：missing（RTCP 才会再查同一 DID 的 Zone）。
    for doc_type in [DidDocType::Device, DidDocType::Zone] {
        let result = fx.resolve("did:web:ood2.example.com", doc_type).await;
        assert!(result.locked);
        assert!(matches!(result.type_state, Some(TypeState::Missing)));
    }

    // BNS 里的 JWT 声明另一种身份：不改写签名 payload，也不当作这个 did:web 的文档。
    fx.bns.put(
        "alice",
        "ood3",
        BnsDocument::jwt("alice", "ood3", device_jwt("did:bns:ood3.alice", 1_000, DEVICE_X)),
    );
    let result = fx.resolve("did:web:ood3.example.com", DidDocType::Device).await;
    assert!(result.locked);
    assert!(matches!(result.type_state, Some(TypeState::Missing)));

    // 存储的设备文档不是 compact JWT：确定性 invalid，不能当作缺失去查 Zone。
    fx.bns.put(
        "alice",
        "ood4",
        BnsDocument::json("alice", "ood4", json!({"id": "did:web:ood4.example.com"})),
    );
    let result = fx.resolve("did:web:ood4.example.com", DidDocType::Device).await;
    assert!(result.locked);
    assert!(matches!(result.type_state, Some(TypeState::Invalid { .. })));
    assert_eq!(fx.public_web.calls(), 0);
}

/// 控制面故障不是 locker 的回答（没有对应的 documentStatus），name-client 继续问 method
/// authority。SN 的 hostname 转发 QA 读同一个 AuthDB / BNS，此时已经拒绝转发，所以对托管域
/// 的公网 HTTPS 请求不会再经 RTCP 回到这里。
#[tokio::test]
async fn control_plane_failure_is_not_a_locker_answer() {
    let fx = Fixture::new().await;
    fx.auth
        .failing_domains
        .lock()
        .unwrap()
        .insert("example.com".to_string());
    let result = fx.resolve("did:web:ood1.example.com", DidDocType::Device).await;
    assert!(!result.locked);
    assert!(!result.is_not_exist(), "unavailable must not become missing");
    assert_eq!(fx.public_web.calls(), 1);
    // 另一个 Zone 不受影响。
    assert!(fx.locked_device("did:web:ood1.bob.example.net").await.is_some());
}
