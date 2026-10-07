use super::hyper_req::HyperHttpRequestHeaderMap;
use crate::*;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain1" priority="1">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            #!(match $PROTOCOL https) && reject;

            # We accept the request if the from buckyos.com
            echo ${REQ.content-type};
            !match ${REQ.content-type} "text/html" && reject;
            echo ${REQ_url};
            match $REQ_url "*.buckyos.com" && accept;
            rewrite $REQ_url "/index.html" "/buckyos/index.html";
        ]]>
    </block>
</process_chain>
</root>
"#;

pub struct HttpHookManager {
    hook_point: HookPoint,
    hook_point_env: HookPointEnv,
}

impl HttpHookManager {
    pub async fn create(process_chain: &str) -> Result<Self, String> {
        // Create a hook point
        let hook_point = HookPoint::new("http-hook-point");
        hook_point
            .load_process_chain_lib("main", 0, process_chain)
            .await?;

        let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Create env to execute the hook point
        let hook_point_env = HookPointEnv::new("http-hook-point", data_dir);

        // Load some collections for file
        hook_point_env
            .load_collection(
                "host",
                CollectionType::MultiMap,
                CollectionFileFormat::Json,
                true,
            )
            .await?;

        hook_point_env
            .load_collection(
                "ip",
                CollectionType::MultiMap,
                CollectionFileFormat::Json,
                true,
            )
            .await?;

        Ok(Self {
            hook_point,
            hook_point_env,
        })
    }
}

type HttpHookManagerRef = Arc<HttpHookManager>;

async fn process_request(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/buckyos/index.html") => {
            info!("Received a GET request {}", req.uri());
            Ok(Response::new(
                Full::new(hyper::body::Bytes::from("Hello, World!"))
                    .map_err(|e| match e {})
                    .boxed(),
            ))
        }
        _ => {
            let mut not_found = Response::<BoxBody<Bytes, hyper::Error>>::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

async fn pre_process_request(
    req: Request<Incoming>,
    exec: ProcessChainLibExecutor,
) -> Result<Request<Incoming>, Response<BoxBody<Bytes, hyper::Error>>> {
    info!("Pre-processing request: {:?}", req);

    // Create a HyperHttpRequestHeaderMap from the request
    let req_map = HyperHttpRequestHeaderMap::new(req);

    {
        // Register visitors for the request headers in the chain environment
        let chain_env = exec.chain_env();
        req_map.register_visitors(chain_env).await.unwrap();

        let req_collection = Arc::new(Box::new(req_map.clone()) as Box<dyn MapCollection>);
        chain_env
            .create("REQ", CollectionValue::Map(req_collection))
            .await
            .unwrap();

        // Exec the process chain list
        let ret = exec.execute_lib().await.unwrap();

        info!("Process chain execution result: {:?}", ret);
        if ret.is_control() {
            if ret.is_drop() {
                info!("Request dropped by the process chain");
                return Err(Response::new(
                    Full::new(Bytes::from("Request dropped"))
                        .map_err(|e| match e {})
                        .boxed(),
                ));
            } else if ret.is_reject() {
                info!("Request rejected by the process chain");
                let mut response = Response::new(
                    Full::new(Bytes::from("Request rejected"))
                        .map_err(|e| match e {})
                        .boxed(),
                );
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Err(response);
            } else {
                info!("Request accepted by the process chain");
            }
        }
    }

    let req = req_map.into_request().unwrap();
    Ok(req)
}

async fn handle(
    req: Request<Incoming>,
    exec: ProcessChainLibExecutor,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    info!("Handling request: {:?}", req);

    let req = match pre_process_request(req, exec).await {
        Ok(req) => req,
        Err(response) => return Ok(response),
    };

    info!("Will processing request: {:?}", req);

    process_request(req).await
}

async fn server_main(addr_tx: oneshot::Sender<SocketAddr>) {
    let hook_manager = HttpHookManager::create(PROCESS_CHAIN).await.unwrap();
    let hook_manager = Arc::new(hook_manager);

    let exec = hook_manager
        .hook_point_env
        .link_hook_point(&hook_manager.hook_point)
        .await
        .unwrap();

    // Bind to an ephemeral port so the test never clashes with another
    // listener (e.g. a Windows-side process surfaced into WSL via localhost
    // forwarding, or a parallel test run).
    let bind_addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let listener = TcpListener::bind(&bind_addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    log::info!("Listening on http://{}", addr);

    // Report the actual port to the test. If the receiver is already gone the
    // test has finished/aborted, so stop the server.
    if addr_tx.send(addr).is_err() {
        log::info!("Test no longer waiting for the server address, shutting down");
        return;
    }

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);

        let exec = exec.clone();
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let lib_exec = exec.prepare_exec_lib("main").unwrap();
                handle(req, lib_exec)
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                log::info!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn client_main(addr: SocketAddr) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method(Method::GET)
        .header("content-type", "text/html")
        .uri(format!("http://{}/index.html", addr))
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = client.request(req).await.unwrap();

    assert!(resp.status().is_success());

    let bytes = resp.collect().await.unwrap().to_bytes();
    assert_eq!(&*bytes, b"Hello, World!");
}

#[tokio::test]
async fn test_main() {
    use simplelog::*;
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap_or_else(|_| {
        // If TermLogger is not available (e.g., in some environments), fall back to SimpleLogger
        let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
    });

    let (addr_tx, addr_rx) = oneshot::channel();
    tokio::spawn(async move {
        server_main(addr_tx).await;
    });

    // Wait until the server has actually bound its port. This also propagates a
    // startup failure (e.g. a bind error) instead of hanging forever.
    let addr = addr_rx.await.expect("http test server failed to start");

    client_main(addr).await;
}
