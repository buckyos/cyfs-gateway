use super::hyper_req::HyperHttpRequestHeaderMap;
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper::{Client, Uri};
use hyper::{Method, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;

use crate::*;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain1" priority="1">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            #!(match $PROTOCOL https) && reject;

            # We accept the request if the from buckyos.com
            echo ${REQ_url};
            match $REQ_url "*.buckyos.com" && accept;
            rewrite  $REQ_url "**/index.html" "**/buckyos/index.html";
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
        hook_point.load_process_chain_list(process_chain).await?;

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

async fn process_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            info!("Received a GET request {}", req.uri());
            Ok(Response::new(Body::from("Hello, World!")))
        }
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

async fn handle(
    req: Request<Body>,
    hook_manager: HttpHookManagerRef,
) -> Result<Response<Body>, Infallible> {
    // Create a HyperHttpRequestHeaderMap from the request
    let req_map = HyperHttpRequestHeaderMap::new(req);

    {
        let exec = hook_manager
            .hook_point_env
            .prepare_exec_list(&hook_manager.hook_point);

        // Register visitors for the request headers in the chain environment
        let chain_env = exec.chain_env();
        req_map
            .register_visitors(&chain_env.variable_visitor_manager())
            .await
            .unwrap();

        exec.chain_collections()
            .add_map_collection("REQ", Arc::new(Box::new(req_map.clone()) as Box<dyn MapCollection>))
            .await
            .unwrap();

        // Exec the process chain list
        let ret = exec.execute_all().await.unwrap();

        if ret.is_control() {
            if ret.is_drop() {
                info!("Request dropped by the process chain");
                return Ok(Response::new(Body::from("Request dropped")));
            } else if ret.is_reject() {
                info!("Request rejected by the process chain");
                let mut response = Response::new(Body::from("Request rejected"));
                *response.status_mut() = StatusCode::FORBIDDEN;
                return Ok(response);
            } else {
                info!("Request accepted by the process chain");
            }
        }
    }

    let req = req_map.into_request().unwrap();

    process_request(req).await
}

async fn server_main() {
    let hok_manager = HttpHookManager::create(PROCESS_CHAIN).await.unwrap();
    let hook_manager = Arc::new(hok_manager);

    let addr = ([127, 0, 0, 1], 3000).into();
    let make_svc = make_service_fn(move |_conn| {
        let hook_manager = hook_manager.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| handle(req, hook_manager.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn client_main() {
    let client = Client::new();

    let uri = "http://127.0.0.1:3000/index.html".parse::<Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();

    assert!(resp.status().is_success());

    let bytes = to_bytes(resp).await.unwrap();
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
        SimpleLogger::init(LevelFilter::Info, Config::default()).unwrap()
    });

    tokio::spawn(async {
        server_main().await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    client_main().await;
}
