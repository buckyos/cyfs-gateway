use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper::{Client, Uri};
use hyper::{Method, StatusCode};
use std::convert::Infallible;

use crate::*;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain1" priority="1">
    <block id="block1">
        <![CDATA[
            # We reject the request if the protocol is not https
            !(match $PROTOCOL https) && reject;

            # We accept the request if the from buckyos.com
            echo ${REQ_url};
            match $REQ_url "*.buckyos.com" && accept;
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

async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            println!("Received a GET request");
            Ok(Response::new(Body::from("Hello, World!")))
        }
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

async fn server_main() {
    let addr = ([127, 0, 0, 1], 3000).into();
    let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn client_main() {
    let client = Client::new();

    let uri = "http://127.0.0.1:3000".parse::<Uri>().unwrap();
    let resp = client.get(uri).await.unwrap();

    assert!(resp.status().is_success());

    let bytes = to_bytes(resp).await.unwrap();
    assert_eq!(&*bytes, b"Hello, World!");
}

#[tokio::test]
async fn test_main() {
    tokio::spawn(async {
        server_main().await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    client_main().await;
}
