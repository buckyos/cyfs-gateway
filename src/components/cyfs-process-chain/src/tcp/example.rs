use super::http::HttpProbeCommand;
use super::sni::HttpsSniProbeCommand;
use crate::*;
use buckyos_kit::AsyncStream;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    ServerConfig, pki_types::CertificateDer, pki_types::PrivateKeyDer, pki_types::ServerName,
};
use simplelog::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use url::Url;

const PROCESS_CHAIN: &str = r#"
<root>
<process_chain id="chain1" priority="1">
    <block id="block1">
        <![CDATA[
            # We first check if the protocol is https or http
            call http-probe;
            call https-sni-probe;

            echo ${REQ.dest_host};
            match ${REQ.app_protocol} "http" && echo ${REQ.ext.url};
            match ${REQ.app_protocol} "https" && return "tcp://127.0.0.1:10000";
            match ${REQ.app_protocol} "http" && return "tcp://127.0.0.1:11000";
        ]]>
    </block>
</process_chain>
</root>
"#;

pub struct HttpConnHookManager {
    hook_point: HookPoint,
    hook_point_env: HookPointEnv,
}

impl HttpConnHookManager {
    pub async fn create(process_chain: &str) -> Result<Self, String> {
        // Create a hook point
        let hook_point = HookPoint::new("http-conn-hook-point");
        hook_point
            .load_process_chain_lib("main", 0, process_chain)
            .await?;

        let data_dir = std::env::temp_dir().join("cyfs-process-chain-test");
        std::fs::create_dir_all(&data_dir).unwrap();

        // Create env to execute the hook point
        let hook_point_env = HookPointEnv::new("http-conn-hook-point", data_dir);

        // Register the external command for HTTPS SNI probing
        let https_sni_probe_command = HttpsSniProbeCommand::new();
        let name = https_sni_probe_command.name().to_owned();
        hook_point_env
            .register_external_command(
                &name,
                Arc::new(Box::new(https_sni_probe_command) as Box<dyn ExternalCommand>),
            )
            .unwrap();

        // Register the external command for HTTP probing
        let http_probe_command = HttpProbeCommand::new();
        let name = http_probe_command.name().to_owned();
        hook_point_env
            .register_external_command(
                &name,
                Arc::new(Box::new(http_probe_command) as Box<dyn ExternalCommand>),
            )
            .unwrap();

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

type HttpHookManagerRef = Arc<HttpConnHookManager>;

async fn on_new_connection(
    stream: Box<dyn AsyncStream>,
    peer_addr: SocketAddr,
    exec: ProcessChainLibExecutor,
) -> Result<(Url, Box<dyn AsyncStream>), String> {
    // Create a new request map for the incoming stream
    let request = StreamRequest::new(stream, peer_addr);

    // TODO fill the request with necessary data
    let request_map = StreamRequestMap::new(request);

    // Register the request map in the environment
    let env = exec.chain_env();
    request_map.register(&env).await.unwrap();

    // Execute the hook point
    let ret: Result<CommandResult, String> = exec.execute_lib().await;

    let request = request_map.into_request().unwrap();
    let stream = request.incoming_stream.lock().unwrap().take().unwrap();

    // If the command was successful, we can get a URL to forward the request
    // Otherwise, we should close the stream and return an error
    if ret.is_err() {
        let msg = format!("Error executing process chain: {}", ret.unwrap_err());
        error!("{}", msg);
        return Err(msg);
    }

    let ret = ret.unwrap();
    let url = match &ret {
        CommandResult::Control(CommandControl::Return(forward)) => {
            // If the command was successful, we can get a URL to forward the request
            let url = Url::parse(&forward.value).map_err(|e| {
                let msg = format!(
                    "Failed to parse URL from process chain: {}, {}",
                    e, forward.value
                );
                error!("{}", msg);
                msg
            })?;
            info!("Request processed successfully {}", url);

            url
        }
        _ => {
            let msg = format!("Process chain did not return a valid URL, got: {:?}", ret);
            error!("{}", msg);
            return Err(msg);
        }
    };

    // Try check the destination host from the request
    assert_eq!(request.dest_host.as_deref().unwrap(), "buckyos.com");
    // Check the protocol is http or https
    assert!(request.app_protocol.is_some());
    if request.app_protocol.as_deref() != Some("http")
        && request.app_protocol.as_deref() != Some("https")
    {
        let msg = format!(
            "Process chain did not return a valid protocol, got: {:?}",
            request.app_protocol
        );
        error!("{}", msg);
        return Err(msg);
    }

    // Return the stream
    info!("Forwarding request to {}", url);
    Ok((url, stream))
}

fn generate_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let subject_alt_names = vec!["buckyos.com".to_string()];

    // Use rcgen to generate a self-signed certificate
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).unwrap();

    // Convert the rcgen certificate to rustls format
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert);
    let rustls_private_key =
        rustls::pki_types::PrivateKeyDer::try_from(signing_key.serialized_der().to_vec()).unwrap();

    // As of rustls 0.23, we need to convert the private key to a format that rustls can use
    // let rustls_private_key = rustls::crypto::ring::any_supported_type(&rustls_key).unwrap();

    println!("✅ Certificate and private key generated.");
    (rustls_cert, rustls_private_key)
}

async fn start_forward_server(port: u16) {
    let hook_manager: HttpConnHookManager =
        HttpConnHookManager::create(PROCESS_CHAIN).await.unwrap();
    let hook_manager = Arc::new(hook_manager);

    let exec = hook_manager
        .hook_point_env
        .link_hook_point(&hook_manager.hook_point)
        .await
        .unwrap();

    // Start the forward server to handle incoming connections
    let forward_listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    tokio::spawn(async move {
        loop {
            let (inbound, peer_addr) = forward_listener.accept().await.unwrap();

            let exec = exec.clone();
            tokio::spawn(async move {
                let stream = Box::new(inbound) as Box<dyn AsyncStream>;
                let lib_exec = exec.prepare_exec_lib("main").unwrap();
                let (forward, mut stream) = on_new_connection(stream, peer_addr, lib_exec)
                    .await
                    .unwrap();

                // Connect to the backend server
                let addrs = forward.socket_addrs(|| None).unwrap();
                let mut outbound = TcpStream::connect(&addrs[0]).await.unwrap();

                tokio::io::copy_bidirectional(&mut stream, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
}

#[tokio::test]
async fn test_https_sni_probe() {
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

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to set default crypto provider");

    // First generate a self-signed certificate
    let (cert_der, key_der) = generate_cert();

    let backend_config = ServerConfig::builder()
        //.with_safe_default_protocol_versions()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    // Simulate a backend TLS server for buckyos.com
    let tls_acceptor = TlsAcceptor::from(Arc::new(backend_config));
    let backend_listener = TcpListener::bind("127.0.0.1:10000").await.unwrap();

    let backend = tokio::spawn(async move {
        let (stream, _) = backend_listener.accept().await.unwrap();
        let mut tls_stream = tls_acceptor.accept(stream).await.unwrap();

        // Respond with a simple message with "Hello, buckyos.com!"
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nHello, buckyos.com!";
        tokio::io::AsyncWriteExt::write_all(&mut tls_stream, response)
            .await
            .unwrap();
        tls_stream.shutdown().await.unwrap();
    });

    // Start the forward server to handle incoming connections
    start_forward_server(10010).await;

    // Now we can create a client to test the HTTPS SNI probing
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("buckyos.com").unwrap();

    let client_stream = TcpStream::connect("127.0.0.1:10010").await.unwrap();
    let mut tls_stream = connector.connect(server_name, client_stream).await.unwrap();

    // Try read the response from the server
    let mut buffer = vec![0; 4096];
    let bytes_read = tls_stream
        .read(&mut buffer)
        .await
        .expect("Failed to read from TLS stream");
    assert!(bytes_read > 0, "No data read from TLS stream");
    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
    info!("Received response: {}", response);
    assert!(
        response.contains("Hello, buckyos.com!"),
        "Unexpected response: {}",
        response
    );

    // Wait for the servers to finish
    backend.await.unwrap();
}

#[tokio::test]
async fn test_http_probe() {
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

    // Start a simple HTTP server to test the HTTP probing
    let addr: SocketAddr = ([127, 0, 0, 1], 11000).into();

    let listener = TcpListener::bind(&addr).await.unwrap();
    log::info!("Listening on http://{}", addr);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            tokio::task::spawn(async move {
                let service = service_fn(move |req| async move {
                    if req.method() == Method::GET && req.uri().path() == "/index.html" {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                            "Hello, World!",
                        ))))
                    } else {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    log::info!("Failed to serve connection: {:?}", err);
                }
            });
        }
    });

    // Start the forward server to handle incoming connections
    start_forward_server(1002).await;

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .method(Method::GET)
        .header("content-type", "text/html")
        .uri("http://127.0.0.1:1002/index.html")
        .header("HOST", "buckyos.com")
        .body(Full::new(Bytes::new()))
        .expect("Failed to build request");

    let resp = client.request(req).await.unwrap();

    assert!(resp.status().is_success());

    let bytes = resp.collect().await.unwrap().to_bytes();
    assert_eq!(&*bytes, b"Hello, World!");
}
