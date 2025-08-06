
use crate::router::*;
use anyhow::Result;//TODO need build a new Result type for cyfs-warp
use cyfs_gateway_lib::*;
use hyper::service::{service_fn};
use hyper::{Request, Response};
use log::*;
use rustls::Certificate;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::pkcs8_private_keys;
use std::fs::File;
use std::io::BufReader;
use http_body_util::combinators::{UnsyncBoxBody};
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;

pub struct CyfsWarpServer {
    config: WarpServerConfig,

    http_servers: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    https_servers: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl CyfsWarpServer {
    pub fn new(config: WarpServerConfig) -> Self {
        Self {
            config,
            http_servers: Arc::new(Mutex::new(Vec::new())),
            https_servers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        // Router for HTTP and HTTPS
        let https_router = Router::new(HashMap::from_iter(self.config.hosts.iter().map(
            |(host, host_config)| {
                (
                    host.clone(),
                    HashMap::from_iter(host_config.routes.iter().map(|(route, route_config)| {
                        (route.clone(), Arc::new(route_config.clone()))
                    })),
                )
            },
        )));

        let http_router = Router::new(HashMap::from_iter(self.config.hosts.iter().map(
            |(host, host_config)| {
                if host_config.redirect_to_https {
                    (
                        host.clone(),
                        HashMap::from_iter(vec![(
                            "/".to_string(),
                            Arc::new(RouteConfig {
                                enable_cors: host_config.enable_cors,
                                response: Some(ResponseRouteConfig {
                                    status: Some(301),
                                    headers: Some(HashMap::from_iter(vec![(
                                        "Location".to_string(),
                                        format!("https://{}", host),
                                    )])),
                                    body: None,
                                }),
                                upstream: None,
                                local_dir: None,
                                inner_service: None,
                                tunnel_selector: None,
                                bucky_service: None,
                                named_mgr: None,
                            }),
                        )]),
                    )
                } else {
                    (
                        host.clone(),
                        HashMap::from_iter(host_config.routes.iter().map(
                            |(route, route_config)| (route.clone(), Arc::new(route_config.clone())),
                        )),
                    )
                }
            },
        )));

        // // Cert manager for HTTPS
        // let root_path = get_buckyos_service_data_dir("cyfs-warp");
        // info!("Will use cyfs-warp data directory: {}", root_path.display());
        // if !root_path.exists() {
        //     info!("Creating cyfs-warp data directory: {}", root_path.display());
        //     if let Err(e) = std::fs::create_dir_all(&root_path) {
        //         let msg = format!(
        //             "Failed to create cyfs-warp data directory: {}, {}",
        //             e,
        //             root_path.display()
        //         );
        //         error!("{}", msg);
        //         return Err(anyhow::anyhow!(msg));
        //     }
        // }

        // let mut cert_mgr_config = CertManagerConfig::default();
        // cert_mgr_config.keystore_path = root_path.to_string_lossy().to_string();

        // let cert_mgr =
        //     CertManager::new(cert_mgr_config, ChallengeEntry::new(http_router.clone())).await?;

        // for (host, host_config) in self.config.hosts.iter() {
        //     cert_mgr.insert_config(host.clone(), host_config.tls.clone())?;
        // }

        // Start all servers
        let bind = self.config.bind.clone().unwrap_or("0.0.0.0".to_string());
        let bind_addrs: Vec<&str> = bind.split(';').collect();
        for bind_addr in bind_addrs {
            let http_router = http_router.clone();
            let https_router = https_router.clone();


            let formatted_bind_addr = if bind_addr.contains(":") && !bind_addr.starts_with("[") {
                format!("[{}]", bind_addr)
            } else {
                bind_addr.to_string()
            };

            let bind_addr_http = format!("{}:{}", formatted_bind_addr, self.config.http_port);
            match Self::start_listen_http(bind_addr_http, http_router).await {
                Ok(server_task) => {
                    self.http_servers.lock().await.push(server_task);
                }
                Err(e) => {
                    // FIXME: should we return error here or just log it?
                    error!("Failed to start HTTP server: {}", e);
                    return Err(e);
                }
            }
            if self.config.tls_port > 0 {
                let bind_addr_https = format!("{}:{}", formatted_bind_addr, self.config.tls_port);
                match Self::start_listen_https(
                    bind_addr_https,
                    https_router,
                    &self.config,
                )
                .await
                {
                    Ok(server_task) => {
                        self.https_servers.lock().await.push(server_task);
                    }
                    Err(e) => {
                        // FIXME: should we return error here or just log it?
                        error!("Failed to start HTTPS server: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut http_servers = self.http_servers.lock().await;
        for server in http_servers.iter_mut() {
            server.abort();
        }
        http_servers.clear();

        let mut https_servers = self.https_servers.lock().await;
        for server in https_servers.iter_mut() {
            server.abort();
        }
        https_servers.clear();

        Ok(())
    }

    async fn handle_request(
        router: Router,
        req: Request<Incoming>,
        client_ip: SocketAddr,
    ) -> Result<Response<UnsyncBoxBody<Bytes, anyhow::Error>>, hyper::Error> {
        match router.route(req, client_ip).await {
            Ok(response) => Ok(response),
            Err(e) => {
                let response = e.build_response();
                Ok(response)
            }
        }
    }

    async fn start_listen_http(
        http_bind_addr: String,
        http_router: Router,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let listener =
            TcpListener::bind(http_bind_addr.clone())
                .await
                .map_err(|e: std::io::Error| {
                    error!("bind http server {} failed,  {}", http_bind_addr, e);
                    anyhow::anyhow!("bind http server {} failed, {}", http_bind_addr, e)
                })?;

        let server_task = tokio::task::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let http_router = http_router.clone();
                        let client_ip = stream.peer_addr().unwrap();
                        let io = TokioIo::new(stream);
                        tokio::spawn(async move {
                            let service = service_fn(move |req| {
                                Self::handle_request(http_router.clone(), req, client_ip)
                            });
                            if let Err(err) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service).await {
                                error!("cyfs-warp failed to serve connection:{:?}", err);
                            }
                        });
                    },
                    Err(e) => {
                        error!(
                        "cyfs-warp HTTP Server stopped with error: {:?}, {}",
                        e, http_bind_addr
                    );
                    }
                }
            }
        });

        Ok(server_task)
    }

    async fn start_listen_https(
        https_bind_addr: String,
        https_router: Router,
        server_config: &WarpServerConfig,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let mut tls_cfg_map = HashMap::new();
        for (host, host_config) in server_config.hosts.iter() {
            if host_config.tls.disable_tls {
                continue;
            }
            if host_config.tls.cert_path.is_some() && host_config.tls.key_path.is_some() {
                let cert_file = File::open(&host_config.tls.cert_path.as_ref().unwrap()).map_err(|e| {
                    error!("Failed to open cert file: {} {}", host_config.tls.cert_path.as_ref().unwrap(), e);
                    anyhow::anyhow!("Failed to open cert file:{} {}", host_config.tls.cert_path.as_ref().unwrap(), e)
                })?;
                let mut cert_file = BufReader::new(cert_file);
                let certs = rustls_pemfile::certs(&mut cert_file).unwrap();
                if certs.is_empty() {
                    error!("No certificates found in cert file");
                    return Err(anyhow::anyhow!("No certificates found in cert file"));
                }
                let cert:Vec<Certificate> = certs.into_iter().map(Certificate).collect();
                //let cert = cert.remove(0);
                debug!("load tls cert: {:?} OK",cert);
                let key_file = File::open(&host_config.tls.key_path.as_ref().unwrap()).map_err(|e| {
                    error!("Failed to open key file: {} {}", host_config.tls.key_path.as_ref().unwrap(), e);
                    anyhow::anyhow!("Failed to open key file: {} {}", host_config.tls.key_path.as_ref().unwrap(), e)
                })?;
                let mut key_file = BufReader::new(key_file);
                let mut keys = pkcs8_private_keys(&mut key_file).unwrap();
                if keys.is_empty() {
                    error!("No private keys found in key file");
                    return Err(anyhow::anyhow!("No private keys found in key file"));
                }
                let key = rustls::PrivateKey(keys.remove(0));
                let mut config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(cert, key)
                    .unwrap();
                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                tls_cfg_map.insert(host.clone(), Arc::new(config));
            }
        }

        let tls_cfg = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SNIResolver::new(tls_cfg_map))),
        );
        let tls_acceptor = TlsAcceptor::from(tls_cfg.clone());
        let listener = TcpListener::bind(https_bind_addr.clone()).await;
        if listener.is_err() {
            error!(
                "bind https server {} failed, please check the port is used",
                https_bind_addr
            );
            return Err(anyhow::anyhow!(
                "bind https server {} failed, please check the port is used",
                https_bind_addr
            ));
        }
        let listener = listener.unwrap();

        let server_task = tokio::task::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let client_ip = stream.peer_addr().unwrap();
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                debug!("tls accept a new tls from tcp stream OK!");

                                let http_router = https_router.clone();
                                let io = TokioIo::new(tls_stream);
                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        Self::handle_request(http_router.clone(), req, client_ip)
                                    });
                                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, service).await {
                                        error!("cyfs-warp failed to serve connection:{:?}", err);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TLS handshake failed: {:?}", e);
                                continue;
                            }
                        }

                    },
                    Err(e) => {
                        error!(
                        "cyfs-warp HTTP Server stopped with error: {:?}, {}",
                        e, https_bind_addr
                    );
                    }
                }
            }
        });

        Ok(server_task)
    }
}

pub async fn start_cyfs_warp_server(config: WarpServerConfig) -> Result<CyfsWarpServer> {
    let server = CyfsWarpServer::new(config);
    server.start().await?;

    Ok(server)
}
