#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use async_compression::tokio::bufread::GzipDecoder;
    use buckyos_kit::init_logging;
    use bytes::Bytes;
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    use hickory_resolver::{TokioAsyncResolver};
    use http_body_util::Full;
    use hyper_util::rt::TokioIo;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tokio::io::AsyncReadExt;
    use cyfs_gateway::{gateway_service_main, read_login_token, GatewayControlClient, GatewayParams, CONTROL_SERVER};

    async fn gunzip_bytes(data: Bytes) -> Bytes {
        let cursor = Cursor::new(data.to_vec());
        let reader = tokio::io::BufReader::new(cursor);
        let mut decoder = GzipDecoder::new(reader);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).await.unwrap();
        Bytes::from(output)
    }

    #[tokio::test]
    async fn test_cyfs_gateway() {
        init_logging("test_cyfs_gateway", false);
        let config = include_str!("test_cyfs_gateway.yaml");
        let local_dns = include_str!("local_dns.toml");
        let config_file = tempfile::NamedTempFile::with_suffix(".yaml").unwrap();
        let local_dns_file = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        std::fs::write(local_dns_file.path(), local_dns).unwrap();
        let config = config.replace("{{local_dns}}", local_dns_file.path().to_str().unwrap());

        let json_set = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        let config = config.replace("{{test_json_set}}", json_set.path().to_str().unwrap());

        let json_map = tempfile::NamedTempFile::with_suffix(".json").unwrap();
        let config = config.replace("{{test_json_map}}", json_map.path().to_str().unwrap());

        let sqlite_set = tempfile::NamedTempFile::with_suffix(".sqlite").unwrap();
        let config = config.replace("{{test_sqlite_set}}", sqlite_set.path().to_str().unwrap());

        let sqlite_map = tempfile::NamedTempFile::with_suffix(".sqlite").unwrap();
        let config = config.replace("{{test_sqlite_map}}", sqlite_map.path().to_str().unwrap());

        let text_set = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        let config = config.replace("{{test_text_set}}", text_set.path().to_str().unwrap());

        let js_hook_file = tempfile::NamedTempFile::with_suffix(".js").unwrap();
        let js_hook = r#"
function test_js_hook(context, host) {
    console.log(`Checking host: ${host}`);
    return true;
}
"#;
        std::fs::write(js_hook_file.path(), js_hook).unwrap();
        let config = config.replace("{{test_js_hook_file}}", js_hook_file.path().to_str().unwrap());

        let db = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let config = config.replace("{{sn_db}}", db.path().to_str().unwrap());

        let local_dir = tempfile::TempDir::new().unwrap();
        let config = config.replace("{{web3_dir}}", local_dir.path().to_str().unwrap());
        let path = local_dir.path().join("index.html");
        std::fs::write(path, "web3.buckyos.com").unwrap();
        let path = local_dir.path().join("test.txt");
        std::fs::write(path, "test").unwrap();

        let local_dir = tempfile::TempDir::new().unwrap();
        let config = config.replace("{{www_dir}}", local_dir.path().to_str().unwrap());
        let path = local_dir.path().join("index.html");
        std::fs::write(path, "www.buckyos.com").unwrap();

        let path = local_dir.path().join("index2.html");
        let raw_compress_body = "www.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.comwww.buckyos.com";
        std::fs::write(path, raw_compress_body).unwrap();

        std::fs::write(config_file.path(), config).unwrap();

        tokio::spawn(async move {
            gateway_service_main(config_file.path(), GatewayParams {
                keep_tunnel: vec![],
            }).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "web3.buckyos.com".len()).as_str());
            assert_eq!(response.headers().get("x-test").unwrap(), "1");
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"web3.buckyos.com");


            let request = hyper::Request::get("/test.txt")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "test".len()).as_str());
            assert_eq!(response.headers().get("x-test").unwrap(), "1");
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"test");
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/index2.html")
                .header("Host", "www.buckyos.com")
                .header("Accept-Encoding", "gzip")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert!(response.headers().get("content-encoding").is_some());
            assert_eq!(response.headers().get("content-encoding").map(|v| v.to_str().unwrap()), Some("gzip"));
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            let decoded = gunzip_bytes(data.to_bytes()).await;
            assert_eq!(decoded.as_ref(), raw_compress_body.as_bytes());
        }

        {
            //用tokio库创建一个tcpstream
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/index2.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert!(response.headers().get("content-encoding").is_none());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), raw_compress_body.as_bytes());
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/api")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "web3.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let name_server_configs = vec![NameServerConfig::new(
                SocketAddr::from_str("127.0.0.1:9545").unwrap(),
                Protocol::Udp,
            )];
            let server_config = ResolverConfig::from_parts(
                None,
                vec![],
                name_server_configs,
            );
            let resolver = TokioAsyncResolver::tokio(server_config, ResolverOpts::default());
            let response = resolver.lookup_ip("www.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response.unwrap().iter().collect::<Vec<_>>();
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("192.168.1.1").unwrap());

            let response = resolver.txt_lookup("www.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response.unwrap().iter().map(|x| x.to_string()).collect::<Vec<_>>();
            assert_eq!(ips.len(), 3);

            let response = resolver.lookup_ip("web3.buckyos.com.").await;
            assert!(response.is_ok());
            let ips = response.unwrap().iter().collect::<Vec<_>>();
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("192.168.1.2").unwrap());
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http_probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_err());
            let ret = cyfs_cmd_client.add_rule("stack1:test1", r#"http-probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_err());
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http-probe && eq ${REQ.dest_host} "test.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "test.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_rule("stack:test1", r#"http-probe && eq ${REQ.dest_host} "test2.buckyos.com" && call-server www.buckyos.com;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client.add_rule("server:www_dir:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.remove_rule("server:www.buckyos.com:main:test2").await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client.remove_rule("server:www.buckyos.com:main:test2").await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.append_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let ret = cyfs_cmd_client.append_rule("server:www_dir:main:test2", r#"starts-with ${REQ.path} "/sn" && rewrite ${REQ.path} "/sn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::METHOD_NOT_ALLOWED);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.move_rule("server:www.buckyos.com:main:test2", -1).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/sn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.set_rule("server:www.buckyos.com:main:test2", r#"starts-with ${REQ.path} "/snsn" && rewrite ${REQ.path} "/snsn*" "/*" && call-server sn.http;"#).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/snsn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        let router_dir = tempfile::TempDir::new().unwrap();
        {
            let router_target = format!("{}/", router_dir.path().to_string_lossy());
            std::fs::write(router_dir.path().join("index.html"), "router").unwrap();

            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_router(Some("server:www.buckyos.com"), "/router/", router_target.as_str()).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/router/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "router".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"router");

            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.remove_router(Some("server:www.buckyos.com"), "/router/", router_target.as_str()).await;
            assert!(ret.is_ok());
            let ret = cyfs_cmd_client.remove_router(Some("server:www.buckyos.com"), "/router/", router_target.as_str()).await;
            assert!(ret.is_err());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/router/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_router(Some("server:www.buckyos.com"), "/reverse/", "http://127.0.0.1:18081/").await;
            ret.as_ref().unwrap();
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/reverse/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(response.headers().get("content-length").unwrap(), format!("{}", "www.buckyos.com".len()).as_str());
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");

            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.remove_router(Some("server:www.buckyos.com"), "/reverse/", "http://127.0.0.1:18081/").await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:18080").await.unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/reverse/index.html")
                .header("Host", "www.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::NOT_FOUND);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.add_dispatch("19080", "127.0.0.1:18080", None).await;
            assert!(ret.is_ok());

            let stream = tokio::net::TcpStream::connect("127.0.0.1:19080").await.unwrap();

            let body = json!({
                    "method": "check_username",
                    "params": {
                        "username": "test",
                    },
                    "sys": [1]
                });
            // 用hyper构造一个http请求
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::post("/snsn")
                .header("Host", "test2.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::from(serde_json::to_string(&body).unwrap().as_bytes().to_vec()))).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }

        {
            let cyfs_cmd_client = GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
            let ret = cyfs_cmd_client.remove_dispatch("19080", None).await;
            assert!(ret.is_ok());

            let ret = tokio::net::TcpStream::connect("127.0.0.1:19080").await;
            assert!(ret.is_err());
        }
    }
}
