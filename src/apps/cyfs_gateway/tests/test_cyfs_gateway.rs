#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
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

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct DecodedIoDumpFrame {
        upload: Vec<u8>,
        download: Vec<u8>,
    }

    fn decode_io_dump_frames(mut data: &[u8]) -> Result<Vec<DecodedIoDumpFrame>, String> {
        let mut frames = Vec::new();
        while !data.is_empty() {
            if data.len() < 9 {
                return Err("truncated frame header".to_string());
            }
            if &data[0..4] != b"CGDP" {
                return Err("invalid frame magic".to_string());
            }
            if data[4] != 1 {
                return Err(format!("unsupported frame version: {}", data[4]));
            }
            let frame_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            if frame_len < 9 || frame_len > data.len() {
                return Err("invalid frame length".to_string());
            }
            let frame = &data[9..frame_len];
            let mut offset = 0usize;

            fn take<'a>(buf: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
                if *offset + len > buf.len() {
                    return Err("truncated frame payload".to_string());
                }
                let part = &buf[*offset..*offset + len];
                *offset += len;
                Ok(part)
            }

            let _ = take(frame, &mut offset, 8)?;
            let _ = take(frame, &mut offset, 8)?;

            let src_len = u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
            let _ = take(frame, &mut offset, src_len)?;

            let dst_len = u16::from_le_bytes(take(frame, &mut offset, 2)?.try_into().unwrap()) as usize;
            let _ = take(frame, &mut offset, dst_len)?;

            let upload_len = u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
            let upload = take(frame, &mut offset, upload_len)?.to_vec();

            let download_len = u32::from_le_bytes(take(frame, &mut offset, 4)?.try_into().unwrap()) as usize;
            let download = take(frame, &mut offset, download_len)?.to_vec();

            frames.push(DecodedIoDumpFrame { upload, download });
            data = &data[frame_len..];
        }
        Ok(frames)
    }

    async fn wait_dump_frames(file: &Path, min_frames: usize) -> Vec<DecodedIoDumpFrame> {
        for _ in 0..80 {
            if let Ok(data) = std::fs::read(file) {
                if !data.is_empty() {
                    if let Ok(frames) = decode_io_dump_frames(&data) {
                        if frames.len() >= min_frames {
                            return frames;
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("io dump frames not ready");
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

        let io_dump = tempfile::NamedTempFile::with_suffix(".dump").unwrap();
        let config = config.replace("{{test_io_dump}}", io_dump.path().to_str().unwrap());

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

            let frames = wait_dump_frames(io_dump.path(), 1).await;
            assert!(frames.iter().any(|f| {
                f.upload.starts_with(b"GET /") && f.download.starts_with(b"HTTP/1.1")
            }));


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
            let stream = tokio::net::TcpStream::connect("127.0.0.1:18084").await.unwrap();

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "ptcp-direct.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
        }

        {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind(SocketAddr::from_str("127.0.0.1:18123").unwrap()).unwrap();
            let stream = socket.connect(SocketAddr::from_str("127.0.0.1:18082").unwrap()).await.unwrap();
            let expected_port = 18123;

            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake(TokioIo::new(stream)).await.unwrap();
            let request = hyper::Request::get("/")
                .header("Host", "ptcp-probe.buckyos.com")
                .version(hyper::Version::HTTP_11)
                .body(Full::new(Bytes::new())).unwrap();

            tokio::spawn(async move {
                conn.await.unwrap();
            });

            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);

            let remote_port = response.headers()
                .get("x-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();
            let conn_remote_port = response.headers()
                .get("x-conn-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();
            let real_remote_port = response.headers()
                .get("x-real-remote-port")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap();

            assert_eq!(remote_port, expected_port);
            assert_eq!(real_remote_port, expected_port);
            assert_ne!(conn_remote_port, expected_port);

            let body = response.into_body();
            let data = body.collect().await.unwrap();
            assert_eq!(data.to_bytes().as_ref(), b"www.buckyos.com");
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
