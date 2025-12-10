/// DirServer 使用示例
/// 
/// 这个示例展示如何使用 DirServer 提供静态文件服务
/// 
/// 运行方式：
/// ```bash
/// cd src
/// cargo run --package cyfs-gateway-lib --example dir_server_example
/// ```
/// 
/// 然后在浏览器或 curl 中访问：
/// ```bash
/// curl http://localhost:8080/test.txt
/// curl -H "Range: bytes=0-99" http://localhost:8080/test.txt
/// ```

use cyfs_gateway_lib::{DirServer, HttpServer, StreamInfo};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 可选：初始化日志
    // 运行时设置环境变量: RUST_LOG=debug cargo run --example dir_server_example
    // env_logger::init();

    // 创建临时目录用于演示
    let temp_dir = tempfile::tempdir()?;
    let root_dir = temp_dir.path().to_path_buf();

    println!("创建演示文件到目录: {:?}", root_dir);

    // 创建一些演示文件
    tokio::fs::write(
        root_dir.join("test.txt"),
        b"Hello, this is a test file from DirServer!\n\
          This file demonstrates the DirServer functionality.\n\
          You can use Range requests to fetch parts of this file.\n",
    )
    .await?;

    tokio::fs::write(
        root_dir.join("index.html"),
        b"<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>DirServer Demo</title>
</head>
<body>
    <h1>Welcome to DirServer Demo</h1>
    <p>This is a static file served by DirServer.</p>
    <ul>
        <li><a href='/test.txt'>test.txt</a></li>
        <li><a href='/data.json'>data.json</a></li>
    </ul>
</body>
</html>",
    )
    .await?;

    tokio::fs::write(
        root_dir.join("data.json"),
        br#"{
    "name": "DirServer",
    "version": "0.4.0",
    "description": "A simple HTTP static file server",
    "features": [
        "Static file serving",
        "Range request support",
        "MIME type detection",
        "Directory index",
        "Path security"
    ]
}"#,
    )
    .await?;

    // 创建 DirServer
    let server = Arc::new(
        DirServer::builder()
            .id("demo_server")
            .root_path(root_dir)
            .index_file("index.html")
            .version("HTTP/1.1")
            .build()
            .await?,
    );

    println!("DirServer 已创建: {}", server.id());
    println!("HTTP 版本: {:?}", server.http_version());

    // 绑定到本地端口
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let listener = TcpListener::bind(addr).await?;

    println!("DirServer 正在监听 http://{}", addr);
    println!("尝试访问:");
    println!("  - http://{}/", addr);
    println!("  - http://{}/test.txt", addr);
    println!("  - http://{}/data.json", addr);
    println!("\n使用 Range 请求:");
    println!("  curl -H 'Range: bytes=0-99' http://{}/test.txt", addr);
    println!("\n按 Ctrl+C 停止服务器");

    // 接受连接
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let server = server.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let server = server.clone();
                async move {
                    let stream_info = StreamInfo::default();
                    
                    // 将 Incoming body 转换为 BoxBody
                    let req = req.map(|body| {
                        body.map_err(|e| {
                            cyfs_gateway_lib::ServerError::new(
                                cyfs_gateway_lib::ServerErrorCode::StreamError,
                                format!("{:?}", e)
                            )
                        }).boxed()
                    });
                    
                    // 调用服务器处理请求
                    let result = server.serve_request(req, stream_info).await;
                    
                    match result {
                        Ok(resp) => {
                            println!("✓ {} - {}", remote_addr, resp.status());
                            Ok::<_, hyper::Error>(resp)
                        }
                        Err(e) => {
                            eprintln!("✗ {} - Error: {:?}", remote_addr, e);
                            // 返回 500 错误
                            Ok(hyper::Response::builder()
                                .status(500)
                                .body(Full::new(Bytes::from("Internal Server Error"))
                                    .map_err(|e: std::convert::Infallible| match e {})
                                    .boxed())
                                .unwrap())
                        }
                    }
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("连接错误: {:?}", err);
            }
        });
    }
}

