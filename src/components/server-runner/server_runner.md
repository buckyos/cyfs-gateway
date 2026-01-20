## 需求

`server-runner` 是一个轻量级库，会监听一个 HTTP（无 TLS）端口，把实现了 `cyfs_gateway_lib::HttpServer` 的实例跑起来。目的是让应用只需要关心自己的 `HttpServer` 实现，即可快速构建出一个可独立运行、二进制尽量小的进程。

## 使用示例

```rust
use std::sync::Arc;
use server_runner::{DirHandlerOptions, Runner};

#[tokio::main]
async fn main() -> cyfs_gateway_lib::ServerResult<()> {
    let runner = Runner::new(3180);
    let app_http_server: Arc<dyn cyfs_gateway_lib::HttpServer> = app::create_http_server();

    runner.add_http_server("/".to_string(), app_http_server)?;
    runner.add_dir_handler_with_options(
        "/".to_string(),
        std::path::PathBuf::from("./web"),
        DirHandlerOptions {
            fallback_file: Some("index.html".to_string()),
            ..Default::default()
        },
    ).await?;
    runner.start().await
}
```

`Runner::add_http_server` 需要一个 `Arc<dyn HttpServer>`；如果手头只有结构体实例，请自行包上一层 `Arc::new(...)`。`Runner::start` 会一直阻塞在监听循环，直到任务被终止或发生致命错误。

`Runner::add_dir_handler_with_options` 可指定 `fallback_file`，用于 SPA 场景：当静态文件不存在时回退到指定文件（通常是 `index.html`）。
