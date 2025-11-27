## 需求

`server-runner` 是一个轻量级库，会监听一个 HTTP（无 TLS）端口，把实现了 `cyfs_gateway_lib::HttpServer` 的实例跑起来。目的是让应用只需要关心自己的 `HttpServer` 实现，即可快速构建出一个可独立运行、二进制尽量小的进程。

## 使用示例

```rust
use std::sync::Arc;
use server_runner::Runner;

#[tokio::main]
async fn main() -> cyfs_gateway_lib::ServerResult<()> {
    let runner = Runner::new(3180);
    let app_http_server: Arc<dyn cyfs_gateway_lib::HttpServer> = app::create_http_server();

    runner.add_http_server(app_http_server)?;
    runner.start().await
}
```

`Runner::add_http_server` 需要一个 `Arc<dyn HttpServer>`；如果手头只有结构体实例，请自行包上一层 `Arc::new(...)`。`Runner::start` 会一直阻塞在监听循环，直到任务被终止或发生致命错误。