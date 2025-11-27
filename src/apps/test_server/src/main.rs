mod simple_server;

use std::sync::Arc;

use cyfs_gateway_lib::ServerResult;
use log::info;
use server_runner::Runner;
use simple_server::SimpleHttpServer;

fn default_port() -> u16 {
    const DEFAULT_PORT: u16 = 3180;
    std::env::var("TEST_SERVER_PORT")
        .ok()
        .and_then(|val| val.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT)
}

#[tokio::main]
async fn main() -> ServerResult<()> {
    buckyos_kit::init_logging("test_server", true);

    let port = default_port();
    let runner = Runner::new(port);
    runner.add_http_server(Arc::new(SimpleHttpServer::new()))?;

    info!("test_server listening on http://127.0.0.1:{port}");
    runner.start().await
}
