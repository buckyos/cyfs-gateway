#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cyfs_gateway::app()?.run().await
}
