#[tokio::main]
async fn main() -> anyhow::Result<()> {
    web3_gateway::app()?.run().await
}
