pub use cyfs_gateway_app_lib::*;
pub use cyfs_gateway_modules::*;

pub fn gateway_app_profile() -> GatewayAppProfile {
    GatewayAppProfile::cyfs_gateway()
}

pub fn build_gateway_composition() -> anyhow::Result<GatewayComposition> {
    let mut builder = GatewayCompositionBuilder::new(gateway_app_profile());
    builder.install(CoreGatewayModule::new())?;
    builder.install(DnsGatewayModule::new())?;
    builder.install(SocksGatewayModule::new())?;
    builder.install(TunGatewayModule::new())?;
    //builder.install(SnGatewayModule::new())?;
    builder.install(TrafficGatewayModule::new())?;
    builder.build()
}

pub fn app() -> anyhow::Result<GatewayApp> {
    GatewayApp::new(gateway_app_profile(), build_gateway_composition()?)
}

pub async fn gateway_service_main(
    config_file: &std::path::Path,
    params: GatewayParams,
) -> anyhow::Result<()> {
    let app = app()?;
    cyfs_gateway_app_lib::gateway_service_main(&app, config_file, params).await
}

pub async fn cyfs_gateway_main() {
    match app() {
        Ok(app) => {
            if let Err(error) = app.run().await {
                log::error!("cyfs_gateway failed: {}", error);
            }
        }
        Err(error) => log::error!("create cyfs_gateway app failed: {}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_capabilities_are_stable() {
        let app = app().unwrap();
        assert_eq!(app.profile(), &GatewayAppProfile::cyfs_gateway());
        assert_eq!(
            app.composition().manifest().stacks,
            ["quic", "rtcp", "tcp", "tls", "tun", "udp"].map(str::to_string)
        );
    }
}
