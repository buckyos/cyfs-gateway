pub use cyfs_gateway_app_lib::*;
pub use cyfs_gateway_modules::*;

pub fn gateway_app_profile() -> GatewayAppProfile {
    GatewayAppProfile::web3_gateway()
}

pub fn build_gateway_composition() -> anyhow::Result<GatewayComposition> {
    let mut builder = GatewayCompositionBuilder::new(gateway_app_profile());
    builder.install(CoreGatewayModule::new())?;
    builder.install(DnsGatewayModule::new())?;
    builder.install(SocksGatewayModule::new())?;
    builder.install(TunGatewayModule::new())?;
    builder.install(SnGatewayModule::new())?;
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

pub async fn web3_gateway_main() {
    match app() {
        Ok(app) => {
            if let Err(error) = app.run().await {
                log::error!("web3_gateway failed: {}", error);
            }
        }
        Err(error) => log::error!("create web3_gateway app failed: {}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_capabilities_are_stable() {
        let app = app().unwrap();
        assert_eq!(app.profile(), &GatewayAppProfile::web3_gateway());
        assert_eq!(app.profile().service_data_namespace, "cyfs_gateway");
        assert_eq!(app.profile().token_audience, "cyfs-gateway");
        assert_eq!(
            app.composition().manifest().stacks,
            ["quic", "rtcp", "tcp", "tls", "tun", "udp"].map(str::to_string)
        );
    }

    #[tokio::test]
    async fn deployment_configs_parse_with_web3_profile() {
        let composition = std::sync::Arc::new(build_gateway_composition().unwrap());
        let parser = GatewayConfigParser::new(composition);
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web3-gateway");
        for name in [
            "web3_gateway.yaml",
            "web3_dns.yaml",
            "web3_relay.yaml",
            "web3_sn_api.yaml",
        ] {
            let loaded = load_config_from_file(&gateway_app_profile(), &base.join(name))
                .await
                .unwrap_or_else(|e| panic!("load {} failed: {}", name, e));
            parser
                .parse(loaded.effective_config)
                .unwrap_or_else(|e| panic!("parse {} failed: {}", name, e.msg()));
        }
    }
}
