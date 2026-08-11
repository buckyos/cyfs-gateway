#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayAppProfile {
    pub binary_name: &'static str,
    pub display_name: &'static str,
    pub log_name: &'static str,
    pub service_data_namespace: &'static str,
    pub config_basename: &'static str,
    pub token_audience: &'static str,
    pub template_namespace: &'static str,
}

impl GatewayAppProfile {
    pub const fn cyfs_gateway() -> Self {
        Self {
            binary_name: "cyfs_gateway",
            display_name: "CYFS Gateway",
            log_name: "cyfs_gateway",
            service_data_namespace: "cyfs_gateway",
            config_basename: "cyfs_gateway",
            token_audience: "cyfs-gateway",
            template_namespace: "cyfs_gateway",
        }
    }

    /// Web3 intentionally keeps the historical CYFS persistence and token namespaces.
    pub const fn web3_gateway() -> Self {
        Self {
            binary_name: "web3_gateway",
            display_name: "Web3 Gateway",
            log_name: "web3_gateway",
            service_data_namespace: "cyfs_gateway",
            config_basename: "cyfs_gateway",
            token_audience: "cyfs-gateway",
            template_namespace: "cyfs_gateway",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web3_compatibility_namespaces_are_explicit() {
        let profile = GatewayAppProfile::web3_gateway();
        assert_eq!(profile.service_data_namespace, "cyfs_gateway");
        assert_eq!(profile.config_basename, "cyfs_gateway");
        assert_eq!(profile.token_audience, "cyfs-gateway");
        assert_eq!(profile.template_namespace, "cyfs_gateway");
    }
}
