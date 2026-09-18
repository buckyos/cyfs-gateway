use std::any::Any;
use std::sync::Arc;

use anyhow::Result;
use cyfs_gateway_lib::{
    ConfigResult, LimiterManager, LimiterManagerRef, StatFactoryRef, StatManagerRef,
};

pub trait GatewayTrafficConfig: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn enabled(&self) -> bool;
}

pub type GatewayTrafficConfigRef = Arc<dyn GatewayTrafficConfig>;

pub trait GatewayTrafficStatFactory: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_stat_factory(&self) -> StatFactoryRef;
}

pub type GatewayTrafficStatFactoryRef = Arc<dyn GatewayTrafficStatFactory>;

#[async_trait::async_trait]
pub trait GatewayTrafficService: Send + Sync {
    async fn stop(self: Box<Self>);
    fn shutdown_now(self: Box<Self>);
}

#[async_trait::async_trait]
pub trait GatewayTrafficAdapter: Send + Sync + 'static {
    fn parse_config(
        &self,
        value: Option<&serde_json::Value>,
    ) -> ConfigResult<GatewayTrafficConfigRef>;

    fn create_stat_factory(
        &self,
        config: &GatewayTrafficConfigRef,
    ) -> Result<GatewayTrafficStatFactoryRef>;

    fn configure_limiter_factory(
        &self,
        config: &GatewayTrafficConfigRef,
        stat_factory: &GatewayTrafficStatFactoryRef,
        limiter_manager: &mut dyn LimiterManager,
    ) -> Result<()>;

    async fn start_service(
        &self,
        config: &GatewayTrafficConfigRef,
        stat_manager: StatManagerRef,
        stat_factory: &GatewayTrafficStatFactoryRef,
        limiter_manager: LimiterManagerRef,
    ) -> Result<Option<Box<dyn GatewayTrafficService>>>;
}

pub type GatewayTrafficAdapterRef = Arc<dyn GatewayTrafficAdapter>;
