use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use as_any::AsAny;
use serde::{Deserialize, Serialize};
use crate::{stack_err, StackErrorCode, StackResult};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy, Hash)]
#[serde(rename_all = "lowercase")]
pub enum StackProtocol {
    Tcp,
    Udp,
    Quic,
    Rtcp,
    Tls,
    Extension(u8),
}

pub trait StackConfig: AsAny + Send + Sync {
    fn stack_protocol(&self) -> StackProtocol;
}

#[async_trait::async_trait]
pub trait Stack {
    fn stack_protocol(&self) -> StackProtocol;
    fn get_bind_addr(&self) -> String;
    async fn start(&mut self) -> StackResult<()>;
    async fn update_config(&mut self, config: Arc<dyn StackConfig>) -> StackResult<()>;
}

pub type StackBox = Box<dyn Stack>;

pub struct StackManager {
    stacks: Vec<StackBox>,
}

impl StackManager {
    pub fn new() -> Self {
        Self {
            stacks: vec![],
        }
    }
}

#[async_trait::async_trait]
pub trait StackFactory: Send + Sync {
    async fn create(&self, config: Box<dyn StackConfig>) -> StackResult<StackBox>;
}

pub struct CyfsStackFactory {
    stack_factory: HashMap<StackProtocol, Arc<dyn StackFactory>>,
}

impl Default for CyfsStackFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsStackFactory {
    pub fn new() -> Self {
        Self {
            stack_factory: HashMap::new(),
        }
    }

    pub fn register(&mut self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.insert(protocol, factory);
    }
}

#[async_trait::async_trait]
impl StackFactory for CyfsStackFactory {
    async fn create(&self, config: Box<dyn StackConfig>) -> StackResult<StackBox> {
        let protocol = config.stack_protocol();
        let factory = self.stack_factory.get(&protocol);
        if factory.is_none() {
            return Err(stack_err!(StackErrorCode::UnsupportedStackProtocol, "unsupported stack protocol {:?}", protocol));
        }
        factory.unwrap().create(config).await
    }
}
