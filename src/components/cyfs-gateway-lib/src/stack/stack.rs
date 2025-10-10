use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use as_any::AsAny;
use serde::{Deserialize, Serialize};
use crate::{stack_err, ProcessChainConfig, StackErrorCode, StackResult};

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
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_config_json(&self) -> String;
    fn add_process_chain(&self, process_chain: ProcessChainConfig) -> Arc<dyn StackConfig>;
    fn remove_process_chain(&self, process_chain_id: &str) -> Arc<dyn StackConfig>;
}

#[async_trait::async_trait]
pub trait Stack: Send + Sync + 'static {
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_bind_addr(&self) -> String;
    async fn start(&self) -> StackResult<()>;
    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()>;
}

pub type StackRef = Arc<dyn Stack>;

pub struct StackManager {
    stacks: Mutex<Vec<StackRef>>,
}
pub type StackManagerRef = Arc<StackManager>;

impl StackManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stacks: Mutex::new(vec![]),
        })
    }

    pub fn add_stack(&self, stack: StackRef) {
        self.stacks.lock().unwrap().push(stack);
    }

    pub async fn start(&self) -> StackResult<()> {
        let mut stacks = Vec::new();
        for stack in self.stacks.lock().unwrap().iter() {
            stacks.push(stack.clone());
        }
        for stack in stacks.iter() {
            stack.start().await?;
        }
        Ok(())
    }

    pub async fn get_stack(&self, id: &str) -> Option<StackRef> {
        for stack in self.stacks.lock().unwrap().iter() {
            if stack.id() == id {
                return Some(stack.clone());
            }
        }
        None
    }
}

#[async_trait::async_trait]
pub trait StackFactory: Send + Sync {
    async fn create(&self, config: Arc<dyn StackConfig>) -> StackResult<StackRef>;
}

pub struct CyfsStackFactory {
    stack_factory: Mutex<HashMap<StackProtocol, Arc<dyn StackFactory>>>,
}

impl Default for CyfsStackFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl CyfsStackFactory {
    pub fn new() -> Self {
        Self {
            stack_factory: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, protocol: StackProtocol, factory: Arc<dyn StackFactory>) {
        self.stack_factory.lock().unwrap().insert(protocol, factory);
    }
}

#[async_trait::async_trait]
impl StackFactory for CyfsStackFactory {
    async fn create(&self, config: Arc<dyn StackConfig>) -> StackResult<StackRef> {
        let protocol = config.stack_protocol();
        let factory = {
            self.stack_factory.lock().unwrap().get(&protocol).cloned()
        };
        if factory.is_none() {
            return Err(stack_err!(StackErrorCode::UnsupportedStackProtocol, "unsupported stack protocol {:?}", protocol));
        }
        factory.unwrap().create(config).await
    }
}
