use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use as_any::AsAny;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::{stack_err, StackErrorCode, StackResult};

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum StackProtocol {
    Tcp,
    Udp,
    Quic,
    Rtcp,
    Tls,
    Extension(String),
}

impl Serialize for StackProtocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            StackProtocol::Tcp => "tcp",
            StackProtocol::Udp => "udp",
            StackProtocol::Quic => "quic",
            StackProtocol::Rtcp => "rtcp",
            StackProtocol::Tls => "tls",
            StackProtocol::Extension(name) => name.as_str(),
        })
    }
}

impl<'de> Deserialize<'de> for StackProtocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "tcp" => Ok(StackProtocol::Tcp),
            "udp" => Ok(StackProtocol::Udp),
            "quic" => Ok(StackProtocol::Quic),
            "rtcp" => Ok(StackProtocol::Rtcp),
            "tls" => Ok(StackProtocol::Tls),
            _ => Ok(StackProtocol::Extension(s)),
        }
    }
}

pub trait StackConfig: AsAny + Send + Sync {
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_config_json(&self) -> String;
}

pub trait StackContext: AsAny + Send + Sync {
    fn stack_protocol(&self) -> StackProtocol;
}

#[async_trait::async_trait]
pub trait Stack: Send + Sync + 'static {
    fn id(&self) -> String;
    fn stack_protocol(&self) -> StackProtocol;
    fn get_bind_addr(&self) -> String;
    async fn start(&self) -> StackResult<()>;
    async fn update_config(&self, config: Arc<dyn StackConfig>) -> StackResult<()> {
        self.prepare_update(config, None).await?;
        self.commit_update().await;
        Ok(())
    }
    async fn prepare_update(&self, config: Arc<dyn StackConfig>, context: Option<Arc<dyn StackContext>>) -> StackResult<()>;
    async fn commit_update(&self);
    async fn rollback_update(&self);
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

    pub fn add_stack(&self, stack: StackRef) -> StackResult<()> {
        if self.get_stack(stack.id().as_str()).is_some() {
            return Err(stack_err!(StackErrorCode::AlreadyExists, "stack {} already exists", stack.id()));
        }
        self.stacks.lock().unwrap().push(stack);
        Ok(())
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

    pub fn get_stack(&self, id: &str) -> Option<StackRef> {
        for stack in self.stacks.lock().unwrap().iter() {
            if stack.id() == id {
                return Some(stack.clone());
            }
        }
        None
    }

    pub fn retain<F>(&self, f: F)
    where
        F: Fn(&str) -> bool,
    {
        let mut stacks = self.stacks.lock().unwrap();
        stacks.retain(|stack| {
            f(stack.id().as_str())
        });
    }

    pub fn remove(&self, id: &str) {
        self.retain(|stack_id| {
            stack_id != id
        });
    }
}

#[async_trait::async_trait]
pub trait StackFactory: Send + Sync {
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef>;
}

pub struct CyfsStackFactory {
    stack_factory: Mutex<HashMap<StackProtocol, Arc<dyn StackFactory>>>,
}
pub type CyfsStackFactoryRef = Arc<CyfsStackFactory>;

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
    async fn create(
        &self,
        config: Arc<dyn StackConfig>,
        context: Arc<dyn StackContext>,
    ) -> StackResult<StackRef> {
        let protocol = config.stack_protocol();
        let factory = {
            self.stack_factory.lock().unwrap().get(&protocol).cloned()
        };
        if factory.is_none() {
            return Err(stack_err!(StackErrorCode::UnsupportedStackProtocol, "unsupported stack protocol {:?}", protocol));
        }
        factory.unwrap().create(config, context).await
    }
}
